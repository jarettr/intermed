//! Fingerprint sidecars: `mtime+size → sha256` mappings that skip full-jar
//! hashing on repeat runs.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::io_util::write_atomic;

use super::util::{WRITE_SHARDS, jar_path_digest, now_unix_secs, sha256_file, shard_index};

pub(crate) const FINGERPRINT_SCHEMA: &str = "intermed-jar-fp-v1";

/// Maps a jar's cheap identity (`mtime` + `size`) to its content `sha256`, so
/// repeat runs skip the full-jar hash.
///
/// **Trust model.** `mtime + size` is a *heuristic* for "same content", not a
/// proof. We trust it on a match to avoid re-hashing on every run, but the
/// heuristic can lie — a same-size, same-mtime in-place rewrite (rare, but
/// possible on copies or certain filesystems) leaves the sidecar pointing at a
/// stale SHA. `get_or_scan` defends against this: the fingerprint SHA only
/// short-circuits when it *also* resolves a usable payload; otherwise we fall
/// back to a real `sha256_file`, so a stale fingerprint costs one wasted lookup,
/// never a wrong result. `last_verified_secs` records when the mapping was last
/// confirmed (diagnostic provenance, and a hook for a future re-verify TTL).
#[derive(Serialize, Deserialize)]
pub(crate) struct FingerprintRecord {
    pub schema: String,
    pub jar_path: String,
    pub mtime_secs: u64,
    pub mtime_nanos: u32,
    pub size_bytes: u64,
    pub sha256: String,
    /// Unix seconds when this `mtime+size → sha256` mapping was last written.
    #[serde(default)]
    pub last_verified_secs: u64,
}

/// Manages fingerprint sidecar I/O under `{root}/{collector_id}/fp/…`.
pub(crate) struct FingerprintManager<'a> {
    root: &'a Path,
    write_locks: &'a [Mutex<()>; WRITE_SHARDS],
    reverify_ttl: Duration,
}

impl<'a> FingerprintManager<'a> {
    pub(crate) fn new(
        root: &'a Path,
        write_locks: &'a [Mutex<()>; WRITE_SHARDS],
        reverify_ttl: Duration,
    ) -> Self {
        Self {
            root,
            write_locks,
            reverify_ttl,
        }
    }

    pub(crate) fn path(&self, collector_id: &str, jar: &Path) -> PathBuf {
        let digest = jar_path_digest(jar);
        let prefix = digest.get(..2).unwrap_or("00");
        self.root
            .join(collector_id)
            .join("fp")
            .join(prefix)
            .join(format!("{digest}.json"))
    }

    pub(crate) fn load(&self, collector_id: &str, jar: &Path) -> Option<FingerprintRecord> {
        let text = fs::read_to_string(self.path(collector_id, jar)).ok()?;
        let fp = serde_json::from_str::<FingerprintRecord>(&text).ok()?;
        if fp.schema == FINGERPRINT_SCHEMA {
            Some(fp)
        } else {
            None
        }
    }

    pub(crate) fn save(
        &self,
        collector_id: &str,
        jar: &Path,
        mtime_secs: u64,
        mtime_nanos: u32,
        size_bytes: u64,
        sha256: &str,
    ) -> io::Result<()> {
        let _guard = self.write_locks[shard_index(sha256)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = self.path(collector_id, jar);

        // Skip the write when the on-disk fingerprint already matches: a clean
        // fast-hit run must not rewrite an unchanged sidecar every time.
        if let Some(existing) = self.load(collector_id, jar) {
            if existing.mtime_secs == mtime_secs
                && existing.mtime_nanos == mtime_nanos
                && existing.size_bytes == size_bytes
                && existing.sha256 == sha256
            {
                return Ok(());
            }
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let record = FingerprintRecord {
            schema: FINGERPRINT_SCHEMA.to_string(),
            jar_path: jar.display().to_string(),
            mtime_secs,
            mtime_nanos,
            size_bytes,
            sha256: sha256.to_string(),
            last_verified_secs: now_unix_secs(),
        };
        let text = serde_json::to_string(&record)?;
        write_atomic(&path, text.as_bytes())?;
        Ok(())
    }

    /// Resolve content SHA-256, returning `(sha256, from_fingerprint)`.
    pub(crate) fn resolve_sha256(
        &self,
        collector_id: &str,
        jar: &Path,
        mtime_secs: u64,
        mtime_nanos: u32,
        size_bytes: u64,
    ) -> Option<(String, bool)> {
        if let Some(fp) = self.load(collector_id, jar) {
            if fp.mtime_secs == mtime_secs
                && fp.mtime_nanos == mtime_nanos
                && fp.size_bytes == size_bytes
                && !fingerprint_expired(&fp, self.reverify_ttl)
            {
                // Counted as a fast hit only once it yields a usable payload (see
                // `get_or_scan`); a stale fingerprint must not inflate the metric.
                return Some((fp.sha256, true));
            }
            // Metadata matched but the mapping is past its re-verify TTL: fall
            // through to a real hash so a same-mtime+size rewrite cannot be
            // trusted indefinitely. The fresh hash refreshes `last_verified_secs`.
        }
        let sha256 = sha256_file(jar).ok()?;
        Some((sha256, false))
    }
}

/// True when a fingerprint is older than `reverify_ttl` and should be re-hashed
/// rather than trusted on metadata alone. A `last_verified_secs` of `0` (older
/// records written before the field existed) is treated as expired.
pub(crate) fn fingerprint_expired(fp: &FingerprintRecord, reverify_ttl: Duration) -> bool {
    let now = now_unix_secs();
    now.saturating_sub(fp.last_verified_secs) >= reverify_ttl.as_secs()
}
