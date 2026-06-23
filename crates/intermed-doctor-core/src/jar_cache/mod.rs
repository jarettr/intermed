//! On-disk jar scan cache (read-through helper for collectors).
//!
//! ```text
//!   jar on disk ──▶ fp mtime+size ──▶ SHA-256 (on fp miss) ──▶ JSON payload
//!                        │ fast hit           │ miss
//!                        └──────── scan() ◀───┘
//! ```
//!
//! Cache files live at:
//! `{root}/{collector_id}/{cache_version}/{sha[0:2]}/{sha256}.json`
//!
//! Fingerprints (mtime+size → sha256, skip full-jar hashing on repeat runs):
//! `{root}/{collector_id}/fp/{digest[0:2]}/{digest}.json`
//!
//! Default root: `$XDG_CACHE_HOME/intermed/jars` (fallback `~/.cache/intermed/jars`).
//! Enabled by default; pass `JarCache::disabled()` or CLI `--no-cache` to bypass.
//!
//! ## Logic versioning
//!
//! The cache key — and the record's validation — both include a per-collector
//! `cache_version` string. This is the fix for the classic stale-scanner bug: a
//! jar's content (and therefore its SHA-256) can be byte-for-byte identical
//! across two releases, yet a collector that improved its parser between those
//! releases must **not** serve the payload computed by the old parser. Folding
//! the collector's logic version into the key guarantees a structural miss when
//! the logic changes, with no manual global-schema bump required. Collectors
//! derive the version from their crate version (see `intermed-*` `CACHE_VERSION`
//! constants), so every release invalidates automatically; a trailing revision
//! lets authors force invalidation mid-release.

mod config;
mod fingerprint;
mod prune;
mod remote;
mod util;

pub use config::{
    DEFAULT_CACHE_MAX_AGE_DAYS, DEFAULT_CACHE_MAX_BYTES, DEFAULT_CACHE_MIN_BYTES,
    DEFAULT_FINGERPRINT_REVERIFY_DAYS, DEFAULT_PRUNE_INTERVAL_DAYS, JarCacheConfig,
};
pub use remote::LocalDirRemoteTier;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Sentinel for `cached_bytes_on_disk`: means "not yet measured this session".
const DISK_USAGE_STALE: u64 = u64::MAX;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::io_util::write_atomic;

use fingerprint::FingerprintManager;
use prune::{disk_usage, maybe_prune};
use util::{
    WRITE_SHARDS, default_cache_root, file_mtime, new_write_locks, sanitize_segment, sha256_file,
    shard_index,
};

/// Schema tag embedded in every cache record.
pub const CACHE_SCHEMA: &str = "intermed-jar-cache-v1";

/// Hit/miss/write counters accumulated during one doctor run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub writes: u64,
    /// Lookups that skipped full-jar SHA-256 via the fingerprint sidecar.
    pub fast_hits: u64,
    /// Concurrent scans of the same content that were coalesced by single-flight
    /// (i.e. the expensive `scan()` they would have duplicated was avoided).
    #[serde(default)]
    pub coalesced: u64,
    /// Hits served from the in-process memory tier (subset of `hits`).
    #[serde(default)]
    pub mem_hits: u64,
    /// Hits served from the remote tier (subset of `hits`).
    #[serde(default)]
    pub remote_hits: u64,
    /// Total on-disk size of the cache in bytes. Computed lazily (only when a
    /// profile is surfaced); `0` when not measured. See [`JarCache::disk_usage`].
    #[serde(default)]
    pub bytes_on_disk: u64,
}

/// Read-through cache for per-jar collector payloads.
pub struct JarCache {
    root: PathBuf,
    enabled: bool,
    config: JarCacheConfig,
    hits: AtomicU64,
    misses: AtomicU64,
    writes: AtomicU64,
    fast_hits: AtomicU64,
    coalesced: AtomicU64,
    write_locks: Box<[Mutex<()>; WRITE_SHARDS]>,
    /// Single-flight registry: per-content gates that coalesce concurrent
    /// cold-cache scans of the same payload key so only one thread runs the
    /// expensive `scan()`. Keyed by `collector\0version\0sha256`.
    inflight: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Cached result of the last `disk_usage()` walk. `DISK_USAGE_STALE`
    /// means "not yet measured this session". Reset to stale after pruning.
    /// Updated incrementally on each `write_record` call.
    cached_bytes_on_disk: AtomicU64,
    /// Tier 1 — in-process memory cache: payload key → cache-record JSON text.
    /// Avoids re-reading and re-parsing disk when the same content SHA is looked
    /// up again within a run (identical bundled libs, duplicate jars across packs).
    memory: Mutex<HashMap<String, String>>,
    /// Tier 3 — optional remote store (object storage / HTTP), behind a stable
    /// trait. `None` keeps the cache local-only (the default).
    remote: Option<Arc<dyn RemoteCacheTier>>,
    /// Hits served from the memory tier (a subset of `hits`).
    mem_hits: AtomicU64,
    /// Hits served from the remote tier (a subset of `hits`).
    remote_hits: AtomicU64,
}

/// Maximum entries held in the in-process memory tier before it is cleared. A
/// flat count cap (not byte-accurate) keeps the hot path lock-cheap; the disk
/// tier remains the source of truth, so a clear only costs re-reads, never data.
const MEM_CACHE_CAP: usize = 8192;

/// Debounce for promote-on-hit: a cache file's mtime is only bumped (to mark it
/// recently used for LRU pruning) when it is already older than this, so a run
/// with many repeat hits does not rewrite metadata on every access.
const PROMOTE_DEBOUNCE_SECS: u64 = 3600;

/// A third cache tier backed by remote/shared storage (object store, HTTP, a CI
/// artifact cache, …). Implementations are content-addressed by the same opaque
/// `key` the local tiers use, so a value put under a key is valid for any machine
/// that reads it back — the key already folds in collector id, logic version, and
/// the content SHA-256.
///
/// Errors are intentionally swallowed at the call site (a remote miss or outage
/// must never fail a scan), so the trait returns `Option` / ignores `put` results.
pub trait RemoteCacheTier: Send + Sync {
    /// Fetch the stored cache-record bytes for `key`, or `None` on miss/error.
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    /// Store cache-record `bytes` under `key`. Best-effort; errors are ignored.
    fn put(&self, key: &str, bytes: &[u8]);
}

#[derive(Serialize, Deserialize)]
struct CacheRecord<T> {
    schema: String,
    collector: String,
    /// Per-collector logic version; a mismatch invalidates the record even when
    /// the schema and content SHA-256 are unchanged.
    #[serde(default)]
    cache_version: String,
    jar_path: String,
    mtime_secs: u64,
    mtime_nanos: u32,
    size_bytes: u64,
    sha256: String,
    payload: T,
}

impl JarCache {
    /// A cache that never reads or writes disk.
    pub fn disabled() -> Self {
        Self {
            root: PathBuf::new(),
            enabled: false,
            config: JarCacheConfig::default(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            fast_hits: AtomicU64::new(0),
            coalesced: AtomicU64::new(0),
            write_locks: new_write_locks(),
            inflight: Mutex::new(HashMap::new()),
            cached_bytes_on_disk: AtomicU64::new(DISK_USAGE_STALE),
            memory: Mutex::new(HashMap::new()),
            remote: None,
            mem_hits: AtomicU64::new(0),
            remote_hits: AtomicU64::new(0),
        }
    }

    /// Build a cache rooted at `cache_dir` when `enabled`, otherwise disabled.
    ///
    /// When `cache_dir` is `None` and no private per-user cache directory can be
    /// resolved (`XDG_CACHE_HOME` / `HOME` both unset), the cache is **disabled**
    /// rather than falling back to a predictable world-writable path such as
    /// `/tmp/intermed` (a cache-poisoning vector). An explicit `cache_dir` is
    /// always honoured.
    ///
    /// Returns an error when the cache root cannot be created (e.g. permission denied).
    pub fn new(enabled: bool, cache_dir: Option<PathBuf>) -> io::Result<Self> {
        Self::new_with_config(enabled, cache_dir, JarCacheConfig::default())
    }

    /// Like [`new`](Self::new) but with an explicit soft size cap (`--cache-max-size`).
    /// `max_bytes` is clamped up to a small floor so a misconfigured tiny value
    /// cannot prune the cache into uselessness on every run.
    pub fn new_with_limits(
        enabled: bool,
        cache_dir: Option<PathBuf>,
        max_bytes: u64,
    ) -> io::Result<Self> {
        Self::new_with_config(
            enabled,
            cache_dir,
            JarCacheConfig::default().with_max_bytes(max_bytes),
        )
    }

    /// Full control over cache limits (age, size, prune cadence, fingerprint TTL).
    pub fn new_with_config(
        enabled: bool,
        cache_dir: Option<PathBuf>,
        config: JarCacheConfig,
    ) -> io::Result<Self> {
        if !enabled {
            return Ok(Self::disabled());
        }
        let base = match cache_dir.or_else(default_cache_root) {
            Some(base) => base,
            None => return Ok(Self::disabled()),
        };
        let root = base.join("jars");
        fs::create_dir_all(&root)?;
        let cache = Self {
            root,
            enabled: true,
            config,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            fast_hits: AtomicU64::new(0),
            coalesced: AtomicU64::new(0),
            write_locks: new_write_locks(),
            inflight: Mutex::new(HashMap::new()),
            cached_bytes_on_disk: AtomicU64::new(DISK_USAGE_STALE),
            memory: Mutex::new(HashMap::new()),
            remote: None,
            mem_hits: AtomicU64::new(0),
            remote_hits: AtomicU64::new(0),
        };
        let _ = cache.maybe_prune();
        Ok(cache)
    }

    /// Attach a remote cache tier (Tier 3). Consumed builder-style; `None`-by
    /// default keeps the cache local-only. A disabled cache ignores the tier.
    #[must_use]
    pub fn with_remote(mut self, remote: Arc<dyn RemoteCacheTier>) -> Self {
        if self.enabled {
            self.remote = Some(remote);
        }
        self
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
            fast_hits: self.fast_hits.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            mem_hits: self.mem_hits.load(Ordering::Relaxed),
            remote_hits: self.remote_hits.load(Ordering::Relaxed),
            bytes_on_disk: 0,
        }
    }

    /// [`stats`](Self::stats) plus a freshly measured on-disk size. Separate
    /// because the size requires a directory walk; callers that only want the
    /// in-memory counters (the hot path) should use `stats`.
    #[must_use]
    pub fn stats_with_disk_usage(&self) -> CacheStats {
        CacheStats {
            bytes_on_disk: self.disk_usage(),
            ..self.stats()
        }
    }

    /// Total bytes occupied by cache + fingerprint files on disk.
    ///
    /// The result is lazily measured on the first call and then kept up to date
    /// incrementally: writes add their payload size, pruning invalidates. A full
    /// directory walk is only repeated when the cached value has been marked stale
    /// (e.g. after pruning or when the `JarCache` is newly constructed).
    #[must_use]
    pub fn disk_usage(&self) -> u64 {
        if !self.enabled {
            return 0;
        }
        let cached = self.cached_bytes_on_disk.load(Ordering::Relaxed);
        if cached != DISK_USAGE_STALE {
            return cached;
        }
        let measured = disk_usage(&self.root);
        self.cached_bytes_on_disk.store(measured, Ordering::Relaxed);
        measured
    }

    /// Return a cached payload or run `scan`, persisting the result on miss.
    ///
    /// `cache_version` is the calling collector's logic version. It participates
    /// in both the cache key and record validation, so a collector whose scan
    /// logic changed will miss the cache even when the jar content (and SHA-256)
    /// is unchanged. See the module docs for the rationale.
    pub fn get_or_scan<T, F>(
        &self,
        collector_id: &str,
        cache_version: &str,
        jar: &Path,
        scan: F,
    ) -> T
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce() -> T,
    {
        if !self.enabled {
            return scan();
        }

        let meta = match fs::metadata(jar) {
            Ok(m) => m,
            Err(_) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return scan();
            }
        };
        let (mtime_secs, mtime_nanos) = file_mtime(&meta);
        let size_bytes = meta.len();

        let fp = self.fingerprints();
        let (sha256, from_fingerprint) =
            match fp.resolve_sha256(collector_id, jar, mtime_secs, mtime_nanos, size_bytes) {
                Some(pair) => pair,
                None => {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return scan();
                }
            };

        // A fingerprint-derived sha may be stale, so it bypasses the memory tier; a
        // freshly-computed sha is trustworthy and keeps the duplicate-content win.
        let first = if from_fingerprint {
            self.try_load_cached_fingerprint(collector_id, cache_version, &sha256)
        } else {
            self.try_load_cached(collector_id, cache_version, &sha256)
        };
        if let Some(payload) = first {
            if from_fingerprint {
                self.fast_hits.fetch_add(1, Ordering::Relaxed);
            }
            let _ = fp.save(
                collector_id,
                jar,
                mtime_secs,
                mtime_nanos,
                size_bytes,
                &sha256,
            );
            return payload;
        }

        let sha256 = if from_fingerprint {
            match sha256_file(jar) {
                Ok(s) => s,
                Err(_) => {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return scan();
                }
            }
        } else {
            sha256
        };

        if let Some(payload) = self.try_load_cached(collector_id, cache_version, &sha256) {
            let _ = fp.save(
                collector_id,
                jar,
                mtime_secs,
                mtime_nanos,
                size_bytes,
                &sha256,
            );
            return payload;
        }

        let key = inflight_key(collector_id, cache_version, &sha256);
        let gate = self.acquire_gate(&key);
        let _flight = InflightGuard { cache: self, key };
        let _scan_guard = gate.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(payload) = self.read_cached(collector_id, cache_version, &sha256) {
            self.coalesced.fetch_add(1, Ordering::Relaxed);
            let _ = fp.save(
                collector_id,
                jar,
                mtime_secs,
                mtime_nanos,
                size_bytes,
                &sha256,
            );
            return payload;
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        let payload = scan();
        let _ = self.write_record(
            collector_id,
            cache_version,
            jar,
            &sha256,
            mtime_secs,
            mtime_nanos,
            size_bytes,
            &payload,
        );
        let _ = fp.save(
            collector_id,
            jar,
            mtime_secs,
            mtime_nanos,
            size_bytes,
            &sha256,
        );
        payload
    }

    fn fingerprints(&self) -> FingerprintManager<'_> {
        FingerprintManager::new(
            &self.root,
            &self.write_locks,
            self.config.fingerprint_reverify_ttl,
        )
    }

    fn acquire_gate(&self, key: &str) -> Arc<Mutex<()>> {
        let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn read_cached<T: Serialize + DeserializeOwned>(
        &self,
        collector_id: &str,
        cache_version: &str,
        sha256: &str,
    ) -> Option<T> {
        // The true-sha path trusts the memory tier; see `read_cached_fingerprint`.
        let text = self.read_cached_text(collector_id, cache_version, sha256, true)?;
        parse_record::<T>(&text, sha256, cache_version)
    }

    /// Like [`read_cached`], but for the **fingerprint fast-path**, where the sha
    /// is derived from a (mtime+size) fingerprint that may be *stale* if a file's
    /// content changed without its mtime/size. The memory tier is bypassed here so
    /// that a stale-sha lookup behaves exactly like the disk tier (which the prune
    /// / eviction safety relies on); the memory tier is only trusted once the sha
    /// has been freshly computed from the file's actual bytes.
    fn read_cached_fingerprint<T: Serialize + DeserializeOwned>(
        &self,
        collector_id: &str,
        cache_version: &str,
        sha256: &str,
    ) -> Option<T> {
        let text = self.read_cached_text(collector_id, cache_version, sha256, false)?;
        parse_record::<T>(&text, sha256, cache_version)
    }

    /// Tiered fetch of a cache-record's JSON text: **memory → disk → remote**.
    /// A hit in a slower tier warms the faster ones; a disk hit also *promotes*
    /// the entry (LRU bump) so pruning keeps hot content longer. `allow_memory`
    /// gates the (untrusted-sha) fingerprint path out of the memory tier.
    fn read_cached_text(
        &self,
        collector_id: &str,
        cache_version: &str,
        sha256: &str,
        allow_memory: bool,
    ) -> Option<String> {
        let key = inflight_key(collector_id, cache_version, sha256);

        // Tier 1 — memory (only on the trusted-sha path).
        if allow_memory {
            if let Some(text) = self.memory.lock().ok().and_then(|m| m.get(&key).cloned()) {
                self.mem_hits.fetch_add(1, Ordering::Relaxed);
                return Some(text);
            }
        }

        // Tier 2 — disk.
        let path = self.cache_path(collector_id, cache_version, sha256);
        if let Ok(text) = fs::read_to_string(&path) {
            self.promote_on_hit(&path);
            self.mem_put(&key, &text);
            return Some(text);
        }

        // Tier 3 — remote (validated before it is allowed to populate the disk).
        if let Some(remote) = &self.remote {
            if let Some(bytes) = remote.get(&key) {
                if let Ok(text) = String::from_utf8(bytes) {
                    if record_header_valid(&text, sha256, cache_version) {
                        self.remote_hits.fetch_add(1, Ordering::Relaxed);
                        let _ = self.write_text_to_disk(sha256, &path, &text);
                        self.mem_put(&key, &text);
                        return Some(text);
                    }
                }
            }
        }
        None
    }

    /// Insert a record's text into the bounded memory tier.
    fn mem_put(&self, key: &str, text: &str) {
        if let Ok(mut map) = self.memory.lock() {
            if map.len() >= MEM_CACHE_CAP {
                map.clear(); // disk remains the source of truth — a clear only costs re-reads
            }
            map.insert(key.to_string(), text.to_string());
        }
    }

    /// LRU promotion: bump a cache file's mtime so the oldest-first prune keeps
    /// recently-used ("hot") entries longer. Debounced via [`PROMOTE_DEBOUNCE_SECS`]
    /// so a run full of repeat hits does not rewrite metadata on every access.
    fn promote_on_hit(&self, path: &Path) {
        if let Ok(meta) = fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().map(|e| e.as_secs()).unwrap_or(u64::MAX)
                    < PROMOTE_DEBOUNCE_SECS
                {
                    return;
                }
            }
        }
        if let Ok(file) = fs::OpenOptions::new().write(true).open(path) {
            let _ = file.set_modified(std::time::SystemTime::now());
        }
    }

    /// Persist record text fetched from the remote tier into the disk tier.
    fn write_text_to_disk(&self, sha256: &str, path: &Path, text: &str) -> io::Result<()> {
        let _guard = self.write_locks[shard_index(sha256)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_atomic(path, text.as_bytes())?;
        // Disk size is lazily measured; a remote-populated write is reconciled on
        // the next disk_usage() walk or prune, so the counter is left untouched.
        Ok(())
    }

    fn try_load_cached<T: Serialize + DeserializeOwned>(
        &self,
        collector_id: &str,
        cache_version: &str,
        sha256: &str,
    ) -> Option<T> {
        let payload = self.read_cached(collector_id, cache_version, sha256)?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(payload)
    }

    /// [`try_load_cached`](Self::try_load_cached) for the fingerprint fast-path
    /// (memory tier bypassed — the sha may be stale).
    fn try_load_cached_fingerprint<T: Serialize + DeserializeOwned>(
        &self,
        collector_id: &str,
        cache_version: &str,
        sha256: &str,
    ) -> Option<T> {
        let payload = self.read_cached_fingerprint(collector_id, cache_version, sha256)?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(payload)
    }

    fn cache_path(&self, collector_id: &str, cache_version: &str, sha256: &str) -> PathBuf {
        let prefix = sha256.get(..2).unwrap_or("00");
        self.root
            .join(collector_id)
            .join(sanitize_segment(cache_version))
            .join(prefix)
            .join(format!("{sha256}.json"))
    }

    #[allow(clippy::too_many_arguments)]
    fn write_record<T: Serialize>(
        &self,
        collector_id: &str,
        cache_version: &str,
        jar: &Path,
        sha256: &str,
        mtime_secs: u64,
        mtime_nanos: u32,
        size_bytes: u64,
        payload: &T,
    ) -> io::Result<()> {
        let _guard = self.write_locks[shard_index(sha256)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path = self.cache_path(collector_id, cache_version, sha256);
        let old_size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let record = CacheRecord {
            schema: CACHE_SCHEMA.to_string(),
            collector: collector_id.to_string(),
            cache_version: cache_version.to_string(),
            jar_path: jar.display().to_string(),
            mtime_secs,
            mtime_nanos,
            size_bytes,
            sha256: sha256.to_string(),
            payload,
        };
        let text = serde_json::to_string_pretty(&record)?;
        write_atomic(&path, text.as_bytes())?;
        self.writes.fetch_add(1, Ordering::Relaxed);
        // Populate the faster/shared tiers so a re-lookup this run hits memory and
        // other machines can hit the remote store.
        let key = inflight_key(collector_id, cache_version, sha256);
        self.mem_put(&key, &text);
        if let Some(remote) = &self.remote {
            remote.put(&key, text.as_bytes());
        }
        // Incrementally update the cached disk size so disk_usage() stays
        // accurate without a full walk after each write. Only update when
        // the cache has been measured (sentinel = stale means skip).
        let written = text.len() as u64;
        let prev = self.cached_bytes_on_disk.load(Ordering::Relaxed);
        if prev != DISK_USAGE_STALE {
            if written > old_size {
                self.cached_bytes_on_disk
                    .fetch_add(written - old_size, Ordering::Relaxed);
            } else if old_size > written {
                self.cached_bytes_on_disk
                    .fetch_sub(old_size - written, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn maybe_prune(&self) -> io::Result<()> {
        let freed = maybe_prune(&self.root, &self.config)?;
        if freed > 0 {
            // Pruning changed the on-disk layout; invalidate the cached size.
            self.cached_bytes_on_disk
                .store(DISK_USAGE_STALE, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Force a prune pass using the configured age and size limits.
    ///
    /// Returns bytes freed from disk. No-op when the cache is disabled.
    pub fn prune_now(&self) -> io::Result<u64> {
        if !self.enabled {
            return Ok(0);
        }
        let freed = prune::prune_stale_entries(&self.root, &self.config)?;
        if freed > 0 {
            self.cached_bytes_on_disk
                .store(DISK_USAGE_STALE, Ordering::Relaxed);
        }
        Ok(freed)
    }

    /// Delete all cache payload and fingerprint files under this cache root.
    ///
    /// Returns bytes removed. Counter atomics are not reset (they reflect the
    /// current process session only).
    pub fn clear_all(&self) -> io::Result<u64> {
        if !self.enabled || !self.root.exists() {
            return Ok(0);
        }
        let bytes = disk_usage(&self.root);
        fs::remove_dir_all(&self.root)?;
        fs::create_dir_all(&self.root)?;
        self.cached_bytes_on_disk.store(0, Ordering::Relaxed);
        Ok(bytes)
    }

    /// On-disk cache root (`.../jars` under the configured base).
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(test)]
    fn prune_stale_entries(&self) -> io::Result<()> {
        let freed = prune::prune_stale_entries(&self.root, &self.config)?;
        if freed > 0 {
            self.cached_bytes_on_disk
                .store(DISK_USAGE_STALE, Ordering::Relaxed);
        }
        Ok(())
    }

    #[cfg(test)]
    fn fingerprint_path(&self, collector_id: &str, jar: &Path) -> PathBuf {
        self.fingerprints().path(collector_id, jar)
    }
}

fn inflight_key(collector_id: &str, cache_version: &str, sha256: &str) -> String {
    format!("{collector_id}\0{cache_version}\0{sha256}")
}

/// Parse a cache-record's JSON text into its payload, validating the schema, the
/// content SHA-256, and the collector logic version. Shared by every tier.
fn parse_record<T: DeserializeOwned>(text: &str, sha256: &str, cache_version: &str) -> Option<T> {
    let record = serde_json::from_str::<CacheRecord<T>>(text).ok()?;
    if record.schema != CACHE_SCHEMA
        || record.sha256 != sha256
        || record.cache_version != cache_version
    {
        return None;
    }
    Some(record.payload)
}

/// Validate a record's header (schema / sha / version) without knowing its
/// payload type — used to gate untrusted remote-tier bytes before they are
/// allowed to populate the local disk cache.
fn record_header_valid(text: &str, sha256: &str, cache_version: &str) -> bool {
    parse_record::<serde_json::Value>(text, sha256, cache_version).is_some()
}

struct InflightGuard<'a> {
    cache: &'a JarCache,
    key: String,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        let mut map = self
            .cache
            .inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        map.remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn find_payload_cache_file(cache_root: &Path, collector_id: &str) -> Option<PathBuf> {
        let mut stack = vec![cache_root.join(collector_id)];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(&dir).ok()?;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if path.file_name().and_then(|n| n.to_str()) != Some("fp") {
                        stack.push(path);
                    }
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    return Some(path);
                }
            }
        }
        None
    }

    fn set_mtime(path: &Path, spec: &str) {
        std::process::Command::new("touch")
            .args(["-d", spec, path.to_str().unwrap()])
            .status()
            .expect("touch mtime");
    }

    fn temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("intermed-cache-test-{label}-{nanos}"))
    }

    #[test]
    fn cache_hit_and_mtime_refresh() {
        let root = temp_root("hit");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"payload-v1").unwrap();

        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let first: String =
            cache.get_or_scan("metadata-scanner", "v1", &jar, || "scanned".to_string());
        assert_eq!(first, "scanned");
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().writes, 1);

        let second: String =
            cache.get_or_scan("metadata-scanner", "v1", &jar, || "again".to_string());
        assert_eq!(second, "scanned");
        assert_eq!(cache.stats().hits, 1);
        assert!(cache.stats().fast_hits >= 1);

        std::thread::sleep(Duration::from_millis(1100));
        fs::write(&jar, b"payload-v1").unwrap();
        let third: String =
            cache.get_or_scan("metadata-scanner", "v1", &jar, || "again".to_string());
        assert_eq!(third, "scanned");
        assert_eq!(cache.stats().hits, 2);
    }

    #[test]
    fn logic_version_bump_invalidates_identical_content() {
        let root = temp_root("logic-version");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"sodium-bytes").unwrap();

        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let v1: String = cache.get_or_scan("mixin-analyzer", "0.1.0", &jar, || "parsed-old".into());
        assert_eq!(v1, "parsed-old");

        let v2: String = cache.get_or_scan("mixin-analyzer", "0.1.1", &jar, || "parsed-new".into());
        assert_eq!(v2, "parsed-new");

        let again_old: String =
            cache.get_or_scan("mixin-analyzer", "0.1.0", &jar, || "unexpected".into());
        assert_eq!(again_old, "parsed-old");

        let again_new: String =
            cache.get_or_scan("mixin-analyzer", "0.1.1", &jar, || "unexpected".into());
        assert_eq!(again_new, "parsed-new");
    }

    #[test]
    fn disabled_cache_always_scans() {
        let root = temp_root("disabled");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"x").unwrap();
        let cache = JarCache::disabled();
        let mut calls = 0u8;
        assert_eq!(
            cache.get_or_scan("c", "v1", &jar, || {
                calls += 1;
                calls
            }),
            1
        );
        assert_eq!(
            cache.get_or_scan("c", "v1", &jar, || {
                calls += 1;
                calls
            }),
            2
        );
        assert_eq!(cache.stats().hits, 0);
    }

    #[test]
    fn content_change_invalidates_by_sha() {
        let root = temp_root("sha");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"v1").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let _: u8 = cache.get_or_scan("c", "v1", &jar, || 1);

        fs::write(&jar, b"v2").unwrap();
        let v: u8 = cache.get_or_scan("c", "v1", &jar, || 2);
        assert_eq!(v, 2);
        assert_eq!(cache.stats().misses, 2);
    }

    #[test]
    fn fingerprint_avoids_sha_on_repeat_lookup() {
        let root = temp_root("fp");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"stable").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let _: u8 = cache.get_or_scan("c", "v1", &jar, || 1);
        let stats_after_first = cache.stats();
        assert_eq!(stats_after_first.fast_hits, 0);

        let _: u8 = cache.get_or_scan("c", "v1", &jar, || 2);
        assert_eq!(cache.stats().fast_hits, 1);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn new_fails_when_cache_root_not_creatable() {
        let blocked = temp_root("blocked");
        fs::create_dir_all(&blocked).unwrap();
        fs::write(blocked.join("jars"), b"not-a-dir").unwrap();
        assert!(JarCache::new(true, Some(blocked)).is_err());
    }

    #[test]
    fn prune_removes_very_old_entries() {
        let root = temp_root("prune");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"x").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let _: u8 = cache.get_or_scan("c", "v1", &jar, || 1);

        let stale = find_payload_cache_file(&root.join("jars"), "c").expect("cache file");
        std::process::Command::new("touch")
            .args(["-d", "@1", stale.to_str().unwrap()])
            .status()
            .expect("touch stale cache file");

        cache.prune_stale_entries().unwrap();
        assert!(!stale.exists());
    }

    #[test]
    fn metadata_only_touch_does_not_rewrite_payload() {
        let root = temp_root("touch-no-rewrite");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"stable-bytes").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();

        let _: u8 = cache.get_or_scan("c", "v1", &jar, || 1);
        assert_eq!(cache.stats().writes, 1);

        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(1100));
            fs::write(&jar, b"stable-bytes").unwrap();
            let v: u8 = cache.get_or_scan("c", "v1", &jar, || 99);
            assert_eq!(v, 1, "must serve cached payload");
        }
        assert_eq!(cache.stats().writes, 1);
        assert!(cache.stats().hits >= 3);
    }

    #[test]
    fn fast_hits_not_inflated_by_logic_version_miss() {
        let root = temp_root("fast-hit-accuracy");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"bytes").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();

        let _: u8 = cache.get_or_scan("c", "0.1.0", &jar, || 1);
        assert_eq!(cache.stats().fast_hits, 0);

        let v: u8 = cache.get_or_scan("c", "0.1.1", &jar, || 2);
        assert_eq!(v, 2);
        assert_eq!(
            cache.stats().fast_hits,
            0,
            "logic-version miss is not a fast hit"
        );
    }

    #[test]
    fn payload_files_are_valid_json_after_write() {
        let root = temp_root("atomic");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"bytes").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let _: u8 = cache.get_or_scan("c", "v1", &jar, || 7);

        let file = find_payload_cache_file(&root.join("jars"), "c").expect("cache file");
        let text = fs::read_to_string(&file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert_eq!(parsed["schema"], CACHE_SCHEMA);
        let dir = file.parent().unwrap();
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(!name.contains(".tmp-"), "stray temp file: {name}");
        }
    }

    #[test]
    fn single_flight_coalesces_concurrent_scans_of_one_jar() {
        use std::sync::Barrier;
        use std::sync::atomic::AtomicUsize;

        let root = temp_root("single-flight");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"contended-bytes").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();

        const THREADS: usize = 16;
        let scan_calls = AtomicUsize::new(0);
        let barrier = Barrier::new(THREADS);

        let results: Vec<u32> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        cache.get_or_scan("c", "v1", &jar, || {
                            scan_calls.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(Duration::from_millis(50));
                            42u32
                        })
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        assert!(results.iter().all(|&v| v == 42));
        assert_eq!(scan_calls.load(Ordering::Relaxed), 1, "scan must run once");

        let stats = cache.stats();
        assert_eq!(stats.misses, 1, "only the producer counts a miss");
        assert_eq!(
            stats.coalesced + stats.hits,
            (THREADS - 1) as u64,
            "all other threads reused the result"
        );
    }

    #[test]
    fn jar_deleted_during_scan_does_not_panic() {
        let root = temp_root("delete-during-scan");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"doomed").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();

        let v: u8 = cache.get_or_scan("c", "v1", &jar, || {
            fs::remove_file(&jar).unwrap();
            7
        });
        assert_eq!(v, 7);

        let again: u8 = cache.get_or_scan("c", "v1", &jar, || 9);
        assert_eq!(again, 9);
    }

    #[test]
    fn stale_fingerprint_with_evicted_payload_rehashes_to_correct_content() {
        let root = temp_root("stale-fp");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        let fixed_mtime = "@1700000000";

        fs::write(&jar, b"aaaa").unwrap();
        set_mtime(&jar, fixed_mtime);
        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let v1: u8 = cache.get_or_scan("c", "v1", &jar, || 1);
        assert_eq!(v1, 1);

        let payload_file = find_payload_cache_file(&root.join("jars"), "c").expect("payload");
        fs::remove_file(&payload_file).unwrap();

        fs::write(&jar, b"bbbb").unwrap();
        set_mtime(&jar, fixed_mtime);

        let v2: u8 = cache.get_or_scan("c", "v1", &jar, || 2);
        assert_eq!(v2, 2, "must reflect new content, not the stale payload");
        assert_eq!(cache.stats().fast_hits, 0);
    }

    #[test]
    fn expired_fingerprint_is_reverified_by_rehash() {
        let root = temp_root("fp-ttl");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        let fixed = "@1700000000";
        fs::write(&jar, b"aaaa").unwrap();
        set_mtime(&jar, fixed);
        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let v1: u8 = cache.get_or_scan("c", "v1", &jar, || 1);
        assert_eq!(v1, 1);

        let fp_path = cache.fingerprint_path("c", &jar);
        let mut fp: fingerprint::FingerprintRecord =
            serde_json::from_str(&fs::read_to_string(&fp_path).unwrap()).unwrap();
        fp.last_verified_secs = 0;
        fs::write(&fp_path, serde_json::to_string(&fp).unwrap()).unwrap();

        fs::write(&jar, b"bbbb").unwrap();
        set_mtime(&jar, fixed);
        let v2: u8 = cache.get_or_scan("c", "v1", &jar, || 2);
        assert_eq!(v2, 2, "expired fingerprint must be re-hashed");
    }

    #[test]
    fn scan_panic_does_not_poison_the_cache() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let root = temp_root("scan-panic");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"bytes").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();

        let panicked = catch_unwind(AssertUnwindSafe(|| {
            let _: u8 = cache.get_or_scan("c", "v1", &jar, || panic!("scan blew up"));
        }));
        assert!(panicked.is_err(), "the panic propagates to the caller");

        let v: u8 = cache.get_or_scan("c", "v1", &jar, || 5);
        assert_eq!(v, 5);
    }

    #[test]
    fn cache_max_size_is_honoured_and_floored() {
        let root = temp_root("max-size");
        fs::create_dir_all(&root).unwrap();
        let tiny = JarCache::new_with_limits(true, Some(root.join("a")), 1).unwrap();
        assert_eq!(tiny.config.max_bytes, DEFAULT_CACHE_MIN_BYTES);
        let sane = JarCache::new_with_limits(true, Some(root.join("b")), 64 * 1024 * 1024).unwrap();
        assert_eq!(sane.config.max_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn disk_usage_counts_written_payloads() {
        let root = temp_root("disk-usage");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"bytes").unwrap();
        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        assert_eq!(cache.disk_usage(), 0);
        let _: u8 = cache.get_or_scan("c", "v1", &jar, || 1);
        assert!(cache.disk_usage() > 0);
        assert_eq!(
            cache.stats_with_disk_usage().bytes_on_disk,
            cache.disk_usage()
        );
    }

    #[test]
    fn default_cache_root_never_returns_world_writable_tmp() {
        if let Some(base) = default_cache_root() {
            assert!(base != Path::new("/tmp/intermed"));
            assert!(base != Path::new("/tmp"));
        }
        assert!(JarCache::new(true, None).is_ok());
    }

    #[test]
    fn memory_tier_serves_duplicate_content_without_disk() {
        // Two different jars with byte-identical content hash to the same key; the
        // second lookup is served from the in-process memory tier.
        let root = temp_root("memtier");
        fs::create_dir_all(&root).unwrap();
        let a = root.join("a.jar");
        let b = root.join("b.jar");
        fs::write(&a, b"identical-content").unwrap();
        fs::write(&b, b"identical-content").unwrap();

        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let v1: u8 = cache.get_or_scan("c", "v1", &a, || 7);
        assert_eq!(v1, 7);
        assert_eq!(cache.stats().mem_hits, 0);

        // b has no fingerprint, so its sha is freshly computed (trusted) → memory hit.
        let v2: u8 = cache.get_or_scan("c", "v1", &b, || 99);
        assert_eq!(v2, 7, "served the cached payload, not a fresh scan");
        assert_eq!(cache.stats().mem_hits, 1);
    }

    #[test]
    fn remote_tier_shares_payloads_across_cache_roots() {
        use crate::jar_cache::LocalDirRemoteTier;
        use std::sync::Arc;

        let base = temp_root("remotetier");
        fs::create_dir_all(&base).unwrap();
        let remote_dir = base.join("remote");
        let jar = base.join("mod.jar");
        fs::write(&jar, b"shared-payload").unwrap();

        // Machine A: scans and pushes to the remote tier.
        let remote_a = Arc::new(LocalDirRemoteTier::new(&remote_dir));
        let cache_a = JarCache::new(true, Some(base.join("a")))
            .unwrap()
            .with_remote(remote_a);
        let v: u8 = cache_a.get_or_scan("c", "v1", &jar, || 42);
        assert_eq!(v, 42);
        assert_eq!(cache_a.stats().writes, 1);

        // Machine B: cold local cache, same remote → hits the remote, no scan.
        let remote_b = Arc::new(LocalDirRemoteTier::new(&remote_dir));
        let cache_b = JarCache::new(true, Some(base.join("b")))
            .unwrap()
            .with_remote(remote_b);
        let mut scanned = false;
        let v2: u8 = cache_b.get_or_scan("c", "v1", &jar, || {
            scanned = true;
            0
        });
        assert_eq!(v2, 42, "served from the remote tier");
        assert!(!scanned, "remote hit must avoid the local scan");
        assert_eq!(cache_b.stats().remote_hits, 1);
    }

    #[test]
    fn disk_hit_promotes_mtime_for_lru_pruning() {
        let root = temp_root("promote");
        let jar = root.join("mod.jar");
        fs::create_dir_all(&root).unwrap();
        fs::write(&jar, b"content").unwrap();

        let cache = JarCache::new(true, Some(root.clone())).unwrap();
        let _: u8 = cache.get_or_scan("c", "v1", &jar, || 1);
        let payload = find_payload_cache_file(&root.join("jars"), "c").expect("payload");
        // Age the payload file well past the promote debounce.
        set_mtime(&payload, "@1700000000");
        let before = fs::metadata(&payload).unwrap().modified().unwrap();

        // A disk hit (drop the in-process cache so it re-reads disk) promotes mtime.
        let cache2 = JarCache::new(true, Some(root.clone())).unwrap();
        let v: u8 = cache2.get_or_scan("c", "v1", &jar, || 2);
        assert_eq!(v, 1, "served the cached payload");
        let after = fs::metadata(&payload).unwrap().modified().unwrap();
        assert!(
            after > before,
            "hot entry's mtime was bumped (LRU promotion)"
        );
    }
}
