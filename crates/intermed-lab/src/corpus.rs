//! Corpus candidates → reproducible corpus lock.
//!
//! The lab's reproducibility guarantee rests on a *lock*: a deterministic,
//! content-addressed pinning of the exact mod versions an environment was tested
//! against. This module owns the pure selection/dedup/lock logic (the rewritten
//! `CorpusLockBuilder` donor). Fetching candidates from the network
//! (`ModrinthClient`) is intentionally **not** here — it is a pluggable
//! [`CandidateProvider`] so the deterministic core stays offline-testable.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{LabError, read_json, write_json_atomic};

/// Schema tag for the candidate-pool input.
pub const CORPUS_CANDIDATES_SCHEMA: &str = "intermed-corpus-candidates-v1";
/// Schema tag for the emitted lock.
pub const CORPUS_LOCK_SCHEMA: &str = "intermed-corpus-lock-v1";

/// The environment a corpus is pinned for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CorpusEnvironment {
    /// Mod loader (`fabric`, `forge`, `neoforge`, `quilt`).
    pub loader: String,
    /// Minecraft version (`1.20.1`).
    pub mc_version: String,
    /// `client`, `server`, or `both`.
    #[serde(default = "default_side")]
    pub side: String,
}

fn default_side() -> String {
    "both".to_string()
}

/// One candidate mod considered for inclusion in a corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateMod {
    pub project_id: String,
    pub version_id: String,
    pub file_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    /// Popularity signal used only to break ties when the same project appears
    /// twice (mirrors the old Modrinth 50%-downloads weighting).
    #[serde(default)]
    pub downloads: u64,
}

/// A candidate pool, as produced by discovery (network or hand-authored).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusCandidates {
    pub schema: String,
    pub environment: CorpusEnvironment,
    #[serde(default)]
    pub candidates: Vec<CandidateMod>,
}

/// A single pinned mod in a lock (no popularity signal — locks are exact).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockedMod {
    pub project_id: String,
    pub version_id: String,
    pub file_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
}

/// A reproducible, content-addressed corpus lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusLock {
    pub schema: String,
    pub environment: CorpusEnvironment,
    /// Pinned mods, deduped by project and sorted for determinism.
    pub mods: Vec<LockedMod>,
    /// SHA-256 over the canonical lock contents — the lock's identity. Two locks
    /// with this digest pin the exact same corpus for the exact same environment.
    pub digest: String,
}

/// Source of candidate mods. The default ([`FileCandidateProvider`]) reads a
/// hand-authored / pre-fetched pool; a networked Modrinth provider is a deferred
/// donor (see crate docs) and would implement this same trait.
pub trait CandidateProvider {
    fn candidates(&self) -> Result<CorpusCandidates, LabError>;
}

/// Reads a candidate pool from an `intermed-corpus-candidates-v1` JSON file.
pub struct FileCandidateProvider<'a> {
    pub path: &'a Path,
}

impl CandidateProvider for FileCandidateProvider<'_> {
    fn candidates(&self) -> Result<CorpusCandidates, LabError> {
        let candidates: CorpusCandidates = read_json(self.path)?;
        if candidates.schema != CORPUS_CANDIDATES_SCHEMA {
            return Err(LabError::schema(
                self.path,
                CORPUS_CANDIDATES_SCHEMA,
                &candidates.schema,
            ));
        }
        Ok(candidates)
    }
}

impl CorpusLock {
    /// Build a deterministic lock from a candidate pool.
    ///
    /// Selection is pure and reproducible:
    /// * duplicate `project_id`s collapse to one entry, keeping the higher
    ///   `downloads` (ties broken by the lexicographically smaller `version_id`);
    /// * the result is sorted by `project_id`;
    /// * a SHA-256 [`digest`](CorpusLock::digest) is computed over the canonical
    ///   pinned set so the lock is content-addressed.
    #[must_use]
    pub fn from_candidates(candidates: &CorpusCandidates) -> Self {
        let mut best: BTreeMap<&str, &CandidateMod> = BTreeMap::new();
        for c in &candidates.candidates {
            best.entry(&c.project_id)
                .and_modify(|cur| {
                    if c.downloads > cur.downloads
                        || (c.downloads == cur.downloads && c.version_id < cur.version_id)
                    {
                        *cur = c;
                    }
                })
                .or_insert(c);
        }

        let mods: Vec<LockedMod> = best
            .values()
            .map(|c| LockedMod {
                project_id: c.project_id.clone(),
                version_id: c.version_id.clone(),
                file_name: c.file_name.clone(),
                sha512: c.sha512.clone(),
                download_url: c.download_url.clone(),
            })
            .collect();

        let digest = lock_digest(&candidates.environment, &mods);
        CorpusLock {
            schema: CORPUS_LOCK_SCHEMA.to_string(),
            environment: candidates.environment.clone(),
            mods,
            digest,
        }
    }

    /// Recompute the digest and verify it matches the stored one (lock integrity).
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.digest == lock_digest(&self.environment, &self.mods)
    }
}

/// Canonical content digest: environment + each pinned
/// `project_id@version_id#sha512` (sorted), independent of JSON formatting.
///
/// The artifact hash is part of the digest on purpose. The lock is sold as a
/// *supply-chain* guarantee ("two locks with one digest pin the exact same
/// corpus"), so it must address *content*, not just coordinates. With only
/// `project_id@version_id`, an artifact re-uploaded under the same `version_id`
/// with a different payload would still match — the precise substitution attack
/// the lock claims to stop. The `CandidateProvider` trait is provider-agnostic
/// (Modrinth's immutable `version_id` is not guaranteed elsewhere), and `sha512`
/// exists specifically to pin content, so it is folded in here. Mods without a
/// known hash contribute an empty field, leaving them coordinate-pinned only.
fn lock_digest(env: &CorpusEnvironment, mods: &[LockedMod]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(env.loader.as_bytes());
    hasher.update(b"\0");
    hasher.update(env.mc_version.as_bytes());
    hasher.update(b"\0");
    hasher.update(env.side.as_bytes());
    hasher.update(b"\n");
    let mut lines: Vec<String> = mods
        .iter()
        .map(|m| {
            format!(
                "{}@{}#{}",
                m.project_id,
                m.version_id,
                m.sha512.as_deref().unwrap_or("")
            )
        })
        .collect();
    lines.sort();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

/// `lab discover`: build a lock from a candidate provider and write it to `out`.
pub fn discover_lock(provider: &dyn CandidateProvider, out: &Path) -> Result<CorpusLock, LabError> {
    let candidates = provider.candidates()?;
    let lock = CorpusLock::from_candidates(&candidates);
    write_json_atomic(out, &lock)?;
    Ok(lock)
}

/// Load and validate a lock file.
pub fn read_lock(path: &Path) -> Result<CorpusLock, LabError> {
    let lock: CorpusLock = read_json(path)?;
    if lock.schema != CORPUS_LOCK_SCHEMA {
        return Err(LabError::schema(path, CORPUS_LOCK_SCHEMA, &lock.schema));
    }
    if !lock.verify_digest() {
        return Err(LabError::new(format!(
            "corpus lock digest mismatch in {} (file tampered or hand-edited)",
            path.display()
        )));
    }
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> CorpusEnvironment {
        CorpusEnvironment {
            loader: "fabric".into(),
            mc_version: "1.20.1".into(),
            side: "server".into(),
        }
    }

    fn candidate(project: &str, version: &str, downloads: u64) -> CandidateMod {
        CandidateMod {
            project_id: project.into(),
            version_id: version.into(),
            file_name: format!("{project}-{version}.jar"),
            sha512: None,
            download_url: None,
            downloads,
        }
    }

    #[test]
    fn dedup_keeps_most_downloaded_and_sorts() {
        let candidates = CorpusCandidates {
            schema: CORPUS_CANDIDATES_SCHEMA.into(),
            environment: env(),
            candidates: vec![
                candidate("sodium", "v1", 10),
                candidate("sodium", "v2", 99), // higher downloads wins
                candidate("lithium", "a", 5),
            ],
        };
        let lock = CorpusLock::from_candidates(&candidates);
        assert_eq!(lock.mods.len(), 2);
        // Sorted by project id.
        assert_eq!(lock.mods[0].project_id, "lithium");
        assert_eq!(lock.mods[1].project_id, "sodium");
        assert_eq!(lock.mods[1].version_id, "v2");
    }

    #[test]
    fn lock_is_deterministic_regardless_of_input_order() {
        let a = CorpusCandidates {
            schema: CORPUS_CANDIDATES_SCHEMA.into(),
            environment: env(),
            candidates: vec![candidate("a", "1", 1), candidate("b", "2", 2)],
        };
        let b = CorpusCandidates {
            schema: CORPUS_CANDIDATES_SCHEMA.into(),
            environment: env(),
            candidates: vec![candidate("b", "2", 2), candidate("a", "1", 1)],
        };
        assert_eq!(
            CorpusLock::from_candidates(&a).digest,
            CorpusLock::from_candidates(&b).digest
        );
    }

    #[test]
    fn digest_changes_with_environment_and_contents() {
        let base = CorpusCandidates {
            schema: CORPUS_CANDIDATES_SCHEMA.into(),
            environment: env(),
            candidates: vec![candidate("a", "1", 1)],
        };
        let lock_a = CorpusLock::from_candidates(&base);

        let mut diff_env = base.clone();
        diff_env.environment.mc_version = "1.21".into();
        assert_ne!(lock_a.digest, CorpusLock::from_candidates(&diff_env).digest);

        let mut diff_ver = base.clone();
        diff_ver.candidates[0].version_id = "2".into();
        assert_ne!(lock_a.digest, CorpusLock::from_candidates(&diff_ver).digest);

        assert!(lock_a.verify_digest());
    }

    #[test]
    fn digest_pins_content_not_just_coordinates() {
        // Supply-chain substitution: same project_id@version_id, different payload.
        // The digest must change, or verify_digest would bless a swapped artifact.
        let mut a = candidate("a", "1", 1);
        a.sha512 = Some("aaaa".into());
        let base = CorpusCandidates {
            schema: CORPUS_CANDIDATES_SCHEMA.into(),
            environment: env(),
            candidates: vec![a],
        };
        let lock_a = CorpusLock::from_candidates(&base);

        let mut swapped = base.clone();
        swapped.candidates[0].sha512 = Some("bbbb".into());
        let lock_b = CorpusLock::from_candidates(&swapped);

        assert_ne!(lock_a.digest, lock_b.digest);
    }
}
