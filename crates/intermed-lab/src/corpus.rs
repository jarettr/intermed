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
/// Canonical schema tag for the emitted lock.
pub const CORPUS_LOCK_SCHEMA: &str = "intermed-corpus-lock-v3";
pub const CORPUS_LOCK_SCHEMA_V2: &str = "intermed-corpus-lock-v2";
pub const CORPUS_LOCK_SCHEMA_V1: &str = "intermed-corpus-lock-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationCompleteness {
    Complete,
    #[default]
    Partial,
}

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
    /// Exact loader version when an authoritative pack manifest declares it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader_version: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LockedPackFile {
    /// Safe path relative to the materialized instance root.
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub downloads: Vec<String>,
    #[serde(default)]
    pub client_required: bool,
    #[serde(default)]
    pub server_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackIdentity {
    pub provider: String,
    pub name: String,
    pub version_id: String,
    pub manifest_sha256: String,
}

/// A reproducible, content-addressed corpus lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusLock {
    pub schema: String,
    pub environment: CorpusEnvironment,
    /// Pinned mods, deduped by project and sorted for determinism.
    pub mods: Vec<LockedMod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<LockedPackFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<PackIdentity>,
    /// Compatibility alias for `lock_manifest_digest` in v3.
    pub digest: String,
    /// Identity of materialized paths and their content hashes. Acquisition URLs
    /// and provider coordinates do not participate.
    #[serde(default)]
    pub content_digest: String,
    /// Identity of the complete canonical lock declaration excluding transport
    /// URLs.
    #[serde(default)]
    pub lock_manifest_digest: String,
    /// Identity of acquisition URLs only. A CDN migration changes this value but
    /// not `content_digest`.
    #[serde(default)]
    pub acquisition_digest: String,
    #[serde(default)]
    pub verification_completeness: VerificationCompleteness,
    #[serde(default)]
    pub unhashed_files: usize,
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

        let digests = lock_digests(&candidates.environment, &mods, &[], None);
        CorpusLock {
            schema: CORPUS_LOCK_SCHEMA.to_string(),
            environment: candidates.environment.clone(),
            mods,
            files: Vec::new(),
            pack: None,
            digest: digests.manifest.clone(),
            content_digest: digests.content,
            lock_manifest_digest: digests.manifest,
            acquisition_digest: digests.acquisition,
            verification_completeness: digests.completeness,
            unhashed_files: digests.unhashed_files,
        }
    }

    /// Recompute the digest and verify it matches the stored one (lock integrity).
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        if self.schema == CORPUS_LOCK_SCHEMA_V1 {
            return self.digest == legacy_lock_digest(&self.environment, &self.mods);
        }
        if self.schema == CORPUS_LOCK_SCHEMA_V2 {
            return self.digest
                == v2_lock_digest(
                    &self.environment,
                    &self.mods,
                    &self.files,
                    self.pack.as_ref(),
                );
        }
        let expected = lock_digests(
            &self.environment,
            &self.mods,
            &self.files,
            self.pack.as_ref(),
        );
        self.digest == expected.manifest
            && self.lock_manifest_digest == expected.manifest
            && self.content_digest == expected.content
            && self.acquisition_digest == expected.acquisition
            && self.verification_completeness == expected.completeness
            && self.unhashed_files == expected.unhashed_files
    }

    #[must_use]
    pub fn from_pack_manifest(
        environment: CorpusEnvironment,
        mut files: Vec<LockedPackFile>,
        pack: PackIdentity,
    ) -> Self {
        files.sort();
        files.dedup();
        let mods = files
            .iter()
            .filter(|file| file.path.starts_with("mods/") && file.path.ends_with(".jar"))
            .map(|file| {
                let file_name = file
                    .path
                    .rsplit('/')
                    .next()
                    .unwrap_or(&file.path)
                    .to_string();
                LockedMod {
                    project_id: file_name.trim_end_matches(".jar").to_string(),
                    version_id: "manifest-pinned".to_string(),
                    file_name,
                    sha512: file.sha512.clone(),
                    download_url: file.downloads.first().cloned(),
                }
            })
            .collect::<Vec<_>>();
        let digests = lock_digests(&environment, &mods, &files, Some(&pack));
        Self {
            schema: CORPUS_LOCK_SCHEMA.to_string(),
            environment,
            mods,
            files,
            pack: Some(pack),
            digest: digests.manifest.clone(),
            content_digest: digests.content,
            lock_manifest_digest: digests.manifest,
            acquisition_digest: digests.acquisition,
            verification_completeness: digests.completeness,
            unhashed_files: digests.unhashed_files,
        }
    }
}

struct LockDigests {
    content: String,
    manifest: String,
    acquisition: String,
    completeness: VerificationCompleteness,
    unhashed_files: usize,
}

fn digest_field(hasher: &mut Sha256, tag: &str, value: &str) {
    hasher.update((tag.len() as u64).to_be_bytes());
    hasher.update(tag.as_bytes());
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn lock_digests(
    env: &CorpusEnvironment,
    mods: &[LockedMod],
    files: &[LockedPackFile],
    pack: Option<&PackIdentity>,
) -> LockDigests {
    let mut content = Sha256::new();
    let mut manifest = Sha256::new();
    let mut acquisition = Sha256::new();
    for hasher in [&mut content, &mut manifest, &mut acquisition] {
        hasher.update(b"intermed-corpus-lock-v3\0");
    }
    for (tag, value) in [
        ("loader", env.loader.as_str()),
        ("minecraft", env.mc_version.as_str()),
        ("side", env.side.as_str()),
        (
            "loader-version",
            env.loader_version.as_deref().unwrap_or(""),
        ),
    ] {
        digest_field(&mut manifest, tag, value);
    }

    let mut unhashed_files = 0usize;
    if files.is_empty() {
        let mut ordered = mods.to_vec();
        ordered.sort();
        for module in &ordered {
            digest_field(&mut content, "path", &module.file_name);
            digest_field(
                &mut content,
                "sha512",
                module.sha512.as_deref().unwrap_or("unverified"),
            );
            if module.sha512.is_none() {
                unhashed_files += 1;
            }
        }
    } else {
        let mut ordered = files.to_vec();
        ordered.sort();
        for file in &ordered {
            digest_field(&mut content, "path", &file.path);
            let hash = file
                .sha512
                .as_deref()
                .map(|value| format!("sha512:{value}"))
                .or_else(|| {
                    file.sha256
                        .as_deref()
                        .map(|value| format!("sha256:{value}"))
                });
            digest_field(
                &mut content,
                "content-hash",
                hash.as_deref().unwrap_or("unverified"),
            );
            if hash.is_none() {
                unhashed_files += 1;
            }
        }
    }
    if let Some(pack) = pack {
        digest_field(&mut content, "manifest-sha256", &pack.manifest_sha256);
    }

    let mut ordered_mods = mods.to_vec();
    ordered_mods.sort();
    for module in &ordered_mods {
        digest_field(&mut manifest, "project", &module.project_id);
        digest_field(&mut manifest, "version", &module.version_id);
        digest_field(&mut manifest, "file", &module.file_name);
        digest_field(
            &mut manifest,
            "sha512",
            module.sha512.as_deref().unwrap_or(""),
        );
        digest_field(
            &mut acquisition,
            "download",
            module.download_url.as_deref().unwrap_or(""),
        );
    }
    let mut ordered_files = files.to_vec();
    ordered_files.sort();
    for file in &ordered_files {
        digest_field(&mut manifest, "path", &file.path);
        digest_field(
            &mut manifest,
            "sha512",
            file.sha512.as_deref().unwrap_or(""),
        );
        digest_field(
            &mut manifest,
            "sha256",
            file.sha256.as_deref().unwrap_or(""),
        );
        digest_field(
            &mut manifest,
            "client",
            if file.client_required { "1" } else { "0" },
        );
        digest_field(
            &mut manifest,
            "server",
            if file.server_required { "1" } else { "0" },
        );
        let mut downloads = file.downloads.clone();
        downloads.sort();
        for download in downloads {
            digest_field(&mut acquisition, "download", &download);
        }
    }
    if let Some(pack) = pack {
        digest_field(&mut manifest, "pack-provider", &pack.provider);
        digest_field(&mut manifest, "pack-name", &pack.name);
        digest_field(&mut manifest, "pack-version", &pack.version_id);
        digest_field(&mut manifest, "manifest-sha256", &pack.manifest_sha256);
    }
    let content_digest = format!("{:x}", content.finalize());
    digest_field(&mut manifest, "content-digest", &content_digest);
    LockDigests {
        content: content_digest,
        manifest: format!("{:x}", manifest.finalize()),
        acquisition: format!("{:x}", acquisition.finalize()),
        completeness: if unhashed_files == 0 {
            VerificationCompleteness::Complete
        } else {
            VerificationCompleteness::Partial
        },
        unhashed_files,
    }
}

/// Reproduce the v2 lock digest byte-for-byte for migration reads. V2 mixed
/// environment, provider coordinates, content hashes, and acquisition URLs into
/// one value; v3 deliberately separates those identities in [`lock_digests`].
fn v2_lock_digest(
    env: &CorpusEnvironment,
    mods: &[LockedMod],
    files: &[LockedPackFile],
    pack: Option<&PackIdentity>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(env.loader.as_bytes());
    hasher.update(b"\0");
    hasher.update(env.mc_version.as_bytes());
    hasher.update(b"\0");
    hasher.update(env.side.as_bytes());
    hasher.update(b"\n");
    if let Some(loader_version) = &env.loader_version {
        hasher.update(b"loader-version\0");
        hasher.update(loader_version.as_bytes());
        hasher.update(b"\n");
    }
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
    if let Some(pack) = pack {
        hasher.update(b"pack\0");
        hasher.update(pack.provider.as_bytes());
        hasher.update(b"\0");
        hasher.update(pack.name.as_bytes());
        hasher.update(b"\0");
        hasher.update(pack.version_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(pack.manifest_sha256.as_bytes());
        hasher.update(b"\n");
    }
    for file in files {
        hasher.update(b"file\0");
        hasher.update(file.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(file.sha512.as_deref().unwrap_or("").as_bytes());
        hasher.update(b"\0");
        hasher.update(file.sha256.as_deref().unwrap_or("").as_bytes());
        hasher.update(b"\0");
        hasher.update(if file.client_required { b"c1" } else { b"c0" });
        hasher.update(b"\0");
        hasher.update(if file.server_required { b"s1" } else { b"s0" });
        let mut downloads = file.downloads.clone();
        downloads.sort();
        for download in downloads {
            hasher.update(b"\0url\0");
            hasher.update(download.as_bytes());
        }
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

fn legacy_lock_digest(env: &CorpusEnvironment, mods: &[LockedMod]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(env.loader.as_bytes());
    hasher.update(b"\0");
    hasher.update(env.mc_version.as_bytes());
    hasher.update(b"\0");
    hasher.update(env.side.as_bytes());
    hasher.update(b"\n");
    let mut lines = mods
        .iter()
        .map(|module| {
            format!(
                "{}@{}#{}",
                module.project_id,
                module.version_id,
                module.sha512.as_deref().unwrap_or("")
            )
        })
        .collect::<Vec<_>>();
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
    if !matches!(
        lock.schema.as_str(),
        CORPUS_LOCK_SCHEMA | CORPUS_LOCK_SCHEMA_V2 | CORPUS_LOCK_SCHEMA_V1
    ) {
        return Err(LabError::schema(
            path,
            "intermed-corpus-lock-v1, v2, or v3",
            &lock.schema,
        ));
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
            loader_version: None,
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

    #[test]
    fn acquisition_url_does_not_change_content_identity() {
        let mut candidate = candidate("a", "1", 1);
        candidate.sha512 = Some("a".repeat(128));
        candidate.download_url = Some("https://cdn-a.invalid/a.jar".into());
        let base = CorpusCandidates {
            schema: CORPUS_CANDIDATES_SCHEMA.into(),
            environment: env(),
            candidates: vec![candidate],
        };
        let lock_a = CorpusLock::from_candidates(&base);
        let mut moved = base.clone();
        moved.candidates[0].download_url = Some("https://cdn-b.invalid/a.jar".into());
        let lock_b = CorpusLock::from_candidates(&moved);
        assert_eq!(lock_a.content_digest, lock_b.content_digest);
        assert_eq!(lock_a.lock_manifest_digest, lock_b.lock_manifest_digest);
        assert_ne!(lock_a.acquisition_digest, lock_b.acquisition_digest);
    }

    #[test]
    fn unhashed_files_are_explicitly_partial() {
        let lock = CorpusLock::from_candidates(&CorpusCandidates {
            schema: CORPUS_CANDIDATES_SCHEMA.into(),
            environment: env(),
            candidates: vec![candidate("a", "1", 1)],
        });
        assert_eq!(
            lock.verification_completeness,
            VerificationCompleteness::Partial
        );
        assert_eq!(lock.unhashed_files, 1);
        assert!(lock.verify_digest());
    }

    #[test]
    fn legacy_v1_lock_digest_remains_readable() {
        let candidates = CorpusCandidates {
            schema: CORPUS_CANDIDATES_SCHEMA.into(),
            environment: env(),
            candidates: vec![candidate("a", "1", 1)],
        };
        let mut lock = CorpusLock::from_candidates(&candidates);
        lock.schema = CORPUS_LOCK_SCHEMA_V1.into();
        lock.digest = legacy_lock_digest(&lock.environment, &lock.mods);
        assert!(lock.verify_digest());
    }
}
