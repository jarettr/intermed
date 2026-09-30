//! Content-addressed artifact storage and deterministic corpus materialization.

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::corpus::{CorpusLock, LockedMod, LockedPackFile};
use crate::{LabError, write_json_atomic};

pub const STORE_MANIFEST_SCHEMA: &str = "intermed-lab-materialization-v1";
pub const TARGET_VERIFICATION_SCHEMA: &str = "intermed-lab-target-verification-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetVerification {
    pub schema: String,
    pub corpus_digest: String,
    pub checked: usize,
    pub optional_absent: usize,
    pub bytes_hashed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedArtifact {
    pub project_id: String,
    pub version_id: String,
    pub file_name: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha512: Option<String>,
    pub bytes: u64,
    pub store_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializationRecord {
    pub schema: String,
    pub corpus_digest: String,
    pub output_dir: PathBuf,
    pub artifacts: Vec<MaterializedArtifact>,
}

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, LabError> {
        let root = root.into();
        std::fs::create_dir_all(root.join("blobs/sha256")).map_err(|error| {
            LabError::new(format!("create artifact store {}: {error}", root.display()))
        })?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ingest(&self, source: &Path) -> Result<(String, PathBuf, u64), LabError> {
        let (sha256, _sha512, bytes) = hashes(source)?;
        let path = self.blob_path(&sha256);
        if path.is_file() {
            let (existing, _, existing_bytes) = hashes(&path)?;
            if existing != sha256 || existing_bytes != bytes {
                return Err(LabError::new(format!(
                    "content-addressed blob verification failed: {}",
                    path.display()
                )));
            }
            return Ok((sha256, path, bytes));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| LabError::new(format!("create {}: {error}", parent.display())))?;
        }
        static TEMP_ID: AtomicU64 = AtomicU64::new(0);
        let temp = path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let mut input = File::open(source)
            .map_err(|error| LabError::new(format!("open {}: {error}", source.display())))?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| LabError::new(format!("create {}: {error}", temp.display())))?;
        std::io::copy(&mut input, &mut output).map_err(|error| {
            LabError::new(format!(
                "copy {} to artifact store: {error}",
                source.display()
            ))
        })?;
        output
            .sync_all()
            .map_err(|error| LabError::new(format!("sync {}: {error}", temp.display())))?;
        let (copied_hash, _, copied_bytes) = hashes(&temp)?;
        if copied_hash != sha256 || copied_bytes != bytes {
            let _ = std::fs::remove_file(&temp);
            return Err(LabError::new("artifact changed while being ingested"));
        }
        match std::fs::rename(&temp, &path) {
            Ok(()) => {}
            Err(_) if path.is_file() => {
                let _ = std::fs::remove_file(&temp);
                let (raced_hash, _, raced_bytes) = hashes(&path)?;
                if raced_hash != sha256 || raced_bytes != bytes {
                    return Err(LabError::new(format!(
                        "content-addressed blob race produced invalid content: {}",
                        path.display()
                    )));
                }
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temp);
                return Err(LabError::new(format!(
                    "commit artifact blob {}: {error}",
                    path.display()
                )));
            }
        }
        if let Some(parent) = path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    LabError::new(format!(
                        "sync artifact-store directory {}: {error}",
                        parent.display()
                    ))
                })?;
        }
        Ok((sha256, path, bytes))
    }

    pub fn materialize(
        &self,
        lock: &CorpusLock,
        source_dir: &Path,
        output_dir: &Path,
    ) -> Result<MaterializationRecord, LabError> {
        if !lock.verify_digest() {
            return Err(LabError::new(
                "refusing to materialize an invalid corpus lock",
            ));
        }
        let mut artifacts = Vec::with_capacity(lock.mods.len().max(lock.files.len()));
        if lock.files.is_empty() {
            let mods_dir = output_dir.join("mods");
            create_safe_directory_tree(output_dir, Path::new("mods"))?;
            for locked in &lock.mods {
                validate_file_name(&locked.file_name)?;
                let source = source_dir.join(&locked.file_name);
                if !source.is_file() {
                    return Err(LabError::new(format!(
                        "locked artifact is unavailable: {}",
                        source.display()
                    )));
                }
                artifacts.push(self.materialize_one(locked, &source, &mods_dir)?);
            }
        } else {
            for locked in &lock.files {
                let source = source_dir.join(&locked.path);
                if !source.is_file() && !required_for_side(locked, &lock.environment.side) {
                    continue;
                }
                artifacts.push(self.materialize_pack_file(locked, source_dir, output_dir)?);
            }
        }
        artifacts.sort_by(|a, b| a.file_name.cmp(&b.file_name));
        let record = MaterializationRecord {
            schema: STORE_MANIFEST_SCHEMA.to_string(),
            corpus_digest: lock.digest.clone(),
            output_dir: output_dir.to_path_buf(),
            artifacts,
        };
        write_json_atomic(&output_dir.join("intermed-materialization.json"), &record)?;
        Ok(record)
    }

    fn materialize_pack_file(
        &self,
        locked: &LockedPackFile,
        source_root: &Path,
        output_root: &Path,
    ) -> Result<MaterializedArtifact, LabError> {
        validate_relative_path(&locked.path)?;
        let source = source_root.join(&locked.path);
        if !source.is_file() {
            return Err(LabError::new(format!(
                "locked pack file is unavailable: {}",
                source.display()
            )));
        }
        let (actual_sha256, actual_sha512, _) = hashes(&source)?;
        if let Some(expected) = &locked.sha512
            && !expected.eq_ignore_ascii_case(&actual_sha512)
        {
            return Err(LabError::new(format!(
                "sha512 mismatch for {}",
                locked.path
            )));
        }
        if let Some(expected) = &locked.sha256
            && !expected.eq_ignore_ascii_case(&actual_sha256)
        {
            return Err(LabError::new(format!(
                "sha256 mismatch for {}",
                locked.path
            )));
        }
        let (sha256, store_path, bytes) = self.ingest(&source)?;
        let destination = output_root.join(&locked.path);
        let relative_parent = Path::new(&locked.path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        create_safe_directory_tree(output_root, relative_parent)?;
        materialize_blob(&store_path, &destination, &sha256)?;
        Ok(MaterializedArtifact {
            project_id: locked.path.clone(),
            version_id: "manifest-pinned".to_string(),
            file_name: locked.path.clone(),
            sha256,
            expected_sha512: locked.sha512.clone(),
            bytes,
            store_path,
        })
    }

    fn materialize_one(
        &self,
        locked: &LockedMod,
        source: &Path,
        mods_dir: &Path,
    ) -> Result<MaterializedArtifact, LabError> {
        let (actual_sha256, actual_sha512, _) = hashes(source)?;
        if let Some(expected) = &locked.sha512
            && !expected.eq_ignore_ascii_case(&actual_sha512)
        {
            return Err(LabError::new(format!(
                "sha512 mismatch for {}: expected {}, found {}",
                locked.file_name, expected, actual_sha512
            )));
        }
        let (sha256, store_path, bytes) = self.ingest(source)?;
        debug_assert_eq!(sha256, actual_sha256);
        let destination = mods_dir.join(&locked.file_name);
        materialize_blob(&store_path, &destination, &sha256)?;
        Ok(MaterializedArtifact {
            project_id: locked.project_id.clone(),
            version_id: locked.version_id.clone(),
            file_name: locked.file_name.clone(),
            sha256,
            expected_sha512: locked.sha512.clone(),
            bytes,
            store_path,
        })
    }

    fn blob_path(&self, sha256: &str) -> PathBuf {
        self.root
            .join("blobs/sha256")
            .join(&sha256[..2])
            .join(sha256)
    }
}

/// Materialize a verified blob without ever opening an existing destination for
/// writing. Two processes may race here; `AlreadyExists` means the winner must
/// be verified, never overwritten. The fallback copy is staged next to the
/// destination and published with another atomic no-clobber hard link.
fn materialize_blob(
    store_path: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<(), LabError> {
    reject_symlink(destination, "materialized destination")?;
    match std::fs::hard_link(store_path, destination) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return verify_materialized_blob(destination, expected_sha256);
        }
        Err(_) => {}
    }

    static MATERIALIZE_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    let temp = destination.with_file_name(format!(
        ".{file_name}.intermed-tmp-{}-{}",
        std::process::id(),
        MATERIALIZE_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut input = File::open(store_path)
            .map_err(|error| LabError::new(format!("open {}: {error}", store_path.display())))?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| LabError::new(format!("create {}: {error}", temp.display())))?;
        std::io::copy(&mut input, &mut output).map_err(|error| {
            LabError::new(format!(
                "copy {} to {}: {error}",
                store_path.display(),
                temp.display()
            ))
        })?;
        output
            .sync_all()
            .map_err(|error| LabError::new(format!("sync {}: {error}", temp.display())))?;
        verify_materialized_blob(&temp, expected_sha256)?;
        match std::fs::hard_link(&temp, destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_materialized_blob(destination, expected_sha256)
            }
            Err(error) => Err(LabError::new(format!(
                "publish materialized artifact {}: {error}",
                destination.display()
            ))),
        }
    })();
    let _ = std::fs::remove_file(&temp);
    result
}

fn verify_materialized_blob(path: &Path, expected_sha256: &str) -> Result<(), LabError> {
    reject_symlink(path, "materialized destination")?;
    let (current, _, _) = hashes(path)?;
    if current == expected_sha256 {
        Ok(())
    } else {
        Err(LabError::new(format!(
            "materialized destination contains different content: {}",
            path.display()
        )))
    }
}

/// Prove that the materialized target still contains the payload pinned by its
/// corpus lock. Required files fail closed; optional side-specific files may be
/// absent, but are verified when present.
pub fn verify_target(lock: &CorpusLock, target: &Path) -> Result<TargetVerification, LabError> {
    if !lock.verify_digest() {
        return Err(LabError::new(
            "target verification received an invalid corpus lock",
        ));
    }
    let mut checked = 0usize;
    let mut optional_absent = 0usize;
    let mut bytes_hashed = 0u64;
    if !lock.files.is_empty() {
        for file in &lock.files {
            validate_relative_path(&file.path)?;
            let path = target.join(&file.path);
            if !path.is_file() {
                if required_for_side(file, &lock.environment.side) {
                    return Err(LabError::new(format!(
                        "required locked target file is absent: {}",
                        path.display()
                    )));
                }
                optional_absent += 1;
                continue;
            }
            let (sha256, sha512, bytes) = hashes(&path)?;
            if file
                .sha256
                .as_ref()
                .is_some_and(|expected| !expected.eq_ignore_ascii_case(&sha256))
                || file
                    .sha512
                    .as_ref()
                    .is_some_and(|expected| !expected.eq_ignore_ascii_case(&sha512))
            {
                return Err(LabError::new(format!(
                    "locked target content mismatch: {}",
                    path.display()
                )));
            }
            checked += 1;
            bytes_hashed = bytes_hashed
                .checked_add(bytes)
                .ok_or_else(|| LabError::new("target verification byte count overflow"))?;
        }
    } else {
        for module in &lock.mods {
            validate_file_name(&module.file_name)?;
            let direct = target.join(&module.file_name);
            let nested = target.join("mods").join(&module.file_name);
            let path = if direct.is_file() { direct } else { nested };
            if !path.is_file() {
                return Err(LabError::new(format!(
                    "locked mod is absent from target: {}",
                    module.file_name
                )));
            }
            let (_, sha512, bytes) = hashes(&path)?;
            if module
                .sha512
                .as_ref()
                .is_some_and(|expected| !expected.eq_ignore_ascii_case(&sha512))
            {
                return Err(LabError::new(format!(
                    "locked mod content mismatch: {}",
                    path.display()
                )));
            }
            checked += 1;
            bytes_hashed = bytes_hashed
                .checked_add(bytes)
                .ok_or_else(|| LabError::new("target verification byte count overflow"))?;
        }
    }
    Ok(TargetVerification {
        schema: TARGET_VERIFICATION_SCHEMA.to_string(),
        corpus_digest: lock.digest.clone(),
        checked,
        optional_absent,
        bytes_hashed,
    })
}

fn required_for_side(file: &LockedPackFile, side: &str) -> bool {
    match side {
        "client" => file.client_required,
        "server" => file.server_required,
        // `both` is a complete dual-side materialization. Unknown legacy side
        // values fail closed if either environment declares the file required.
        _ => file.client_required || file.server_required,
    }
}

fn validate_file_name(name: &str) -> Result<(), LabError> {
    let path = Path::new(name);
    if name.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || matches!(component, Component::ParentDir | Component::RootDir)
        })
        || path.components().count() != 1
    {
        return Err(LabError::new(format!(
            "unsafe locked artifact file name: {name}"
        )));
    }
    Ok(())
}

fn validate_relative_path(name: &str) -> Result<(), LabError> {
    let path = Path::new(name);
    if name.is_empty()
        || name.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LabError::new(format!("unsafe pack file path: {name}")));
    }
    Ok(())
}

/// Create a directory path below `root` without following attacker-controlled
/// symlinks in an already-existing materialization tree.
fn create_safe_directory_tree(root: &Path, relative: &Path) -> Result<(), LabError> {
    std::fs::create_dir_all(root)
        .map_err(|error| LabError::new(format!("create {}: {error}", root.display())))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(LabError::new(format!(
                "unsafe materialization directory: {}",
                relative.display()
            )));
        };
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(LabError::new(format!(
                    "materialization path traverses a symlink: {}",
                    current.display()
                )));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(LabError::new(format!(
                    "materialization path component is not a directory: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|error| {
                    LabError::new(format!("create {}: {error}", current.display()))
                })?;
            }
            Err(error) => {
                return Err(LabError::new(format!(
                    "inspect {}: {error}",
                    current.display()
                )));
            }
        }
    }
    Ok(())
}

fn reject_symlink(path: &Path, label: &str) -> Result<(), LabError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(LabError::new(format!(
            "{label} must not be a symlink: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LabError::new(format!(
            "inspect {}: {error}",
            path.display()
        ))),
    }
}

fn hashes(path: &Path) -> Result<(String, String, u64), LabError> {
    let mut file = File::open(path)
        .map_err(|error| LabError::new(format!("open {}: {error}", path.display())))?;
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| LabError::new(format!("read {}: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| LabError::new("artifact byte count overflow"))?;
        sha256.update(&buffer[..read]);
        sha512.update(&buffer[..read]);
    }
    Ok((
        format!("{:x}", sha256.finalize()),
        format!("{:x}", sha512.finalize()),
        bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::{CORPUS_LOCK_SCHEMA, CorpusEnvironment};

    fn temp(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "intermed-store-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn content_is_deduplicated_and_materialized() {
        let root = temp("dedup");
        let source = root.join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("a.jar"), b"same bytes").unwrap();
        let (_, sha512, _) = hashes(&source.join("a.jar")).unwrap();
        let mut lock = CorpusLock {
            schema: CORPUS_LOCK_SCHEMA.into(),
            environment: CorpusEnvironment {
                loader: "fabric".into(),
                mc_version: "1.20.1".into(),
                side: "server".into(),
                loader_version: None,
            },
            mods: vec![LockedMod {
                project_id: "a".into(),
                version_id: "1".into(),
                file_name: "a.jar".into(),
                sha512: Some(sha512),
                download_url: None,
            }],
            files: Vec::new(),
            pack: None,
            digest: String::new(),
            content_digest: String::new(),
            lock_manifest_digest: String::new(),
            acquisition_digest: String::new(),
            verification_completeness: crate::corpus::VerificationCompleteness::Partial,
            unhashed_files: 0,
        };
        // Use the public canonical builder to obtain a valid digest.
        let candidates = crate::corpus::CorpusCandidates {
            schema: crate::corpus::CORPUS_CANDIDATES_SCHEMA.into(),
            environment: lock.environment.clone(),
            candidates: vec![crate::corpus::CandidateMod {
                project_id: "a".into(),
                version_id: "1".into(),
                file_name: "a.jar".into(),
                sha512: lock.mods[0].sha512.clone(),
                download_url: None,
                downloads: 0,
            }],
        };
        lock = CorpusLock::from_candidates(&candidates);
        let store = ArtifactStore::open(root.join("store")).unwrap();
        let record = store
            .materialize(&lock, &source, &root.join("instance"))
            .unwrap();
        assert_eq!(record.artifacts.len(), 1);
        assert!(root.join("instance/mods/a.jar").is_file());
        assert!(record.artifacts[0].store_path.is_file());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn existing_materialization_is_verified_without_clobbering_store_blob() {
        let root = temp("existing-destination");
        let store_blob = root.join("store-blob");
        let destination = root.join("destination");
        std::fs::write(&store_blob, b"immutable content").unwrap();
        std::fs::hard_link(&store_blob, &destination).unwrap();
        let (expected, _, _) = hashes(&store_blob).unwrap();

        materialize_blob(&store_blob, &destination, &expected).unwrap();

        assert_eq!(std::fs::read(&store_blob).unwrap(), b"immutable content");
        assert_eq!(std::fs::read(&destination).unwrap(), b"immutable content");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn concurrent_materialization_never_clobbers_a_shared_blob() {
        let root = temp("concurrent-destination");
        let store_blob = root.join("store-blob");
        let destination = root.join("destination");
        std::fs::write(&store_blob, vec![0x5a; 256 * 1024]).unwrap();
        let (expected, _, _) = hashes(&store_blob).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));

        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..16 {
                let barrier = barrier.clone();
                let store_blob = &store_blob;
                let destination = &destination;
                let expected = &expected;
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    materialize_blob(store_blob, destination, expected)
                }));
            }
            for worker in workers {
                worker.join().unwrap().unwrap();
            }
        });

        assert_eq!(hashes(&store_blob).unwrap().0, expected);
        assert_eq!(hashes(&destination).unwrap().0, expected);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_file_name("../escape.jar").is_err());
        assert!(validate_file_name("nested/a.jar").is_err());
        assert!(validate_relative_path("mods/../escape.jar").is_err());
        assert!(validate_relative_path("./mods/a.jar").is_err());
        assert!(validate_relative_path("mods\\..\\escape.jar").is_err());
    }

    #[test]
    fn optional_pack_file_may_be_absent_for_selected_side() {
        let root = temp("optional-side");
        let source = root.join("source");
        std::fs::create_dir_all(&source).unwrap();
        let pack = crate::corpus::PackIdentity {
            provider: "test".into(),
            name: "optional".into(),
            version_id: "1".into(),
            manifest_sha256: "a".repeat(64),
        };
        let lock = CorpusLock::from_pack_manifest(
            CorpusEnvironment {
                loader: "fabric".into(),
                mc_version: "1.20.1".into(),
                side: "client".into(),
                loader_version: Some("0.16.0".into()),
            },
            vec![LockedPackFile {
                path: "server-only.cfg".into(),
                sha512: Some("b".repeat(128)),
                sha256: None,
                downloads: Vec::new(),
                client_required: false,
                server_required: true,
            }],
            pack,
        );
        let store = ArtifactStore::open(root.join("store")).unwrap();
        let record = store
            .materialize(&lock, &source, &root.join("instance"))
            .unwrap();
        assert!(record.artifacts.is_empty());
        let verification = verify_target(&lock, &root.join("instance")).unwrap();
        assert_eq!(verification.optional_absent, 1);
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn materialization_refuses_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let root = temp("symlink-parent");
        let output = root.join("output");
        let outside = root.join("outside");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, output.join("mods")).unwrap();

        let error = create_safe_directory_tree(&output, Path::new("mods/nested")).unwrap_err();
        assert!(error.to_string().contains("traverses a symlink"));
        assert!(!outside.join("nested").exists());
        std::fs::remove_dir_all(root).ok();
    }
}
