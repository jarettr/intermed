//! Modpack archive materialization (`.mrpack`, `.zip`, CurseForge/Modrinth exports).
//!
//! `detect_target` classifies archives but collectors need a directory tree. This
//! module extracts archives to a private temp directory and rewrites the
//! [`Target`] to point at the unpacked instance.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;
use zip::read::ZipArchive;

use crate::instance_layout::resolve_layout;
use crate::target::{Target, TargetKind, target_from_layout};

/// Error unpacking a modpack archive.
#[derive(Debug, Error)]
pub enum ModpackError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Message(String),
}

/// Temporary mount of an extracted modpack; removed on drop.
pub struct ModpackMount {
    root: PathBuf,
    _guard: tempfile::TempDir,
}

impl ModpackMount {
    /// Root directory of the unpacked instance/server.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// When `target` is a modpack archive, extract it and return an updated target.
///
/// Returns `Ok(None)` for non-archive targets (unchanged). On success the
/// returned mount must be kept alive for the duration of the diagnosis run.
pub fn materialize_modpack_archive(
    target: &Target,
) -> Result<(Target, Option<ModpackMount>), ModpackError> {
    if target.kind != TargetKind::ModpackArchive || !target.path.is_file() {
        return Ok((target.clone(), None));
    }
    let guard_dir = temp_extract_dir(&target.path)?;
    extract_archive(&target.path, guard_dir.path())?;
    let root = find_instance_root(guard_dir.path())?;
    let resolved = resolve_layout(&root);
    let updated = target_from_layout(&root, &resolved);
    let mount = ModpackMount {
        root: root.clone(),
        _guard: guard_dir,
    };
    Ok((updated, Some(mount)))
}

fn temp_extract_dir(archive: &Path) -> Result<tempfile::TempDir, ModpackError> {
    let stem = archive
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("modpack");
    let dir = tempfile::Builder::new()
        .prefix(&format!("intermed-modpack-{stem}-"))
        .tempdir()
        .map_err(|e| ModpackError::Message(e.to_string()))?;
    Ok(dir)
}

/// Limits applied while extracting an *untrusted* modpack archive.
///
/// Modpacks (`.zip` / `.mrpack` / CurseForge exports) are arbitrary files from
/// the internet. Without limits a crafted archive can exhaust the disk (a "zip
/// bomb": a few KiB inflating to many GiB) or escape the destination directory
/// (a "zip slip": entries named `../../etc/...`). Both are handled here.
#[derive(Debug, Clone)]
pub struct ExtractLimits {
    /// Maximum number of entries in the archive.
    pub max_entries: usize,
    /// Maximum total uncompressed bytes written across all entries.
    pub max_total_uncompressed_bytes: u64,
    /// Maximum uncompressed bytes for any single entry.
    pub max_single_entry_bytes: u64,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_total_uncompressed_bytes: 8 * 1024 * 1024 * 1024, // 8 GiB
            max_single_entry_bytes: 2 * 1024 * 1024 * 1024,       // 2 GiB
        }
    }
}

/// Resolve an archive entry name to a path that is guaranteed to stay inside
/// `dest`. Rejects absolute paths, drive prefixes, and any `..` traversal.
///
/// This is the zip-slip guard: every byte we write must land under the private
/// temp directory, never at an attacker-chosen location like `~/.ssh/`.
fn safe_entry_path(dest: &Path, raw_name: &str) -> Result<PathBuf, ModpackError> {
    // Normalize Windows-style separators so `C:\evil` / `..\..\x` are inspected
    // the same way on every platform (on Unix the backslash is otherwise a
    // legal filename byte and would slip through `Path::components`).
    let normalized = raw_name.replace('\\', "/");
    let path = Path::new(&normalized);

    if path.is_absolute() {
        return Err(ModpackError::Message(format!(
            "archive entry uses an absolute path: {raw_name}"
        )));
    }

    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ModpackError::Message(format!(
                    "archive entry escapes destination: {raw_name}"
                )));
            }
        }
    }

    Ok(dest.join(path))
}

fn extract_archive(archive: &Path, dest: &Path) -> Result<(), ModpackError> {
    extract_archive_with_limits(archive, dest, &ExtractLimits::default())
}

fn extract_archive_with_limits(
    archive: &Path,
    dest: &Path,
    limits: &ExtractLimits,
) -> Result<(), ModpackError> {
    let file = File::open(archive)?;
    let mut zip = ZipArchive::new(file)
        .map_err(|e| ModpackError::Message(format!("zip open {}: {e}", archive.display())))?;

    if zip.len() > limits.max_entries {
        return Err(ModpackError::Message(format!(
            "archive has {} entries, exceeding the {} entry limit",
            zip.len(),
            limits.max_entries
        )));
    }

    let mut total_written: u64 = 0;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| ModpackError::Message(format!("zip entry {i}: {e}")))?;

        // Directory entries: validate the path but write nothing.
        if entry.is_dir() || entry.name().ends_with('/') {
            let dir_path = safe_entry_path(dest, entry.name())?;
            fs::create_dir_all(&dir_path)?;
            continue;
        }

        // Reject early on the *declared* size (cheap), then enforce the real
        // size during copy so a lying header can't get past us either.
        if entry.size() > limits.max_single_entry_bytes {
            return Err(ModpackError::Message(format!(
                "archive entry {} declares {} bytes, exceeding the per-entry limit",
                entry.name(),
                entry.size()
            )));
        }

        let out_path = safe_entry_path(dest, entry.name())?;
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = File::create(&out_path)?;

        // Cap the reader at one byte past the limit so an over-large (or
        // bomb-inflated) entry is detected rather than fully materialized.
        let cap = limits.max_single_entry_bytes.saturating_add(1);
        let mut capped = (&mut entry).take(cap);
        let written = io::copy(&mut capped, &mut out)?;
        if written > limits.max_single_entry_bytes {
            let _ = fs::remove_file(&out_path);
            return Err(ModpackError::Message(format!(
                "archive entry {} exceeds the per-entry size limit while extracting",
                entry.name()
            )));
        }

        total_written = total_written.saturating_add(written);
        if total_written > limits.max_total_uncompressed_bytes {
            return Err(ModpackError::Message(format!(
                "archive exceeds the {} byte total uncompressed limit (zip bomb?)",
                limits.max_total_uncompressed_bytes
            )));
        }
    }
    Ok(())
}

fn find_instance_root(extract_root: &Path) -> Result<PathBuf, ModpackError> {
    // Single top-level directory (common for exported zips).
    if let Ok(rd) = fs::read_dir(extract_root) {
        let mut dirs = Vec::new();
        let mut files = 0usize;
        for entry in rd.flatten() {
            if entry.path().is_dir() {
                dirs.push(entry.path());
            } else {
                files += 1;
            }
        }
        if files == 0 && dirs.len() == 1 {
            return Ok(dirs.pop().expect("one dir"));
        }
    }
    Ok(extract_root.to_path_buf())
}

/// Modrinth `.mrpack` index (subset used for validation only).
#[derive(Debug, Deserialize)]
struct MrpackIndex {
    #[serde(default)]
    format_version: u32,
}

/// Returns true when `path` looks like a Modrinth pack by index presence.
#[must_use]
pub fn is_mrpack_layout(root: &Path) -> bool {
    let index_path = root.join("modrinth.index.json");
    if !index_path.is_file() {
        return false;
    }
    let Ok(text) = fs::read_to_string(&index_path) else {
        return false;
    };
    serde_json::from_str::<MrpackIndex>(&text)
        .map(|idx| idx.format_version > 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    fn write_test_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        for (name, bytes) in entries {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn extracts_zip_with_mods_dir() {
        let dir = std::env::temp_dir().join(format!(
            "intermed-modpack-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let archive = dir.join("pack.zip");
        write_test_zip(
            &archive,
            &[("mods/alpha.jar", b"jar"), ("server.properties", b"test=1")],
        );
        let target = Target {
            path: archive.clone(),
            kind: TargetKind::ModpackArchive,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let (updated, mount) = materialize_modpack_archive(&target).expect("extract");
        assert!(mount.is_some());
        assert_eq!(updated.kind, TargetKind::Server);
        assert!(
            updated
                .mods_dir
                .as_ref()
                .is_some_and(|m| m.ends_with("mods"))
        );
        assert_eq!(
            updated.instance_type,
            Some(crate::target::InstanceType::Server)
        );
        fs::remove_dir_all(dir).ok();
    }

    fn unique_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn safe_entry_path_rejects_parent_traversal() {
        let dest = Path::new("/tmp/intermed-dest");
        let err = safe_entry_path(dest, "../escape.txt").unwrap_err();
        assert!(matches!(err, ModpackError::Message(m) if m.contains("escapes destination")));
    }

    #[test]
    fn safe_entry_path_rejects_absolute_path() {
        let dest = Path::new("/tmp/intermed-dest");
        let err = safe_entry_path(dest, "/tmp/escape.txt").unwrap_err();
        assert!(matches!(err, ModpackError::Message(m) if m.contains("absolute path")));
    }

    #[test]
    fn safe_entry_path_rejects_windows_drive_path() {
        let dest = Path::new("/tmp/intermed-dest");
        // Backslash-separated Windows path with a drive prefix and traversal.
        let err = safe_entry_path(dest, "..\\..\\Users\\evil.txt").unwrap_err();
        assert!(matches!(err, ModpackError::Message(m) if m.contains("escapes destination")));
    }

    #[test]
    fn safe_entry_path_allows_normal_nested_path() {
        let dest = Path::new("/tmp/intermed-dest");
        let p = safe_entry_path(dest, "overrides/mods/a.jar").unwrap();
        assert_eq!(p, dest.join("overrides/mods/a.jar"));
    }

    #[test]
    fn extraction_rejects_zip_slip_entry() {
        let dir = unique_dir("intermed-modpack-slip");
        let archive = dir.join("evil.zip");
        write_test_zip(
            &archive,
            &[("../escape.txt", b"pwned"), ("mods/ok.jar", b"j")],
        );
        let dest = dir.join("out");
        fs::create_dir_all(&dest).unwrap();
        let err = extract_archive(&archive, &dest).unwrap_err();
        assert!(matches!(err, ModpackError::Message(m) if m.contains("escapes destination")));
        // The traversal target must not have been written outside dest.
        assert!(!dir.join("escape.txt").exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn extraction_rejects_too_many_entries() {
        let dir = unique_dir("intermed-modpack-count");
        let archive = dir.join("many.zip");
        let entries: Vec<(String, &[u8])> = (0..50)
            .map(|i| (format!("f{i}.txt"), b"x" as &[u8]))
            .collect();
        let refs: Vec<(&str, &[u8])> = entries.iter().map(|(n, b)| (n.as_str(), *b)).collect();
        write_test_zip(&archive, &refs);
        let dest = dir.join("out");
        fs::create_dir_all(&dest).unwrap();
        let limits = ExtractLimits {
            max_entries: 10,
            ..ExtractLimits::default()
        };
        let err = extract_archive_with_limits(&archive, &dest, &limits).unwrap_err();
        assert!(matches!(err, ModpackError::Message(m) if m.contains("entry limit")));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn extraction_rejects_oversize_single_entry() {
        let dir = unique_dir("intermed-modpack-big");
        let archive = dir.join("big.zip");
        write_test_zip(&archive, &[("data.bin", &vec![0u8; 4096])]);
        let dest = dir.join("out");
        fs::create_dir_all(&dest).unwrap();
        let limits = ExtractLimits {
            max_single_entry_bytes: 1024,
            ..ExtractLimits::default()
        };
        let err = extract_archive_with_limits(&archive, &dest, &limits).unwrap_err();
        assert!(matches!(err, ModpackError::Message(m) if m.contains("per-entry")));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn extraction_rejects_total_size_overflow() {
        let dir = unique_dir("intermed-modpack-total");
        let archive = dir.join("total.zip");
        write_test_zip(
            &archive,
            &[
                ("a.bin", &vec![1u8; 4096]),
                ("b.bin", &vec![2u8; 4096]),
                ("c.bin", &vec![3u8; 4096]),
            ],
        );
        let dest = dir.join("out");
        fs::create_dir_all(&dest).unwrap();
        let limits = ExtractLimits {
            max_single_entry_bytes: 1_000_000,
            max_total_uncompressed_bytes: 6000,
            ..ExtractLimits::default()
        };
        let err = extract_archive_with_limits(&archive, &dest, &limits).unwrap_err();
        assert!(matches!(err, ModpackError::Message(m) if m.contains("total uncompressed")));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn extracts_curseforge_overrides_layout() {
        let dir = std::env::temp_dir().join(format!(
            "intermed-modpack-cf-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let archive = dir.join("pack.zip");
        write_test_zip(
            &archive,
            &[
                ("manifest.json", br#"{"minecraft":{"version":"1.20.1"}}"#),
                ("modlist.html", b"<html></html>"),
                ("overrides/mods/mod.jar", b"j"),
            ],
        );
        let target = Target {
            path: archive.clone(),
            kind: TargetKind::ModpackArchive,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let (updated, _) = materialize_modpack_archive(&target).expect("extract");
        assert_eq!(updated.kind, TargetKind::Instance);
        assert!(
            updated
                .mods_dir
                .as_ref()
                .is_some_and(|m| m.ends_with("overrides/mods"))
        );
        fs::remove_dir_all(dir).ok();
    }
}
