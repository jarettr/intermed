//! # intermed-packops — Phase 3
//!
//! Explicit pack operations built on VFS evidence. `doctor` remains read-only;
//! this crate writes only when a user invokes `intermed vfs overlay --out ...`.

use std::fmt;
use std::path::{Path, PathBuf};

use intermed_vfs::{merge_tag_values, scan_mods_dir, ConflictClass, ResourceCollision};
use serde::{Deserialize, Serialize};

/// Implementation status for help output.
pub const STATUS: &str = "active: Phase 3";

/// One file staged into an overlay preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayItem {
    pub path: String,
    pub class: ConflictClass,
    pub writers: Vec<String>,
    pub source: String,
}

/// Manifest written as `intermed-overlay-manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayManifest {
    pub schema: String,
    pub source_mods_dir: String,
    pub items: Vec<OverlayItem>,
}

/// Result of planning and writing an overlay preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayPlan {
    pub out_dir: String,
    pub manifest: OverlayManifest,
}

/// Pack operation failure.
#[derive(Debug, Clone)]
pub struct PackOpsError {
    message: String,
}

impl PackOpsError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PackOpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PackOpsError {}

/// Build a deterministic overlay preview from resource collisions.
///
/// The output directory must not already exist. Files are staged into a sibling
/// temporary directory first and then atomically renamed into place.
pub fn write_overlay_preview(mods_dir: &Path, out_dir: &Path) -> Result<OverlayPlan, PackOpsError> {
    let tmp = temp_sibling(out_dir);
    if tmp.exists() {
        return Err(PackOpsError::new(format!(
            "temporary overlay path already exists: {}",
            tmp.display()
        )));
    }
    match stage_overlay_preview(mods_dir, out_dir, &tmp) {
        Ok(plan) => Ok(plan),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

fn stage_overlay_preview(
    mods_dir: &Path,
    out_dir: &Path,
    tmp: &Path,
) -> Result<OverlayPlan, PackOpsError> {
    if out_dir.exists() {
        return Err(PackOpsError::new(format!(
            "overlay output already exists: {}",
            out_dir.display()
        )));
    }

    let scan = scan_mods_dir(mods_dir).map_err(|e| PackOpsError::new(e.to_string()))?;
    let parent = out_dir.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|e| PackOpsError::new(format!("create {}: {e}", parent.display())))?;

    std::fs::create_dir_all(tmp)
        .map_err(|e| PackOpsError::new(format!("create {}: {e}", tmp.display())))?;

    let mut items = Vec::new();
    for collision in &scan.collisions {
        if collision.class == ConflictClass::Identical {
            continue;
        }
        let bytes = overlay_bytes(collision, &scan)?;
        let dest = safe_overlay_path(tmp, &collision.path)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| PackOpsError::new(format!("create {}: {e}", parent.display())))?;
        }
        std::fs::write(&dest, bytes)
            .map_err(|e| PackOpsError::new(format!("write {}: {e}", dest.display())))?;
        items.push(OverlayItem {
            path: collision.path.clone(),
            class: collision.class,
            writers: collision.writers.clone(),
            source: overlay_source(collision),
        });
    }

    let manifest = OverlayManifest {
        schema: "intermed-overlay-preview-v1".to_string(),
        source_mods_dir: mods_dir.display().to_string(),
        items,
    };
    let manifest_path = tmp.join("intermed-overlay-manifest.json");
    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| PackOpsError::new(format!("serialize overlay manifest: {e}")))?;
    std::fs::write(&manifest_path, manifest_json)
        .map_err(|e| PackOpsError::new(format!("write {}: {e}", manifest_path.display())))?;

    std::fs::rename(tmp, out_dir).map_err(|e| {
        PackOpsError::new(format!(
            "commit overlay {} -> {}: {e}",
            tmp.display(),
            out_dir.display()
        ))
    })?;

    Ok(OverlayPlan {
        out_dir: out_dir.display().to_string(),
        manifest,
    })
}

/// Compatibility wrapper for older callers.
pub fn plan_overlay(mods_dir: &Path) -> Result<OverlayPlan, PackOpsError> {
    write_overlay_preview(mods_dir, &mods_dir.join("intermed-overlay-preview"))
}

fn overlay_bytes(
    collision: &ResourceCollision,
    scan: &intermed_vfs::ResourceScan,
) -> Result<Vec<u8>, PackOpsError> {
    if collision.class == ConflictClass::SafeCrdtMerge {
        let blobs = scan.blobs_for_path(&collision.path);
        if let Some(merged) = merge_tag_values(&blobs) {
            return Ok(merged);
        }
    }
    scan.winning_blob(&collision.path)
        .map(|b| b.to_vec())
        .ok_or_else(|| PackOpsError::new(format!("no resource bytes for {}", collision.path)))
}

fn overlay_source(collision: &ResourceCollision) -> String {
    match collision.class {
        ConflictClass::SafeCrdtMerge => "merged tag values".to_string(),
        ConflictClass::JsonMergeCandidate | ConflictClass::UnsafeReplace => collision
            .archives
            .last()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        ConflictClass::Identical => "identical".to_string(),
    }
}

fn safe_overlay_path(root: &Path, rel: &str) -> Result<PathBuf, PackOpsError> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() || rel.split('/').any(|part| part == "..") {
        return Err(PackOpsError::new(format!("unsafe overlay path: {rel}")));
    }
    Ok(root.join(rel_path))
}

fn temp_sibling(out_dir: &Path) -> PathBuf {
    let name = out_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("overlay");
    out_dir.with_file_name(format!(".{name}.tmp-{}", std::process::id()))
}
