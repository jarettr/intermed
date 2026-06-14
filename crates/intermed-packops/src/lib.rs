//! # intermed-packops — Phase 3
//!
//! Explicit pack operations built on VFS evidence. `doctor` remains read-only;
//! this crate writes only when a user invokes `intermed vfs overlay --out ...`.

use std::path::{Path, PathBuf};

use intermed_vfs::{
    merge_lang_json, merge_lang_properties, merge_tag_values, scan_mods_dir, ConflictClass,
    ResourceCollision,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Implementation status for help output.
pub const STATUS: &str = "active: Phase 3";

/// How an overlay item's bytes were produced.
///
/// `DeterministicMerge` is order-independent and genuinely safe to apply.
/// `LexicalWinnerPreview` just picks one writer's bytes by a stable (lexical)
/// rule — it is a *preview* of what the runtime might do, not a fix, because the
/// real winner depends on mod load order which is not known statically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergePolicy {
    DeterministicMerge,
    LexicalWinnerPreview,
}

impl MergePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            MergePolicy::DeterministicMerge => "deterministic_merge",
            MergePolicy::LexicalWinnerPreview => "lexical_winner_preview",
        }
    }
}

/// One file staged into an overlay preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayItem {
    pub path: String,
    pub class: ConflictClass,
    pub writers: Vec<String>,
    pub source: String,
    /// How the bytes were produced (see [`MergePolicy`]).
    pub merge_policy: MergePolicy,
    /// Whether the true runtime winner is statically known. `false` for any
    /// lexical-winner preview (load order decides at runtime).
    pub runtime_order_known: bool,
    /// Whether applying this item as-is is safe. Only deterministic merges are.
    pub safe_to_apply: bool,
}

/// A collision that was deliberately *not* staged (an order-dependent winner
/// pick that the user did not opt into). Surfaced so the manifest is honest
/// about what it left out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedItem {
    pub path: String,
    pub class: ConflictClass,
    pub writers: Vec<String>,
    pub reason: String,
}

/// Manifest written as `intermed-overlay-manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayManifest {
    pub schema: String,
    pub source_mods_dir: String,
    /// Whether the caller opted into staging order-dependent winner previews.
    pub include_unsafe_winners: bool,
    /// Whether *every* staged item is safe to apply. `false` if any
    /// lexical-winner preview was written.
    pub safe_to_apply: bool,
    pub items: Vec<OverlayItem>,
    /// Order-dependent collisions left unstaged (empty when `include_unsafe_winners`).
    pub skipped: Vec<SkippedItem>,
}

/// Result of planning and writing an overlay preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayPlan {
    pub out_dir: String,
    pub manifest: OverlayManifest,
}

/// Pack operation failure.
#[derive(Debug, Clone, Error)]
#[error("{message}")]
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

/// Build a deterministic overlay preview from resource collisions.
///
/// The output directory must not already exist. Files are staged into a sibling
/// temporary directory first and then atomically renamed into place.
pub fn write_overlay_preview(
    mods_dir: &Path,
    out_dir: &Path,
    include_unsafe_winners: bool,
) -> Result<OverlayPlan, PackOpsError> {
    let tmp = temp_sibling(out_dir);
    if tmp.exists() {
        return Err(PackOpsError::new(format!(
            "temporary overlay path already exists: {}",
            tmp.display()
        )));
    }
    match stage_overlay_preview(mods_dir, out_dir, &tmp, include_unsafe_winners) {
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
    include_unsafe_winners: bool,
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
    let mut skipped = Vec::new();
    for collision in &scan.collisions {
        if collision.class == ConflictClass::Identical {
            continue;
        }
        let safe = collision.class.is_safe_merge();
        // The core safety rule: a deterministic, order-independent merge is the
        // only thing we apply by default. Order-dependent collisions are just a
        // lexical-winner *preview* and must be opted into — otherwise the user
        // could mistake "we picked a winner" for "we resolved the conflict".
        if !safe && !include_unsafe_winners {
            skipped.push(SkippedItem {
                path: collision.path.clone(),
                class: collision.class,
                writers: collision.writers.clone(),
                reason: "order-dependent winner pick; rerun with --include-unsafe-winners to stage \
                         a preview"
                    .to_string(),
            });
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
        let merge_policy = if safe {
            MergePolicy::DeterministicMerge
        } else {
            MergePolicy::LexicalWinnerPreview
        };
        items.push(OverlayItem {
            path: collision.path.clone(),
            class: collision.class,
            writers: collision.writers.clone(),
            source: overlay_source(collision),
            merge_policy,
            runtime_order_known: safe,
            safe_to_apply: safe,
        });
    }

    let all_safe = items.iter().all(|i| i.safe_to_apply);
    let manifest = OverlayManifest {
        schema: "intermed-overlay-preview-v1".to_string(),
        source_mods_dir: mods_dir.display().to_string(),
        include_unsafe_winners,
        safe_to_apply: all_safe,
        items,
        skipped,
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

/// Compatibility wrapper for older callers. Defaults to safe merges only.
pub fn plan_overlay(mods_dir: &Path) -> Result<OverlayPlan, PackOpsError> {
    write_overlay_preview(mods_dir, &mods_dir.join("intermed-overlay-preview"), false)
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
    if collision.class == ConflictClass::LangJsonMerge {
        let blobs = scan.blobs_for_path(&collision.path);
        if let Some(merged) = merge_lang_json(&blobs) {
            return Ok(merged);
        }
    }
    if collision.class == ConflictClass::LangPropertiesMerge {
        let blobs = scan.blobs_for_path(&collision.path);
        if let Some(merged) = merge_lang_properties(&blobs) {
            return Ok(merged);
        }
    }
    scan.winning_blob(&collision.path)
        .map(|b| b.to_vec())
        .ok_or_else(|| PackOpsError::new(format!("no resource bytes for {}", collision.path)))
}

fn overlay_source(collision: &ResourceCollision) -> String {
    let winner = || {
        collision
            .archives
            .last()
            .cloned()
            .map(|a| format!("lexical winner: {a}"))
            .unwrap_or_else(|| "lexical winner: unknown".to_string())
    };
    match collision.class {
        ConflictClass::SafeCrdtMerge => "merged tag values".to_string(),
        ConflictClass::LangJsonMerge => "merged lang json keys".to_string(),
        ConflictClass::LangPropertiesMerge => "merged lang properties".to_string(),
        ConflictClass::Identical => "identical".to_string(),
        // Everything else is an order-dependent winner pick.
        ConflictClass::LangFormatMismatch
        | ConflictClass::JsonMergeCandidate
        | ConflictClass::JsonOverride
        | ConflictClass::TagReplaceOrderDependent
        | ConflictClass::TagMixedRequired
        | ConflictClass::TagInvalid
        | ConflictClass::UnsafeReplace => winner(),
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

// ── Overlay plan v2 (semantic) ──────────────────────────────────────────────

/// One classified collision in an [`OverlayPlanV2`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayPlanItem {
    pub path: String,
    pub class: String,
    pub writers: Vec<String>,
    /// Why this item landed in its bucket.
    pub reason: String,
}

/// A read-only, semantic overlay *plan* (`intermed-overlay-plan-v2`).
///
/// Unlike the v1 preview (which stages files), this is pure planning: it buckets
/// every collision into `safe` (deterministic, order-independent merges that may
/// be written by default), `review` (a human must choose — order-dependent merges
/// and, crucially, recipe overrides where the **output item changes**, detected by
/// Layer M), and `unsafe` (order-dependent winner picks with no semantic signal).
///
/// `runtime_order_known` is always `false` here: without the actual load order we
/// only ever produce a lexical preview, never a guaranteed runtime result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayPlanV2 {
    pub schema: String,
    pub source_mods_dir: String,
    pub safe_items: Vec<OverlayPlanItem>,
    pub review_items: Vec<OverlayPlanItem>,
    pub unsafe_items: Vec<OverlayPlanItem>,
    pub writer_order_policy: String,
    pub runtime_order_known: bool,
}

/// Build the semantic overlay plan for a mods directory. Read-only.
pub fn build_overlay_plan_v2(mods_dir: &Path) -> Result<OverlayPlanV2, PackOpsError> {
    let scan = scan_mods_dir(mods_dir).map_err(|e| PackOpsError::new(e.to_string()))?;

    // Layer-M semantic diffs: the set of paths whose writers craft different
    // outputs (or bind a shared lang key to different text). These elevate an
    // otherwise-opaque override into a "must review" decision.
    let semantic = intermed_resource_ast::scan_mods_dir(
        mods_dir,
        intermed_resource_ast::ResourceLevel::Full,
    )
    .map_err(|e| PackOpsError::new(e.to_string()))?;
    let diffs = intermed_resource_ast::diff::compute(&semantic.records);
    let semantic_review: std::collections::BTreeSet<&str> =
        diffs.iter().map(|d| d.path.as_str()).collect();

    let mut safe_items = Vec::new();
    let mut review_items = Vec::new();
    let mut unsafe_items = Vec::new();

    for c in &scan.collisions {
        if c.class == ConflictClass::Identical {
            continue;
        }
        let item = |reason: &str| OverlayPlanItem {
            path: c.path.clone(),
            class: c.class.as_str().to_string(),
            writers: c.writers.clone(),
            reason: reason.to_string(),
        };

        if c.class.is_safe_merge() {
            safe_items.push(item("deterministic, order-independent merge"));
            continue;
        }
        // Semantic escalation: a recipe/lang path where Layer M proved the meaning
        // differs always needs review, regardless of byte class.
        if semantic_review.contains(c.path.as_str()) {
            review_items.push(item("writers disagree semantically (output/text changes) — choose a winner"));
            continue;
        }
        match c.class {
            ConflictClass::TagReplaceOrderDependent
            | ConflictClass::TagMixedRequired
            | ConflictClass::LangFormatMismatch
            | ConflictClass::JsonMergeCandidate => {
                review_items.push(item("order-dependent or unproven merge — review before applying"));
            }
            _ => {
                unsafe_items.push(item("order-dependent winner pick; load order decides at runtime"));
            }
        }
    }

    safe_items.sort_by(|a, b| a.path.cmp(&b.path));
    review_items.sort_by(|a, b| a.path.cmp(&b.path));
    unsafe_items.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(OverlayPlanV2 {
        schema: "intermed-overlay-plan-v2".to_string(),
        source_mods_dir: mods_dir.display().to_string(),
        safe_items,
        review_items,
        unsafe_items,
        writer_order_policy: "lexical-preview".to_string(),
        runtime_order_known: false,
    })
}
