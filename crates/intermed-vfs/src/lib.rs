//! # intermed-vfs — Layer E (Phase 3)
//!
//! Resource / data conflict analysis for Minecraft modpacks. This crate stays
//! read-only: it scans jar resources, emits facts, and classifies collisions.
//! File-writing overlay previews live in `intermed-packops`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use intermed_doctor_core::evidence::Finding;
use intermed_doctor_core::facts::{kind, SourceRef};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, JarCache, Layer, Rule, RuleCtx, Target, TargetKind,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const EXTRACTOR: &str = "vfs-scanner";
/// Cache key version for this collector's payload. The crate version invalidates
/// the cache automatically on every release; bump the trailing revision when the
/// scan logic changes within a single release.
const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-r3");

/// Implementation status for help text.
pub const STATUS: &str = "active: Phase 3";

/// The Layer-E collector.
pub fn collector() -> impl Collector {
    ResourceCollector
}

/// The Layer-E resource conflict rule.
pub fn rule() -> impl Rule {
    ResourceConflictRule
}

/// Resource collision classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictClass {
    /// Multiple jars write byte-for-byte identical content.
    Identical,
    /// Generic / sounds JSON files look mergeable as a key union, but no
    /// commutative merge rule is *proven* safe for them yet.
    JsonMergeCandidate,
    /// A domain JSON that is a single document (recipe / loot table / advancement
    /// / blockstate / model / atlas / `pack.mcmeta`): multiple writers mean a
    /// load-order override, not a mergeable union.
    JsonOverride,
    /// Minecraft tag JSON, all writers append-only (no `replace`) — a safe,
    /// order-independent set union.
    SafeCrdtMerge,
    /// Tag JSON where at least one writer sets `"replace": true`: the result
    /// depends on writer order, so it is **not** a safe CRDT merge.
    TagReplaceOrderDependent,
    /// Tag JSON whose object entries carry `required` flags — set union is
    /// possible but the optional/required semantics need review.
    TagMixedRequired,
    /// A tag-path JSON that does not parse as a valid tag document.
    TagInvalid,
    /// JSON language files (`assets/*/lang/*.json`) differ only in translation keys.
    LangJsonMerge,
    /// Legacy Forge `.lang` property files differ only in key lines.
    LangPropertiesMerge,
    /// The same locale is provided as both JSON and `.lang` (incompatible formats).
    LangFormatMismatch,
    /// Later writer replaces earlier content; order matters.
    UnsafeReplace,
}

impl ConflictClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ConflictClass::Identical => "identical",
            ConflictClass::JsonMergeCandidate => "json-merge-candidate",
            ConflictClass::JsonOverride => "json-override",
            ConflictClass::SafeCrdtMerge => "safe-crdt-merge",
            ConflictClass::TagReplaceOrderDependent => "tag-replace-order-dependent",
            ConflictClass::TagMixedRequired => "tag-mixed-required",
            ConflictClass::TagInvalid => "tag-invalid",
            ConflictClass::LangJsonMerge => "lang-json-merge",
            ConflictClass::LangPropertiesMerge => "lang-properties-merge",
            ConflictClass::LangFormatMismatch => "lang-format-mismatch",
            ConflictClass::UnsafeReplace => "unsafe-replace",
        }
    }

    /// Whether this class has a proven order-independent merge. Only these are
    /// written into an overlay by default (see `intermed-packops`); everything
    /// else is a winner-pick *preview*, not a safe fix.
    pub fn is_safe_merge(self) -> bool {
        matches!(
            self,
            ConflictClass::Identical
                | ConflictClass::SafeCrdtMerge
                | ConflictClass::LangJsonMerge
                | ConflictClass::LangPropertiesMerge
        )
    }
}

/// The Minecraft data/asset domain of a resource path. Independent of merge
/// safety (which is [`ConflictClass`]): the domain says *what kind of file* this
/// is, so reports can explain a collision in the right vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JsonDomain {
    Recipe,
    LootTable,
    Advancement,
    Tag,
    Blockstate,
    Model,
    Atlas,
    Sounds,
    Lang,
    PackMcmeta,
    GenericJson,
    BinaryAsset,
}

impl JsonDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            JsonDomain::Recipe => "recipe",
            JsonDomain::LootTable => "loot-table",
            JsonDomain::Advancement => "advancement",
            JsonDomain::Tag => "tag",
            JsonDomain::Blockstate => "blockstate",
            JsonDomain::Model => "model",
            JsonDomain::Atlas => "atlas",
            JsonDomain::Sounds => "sounds",
            JsonDomain::Lang => "lang",
            JsonDomain::PackMcmeta => "pack-mcmeta",
            JsonDomain::GenericJson => "generic-json",
            JsonDomain::BinaryAsset => "binary-asset",
        }
    }

    /// A single-document JSON file: two writers at the same path is an override
    /// decided by load order, never a mergeable union.
    fn is_single_document(self) -> bool {
        matches!(
            self,
            JsonDomain::Recipe
                | JsonDomain::LootTable
                | JsonDomain::Advancement
                | JsonDomain::Blockstate
                | JsonDomain::Model
                | JsonDomain::Atlas
                | JsonDomain::PackMcmeta
        )
    }
}

/// Classify a resource path into its Minecraft domain.
pub fn json_domain(path: &str) -> JsonDomain {
    if path == "pack.mcmeta" {
        return JsonDomain::PackMcmeta;
    }
    if !is_json_path(path) {
        return JsonDomain::BinaryAsset;
    }
    if is_tag_json_path(path) {
        return JsonDomain::Tag;
    }
    if is_lang_json_path(path) {
        return JsonDomain::Lang;
    }
    // `data/<ns>/...` data-pack domains.
    if path.starts_with("data/") {
        if path.contains("/recipe/") || path.contains("/recipes/") {
            return JsonDomain::Recipe;
        }
        if path.contains("/loot_table/") || path.contains("/loot_tables/") {
            return JsonDomain::LootTable;
        }
        if path.contains("/advancement/") || path.contains("/advancements/") {
            return JsonDomain::Advancement;
        }
    }
    // `assets/<ns>/...` resource-pack domains.
    if path.starts_with("assets/") {
        if path.ends_with("/sounds.json") {
            return JsonDomain::Sounds;
        }
        if path.contains("/blockstates/") {
            return JsonDomain::Blockstate;
        }
        if path.contains("/models/") {
            return JsonDomain::Model;
        }
        if path.contains("/atlases/") {
            return JsonDomain::Atlas;
        }
    }
    JsonDomain::GenericJson
}

/// A single resource writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceWrite {
    pub path: String,
    pub writer: String,
    pub archive: String,
    pub size: u64,
    pub json: bool,
}

/// A path written by more than one archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCollision {
    pub path: String,
    pub writers: Vec<String>,
    pub archives: Vec<String>,
    pub class: ConflictClass,
    pub reason: String,
}

/// An archive that could not be inspected. Scans are tolerant: one bad jar does
/// not hide evidence from the rest of the pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceScanFailure {
    pub archive: String,
    pub reason: String,
}

/// Result of a VFS scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceScan {
    pub target: String,
    pub writes: Vec<ResourceWrite>,
    pub collisions: Vec<ResourceCollision>,
    pub failures: Vec<ResourceScanFailure>,
    /// `(archive, reason)` for jars whose scan hit a resource limit (DoS guard).
    #[serde(default)]
    pub truncations: Vec<(String, String)>,
    #[serde(skip)]
    blobs: Vec<ResourceBlob>,
}

impl ResourceScan {
    /// Return resource bytes for the deterministic overlay winner.
    pub fn winning_blob(&self, path: &str) -> Option<&[u8]> {
        self.blobs
            .iter()
            .filter(|b| b.path == path)
            .max_by(|a, b| {
                a.archive
                    .cmp(&b.archive)
                    .then_with(|| a.writer.cmp(&b.writer))
            })
            .map(|b| b.bytes.as_slice())
    }

    /// Return all blobs for a resource path in deterministic order.
    pub fn blobs_for_path(&self, path: &str) -> Vec<&[u8]> {
        let mut blobs: Vec<&ResourceBlob> = self.blobs.iter().filter(|b| b.path == path).collect();
        blobs.sort_by(|a, b| {
            a.archive
                .cmp(&b.archive)
                .then_with(|| a.writer.cmp(&b.writer))
        });
        blobs.into_iter().map(|b| b.bytes.as_slice()).collect()
    }
}

#[derive(Debug, Clone)]
struct ResourceBlob {
    path: String,
    writer: String,
    archive: String,
    bytes: Vec<u8>,
}

/// VFS scan failure.
#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct ScanError {
    message: String,
}

impl ScanError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

// ── Collector ─────────────────────────────────────────────────────────────

pub struct ResourceCollector;

impl Collector for ResourceCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }

    fn layer(&self) -> Layer {
        Layer::Resource
    }

    fn applies(&self, target: &Target) -> bool {
        mods_dir(target).is_some()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let Some(dir) = mods_dir(ctx.target) else {
            return CollectorOutcome::skipped("no mods directory for VFS scan");
        };
        match scan_mods_dir_filtered(&dir, ctx.jar_cache, &ctx.settings.scan) {
            Ok(scan) => {
                let emitted = emit_scan(ctx, &scan);
                CollectorOutcome::active(
                    emitted,
                    format!(
                        "{} resource writer(s), {} collision(s), {} scan failure(s)",
                        scan.writes.len(),
                        scan.collisions.len(),
                        scan.failures.len()
                    ),
                )
            }
            Err(e) => CollectorOutcome::failed(e.to_string()),
        }
    }
}

fn emit_scan(ctx: &mut CollectCtx<'_>, scan: &ResourceScan) -> usize {
    let mut emitted = 0usize;
    for (archive, reason) in &scan.truncations {
        ctx.store
            .fact(EXTRACTOR, kind::SCAN_TRUNCATED)
            .subject(archive.clone())
            .attr("layer", "resource")
            .attr("reason", reason.clone())
            .source(SourceRef::file(archive.clone()))
            .confidence(0.95)
            .emit();
        emitted += 1;
    }
    for w in &scan.writes {
        ctx.store
            .fact(EXTRACTOR, kind::RESOURCE_WRITER)
            .subject(w.writer.clone())
            .attr("path", w.path.clone())
            .attr("archive", w.archive.clone())
            .attr("size", w.size as i64)
            .attr("json", w.json)
            .source(SourceRef::inside(w.archive.clone(), w.path.clone()))
            .emit();
        emitted += 1;
    }

    for c in &scan.collisions {
        ctx.store
            .fact(EXTRACTOR, kind::RESOURCE_COLLISION)
            .subject(c.path.clone())
            .attr("writers", c.writers.join(","))
            .attr("archives", c.archives.join(","))
            .attr("class", c.class.as_str())
            .attr("domain", json_domain(&c.path).as_str())
            .attr("safe_merge", c.class.is_safe_merge())
            .attr("reason", c.reason.clone())
            .source(SourceRef::file(c.path.clone()))
            .emit();
        emitted += 1;

        let kind = match c.class {
            ConflictClass::Identical => None,
            ConflictClass::JsonMergeCandidate => Some(kind::JSON_MERGE_CANDIDATE),
            ConflictClass::JsonOverride => Some(kind::JSON_OVERRIDE_CONFLICT),
            ConflictClass::SafeCrdtMerge => Some(kind::SAFE_CRDT_MERGE),
            ConflictClass::TagReplaceOrderDependent => Some(kind::TAG_REPLACE_CONFLICT),
            ConflictClass::TagMixedRequired => Some(kind::TAG_MIXED_REQUIRED),
            ConflictClass::TagInvalid => Some(kind::TAG_INVALID),
            ConflictClass::LangJsonMerge => Some(kind::LANG_JSON_MERGE),
            ConflictClass::LangPropertiesMerge => Some(kind::LANG_PROPERTIES_MERGE),
            ConflictClass::LangFormatMismatch => Some(kind::LANG_FORMAT_CONFLICT),
            ConflictClass::UnsafeReplace => Some(kind::UNSAFE_REPLACE_CONFLICT),
        };
        if let Some(predicate) = kind {
            ctx.store
                .fact(EXTRACTOR, predicate)
                .subject(c.path.clone())
                .attr("writers", c.writers.join(","))
                .attr("reason", c.reason.clone())
                .source(SourceRef::file(c.path.clone()))
                .emit();
            emitted += 1;
        }
    }

    for failure in &scan.failures {
        ctx.store
            .fact(EXTRACTOR, kind::UNPARSEABLE_ARCHIVE)
            .subject(failure.archive.clone())
            .attr("reason", failure.reason.clone())
            .source(SourceRef::file(failure.archive.clone()))
            .confidence(0.9)
            .emit();
        emitted += 1;
    }
    emitted
}

// ── Rule ─────────────────────────────────────────────────────────────────

pub struct ResourceConflictRule;

impl Rule for ResourceConflictRule {
    fn id(&self) -> &'static str {
        "resource-conflict"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        // Evaluate *only* the resource-conflict rules, not the whole core pack.
        // The declarative core pack is the single source of truth for the
        // resource-conflict logic, but this layer must not silently run unrelated
        // rules (security, deps, …): that would duplicate work and, since the
        // engine also registers the full declarative pack, surface the other
        // layers' findings a second time under this rule's id.
        let pack = resource_conflict_pack();
        intermed_rules::evaluate_pack(&pack, ctx)
    }
}

/// The subset of the core declarative pack that emits `resource-conflict`
/// findings. Derived from the canonical pack so the logic never drifts.
fn resource_conflict_pack() -> intermed_rules::RulePack {
    let mut pack = intermed_rules::default_core_pack_v2();
    pack.rules.retain(|spec| {
        let emitted_rule_id = spec.finding.rule_id.as_deref().unwrap_or(&spec.id);
        emitted_rule_id == "resource-conflict"
    });
    pack
}

// ── Scanner ──────────────────────────────────────────────────────────────

pub fn scan_target(target: &Target) -> Result<ResourceScan, ScanError> {
    let Some(dir) = mods_dir(target) else {
        return Err(ScanError::new("target has no mods directory"));
    };
    scan_mods_dir(&dir)
}

pub fn scan_mods_dir(dir: &Path) -> Result<ResourceScan, ScanError> {
    scan_mods_dir_with_cache(dir, None)
}

pub fn scan_mods_dir_with_cache(
    dir: &Path,
    cache: Option<&JarCache>,
) -> Result<ResourceScan, ScanError> {
    scan_mods_dir_filtered(dir, cache, &intermed_doctor_core::ScanSettings::default())
}

/// Like [`scan_mods_dir_with_cache`] but honors incremental [`ScanSettings`].
pub fn scan_mods_dir_filtered(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
) -> Result<ResourceScan, ScanError> {
    if !dir.is_dir() {
        return Err(ScanError::new(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }

    let jars = intermed_doctor_core::list_jar_archives(dir, scan).map_err(|e| {
        ScanError::new(format!("read {}: {e}", dir.display()))
    })?;

    // Independent per-jar resource enumeration; fan out across cores.
    // `par_iter().map()` preserves order for deterministic aggregation.
    let scanned: Vec<(String, CachedVfsJar)> = jars
        .par_iter()
        .map(|jar| {
            let archive = file_name_of(jar);
            let cached = match cache {
                Some(c) => c.get_or_scan(EXTRACTOR, CACHE_VERSION, jar, || scan_jar_cached(jar)),
                None => scan_jar_cached(jar),
            };
            (archive, cached)
        })
        .collect();

    let mut writes = Vec::new();
    let mut blobs = Vec::new();
    let mut failures = Vec::new();
    let mut truncations = Vec::new();
    for (archive, cached) in scanned {
        match cached {
            CachedVfsJar::Ok(partial) => {
                writes.extend(partial.writes);
                for blob in partial.blobs {
                    blobs.push(ResourceBlob {
                        path: blob.path,
                        writer: blob.writer,
                        archive: blob.archive,
                        bytes: blob.bytes,
                    });
                }
                for reason in partial.truncations {
                    truncations.push((archive.clone(), reason));
                }
            }
            CachedVfsJar::Err(reason) => failures.push(ResourceScanFailure { archive, reason }),
        }
    }

    let mut collisions = classify_collisions(&blobs);
    collisions.extend(detect_cross_format_lang_collisions(&writes));
    collisions.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(ResourceScan {
        target: dir.display().to_string(),
        writes,
        collisions,
        failures,
        truncations,
        blobs,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedBlob {
    path: String,
    writer: String,
    archive: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JarVfsPartial {
    writes: Vec<ResourceWrite>,
    blobs: Vec<CachedBlob>,
    #[serde(default)]
    truncations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CachedVfsJar {
    Ok(JarVfsPartial),
    Err(String),
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string()
}

fn scan_jar_cached(jar: &Path) -> CachedVfsJar {
    let mut writes = Vec::new();
    let mut blobs = Vec::new();
    let mut truncations = Vec::new();
    match scan_jar(jar, &mut writes, &mut blobs, &mut truncations) {
        Ok(()) => CachedVfsJar::Ok(JarVfsPartial {
            writes,
            blobs: blobs
                .into_iter()
                .map(|b| CachedBlob {
                    path: b.path,
                    writer: b.writer,
                    archive: b.archive,
                    bytes: b.bytes,
                })
                .collect(),
            truncations,
        }),
        Err(e) => CachedVfsJar::Err(e.to_string()),
    }
}

/// Per-jar resource scan limits. Minecraft jars are untrusted input: a malicious
/// archive can declare an enormous resource, thousands of entries, or a zip bomb.
/// These caps bound memory and time; exceeding one records a `scan_truncated`
/// diagnostic rather than silently dropping evidence.
const MAX_RESOURCE_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RESOURCE_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RESOURCE_ENTRIES: usize = 50_000;

fn scan_jar(
    jar: &Path,
    writes: &mut Vec<ResourceWrite>,
    blobs: &mut Vec<ResourceBlob>,
    truncations: &mut Vec<String>,
) -> Result<(), ScanError> {
    let file = std::fs::File::open(jar)
        .map_err(|e| ScanError::new(format!("open {}: {e}", jar.display())))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| ScanError::new(format!("zip {}: {e}", jar.display())))?;

    let archive_name = jar
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string();
    let writer = detect_writer_id(&mut archive).unwrap_or_else(|| archive_stem(&archive_name));

    let mut total_bytes: u64 = 0;
    let mut resource_entries = 0usize;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| ScanError::new(format!("read {} entry {i}: {e}", jar.display())))?;
        if entry.is_dir() {
            continue;
        }
        let path = normalize_resource_path(entry.name());
        if !is_resource_path(&path) || !is_safe_resource_path(&path) {
            continue;
        }

        resource_entries += 1;
        if resource_entries > MAX_RESOURCE_ENTRIES {
            truncations.push(format!(
                "stopped after {MAX_RESOURCE_ENTRIES} resource entries (archive has more)"
            ));
            break;
        }
        // Skip an entry whose declared size alone blows the per-entry cap, before
        // allocating anything for it.
        if entry.size() > MAX_RESOURCE_ENTRY_BYTES {
            truncations.push(format!(
                "{path}: {} bytes exceeds {MAX_RESOURCE_ENTRY_BYTES} byte entry cap, skipped",
                entry.size()
            ));
            continue;
        }
        if total_bytes >= MAX_RESOURCE_TOTAL_BYTES {
            truncations.push(format!(
                "reached {MAX_RESOURCE_TOTAL_BYTES} byte total cap; remaining entries skipped"
            ));
            break;
        }

        // Defense in depth against a lying zip header: cap the actual read too.
        let mut bytes = Vec::new();
        let read_cap = MAX_RESOURCE_ENTRY_BYTES.saturating_add(1);
        std::io::Read::take(&mut entry, read_cap)
            .read_to_end(&mut bytes)
            .map_err(|e| ScanError::new(format!("read {}!{path}: {e}", jar.display())))?;
        if bytes.len() as u64 > MAX_RESOURCE_ENTRY_BYTES {
            truncations.push(format!(
                "{path}: decompressed past {MAX_RESOURCE_ENTRY_BYTES} byte cap, skipped"
            ));
            continue;
        }
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        let json =
            is_json_path(&path) && serde_json::from_slice::<serde_json::Value>(&bytes).is_ok();

        writes.push(ResourceWrite {
            path: path.clone(),
            writer: writer.clone(),
            archive: archive_name.clone(),
            size: bytes.len() as u64,
            json,
        });
        blobs.push(ResourceBlob {
            path,
            writer: writer.clone(),
            archive: archive_name.clone(),
            bytes,
        });
    }
    Ok(())
}

fn classify_collisions(blobs: &[ResourceBlob]) -> Vec<ResourceCollision> {
    let mut by_path: BTreeMap<&str, Vec<&ResourceBlob>> = BTreeMap::new();
    for blob in blobs {
        by_path.entry(blob.path.as_str()).or_default().push(blob);
    }

    let mut out = Vec::new();
    for (path, mut group) in by_path {
        if group.len() < 2 {
            continue;
        }
        group.sort_by(|a, b| {
            a.archive
                .cmp(&b.archive)
                .then_with(|| a.writer.cmp(&b.writer))
        });
        let writers: Vec<String> = group
            .iter()
            .map(|b| b.writer.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let archives: Vec<String> = group.iter().map(|b| b.archive.clone()).collect();

        let (class, reason) = classify_group(path, &group);
        out.push(ResourceCollision {
            path: path.to_string(),
            writers,
            archives,
            class,
            reason,
        });
    }
    out
}

fn classify_group(path: &str, group: &[&ResourceBlob]) -> (ConflictClass, String) {
    if group
        .first()
        .is_some_and(|first| group.iter().all(|b| b.bytes == first.bytes))
    {
        return (
            ConflictClass::Identical,
            "all writers provide byte-identical content".to_string(),
        );
    }

    if is_tag_json_path(path) {
        return classify_tag_group(group);
    }

    if is_lang_json_path(path) && group.iter().all(|b| lang_json_keys(&b.bytes).is_some()) {
        return (
            ConflictClass::LangJsonMerge,
            "JSON language files can be merged as a deterministic key union".to_string(),
        );
    }

    if is_lang_properties_path(path) && group.iter().all(|b| lang_properties_keys(&b.bytes).is_some())
    {
        return (
            ConflictClass::LangPropertiesMerge,
            "`.lang` property files can be merged as a deterministic key union".to_string(),
        );
    }

    // Domain-aware handling of every other JSON: recipes, loot tables,
    // advancements, blockstates, models, atlases, sounds, pack.mcmeta. These are
    // not all "merge candidates" — single-document files (one recipe per file,
    // one model per file, …) are load-order overrides, which we must not present
    // as mergeable.
    if is_json_path(path)
        && group
            .iter()
            .all(|b| serde_json::from_slice::<serde_json::Value>(&b.bytes).is_ok())
    {
        let domain = json_domain(path);
        if domain.is_single_document() {
            return (
                ConflictClass::JsonOverride,
                format!(
                    "{} is a single-document file written by multiple jars; the runtime keeps one \
                     by load order — this is an override, not a merge",
                    domain.as_str()
                ),
            );
        }
        return (
            ConflictClass::JsonMergeCandidate,
            format!(
                "all writers provide valid {} JSON, but a commutative merge rule is not proven safe",
                domain.as_str()
            ),
        );
    }

    (
        ConflictClass::UnsafeReplace,
        "content differs and no safe merge rule is known".to_string(),
    )
}

/// Classify a Minecraft tag-path collision. Vanilla tag merge is a set union of
/// `values`, which is order-independent **only** when no writer sets
/// `"replace": true`. A replace wipes earlier writers, making the outcome
/// order-dependent — so it cannot be advertised as a safe CRDT merge.
fn classify_tag_group(group: &[&ResourceBlob]) -> (ConflictClass, String) {
    let docs: Option<Vec<TagDoc>> = group.iter().map(|b| parse_tag_doc(&b.bytes)).collect();
    let Some(docs) = docs else {
        return (
            ConflictClass::TagInvalid,
            "a writer on this tag path is not a valid tag document (no string/object `values`)"
                .to_string(),
        );
    };
    if docs.iter().any(|d| d.replace) {
        return (
            ConflictClass::TagReplaceOrderDependent,
            "at least one writer sets `\"replace\": true`, which wipes earlier values — the \
             merged result depends on load order and is not a safe CRDT merge"
                .to_string(),
        );
    }
    if docs.iter().any(|d| d.has_required_flag) {
        return (
            ConflictClass::TagMixedRequired,
            "tag entries carry `required` flags; values can still union but the optional/required \
             semantics should be reviewed"
                .to_string(),
        );
    }
    (
        ConflictClass::SafeCrdtMerge,
        "all writers append values without replace — a deterministic, order-independent set union"
            .to_string(),
    )
}

/// Merge Minecraft tag JSON blobs in deterministic writer order.
///
/// When a writer sets `"replace": true`, it **replaces** the accumulated value
/// set from earlier writers (vanilla / Forge tag merge semantics) before its own
/// `values` are applied. The output carries `"replace": true` when any writer in
/// the chain used replace mode.
pub fn merge_tag_values(blobs: &[&[u8]]) -> Option<Vec<u8>> {
    let mut replace_seen = false;
    let mut values = BTreeSet::new();
    for blob in blobs {
        let (blob_replace, blob_values) = tag_values(blob)?;
        if blob_replace {
            values.clear();
            replace_seen = true;
        }
        values.extend(blob_values);
    }

    let out = serde_json::json!({
        "replace": replace_seen,
        "values": values.into_iter().collect::<Vec<_>>(),
    });
    serde_json::to_vec_pretty(&out).ok()
}

/// Merge JSON language files (`assets/*/lang/*.json`) as a flat key union.
pub fn merge_lang_json(blobs: &[&[u8]]) -> Option<Vec<u8>> {
    let mut keys = BTreeMap::<String, String>::new();
    for blob in blobs {
        let entries = lang_json_keys(blob)?;
        for (k, v) in entries {
            keys.insert(k, v);
        }
    }
    let value: serde_json::Value = keys.into_iter().collect();
    serde_json::to_vec_pretty(&value).ok()
}

/// Merge legacy `.lang` property files as `key=value` lines (sorted keys).
pub fn merge_lang_properties(blobs: &[&[u8]]) -> Option<Vec<u8>> {
    let mut keys = BTreeMap::<String, String>::new();
    for blob in blobs {
        for (k, v) in lang_properties_keys(blob)? {
            keys.insert(k, v);
        }
    }
    let mut lines: Vec<String> = keys
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    lines.sort();
    Some(lines.join("\n").into_bytes())
}

/// Parsed shape of a tag document, used for *classification* (whether the
/// collision is a safe append, an order-dependent replace, or carries
/// optional/required entries). The actual merge uses [`tag_values`].
struct TagDoc {
    replace: bool,
    has_required_flag: bool,
}

fn parse_tag_doc(bytes: &[u8]) -> Option<TagDoc> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = value.as_object()?;
    let values = obj.get("values")?.as_array()?;
    let mut has_required_flag = false;
    for v in values {
        if v.as_str().is_some() {
            continue;
        }
        // Object entries must carry an `id`; a `required` flag marks the
        // optional/required tag semantics worth reviewing.
        let entry = v.as_object()?;
        entry.get("id").and_then(|x| x.as_str())?;
        if entry.contains_key("required") {
            has_required_flag = true;
        }
    }
    let replace = obj
        .get("replace")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    Some(TagDoc {
        replace,
        has_required_flag,
    })
}

fn tag_values(bytes: &[u8]) -> Option<(bool, Vec<String>)> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = value.as_object()?;
    let values = obj.get("values")?.as_array()?;
    let mut out = Vec::new();
    for v in values {
        if let Some(s) = v.as_str() {
            out.push(s.to_string());
        } else if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
            out.push(id.to_string());
        } else {
            return None;
        }
    }
    let replace = obj
        .get("replace")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    Some((replace, out))
}

fn mods_dir(target: &Target) -> Option<PathBuf> {
    if let Some(dir) = &target.mods_dir {
        return Some(dir.clone());
    }
    if matches!(target.kind, TargetKind::ModsDir) {
        return Some(target.path.clone());
    }
    let direct = target.path.join("mods");
    if direct.is_dir() {
        return Some(direct);
    }
    None
}

fn is_resource_path(path: &str) -> bool {
    path == "pack.mcmeta" || path.starts_with("assets/") || path.starts_with("data/")
}

fn is_safe_resource_path(path: &str) -> bool {
    !path.starts_with('/')
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn is_json_path(path: &str) -> bool {
    path.ends_with(".json") || path == "pack.mcmeta"
}

fn is_tag_json_path(path: &str) -> bool {
    path.starts_with("data/") && path.contains("/tags/") && path.ends_with(".json")
}

fn is_lang_json_path(path: &str) -> bool {
    path.starts_with("assets/") && path.contains("/lang/") && path.ends_with(".json")
}

fn is_lang_properties_path(path: &str) -> bool {
    path.starts_with("assets/") && path.contains("/lang/") && path.ends_with(".lang")
}

/// Detect when different mods ship the same locale as JSON **and** `.lang`.
fn detect_cross_format_lang_collisions(writes: &[ResourceWrite]) -> Vec<ResourceCollision> {
    let mut by_locale: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for w in writes {
        let Some((locale_key, ext)) = lang_locale_key(&w.path) else {
            continue;
        };
        by_locale
            .entry(locale_key)
            .or_default()
            .entry(ext.to_string())
            .or_default()
            .insert(w.writer.clone());
    }

    let mut out = Vec::new();
    for (locale_key, formats) in by_locale {
        if formats.len() < 2 {
            continue;
        }
        let mut writers: BTreeSet<String> = BTreeSet::new();
        let mut archives = Vec::new();
        let mut format_list = Vec::new();
        for (ext, mods) in &formats {
            format_list.push(ext.as_str());
            writers.extend(mods.iter().cloned());
        }
        format_list.sort_unstable();
        for w in writes.iter().filter(|w| lang_locale_key(&w.path).is_some_and(|(k, _)| k == locale_key))
        {
            archives.push(w.archive.clone());
        }
        archives.sort_unstable();
        archives.dedup();
        let writers_vec: Vec<String> = writers.into_iter().collect();
        out.push(ResourceCollision {
            path: locale_key.clone(),
            writers: writers_vec,
            archives,
            class: ConflictClass::LangFormatMismatch,
            reason: format!(
                "locale `{}` is shipped as both {} — JSON and `.lang` cannot be merged safely",
                locale_key,
                format_list.join(" and ")
            ),
        });
    }
    out
}

/// Stable locale identity: `assets/<namespace>/lang/<locale>` without extension.
fn lang_locale_key(path: &str) -> Option<(String, &'static str)> {
    if !path.starts_with("assets/") || !path.contains("/lang/") {
        return None;
    }
    if path.ends_with(".json") {
        let base = path.strip_suffix(".json")?;
        return Some((base.to_string(), "json"));
    }
    if path.ends_with(".lang") {
        let base = path.strip_suffix(".lang")?;
        return Some((base.to_string(), "lang"));
    }
    None
}

fn lang_json_keys(bytes: &[u8]) -> Option<BTreeMap<String, String>> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = value.as_object()?;
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        if let Some(s) = v.as_str() {
            out.insert(k.clone(), s.to_string());
        } else {
            return None;
        }
    }
    Some(out)
}

fn lang_properties_keys(bytes: &[u8]) -> Option<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        let key = key.trim();
        if key.is_empty() {
            return None;
        }
        out.insert(key.to_string(), value.trim().to_string());
    }
    Some(out)
}

fn normalize_resource_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn archive_stem(name: &str) -> String {
    name.strip_suffix(".jar").unwrap_or(name).to_string()
}

fn detect_writer_id(archive: &mut zip::ZipArchive<std::fs::File>) -> Option<String> {
    read_zip_text(archive, "fabric.mod.json")
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_string))
        })
        .or_else(|| {
            read_zip_text(archive, "quilt.mod.json").and_then(|text| {
                serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| {
                        v.get("quilt_loader")
                            .and_then(|q| q.get("id"))
                            .and_then(|x| x.as_str())
                            .map(str::to_string)
                    })
            })
        })
        .or_else(|| {
            read_zip_text(archive, "META-INF/mods.toml")
                .or_else(|| read_zip_text(archive, "META-INF/neoforge.mods.toml"))
                .and_then(|text| {
                    text.lines()
                        .find_map(|line| line.trim().strip_prefix("modId"))
                        .and_then(|rest| rest.split_once('='))
                        .map(|(_, value)| value.trim().trim_matches('"').to_string())
                })
        })
        .or_else(|| {
            read_zip_text(archive, "plugin.yml")
                .or_else(|| read_zip_text(archive, "paper-plugin.yml"))
                .and_then(|text| {
                    text.lines()
                        .find_map(|line| line.trim().strip_prefix("name:"))
                        .map(|value| value.trim().to_string())
                })
        })
}

fn read_zip_text(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Option<String> {
    let mut entry = archive.by_name(name).ok()?;
    let mut text = String::new();
    entry.read_to_string(&mut text).ok()?;
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_tag_values_as_set() {
        let a = br#"{"values":["minecraft:stone","minecraft:dirt"]}"#;
        let b = br#"{"values":["minecraft:dirt","minecraft:granite"]}"#;
        let merged = merge_tag_values(&[a.as_slice(), b.as_slice()]).unwrap();
        let text = String::from_utf8(merged).unwrap();
        assert!(text.contains("minecraft:stone"));
        assert!(text.contains("minecraft:granite"));
    }

    #[test]
    fn replace_true_clears_prior_tag_values() {
        let base = br#"{"values":["minecraft:stone","minecraft:dirt"]}"#;
        let wipe = br#"{"replace":true,"values":["minecraft:granite"]}"#;
        let merged = merge_tag_values(&[base.as_slice(), wipe.as_slice()]).unwrap();
        let text = String::from_utf8(merged).unwrap();
        assert!(text.contains("minecraft:granite"));
        assert!(!text.contains("minecraft:stone"));
        assert!(text.contains(r#""replace": true"#));
    }

    #[test]
    fn merges_lang_json_keys() {
        let a = br#"{"item.a":"A","item.b":"B"}"#;
        let b = br#"{"item.b":"B2","item.c":"C"}"#;
        let merged = merge_lang_json(&[a.as_slice(), b.as_slice()]).unwrap();
        let text = String::from_utf8(merged).unwrap();
        assert!(text.contains("item.a"));
        assert!(text.contains(r#""A""#));
        assert!(text.contains("item.c"));
        assert!(text.contains(r#""B2""#));
    }

    #[test]
    fn classifies_tags_as_safe_merge() {
        let blobs = vec![
            ResourceBlob {
                path: "data/minecraft/tags/items/axes.json".into(),
                writer: "a".into(),
                archive: "a.jar".into(),
                bytes: br#"{"values":["a:x"]}"#.to_vec(),
            },
            ResourceBlob {
                path: "data/minecraft/tags/items/axes.json".into(),
                writer: "b".into(),
                archive: "b.jar".into(),
                bytes: br#"{"values":["b:y"]}"#.to_vec(),
            },
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].class, ConflictClass::SafeCrdtMerge);
    }

    fn blob(path: &str, writer: &str, bytes: &[u8]) -> ResourceBlob {
        ResourceBlob {
            path: path.into(),
            writer: writer.into(),
            archive: format!("{writer}.jar"),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn tag_replace_is_order_dependent_not_safe() {
        let blobs = vec![
            blob("data/c/tags/items/t.json", "a", br#"{"values":["a:x"]}"#),
            blob(
                "data/c/tags/items/t.json",
                "b",
                br#"{"replace":true,"values":["b:y"]}"#,
            ),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::TagReplaceOrderDependent);
    }

    #[test]
    fn tag_with_required_flag_needs_review() {
        let blobs = vec![
            blob("data/c/tags/items/t.json", "a", br#"{"values":["a:x"]}"#),
            blob(
                "data/c/tags/items/t.json",
                "b",
                br#"{"values":[{"id":"b:y","required":false}]}"#,
            ),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::TagMixedRequired);
    }

    #[test]
    fn invalid_tag_path_is_tag_invalid() {
        let blobs = vec![
            blob("data/c/tags/items/t.json", "a", br#"{"values":["a:x"]}"#),
            blob("data/c/tags/items/t.json", "b", br#"{"not_values":1}"#),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::TagInvalid);
    }

    #[test]
    fn recipe_collision_is_override_not_merge() {
        let blobs = vec![
            blob("data/c/recipes/r.json", "a", br#"{"type":"a"}"#),
            blob("data/c/recipes/r.json", "b", br#"{"type":"b"}"#),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::JsonOverride);
        assert_eq!(json_domain("data/c/recipes/r.json"), JsonDomain::Recipe);
    }

    #[test]
    fn generic_json_is_merge_candidate() {
        let blobs = vec![
            blob("assets/c/sounds.json", "a", br#"{"a":{"sounds":["x"]}}"#),
            blob("assets/c/sounds.json", "b", br#"{"b":{"sounds":["y"]}}"#),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::JsonMergeCandidate);
        assert_eq!(json_domain("assets/c/sounds.json"), JsonDomain::Sounds);
    }
}
