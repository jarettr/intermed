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
use intermed_doctor_core::facts::{SourceRef, kind};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, JarCache, Layer, Rule, RuleCtx, Target, TargetKind,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const EXTRACTOR: &str = "vfs-scanner";
/// Cache key version for this collector's payload. The crate version invalidates
/// the cache automatically on every release; bump the trailing revision when the
/// scan logic changes within a single release.
// `-r4`: per-jar cache no longer stores resource blobs (two-pass scan re-reads
// only collision paths), so old `-r3` entries with blobs are invalidated.
// `-r5`: mods.toml writer-id parse scoped to `[[mods]]` + comment/quote-safe, so
// cached writer names from the old parse (e.g. `x" # mandatory`) are invalidated.
const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-r5");

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
    /// A JSON *object* whose writers' top-level keys are disjoint (or agree on
    /// shared keys): a deterministic, order-independent key union — e.g. a
    /// `sounds.json` where each mod registers its own sound events. Safe to merge.
    SafeJsonObjectMerge,
    /// A root pack descriptor (`pack.mcmeta`, root `pack.png`): every resource
    /// pack ships one. The override is expected, not a conflict — an overlay
    /// carries its own. Surfaced only for explain/overlay, not as a problem.
    RootMetadata,
    /// `assets/<ns>/atlases/*.json` written by multiple jars. Atlas sources are a
    /// list the game reads from one file by load order — dropping another writer's
    /// sources. Not a plain merge; order-dependent.
    OrderDependentAtlas,
    /// `sounds.json` where writers define the *same* sound event differently. The
    /// object merges, but the conflicting event is resolved by load order.
    OrderDependentSoundDef,
    /// A shader program/include (`assets/<ns>/shaders/**`) overridden by multiple
    /// jars. Shader pipelines are load-order sensitive and loader-specific.
    OrderDependentShader,
    /// A binary asset (texture / font / sound file / …) provided with differing
    /// bytes by multiple jars: a load-order override. Severity depends on the
    /// asset domain (a texture override is cosmetic; a font/shader override is not).
    BinaryOverride,
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
            ConflictClass::SafeJsonObjectMerge => "safe-json-object-merge",
            ConflictClass::RootMetadata => "root-metadata",
            ConflictClass::OrderDependentAtlas => "order-dependent-atlas",
            ConflictClass::OrderDependentSoundDef => "order-dependent-sound-def",
            ConflictClass::OrderDependentShader => "order-dependent-shader",
            ConflictClass::BinaryOverride => "binary-override",
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
                | ConflictClass::SafeJsonObjectMerge
                | ConflictClass::LangJsonMerge
                | ConflictClass::LangPropertiesMerge
        )
    }

    /// Whether the resolved outcome depends on loader/resource-pack load order
    /// (an override, not a union). These need a chosen winner, not a merge.
    pub fn is_order_dependent(self) -> bool {
        matches!(
            self,
            ConflictClass::JsonOverride
                | ConflictClass::TagReplaceOrderDependent
                | ConflictClass::OrderDependentAtlas
                | ConflictClass::OrderDependentSoundDef
                | ConflictClass::OrderDependentShader
                | ConflictClass::BinaryOverride
                | ConflictClass::UnsafeReplace
        )
    }

    /// What an overlay generator would do to resolve this collision, as the
    /// stable `action` term of a [`kind::RESOURCE_OVERLAY_ACTION`] fact.
    pub fn overlay_action(self) -> &'static str {
        match self {
            ConflictClass::Identical => "keep-any",
            ConflictClass::SafeCrdtMerge
            | ConflictClass::SafeJsonObjectMerge
            | ConflictClass::LangJsonMerge
            | ConflictClass::LangPropertiesMerge => "merge",
            // pack.mcmeta: an overlay must generate its *own*, not copy a writer's.
            ConflictClass::RootMetadata => "generate-own",
            // Everything order-dependent needs an explicit winner picked.
            _ => "pick-winner",
        }
    }
}

/// How confidently InterMed can predict the *resolved* outcome of a collision.
///
/// For a safe union the outcome is independent of order, so confidence is `High`.
/// For an order-dependent override the winner is whichever jar the loader places
/// last — and a static mods-dir scan does not know the loader's final order
/// (it depends on dependency sorting, file names, and loader version), so we are
/// honest: `Low`. This is reported as `load_order_confidence`, never as a claim
/// that the outcome is "nondeterministic".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadOrderConfidence {
    /// Outcome is order-independent (a union / identical content).
    High,
    /// Outcome depends on order, but a deterministic tiebreak is documented.
    Medium,
    /// Outcome depends on a loader load order this scan cannot observe.
    Low,
}

impl LoadOrderConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            LoadOrderConfidence::High => "high",
            LoadOrderConfidence::Medium => "medium",
            LoadOrderConfidence::Low => "low",
        }
    }

    /// The confidence implied by a collision class.
    fn for_class(class: ConflictClass) -> Self {
        if class.is_safe_merge() {
            LoadOrderConfidence::High
        } else if matches!(
            class,
            ConflictClass::RootMetadata | ConflictClass::TagMixedRequired
        ) {
            // Resolvable without knowing loader order (own metadata / union + flag review).
            LoadOrderConfidence::Medium
        } else {
            LoadOrderConfidence::Low
        }
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
    Shader,
    Font,
    Particle,
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
            JsonDomain::Shader => "shader",
            JsonDomain::Font => "font",
            JsonDomain::Particle => "particle",
            JsonDomain::Lang => "lang",
            JsonDomain::PackMcmeta => "pack-mcmeta",
            JsonDomain::GenericJson => "generic-json",
            JsonDomain::BinaryAsset => "binary-asset",
        }
    }

    /// A single-document JSON file: two writers at the same path is an override
    /// decided by load order, never a mergeable union. (Atlas / sounds / shader /
    /// pack.mcmeta have *dedicated* classes and are dispatched before this check.)
    fn is_single_document(self) -> bool {
        matches!(
            self,
            JsonDomain::Recipe
                | JsonDomain::LootTable
                | JsonDomain::Advancement
                | JsonDomain::Blockstate
                | JsonDomain::Model
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
        if path.contains("/shaders/") {
            return JsonDomain::Shader;
        }
        if path.contains("/font/") {
            return JsonDomain::Font;
        }
        if path.contains("/particles/") {
            return JsonDomain::Particle;
        }
    }
    JsonDomain::GenericJson
}

/// Classify *any* resource path (JSON or binary) into its asset domain. For JSON
/// this is [`json_domain`]; for binary files it recognizes the subtypes whose
/// override severity differs (a texture override is cosmetic, a font/shader
/// override is not). This is what the `domain` term of a collision fact carries.
pub fn asset_domain(path: &str) -> JsonDomain {
    if is_json_path(path) {
        return json_domain(path);
    }
    if path.contains("/shaders/") {
        return JsonDomain::Shader;
    }
    // `font/` providers, and bitmap font sheets under `textures/font/`.
    if path.contains("/font/") {
        return JsonDomain::Font;
    }
    if path.ends_with(".ogg") || path.contains("/sounds/") {
        return JsonDomain::Sounds;
    }
    JsonDomain::BinaryAsset
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
        let confidence = LoadOrderConfidence::for_class(c.class);
        ctx.store
            .fact(EXTRACTOR, kind::RESOURCE_COLLISION)
            .subject(c.path.clone())
            .attr("writers", c.writers.join(","))
            .attr("archives", c.archives.join(","))
            .attr("class", c.class.as_str())
            .attr("domain", asset_domain(&c.path).as_str())
            .attr("safe_merge", c.class.is_safe_merge())
            .attr("order_dependent", c.class.is_order_dependent())
            .attr("load_order_confidence", confidence.as_str())
            .attr("writer_count", c.writers.len() as i64)
            .attr("reason", c.reason.clone())
            .source(SourceRef::file(c.path.clone()))
            .emit();
        emitted += 1;

        // Overlay/PackOps intent: what an overlay generator *would* do. Read-only
        // — Layer E never writes files, but downstream PackOps and the report
        // consume this stable action model (roadmap §4.6).
        ctx.store
            .fact(EXTRACTOR, kind::RESOURCE_OVERLAY_ACTION)
            .subject(c.path.clone())
            .attr("action", c.class.overlay_action())
            .attr(
                "safety",
                if c.class.is_safe_merge() {
                    "safe"
                } else {
                    "manual"
                },
            )
            .attr("class", c.class.as_str())
            .attr("domain", asset_domain(&c.path).as_str())
            .attr("writers", c.writers.join(","))
            .attr("requires_manual_review", !c.class.is_safe_merge())
            .attr("reason", c.reason.clone())
            .source(SourceRef::file(c.path.clone()))
            .emit();
        emitted += 1;

        // Legacy per-class predicate facts retained for the classes that had them
        // (no consumer reads the newer classes' predicates, so none are emitted —
        // avoids a dead fact stream; rules read `resource_collision.class`).
        let kind = match c.class {
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
            // Identical and the Phase-2 classes have no separate predicate.
            _ => None,
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

    let jars = intermed_doctor_core::list_jar_archives(dir, scan)
        .map_err(|e| ScanError::new(format!("read {}: {e}", dir.display())))?;

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

    // Pass 1: aggregate the lightweight write records only (no resource bytes).
    let mut writes = Vec::new();
    let mut failures = Vec::new();
    let mut truncations = Vec::new();
    for (archive, cached) in scanned {
        match cached {
            CachedVfsJar::Ok(partial) => {
                writes.extend(partial.writes);
                for reason in partial.truncations {
                    truncations.push((archive.clone(), reason));
                }
            }
            CachedVfsJar::Err(reason) => failures.push(ResourceScanFailure { archive, reason }),
        }
    }

    // A path written by ≥2 archives is the only kind that can collide (and the only
    // kind any consumer — `classify_collisions` and the overlay `winning_blob` /
    // `blobs_for_path` — ever asks bytes for). Pass 2 re-reads bytes for just those.
    let mut path_writes: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for w in &writes {
        *path_writes.entry(w.path.as_str()).or_default() += 1;
    }
    let collision_paths: BTreeSet<String> = path_writes
        .into_iter()
        .filter(|&(_, n)| n >= 2)
        .map(|(p, _)| p.to_string())
        .collect();

    // Pass 2: re-read resource bytes for collision paths only. This is the sole
    // retained byte buffer, bounded by the colliding-resource volume rather than
    // every resource in every jar.
    let blobs = reread_collision_blobs(&jars, &collision_paths);

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
struct JarVfsPartial {
    writes: Vec<ResourceWrite>,
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
    let mut truncations = Vec::new();
    match scan_jar(jar, &mut writes, &mut truncations) {
        Ok(()) => CachedVfsJar::Ok(JarVfsPartial {
            writes,
            truncations,
        }),
        Err(e) => CachedVfsJar::Err(e.to_string()),
    }
}

/// Pass 2 of the two-pass scan: re-read resource bytes for `collision_paths` only.
/// Mirrors `scan_jar`'s path normalization, writer detection, and per-entry cap so
/// the produced blobs line up with the pass-1 [`ResourceWrite`] records. Not cached
/// (collision membership depends on the whole jar set, not one jar), but cheap: it
/// touches only the small subset of entries whose path collides. Runs per jar in
/// parallel; `classify_collisions` re-sorts each group, so blob order is irrelevant.
fn reread_collision_blobs(
    jars: &[PathBuf],
    collision_paths: &BTreeSet<String>,
) -> Vec<ResourceBlob> {
    if collision_paths.is_empty() {
        return Vec::new();
    }
    jars.par_iter()
        .flat_map_iter(|jar| reread_collision_blobs_one(jar, collision_paths))
        .collect()
}

fn reread_collision_blobs_one(jar: &Path, collision_paths: &BTreeSet<String>) -> Vec<ResourceBlob> {
    let mut out = Vec::new();
    let Ok(file) = std::fs::File::open(jar) else {
        return out;
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return out;
    };
    let archive_name = file_name_of(jar);
    let writer = detect_writer_id(&mut archive).unwrap_or_else(|| archive_stem(&archive_name));
    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let path = normalize_resource_path(entry.name());
        if !collision_paths.contains(&path)
            || !is_resource_path(&path)
            || !is_safe_resource_path(&path)
            || entry.size() > MAX_RESOURCE_ENTRY_BYTES
        {
            continue;
        }
        let mut bytes = Vec::new();
        let read_cap = MAX_RESOURCE_ENTRY_BYTES.saturating_add(1);
        if std::io::Read::take(&mut entry, read_cap)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_RESOURCE_ENTRY_BYTES
        {
            continue;
        }
        out.push(ResourceBlob {
            path,
            writer: writer.clone(),
            archive: archive_name.clone(),
            bytes,
        });
    }
    out
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
            path,
            writer: writer.clone(),
            archive: archive_name.clone(),
            size: bytes.len() as u64,
            json,
        });
        // Pass 1 intentionally drops `bytes`: only `size`/`json` are needed for the
        // write record. Resource bytes are re-read in pass 2 (`reread_collision_blobs`)
        // for the few paths that actually collide — see `scan_mods_dir_filtered`.
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

    if is_lang_json_path(path) {
        if let Some(per_writer) = group
            .iter()
            .map(|b| lang_json_keys(&b.bytes))
            .collect::<Option<Vec<_>>>()
        {
            // Key-level diff: a JSON lang file is always mechanically mergeable as
            // a key union, but report *how many* shared keys map to different text
            // (the last writer wins per key). The semantic "which tooltip shows"
            // finding is Layer M's `lang-key-conflict`; Layer E only records the
            // structural count so the overlay/report can show it without a
            // duplicate finding.
            let conflicts = count_conflicting_keys(&per_writer);
            let reason = if conflicts == 0 {
                "JSON language files merge as a deterministic key union (no shared key differs)"
                    .to_string()
            } else {
                format!(
                    "JSON language files merge as a key union; {conflicts} shared key(s) map to \
                     different text and are resolved by load order"
                )
            };
            return (ConflictClass::LangJsonMerge, reason);
        }
    }

    if is_lang_properties_path(path)
        && group
            .iter()
            .all(|b| lang_properties_keys(&b.bytes).is_some())
    {
        return (
            ConflictClass::LangPropertiesMerge,
            "`.lang` property files can be merged as a deterministic key union".to_string(),
        );
    }

    let domain = asset_domain(path);

    // Root pack descriptor: every pack ships one; the override is expected.
    if domain == JsonDomain::PackMcmeta {
        return (
            ConflictClass::RootMetadata,
            "pack.mcmeta is root pack metadata present in every resource pack; an overlay carries \
             its own rather than copying a writer's"
                .to_string(),
        );
    }

    // Domain-aware handling of JSON whose writers all parse.
    if is_json_path(path)
        && group
            .iter()
            .all(|b| serde_json::from_slice::<serde_json::Value>(&b.bytes).is_ok())
    {
        match domain {
            // Atlas sources are a list one file owns; a second writer drops the
            // first's sources — order-dependent, not a plain merge.
            JsonDomain::Atlas => {
                return (
                    ConflictClass::OrderDependentAtlas,
                    "atlas definitions list texture sources read from one file by load order; \
                     merging is not a plain union — sources can be dropped"
                        .to_string(),
                );
            }
            JsonDomain::Shader => {
                return (
                    ConflictClass::OrderDependentShader,
                    "shader definition overridden by multiple jars; shader pipelines are \
                     load-order sensitive and loader-specific"
                        .to_string(),
                );
            }
            // sounds.json is an object keyed by sound event: disjoint events merge
            // safely; the same event defined differently is an order-dependent pick.
            JsonDomain::Sounds => {
                return classify_object_merge_group(
                    group,
                    ConflictClass::OrderDependentSoundDef,
                    "sound event(s)",
                );
            }
            // Single-document data files: the runtime keeps one by load order.
            d if d.is_single_document() => {
                return (
                    ConflictClass::JsonOverride,
                    format!(
                        "{} is a single-document file written by multiple jars; the runtime keeps \
                         one by load order — this is an override, not a merge",
                        d.as_str()
                    ),
                );
            }
            // Font providers / generic JSON objects: disjoint keys union safely.
            JsonDomain::Font => {
                return (
                    ConflictClass::JsonOverride,
                    "font provider definition kept as one document by load order".to_string(),
                );
            }
            _ => {
                return classify_object_merge_group(
                    group,
                    ConflictClass::JsonMergeCandidate,
                    "key(s)",
                );
            }
        }
    }

    // Non-JSON content that differs: a binary override. Severity is decided by the
    // asset domain downstream (texture cosmetic vs font/shader functional).
    if !is_json_path(path) {
        return (
            ConflictClass::BinaryOverride,
            format!(
                "{} binary asset provided with differing bytes by multiple jars; the runtime keeps \
                 one by load order",
                domain.as_str()
            ),
        );
    }

    (
        ConflictClass::UnsafeReplace,
        "content differs and no safe merge rule is known".to_string(),
    )
}

/// Classify a collision of JSON *objects* by their top-level key sets. Writers
/// whose keys are disjoint (or agree on shared keys) form a deterministic union
/// ([`ConflictClass::SafeJsonObjectMerge`]); a shared key bound to *different*
/// values is resolved by load order (`conflicting_class`).
fn classify_object_merge_group(
    group: &[&ResourceBlob],
    conflicting_class: ConflictClass,
    unit: &str,
) -> (ConflictClass, String) {
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    let mut conflicts: BTreeSet<String> = BTreeSet::new();
    for blob in group {
        let Some(obj) = serde_json::from_slice::<serde_json::Value>(&blob.bytes)
            .ok()
            .and_then(|v| v.as_object().cloned())
        else {
            // Not a flat object on every writer — fall back to "needs review".
            return (
                ConflictClass::JsonMergeCandidate,
                "writers provide valid JSON but not all are objects; a commutative merge is not \
                 proven safe"
                    .to_string(),
            );
        };
        for (k, v) in obj {
            let canonical = v.to_string();
            match merged.get(&k) {
                Some(prev) if prev != &canonical => {
                    conflicts.insert(k);
                }
                _ => {
                    merged.insert(k, canonical);
                }
            }
        }
    }
    if conflicts.is_empty() {
        (
            ConflictClass::SafeJsonObjectMerge,
            "writers define disjoint (or identical) top-level keys — a deterministic, \
             order-independent object union"
                .to_string(),
        )
    } else {
        (
            conflicting_class,
            format!(
                "writers disagree on {} {}: {} — resolved by load order",
                conflicts.len(),
                unit,
                conflicts
                    .iter()
                    .take(6)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    }
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
    let mut lines: Vec<String> = keys.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
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
        for w in writes
            .iter()
            .filter(|w| lang_locale_key(&w.path).is_some_and(|(k, _)| k == locale_key))
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

/// Count shared keys whose mapped value differs across writers (the keys whose
/// resolved text depends on load order). Used for the Layer-E lang key-level diff.
fn count_conflicting_keys(per_writer: &[BTreeMap<String, String>]) -> usize {
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    let mut conflicting: BTreeSet<&str> = BTreeSet::new();
    for map in per_writer {
        for (k, v) in map {
            match seen.get(k.as_str()) {
                Some(prev) if *prev != v.as_str() => {
                    conflicting.insert(k.as_str());
                }
                _ => {
                    seen.insert(k.as_str(), v.as_str());
                }
            }
        }
    }
    conflicting.len()
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
                .and_then(|text| intermed_resource_identity::mod_id_from_mods_toml(&text))
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
    fn sounds_with_disjoint_events_is_safe_object_merge() {
        // Each mod registers its own sound event → deterministic object union.
        let blobs = vec![
            blob(
                "assets/c/sounds.json",
                "a",
                br#"{"a.event":{"sounds":["x"]}}"#,
            ),
            blob(
                "assets/c/sounds.json",
                "b",
                br#"{"b.event":{"sounds":["y"]}}"#,
            ),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::SafeJsonObjectMerge);
        assert!(collisions[0].class.is_safe_merge());
        assert_eq!(json_domain("assets/c/sounds.json"), JsonDomain::Sounds);
    }

    #[test]
    fn sounds_with_conflicting_event_is_order_dependent() {
        // Same event, different definition → resolved by load order.
        let blobs = vec![
            blob(
                "assets/c/sounds.json",
                "a",
                br#"{"shared":{"sounds":["x"]}}"#,
            ),
            blob(
                "assets/c/sounds.json",
                "b",
                br#"{"shared":{"sounds":["y"]}}"#,
            ),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::OrderDependentSoundDef);
        assert!(collisions[0].class.is_order_dependent());
    }

    #[test]
    fn pack_mcmeta_is_root_metadata() {
        let blobs = vec![
            blob("pack.mcmeta", "a", br#"{"pack":{"pack_format":15}}"#),
            blob("pack.mcmeta", "b", br#"{"pack":{"pack_format":18}}"#),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::RootMetadata);
        assert_eq!(collisions[0].class.overlay_action(), "generate-own");
    }

    #[test]
    fn atlas_collision_is_order_dependent_atlas() {
        let blobs = vec![
            blob(
                "assets/minecraft/atlases/blocks.json",
                "a",
                br#"{"sources":[{"type":"directory","source":"a"}]}"#,
            ),
            blob(
                "assets/minecraft/atlases/blocks.json",
                "b",
                br#"{"sources":[{"type":"directory","source":"b"}]}"#,
            ),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::OrderDependentAtlas);
        assert_eq!(
            json_domain("assets/minecraft/atlases/blocks.json"),
            JsonDomain::Atlas
        );
    }

    #[test]
    fn shader_json_is_order_dependent_shader() {
        let blobs = vec![
            blob(
                "assets/minecraft/shaders/core/x.json",
                "a",
                br#"{"vertex":"a"}"#,
            ),
            blob(
                "assets/minecraft/shaders/core/x.json",
                "b",
                br#"{"vertex":"b"}"#,
            ),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::OrderDependentShader);
    }

    #[test]
    fn differing_texture_is_binary_override_with_texture_domain() {
        let blobs = vec![
            blob(
                "assets/c/textures/item/x.png",
                "a",
                &[0x89, 0x50, 0x4e, 0x47, 1],
            ),
            blob(
                "assets/c/textures/item/x.png",
                "b",
                &[0x89, 0x50, 0x4e, 0x47, 2],
            ),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::BinaryOverride);
        // Cosmetic texture domain (drives note-severity rule).
        assert_eq!(
            asset_domain("assets/c/textures/item/x.png"),
            JsonDomain::BinaryAsset
        );
    }

    #[test]
    fn differing_shader_binary_is_functional_domain() {
        let blobs = vec![
            blob(
                "assets/minecraft/shaders/core/x.fsh",
                "a",
                b"void main(){a;}",
            ),
            blob(
                "assets/minecraft/shaders/core/x.fsh",
                "b",
                b"void main(){b;}",
            ),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::BinaryOverride);
        // Functional shader domain (drives warn-severity rule).
        assert_eq!(
            asset_domain("assets/minecraft/shaders/core/x.fsh"),
            JsonDomain::Shader
        );
    }

    #[test]
    fn generic_object_disjoint_keys_is_safe_merge() {
        let blobs = vec![
            blob("assets/c/custom.json", "a", br#"{"a":1}"#),
            blob("assets/c/custom.json", "b", br#"{"b":2}"#),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::SafeJsonObjectMerge);
    }

    #[test]
    fn generic_object_conflicting_keys_is_merge_candidate() {
        let blobs = vec![
            blob("assets/c/custom.json", "a", br#"{"k":1}"#),
            blob("assets/c/custom.json", "b", br#"{"k":2}"#),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::JsonMergeCandidate);
    }

    #[test]
    fn lang_json_reports_conflicting_key_count() {
        // Shared key `item.x` maps to different text; `item.a`/`item.b` are disjoint.
        let blobs = vec![
            blob(
                "assets/c/lang/en_us.json",
                "a",
                br#"{"item.a":"A","item.x":"X1"}"#,
            ),
            blob(
                "assets/c/lang/en_us.json",
                "b",
                br#"{"item.b":"B","item.x":"X2"}"#,
            ),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::LangJsonMerge);
        assert!(
            collisions[0].reason.contains("1 shared key"),
            "reason carries key-level diff count: {}",
            collisions[0].reason
        );
    }

    #[test]
    fn lang_json_disjoint_keys_reports_no_conflict() {
        let blobs = vec![
            blob("assets/c/lang/en_us.json", "a", br#"{"item.a":"A"}"#),
            blob("assets/c/lang/en_us.json", "b", br#"{"item.b":"B"}"#),
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions[0].class, ConflictClass::LangJsonMerge);
        assert!(collisions[0].reason.contains("no shared key differs"));
    }

    #[test]
    fn load_order_confidence_tracks_class() {
        assert_eq!(
            LoadOrderConfidence::for_class(ConflictClass::SafeCrdtMerge),
            LoadOrderConfidence::High
        );
        assert_eq!(
            LoadOrderConfidence::for_class(ConflictClass::JsonOverride),
            LoadOrderConfidence::Low
        );
        assert_eq!(
            LoadOrderConfidence::for_class(ConflictClass::RootMetadata),
            LoadOrderConfidence::Medium
        );
    }
}
