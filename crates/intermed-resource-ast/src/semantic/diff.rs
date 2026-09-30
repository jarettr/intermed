//! Cross-writer semantic diffs.
//!
//! Layer E already classifies *byte-level* collisions (identical, override, safe
//! union). Layer M adds the **semantic** disagreement that bytes can't express:
//! two writers at the same recipe path that craft *different outputs*, or two
//! lang writers that map the *same key to different text*. These are produced
//! here and lowered into `resource_semantic_diff` facts; rules turn the
//! meaningful ones into findings.

use std::collections::BTreeMap;

use crate::model::{ResourceDomain, ResourceSummary};
use crate::semantic::refs::ResourceAstRecord;

/// The kind of semantic disagreement between writers of one resource path.
///
/// Deliberately narrow: Layer M only reports a diff when the disagreement is
/// *semantically meaningful and not already covered by Layer E*. Tags that
/// disagree only in content union safely (benign), so no tag diff is emitted —
/// the anti-false-positive default. Diffs that are already handled at Layer E
/// (byte-level override) are intentionally not re-flagged here.
///
/// The variants cover recipes, language files, loot tables, atlases, models,
/// blockstates, ambiguous same-writer definitions, and other supported datapack
/// domains. New domains are added by implementing `ResourceDomainAnalyzer` and
/// registering it in `ANALYZERS` — no central match arm to touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    /// Same recipe path, writers produce different output item sets.
    RecipeOutputOverride,
    /// Same outputs, but writers use a different recipe `type` (serializer).
    RecipeTypeOverride,
    /// Same outputs and type, but writers use different ingredients.
    RecipeIngredientOverride,
    /// Same recipe otherwise, but writers differ only on load `conditions`.
    RecipeConditionOverride,
    /// Same recipe path, writers use a custom serializer we cannot interpret, and
    /// their raw payloads differ — an opaque difference (we don't claim *what*).
    RecipeOpaqueOverride,
    /// Same loot-table path, writers drop different item/tag sets.
    LootDropOverride,
    /// Same dropped ids, but rolls/weights/conditions/functions/counts differ.
    LootStructureOverride,
    /// Same atlas path, writers list different texture sources (one drops another's).
    AtlasSourceOverride,
    /// Same model path, writers declare a different `parent` model.
    ModelParentOverride,
    /// Same model parent, but texture-slot mappings differ.
    ModelTextureOverride,
    /// Same model parent/textures, but item override predicates or order differ.
    ModelPredicateOverride,
    /// Same blockstate path, writers map to a different set of models/variants.
    BlockstateVariantOverride,
    /// Same advancement path, writers ship different definitions.
    AdvancementOverride,
    /// Same predicate path, writers ship different conditions.
    PredicateOverride,
    /// Same item-modifier path, writers ship different functions.
    ItemModifierOverride,
    /// Same object id in an *unmodelled* datapack registry (damage type, trim
    /// material, banner pattern, dimension type, …) with a different definition.
    /// The generic fallback so coverage doesn't require a parser per registry.
    RegistryObjectOverride,
    /// Same locale file, writers map a shared key to different translations.
    LangKeyConflict,
    /// Same tag path, but at least one writer uses `replace: true` while another
    /// does not, or competing `replace: true` definitions exist — not a safe union.
    TagReplaceOverride,
    /// Multiple physical artifacts with one canonical writer id provide
    /// incompatible definitions at the same path.
    SameWriterAmbiguousDefinition,
}

impl DiffKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DiffKind::RecipeOutputOverride => "recipe-output-override",
            DiffKind::RecipeTypeOverride => "recipe-type-override",
            DiffKind::RecipeIngredientOverride => "recipe-ingredient-override",
            DiffKind::RecipeConditionOverride => "recipe-condition-override",
            DiffKind::RecipeOpaqueOverride => "recipe-opaque-override",
            DiffKind::LootDropOverride => "loot-table-output-override",
            DiffKind::LootStructureOverride => "loot-table-structure-override",
            DiffKind::AtlasSourceOverride => "atlas-source-override",
            DiffKind::ModelParentOverride => "model-override",
            DiffKind::ModelTextureOverride => "model-texture-override",
            DiffKind::ModelPredicateOverride => "model-predicate-override",
            DiffKind::BlockstateVariantOverride => "blockstate-override",
            DiffKind::AdvancementOverride => "advancement-override",
            DiffKind::PredicateOverride => "predicate-override",
            DiffKind::ItemModifierOverride => "item-modifier-override",
            DiffKind::RegistryObjectOverride => "registry-object-override",
            DiffKind::LangKeyConflict => "lang-key-conflict",
            DiffKind::TagReplaceOverride => "tag-replace-override",
            DiffKind::SameWriterAmbiguousDefinition => "same-writer-ambiguous-definition",
        }
    }

    /// Parse a `diff_kind` string back into the enum (inverse of [`Self::as_str`]).
    #[must_use]
    pub fn from_kind_str(s: &str) -> Option<Self> {
        Some(match s {
            "recipe-output-override" => DiffKind::RecipeOutputOverride,
            "recipe-type-override" => DiffKind::RecipeTypeOverride,
            "recipe-ingredient-override" => DiffKind::RecipeIngredientOverride,
            "recipe-condition-override" => DiffKind::RecipeConditionOverride,
            "recipe-opaque-override" => DiffKind::RecipeOpaqueOverride,
            "loot-table-output-override" => DiffKind::LootDropOverride,
            "loot-table-structure-override" => DiffKind::LootStructureOverride,
            "atlas-source-override" => DiffKind::AtlasSourceOverride,
            "model-override" => DiffKind::ModelParentOverride,
            "model-texture-override" => DiffKind::ModelTextureOverride,
            "model-predicate-override" => DiffKind::ModelPredicateOverride,
            "blockstate-override" => DiffKind::BlockstateVariantOverride,
            "advancement-override" => DiffKind::AdvancementOverride,
            "predicate-override" => DiffKind::PredicateOverride,
            "item-modifier-override" => DiffKind::ItemModifierOverride,
            "registry-object-override" => DiffKind::RegistryObjectOverride,
            "lang-key-conflict" => DiffKind::LangKeyConflict,
            "tag-replace-override" => DiffKind::TagReplaceOverride,
            "same-writer-ambiguous-definition" => DiffKind::SameWriterAmbiguousDefinition,
            _ => return None,
        })
    }

    /// What this diff changes for the game — drives severity centrally via
    /// [`crate::semantic::impact::severity_for`] instead of per-rule hand-tuning.
    #[must_use]
    pub fn impact(self) -> crate::semantic::impact::SemanticImpact {
        use crate::semantic::impact::SemanticImpact as I;
        match self {
            // What the player crafts / obtains / triggers.
            DiffKind::RecipeOutputOverride
            | DiffKind::RecipeTypeOverride
            | DiffKind::LootDropOverride
            | DiffKind::LootStructureOverride => I::GameplayBehavior,
            // Same result, different route, or condition-only: a compat nuance.
            DiffKind::RecipeIngredientOverride
            | DiffKind::RecipeConditionOverride
            | DiffKind::RecipeOpaqueOverride
            | DiffKind::AdvancementOverride
            | DiffKind::PredicateOverride
            | DiffKind::ItemModifierOverride
            | DiffKind::RegistryObjectOverride
            | DiffKind::TagReplaceOverride => I::CompatRisk,
            DiffKind::SameWriterAmbiguousDefinition => I::CompatRisk,
            // Client visuals.
            DiffKind::AtlasSourceOverride => I::AssetVisual,
            DiffKind::ModelParentOverride
            | DiffKind::ModelTextureOverride
            | DiffKind::ModelPredicateOverride
            | DiffKind::BlockstateVariantOverride => I::ClientLoadRisk,
            DiffKind::LangKeyConflict => I::Localization,
        }
    }

    /// Confidence baseline for the diff. Below the warn gate for domains that are
    /// commonly runtime-generated (models/blockstates), so they stay `Note`.
    #[must_use]
    pub fn base_confidence(self) -> f32 {
        match self {
            DiffKind::ModelParentOverride
            | DiffKind::ModelTextureOverride
            | DiffKind::ModelPredicateOverride
            | DiffKind::BlockstateVariantOverride => 0.8,
            _ => 0.9,
        }
    }

    /// Derived severity (`impact + confidence`), the single source of truth.
    #[must_use]
    pub fn severity(self) -> intermed_doctor_core::evidence::Severity {
        crate::semantic::impact::severity_for(self.impact(), self.base_confidence())
    }
}

/// One semantic diff at a resource path.
#[derive(Debug, Clone)]
pub struct SemanticDiff {
    pub path: String,
    pub kind: DiffKind,
    pub writers: Vec<String>,
    /// Human-readable detail (e.g. the conflicting outputs / keys), bounded.
    pub detail: String,
}

/// Compute all semantic diffs across the pack. Records are grouped by path; a
/// group with a single distinct *semantic hash* agrees and is skipped (writers
/// differing only in key order hash identically, so this is conflict-free).
///
/// Invalid-AST records are excluded before diffing so a parse failure in one
/// writer does not produce a spurious cross-writer disagreement. When a single
/// writer ships a path multiple times (same-writer ambiguity), we take one
/// canonical record per writer — comparing writers, not installations.
#[must_use]
pub fn compute(records: &[ResourceAstRecord]) -> Vec<SemanticDiff> {
    let mut by_path: BTreeMap<&str, Vec<&ResourceAstRecord>> = BTreeMap::new();
    for rec in records {
        by_path
            .entry(rec.ast.resource_path.as_str())
            .or_default()
            .push(rec);
    }

    let mut out = Vec::new();
    for (path, group) in by_path {
        // Drop invalid-AST records — a parse failure is not a semantic diff.
        let valid_group: Vec<&ResourceAstRecord> = group
            .into_iter()
            .filter(|r| !matches!(r.ast.parse_status, crate::model::ParseStatus::Invalid))
            .collect();

        let mut by_writer: BTreeMap<&str, Vec<&ResourceAstRecord>> = BTreeMap::new();
        for record in &valid_group {
            by_writer
                .entry(record.writer.as_str())
                .or_default()
                .push(record);
        }
        let ambiguous_writers: Vec<String> = by_writer
            .iter()
            .filter_map(|(writer, records)| {
                let artifacts: std::collections::BTreeSet<&str> =
                    records.iter().map(|r| r.artifact_id.as_str()).collect();
                let hashes: std::collections::BTreeSet<&str> = records
                    .iter()
                    .map(|r| r.ast.semantic_hash.as_str())
                    .collect();
                (artifacts.len() > 1 && hashes.len() > 1).then(|| (*writer).to_string())
            })
            .collect();
        if !ambiguous_writers.is_empty() {
            out.push(SemanticDiff {
                path: path.to_string(),
                kind: DiffKind::SameWriterAmbiguousDefinition,
                writers: ambiguous_writers.clone(),
                detail: format!(
                    "multiple physical artifacts for writer(s) {} contain different definitions",
                    ambiguous_writers.join(", ")
                ),
            });
        }

        // Reduce to one canonical record per writer. If a writer ships the same
        // path multiple times, that is a same-writer ambiguity (not a cross-writer
        // conflict). We pick the last record for each writer (stable, deterministic).
        let mut per_writer: BTreeMap<&str, &ResourceAstRecord> = BTreeMap::new();
        for rec in &valid_group {
            per_writer.insert(rec.writer.as_str(), rec);
        }

        if per_writer.len() < 2 {
            continue;
        }

        // The deduplicated writers and their canonical records.
        let dedup_group: Vec<&ResourceAstRecord> = per_writer.values().copied().collect();
        let mut writers: Vec<String> = per_writer.keys().map(|w| w.to_string()).collect();
        writers.sort();

        // Agreement: every writer's semantic hash matches → no diff.
        let first_hash = &dedup_group[0].ast.semantic_hash;
        if dedup_group
            .iter()
            .all(|r| &r.ast.semantic_hash == first_hash)
        {
            continue;
        }

        let domain = dedup_group[0].ast.domain;
        if let Some(diff) = diff_group(path, domain, &dedup_group, &writers) {
            out.push(diff);
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// The per-domain analysis contract (roadmap §4). Each domain owns its
/// cross-writer `diff` logic behind one trait, so adding a domain means
/// implementing this and registering it — not editing a central `match`. (Parsing
/// and reference extraction are the existing `domain::*::parse` → `DomainParse`
/// contract; validation findings are intentionally not produced — see the
/// dangling-reference note in `rule.rs`.)
pub trait ResourceDomainAnalyzer: Sync {
    /// The domain this analyzer handles.
    fn domain(&self) -> ResourceDomain;

    /// Whether a path belongs to this domain (canonical classification).
    fn matches_path(&self, path: &str) -> bool {
        intermed_resource_identity::classify(path) == self.domain()
    }

    /// Compute the semantic diff for a group of writers at one path, or `None`
    /// when the disagreement is benign / already covered by Layer E.
    fn diff(
        &self,
        path: &str,
        group: &[&ResourceAstRecord],
        writers: &[String],
    ) -> Option<SemanticDiff>;
}

macro_rules! domain_analyzer {
    ($name:ident, $domain:expr, $body:expr) => {
        struct $name;
        impl ResourceDomainAnalyzer for $name {
            fn domain(&self) -> ResourceDomain {
                $domain
            }
            fn diff(
                &self,
                path: &str,
                group: &[&ResourceAstRecord],
                writers: &[String],
            ) -> Option<SemanticDiff> {
                #[allow(clippy::redundant_closure_call)]
                ($body)(path, group, writers)
            }
        }
    };
}

domain_analyzer!(RecipeAnalyzer, ResourceDomain::Recipe, recipe_diff);
domain_analyzer!(LangAnalyzer, ResourceDomain::Lang, lang_diff);
domain_analyzer!(LootAnalyzer, ResourceDomain::LootTable, loot_diff);
domain_analyzer!(AtlasAnalyzer, ResourceDomain::Atlas, atlas_diff);
domain_analyzer!(ModelAnalyzer, ResourceDomain::Model, model_diff);
domain_analyzer!(
    BlockstateAnalyzer,
    ResourceDomain::Blockstate,
    blockstate_diff
);
domain_analyzer!(
    AdvancementAnalyzer,
    ResourceDomain::Advancement,
    |p, _g, w| {
        Some(simple_override(
            p,
            DiffKind::AdvancementOverride,
            w,
            "advancement",
        ))
    }
);
domain_analyzer!(PredicateAnalyzer, ResourceDomain::Predicate, |p, _g, w| {
    Some(simple_override(
        p,
        DiffKind::PredicateOverride,
        w,
        "predicate",
    ))
});
domain_analyzer!(
    ItemModifierAnalyzer,
    ResourceDomain::ItemModifier,
    |p, _g, w| {
        Some(simple_override(
            p,
            DiffKind::ItemModifierOverride,
            w,
            "item modifier",
        ))
    }
);
domain_analyzer!(
    GenericRegistryAnalyzer,
    ResourceDomain::GenericJson,
    |p, _g, w| { generic_registry_diff(p, w) }
);
domain_analyzer!(TagAnalyzer, ResourceDomain::Tag, tag_diff);

/// The registered domain analyzers. A domain not listed here produces no semantic
/// diff (binary/structure/etc. are benign), which is the anti-false-positive default.
/// Tags are registered for the narrow `replace: true` conflict only — general
/// content divergence is still benign and intentionally not flagged.
const ANALYZERS: &[&dyn ResourceDomainAnalyzer] = &[
    &RecipeAnalyzer,
    &LangAnalyzer,
    &LootAnalyzer,
    &AtlasAnalyzer,
    &ModelAnalyzer,
    &BlockstateAnalyzer,
    &AdvancementAnalyzer,
    &PredicateAnalyzer,
    &ItemModifierAnalyzer,
    &GenericRegistryAnalyzer,
    &TagAnalyzer,
];

/// The analyzer for a domain, if one is registered.
#[must_use]
pub fn analyzer_for(domain: ResourceDomain) -> Option<&'static dyn ResourceDomainAnalyzer> {
    ANALYZERS.iter().copied().find(|a| a.domain() == domain)
}

fn diff_group(
    path: &str,
    domain: ResourceDomain,
    group: &[&ResourceAstRecord],
    writers: &[String],
) -> Option<SemanticDiff> {
    let analyzer = analyzer_for(domain)?;
    // Double-check that the path actually belongs to this domain via the
    // canonical classifier — guards against stale or mis-tagged domain fields.
    if !analyzer.matches_path(path) {
        return None;
    }
    analyzer.diff(path, group, writers)
}

/// A note-level override for a single-document registry file whose writers differ
/// (the agreement check in `compute` already proved they do).
fn simple_override(path: &str, kind: DiffKind, writers: &[String], label: &str) -> SemanticDiff {
    SemanticDiff {
        path: path.to_string(),
        kind,
        writers: writers.to_vec(),
        detail: format!("multiple writers define this {label} differently"),
    }
}

/// The generic-registry fallback (roadmap §7): an unmodelled
/// `data/<ns>/<registry>/<object>.json` overridden by multiple writers. Gated on
/// the path actually being a datapack registry object so assets/non-registry
/// generic JSON is not flagged.
fn generic_registry_diff(path: &str, writers: &[String]) -> Option<SemanticDiff> {
    let key = intermed_resource_identity::ResourceKey::from_path(path);
    let is_registry_object = matches!(key.side, Some(intermed_resource_identity::Side::Server))
        && key.registry.is_some()
        && key.object_id.is_some();
    if !is_registry_object {
        return None;
    }
    let registry = key.registry.unwrap_or_default();
    Some(SemanticDiff {
        path: path.to_string(),
        kind: DiffKind::RegistryObjectOverride,
        writers: writers.to_vec(),
        detail: format!("multiple writers define this `{registry}` registry object differently"),
    })
}

/// The set of reference targets a record declares for one relation kind.
fn targets_for(
    rec: &ResourceAstRecord,
    relation: crate::model::RefRelation,
) -> std::collections::BTreeSet<String> {
    rec.ast
        .references
        .iter()
        .filter(|r| r.relation == relation)
        .map(|r| r.target.clone())
        .collect()
}

/// Elements present in some writers' set but not all — the divergence sample.
fn divergence(sets: &[std::collections::BTreeSet<String>]) -> Vec<String> {
    let mut union: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for s in sets {
        union.extend(s.iter().cloned());
    }
    union
        .into_iter()
        .filter(|v| !sets.iter().all(|s| s.contains(v)))
        .collect()
}

/// Tag writers conflict when one uses `replace: true` and another does not, or
/// when multiple competing definitions carry `replace: true`. In all other cases
/// (differing content, extra entries) the tag union is benign.
fn tag_diff(path: &str, group: &[&ResourceAstRecord], writers: &[String]) -> Option<SemanticDiff> {
    let summaries: Vec<&crate::domain::tag::TagSummary> = group
        .iter()
        .filter_map(|r| match &r.ast.summary {
            ResourceSummary::Tag(s) => Some(s),
            _ => None,
        })
        .collect();
    if summaries.len() < 2 {
        return None;
    }
    // Only flag when replace semantics are in conflict: either mixed true/false,
    // or multiple `replace: true` definitions (last-write-wins is non-obvious).
    let has_replace = summaries.iter().any(|s| s.replace);
    let all_replace = summaries.iter().all(|s| s.replace);
    if !has_replace {
        return None; // all replace:false → safe union, no diff
    }
    let detail = if !all_replace {
        "replace:true in some writers silently drops other writers' tag entries".to_string()
    } else {
        "multiple writers use replace:true; load order determines which entries survive".to_string()
    };
    Some(SemanticDiff {
        path: path.to_string(),
        kind: DiffKind::TagReplaceOverride,
        writers: writers.to_vec(),
        detail,
    })
}

/// Recipe writers conflict, in priority order, on: produced outputs (the result a
/// player obtains), the serializer `type`, the ingredients, or only the load
/// `conditions`. Reporting the most behaviour-changing difference first keeps one
/// finding per recipe path rather than four overlapping ones.
fn recipe_diff(
    path: &str,
    group: &[&ResourceAstRecord],
    writers: &[String],
) -> Option<SemanticDiff> {
    let summaries: Vec<&crate::domain::recipe::RecipeSummary> = group
        .iter()
        .filter_map(|r| match &r.ast.summary {
            ResourceSummary::Recipe(s) => Some(s),
            _ => None,
        })
        .collect();
    if summaries.len() < 2 {
        return None;
    }
    let mk = |kind: DiffKind, detail: String| {
        Some(SemanticDiff {
            path: path.to_string(),
            kind,
            writers: writers.to_vec(),
            detail,
        })
    };

    // 0. All opaque custom serializers: the extracted outputs/ingredients are
    //    unreliable, so we must NOT claim an output/type override. We only know the
    //    raw payloads differ (the agreement check already proved that). Report it
    //    as an opaque difference at note severity rather than a false "output override".
    if summaries
        .iter()
        .all(|s| s.opacity == crate::model::SemanticOpacity::OpaqueCustomSerializer)
    {
        let mut types: Vec<String> = summaries.iter().map(|s| s.recipe_type.clone()).collect();
        types.sort();
        types.dedup();
        return mk(
            DiffKind::RecipeOpaqueOverride,
            format!(
                "custom serializer payload differs ({})",
                truncate_list(&types)
            ),
        );
    }

    // For mixed opaque/transparent: only compare the transparent writers' reliable
    // fields. Opaque writers make no claim about their outputs/ingredients, so
    // including them would produce false positives (RecipeOutputOverride when the
    // opaque side actually produces the same output — we just can't read it).
    let transparent: Vec<&&crate::domain::recipe::RecipeSummary> = summaries
        .iter()
        .filter(|s| s.opacity.is_reliable())
        .collect();

    // If all remaining reliable summaries agree, defer to opaque handling.
    let cmp_summaries: &[&crate::domain::recipe::RecipeSummary] = if transparent.len() >= 2 {
        &transparent.iter().map(|s| **s).collect::<Vec<_>>()[..]
    } else {
        // Only one (or zero) transparent writers — nothing to compare precisely.
        return mk(
            DiffKind::RecipeOpaqueOverride,
            "mixed transparent/opaque recipe definitions".to_string(),
        );
    };

    let mk_cmp = |kind: DiffKind, detail: String| {
        Some(SemanticDiff {
            path: path.to_string(),
            kind,
            writers: writers.to_vec(),
            detail,
        })
    };

    // 1. Output set — the strongest signal (what you actually craft).
    let first_out = &cmp_summaries[0].outputs;
    let first_output_fp = &cmp_summaries[0].output_fingerprint;
    if !cmp_summaries
        .iter()
        .all(|s| &s.outputs == first_out && &s.output_fingerprint == first_output_fp)
    {
        let output_sets: Vec<std::collections::BTreeSet<String>> = cmp_summaries
            .iter()
            .map(|s| s.outputs.iter().cloned().collect())
            .collect();
        return mk_cmp(
            DiffKind::RecipeOutputOverride,
            format!(
                "conflicting outputs, quantities, or output layout: {}",
                truncate_list(&divergence(&output_sets))
            ),
        );
    }
    // 2. Serializer type (same output, different `type` → different mod wins).
    let first_type = &cmp_summaries[0].recipe_type;
    if !cmp_summaries.iter().all(|s| &s.recipe_type == first_type) {
        let mut types: Vec<String> = cmp_summaries
            .iter()
            .map(|s| s.recipe_type.clone())
            .collect();
        types.sort();
        types.dedup();
        return mk_cmp(
            DiffKind::RecipeTypeOverride,
            format!(
                "same output, different recipe types: {}",
                truncate_list(&types)
            ),
        );
    }
    // 3. Ingredients (same output and type, different inputs → note).
    //    Compare as multisets (sorted Vec) so order doesn't matter, and build
    //    the detail from the symmetric set difference — not from the Vec diff —
    //    so the message is never empty when there is a real disagreement.
    let ingredient_sets: Vec<std::collections::BTreeSet<String>> = cmp_summaries
        .iter()
        .map(|s| s.ingredients.iter().cloned().collect())
        .collect();
    let first_input_fp = &cmp_summaries[0].input_fingerprint;
    if !ingredient_sets.iter().all(|s| s == &ingredient_sets[0])
        || !cmp_summaries
            .iter()
            .all(|s| &s.input_fingerprint == first_input_fp)
    {
        let diff_items = divergence(&ingredient_sets);
        return mk_cmp(
            DiffKind::RecipeIngredientOverride,
            format!(
                "same output, different ingredients, multiplicity, or shaped layout: {}",
                truncate_list(&diff_items)
            ),
        );
    }
    // 4. Conditions differ: presence mismatch OR same presence but different
    //    condition trees (e.g. modloaded:create vs modloaded:thermal).
    let any_conditioned = cmp_summaries.iter().any(|s| s.has_conditions);
    let all_conditioned = cmp_summaries.iter().all(|s| s.has_conditions);
    if any_conditioned && !all_conditioned {
        return mk_cmp(
            DiffKind::RecipeConditionOverride,
            "identical recipe gated by load conditions in only some writers".to_string(),
        );
    }
    if all_conditioned {
        // All conditioned: check whether the condition fingerprints differ.
        let first_fp = &cmp_summaries[0].condition_fingerprint;
        if !cmp_summaries
            .iter()
            .all(|s| &s.condition_fingerprint == first_fp)
        {
            return mk_cmp(
                DiffKind::RecipeConditionOverride,
                "writers use different load conditions for the same recipe".to_string(),
            );
        }
    }
    None
}

/// Loot-table writers conflict when the dropped item/tag set differs — the items
/// a player actually receives change by load order.
fn loot_diff(path: &str, group: &[&ResourceAstRecord], writers: &[String]) -> Option<SemanticDiff> {
    let summaries: Vec<&crate::domain::loot_table::LootTableSummary> = group
        .iter()
        .filter_map(|r| match &r.ast.summary {
            ResourceSummary::LootTable(s) => Some(s),
            _ => None,
        })
        .collect();
    if summaries.len() < 2
        || summaries
            .iter()
            .all(|s| s.structure_fingerprint == summaries[0].structure_fingerprint)
    {
        return None;
    }
    let drop_sets: Vec<std::collections::BTreeSet<String>> = summaries
        .iter()
        .map(|s| s.drops.iter().cloned().collect())
        .collect();
    let same_drops = drop_sets.iter().all(|s| s == &drop_sets[0]);
    let detail = if same_drops {
        "same drops but different rolls, weights, conditions, functions, counts, or entry order"
            .to_string()
    } else {
        format!(
            "differing drops: {}",
            truncate_list(&divergence(&drop_sets))
        )
    };
    Some(SemanticDiff {
        path: path.to_string(),
        kind: if same_drops {
            DiffKind::LootStructureOverride
        } else {
            DiffKind::LootDropOverride
        },
        writers: writers.to_vec(),
        detail,
    })
}

/// Atlas writers conflict when their texture-source lists differ: one file is read
/// by load order, so a second writer's sources are dropped.
fn atlas_diff(
    path: &str,
    group: &[&ResourceAstRecord],
    writers: &[String],
) -> Option<SemanticDiff> {
    // Prefer the summary's full source descriptor list (covers directory/filter
    // sources that produce no reference edge); fall back to single-source refs.
    let source_sets: Vec<std::collections::BTreeSet<String>> = group
        .iter()
        .map(|r| match &r.ast.summary {
            ResourceSummary::Atlas(s) if !s.sources.is_empty() => {
                s.sources.iter().cloned().collect()
            }
            _ => targets_for(r, crate::model::RefRelation::AtlasSource),
        })
        .collect();
    if source_sets.len() < 2 || source_sets.iter().all(|s| s == &source_sets[0]) {
        return None;
    }
    Some(SemanticDiff {
        path: path.to_string(),
        kind: DiffKind::AtlasSourceOverride,
        writers: writers.to_vec(),
        detail: format!(
            "atlas sources only some writers declare: {}",
            truncate_list(&divergence(&source_sets))
        ),
    })
}

/// Model writers conflict when they declare a different `parent`. Kept at note
/// severity: models are commonly runtime-generated or resource-pack-shipped, so a
/// parent override is worth noting, not alarming.
fn model_diff(
    path: &str,
    group: &[&ResourceAstRecord],
    writers: &[String],
) -> Option<SemanticDiff> {
    let summaries: Vec<&crate::domain::model::ModelSummary> = group
        .iter()
        .filter_map(|r| match &r.ast.summary {
            ResourceSummary::Model(s) => Some(s),
            _ => None,
        })
        .collect();
    if summaries.len() < 2 {
        return None;
    }
    let same_parent = summaries.iter().all(|s| s.parent == summaries[0].parent);
    let same_textures = summaries
        .iter()
        .all(|s| s.textures == summaries[0].textures);
    let same_overrides = summaries
        .iter()
        .all(|s| s.overrides_fingerprint == summaries[0].overrides_fingerprint);
    if same_parent && same_textures && same_overrides {
        return None;
    }
    let (kind, detail) = if !same_parent {
        let mut distinct: Vec<String> = summaries.iter().filter_map(|s| s.parent.clone()).collect();
        distinct.sort();
        distinct.dedup();
        (
            DiffKind::ModelParentOverride,
            format!("different parent models: {}", truncate_list(&distinct)),
        )
    } else if !same_textures {
        (
            DiffKind::ModelTextureOverride,
            "same parent but different texture-slot mappings".to_string(),
        )
    } else {
        (
            DiffKind::ModelPredicateOverride,
            "same parent/textures but different item override predicates or order".to_string(),
        )
    };
    Some(SemanticDiff {
        path: path.to_string(),
        kind,
        writers: writers.to_vec(),
        detail,
    })
}

/// Blockstate writers conflict when they map the block variants differently.
/// We compare the canonical `variant_fingerprint` (which encodes the full
/// variant→model mapping including rotation/uvlock/weight) rather than just the
/// model set — so writer A `{north→model_a, south→model_b}` and writer B
/// `{north→model_b, south→model_a}` correctly produce a diff even though both
/// use the same model set.
fn blockstate_diff(
    path: &str,
    group: &[&ResourceAstRecord],
    writers: &[String],
) -> Option<SemanticDiff> {
    // Prefer fingerprint comparison (precise); fall back to model-set only when
    // the summary predates variant_fingerprint (older cache entries).
    let fingerprints: Vec<Option<&String>> = group
        .iter()
        .filter_map(|r| match &r.ast.summary {
            ResourceSummary::Blockstate(s) => Some(s.variant_fingerprint.as_ref()),
            _ => None,
        })
        .collect();

    if fingerprints.len() < 2 {
        return None;
    }

    // If all records have a fingerprint, use it for comparison.
    if fingerprints.iter().all(Option::is_some) {
        let first = fingerprints[0];
        if fingerprints.iter().all(|fp| fp == &first) {
            return None;
        }
        let model_sets: Vec<std::collections::BTreeSet<String>> = group
            .iter()
            .map(|r| targets_for(r, crate::model::RefRelation::UsesModel))
            .collect();
        return Some(SemanticDiff {
            path: path.to_string(),
            kind: DiffKind::BlockstateVariantOverride,
            writers: writers.to_vec(),
            detail: format!(
                "different variant mapping: {}",
                truncate_list(&divergence(&model_sets))
            ),
        });
    }

    // Fallback: compare model sets (less precise — may miss rotation/weight diffs).
    let model_sets: Vec<std::collections::BTreeSet<String>> = group
        .iter()
        .map(|r| targets_for(r, crate::model::RefRelation::UsesModel))
        .collect();
    if model_sets.iter().all(|s| s == &model_sets[0]) {
        return None;
    }
    Some(SemanticDiff {
        path: path.to_string(),
        kind: DiffKind::BlockstateVariantOverride,
        writers: writers.to_vec(),
        detail: format!(
            "different variant models: {}",
            truncate_list(&divergence(&model_sets))
        ),
    })
}

/// Two lang writers conflict when they map a shared key to different values.
fn lang_diff(path: &str, group: &[&ResourceAstRecord], writers: &[String]) -> Option<SemanticDiff> {
    // key → distinct values seen
    let mut values: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    for rec in group {
        if let ResourceSummary::Lang(s) = &rec.ast.summary {
            for (k, v) in &s.entries {
                values.entry(k.clone()).or_default().insert(v.clone());
            }
        }
    }
    let conflicts: Vec<String> = values
        .into_iter()
        .filter(|(_, vs)| vs.len() > 1)
        .map(|(k, _)| k)
        .collect();
    if conflicts.is_empty() {
        return None;
    }
    Some(SemanticDiff {
        path: path.to_string(),
        kind: DiffKind::LangKeyConflict,
        writers: writers.to_vec(),
        detail: format!(
            "{} key(s) map to different text: {}",
            conflicts.len(),
            truncate_list(&conflicts)
        ),
    })
}

/// Join up to 8 ids for a bounded, deterministic detail string.
fn truncate_list(items: &[String]) -> String {
    const MAX: usize = 8;
    if items.len() <= MAX {
        return items.join(", ");
    }
    format!(
        "{}, … (+{} more)",
        items[..MAX].join(", "),
        items.len() - MAX
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::lang::LangSummary;
    use crate::domain::recipe::RecipeSummary;
    use crate::model::{CachedResourceAst, ParseStatus, ResourceDomain};

    fn rec(
        writer: &str,
        path: &str,
        domain: ResourceDomain,
        hash: &str,
        summary: ResourceSummary,
    ) -> ResourceAstRecord {
        ResourceAstRecord {
            archive: format!("{writer}.jar"),
            artifact_id: format!("sha256:{writer}"),
            writer: writer.into(),
            ast: CachedResourceAst {
                schema: "s".into(),
                parser_version: "v".into(),
                resource_path: path.into(),
                domain,
                parse_status: ParseStatus::Parsed,
                semantic_hash: hash.into(),
                summary,
                references: vec![],
                references_complete: true,
                reference_gap: None,
                diagnostics: vec![],
            },
        }
    }

    fn recipe(outputs: &[&str]) -> ResourceSummary {
        ResourceSummary::Recipe(RecipeSummary {
            recipe_type: "minecraft:crafting_shaped".into(),
            serializer_namespace: "minecraft".into(),
            ingredient_count: 1,
            output_count: outputs.len(),
            has_conditions: false,
            condition_fingerprint: None,
            group: None,
            opacity: crate::model::SemanticOpacity::Transparent,
            outputs: outputs.iter().map(|s| s.to_string()).collect(),
            ingredients: vec!["minecraft:stick".into()],
            custom_payload_hash: None,
            structure_fingerprint: outputs.join("|"),
            output_fingerprint: outputs.join("|"),
            input_fingerprint: "minecraft:stick".into(),
        })
    }

    /// An opaque custom-serializer recipe (unreliable outputs; differs by payload hash).
    fn opaque_recipe(payload: &str) -> ResourceSummary {
        ResourceSummary::Recipe(RecipeSummary {
            recipe_type: "create:mixing".into(),
            serializer_namespace: "create".into(),
            ingredient_count: 0,
            output_count: 0,
            has_conditions: false,
            condition_fingerprint: None,
            group: None,
            opacity: crate::model::SemanticOpacity::OpaqueCustomSerializer,
            outputs: vec![],
            ingredients: vec![],
            custom_payload_hash: Some(payload.into()),
            structure_fingerprint: payload.into(),
            output_fingerprint: String::new(),
            input_fingerprint: String::new(),
        })
    }

    fn lang(pairs: &[(&str, &str)]) -> ResourceSummary {
        ResourceSummary::Lang(LangSummary {
            format: "json".into(),
            key_count: pairs.len(),
            entries: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
    }

    #[test]
    fn recipe_output_override_detected() {
        let recs = vec![
            rec(
                "a",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "h1",
                recipe(&["a:gear"]),
            ),
            rec(
                "b",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "h2",
                recipe(&["b:cog"]),
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::RecipeOutputOverride);
    }

    #[test]
    fn identical_hash_is_no_diff() {
        let recs = vec![
            rec(
                "a",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "same",
                recipe(&["a:gear"]),
            ),
            rec(
                "b",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "same",
                recipe(&["a:gear"]),
            ),
        ];
        assert!(compute(&recs).is_empty());
    }

    #[test]
    fn lang_key_conflict_detected() {
        let recs = vec![
            rec(
                "a",
                "assets/c/lang/en_us.json",
                ResourceDomain::Lang,
                "h1",
                lang(&[("item.x", "Sword")]),
            ),
            rec(
                "b",
                "assets/c/lang/en_us.json",
                ResourceDomain::Lang,
                "h2",
                lang(&[("item.x", "Blade")]),
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::LangKeyConflict);
    }

    fn rec_refs(
        writer: &str,
        path: &str,
        domain: ResourceDomain,
        hash: &str,
        summary: ResourceSummary,
        refs: Vec<crate::model::ResourceReference>,
    ) -> ResourceAstRecord {
        let mut r = rec(writer, path, domain, hash, summary);
        r.ast.references = refs;
        r
    }

    fn atlas_ref(target: &str) -> crate::model::ResourceReference {
        crate::model::ResourceReference {
            relation: crate::model::RefRelation::AtlasSource,
            target: target.into(),
            namespace: "minecraft".into(),
            required: false,
            conditions: vec![],
            is_tag: false,
            certainty: crate::model::ReferenceCertainty::ExactSchemaReference,
        }
    }

    #[test]
    fn analyzer_registry_covers_diff_domains() {
        // Every domain that produces a diff has a registered analyzer, and
        // matches_path agrees with the canonical classifier.
        assert!(analyzer_for(ResourceDomain::Recipe).is_some());
        assert!(analyzer_for(ResourceDomain::GenericJson).is_some());
        // Tag now has an analyzer (narrow TagReplaceOverride; benign content diffs
        // are still suppressed inside tag_diff itself).
        assert!(analyzer_for(ResourceDomain::Tag).is_some());
        // Binary / structure domains still have no analyzer (anti-FP default).
        assert!(analyzer_for(ResourceDomain::PackMcmeta).is_none());
        let recipe = analyzer_for(ResourceDomain::Recipe).unwrap();
        assert!(recipe.matches_path("data/c/recipes/x.json"));
        assert!(!recipe.matches_path("data/c/loot_tables/x.json"));
        let tag = analyzer_for(ResourceDomain::Tag).unwrap();
        assert!(tag.matches_path("data/c/tags/items/t.json"));
        assert!(!tag.matches_path("data/c/recipes/r.json"));
    }

    #[test]
    fn opaque_custom_serializers_diff_without_claiming_output() {
        // Two custom-serializer recipes with differing payloads → opaque override
        // (note), NOT a false "output override" (we can't read their outputs).
        let recs = vec![
            rec(
                "a",
                "data/create/recipe/m.json",
                ResourceDomain::Recipe,
                "h1",
                opaque_recipe("pa"),
            ),
            rec(
                "b",
                "data/create/recipe/m.json",
                ResourceDomain::Recipe,
                "h2",
                opaque_recipe("pb"),
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::RecipeOpaqueOverride);
        assert_eq!(
            diffs[0].kind.severity(),
            intermed_doctor_core::evidence::Severity::Note
        );
    }

    #[test]
    fn recipe_type_override_when_output_same() {
        let mut a = recipe(&["x:gear"]);
        if let ResourceSummary::Recipe(s) = &mut a {
            s.recipe_type = "create:crushing".into();
        }
        let mut b = recipe(&["x:gear"]);
        if let ResourceSummary::Recipe(s) = &mut b {
            s.recipe_type = "minecraft:crafting_shaped".into();
        }
        let recs = vec![
            rec("a", "data/c/recipe/r.json", ResourceDomain::Recipe, "h1", a),
            rec("b", "data/c/recipe/r.json", ResourceDomain::Recipe, "h2", b),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::RecipeTypeOverride);
    }

    #[test]
    fn loot_drop_override_detected() {
        let loot = |drops: &[&str]| {
            ResourceSummary::LootTable(crate::domain::loot_table::LootTableSummary {
                pool_count: 1,
                entry_count: drops.len(),
                drops: drops.iter().map(|s| s.to_string()).collect(),
                structure_fingerprint: format!("fp:{}", drops.join("|")),
            })
        };
        let recs = vec![
            rec(
                "a",
                "data/c/loot_tables/x.json",
                ResourceDomain::LootTable,
                "h1",
                loot(&["a:gem"]),
            ),
            rec(
                "b",
                "data/c/loot_tables/x.json",
                ResourceDomain::LootTable,
                "h2",
                loot(&["b:dust"]),
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::LootDropOverride);
    }

    #[test]
    fn loot_structure_change_is_detected_when_drop_set_is_equal() {
        let loot = |fingerprint: &str| {
            ResourceSummary::LootTable(crate::domain::loot_table::LootTableSummary {
                pool_count: 1,
                entry_count: 1,
                drops: vec!["minecraft:diamond".into()],
                structure_fingerprint: fingerprint.into(),
            })
        };
        let recs = vec![
            rec(
                "a",
                "data/c/loot_tables/x.json",
                ResourceDomain::LootTable,
                "h1",
                loot("chance-1-percent"),
            ),
            rec(
                "b",
                "data/c/loot_tables/x.json",
                ResourceDomain::LootTable,
                "h2",
                loot("chance-100-percent"),
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::LootStructureOverride);
        assert!(diffs[0].detail.contains("same drops"));
    }

    #[test]
    fn model_parent_override_detected() {
        let model = |parent: &str| {
            use std::collections::BTreeMap;
            ResourceSummary::Model(crate::domain::model::ModelSummary {
                parent: Some(parent.into()),
                textures: BTreeMap::new(),
                overrides_fingerprint: None,
            })
        };
        let recs = vec![
            rec(
                "a",
                "assets/c/models/item/x.json",
                ResourceDomain::Model,
                "h1",
                model("minecraft:item/generated"),
            ),
            rec(
                "b",
                "assets/c/models/item/x.json",
                ResourceDomain::Model,
                "h2",
                model("minecraft:item/handheld"),
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::ModelParentOverride);
    }

    #[test]
    fn model_texture_and_override_changes_are_detected_with_same_parent() {
        use std::collections::BTreeMap;
        let model = |texture: &str, override_fp: &str| {
            ResourceSummary::Model(crate::domain::model::ModelSummary {
                parent: Some("minecraft:item/generated".into()),
                textures: BTreeMap::from([("layer0".into(), texture.into())]),
                overrides_fingerprint: Some(override_fp.into()),
            })
        };
        let texture_diff = compute(&[
            rec(
                "a",
                "assets/c/models/item/x.json",
                ResourceDomain::Model,
                "h1",
                model("c:item/a", "same"),
            ),
            rec(
                "b",
                "assets/c/models/item/x.json",
                ResourceDomain::Model,
                "h2",
                model("c:item/b", "same"),
            ),
        ]);
        assert_eq!(texture_diff.len(), 1);
        assert_eq!(texture_diff[0].kind, DiffKind::ModelTextureOverride);
        assert!(texture_diff[0].detail.contains("texture-slot"));

        let override_diff = compute(&[
            rec(
                "a",
                "assets/c/models/item/y.json",
                ResourceDomain::Model,
                "h1",
                model("c:item/a", "first"),
            ),
            rec(
                "b",
                "assets/c/models/item/y.json",
                ResourceDomain::Model,
                "h2",
                model("c:item/a", "second"),
            ),
        ]);
        assert_eq!(override_diff.len(), 1);
        assert_eq!(override_diff[0].kind, DiffKind::ModelPredicateOverride);
        assert!(override_diff[0].detail.contains("override predicates"));
    }

    #[test]
    fn atlas_source_override_detected() {
        let summary = ResourceSummary::Atlas(crate::domain::atlas::AtlasSummary {
            source_count: 1,
            has_non_single_source: true,
            // Empty summary sources → atlas_diff falls back to the reference edges.
            sources: vec![],
        });
        let recs = vec![
            rec_refs(
                "a",
                "assets/minecraft/atlases/blocks.json",
                ResourceDomain::Atlas,
                "h1",
                summary.clone(),
                vec![atlas_ref("minecraft:block/a")],
            ),
            rec_refs(
                "b",
                "assets/minecraft/atlases/blocks.json",
                ResourceDomain::Atlas,
                "h2",
                summary,
                vec![atlas_ref("minecraft:block/b")],
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::AtlasSourceOverride);
    }

    #[test]
    fn generic_registry_object_override_detected() {
        // data/<ns>/<registry>/<obj>.json with no dedicated domain → GenericJson.
        let recs = vec![
            rec(
                "a",
                "data/c/damage_type/x.json",
                ResourceDomain::GenericJson,
                "h1",
                ResourceSummary::GenericJson {
                    fingerprint: "h-a".into(),
                },
            ),
            rec(
                "b",
                "data/c/damage_type/x.json",
                ResourceDomain::GenericJson,
                "h2",
                ResourceSummary::GenericJson {
                    fingerprint: "h-b".into(),
                },
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::RegistryObjectOverride);
    }

    #[test]
    fn generic_assets_json_is_not_registry_override() {
        // assets-side generic JSON is not a datapack registry object → no diff.
        let recs = vec![
            rec(
                "a",
                "assets/c/custom/x.json",
                ResourceDomain::GenericJson,
                "h1",
                ResourceSummary::GenericJson {
                    fingerprint: "h-a".into(),
                },
            ),
            rec(
                "b",
                "assets/c/custom/x.json",
                ResourceDomain::GenericJson,
                "h2",
                ResourceSummary::GenericJson {
                    fingerprint: "h-b".into(),
                },
            ),
        ];
        assert!(compute(&recs).is_empty());
    }

    #[test]
    fn advancement_override_detected() {
        let adv = || {
            ResourceSummary::Advancement(crate::domain::advancement::AdvancementSummary {
                parent: None,
                criteria_count: 1,
                has_rewards: false,
                has_conditions: false,
            })
        };
        let recs = vec![
            rec(
                "a",
                "data/c/advancements/x.json",
                ResourceDomain::Advancement,
                "h1",
                adv(),
            ),
            rec(
                "b",
                "data/c/advancements/x.json",
                ResourceDomain::Advancement,
                "h2",
                adv(),
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::AdvancementOverride);
    }

    #[test]
    fn lang_disjoint_keys_no_conflict() {
        let recs = vec![
            rec(
                "a",
                "assets/c/lang/en_us.json",
                ResourceDomain::Lang,
                "h1",
                lang(&[("item.x", "Sword")]),
            ),
            rec(
                "b",
                "assets/c/lang/en_us.json",
                ResourceDomain::Lang,
                "h2",
                lang(&[("item.y", "Shield")]),
            ),
        ];
        assert!(compute(&recs).is_empty());
    }

    // ── Regression tests for fixed bugs ──────────────────────────────────────

    /// Bug: same-writer ships same path twice; second record must not trigger a
    /// cross-writer diff. Only one writer → skip.
    #[test]
    fn same_writer_two_records_no_cross_writer_diff() {
        let recs = vec![
            rec(
                "a",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "h1",
                recipe(&["a:gear"]),
            ),
            rec(
                "a",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "h2",
                recipe(&["a:cog"]),
            ),
        ];
        // Only one distinct writer → no cross-writer diff.
        assert!(
            compute(&recs).is_empty(),
            "same-writer ambiguity must not produce a cross-writer diff"
        );
    }

    /// Bug: writer A has two records (outputs differ), writer B agrees with one of
    /// them. After per-writer dedup the group should not produce RecipeOutputOverride.
    #[test]
    fn same_writer_dedup_does_not_create_false_cross_writer_diff() {
        // writer a ships gear AND cog; writer b ships gear.
        // Per-writer canonical: a→gear (last), b→gear → same outputs → no diff.
        let a1 = rec(
            "a",
            "data/c/recipe/r.json",
            ResourceDomain::Recipe,
            "h1",
            recipe(&["a:gear"]),
        );
        let a2 = rec(
            "a",
            "data/c/recipe/r.json",
            ResourceDomain::Recipe,
            "h2",
            recipe(&["a:cog"]),
        );
        let b = rec(
            "b",
            "data/c/recipe/r.json",
            ResourceDomain::Recipe,
            "h2",
            recipe(&["a:cog"]),
        );
        // last record per writer: a→cog, b→cog → agreement → no diff.
        assert!(
            compute(&[a1, a2, b]).is_empty(),
            "per-writer dedup: when both writers resolve to same output, no diff"
        );
    }

    #[test]
    fn different_artifacts_with_same_writer_preserve_ambiguity() {
        let mut first = rec(
            "duplicate",
            "data/c/recipe/r.json",
            ResourceDomain::Recipe,
            "h1",
            recipe(&["a:gear"]),
        );
        first.artifact_id = "sha256:first".into();
        first.archive = "mods/first.jar".into();
        let mut second = rec(
            "duplicate",
            "data/c/recipe/r.json",
            ResourceDomain::Recipe,
            "h2",
            recipe(&["b:gear"]),
        );
        second.artifact_id = "sha256:second".into();
        second.archive = "plugins/second.jar".into();

        let diffs = compute(&[first, second]);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::SameWriterAmbiguousDefinition);
    }

    /// Bug: Invalid AST must be excluded from diff (parse failure ≠ semantic diff).
    #[test]
    fn invalid_ast_excluded_from_diff() {
        let mut bad = rec(
            "a",
            "data/c/recipe/r.json",
            ResourceDomain::Recipe,
            "h1",
            recipe(&["a:gear"]),
        );
        bad.ast.parse_status = crate::model::ParseStatus::Invalid;
        let good = rec(
            "b",
            "data/c/recipe/r.json",
            ResourceDomain::Recipe,
            "h2",
            recipe(&["b:cog"]),
        );
        // After filtering Invalid, only one valid writer → no diff.
        assert!(
            compute(&[bad, good]).is_empty(),
            "invalid AST must be filtered out before diff"
        );
    }

    /// Bug: mixed opaque/transparent must not produce RecipeOutputOverride.
    #[test]
    fn mixed_opaque_transparent_no_output_override() {
        // Writer a: opaque (outputs=[]), writer b: transparent (outputs=[x:gear]).
        // Before fix: RecipeOutputOverride. After fix: RecipeOpaqueOverride.
        let a = rec(
            "a",
            "data/c/recipe/m.json",
            ResourceDomain::Recipe,
            "h1",
            opaque_recipe("payload-a"),
        );
        let mut b_summary = recipe(&["x:gear"]);
        if let ResourceSummary::Recipe(ref mut s) = b_summary {
            s.recipe_type = "minecraft:crafting_shaped".into();
        }
        let b = rec(
            "b",
            "data/c/recipe/m.json",
            ResourceDomain::Recipe,
            "h2",
            b_summary,
        );
        let diffs = compute(&[a, b]);
        // Only one transparent writer → RecipeOpaqueOverride (not RecipeOutputOverride).
        assert_eq!(diffs.len(), 1);
        assert_eq!(
            diffs[0].kind,
            DiffKind::RecipeOpaqueOverride,
            "mixed opaque/transparent must not produce a false output override"
        );
    }

    /// Bug: ingredients comparison Vec vs Set — [iron, stick] vs [stick, iron]
    /// should NOT produce a diff (order-insensitive multiset).
    #[test]
    fn ingredient_order_difference_no_diff() {
        let mut a_sum = recipe(&["x:gear"]);
        let mut b_sum = recipe(&["x:gear"]);
        if let ResourceSummary::Recipe(ref mut s) = a_sum {
            s.ingredients = vec!["minecraft:iron".into(), "minecraft:stick".into()];
        }
        if let ResourceSummary::Recipe(ref mut s) = b_sum {
            s.ingredients = vec!["minecraft:stick".into(), "minecraft:iron".into()];
        }
        let recs = vec![
            rec(
                "a",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "h1",
                a_sum,
            ),
            rec(
                "b",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "h2",
                b_sum,
            ),
        ];
        // Same multiset of ingredients → no ingredient override diff.
        let diffs = compute(&recs);
        assert!(
            diffs
                .iter()
                .all(|d| d.kind != DiffKind::RecipeIngredientOverride),
            "ingredient order difference must not produce IngredientOverride"
        );
    }

    /// Bug: conditions fingerprint — two conditioned recipes with different mod
    /// gates must produce RecipeConditionOverride.
    #[test]
    fn different_condition_fingerprints_produce_condition_override() {
        let mut a_sum = recipe(&["x:gear"]);
        let mut b_sum = recipe(&["x:gear"]);
        if let ResourceSummary::Recipe(ref mut s) = a_sum {
            s.has_conditions = true;
            s.condition_fingerprint = Some("fp-create".into());
        }
        if let ResourceSummary::Recipe(ref mut s) = b_sum {
            s.has_conditions = true;
            s.condition_fingerprint = Some("fp-thermal".into());
        }
        let recs = vec![
            rec(
                "a",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "h1",
                a_sum,
            ),
            rec(
                "b",
                "data/c/recipe/r.json",
                ResourceDomain::Recipe,
                "h2",
                b_sum,
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(
            diffs[0].kind,
            DiffKind::RecipeConditionOverride,
            "different condition fingerprints must be detected"
        );
    }

    /// Bug: blockstate variant mapping — same model set, different mapping.
    #[test]
    fn blockstate_same_model_set_different_mapping_is_diff() {
        use crate::domain::blockstate::BlockstateSummary;
        use crate::model::ResourceSummary;
        // Writer A: north→model_a, south→model_b
        // Writer B: north→model_b, south→model_a
        // Same model set {model_a, model_b} but different fingerprint.
        let a_sum = ResourceSummary::Blockstate(BlockstateSummary {
            variant_count: 2,
            model_count: 2,
            variant_fingerprint: Some("fp-north-a-south-b".into()),
        });
        let b_sum = ResourceSummary::Blockstate(BlockstateSummary {
            variant_count: 2,
            model_count: 2,
            variant_fingerprint: Some("fp-north-b-south-a".into()),
        });
        let recs = vec![
            rec(
                "a",
                "assets/c/blockstates/x.json",
                ResourceDomain::Blockstate,
                "h1",
                a_sum,
            ),
            rec(
                "b",
                "assets/c/blockstates/x.json",
                ResourceDomain::Blockstate,
                "h2",
                b_sum,
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(
            diffs[0].kind,
            DiffKind::BlockstateVariantOverride,
            "different variant mappings with same model set must produce diff"
        );
    }

    /// Bug: tag replace:true must be flagged, but replace:false content-only diffs must not.
    #[test]
    fn tag_replace_true_conflict_detected() {
        let tag_a = ResourceSummary::Tag(crate::domain::tag::TagSummary {
            registry: "items".into(),
            replace: false,
            entry_count: 2,
            has_required_flag: false,
            entries: vec![
                crate::domain::tag::TagEntrySummary {
                    id: "a:gem".into(),
                    is_tag: false,
                    required: true,
                },
                crate::domain::tag::TagEntrySummary {
                    id: "b:shard".into(),
                    is_tag: false,
                    required: true,
                },
            ],
        });
        let tag_b = ResourceSummary::Tag(crate::domain::tag::TagSummary {
            registry: "items".into(),
            replace: true, // drops writer A's entries
            entry_count: 1,
            has_required_flag: false,
            entries: vec![crate::domain::tag::TagEntrySummary {
                id: "c:dust".into(),
                is_tag: false,
                required: true,
            }],
        });
        let recs = vec![
            rec(
                "a",
                "data/c/tags/items/gems.json",
                ResourceDomain::Tag,
                "h1",
                tag_a,
            ),
            rec(
                "b",
                "data/c/tags/items/gems.json",
                ResourceDomain::Tag,
                "h2",
                tag_b,
            ),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::TagReplaceOverride);
    }

    /// Tags that differ only in content (no replace:true) must not be flagged.
    #[test]
    fn tag_content_only_diff_no_flag() {
        let tag_a = ResourceSummary::Tag(crate::domain::tag::TagSummary {
            registry: "items".into(),
            replace: false,
            entry_count: 1,
            has_required_flag: false,
            entries: vec![crate::domain::tag::TagEntrySummary {
                id: "a:gem".into(),
                is_tag: false,
                required: true,
            }],
        });
        let tag_b = ResourceSummary::Tag(crate::domain::tag::TagSummary {
            registry: "items".into(),
            replace: false,
            entry_count: 1,
            has_required_flag: false,
            entries: vec![crate::domain::tag::TagEntrySummary {
                id: "b:shard".into(),
                is_tag: false,
                required: true,
            }],
        });
        let recs = vec![
            rec(
                "a",
                "data/c/tags/items/t.json",
                ResourceDomain::Tag,
                "h1",
                tag_a,
            ),
            rec(
                "b",
                "data/c/tags/items/t.json",
                ResourceDomain::Tag,
                "h2",
                tag_b,
            ),
        ];
        // Content-only divergence is benign — tag_diff must suppress it.
        assert!(
            compute(&recs).is_empty(),
            "tag content-only diff must be suppressed"
        );
    }

    /// matches_path() guard in diff_group: a stale domain field must not produce a diff.
    #[test]
    fn mismatched_domain_field_suppressed_by_matches_path() {
        // Recipe summary but domain claims Lang — misclassification.
        let recs = vec![
            rec(
                "a",
                "data/c/recipe/r.json",
                ResourceDomain::Lang,
                "h1",
                recipe(&["a:gear"]),
            ),
            rec(
                "b",
                "data/c/recipe/r.json",
                ResourceDomain::Lang,
                "h2",
                recipe(&["b:cog"]),
            ),
        ];
        // LangAnalyzer.matches_path("data/c/recipe/r.json") == false → no diff.
        assert!(
            compute(&recs).is_empty(),
            "matches_path guard must suppress diff when domain field is stale"
        );
    }
}

#[cfg(test)]
mod phase5_integration {
    use super::*;
    use crate::domain::parse_resource;
    use crate::model::ResourceLevel;
    use crate::semantic::refs::ResourceAstRecord;

    #[test]
    fn real_parse_generic_registry_override() {
        let a = parse_resource(
            "data/c/damage_type/sharp.json",
            br#"{"exhaustion":0.1,"message_id":"alpha"}"#,
            ResourceLevel::Full,
        );
        let b = parse_resource(
            "data/c/damage_type/sharp.json",
            br#"{"exhaustion":0.1,"message_id":"beta"}"#,
            ResourceLevel::Full,
        );
        assert_ne!(
            a.semantic_hash, b.semantic_hash,
            "generic-json content must hash distinctly"
        );
        let recs = vec![
            ResourceAstRecord {
                archive: "a.jar".into(),
                artifact_id: format!("sha256:{}", "a".repeat(64)),
                writer: "a".into(),
                ast: a,
            },
            ResourceAstRecord {
                archive: "b.jar".into(),
                artifact_id: format!("sha256:{}", "b".repeat(64)),
                writer: "b".into(),
                ast: b,
            },
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1, "expected registry override diff");
        assert_eq!(diffs[0].kind, DiffKind::RegistryObjectOverride);
    }
}
