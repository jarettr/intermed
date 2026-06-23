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
/// *semantically meaningful and not already covered by Layer E*. Tags union
/// (differing content is benign), and single-document overrides are already
/// classified by Layer E — re-flagging either would be a false positive, which is
/// the cardinal sin here. So the only diffs are the two that change *behaviour*:
/// a recipe that crafts a different result, and a locale key that maps to
/// different text.
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
    /// Same atlas path, writers list different texture sources (one drops another's).
    AtlasSourceOverride,
    /// Same model path, writers declare a different `parent` model.
    ModelParentOverride,
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
            DiffKind::AtlasSourceOverride => "atlas-source-override",
            DiffKind::ModelParentOverride => "model-override",
            DiffKind::BlockstateVariantOverride => "blockstate-override",
            DiffKind::AdvancementOverride => "advancement-override",
            DiffKind::PredicateOverride => "predicate-override",
            DiffKind::ItemModifierOverride => "item-modifier-override",
            DiffKind::RegistryObjectOverride => "registry-object-override",
            DiffKind::LangKeyConflict => "lang-key-conflict",
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
            "atlas-source-override" => DiffKind::AtlasSourceOverride,
            "model-override" => DiffKind::ModelParentOverride,
            "blockstate-override" => DiffKind::BlockstateVariantOverride,
            "advancement-override" => DiffKind::AdvancementOverride,
            "predicate-override" => DiffKind::PredicateOverride,
            "item-modifier-override" => DiffKind::ItemModifierOverride,
            "registry-object-override" => DiffKind::RegistryObjectOverride,
            "lang-key-conflict" => DiffKind::LangKeyConflict,
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
            | DiffKind::LootDropOverride => I::GameplayBehavior,
            // Same result, different route, or condition-only: a compat nuance.
            DiffKind::RecipeIngredientOverride
            | DiffKind::RecipeConditionOverride
            | DiffKind::RecipeOpaqueOverride
            | DiffKind::AdvancementOverride
            | DiffKind::PredicateOverride
            | DiffKind::ItemModifierOverride
            | DiffKind::RegistryObjectOverride => I::CompatRisk,
            // Client visuals.
            DiffKind::AtlasSourceOverride => I::AssetVisual,
            DiffKind::ModelParentOverride | DiffKind::BlockstateVariantOverride => {
                I::ClientLoadRisk
            }
            DiffKind::LangKeyConflict => I::Localization,
        }
    }

    /// Confidence baseline for the diff. Below the warn gate for domains that are
    /// commonly runtime-generated (models/blockstates), so they stay `Note`.
    #[must_use]
    pub fn base_confidence(self) -> f32 {
        match self {
            DiffKind::ModelParentOverride | DiffKind::BlockstateVariantOverride => 0.8,
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
        // Distinct writers only — one writer shipping a path twice is not a
        // cross-writer disagreement.
        let mut writers: Vec<String> = group.iter().map(|r| r.writer.clone()).collect();
        writers.sort();
        writers.dedup();
        if writers.len() < 2 {
            continue;
        }
        // Agreement: every writer's semantic hash matches → no diff.
        let first_hash = &group[0].ast.semantic_hash;
        if group.iter().all(|r| &r.ast.semantic_hash == first_hash) {
            continue;
        }

        let domain = group[0].ast.domain;
        if let Some(diff) = diff_group(path, domain, &group, &writers) {
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

/// The registered domain analyzers. A domain not listed here produces no semantic
/// diff (tags union safely; binary/structure/etc. are benign), which is the
/// anti-false-positive default.
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
    analyzer_for(domain)?.diff(path, group, writers)
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

    // 0. Opaque custom serializers: the extracted outputs/ingredients are
    //    unreliable, so we must NOT claim an output/type override. We only know the
    //    raw payloads differ (the agreement check already proved that). Report it
    //    as an opaque difference at note severity rather than a false "output
    //    override". (Mixed opaque/transparent falls through to the precise checks,
    //    which are reliable for the transparent writers.)
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

    // 1. Output set — the strongest signal (what you actually craft).
    let first_out = &summaries[0].outputs;
    if !summaries.iter().all(|s| &s.outputs == first_out) {
        let mut all: Vec<String> = summaries.iter().flat_map(|s| s.outputs.clone()).collect();
        all.sort();
        all.dedup();
        return mk(
            DiffKind::RecipeOutputOverride,
            format!("conflicting outputs: {}", truncate_list(&all)),
        );
    }
    // 2. Serializer type (same output, different `type` → different mod wins).
    let first_type = &summaries[0].recipe_type;
    if !summaries.iter().all(|s| &s.recipe_type == first_type) {
        let mut types: Vec<String> = summaries.iter().map(|s| s.recipe_type.clone()).collect();
        types.sort();
        types.dedup();
        return mk(
            DiffKind::RecipeTypeOverride,
            format!(
                "same output, different recipe types: {}",
                truncate_list(&types)
            ),
        );
    }
    // 3. Ingredients (same output and type, different inputs → note).
    let first_ing = &summaries[0].ingredients;
    if !summaries.iter().all(|s| &s.ingredients == first_ing) {
        let sets: Vec<std::collections::BTreeSet<String>> = summaries
            .iter()
            .map(|s| s.ingredients.iter().cloned().collect())
            .collect();
        return mk(
            DiffKind::RecipeIngredientOverride,
            format!(
                "same output, different ingredients: {}",
                truncate_list(&divergence(&sets))
            ),
        );
    }
    // 4. Only the load conditions differ (one writer gates it) → note.
    if summaries.iter().any(|s| s.has_conditions) && !summaries.iter().all(|s| s.has_conditions) {
        return mk(
            DiffKind::RecipeConditionOverride,
            "identical recipe gated by load conditions in only some writers".to_string(),
        );
    }
    None
}

/// Loot-table writers conflict when the dropped item/tag set differs — the items
/// a player actually receives change by load order.
fn loot_diff(path: &str, group: &[&ResourceAstRecord], writers: &[String]) -> Option<SemanticDiff> {
    let drop_sets: Vec<std::collections::BTreeSet<String>> = group
        .iter()
        .filter_map(|r| match &r.ast.summary {
            ResourceSummary::LootTable(s) => Some(s.drops.iter().cloned().collect()),
            _ => None,
        })
        .collect();
    if drop_sets.len() < 2 || drop_sets.iter().all(|s| s == &drop_sets[0]) {
        return None;
    }
    Some(SemanticDiff {
        path: path.to_string(),
        kind: DiffKind::LootDropOverride,
        writers: writers.to_vec(),
        detail: format!(
            "differing drops: {}",
            truncate_list(&divergence(&drop_sets))
        ),
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
    let parents: Vec<String> = group
        .iter()
        .filter_map(|r| match &r.ast.summary {
            ResourceSummary::Model(s) => Some(s.parent.clone().unwrap_or_default()),
            _ => None,
        })
        .collect();
    if parents.len() < 2 || parents.iter().all(|p| p == &parents[0]) {
        return None;
    }
    let mut distinct: Vec<String> = parents.into_iter().filter(|p| !p.is_empty()).collect();
    distinct.sort();
    distinct.dedup();
    Some(SemanticDiff {
        path: path.to_string(),
        kind: DiffKind::ModelParentOverride,
        writers: writers.to_vec(),
        detail: format!("different parent models: {}", truncate_list(&distinct)),
    })
}

/// Blockstate writers conflict when they map the block to a different set of
/// models. Note severity for the same runtime-generation reason as models.
fn blockstate_diff(
    path: &str,
    group: &[&ResourceAstRecord],
    writers: &[String],
) -> Option<SemanticDiff> {
    let model_sets: Vec<std::collections::BTreeSet<String>> = group
        .iter()
        .map(|r| targets_for(r, crate::model::RefRelation::UsesModel))
        .collect();
    if model_sets.len() < 2 || model_sets.iter().all(|s| s == &model_sets[0]) {
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
            group: None,
            opacity: crate::model::SemanticOpacity::Transparent,
            outputs: outputs.iter().map(|s| s.to_string()).collect(),
            ingredients: vec!["minecraft:stick".into()],
            custom_payload_hash: None,
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
            group: None,
            opacity: crate::model::SemanticOpacity::OpaqueCustomSerializer,
            outputs: vec![],
            ingredients: vec![],
            custom_payload_hash: Some(payload.into()),
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
        }
    }

    #[test]
    fn analyzer_registry_covers_diff_domains() {
        // Every domain that produces a diff has a registered analyzer, and
        // matches_path agrees with the canonical classifier.
        assert!(analyzer_for(ResourceDomain::Recipe).is_some());
        assert!(analyzer_for(ResourceDomain::GenericJson).is_some());
        // Tag has no analyzer (unions safely) — the anti-FP default.
        assert!(analyzer_for(ResourceDomain::Tag).is_none());
        let recipe = analyzer_for(ResourceDomain::Recipe).unwrap();
        assert!(recipe.matches_path("data/c/recipes/x.json"));
        assert!(!recipe.matches_path("data/c/loot_tables/x.json"));
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
    fn model_parent_override_detected() {
        let model = |parent: &str| {
            ResourceSummary::Model(crate::domain::model::ModelSummary {
                parent: Some(parent.into()),
                texture_count: 0,
                override_count: 0,
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
                writer: "a".into(),
                ast: a,
            },
            ResourceAstRecord {
                archive: "b.jar".into(),
                writer: "b".into(),
                ast: b,
            },
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1, "expected registry override diff");
        assert_eq!(diffs[0].kind, DiffKind::RegistryObjectOverride);
    }
}
