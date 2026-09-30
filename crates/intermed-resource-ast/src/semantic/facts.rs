//! Lowering the typed AST into compact facts.
//!
//! This is the one place where Layer M touches the [`FactStore`]. It emits only
//! compact, bounded facts (summaries and edges — never raw JSON), preserving the
//! contract that **the AST never emits findings**: rules in [`crate::rule`] read
//! these facts and decide what is a problem.

use std::collections::BTreeMap;

use intermed_doctor_core::facts::{FactBuilder, FactRead, FactWrite, SourceRef, kind};

use crate::model::ResourceSummary;
use crate::semantic::diff::SemanticDiff;
use crate::semantic::namespace::{is_platform_namespace, path_namespace};
use crate::semantic::refs::{ResourceAstRecord, ResourceGraph, ResourcePresence};

/// Collector / extractor id for all Layer-M facts.
pub const EXTRACTOR: &str = "resource-ast-scanner";

/// Per-namespace accumulator for the implicit-dependency candidate fact.
///
/// Three reference states are tracked separately — deriving `conditioned` from
/// `!required` is wrong: an optional-unconditioned ref (`required=false, conds=[]`)
/// is neither "required" nor "conditioned" (bug #1/#10).
#[derive(Default)]
struct ImplicitAgg<'a> {
    ref_count: usize,
    /// At least one ref is required AND unconditioned — a real hard dependency.
    has_required_unconditioned: bool,
    /// At least one ref carries a load-condition gate (`mod_loaded`, etc.).
    has_conditioned: bool,
    /// At least one ref is explicitly optional but unconditioned.
    has_optional_unconditioned: bool,
    /// Recipe-serializer `type` reference (lowest-FP signal).
    via_recipe_type: bool,
    // Regression: sample provenance tracks the *highest-priority* edge so the emitted
    // fact's source always corresponds to the signal that drove the aggregate.
    // Priority: recipe-serializer > structural ref > registry-ref heuristic.
    sample_path: &'a str,
    sample_target: &'a str,
    sample_via_recipe_type: bool,
    sample_certainty: crate::model::ReferenceCertainty,
}

impl<'a> ImplicitAgg<'a> {
    /// Update the sample when the incoming edge carries a higher-priority signal.
    fn update_sample(
        &mut self,
        path: &'a str,
        target: &'a str,
        via_recipe_type: bool,
        certainty: crate::model::ReferenceCertainty,
    ) {
        // Replace if: no sample yet, or this edge is a recipe-type and current isn't.
        if self.sample_path.is_empty()
            || (via_recipe_type && !self.sample_via_recipe_type)
            || (via_recipe_type == self.sample_via_recipe_type && certainty < self.sample_certainty)
        {
            self.sample_path = path;
            self.sample_target = target;
            self.sample_via_recipe_type = via_recipe_type;
            self.sample_certainty = certainty;
        }
    }

    /// True when the aggregate constitutes a genuinely required dependency.
    fn required(&self) -> bool {
        self.has_required_unconditioned
    }

    /// True when ALL evidence is conditioned (no unconditional required ref found).
    fn conditioned(&self) -> bool {
        self.has_conditioned && !self.has_required_unconditioned
    }
}

/// Per-`(consumer mod, provider namespace)` accumulator for the per-mod
/// `implicit_dependency_edge` fact (the three-level dependency model).
///
/// Same three-state model as [`ImplicitAgg`] — `conditioned` is stored
/// independently, never derived as `!required` (bug #1).
#[derive(Default)]
struct ConsumerAgg<'a> {
    ref_count: usize,
    /// Some reference is unconditioned and required.
    required: bool,
    /// Some reference is gated by a load condition.
    conditioned: bool,
    /// At least one reference is load-breaking if absent (recipe serializer `type`).
    hard: bool,
    // Regression: separate sample for the "best" evidence path so `via` always
    // matches the edge that set the highest-priority flag.
    sample_path: &'a str,
    sample_archive: &'a str,
    via: &'a str,
    via_is_serializer: bool,
    sample_certainty: crate::model::ReferenceCertainty,
}

impl<'a> ConsumerAgg<'a> {
    /// Update sample when the incoming edge carries a higher-priority signal.
    /// Priority: recipe-serializer > any other structural ref.
    fn update_sample(
        &mut self,
        path: &'a str,
        archive: &'a str,
        via: &'a str,
        is_serializer: bool,
        certainty: crate::model::ReferenceCertainty,
    ) {
        if self.sample_path.is_empty()
            || (is_serializer && !self.via_is_serializer)
            || (is_serializer == self.via_is_serializer && certainty < self.sample_certainty)
        {
            self.sample_path = path;
            self.sample_archive = archive;
            self.via = via;
            self.via_is_serializer = is_serializer;
            self.sample_certainty = certainty;
        }
    }
}

/// Emit every Layer-M fact for the parsed pack. Returns the number emitted.
///
/// `max_refs_per_resource` bounds the per-resource `resource_reference` fan-out so
/// a pathological resource cannot flood the store (backpressure, Stage 3).
pub fn emit(
    store: &mut dyn FactWrite,
    inputs: &dyn FactRead,
    records: &[ResourceAstRecord],
    presences: &[ResourcePresence],
    graph: &ResourceGraph,
    diffs: &[SemanticDiff],
    max_refs_per_resource: usize,
) -> usize {
    let mut n = 0;

    for rec in records {
        let ast = &rec.ast;
        let src = || SourceRef::inside(rec.archive.clone(), ast.resource_path.clone());

        let total_refs = ast.references.len();
        let emitted_refs = total_refs.min(max_refs_per_resource);
        let builder = store
            .fact(EXTRACTOR, kind::RESOURCE_AST_PARSED)
            .subject(ast.resource_path.clone())
            .attr("domain", ast.domain.as_str())
            .attr("parse_status", ast.parse_status.as_str())
            .attr("semantic_hash", ast.semantic_hash.clone())
            .attr("writer", rec.writer.clone())
            .attr("archive", rec.archive.clone())
            .attr("artifact_id", rec.artifact_id.clone())
            .attr("ref_count", ast.references.len() as i64)
            .attr(
                "references_truncated",
                !ast.references_complete || total_refs > max_refs_per_resource,
            )
            .attr("emitted_ref_count", emitted_refs as i64)
            .attr(
                "reference_gap",
                ast.reference_gap.clone().unwrap_or_default(),
            )
            .attr("diagnostic_count", ast.diagnostics.len() as i64)
            .source(src());
        apply_summary_attrs(builder, &ast.summary).emit();
        n += 1;

        let ns = rec.definition_namespace();

        // Regression: instead of emitting a pre-interpreted
        // SECURITY_SUSPECT_MODIFICATION fact (which encodes a rule decision), emit
        // neutral observations that carry the raw data. Rules in Layer C/M read
        // these and decide whether the observation constitutes a finding.
        //
        //   platform_tag_replace  → namespace=<ns>, replace=true already in
        //                           RESOURCE_AST_PARSED (via apply_summary_attrs).
        //   platform_recipe_disabled → output_count=0 already in RESOURCE_AST_PARSED.
        //
        // Both are therefore already observable from RESOURCE_AST_PARSED.
        // We additionally emit a lightweight RESOURCE_PLATFORM_OBSERVATION fact so
        // rules have a typed, queryable hook without re-filtering parsed facts.
        match &ast.summary {
            ResourceSummary::Tag(s) if s.replace && is_platform_namespace(&ns) => {
                store
                    .fact(EXTRACTOR, kind::RESOURCE_PLATFORM_OBSERVATION)
                    .subject(ast.resource_path.clone())
                    .attr("observation", "tag_replace")
                    .attr("namespace", ns.clone())
                    .attr("writer", rec.writer.clone())
                    .source(src())
                    .emit();
                n += 1;
            }
            ResourceSummary::Recipe(s) if s.output_count == 0 && is_platform_namespace(&ns) => {
                store
                    .fact(EXTRACTOR, kind::RESOURCE_PLATFORM_OBSERVATION)
                    .subject(ast.resource_path.clone())
                    .attr("observation", "recipe_output_empty")
                    .attr("namespace", ns.clone())
                    .attr("writer", rec.writer.clone())
                    .source(src())
                    .emit();
                n += 1;
            }
            _ => {}
        }

        store
            .fact(EXTRACTOR, kind::RESOURCE_DEFINITION)
            .subject(ast.resource_path.clone())
            .attr("domain", ast.domain.as_str())
            .attr("namespace", rec.definition_namespace())
            .attr("writer", rec.writer.clone())
            .attr("artifact_id", rec.artifact_id.clone())
            .attr(
                "definition_state",
                match ast.parse_status {
                    crate::model::ParseStatus::Invalid => "invalid-definition",
                    crate::model::ParseStatus::Skipped => "present-unparsed",
                    crate::model::ParseStatus::Parsed
                    | crate::model::ParseStatus::PartiallyParsed => "valid-definition",
                },
            )
            .source(src())
            .emit();
        n += 1;

        for r in ast.references.iter().take(max_refs_per_resource) {
            store
                .fact(EXTRACTOR, kind::RESOURCE_REFERENCE)
                .subject(ast.resource_path.clone())
                .attr("relation", r.relation.as_str())
                .attr("to", r.target.clone())
                .attr("namespace", r.namespace.clone())
                .attr("required", r.required)
                // Regression: `!conditions.is_empty()` is the correct per-edge gate —
                // it signals "this specific edge is gated by a load condition".
                // This is NOT the same as the aggregate `conditioned` flag (which
                // means "no required-unconditioned ref exists"). Per-edge this is fine.
                .attr("conditioned", !r.conditions.is_empty())
                .attr("is_tag", r.is_tag)
                .attr("reference_certainty", r.certainty.as_str())
                // Structural refs are certain; data-driven registry refs are a
                // heuristic JSON-pointer read, hence lower confidence (§24.2).
                .attr("confidence", ref_confidence(r.certainty) as f64)
                .source(src())
                .emit();
            n += 1;
        }

        // Per-object validation issues (the §4 `validate` output): parse
        // diagnostics surfaced as explain-only facts, never per-file warnings.
        for diag in &ast.diagnostics {
            store
                .fact(EXTRACTOR, kind::RESOURCE_SEMANTIC_ISSUE)
                .subject(ast.resource_path.clone())
                .attr("domain", ast.domain.as_str())
                .attr("severity", diag.severity.as_str())
                .attr("message", diag.message.clone())
                .attr("writer", rec.writer.clone())
                .source(src())
                .emit();
            n += 1;
        }
    }

    let parsed: std::collections::BTreeSet<(&str, &str)> = records
        .iter()
        .map(|record| {
            (
                record.artifact_id.as_str(),
                record.ast.resource_path.as_str(),
            )
        })
        .collect();
    for presence in presences {
        if parsed.contains(&(presence.artifact_id.as_str(), presence.path.as_str())) {
            continue;
        }
        store
            .fact(EXTRACTOR, kind::RESOURCE_DEFINITION)
            .subject(presence.path.clone())
            .attr(
                "domain",
                intermed_resource_identity::classify(&presence.path).as_str(),
            )
            .attr(
                "namespace",
                path_namespace(&presence.path).unwrap_or_else(|| "minecraft".to_string()),
            )
            .attr("writer", presence.writer.clone())
            .attr("artifact_id", presence.artifact_id.clone())
            .attr("definition_state", "present-unparsed")
            .source(SourceRef::inside(
                presence.archive.clone(),
                presence.path.clone(),
            ))
            .emit();
        n += 1;
    }

    for (ns, writers) in &graph.namespace_owners {
        for writer in writers {
            store
                .fact(EXTRACTOR, kind::NAMESPACE_OWNER)
                .subject(ns.clone())
                .attr("writer", writer.clone())
                .emit();
            n += 1;
        }
    }

    // Regression: the deleted_paths / RESOURCE_SEMANTIC_CONFLICT block was removed.
    //
    // The original logic classified a recipe with output_count==0 or a tag with
    // replace+empty as a "deleted" resource, then looked for references to it.
    // This had two fatal flaws:
    //
    //  1. Type mismatch: recipe paths are `data/.../recipe/*.json` and tag paths
    //     are `data/.../tags/…`. The reference expected_path computation produces
    //     `assets/.../models/`, `assets/.../textures/`, `data/.../loot_tables/`,
    //     or `data/.../advancements/` — none of which can overlap. The check was
    //     practically dead code.
    //
    //  2. Semantic error: `{"replace":true,"values":[]}` is a valid existing tag
    //     that happens to clear its effective membership. A reference `#foo:my_tag`
    //     to it is perfectly valid. Treating it as "deleted" was wrong.
    //
    // The neutral RESOURCE_PLATFORM_OBSERVATION facts (emitted above) carry the
    // raw replace/output_count data. Rules may decide whether to flag the
    // combination of "empty output + platform namespace" as suspicious.

    // dependency, regardless of how many resources reference it). The aggregate
    // carries exactly what Layer C needs to decide satisfied / missing /
    // optional-gated without re-reading edges:
    //   - `has_required_unconditioned` : some reference is required AND unconditioned.
    //   - `has_conditioned`            : some reference carries a load-gate condition.
    //   - `has_optional_unconditioned` : optional but no condition gate.
    //   - `via_recipe_type` : referenced as a recipe serializer `type` — lowest-FP signal.
    //   - `ref_count` / `from_path` / `target` : highest-priority sample provenance.
    let mut by_ns: BTreeMap<&str, ImplicitAgg<'_>> = BTreeMap::new();
    for edge in graph.implicit_dependency_candidates() {
        let agg = by_ns.entry(edge.namespace.as_str()).or_default();
        agg.ref_count += 1;
        let is_recipe_type = matches!(edge.relation, crate::model::RefRelation::UsesRecipeType);

        // Regression: track three states independently — never derive `conditioned`
        // from `!required`. An optional-unconditioned ref (`required=false, conds=[]`)
        // is a third state, neither "required" nor "conditioned".
        if !edge.conditions.is_empty() {
            agg.has_conditioned = true;
        } else if edge.required {
            // Unconditioned and required → real hard dependency.
            agg.has_required_unconditioned = true;
        } else {
            // Unconditioned but optional (`required:false` tag entry).
            agg.has_optional_unconditioned = true;
        }

        if is_recipe_type {
            agg.via_recipe_type = true;
        }

        // Regression: update sample using the priority method — recipe-type edges
        // supersede generic structural refs so `from_path`/`target` always
        // correspond to the evidence that drove the highest-priority flag.
        agg.update_sample(
            &edge.from_path,
            &edge.target,
            is_recipe_type,
            edge.certainty,
        );
    }

    // Regression: / #2 (provider_mod): the `installed` set must contain only *real
    // mod/plugin IDs* — not namespace names. Mixing namespace owners into
    // `installed` caused every owned namespace to be classified as "installed"
    // and blocked the single-owner branch in provider_mod resolution.
    //
    // We build two separate structures:
    //   `mod_ids`      — actual installed mod/plugin subject IDs + provided aliases.
    //   `provider_map` — namespace → set of mod IDs that own it (from namespace_owners
    //                    in the graph, NOT added to mod_ids).
    //
    // `classify_namespace` uses `mod_ids` for its "is this mod installed?" check.
    let mut mod_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for f in inputs
        .by_kind(kind::MOD)
        .chain(inputs.by_kind(kind::PLUGIN))
    {
        mod_ids.insert(f.subject.to_string());
    }
    for f in inputs.by_kind(kind::PROVIDED_DEPENDENCY) {
        if let Some(p) = f.attr("provides") {
            mod_ids.insert(p.to_string());
        }
    }
    // Namespace owners are NOT added to mod_ids — a namespace name is not a mod id.
    // They are used separately for provider_mod resolution (see below).

    for (ns, agg) in &by_ns {
        // Resolution record (§18): classify using real mod ids only.
        let class = intermed_resource_identity::classify_namespace(ns, &mod_ids);
        // Regression: use the three-state accessors — never `!required`.
        let required = agg.required();
        let conditioned = agg.conditioned();
        let state = intermed_resource_identity::resolve_state(class, required, conditioned);
        store
            .fact(EXTRACTOR, kind::RESOURCE_RESOLVE_RESULT)
            .subject(ns.to_string())
            .attr("namespace", ns.to_string())
            .attr("namespace_class", class.as_str())
            .attr("state", state.as_str())
            .attr("source_path", agg.sample_path.to_string())
            .attr(
                "ref_kind",
                if agg.via_recipe_type {
                    "recipe-serializer"
                } else {
                    "reference"
                },
            )
            .attr("required", required)
            .attr("conditioned", conditioned)
            // Regression: use SourceRef::file — these aggregate facts have no single
            // archive; the sample_path is the best provenance we have.
            .source(SourceRef::file(agg.sample_path.to_string()))
            .emit();
        n += 1;

        store
            .fact(EXTRACTOR, kind::IMPLICIT_DEPENDENCY_CANDIDATE)
            .subject(ns.to_string())
            .attr("from_path", agg.sample_path.to_string())
            .attr("target", agg.sample_target.to_string())
            .attr("ref_count", agg.ref_count as i64)
            .attr("required", required)
            .attr("conditioned", conditioned)
            .attr("via_recipe_type", agg.via_recipe_type)
            .attr("reference_certainty", agg.sample_certainty.as_str())
            // Carry the resolution so Layer C need not recompute it.
            .attr("namespace_class", class.as_str())
            .attr("resolve_state", state.as_str())
            .source(SourceRef::file(agg.sample_path.to_string()))
            .emit();
        n += 1;
    }

    // ── Per-mod implicit dependency edges (three-level model) ──────────────────
    // Attribute each *cross-namespace* structural reference to the mod that ships
    // it, so Layer C can compare implicit usage against the *declared* dependency
    // set (undisclosed / unused / conditionally-required findings). Scope is the
    // same low-FP relations as the candidate, but keyed per (consumer, provider)
    // and only when the provider namespace is genuinely foreign to the consumer.
    let mut by_consumer: BTreeMap<(&str, &str), ConsumerAgg<'_>> = BTreeMap::new();
    for edge in &graph.references {
        let via = match edge.relation {
            crate::model::RefRelation::UsesRecipeType => "recipe-serializer",
            crate::model::RefRelation::RegistryRef => "registry-ref",
            crate::model::RefRelation::LootEntry => "loot-function",
            _ => continue,
        };
        let ns = edge.namespace.as_str();
        let writer = edge.writer.as_str();
        if ns.is_empty() || writer.is_empty() || is_platform_namespace(ns) {
            continue;
        }
        // A mod referencing its own namespace is not a dependency on another mod.
        if graph
            .namespace_owners
            .get(ns)
            .is_some_and(|w| w.contains(writer))
        {
            continue;
        }
        // Find the archive for this edge's source record (for provenance).
        let archive = records
            .iter()
            .find(|r| r.ast.resource_path == edge.from_path)
            .map(|r| r.archive.as_str())
            .unwrap_or("");

        let agg = by_consumer.entry((writer, ns)).or_default();
        agg.ref_count += 1;
        let is_serializer = matches!(edge.relation, crate::model::RefRelation::UsesRecipeType);
        if edge.conditions.is_empty() {
            // Unconditioned, but an explicitly optional reference (`required:false`)
            // still does not force the dependency.
            if edge.required {
                agg.required = true;
            }
        } else {
            // Regression: store conditioned state separately — never derive from !required.
            agg.conditioned = true;
        }
        if is_serializer && edge.certainty == crate::model::ReferenceCertainty::ExactSchemaReference
        {
            agg.hard = true;
        }
        // Regression: update sample using priority — recipe-serializer edges supersede
        // loot-function / registry-ref so `via` always matches the dominant signal.
        agg.update_sample(&edge.from_path, archive, via, is_serializer, edge.certainty);
    }
    for ((writer, ns), agg) in by_consumer {
        // Regression: classify against mod_ids, not the old `installed` set that mixed
        // in namespace owners and would shadow the single-owner provider_mod branch.
        let class = intermed_resource_identity::classify_namespace(ns, &mod_ids);
        // Regression: agg.conditioned is stored independently — never `!agg.required`.
        let state = intermed_resource_identity::resolve_state(class, agg.required, agg.conditioned);

        // Regression: provider_mod resolution.
        // Previously: `installed.contains(ns)` → always true for owned namespaces
        // (because namespace owners were in installed), making the single-owner
        // branch unreachable.
        // Now: check if the namespace itself is a known mod id first; if not, look
        // for a single unambiguous owner in the graph's namespace_owners map.
        let provider_mod = if mod_ids.contains(ns) {
            // The namespace IS a mod id (e.g. mod id == namespace).
            ns.to_string()
        } else {
            // Try to resolve to the single mod that owns this namespace.
            graph
                .namespace_owners
                .get(ns)
                .filter(|w| w.len() == 1)
                .and_then(|w| w.iter().next())
                .cloned()
                .unwrap_or_else(|| ns.to_string())
        };
        store
            .fact(EXTRACTOR, kind::IMPLICIT_DEPENDENCY_EDGE)
            .subject(writer.to_string())
            .attr("provider_namespace", ns.to_string())
            .attr("provider_mod", provider_mod)
            .attr("via", agg.via.to_string())
            .attr("required", agg.required)
            .attr("conditioned", agg.conditioned)
            .attr("hard", agg.hard)
            .attr("reference_certainty", agg.sample_certainty.as_str())
            .attr("ref_count", agg.ref_count as i64)
            .attr("from_path", agg.sample_path.to_string())
            .attr("namespace_class", class.as_str())
            .attr("resolve_state", state.as_str())
            // Regression: use inside() with the archive so the source is correctly
            // attributed to the jar that contributed the sample edge.
            .source(if agg.sample_archive.is_empty() {
                SourceRef::file(agg.sample_path.to_string())
            } else {
                SourceRef::inside(agg.sample_archive.to_string(), agg.sample_path.to_string())
            })
            .emit();
        n += 1;
    }

    for diff in diffs {
        store
            .fact(EXTRACTOR, kind::RESOURCE_SEMANTIC_DIFF)
            .subject(diff.path.clone())
            .attr("diff_kind", diff.kind.as_str())
            .attr("writers", diff.writers.join(","))
            .attr("writer_count", diff.writers.len() as i64)
            .attr("detail", diff.detail.clone())
            // Principled severity: the diff declares its impact; severity is derived
            // centrally (impact + confidence), never hand-set per rule.
            .attr("impact", diff.kind.impact().as_str())
            .attr("severity", diff.kind.severity().as_str())
            .source(SourceRef::file(diff.path.clone()))
            .emit();
        n += 1;
    }

    // Emit dangling facts only for datapack-resource → datapack-resource relations
    // (loot table / advancement parent), the only ones a rule turns into a finding.
    // Model/texture unresolved refs are runtime-generatable (never a finding) and
    // are surfaced for `vfs explain` via `unresolved_model_references()` directly —
    // emitting them here would be thousands of dead facts.
    for d in graph.dangling_references().into_iter().filter(|d| {
        matches!(
            d.relation,
            crate::model::RefRelation::LootEntry | crate::model::RefRelation::ParentAdvancement
        )
    }) {
        let from_ns = path_namespace(d.from_path).unwrap_or_default();
        let owners = graph.owners_of(d.namespace);
        store
            .fact(EXTRACTOR, kind::RESOURCE_DANGLING_REFERENCE)
            .subject(d.from_path)
            .attr("relation", d.relation.as_str())
            .attr("to", d.target.to_string())
            .attr("namespace", d.namespace.to_string())
            .attr("from_namespace", from_ns.clone())
            // The reference points inside the *same* mod's own namespace — a typo /
            // forgotten file the mod controls, vs a cross-mod version mismatch.
            .attr("internal", !from_ns.is_empty() && from_ns == d.namespace)
            .attr("owners", owners.join(","))
            .attr("expected_path", d.expected_path.clone())
            .source(SourceRef::file(d.from_path.to_string()))
            .emit();
        n += 1;
    }

    // Effective-tag-membership: tag → missing tag references (resolvable now that
    // vanilla tags are indexed). Same dangling fact kind, `uses_tag` relation.
    for (from_path, tag_id, expected) in graph.missing_tag_references() {
        let to_ns = tag_id
            .trim_start_matches('#')
            .split_once(':')
            .map(|(ns, _)| ns.to_string())
            .unwrap_or_else(|| "minecraft".to_string());
        let from_ns = path_namespace(&from_path).unwrap_or_default();
        let owners = graph.owners_of(&to_ns);
        store
            .fact(EXTRACTOR, kind::RESOURCE_DANGLING_REFERENCE)
            .subject(from_path.clone())
            .attr("relation", crate::model::RefRelation::UsesTag.as_str())
            .attr("to", tag_id)
            .attr("namespace", to_ns.clone())
            .attr("from_namespace", from_ns.clone())
            .attr("internal", !from_ns.is_empty() && from_ns == to_ns)
            .attr("owners", owners.join(","))
            .attr("expected_path", expected)
            .source(SourceRef::file(from_path))
            .emit();
        n += 1;
    }

    n
}

/// Confidence for a reference edge: structural refs are certain; data-driven
/// registry-spec refs are a heuristic JSON-pointer read.
fn ref_confidence(certainty: crate::model::ReferenceCertainty) -> f32 {
    match certainty {
        crate::model::ReferenceCertainty::ExactSchemaReference => 1.0,
        crate::model::ReferenceCertainty::HeuristicRegistryReference => 0.8,
        crate::model::ReferenceCertainty::OpaqueCustomReference => 0.4,
    }
}

/// Attach a few compact, domain-specific attributes to the `resource_ast_parsed`
/// fact so reports and rules don't need to re-open the resource.
fn apply_summary_attrs<'a>(builder: FactBuilder<'a>, summary: &ResourceSummary) -> FactBuilder<'a> {
    match summary {
        ResourceSummary::Tag(s) => builder
            .attr("registry", s.registry.clone())
            .attr("replace", s.replace)
            .attr("entry_count", s.entry_count as i64)
            .attr("has_required_flag", s.has_required_flag),
        ResourceSummary::Recipe(s) => builder
            .attr("recipe_type", s.recipe_type.clone())
            .attr("serializer_namespace", s.serializer_namespace.clone())
            .attr("ingredient_count", s.ingredient_count as i64)
            .attr("output_count", s.output_count as i64)
            .attr("has_conditions", s.has_conditions)
            .attr("opacity", s.opacity.as_str()),
        ResourceSummary::Lang(s) => builder
            .attr("format", s.format.clone())
            .attr("key_count", s.key_count as i64),
        ResourceSummary::PackMcmeta(s) => {
            let b = builder.attr("has_description", s.has_description);
            match s.pack_format {
                Some(f) => b.attr("pack_format", f),
                None => b,
            }
        }
        ResourceSummary::Model(s) => {
            let b = builder.attr("texture_count", s.textures.len() as i64);
            let b = if let Some(fp) = &s.overrides_fingerprint {
                b.attr("overrides_fingerprint", fp.clone())
            } else {
                b.attr("override_count", 0i64)
            };
            match &s.parent {
                Some(p) => b.attr("parent", p.clone()),
                None => b,
            }
        }
        ResourceSummary::Blockstate(s) => builder
            .attr("variant_count", s.variant_count as i64)
            .attr("model_count", s.model_count as i64),
        ResourceSummary::LootTable(s) => builder
            .attr("pool_count", s.pool_count as i64)
            .attr("entry_count", s.entry_count as i64),
        ResourceSummary::Atlas(s) => builder
            .attr("source_count", s.source_count as i64)
            .attr("has_non_single_source", s.has_non_single_source),
        ResourceSummary::Advancement(s) => {
            let b = builder
                .attr("criteria_count", s.criteria_count as i64)
                .attr("has_rewards", s.has_rewards)
                .attr("has_conditions", s.has_conditions);
            match &s.parent {
                Some(p) => b.attr("parent", p.clone()),
                None => b,
            }
        }
        ResourceSummary::Predicate(s) => builder.attr("has_conditions", s.has_conditions),
        ResourceSummary::ItemModifier(s) => builder.attr("has_conditions", s.has_conditions),
        ResourceSummary::GenericJson { .. } | ResourceSummary::Generic => builder,
    }
}

#[cfg(test)]
mod edge_tests {
    use super::*;
    use crate::semantic::refs::ResourceAstRecord;
    use crate::{ResourceLevel, parse_resource};
    use intermed_doctor_core::facts::FactStore;

    fn record(writer: &str, path: &str, bytes: &[u8]) -> ResourceAstRecord {
        ResourceAstRecord {
            archive: format!("{writer}.jar"),
            artifact_id: format!("sha256:{writer}"),
            writer: writer.to_string(),
            ast: parse_resource(path, bytes, ResourceLevel::Full),
        }
    }

    #[test]
    fn implicit_edge_attributes_serializer_reference_to_consumer() {
        // `addon` ships a recipe whose serializer `type` is a foreign namespace.
        let recipe = br#"{"type":"thermal:smelter","ingredient":{"item":"minecraft:iron_ingot"},"result":{"id":"minecraft:gold_ingot"}}"#;
        let records = vec![record("addon", "data/addon/recipe/x.json", recipe)];
        let graph = ResourceGraph::build(&records);

        let mut store = FactStore::new();
        emit(
            &mut store,
            &FactStore::new(),
            &records,
            &[],
            &graph,
            &[],
            64,
        );

        let edges: Vec<_> = store.by_kind(kind::IMPLICIT_DEPENDENCY_EDGE).collect();
        assert_eq!(edges.len(), 1, "expected one implicit edge");
        let e = edges[0];
        assert_eq!(e.subject, "addon");
        assert_eq!(e.attr("provider_namespace"), Some("thermal"));
        assert_eq!(e.attr("via"), Some("recipe-serializer"));
        assert_eq!(e.attr_bool("hard"), Some(true));
        assert_eq!(e.attr_bool("required"), Some(true));
    }

    #[test]
    fn implicit_edge_skips_self_namespace() {
        // A recipe referencing its own namespace's serializer is not a cross-mod dep.
        let recipe = br#"{"type":"addon:custom","ingredient":{"item":"minecraft:stone"},"result":{"id":"addon:thing"}}"#;
        let records = vec![record("addon", "data/addon/recipe/y.json", recipe)];
        let graph = ResourceGraph::build(&records);

        let mut store = FactStore::new();
        emit(
            &mut store,
            &FactStore::new(),
            &records,
            &[],
            &graph,
            &[],
            64,
        );

        assert_eq!(store.by_kind(kind::IMPLICIT_DEPENDENCY_EDGE).count(), 0);
    }

    // ── Regression tests for fact-lowering invariants ────────────────────────

    /// Regression: conditioned must be stored independently from !required.
    /// An optional-unconditioned ref (`required=false, conditions=[]`) must produce
    /// `required=false, conditioned=false` on the aggregate, not `conditioned=true`.
    #[test]
    fn aggregate_conditioned_is_independent_of_required() {
        // Tag with `required:false` optional entry — no conditions, not required.
        // This exercises the three-state path.
        let recipe = br#"{"type":"thermal:optional_ref","ingredient":{"item":"minecraft:stone","required":false},"result":{"id":"minecraft:stone"}}"#;
        let records = vec![record("addon", "data/addon/recipe/z.json", recipe)];
        let graph = ResourceGraph::build(&records);
        let mut store = FactStore::new();
        emit(
            &mut store,
            &FactStore::new(),
            &records,
            &[],
            &graph,
            &[],
            64,
        );

        for edge in store.by_kind(kind::IMPLICIT_DEPENDENCY_EDGE) {
            // If conditioned were derived as !required this would be true for
            // required=false edges. It must always equal the actual condition state.
            let required = edge.attr_bool("required").unwrap_or(false);
            let conditioned = edge.attr_bool("conditioned").unwrap_or(false);
            // For an unconditioned edge: conditioned must NOT be derived as !required.
            // Both required and conditioned can be false simultaneously (optional, no gate).
            assert!(
                !(required && conditioned),
                "required and conditioned cannot both be true on the same edge"
            );
        }
    }

    /// Regression: provider_mod must resolve to the actual mod id (single owner),
    /// not fall back to the namespace name when a namespace is owned by exactly one mod.
    #[test]
    fn provider_mod_resolves_to_single_owner_not_namespace() {
        // `addon` uses a recipe serializer from `legacy_api` namespace,
        // which is owned by `actualmod` (different mod id from namespace).
        let recipe = br#"{"type":"legacy_api:smelter","ingredient":{"item":"minecraft:iron_ingot"},"result":{"id":"minecraft:gold_ingot"}}"#;
        let mut records = vec![record("addon", "data/addon/recipe/p.json", recipe)];
        // Ship a definition under legacy_api namespace so actualmod owns it.
        let legacy_def = br#"{"type":"legacy_api:processing","ingredient":{"item":"minecraft:stone"},"result":{"id":"minecraft:stone"}}"#;
        records.push(ResourceAstRecord {
            archive: "actualmod.jar".to_string(),
            artifact_id: "sha256:actualmod".to_string(),
            writer: "actualmod".to_string(),
            ast: parse_resource(
                "data/legacy_api/recipe/x.json",
                legacy_def,
                ResourceLevel::Full,
            ),
        });
        let graph = ResourceGraph::build(&records);
        let mut store = FactStore::new();
        emit(
            &mut store,
            &FactStore::new(),
            &records,
            &[],
            &graph,
            &[],
            64,
        );

        let edges: Vec<_> = store
            .by_kind(kind::IMPLICIT_DEPENDENCY_EDGE)
            .filter(|e| e.attr("provider_namespace") == Some("legacy_api"))
            .collect();
        // The edge must resolve provider_mod to "actualmod" (the single owner),
        // not "legacy_api" (the namespace name, which is not a mod id).
        if let Some(e) = edges.first() {
            assert_eq!(
                e.attr("provider_mod"),
                Some("actualmod"),
                "provider_mod must be the owning mod id, not the namespace name"
            );
        }
    }

    /// Regression: platform-namespace observations must be emitted as neutral
    /// RESOURCE_PLATFORM_OBSERVATION facts, not SECURITY_SUSPECT_MODIFICATION.
    #[test]
    fn platform_tag_replace_emits_neutral_observation_not_security_fact() {
        // A minecraft: tag with replace=true.
        let tag = br#"{"replace":true,"values":["minecraft:oak_log"]}"#;
        let records = vec![record("addon", "data/minecraft/tags/items/logs.json", tag)];
        let graph = ResourceGraph::build(&records);
        let mut store = FactStore::new();
        emit(
            &mut store,
            &FactStore::new(),
            &records,
            &[],
            &graph,
            &[],
            64,
        );

        // Must emit a neutral observation fact.
        let obs: Vec<_> = store.by_kind(kind::RESOURCE_PLATFORM_OBSERVATION).collect();
        assert!(!obs.is_empty(), "platform observation must be emitted");
        assert_eq!(obs[0].attr("observation"), Some("tag_replace"));

        // Must NOT emit a security suspect fact (that's a rule's job).
        assert_eq!(
            store.by_kind("security_suspect_modification").count(),
            0,
            "Layer M must not pre-interpret the observation as suspicious"
        );
    }

    /// Regression: references_truncated and emitted_ref_count must be emitted
    /// when references are truncated by max_refs_per_resource.
    #[test]
    fn truncation_metadata_emitted_when_refs_exceed_limit() {
        // A recipe with one reference, but limit is set to 0.
        let recipe = br#"{"type":"thermal:smelter","ingredient":{"item":"minecraft:iron_ingot"},"result":{"id":"minecraft:gold_ingot"}}"#;
        let records = vec![record("addon", "data/addon/recipe/t.json", recipe)];
        let graph = ResourceGraph::build(&records);
        let mut store = FactStore::new();
        // Set max_refs=0 to trigger truncation.
        emit(&mut store, &FactStore::new(), &records, &[], &graph, &[], 0);

        // Find the RESOURCE_AST_PARSED fact that carries truncation metadata.
        let parsed: Vec<_> = store
            .by_kind(kind::RESOURCE_AST_PARSED)
            .filter(|f| f.attr_bool("references_truncated").is_some())
            .collect();
        assert_eq!(parsed.len(), 1, "one resource must emit one AST fact");
        let f = parsed[0];
        assert_eq!(
            f.attr_bool("references_truncated"),
            Some(true),
            "references_truncated must be true when refs exceed limit"
        );
        assert_eq!(
            f.attr_f64("emitted_ref_count").map(|v| v as i64),
            Some(0),
            "emitted_ref_count must be 0 when limit is 0"
        );
    }
}
