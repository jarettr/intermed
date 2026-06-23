//! Lowering the typed AST into compact facts.
//!
//! This is the one place where Layer M touches the [`FactStore`]. It emits only
//! compact, bounded facts (summaries and edges — never raw JSON), preserving the
//! contract that **the AST never emits findings**: rules in [`crate::rule`] read
//! these facts and decide what is a problem.

use std::collections::BTreeMap;

use intermed_doctor_core::facts::{FactBuilder, FactStore, SourceRef, kind};

use crate::model::ResourceSummary;
use crate::semantic::diff::SemanticDiff;
use crate::semantic::namespace::{is_platform_namespace, path_namespace};
use crate::semantic::refs::{ResourceAstRecord, ResourceGraph};

/// Collector / extractor id for all Layer-M facts.
pub const EXTRACTOR: &str = "resource-ast-scanner";

/// Per-namespace accumulator for the implicit-dependency candidate fact.
#[derive(Default)]
struct ImplicitAgg<'a> {
    ref_count: usize,
    required: bool,
    via_recipe_type: bool,
    sample_path: &'a str,
    sample_target: &'a str,
}

/// Per-`(consumer mod, provider namespace)` accumulator for the per-mod
/// `implicit_dependency_edge` fact (the three-level dependency model).
#[derive(Default)]
struct ConsumerAgg<'a> {
    ref_count: usize,
    /// Some reference is unconditioned — the consumer genuinely needs the provider.
    required: bool,
    /// Some reference is gated (e.g. `modloaded:other`) — a conditional requirement.
    conditioned: bool,
    /// At least one reference is load-breaking if absent (recipe serializer `type`).
    hard: bool,
    sample_path: &'a str,
    via: &'a str,
}

/// Emit every Layer-M fact for the parsed pack. Returns the number emitted.
///
/// `max_refs_per_resource` bounds the per-resource `resource_reference` fan-out so
/// a pathological resource cannot flood the store (backpressure, Stage 3).
pub fn emit(
    store: &mut FactStore,
    records: &[ResourceAstRecord],
    graph: &ResourceGraph,
    diffs: &[SemanticDiff],
    max_refs_per_resource: usize,
) -> usize {
    let mut n = 0;

    for rec in records {
        let ast = &rec.ast;
        let src = || SourceRef::inside(rec.archive.clone(), ast.resource_path.clone());

        let builder = store
            .fact(EXTRACTOR, kind::RESOURCE_AST_PARSED)
            .subject(ast.resource_path.clone())
            .attr("domain", ast.domain.as_str())
            .attr("parse_status", ast.parse_status.as_str())
            .attr("semantic_hash", ast.semantic_hash.clone())
            .attr("writer", rec.writer.clone())
            .attr("archive", rec.archive.clone())
            .attr("ref_count", ast.references.len() as i64)
            .attr("diagnostic_count", ast.diagnostics.len() as i64)
            .source(src());
        apply_summary_attrs(builder, &ast.summary).emit();
        n += 1;

        let ns = rec.definition_namespace();
        match &ast.summary {
            ResourceSummary::Tag(s) if s.replace && is_platform_namespace(&ns) => {
                store
                    .fact(EXTRACTOR, kind::SECURITY_SUSPECT_MODIFICATION)
                    .subject(ast.resource_path.clone())
                    .attr("detail", "platform_tag_replace")
                    .attr("writer", rec.writer.clone())
                    .source(src())
                    .emit();
                n += 1;
            }
            ResourceSummary::Recipe(s) if s.output_count == 0 && is_platform_namespace(&ns) => {
                store
                    .fact(EXTRACTOR, kind::SECURITY_SUSPECT_MODIFICATION)
                    .subject(ast.resource_path.clone())
                    .attr("detail", "platform_recipe_disabled")
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
                .attr("conditioned", !r.conditions.is_empty())
                .attr("is_tag", r.is_tag)
                // Structural refs are certain; data-driven registry refs are a
                // heuristic JSON-pointer read, hence lower confidence (§24.2).
                .attr("confidence", ref_confidence(r.relation) as f64)
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

    let mut deleted_paths = std::collections::BTreeSet::new();
    for rec in records {
        let is_deleted = match &rec.ast.summary {
            ResourceSummary::Recipe(s) => s.output_count == 0,
            ResourceSummary::Tag(s) => s.replace && s.entry_count == 0,
            _ => false,
        };
        if is_deleted {
            deleted_paths.insert(rec.ast.resource_path.as_str());
        }
    }

    for rec in records {
        for r in &rec.ast.references {
            let expected_path = match r.relation {
                crate::model::RefRelation::ParentModel | crate::model::RefRelation::UsesModel => {
                    Some(crate::semantic::refs::model_resource_path(&r.target))
                }
                crate::model::RefRelation::UsesTexture => {
                    Some(crate::semantic::refs::texture_resource_path(&r.target))
                }
                crate::model::RefRelation::LootEntry => {
                    Some(crate::semantic::refs::loot_table_resource_path(&r.target))
                }
                crate::model::RefRelation::AdvancementCriterion => {
                    Some(crate::semantic::refs::advancement_resource_path(&r.target))
                }
                _ => None,
            };

            if let Some(ep) = expected_path {
                if deleted_paths.contains(ep.as_str()) {
                    store
                        .fact(EXTRACTOR, kind::RESOURCE_SEMANTIC_CONFLICT)
                        .subject(rec.ast.resource_path.clone())
                        .attr("relation", r.relation.as_str())
                        .attr("to", r.target.clone())
                        .attr("expected_path", ep)
                        .attr("conflict_type", "references_deleted_resource")
                        .source(SourceRef::inside(
                            rec.archive.clone(),
                            rec.ast.resource_path.clone(),
                        ))
                        .emit();
                    n += 1;
                }
            }
        }
    }

    // Implicit dependencies: one candidate per *namespace* (a missing mod is a
    // dependency, regardless of how many resources reference it). The aggregate
    // carries exactly what Layer C needs to decide satisfied / missing /
    // optional-gated without re-reading edges:
    //   - `required`  : some reference is unconditioned (absence would break it).
    //   - `via_recipe_type` : referenced as a recipe serializer `type` — the
    //     lowest-false-positive signal, since a missing serializer hard-fails the
    //     recipe load rather than silently skipping it.
    //   - `ref_count` / `from_path` : sample provenance.
    let mut by_ns: BTreeMap<&str, ImplicitAgg<'_>> = BTreeMap::new();
    for edge in graph.implicit_dependency_candidates() {
        let agg = by_ns.entry(edge.namespace.as_str()).or_default();
        agg.ref_count += 1;
        // A reference makes the namespace a *hard* dependency only when it is both
        // unconditioned (no `mod_loaded` load-gate) **and** not an explicitly
        // optional entry (`{"id": …, "required": false}` in a tag). Ignoring
        // `edge.required` flagged optional compat tag entries (an `alexsmobs:`
        // elytra listed `required:false`) and mod-gated compat recipes as
        // `required-missing` — false positives, since Minecraft silently drops
        // both when the other mod is absent.
        if edge.conditions.is_empty() && edge.required {
            agg.required = true;
        }
        if matches!(edge.relation, crate::model::RefRelation::UsesRecipeType) {
            agg.via_recipe_type = true;
        }
        if agg.sample_path.is_empty() {
            agg.sample_path = &edge.from_path;
            agg.sample_target = &edge.target;
        }
    }
    // The satisfied set for namespace resolution: installed mod/plugin ids, declared
    // `provides` aliases, and every resource-namespace owner in the pack. Built once
    // (owned) so the emit loop below can borrow the store mutably.
    let mut installed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for f in store.by_kind(kind::MOD).chain(store.by_kind(kind::PLUGIN)) {
        installed.insert(f.subject.clone());
    }
    for f in store.by_kind(kind::PROVIDED_DEPENDENCY) {
        if let Some(p) = f.attr("provides") {
            installed.insert(p.to_string());
        }
    }
    for owner_ns in graph.namespace_owners.keys() {
        installed.insert(owner_ns.clone());
    }

    for (ns, agg) in by_ns {
        // Resolution record (§18): classify the namespace and derive a resolve
        // state. A reference gated only by conditions is never `required-missing`.
        let class = intermed_resource_identity::classify_namespace(ns, &installed);
        let conditioned = !agg.required;
        let state = intermed_resource_identity::resolve_state(class, agg.required, conditioned);
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
            .attr("required", agg.required)
            .source(SourceRef::file(agg.sample_path.to_string()))
            .emit();
        n += 1;

        store
            .fact(EXTRACTOR, kind::IMPLICIT_DEPENDENCY_CANDIDATE)
            .subject(ns.to_string())
            .attr("from_path", agg.sample_path.to_string())
            .attr("target", agg.sample_target.to_string())
            .attr("ref_count", agg.ref_count as i64)
            .attr("required", agg.required)
            .attr("via_recipe_type", agg.via_recipe_type)
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
        let agg = by_consumer.entry((writer, ns)).or_default();
        agg.ref_count += 1;
        if edge.conditions.is_empty() {
            // Unconditioned, but an explicitly optional reference (`required:false`)
            // still does not force the dependency.
            if edge.required {
                agg.required = true;
            }
        } else {
            agg.conditioned = true;
        }
        if matches!(edge.relation, crate::model::RefRelation::UsesRecipeType) {
            agg.hard = true;
        }
        if agg.sample_path.is_empty() {
            agg.sample_path = &edge.from_path;
            agg.via = via;
        }
    }
    for ((writer, ns), agg) in by_consumer {
        let class = intermed_resource_identity::classify_namespace(ns, &installed);
        let conditioned = !agg.required;
        let state = intermed_resource_identity::resolve_state(class, agg.required, conditioned);
        // Resolve the provider mod id when unambiguous (the namespace is itself an
        // installed id, or a single owner ships it under a different mod id).
        let provider_mod = if installed.contains(ns) {
            ns.to_string()
        } else {
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
            .attr("ref_count", agg.ref_count as i64)
            .attr("from_path", agg.sample_path.to_string())
            .attr("namespace_class", class.as_str())
            .attr("resolve_state", state.as_str())
            .source(SourceRef::file(agg.sample_path.to_string()))
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
            crate::model::RefRelation::LootEntry | crate::model::RefRelation::AdvancementCriterion
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
fn ref_confidence(relation: crate::model::RefRelation) -> f32 {
    match relation {
        crate::model::RefRelation::RegistryRef => 0.8,
        _ => 1.0,
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
            let b = builder
                .attr("texture_count", s.texture_count as i64)
                .attr("override_count", s.override_count as i64);
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

    fn record(writer: &str, path: &str, bytes: &[u8]) -> ResourceAstRecord {
        ResourceAstRecord {
            archive: format!("{writer}.jar"),
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
        emit(&mut store, &records, &graph, &[], 64);

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
        emit(&mut store, &records, &graph, &[], 64);

        assert_eq!(store.by_kind(kind::IMPLICIT_DEPENDENCY_EDGE).count(), 0);
    }
}
