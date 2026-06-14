//! Lowering the typed AST into compact facts.
//!
//! This is the one place where Layer M touches the [`FactStore`]. It emits only
//! compact, bounded facts (summaries and edges — never raw JSON), preserving the
//! contract that **the AST never emits findings**: rules in [`crate::rule`] read
//! these facts and decide what is a problem.

use std::collections::BTreeMap;

use intermed_doctor_core::facts::{kind, FactBuilder, FactStore, SourceRef};

use crate::model::ResourceSummary;
use crate::semantic::diff::SemanticDiff;
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
                .attr("conditioned", r.conditioned)
                .attr("is_tag", r.is_tag)
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
        if !edge.conditioned {
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
    for (ns, agg) in by_ns {
        store
            .fact(EXTRACTOR, kind::IMPLICIT_DEPENDENCY_CANDIDATE)
            .subject(ns.to_string())
            .attr("from_path", agg.sample_path.to_string())
            .attr("target", agg.sample_target.to_string())
            .attr("ref_count", agg.ref_count as i64)
            .attr("required", agg.required)
            .attr("via_recipe_type", agg.via_recipe_type)
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
            .source(SourceRef::file(diff.path.clone()))
            .emit();
        n += 1;
    }

    n
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
            .attr("ingredient_count", s.ingredient_count as i64)
            .attr("output_count", s.output_count as i64)
            .attr("has_conditions", s.has_conditions),
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
        ResourceSummary::Generic => builder,
    }
}
