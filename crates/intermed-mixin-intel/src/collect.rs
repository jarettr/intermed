//! Fact emission from mixin scan results.

use intermed_doctor_core::facts::{kind, SourceRef};
use intermed_doctor_core::CollectCtx;
use intermed_doctor_core::settings::MixinSettings;

use crate::model::{MixinOperation, MixinScan};
use crate::scan::extractor_id;

pub fn emit_scan(ctx: &mut CollectCtx<'_>, scan: &MixinScan) -> usize {
    emit_scan_with_settings(ctx, scan, ctx.settings.mixin)
}

/// Emit mixin facts, honoring [`MixinSettings`] noise controls.
pub fn emit_scan_with_settings(
    ctx: &mut CollectCtx<'_>,
    scan: &MixinScan,
    mixin: MixinSettings,
) -> usize {
    let extractor = extractor_id();
    let mut emitted = 0usize;

    for c in &scan.configs {
        ctx.store
            .fact(extractor, kind::MIXIN_CONFIG)
            .subject(c.mod_id.clone())
            .attr("archive", c.archive.clone())
            .attr("path", c.path.clone())
            .attr("package", c.package.clone())
            .attr("priority", c.priority)
            .attr("mixins", c.mixins.join(","))
            .attr("has_plugin", c.plugin.is_some())
            .source(SourceRef::inside(c.archive.clone(), c.path.clone()))
            .emit();
        emitted += 1;

        if let Some(plugin) = &c.plugin {
            ctx.store
                .fact(extractor, kind::MIXIN_CONFIG_PLUGIN)
                .subject(c.mod_id.clone())
                .attr("plugin", plugin.clone())
                .attr("config", c.path.clone())
                .source(SourceRef::inside(c.archive.clone(), c.path.clone()))
                .emit();
            emitted += 1;
        }

        if let Some(refmap) = &c.refmap {
            // Records that name resolution is available for this config, so the
            // analyzer's site keys for it are higher-confidence (vs. a config
            // with no refmap whose injection points may stay in named form).
            ctx.store
                .fact(extractor, kind::MIXIN_REFMAP_LOADED)
                .subject(c.mod_id.clone())
                .attr("refmap", refmap.clone())
                .attr("config", c.path.clone())
                .source(SourceRef::inside(c.archive.clone(), c.path.clone()))
                .emit();
            emitted += 1;
        }
    }

    for class in &scan.classes {
        ctx.store
            .fact(extractor, kind::MIXIN_CLASS)
            .subject(class.class_name.clone())
            .attr("mod", class.mod_id.clone())
            .attr("archive", class.archive.clone())
            .attr("config", class.config.clone())
            .attr("class_path", class.class_path.clone())
            .attr("priority", class.priority)
            .attr(
                "operations",
                class
                    .operations
                    .iter()
                    .map(MixinOperation::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .source(SourceRef::inside(
                class.archive.clone(),
                class.class_path.clone(),
            ))
            .emit();
        emitted += 1;

        for target in &class.targets {
            let mut builder = ctx
                .store
                .fact(extractor, kind::MIXIN_TARGET)
                .subject(class.mod_id.clone())
                .attr("target", target.clone())
                .attr("mixin", class.class_name.clone())
                .attr("priority", class.priority);
            if let Some(ns) = class.target_namespace.get(target) {
                if let Some(named) = &ns.named {
                    builder = builder.attr("target_named", named.clone());
                }
                if let Some(inter) = &ns.intermediary {
                    builder = builder.attr("target_intermediary", inter.clone());
                }
            }
            builder
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }

        for op in &class.operations {
            if class.targets.is_empty() {
                continue;
            }
            for target in &class.targets {
                ctx.store
                    .fact(extractor, kind::MIXIN_OPERATION)
                    .subject(class.mod_id.clone())
                    .attr("target", target.clone())
                    .attr("mixin", class.class_name.clone())
                    .attr("operation", op.as_str())
                    .source(SourceRef::inside(
                        class.archive.clone(),
                        class.class_path.clone(),
                    ))
                    .emit();
                emitted += 1;
            }
        }

        for hot in &class.hot_paths {
            ctx.store
                .fact(extractor, kind::MIXIN_HOTSPOT)
                .subject(hot.clone())
                .attr("mod", class.mod_id.clone())
                .attr("mixin", class.class_name.clone())
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }

        for inj in &class.injected_methods {
            ctx.store
                .fact(extractor, kind::MIXIN_INJECTION_POINT)
                .subject(class.mod_id.clone())
                .attr("mixin", class.class_name.clone())
                .attr("target", inj.target.clone())
                .attr("method", inj.original.clone())
                .attr("resolved_method", inj.resolved.clone())
                .attr("canonical_method", inj.canonical.clone())
                .attr("site_key", inj.site_key.clone())
                .attr("handler_method", inj.handler_method.clone())
                .attr("handler_descriptor", inj.handler_descriptor.clone())
                .attr("mutates_target_local", inj.mutates_target_local)
                .attr("at_target", inj.at_target.clone())
                .attr("at_detail", inj.at_detail.clone())
                .attr("impact", inj.impact.clone())
                .attr("injection_type", inj.injection_type.clone())
                .attr("resolved_via_refmap", inj.resolved_via_refmap)
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }

        for shadow in &class.shadows {
            ctx.store
                .fact(extractor, kind::MIXIN_SHADOW)
                .subject(class.mod_id.clone())
                .attr("mixin", class.class_name.clone())
                .attr("target", shadow.target.clone())
                .attr("name", shadow.name.clone())
                .attr("descriptor", shadow.descriptor.clone())
                .attr("kind", match shadow.kind {
                    crate::model::MemberKind::Field => "field",
                    crate::model::MemberKind::Method => "method",
                })
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }

        for added in &class.added_members {
            ctx.store
                .fact(extractor, kind::MIXIN_ADDED_MEMBER)
                .subject(class.mod_id.clone())
                .attr("mixin", class.class_name.clone())
                .attr("target", added.target.clone())
                .attr("name", added.name.clone())
                .attr("descriptor", added.descriptor.clone())
                .attr("kind", match added.kind {
                    crate::model::MemberKind::Field => "field",
                    crate::model::MemberKind::Method => "method",
                })
                .attr("origin", added.origin.clone())
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }

        for call in &class.calls {
            ctx.store
                .fact(extractor, kind::MIXIN_CALLS)
                .subject(class.mod_id.clone())
                .attr("mixin", class.class_name.clone())
                .attr("target", call.target.clone())
                .attr("owner", call.owner_class.clone())
                .attr("member", call.member_name.clone())
                .attr("descriptor", call.descriptor.clone())
                .attr(
                    "kind",
                    match call.kind {
                        crate::model::CallKind::MethodInvocation => "method",
                        crate::model::CallKind::FieldAccess => "field",
                    },
                )
                .attr("provenance", call.provenance.as_str())
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }

        for body in &class.handler_bodies {
            ctx.store
                .fact(extractor, kind::MIXIN_HANDLER_BODY)
                .subject(class.mod_id.clone())
                .attr("mixin", class.class_name.clone())
                .attr("handler_method", body.handler_method.clone())
                .attr("instruction_count", i64::from(body.instruction_count))
                .attr("branch_count", i64::from(body.branch_count))
                .attr("return_count", i64::from(body.return_count))
                .attr("exception_handlers", i64::from(body.exception_handlers))
                .attr("uses_reflection", body.uses_reflection)
                .attr("modifies_return_value", body.modifies_return_value)
                .attr("throws_exception", body.throws_exception)
                .attr("uses_callback_info", body.uses_callback_info)
                .attr("calls_original_operation", body.calls_original_operation)
                .attr("handler_descriptor", body.handler_descriptor.clone())
                .attr("handler_local_store", body.handler_local_store)
                .attr(
                    "accesses_target_fields",
                    body.accesses_target_fields.join(","),
                )
                .attr("calls_target_methods", body.calls_target_methods.join(","))
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;

            if mixin.emit_handler_effect_facts() {
                let handler_effect = crate::handler_effect::derive_handler_effect(body);
                ctx.store
                    .fact(extractor, kind::MIXIN_HANDLER_EFFECT)
                .subject(class.mod_id.clone())
                .attr("mixin", class.class_name.clone())
                .attr("handler_method", handler_effect.handler_method.clone())
                .attr("handler_local_store", handler_effect.handler_local_store)
                .attr("modifies_return", handler_effect.modifies_return)
                .attr("early_return", handler_effect.early_return)
                .attr("cancels", handler_effect.cancels)
                .attr("sets_return_value", handler_effect.sets_return_value)
                .attr("conditional_control", handler_effect.conditional_control)
                .attr("return_value_source", handler_effect.return_value_source.as_str())
                .attr("writes_target_state", handler_effect.writes_target_state)
                .attr("original_call_count", i64::from(handler_effect.original_call_count))
                .attr("complexity_score", i64::from(handler_effect.complexity_score))
                .attr(
                    "side_effects",
                    handler_effect
                        .side_effects
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
                emitted += 1;
            }
        }

        for effect in &class.effects {
            ctx.store
                .fact(extractor, kind::MIXIN_EFFECT)
                .subject(class.mod_id.clone())
                .attr("mixin", effect.mixin_class.clone())
                .attr("target", effect.target.clone())
                .attr("method", effect.method.clone())
                .attr("handler_method", effect.handler_method.clone())
                .attr("operation", effect.operation.as_str())
                .attr("site_key", effect.site_key.clone())
                .attr("at_target", effect.at_target.clone())
                .attr("hot_path", effect.hot_path)
                .attr("effect_description", effect.effect_description.clone())
                .attr(
                    "effect_kinds",
                    effect
                        .effect_kinds
                        .iter()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }

        for edge in &class.target_hierarchy {
            ctx.store
                .fact(extractor, kind::MIXIN_HIERARCHY)
                .subject(edge.target.clone())
                .attr("ancestor", edge.ancestor.clone())
                .attr("depth", i64::from(edge.depth))
                .attr("relation", edge.relation.clone())
                .attr("mod", class.mod_id.clone())
                .attr("mixin", class.class_name.clone())
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }
    }

    for overlap in &scan.overlaps {
        ctx.store
            .fact(extractor, kind::MIXIN_OVERLAP)
            .subject(overlap.target.clone())
            .attr("mods", overlap.mods.join(","))
            .attr("classes", overlap.classes.join(","))
            .attr(
                "operations",
                overlap
                    .operations
                    .iter()
                    .map(MixinOperation::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .attr("hot_path", overlap.hot_path)
            .attr("method_conflict", overlap.method_conflict)
            .attr("shared_methods", overlap.shared_methods.join(","))
            .attr("effect_summaries", overlap.effect_summaries.join(" | "))
            .source(SourceRef::file(overlap.target.clone()))
            .emit();
        emitted += 1;
    }

    for overwrite in &scan.high_risk_overwrites {
        ctx.store
            .fact(extractor, kind::HIGH_RISK_OVERWRITE)
            .subject(overwrite.mod_id.clone())
            .attr("target", overwrite.target.clone())
            .attr("mixin", overwrite.class_name.clone())
            .attr("method", overwrite.method.clone())
            .attr("site_key", overwrite.site_key.clone())
            .attr("hot_path", overwrite.hot_path)
            .attr("effect_description", overwrite.effect_description.clone())
            .source(SourceRef::file(overwrite.target.clone()))
            .emit();
        emitted += 1;
    }

    for interaction in &scan.interactions {
        ctx.store
            .fact(extractor, kind::MIXIN_INTERACTION)
            .subject(interaction.id.clone())
            .attr("interaction_type", interaction.interaction_type.as_str())
            .attr("mod_a", interaction.mod_a.clone())
            .attr("mod_b", interaction.mod_b.clone())
            .attr("mixin_a", interaction.mixin_a.clone())
            .attr("mixin_b", interaction.mixin_b.clone())
            .attr("target", interaction.target.clone())
            .attr("detail", interaction.detail.clone())
            .attr("strength", i64::from(interaction.strength))
            .attr("cross_mod", interaction.cross_mod)
            .source(SourceRef::file(interaction.target.clone()))
            .emit();
        emitted += 1;
    }

    for edge in &scan.conflict_edges {
        ctx.store
            .fact(extractor, kind::MIXIN_CONFLICT_EDGE)
            .subject(edge.id.clone())
            .attr("edge_type", edge.edge_type.as_str())
            .attr("source_mod", edge.source_mod.clone())
            .attr("target_mod", edge.target_mod.clone())
            .attr("source_mixin", edge.source_mixin.clone())
            .attr("target_mixin", edge.target_mixin.clone())
            .attr("target_class", edge.target_class.clone())
            .attr("site", edge.site.clone())
            .attr("strength", i64::from(edge.strength))
            .source(SourceRef::file(edge.target_class.clone()))
            .emit();
        emitted += 1;
    }

    for conflict in &scan.priority_conflicts {
        ctx.store
            .fact(extractor, kind::MIXIN_PRIORITY_CONFLICT)
            .subject(conflict.target.clone())
            .attr("mod_a", conflict.mod_a.clone())
            .attr("mod_b", conflict.mod_b.clone())
            .attr("mixin_a", conflict.mixin_a.clone())
            .attr("mixin_b", conflict.mixin_b.clone())
            .attr("priority_a", conflict.priority_a)
            .attr("priority_b", conflict.priority_b)
            .attr("detail", conflict.detail.clone())
            .source(SourceRef::file(conflict.target.clone()))
            .emit();
        emitted += 1;
    }

    if mixin.emit_recommendation_facts() {
        for rec in &scan.recommendations {
            let mut builder = ctx
                .store
                .fact(extractor, kind::MIXIN_RECOMMENDATION)
                .subject(rec.mod_id.clone())
                .attr("mixin", rec.mixin_class.clone())
                .attr("target", rec.target.clone())
                .attr("site_key", rec.site_key.clone())
                .attr("rec_id", rec.recommendation.id.clone())
                .attr("title", rec.recommendation.title.clone())
                .attr("description", rec.recommendation.description.clone())
                .attr("rationale", rec.recommendation.rationale.clone())
                .attr("confidence", f64::from(rec.recommendation.confidence));
            if let Some(example) = &rec.recommendation.example {
                builder = builder.attr("example", example.clone());
            }
            if let Some(url) = &rec.recommendation.doc_url {
                builder = builder.attr("doc_url", url.clone());
            }
            builder.source(SourceRef::file(rec.target.clone())).emit();
            emitted += 1;
        }
    }

    for risk in &scan.risk_assessments {
        ctx.store
            .fact(extractor, kind::MIXIN_RISK_SCORE)
            .subject(risk.subject.clone())
            .attr("score", i64::from(risk.score))
            .attr("certainty", i64::from(risk.certainty))
            .attr("apply_failure", i64::from(risk.apply_failure))
            .attr("semantic_conflict", i64::from(risk.semantic_conflict))
            .attr("blast_radius", i64::from(risk.blast_radius))
            .attr("fragility", i64::from(risk.fragility))
            .attr("actionability", i64::from(risk.actionability))
            .attr("reasons", risk.reasons.join("; "))
            .attr("mods", risk.mods.join(","))
            .attr("hot_path", risk.hot_path)
            .attr("unresolved_points", i64::try_from(risk.unresolved_points).unwrap_or(i64::MAX))
            .source(SourceRef::file(risk.subject.clone()))
            .emit();
        emitted += 1;
    }

    for cc in &scan.class_complexity {
        ctx.store
            .fact(extractor, kind::MIXIN_CLASS_COMPLEXITY)
            .subject(cc.mixin_class.clone())
            .attr("mod_id", cc.mod_id.clone())
            .attr("score", i64::from(cc.score))
            .attr("injection_sites", i64::from(cc.injection_sites))
            .attr("target_count", i64::from(cc.target_count))
            .attr("peak_handler_complexity", i64::from(cc.peak_handler_complexity))
            .attr("components", format_components(&cc.components))
            .source(SourceRef::file(cc.mixin_class.clone()))
            .emit();
        emitted += 1;
    }

    for mc in &scan.mod_complexity {
        ctx.store
            .fact(extractor, kind::MIXIN_MOD_COMPLEXITY)
            .subject(mc.mod_id.clone())
            .attr("score", i64::from(mc.score))
            .attr("class_count", i64::from(mc.class_count))
            .attr("target_count", i64::from(mc.target_count))
            .attr("total_injection_sites", i64::from(mc.total_injection_sites))
            .attr("conflict_edges", i64::from(mc.conflict_edges))
            .attr("peak_class_score", i64::from(mc.peak_class_score))
            .attr("components", format_components(&mc.components))
            .source(SourceRef::file(mc.mod_id.clone()))
            .emit();
        emitted += 1;
    }

    for b in &scan.bloat {
        ctx.store
            .fact(extractor, kind::MIXIN_BLOAT)
            .subject(b.mod_id.clone())
            .attr("score", i64::from(b.score))
            .attr("total_handlers", i64::from(b.total_handlers))
            .attr("inert_handlers", i64::from(b.inert_handlers))
            .attr("effective_handlers", i64::from(b.effective_handlers))
            .attr("inert_instructions", i64::from(b.inert_instructions))
            .attr("total_handler_instructions", i64::from(b.total_handler_instructions))
            .attr("components", format_components(&b.components))
            .source(SourceRef::file(b.mod_id.clone()))
            .emit();
        emitted += 1;
    }

    for af in &scan.apply_failures {
        ctx.store
            .fact(extractor, af.kind.as_str())
            .subject(af.mod_id.clone())
            .attr("mixin", af.mixin.clone())
            .attr("target", af.target.clone())
            .attr("member", af.member.clone())
            .attr("detail", af.detail.clone())
            .attr("confirmed", af.confirmed)
            .source(SourceRef::file(af.mixin.clone()))
            .confidence(if af.confirmed { 0.95 } else { 0.6 })
            .emit();
        emitted += 1;
    }

    emitted
}

/// Render complexity components as a compact, stable `label=points(measure)` list
/// for the fact attribute — keeps the full breakdown inspectable in `--dump-facts`.
fn format_components(components: &[crate::model::ComplexityComponent]) -> String {
    components
        .iter()
        .map(|c| format!("{}={}({})", c.label, c.points, c.measure))
        .collect::<Vec<_>>()
        .join("; ")
}