//! Safer-mixin recommendations from effective effects and interaction patterns.
//!
//! [`recommend_for_scan`] runs after effect modelling and produces
//! [`MixinRecommendationRecord`] rows consumed by fact emission, mixin-map, and rules.
//! Each [`Recommendation`] may include a concrete code snippet and an authoritative
//! documentation link so `--explain` output is immediately actionable.

use std::collections::BTreeMap;

use intermed_doctor_core::facts::kind;
use intermed_doctor_core::RuleCtx;

use crate::model::{
    EffectiveEffectKind, MixinClassRecord, MixinEffect, MixinOperation, MixinRecommendationRecord,
    Recommendation,
};

const MIXIN_INJECT_WIKI: &str =
    "https://github.com/SpongePowered/Mixin/wiki/Injection-Point-Selection";
const MIXIN_OVERWRITE_WIKI: &str = "https://github.com/SpongePowered/Mixin/wiki/Introduction-to-Mixins---The-Overwrite-Annotation";
const MIXIN_REDIRECT_WIKI: &str =
    "https://github.com/SpongePowered/Mixin/wiki/Injection-Point-Selection#redirector";
const MIXINEXTRAS_MODIFY_RETURN: &str =
    "https://github.com/LlamaLad7/MixinExtras/wiki/ModifyReturnValue";
const MIXINEXTRAS_WRAP: &str = "https://github.com/LlamaLad7/MixinExtras/wiki/WrapOperation";

/// Generate recommendations for one mixin effect on a class.
pub fn recommend_for_effect(
    effect: &MixinEffect,
    class: &MixinClassRecord,
    redirect_count_on_method: usize,
) -> Vec<Recommendation> {
    let mut out = Vec::new();

    // @Overwrite is the most fragile mixin form regardless of hot-path status: it
    // replaces the whole method, so every other mixin on it is shut out and any
    // upstream change to the original silently diverges. Always offer the safer
    // composable alternatives; the hot-path case just raises confidence.
    if effect.operation == MixinOperation::Overwrite {
        let (confidence, why) = if effect.hot_path {
            (0.85, " on a hot path — full replacement breaks more often across updates")
        } else {
            (0.65, " — full replacement is the most fragile mixin form across game/mod updates")
        };
        let method_simple = effect.method.split('(').next().unwrap_or(&effect.method);
        out.push(Recommendation {
            id: format!("overwrite-to-inject:{}", effect.site_key),
            title: "Prefer @Inject / @ModifyReturnValue over @Overwrite".into(),
            description: "Replace @Overwrite with a targeted @Inject (HEAD/RETURN + CallbackInfoReturnable) or MixinExtras @ModifyReturnValue / @WrapOperation, so other mixins can still compose with the method instead of being locked out by a full replacement.".into(),
            rationale: format!(
                "`{}` overwrites `{}#{}`{}.",
                effect.mod_id, effect.target, effect.method, why
            ),
            confidence,
            example: Some(format!(
                "@Mixin({target}.class)\npublic class {mixin} {{\n    @Inject(method = \"{method_simple}\", at = @At(\"HEAD\"), cancellable = true)\n    private void intermed$guard({target} self, CallbackInfo ci) {{\n        // narrow change — other mixins can still inject at RETURN\n    }}\n}}\n\n// Or with MixinExtras (composable return rewrite):\n@ModifyReturnValue(method = \"{method_simple}\")\nprivate static boolean intermed$wrap(boolean original) {{\n    return original; // compose with upstream mixins\n}}",
                target = effect.target.rsplit('.').next().unwrap_or(&effect.target),
                mixin = effect.mixin_class.rsplit('.').next().unwrap_or(&effect.mixin_class),
                method_simple = method_simple,
            )),
            doc_url: Some(MIXINEXTRAS_MODIFY_RETURN.to_string()),
        });
    }

    if redirect_count_on_method >= 3
        && matches!(
            effect.operation,
            MixinOperation::Redirect | MixinOperation::WrapOperation
        )
    {
        out.push(Recommendation {
            id: format!("redirect-to-wrap:{}", effect.site_key),
            title: "Consolidate multiple @Redirect handlers".into(),
            description: "Several @Redirect handlers target the same method — consider a single @WrapOperation to reduce ordering surprises.".into(),
            rationale: format!(
                "{redirect_count_on_method} redirect/wrap handler(s) touch `{}#{}`.",
                effect.target, effect.method
            ),
            confidence: 0.75,
            example: Some(
                "@WrapOperation(\n    method = \"tick\",\n    at = @At(value = \"INVOKE\", target = \"Lnet/minecraft/...;method()V\")\n)\nprivate static void intermed$wrap(Operation<?> original) {\n    original.call(); // one wrapper owns ordering\n}"
                    .to_string(),
            ),
            doc_url: Some(MIXINEXTRAS_WRAP.to_string()),
        });
    }

    if effect.operation == MixinOperation::ModifyReturnValue {
        out.push(Recommendation {
            id: format!("mixinextras-return:{}", effect.site_key),
            title: "MixinExtras @ModifyReturnValue — keep composability".into(),
            description: "This site uses MixinExtras return rewriting. Prefer chaining the `original` argument rather than returning a constant so downstream @ModifyReturnValue / @WrapOperation handlers still compose.".into(),
            rationale: format!(
                "`{}` applies @ModifyReturnValue on `{}#{}`.",
                effect.mod_id, effect.target, effect.method
            ),
            confidence: 0.8,
            example: Some(
                "@ModifyReturnValue(method = \"use\")\nprivate static ItemStack intermed$stack(ItemStack original) {\n    return original; // transform `original`, don't discard upstream mixins\n}"
                    .to_string(),
            ),
            doc_url: Some(MIXINEXTRAS_MODIFY_RETURN.to_string()),
        });
    }

    if let Some(handler) = &effect.handler_effect {
        if handler.complexity_score >= 55 {
            out.push(Recommendation {
                id: format!("complex-handler:{}", effect.handler_method),
                title: "Complex handler — expect harder debugging".into(),
                description: "Split logic into a plain helper method on the mixin class so the woven handler stays small and stack traces stay readable.".into(),
                rationale: format!(
                    "Handler `{}` complexity score is {}/100 (branches, target calls, reflection).",
                    effect.handler_method, handler.complexity_score
                ),
                confidence: 0.8,
                example: Some(format!(
                    "@Inject(method = \"{method}\", at = @At(\"HEAD\"))\nprivate void {handler}({target} self, CallbackInfo ci) {{\n    intermed$apply(self); // delegate to a plain helper\n}}\n\nprivate static void intermed$apply({target} self) {{\n    // heavy logic here — easier to breakpoint\n}}",
                    method = effect.method.split('(').next().unwrap_or(&effect.method),
                    handler = effect.handler_method,
                    target = effect.target.rsplit('.').next().unwrap_or(&effect.target),
                )),
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            });
        }
        if handler.cancels && !handler.conditional_control {
            out.push(Recommendation {
                id: format!("unconditional-cancel:{}", effect.site_key),
                title: "Unconditional cancel — likely to break stacked mixins".into(),
                description: "This handler always cancels the target method. Any other mixin injecting later in the method (or at RETURN) will never run. Prefer a guarded cancel (cancel only under the condition you care about) so co-existing mixins still observe the method.".into(),
                rationale: format!(
                    "Dataflow shows `{}` calls CallbackInfo.cancel() on every path{}.",
                    effect.handler_method,
                    if effect.hot_path { " of a hot-path method" } else { "" }
                ),
                confidence: 0.88,
                example: Some(
                    "@Inject(method = \"tick\", at = @At(\"HEAD\"), cancellable = true)\nprivate void intermed$tick(Tickable self, CallbackInfo ci) {\n    if (!shouldSkip(self)) {\n        return; // only cancel when the guard fires\n    }\n    ci.cancel();\n}"
                        .to_string(),
                ),
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            });
        } else if handler.early_return && effect.operation == MixinOperation::Inject {
            out.push(Recommendation {
                id: format!("early-return:{}", effect.site_key),
                title: "Document CallbackInfo early-exit paths".into(),
                description: "This inject conditionally cancels / sets a return value — document when the target method is short-circuited so compat layers know ordering matters.".into(),
                rationale: "Early return via CallbackInfo changes observable method behaviour for downstream mixins.".into(),
                confidence: 0.74,
                example: Some(
                    "// Document: RETURN injects from other mods won't run when ci.cancel() fires at HEAD.\n@Inject(method = \"render\", at = @At(\"HEAD\"), cancellable = true)\nprivate void intermed$render(..., CallbackInfo ci) { /* ... */ }"
                        .to_string(),
                ),
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            });
        }
        if handler.sets_return_value
            && handler.return_value_source == crate::model::ValueSource::Constant
        {
            out.push(Recommendation {
                id: format!("constant-return:{}", effect.site_key),
                title: "Return value replaced by a constant".into(),
                description: "This handler forces a constant return value. Mixins that wrap or read the original result will see the constant instead — confirm that is intended and consider @ModifyReturnValue (MixinExtras) so other handlers can still compose.".into(),
                rationale: format!(
                    "Dataflow proved `{}` feeds a compile-time constant to setReturnValue.",
                    effect.handler_method
                ),
                confidence: 0.82,
                example: Some(
                    "@ModifyReturnValue(method = \"isEnabled\")\nprivate static boolean intermed$enabled(boolean original) {\n    return original && MY_FLAG; // preserve upstream mixins\n}"
                        .to_string(),
                ),
                doc_url: Some(MIXINEXTRAS_MODIFY_RETURN.to_string()),
            });
        }
        if handler.writes_target_state {
            out.push(Recommendation {
                id: format!("target-state-write:{}", effect.site_key),
                title: "Handler mutates target fields".into(),
                description: "This handler writes into the target's own fields. Order against other state-touching mixins is observable; keep the write minimal and document the invariant it maintains.".into(),
                rationale: format!(
                    "Dataflow recorded a PUTFIELD into target state from `{}`.",
                    effect.handler_method
                ),
                confidence: 0.72,
                example: Some(
                    "@Shadow @Final private SomeType intermed$field;\n// Prefer @Accessor + small helper over ad-hoc PUTFIELD in a large handler."
                        .to_string(),
                ),
                doc_url: Some(MIXIN_OVERWRITE_WIKI.to_string()),
            });
        }
        // ── deepened dataflow side-effect recommendations ──
        use crate::model::HandlerSideEffect as SE;
        if handler.side_effects.contains(&SE::WorldMutation) && effect.hot_path {
            out.push(Recommendation {
                id: format!("hot-world-mutation:{}", effect.site_key),
                title: "World mutation inside a hot-path injection".into(),
                description: "This handler calls a world/level mutation API on a hot path. Block updates and entity spawns from inside a frequently-called woven method are a common TPS sink and ordering hazard — move the mutation behind a guard or schedule it once.".into(),
                rationale: format!(
                    "Dataflow saw a world-mutation call in `{}` on hot-path `{}`.",
                    effect.handler_method, effect.target
                ),
                confidence: 0.8,
                example: None,
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            });
        }
        if handler.side_effects.contains(&SE::AsyncScheduling) {
            out.push(Recommendation {
                id: format!("async-from-woven:{}", effect.site_key),
                title: "Async work scheduled from a woven method".into(),
                description: "This handler submits async / background work. Capturing target state into another thread from inside a mixin is a frequent source of races and crashes — confirm thread-safety and that the captured state is stable.".into(),
                rationale: format!("Dataflow saw an executor/future call in `{}`.", effect.handler_method),
                confidence: 0.72,
                example: None,
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            });
        }
        if handler.side_effects.contains(&SE::GlobalStateWrite) {
            out.push(Recommendation {
                id: format!("global-state-write:{}", effect.site_key),
                title: "Handler writes global static state".into(),
                description: "This handler writes a static field outside the target. Global mutation from a woven method is order-sensitive across mods and can leak across world reloads — prefer instance state or a documented, idempotent write.".into(),
                rationale: format!("Dataflow recorded a PUTSTATIC outside the target from `{}`.", effect.handler_method),
                confidence: 0.7,
                example: None,
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            });
        }
        if handler.side_effects.contains(&SE::HeavyAllocation) && effect.hot_path {
            out.push(Recommendation {
                id: format!("hot-allocation:{}", effect.site_key),
                title: "Allocation-heavy handler on a hot path".into(),
                description: "This hot-path handler allocates several objects per call. Reuse buffers or hoist allocations out of the woven method to avoid GC pressure on the tick loop.".into(),
                rationale: format!("Multiple allocations in hot-path handler `{}`.", effect.handler_method),
                confidence: 0.65,
                example: None,
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            });
        }
    }

    if effect
        .effect_kinds
        .contains(&EffectiveEffectKind::FullMethodReplacement)
        && class.operations.len() > 1
    {
        out.push(Recommendation {
            id: format!("narrow-overwrite:{}", effect.site_key),
            title: "Narrow overwrite scope".into(),
            description: "This mixin also uses non-overwrite operations — keep @Overwrite limited to one method to reduce interaction surface.".into(),
            rationale: "Mixins combining @Overwrite with inject/redirect multiply conflict vectors.".into(),
            confidence: 0.68,
            example: None,
            doc_url: Some(MIXIN_OVERWRITE_WIKI.to_string()),
        });
    }

    if effect.operation == MixinOperation::Redirect && redirect_count_on_method == 1 {
        out.push(Recommendation {
            id: format!("redirect-doc:{}", effect.site_key),
            title: "@Redirect — verify target signature stability".into(),
            description: "A @Redirect pins an exact call descriptor. Game or dependency updates that rename/move the callee will fail at apply time — keep the redirect narrow and add a refmap entry.".into(),
            rationale: format!(
                "`{}` redirects a call in `{}#{}`.",
                effect.mod_id, effect.target, effect.method
            ),
            confidence: 0.7,
            example: None,
            doc_url: Some(MIXIN_REDIRECT_WIKI.to_string()),
        });
    }

    out
}

/// Count @Redirect / @WrapOperation handlers per (target, method) across a modpack scan.
pub fn redirect_counts_by_method(classes: &[MixinClassRecord]) -> BTreeMap<(String, String), usize> {
    let mut counts = BTreeMap::new();
    for class in classes {
        for inj in &class.injected_methods {
            if inj.injection_type == MixinOperation::Redirect.as_str()
                || inj.injection_type == MixinOperation::WrapOperation.as_str()
            {
                let key = (inj.target.clone(), inj.resolved.clone());
                *counts.entry(key).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Build scan-level recommendation records for every mixin effect, plus
/// conflict-taxonomy and apply-failure advice.
pub fn recommend_for_scan(
    classes: &[MixinClassRecord],
    effects: &[MixinEffect],
    conflict_edges: &[crate::model::MixinConflictEdgeRecord],
    apply_failures: &[crate::apply_failure::ApplyFailure],
) -> Vec<MixinRecommendationRecord> {
    let redirect_counts = redirect_counts_by_method(classes);
    let class_by_name: BTreeMap<_, _> = classes
        .iter()
        .map(|c| (c.class_name.as_str(), c))
        .collect();
    let mut out = Vec::new();

    for effect in effects {
        let Some(class) = class_by_name.get(effect.mixin_class.as_str()) else {
            continue;
        };
        let redirect_count = redirect_counts
            .get(&(effect.target.clone(), effect.method.clone()))
            .copied()
            .unwrap_or(0);
        for rec in recommend_for_effect(effect, class, redirect_count) {
            out.push(MixinRecommendationRecord {
                mod_id: effect.mod_id.clone(),
                mixin_class: effect.mixin_class.clone(),
                target: effect.target.clone(),
                site_key: effect.site_key.clone(),
                recommendation: rec,
            });
        }
    }
    out.extend(recommend_for_conflicts(conflict_edges));
    out.extend(recommend_for_apply_failures(apply_failures));
    out
}

/// Conflict-taxonomy recommendations (5.4): targeted advice for the precise edge
/// types — who should change what so two mods can coexist.
pub fn recommend_for_conflicts(
    conflict_edges: &[crate::model::MixinConflictEdgeRecord],
) -> Vec<MixinRecommendationRecord> {
    use crate::model::ConflictEdgeType as E;
    let mut out = Vec::new();
    for edge in conflict_edges {
        let rec = match edge.edge_type {
            E::OverwriteVsInjector => Some(Recommendation {
                id: format!("overwrite-locks-out:{}:{}", edge.source_mixin, edge.site),
                title: "@Overwrite locks out another mod's injectors".into(),
                description: format!(
                    "`{}` @Overwrites a method that `{}` injects into — the overwrite replaces the \
                     whole body, so the other mod's hooks silently stop applying. Convert the \
                     @Overwrite to @Inject / @ModifyReturnValue / @WrapOperation so both survive.",
                    edge.source_mod, edge.target_mod
                ),
                rationale: format!("Overwrite vs injector on `{}` ({}).", edge.target_class, edge.site),
                confidence: 0.85,
                example: None,
                doc_url: Some(MIXINEXTRAS_MODIFY_RETURN.to_string()),
            }),
            E::CancellableHeadVsReturn => Some(Recommendation {
                id: format!("cancel-head-vs-return:{}:{}", edge.source_mixin, edge.site),
                title: "Cancellable HEAD can starve a RETURN injector".into(),
                description: format!(
                    "`{}` cancels at HEAD on a method `{}` injects at RETURN; when the HEAD cancel \
                     fires the RETURN handler never runs. Guard the cancel narrowly, or coordinate \
                     priorities so the RETURN injector still observes the method.",
                    edge.source_mod, edge.target_mod
                ),
                rationale: format!("Cancellable HEAD vs RETURN on `{}`.", edge.target_class),
                confidence: 0.75,
                example: None,
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            }),
            E::RedirectVsWrapOperation => Some(Recommendation {
                id: format!("redirect-vs-wrap:{}:{}", edge.source_mixin, edge.site),
                title: "@Redirect and @WrapOperation fight for one call".into(),
                description: format!(
                    "`{}` and `{}` both seize the same call site; only one can own it. Prefer \
                     @WrapOperation on both sides (composable) and order by priority.",
                    edge.source_mod, edge.target_mod
                ),
                rationale: format!("Redirect vs WrapOperation on `{}` ({}).", edge.target_class, edge.site),
                confidence: 0.78,
                example: None,
                doc_url: Some(MIXINEXTRAS_WRAP.to_string()),
            }),
            E::WrapConditionSuppressesCall => Some(Recommendation {
                id: format!("wrapcond-suppresses:{}:{}", edge.source_mixin, edge.site),
                title: "@WrapWithCondition can suppress another mod's hook".into(),
                description: format!(
                    "`{}`'s @WrapWithCondition may skip the call `{}` hooks; when the condition is \
                     false the wrapped call (and the other mod's redirect/inject on it) never runs. \
                     Confirm the condition is intended to gate the other mod too.",
                    edge.source_mod, edge.target_mod
                ),
                rationale: format!("WrapWithCondition suppresses a call on `{}`.", edge.target_class),
                confidence: 0.7,
                example: None,
                doc_url: Some(MIXINEXTRAS_WRAP.to_string()),
            }),
            E::UniqueMemberConflict => Some(Recommendation {
                id: format!("unique-member:{}:{}", edge.source_mixin, edge.site),
                title: "Add @Unique to collision-prone added members".into(),
                description: format!(
                    "`{}` and `{}` add a member of the same name to `{}` without @Unique, so they \
                     collide. Mark added members @Unique (or prefix with your mod id) to prevent the clash.",
                    edge.source_mod, edge.target_mod, edge.target_class
                ),
                rationale: format!("Unique-less member collision on `{}` ({}).", edge.target_class, edge.site),
                confidence: 0.8,
                example: Some(
                    "@Unique\nprivate int myMod$counter; // unique-prefixed and @Unique-marked"
                        .to_string(),
                ),
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            }),
            _ => None,
        };
        if let Some(rec) = rec {
            out.push(MixinRecommendationRecord {
                mod_id: edge.source_mod.clone(),
                mixin_class: edge.source_mixin.clone(),
                target: edge.target_class.clone(),
                site_key: edge.site.clone(),
                recommendation: rec,
            });
        }
    }
    out
}

/// Apply-failure recommendations (5.3): how to make a non-applying mixin apply.
pub fn recommend_for_apply_failures(
    apply_failures: &[crate::apply_failure::ApplyFailure],
) -> Vec<MixinRecommendationRecord> {
    use crate::apply_failure::ApplyFailureKind as K;
    let mut out = Vec::new();
    for af in apply_failures {
        let (title, description) = match af.kind {
            K::RefmapMissing => (
                "Ship a refmap for named Minecraft targets",
                "This mixin targets named Minecraft classes but no refmap is present, so its \
                 references will not resolve to the runtime (intermediary) namespace. Ensure the \
                 mixin annotation processor runs and the refmap is bundled.",
            ),
            K::RemapFalseSuspicious => (
                "Review remap = false on a Minecraft target",
                "remap = false uses the reference unmapped; on a Minecraft target it only works if \
                 the name is already in the runtime namespace. Remove remap = false unless you are \
                 deliberately referencing an intermediary/runtime name.",
            ),
            K::TargetMethodMissing | K::RequireUnsatisfied => (
                "Target method not found — rebuild against this version",
                "The target method does not exist on the installed target class. Rebuild the mixin \
                 against the correct Minecraft/mod version, or fix the method reference/mappings.",
            ),
            K::TargetClassMissing => (
                "Target class not found",
                "The target class is absent from the indexed jar. Verify the dependency is present \
                 at the expected version.",
            ),
            K::DescriptorMismatch => (
                "@Shadow descriptor disagrees with the target",
                "The @Shadow member's declared type does not match the target. Align the descriptor \
                 with the installed version's field/method signature.",
            ),
            K::OrdinalOutOfRange => (
                "@At(ordinal) exceeds the available call sites",
                "The requested ordinal selects a call site that does not exist in the target \
                 method for this version. Lower the ordinal or use a more specific @At target/slice.",
            ),
        };
        out.push(MixinRecommendationRecord {
            mod_id: af.mod_id.clone(),
            mixin_class: af.mixin.clone(),
            target: af.target.clone(),
            site_key: format!("apply:{}", af.member),
            recommendation: Recommendation {
                id: format!("apply-fix:{}:{}:{}", af.kind.as_str(), af.mixin, af.member),
                title: title.to_string(),
                description: description.to_string(),
                rationale: af.detail.clone(),
                confidence: if af.confirmed { 0.9 } else { 0.6 },
                example: None,
                doc_url: Some(MIXIN_INJECT_WIKI.to_string()),
            },
        });
    }
    out
}

/// Group recommendations by `site_key` for rule / explain lookup.
pub fn recommendations_by_site(
    records: &[MixinRecommendationRecord],
) -> BTreeMap<String, Vec<Recommendation>> {
    let mut out: BTreeMap<String, Vec<Recommendation>> = BTreeMap::new();
    for row in records {
        out
            .entry(row.site_key.clone())
            .or_default()
            .push(row.recommendation.clone());
    }
    out
}

/// Historical runtime correlation boost when log facts report similar patterns.
pub fn historical_severity_boost(ctx: &RuleCtx<'_>, effect: &MixinEffect) -> u8 {
    let pattern = effect.operation.as_str();
    let mut boost = 0u8;
    for f in ctx.store.by_kind(kind::LOG_MIXIN_CORRELATION) {
        let same_target = f.attr("target").is_some_and(|t| t == effect.target);
        let same_op = f.attr("operation").is_some_and(|o| o == pattern);
        if same_target && same_op {
            boost = boost.saturating_add(12);
        } else if same_target {
            boost = boost.saturating_add(5);
        }
    }
    // Layer-I Spark hot-method correlation on the same target class.
    for f in ctx.store.by_kind(kind::HOT_METHOD) {
        let class = f.attr("class").unwrap_or(&f.subject);
        if class == effect.target.as_str() || class.rsplit('.').next() == effect.target.rsplit('.').next()
        {
            let percent = f.attr_f64("percent").unwrap_or(0.0);
            if percent >= 5.0 {
                boost = boost.saturating_add(if percent >= 25.0 { 10 } else { 5 });
            }
        }
    }
    boost.min(25)
}

/// Format recommendations for plain-text reports and `--explain` appendices.
pub fn format_recommendations(recs: &[Recommendation]) -> String {
    if recs.is_empty() {
        return String::new();
    }
    let mut lines = Vec::from(["Recommendations:".to_string()]);
    for rec in recs {
        lines.push(format!("  • {} — {}", rec.title, rec.description));
        if !rec.rationale.is_empty() {
            lines.push(format!("    ({})", rec.rationale));
        }
        if let Some(url) = &rec.doc_url {
            lines.push(format!("    Docs: {url}"));
        }
        if let Some(example) = &rec.example {
            lines.push("    Example:".to_string());
            for line in example.lines() {
                lines.push(format!("      {line}"));
            }
        }
    }
    lines.join("\n")
}

/// Map a [`Recommendation`] to doctor fix-candidate text and confidence.
pub fn recommendation_as_fix(rec: &Recommendation) -> (String, f32) {
    let mut text = format!("{}: {}", rec.title, rec.description);
    if let Some(url) = &rec.doc_url {
        text.push_str(&format!(" See {url}."));
    }
    (text, rec.confidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HandlerEffect, HandlerSideEffect};

    fn sample_class(ops: Vec<MixinOperation>, hot: bool) -> MixinClassRecord {
        MixinClassRecord {
            archive: "a.jar".into(),
            mod_id: "alpha".into(),
            config: "m.json".into(),
            class_name: "alpha.Mixin".into(),
            class_path: "a.class".into(),
            targets: vec!["T".into()],
            target_namespace: Default::default(),
            operations: ops,
            injected_methods: Vec::new(),
            shadows: Vec::new(),
            added_members: Vec::new(),
            calls: Vec::new(),
            handler_bodies: Vec::new(),
            target_hierarchy: Vec::new(),
            priority: 1000,
            refmap: None,
            hot_paths: if hot { vec!["tick".into()] } else { Vec::new() },
            effects: Vec::new(),
            plugin_gated: false,
        }
    }

    fn sample_effect(op: MixinOperation, hot: bool) -> MixinEffect {
        MixinEffect {
            mod_id: "alpha".into(),
            mixin_class: "alpha.Mixin".into(),
            target: "T".into(),
            method: "tick()V".into(),
            handler_method: "handler".into(),
            operation: op,
            effect_kinds: vec![EffectiveEffectKind::FullMethodReplacement],
            effect_description: "effect".into(),
            handler_effect: Some(HandlerEffect {
                handler_method: "handler".into(),
                handler_local_store: false,
                modifies_return: false,
                early_return: true,
                side_effects: vec![HandlerSideEffect::CallbackControl],
                complexity_score: 60,
                cancels: false,
                sets_return_value: false,
                conditional_control: false,
                return_value_source: crate::model::ValueSource::Unknown,
                writes_target_state: false,
                original_call_count: 0,
            }),
            hot_path: hot,
            site_key: "tick()V@HEAD".into(),
            at_target: "HEAD".into(),
        }
    }

    #[test]
    fn overwrite_hot_path_gets_inject_advice_with_example() {
        let class = sample_class(vec![MixinOperation::Overwrite], true);
        let effect = sample_effect(MixinOperation::Overwrite, true);
        let recs = recommend_for_effect(&effect, &class, 0);
        let rec = recs.iter().find(|r| r.title.contains("@Inject")).expect("inject advice");
        assert!(rec.example.as_ref().is_some_and(|e| e.contains("@Inject")));
        assert!(rec.doc_url.is_some());
    }

    #[test]
    fn redirect_storm_suggests_wrap_operation() {
        let class = sample_class(vec![MixinOperation::Redirect], false);
        let effect = sample_effect(MixinOperation::Redirect, false);
        let recs = recommend_for_effect(&effect, &class, 4);
        assert!(recs.iter().any(|r| r.id.starts_with("redirect-to-wrap:")));
    }

    #[test]
    fn recommend_for_scan_emits_bound_records() {
        let class = sample_class(vec![MixinOperation::Overwrite], true);
        let effect = sample_effect(MixinOperation::Overwrite, true);
        let rows = recommend_for_scan(&[class], &[effect], &[], &[]);
        assert!(!rows.is_empty());
        assert_eq!(rows[0].mod_id, "alpha");
        assert_eq!(rows[0].site_key, "tick()V@HEAD");
    }

    #[test]
    fn conflict_recommendations_cover_overwrite_and_unique() {
        use crate::model::{ConflictEdgeType, MixinConflictEdgeRecord};
        let edge = |t: ConflictEdgeType| MixinConflictEdgeRecord {
            id: "e1".into(),
            edge_type: t,
            source_mod: "a".into(),
            target_mod: "b".into(),
            source_mixin: "a.Mixin".into(),
            target_mixin: "b.Mixin".into(),
            target_class: "net.minecraft.Foo".into(),
            site: "tick()V".into(),
            strength: 90,
        };
        let recs = recommend_for_conflicts(&[
            edge(ConflictEdgeType::OverwriteVsInjector),
            edge(ConflictEdgeType::UniqueMemberConflict),
        ]);
        assert!(recs.iter().any(|r| r.recommendation.id.starts_with("overwrite-locks-out")));
        assert!(recs.iter().any(|r| r.recommendation.id.starts_with("unique-member")));
    }

    #[test]
    fn apply_failure_recommendations_are_produced() {
        use crate::apply_failure::{ApplyFailure, ApplyFailureKind};
        let af = ApplyFailure {
            kind: ApplyFailureKind::OrdinalOutOfRange,
            mod_id: "a".into(),
            mixin: "a.Mixin".into(),
            target: "net.minecraft.Foo".into(),
            member: "bar#3".into(),
            detail: "ordinal 3 of 2".into(),
            confirmed: true,
        };
        let recs = recommend_for_apply_failures(&[af]);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].recommendation.title.contains("ordinal"));
        assert!(recs[0].recommendation.confidence >= 0.85);
    }

    #[test]
    fn recommendations_by_site_groups_rows() {
        let rows = recommend_for_scan(
            &[sample_class(vec![MixinOperation::Overwrite], true)],
            &[sample_effect(MixinOperation::Overwrite, true)],
            &[],
            &[],
        );
        let grouped = recommendations_by_site(&rows);
        assert!(grouped.contains_key("tick()V@HEAD"));
    }

    #[test]
    fn historical_boost_elevates_matching_target_and_operation() {
        use intermed_doctor_core::facts::FactStore;
        use intermed_doctor_core::{RuleCtx, Target, TargetKind};

        let mut store = FactStore::new();
        store
            .fact("log-analyzer", kind::LOG_MIXIN_CORRELATION)
            .subject("crash")
            .attr("target", "net.minecraft.server.MinecraftServer")
            .attr("operation", "overwrite")
            .emit();

        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        let mut effect = sample_effect(MixinOperation::Overwrite, true);
        effect.target = "net.minecraft.server.MinecraftServer".into();
        assert_eq!(historical_severity_boost(&ctx, &effect), 12);
    }

    #[test]
    fn spark_hot_method_adds_historical_boost() {
        use intermed_doctor_core::facts::FactStore;
        use intermed_doctor_core::{RuleCtx, Target, TargetKind};

        let mut store = FactStore::new();
        store
            .fact("spark-importer", kind::HOT_METHOD)
            .subject("net.minecraft.client.render.WorldRenderer")
            .attr("class", "net.minecraft.client.render.WorldRenderer")
            .attr("method", "render")
            .attr("percent", 30.0f64)
            .emit();
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        let mut effect = sample_effect(MixinOperation::Inject, true);
        effect.target = "net.minecraft.client.render.WorldRenderer".into();
        assert!(historical_severity_boost(&ctx, &effect) >= 10);
    }

    #[test]
    fn redirect_counts_aggregate_per_method() {
        use crate::model::ResolvedInjectionPoint;
        let mut class = sample_class(vec![MixinOperation::Redirect], false);
        class.injected_methods = vec![
            ResolvedInjectionPoint {
                target: "T".into(),
                original: "tick()V".into(),
                resolved: "tick()V".into(),
                canonical: "tick()V".into(),
                site_key: "a".into(),
                namespace: crate::refmap::Namespace::Named,
                injection_type: "redirect".into(),
                resolved_via_refmap: false,
                handler_method: "h1".into(),
                handler_descriptor: String::new(),
                mutates_target_local: false,
                at_target: "INVOKE".into(),
                at_detail: String::new(),
                impact: "call-replace".into(),
                local_index: None,
                local_capture: String::new(),
                meta: Default::default(),
                at_ordinal: None,
                at_target_member: String::new(),
            },
            ResolvedInjectionPoint {
                target: "T".into(),
                original: "tick()V".into(),
                resolved: "tick()V".into(),
                canonical: "tick()V".into(),
                site_key: "b".into(),
                namespace: crate::refmap::Namespace::Named,
                injection_type: "redirect".into(),
                resolved_via_refmap: false,
                handler_method: "h2".into(),
                handler_descriptor: String::new(),
                mutates_target_local: false,
                at_target: "INVOKE".into(),
                at_detail: String::new(),
                impact: "call-replace".into(),
                local_index: None,
                local_capture: String::new(),
                meta: Default::default(),
                at_ordinal: None,
                at_target_member: String::new(),
            },
        ];
        let counts = redirect_counts_by_method(&[class]);
        assert_eq!(counts.get(&("T".into(), "tick()V".into())).copied(), Some(2));
    }
}