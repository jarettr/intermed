//! Mixin risk rule — composite scoring with Spark cross-layer integration.
//!
//! Emits composite risk findings, per-injection [`mixin_effect_summary`] notes, and
//! attaches safer-mixin recommendations to `--explain` via `fix_candidates`.

use intermed_doctor_core::evidence::{
    Category, EvidenceEdge, Finding, FixCandidate, Relation, Severity,
};
use intermed_doctor_core::facts::{kind, FactId};
use intermed_doctor_core::RuleCtx;

use crate::model::{
    EffectiveEffectKind, HandlerEffect, HandlerSideEffect, MixinOperation, Recommendation,
};
use crate::recommendation::{
    format_recommendations, historical_severity_boost, recommendation_as_fix,
    recommendations_by_site,
};

const RULE_ID: &str = "mixin-risk";

pub struct MixinRiskRule;

impl intermed_doctor_core::Rule for MixinRiskRule {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        let hot_methods = collect_hot_methods(ctx);

        for f in ctx.store.by_kind(kind::MIXIN_RISK_SCORE) {
            let score = u8::try_from(f.attr_int("score").unwrap_or(0).clamp(0, 100)).unwrap_or(0);
            let mods = split_attr(f.attr("mods"));
            let hot_path = f.attr_bool("hot_path").unwrap_or(false);
            let reasons = f.attr("reasons").unwrap_or("").to_string();
            let (named, inter) = target_aliases(ctx, &f.subject);
            let (spark_boost, spark_quality) = spark_overlap_boost(
                &hot_methods,
                &f.subject,
                named.as_deref(),
                inter.as_deref(),
            );
            let adjusted = score.saturating_add(spark_boost).min(100);
            let severity = risk_severity(adjusted);

            // Risk (severity) and confidence are different axes. Severity is "how
            // bad if true"; confidence is "how sure we are the site resolved".
            // A high-risk redirect with unresolved mappings is high severity but
            // LOW confidence — never the risk-score-as-confidence the old code used.
            let unresolved = f.attr_int("unresolved_points").unwrap_or(0).max(0);
            let intermediary_known = inter.is_some();
            let mut confidence = resolution_confidence(unresolved, intermediary_known);
            // A Spark correlation by simple class name only is weak evidence — cap
            // confidence so the "hot method" claim reads as *possible*, not proven.
            let weak_spark = spark_boost > 0 && spark_quality == Some(MatchQuality::SimpleName);
            if weak_spark {
                confidence = confidence.min(0.5);
            }

            let mut explanation = format!("Mixin risk {adjusted}/100 for {}.", f.subject);
            if !reasons.is_empty() {
                explanation.push_str(&format!(" Reasons: {reasons}."));
            }
            if spark_boost > 0 {
                let (named, inter) = target_aliases(ctx, &f.subject);
                let hot_names: Vec<&str> = hot_methods_for_class(
                    &hot_methods,
                    &f.subject,
                    named.as_deref(),
                    inter.as_deref(),
                )
                    .iter()
                    .filter(|hm| hm.percent >= 5.0)
                    .map(|hm| hm.method.as_str())
                    .collect();
                let qualifier = if weak_spark {
                    " (matched by class name only — possible, not confirmed)"
                } else {
                    ""
                };
                if hot_names.is_empty() {
                    explanation.push_str(&format!(
                        " Spark profile shows hot methods on this class{qualifier} — risk elevated.",
                    ));
                } else {
                    explanation.push_str(&format!(
                        " Spark profile hot method(s) on this class: {}{qualifier} — risk elevated.",
                        hot_names.join(", ")
                    ));
                }
            }
            if mods.len() > 1 {
                explanation.push_str(&format!(" Overlapping mods: {}.", mods.join(", ")));
            }
            if unresolved > 0 || !intermediary_known {
                explanation.push_str(&format!(
                    " Resolution confidence {:.0}% — {}.",
                    confidence * 100.0,
                    if unresolved > 0 {
                        format!("{unresolved} injection point(s) could not be fully resolved")
                    } else {
                        "target could not be canonicalized to intermediary".to_string()
                    }
                ));
            }

            // Layer B → Layer F context: what the involved mods actually do. A mixin
            // risk on a render class reads very differently when the mod is known to
            // `modifies_rendering` + is `performance_oriented`.
            let capabilities = capability_context(ctx, &mods);
            if !capabilities.is_empty() {
                let summary = capabilities
                    .iter()
                    .map(|(mod_id, caps, _)| format!("{mod_id} → {}", caps.join(", ")))
                    .collect::<Vec<_>>()
                    .join("; ");
                explanation.push_str(&format!(" Involved mod capabilities: {summary}."));
            }

            let mut builder = Finding::builder(RULE_ID, format!("mixin-risk:{}", f.subject))
                .severity(severity)
                .category(Category::Mixin)
                .title(format!("Mixin risk {adjusted}/100: {}", f.subject))
                .explanation(explanation)
                .evidence(EvidenceEdge::subject(f.id))
                .affects(f.subject.clone())
                .fix(FixCandidate::advice(risk_advice(adjusted, hot_path)))
                .tag("mixin")
                .tag("risk-score")
                .confidence(confidence);
            if confidence < 0.6 {
                builder = builder.tag("low-resolution-confidence");
            }

            for target in ctx.store.by_kind(kind::MIXIN_TARGET) {
                if target.attr("target") == Some(f.subject.as_str()) {
                    builder = builder.evidence(EvidenceEdge::new(target.id, Relation::Supports, 0.8));
                }
            }
            for edge in ctx.store.by_kind(kind::MIXIN_CONFLICT_EDGE) {
                if edge.attr("target_class") == Some(f.subject.as_str()) {
                    builder =
                        builder.evidence(EvidenceEdge::new(edge.id, Relation::ConflictsWith, 0.85));
                }
            }
            let (named, inter) = target_aliases(ctx, &f.subject);
            for hm in hot_methods_for_class(
                &hot_methods,
                &f.subject,
                named.as_deref(),
                inter.as_deref(),
            ) {
                builder = builder
                    .evidence(EvidenceEdge::new(hm.fact_id, Relation::CorrelatesWith, 0.9))
                    .tag("hot-path");
            }
            for (_, _, fact_ids) in &capabilities {
                for id in fact_ids {
                    builder =
                        builder.evidence(EvidenceEdge::new(*id, Relation::CorrelatesWith, 0.6));
                }
            }
            out.push(builder.build());
        }

        // Legacy overlap facts when risk scores are absent (cached older scans).
        if out.is_empty() {
            out.extend(legacy_overlap_findings(ctx));
            out.extend(legacy_overwrite_findings(ctx));
        }

        if ctx.settings.mixin.effect_summary_findings() {
            out.extend(mixin_effect_summary_findings(ctx));
        }
        out.extend(enhanced_overwrite_findings(ctx));
        if ctx.settings.mixin.handler_intelligence_findings() {
            out.extend(handler_intelligence_findings(ctx));
        }
        out.extend(mod_complexity_findings(ctx));
        out.extend(mixin_bloat_findings(ctx));
        out.extend(mixin_plugin_findings(ctx));
        out.extend(apply_failure_findings(ctx));

        for f in ctx.store.by_kind(kind::MIXIN_INTERACTION) {
            let strength = f.attr_int("strength").unwrap_or(50) as u8;
            if strength < 70 {
                continue;
            }
            let detail = f.attr("detail").unwrap_or("mixin interaction");
            let target = f.attr("target").unwrap_or(&f.subject);
            out.push(
                Finding::builder(RULE_ID, format!("mixin-interaction:{}", f.subject))
                    .severity(if strength >= 90 {
                        Severity::Warn
                    } else {
                        Severity::Note
                    })
                    .category(Category::Mixin)
                    .title(format!("Mixin interaction on {target}"))
                    .explanation(detail.to_string())
                    .evidence(EvidenceEdge::subject(f.id))
                    .affects(target)
                    .fix(FixCandidate::advice(
                        "Review mod load order, mixin priority, and compatibility notes for these mods.",
                    ))
                    .tag("mixin")
                    .tag("interaction")
                    .confidence(f32::from(strength) / 100.0)
                    .build(),
            );
        }

        out
    }
}

/// Surface the mods with the heaviest mixin footprint as an informational note.
///
/// The Mixin Complexity Score is a measurement, not a defect, so this stays at
/// `Note` severity and only fires above a high threshold — it is a "this mod
/// touches a lot, review it first" signal for adoption, with the full transparent
/// component breakdown carried in the explanation.
fn mod_complexity_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    const COMPLEXITY_NOTE_THRESHOLD: i64 = 80;
    let mut out = Vec::new();
    for f in ctx.store.by_kind(kind::MIXIN_MOD_COMPLEXITY) {
        let score = f.attr_int("score").unwrap_or(0);
        if score < COMPLEXITY_NOTE_THRESHOLD {
            continue;
        }
        let class_count = f.attr_int("class_count").unwrap_or(0);
        let target_count = f.attr_int("target_count").unwrap_or(0);
        let components = f.attr("components").unwrap_or("");
        out.push(
            Finding::builder(RULE_ID, format!("mixin-complexity:{}", f.subject))
                .severity(Severity::Note)
                .category(Category::Mixin)
                .title(format!(
                    "High mixin complexity in `{}` (score {score}/100)",
                    f.subject
                ))
                .explanation(format!(
                    "`{}` weaves {class_count} mixin class(es) across {target_count} target class(es). \
                     Complexity breakdown: {components}. A high score means a larger blast radius \
                     under refactors and load-order changes — review this mod first when triaging \
                     mixin conflicts.",
                    f.subject
                ))
                .evidence(EvidenceEdge::subject(f.id))
                .affects(f.subject.clone())
                .fix(FixCandidate::advice(
                    "Review whether this mod's mixins can be narrowed (fewer targets / @Overwrite \
                     replaced with @Inject), and prioritize it when checking compatibility.",
                ))
                .tag("mixin")
                .tag("complexity")
                .confidence(f32::from(u8::try_from(score.clamp(0, 100)).unwrap_or(0)) / 100.0)
                .build(),
        );
    }
    out
}

/// Surface mods whose mixins weave a lot of bytecode that provably does nothing
/// observable to their targets (inert handlers). Informational `Note` — a
/// review/cleanup signal, not a defect — gated so tiny or marginal cases stay quiet.
fn mixin_bloat_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    const BLOAT_NOTE_THRESHOLD: i64 = 50;
    const MIN_INERT_HANDLERS: i64 = 3;
    let mut out = Vec::new();
    for f in ctx.store.by_kind(kind::MIXIN_BLOAT) {
        let score = f.attr_int("score").unwrap_or(0);
        let inert = f.attr_int("inert_handlers").unwrap_or(0);
        if score < BLOAT_NOTE_THRESHOLD || inert < MIN_INERT_HANDLERS {
            continue;
        }
        let total = f.attr_int("total_handlers").unwrap_or(0);
        let inert_instructions = f.attr_int("inert_instructions").unwrap_or(0);
        out.push(
            Finding::builder(RULE_ID, format!("mixin-bloat:{}", f.subject))
                .severity(Severity::Note)
                .category(Category::Mixin)
                .title(format!(
                    "Low-yield mixin footprint in `{}` ({inert}/{total} handlers inert)",
                    f.subject
                ))
                .explanation(format!(
                    "{inert} of `{}`'s {total} mixin handler(s) (~{inert_instructions} instructions) \
                     have no *target-visible* effect detected — no return change, no \
                     cancel/CallbackInfo control, no target field or method access, no reflection. \
                     Static analysis cannot see effects on non-target state (global registries, \
                     loggers, other mods' APIs), so this is a hint to review, not proof a handler \
                     is dead. Review whether these handlers are still needed.",
                    f.subject
                ))
                .evidence(EvidenceEdge::subject(f.id))
                .affects(f.subject.clone())
                .fix(FixCandidate::advice(
                    "Review handlers with no target-visible effect; if they also have no external \
                     side effect they can be removed or narrowed, as dead @Inject handlers still \
                     cost weave time and obscure real conflicts.",
                ))
                .tag("mixin")
                .tag("bloat")
                // Confidence is evidence quality, not the bloat magnitude (that is
                // the score/severity): static analysis can't observe non-target
                // side effects, so this stays deliberately moderate.
                .confidence(0.6)
                .build(),
        );
    }
    out
}

struct HotMethodRef {
    class: String,
    method: String,
    percent: f64,
    fact_id: FactId,
}

fn target_aliases(ctx: &RuleCtx<'_>, target: &str) -> (Option<String>, Option<String>) {
    for f in ctx.store.by_kind(kind::MIXIN_TARGET) {
        if f.attr("target") == Some(target) {
            return (
                f.attr("target_named").map(str::to_string),
                f.attr("target_intermediary").map(str::to_string),
            );
        }
    }
    (None, None)
}

/// Layer B → Layer F context: the [`kind::MOD_CAPABILITY`] facts for each mod
/// involved in a risk assessment, as `(mod_id, capabilities, evidence_fact_ids)`.
/// Lets a mixin-risk finding explain *what the mod does* (modifies rendering,
/// performance-oriented, deep runtime integration), not just that it weaves code.
fn capability_context(
    ctx: &RuleCtx<'_>,
    mods: &[String],
) -> Vec<(String, Vec<String>, Vec<FactId>)> {
    let mut out = Vec::new();
    for mod_id in mods {
        let mut caps = Vec::new();
        let mut ids = Vec::new();
        for f in ctx.store.by_kind(kind::MOD_CAPABILITY) {
            if f.subject == *mod_id {
                if let Some(cap) = f.attr("capability") {
                    caps.push(cap.to_string());
                    ids.push(f.id);
                }
            }
        }
        if !caps.is_empty() {
            out.push((mod_id.clone(), caps, ids));
        }
    }
    out
}

fn collect_hot_methods(ctx: &RuleCtx<'_>) -> Vec<HotMethodRef> {
    ctx.store
        .by_kind(kind::HOT_METHOD)
        .filter_map(|f| {
            let class = f.attr("class")?;
            let method = f.attr("method")?;
            let percent = f.attr_f64("percent").unwrap_or(0.0);
            Some(HotMethodRef {
                class: class.to_string(),
                method: method.to_string(),
                percent,
                fact_id: f.id,
            })
        })
        .collect()
}

fn hot_methods_for_class<'a>(
    hot: &'a [HotMethodRef],
    target: &str,
    target_named: Option<&str>,
    target_intermediary: Option<&str>,
) -> Vec<&'a HotMethodRef> {
    hot.iter()
        .filter(|hm| {
            classes_match_with_aliases(&hm.class, target, target_named, target_intermediary)
        })
        .collect()
}

/// How strongly a Spark hot class matches a mixin target. A full FQN/alias match
/// is trustworthy; a bare simple-name match (`…ClientWorld` == `…ClientWorld`)
/// can be a coincidence across packages, so it earns less boost and lower
/// confidence — performance findings should not over-claim on a weak match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchQuality {
    /// Only the simple (final) class name matched.
    SimpleName,
    /// A full mapped-alias / fully-qualified name matched.
    Fqn,
}

fn spark_overlap_boost(
    hot: &[HotMethodRef],
    target: &str,
    target_named: Option<&str>,
    target_intermediary: Option<&str>,
) -> (u8, Option<MatchQuality>) {
    let mut boost = 0u8;
    let mut best: Option<MatchQuality> = None;
    for hm in hot {
        let Some(quality) =
            class_match_quality(&hm.class, target, target_named, target_intermediary)
        else {
            continue;
        };
        if hm.percent < 5.0 {
            continue;
        }
        best = best.max(Some(quality));
        let base = if hm.percent >= 25.0 { 18 } else { 10 };
        // A simple-name-only match contributes a fraction of the boost.
        let scaled = match quality {
            MatchQuality::Fqn => base,
            MatchQuality::SimpleName => base / 2,
        };
        boost = boost.saturating_add(scaled);
    }
    (boost.min(28), best)
}

/// Exact / simple-name equality between two dotted class names.
fn fqn_equal(a: &str, b: &str) -> bool {
    a == b
}

fn simple_name_equal(a: &str, b: &str) -> bool {
    a.rsplit('.').next() == b.rsplit('.').next()
}

fn class_match_quality(
    spark_class: &str,
    mixin_target: &str,
    target_named: Option<&str>,
    target_intermediary: Option<&str>,
) -> Option<MatchQuality> {
    let candidates = [Some(mixin_target), target_named, target_intermediary];
    if candidates
        .iter()
        .flatten()
        .any(|c| fqn_equal(spark_class, c))
    {
        return Some(MatchQuality::Fqn);
    }
    if candidates
        .iter()
        .flatten()
        .any(|c| simple_name_equal(spark_class, c))
    {
        return Some(MatchQuality::SimpleName);
    }
    None
}

fn classes_match_with_aliases(
    spark_class: &str,
    mixin_target: &str,
    target_named: Option<&str>,
    target_intermediary: Option<&str>,
) -> bool {
    class_match_quality(spark_class, mixin_target, target_named, target_intermediary).is_some()
}

/// Note findings for configs with a dynamic `IMixinConfigPlugin`: static
/// analysis cannot know which mixins the plugin enables/disables at load time, so
/// any absence-based conclusion (e.g. "no conflict here") is less certain.
fn mixin_plugin_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in ctx.store.by_kind(kind::MIXIN_CONFIG_PLUGIN) {
        let plugin = f.attr("plugin").unwrap_or("<plugin>");
        let config = f.attr("config").unwrap_or("");
        out.push(
            Finding::builder(RULE_ID, format!("mixin-plugin:{}:{config}", f.subject))
                .severity(Severity::Note)
                .category(Category::Mixin)
                .title(format!("Dynamic mixin plugin in `{}`", f.subject))
                .explanation(format!(
                    "`{}`'s mixin config `{config}` declares a config plugin (`{plugin}`). \
                     The plugin can enable or disable mixins at load time, so this layer's \
                     static view of which mixins apply may be incomplete — treat absence of a \
                     mixin finding here as lower-confidence.",
                    f.subject
                ))
                .evidence(EvidenceEdge::subject(f.id))
                .affects(f.subject.clone())
                .tag("mixin")
                .tag("config-plugin")
                .confidence(0.9)
                .build(),
        );
    }
    out
}

/// Apply-time failure findings (plan 5.3). These are higher-certainty than
/// semantic conflicts: a `confirmed` failure (missing target with `require`, a
/// `@Shadow` descriptor mismatch, an absent class with the MC jar indexed) is an
/// `Error` — the mixin will not apply. Unconfirmed risks (refmap missing,
/// `remap = false` on a Minecraft target, an unmatched method without `require`)
/// are `Warn`.
fn apply_failure_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    const APPLY_KINDS: &[&str] = &[
        "mixin_apply_target_class_missing",
        "mixin_apply_target_method_missing",
        "mixin_apply_descriptor_mismatch",
        "mixin_apply_require_unsatisfied",
        "mixin_apply_refmap_missing",
        "mixin_apply_remap_false_suspicious",
        "mixin_apply_ordinal_out_of_range",
    ];
    let mut out = Vec::new();
    for kind in APPLY_KINDS {
        for f in ctx.store.by_kind(kind) {
            let confirmed = f.attr_bool("confirmed").unwrap_or(false);
            let target = f.attr("target").unwrap_or("");
            let member = f.attr("member").unwrap_or("");
            let detail = f.attr("detail").unwrap_or("mixin apply failure");
            let mixin = f.attr("mixin").unwrap_or(&f.subject);
            out.push(
                Finding::builder(
                    RULE_ID,
                    format!("mixin-apply:{kind}:{}:{target}:{member}", f.subject),
                )
                .severity(if confirmed { Severity::Error } else { Severity::Warn })
                .category(Category::Mixin)
                .title(if confirmed {
                    format!("Mixin will not apply: `{mixin}` -> {target}")
                } else {
                    format!("Mixin may not apply: `{mixin}` -> {target}")
                })
                .explanation(format!(
                    "`{}` ({mixin}): {detail}.",
                    f.subject
                ))
                .evidence(EvidenceEdge::subject(f.id))
                .affects(f.subject.clone())
                .fix(FixCandidate::advice(
                    "Verify the target class/method exists in the installed version; rebuild the \
                     mixin against the correct Minecraft/mod mappings, or run with --minecraft-jar \
                     for full apply verification.",
                ))
                .tag("mixin")
                .tag("apply-failure")
                .confidence(if confirmed { 0.95 } else { 0.6 })
                .build(),
            );
        }
    }
    out
}

/// Confidence that the risk finding's *site resolution* is correct — an
/// evidence-quality measure, independent of how severe the risk would be.
///
/// Starts high and is reduced by unresolved injection points (each one is a site
/// we could not pin down) and by an inability to canonicalize the target to the
/// cross-mod-stable intermediary namespace.
fn resolution_confidence(unresolved_points: i64, intermediary_known: bool) -> f32 {
    let mut c: f32 = if intermediary_known { 0.9 } else { 0.65 };
    if unresolved_points > 0 {
        c -= (unresolved_points as f32 * 0.1).min(0.5);
    }
    c.clamp(0.2, 0.95)
}

fn risk_severity(score: u8) -> Severity {
    match score {
        0..=30 => Severity::Note,
        31..=60 => Severity::Note,
        61..=80 => Severity::Warn,
        _ => Severity::Warn,
    }
}

fn risk_advice(score: u8, hot_path: bool) -> String {
    if score >= 80 {
        if hot_path {
            "High-risk hot-path mixin overlap: test with each conflicting mod disabled and compare Spark profiles.".to_string()
        } else {
            "High-risk mixin overlap: check compatibility matrices and consider removing one conflicting mod.".to_string()
        }
    } else if score >= 50 {
        "Moderate mixin risk: verify mod versions and watch logs for Mixin apply errors.".to_string()
    } else {
        "Low mixin risk: informational overlap — monitor after mod updates.".to_string()
    }
}

/// Surface per-handler bytecode intelligence even when no cross-mod overlap exists.
fn handler_intelligence_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in ctx.store.by_kind(kind::MIXIN_HANDLER_EFFECT) {
        let cancels = f.attr_bool("cancels").unwrap_or(false);
        let sets_return = f.attr_bool("sets_return_value").unwrap_or(false);
        let writes_target = f.attr_bool("writes_target_state").unwrap_or(false);
        let complexity = f.attr_int("complexity_score").unwrap_or(0);
        let conditional = f.attr_bool("conditional_control").unwrap_or(false);
        if !cancels
            && !sets_return
            && !writes_target
            && complexity < 55
        {
            continue;
        }
        let mixin = f.attr("mixin").unwrap_or("?");
        let handler = f.attr("handler_method").unwrap_or("?");
        let mut parts: Vec<String> = Vec::new();
        if cancels {
            parts.push(
                if conditional {
                    "may cancel via CallbackInfo".to_string()
                } else {
                    "unconditionally cancels via CallbackInfo".to_string()
                },
            );
        }
        if sets_return {
            parts.push(
                if conditional {
                    "may set return value".to_string()
                } else {
                    "unconditionally sets return value".to_string()
                },
            );
        }
        if writes_target {
            parts.push("writes target state".to_string());
        }
        if complexity >= 55 {
            parts.push(format!("complexity {complexity}/100"));
        }
        let explanation = parts.join("; ");
        let severity = if (!conditional && (cancels || sets_return)) || writes_target {
            Severity::Warn
        } else {
            Severity::Note
        };
        out.push(
            Finding::builder(RULE_ID, format!("mixin-handler-intel:{mixin}:{handler}"))
                .severity(severity)
                .category(Category::Mixin)
                .title(format!("Mixin handler `{mixin}#{handler}`"))
                .explanation(explanation)
                .evidence(EvidenceEdge::subject(f.id))
                .affects(f.subject.as_str())
                .tag("mixin")
                .tag("handler-intelligence")
                .confidence(0.88)
                .build(),
        );
    }
    out
}

fn mixin_effect_summary_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let recs_by_site = recommendation_facts_grouped(ctx);
    let mut out = Vec::new();
    for f in ctx.store.by_kind(kind::MIXIN_EFFECT) {
        let operation = parse_operation(f.attr("operation").unwrap_or("unknown"));
        // Overwrite effects are surfaced by `enhanced_overwrite_findings` with recommendations.
        if operation == MixinOperation::Overwrite {
            continue;
        }
        let description = f.attr("effect_description").unwrap_or("mixin effect");
        let target = f.attr("target").unwrap_or(&f.subject);
        let method = f.attr("method").unwrap_or("");
        let site_key = f.attr("site_key").unwrap_or("");
        let hot_path = f.attr_bool("hot_path").unwrap_or(false);
        let handler_method = f.attr("handler_method").unwrap_or("").to_string();
        let handler_effect = lookup_handler_effect(
            ctx,
            f.subject.as_str(),
            f.attr("mixin").unwrap_or(""),
            &handler_method,
        );

        let effect = crate::model::MixinEffect {
            mod_id: f.subject.clone(),
            mixin_class: f.attr("mixin").unwrap_or("").to_string(),
            target: target.to_string(),
            method: method.to_string(),
            handler_method,
            operation,
            effect_kinds: parse_effect_kinds(f.attr("effect_kinds").unwrap_or("")),
            effect_description: description.to_string(),
            handler_effect,
            hot_path,
            site_key: site_key.to_string(),
            at_target: f.attr("at_target").unwrap_or("").to_string(),
        };

        let hist_boost = historical_severity_boost(ctx, &effect);
        let severity = effect_summary_severity(&effect, hist_boost);
        let recs: Vec<Recommendation> = recs_by_site
            .get(site_key)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
            .to_vec();

        let mut explanation = description.to_string();
        if let Some(handler) = &effect.handler_effect {
            if handler.complexity_score >= 55 {
                explanation.push_str(&format!(
                    " Handler complexity score is {}/100.",
                    handler.complexity_score
                ));
            }
        }
        if hist_boost > 0 {
            explanation.push_str(
                " Historical runtime logs show similar mixin patterns on this target — severity elevated.",
            );
        }
        let rec_text = format_recommendations(&recs);
        if !rec_text.is_empty() {
            explanation.push('\n');
            explanation.push_str(&rec_text);
        }

        let finding_id = if site_key.is_empty() {
            format!("mixin-effect-summary:{target}:{method}")
        } else {
            format!("mixin-effect-summary:{site_key}")
        };

        let mut builder = Finding::builder(RULE_ID, finding_id)
            .severity(severity)
            .category(Category::Mixin)
            .title(format!("Mixin effect: {target}#{method}"))
            .explanation(explanation)
            .evidence(EvidenceEdge::subject(f.id))
            .affects(target)
            .tag("mixin")
            .tag("mixin-effect-summary")
            .confidence(0.82);

        for rec in &recs {
            let (text, confidence) = recommendation_as_fix(rec);
            builder = builder.fix(FixCandidate {
                description: text,
                command: None,
                confidence,
            });
            if let Some(fid) = recommendation_fact_id(ctx, site_key, &rec.id) {
                builder = builder.evidence(EvidenceEdge::new(fid, Relation::Supports, rec.confidence));
            }
        }
        out.push(builder.build());
    }
    out
}

fn enhanced_overwrite_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let recs_by_site = recommendation_facts_grouped(ctx);
    let mut out = Vec::new();
    for f in ctx.store.by_kind(kind::HIGH_RISK_OVERWRITE) {
        let target = f.attr("target").unwrap_or(&f.subject);
        let effect_desc = f.attr("effect_description").unwrap_or("");
        if effect_desc.is_empty() {
            continue;
        }
        let hot_path = f.attr_bool("hot_path").unwrap_or(false);
        let method = f.attr("method").unwrap_or("");
        let mixin = f.attr("mixin").unwrap_or("");
        let site_key = f
            .attr("site_key")
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| overwrite_recommendation_site_key(ctx, f.subject.as_str(), mixin, target, method));
        let recs: Vec<Recommendation> = recs_by_site
            .get(site_key.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[])
            .to_vec();

        let mut explanation = effect_desc.to_string();
        let rec_text = format_recommendations(&recs);
        if !rec_text.is_empty() {
            explanation.push('\n');
            explanation.push_str(&rec_text);
        }
        let mut builder = Finding::builder(
            RULE_ID,
            format!("mixin-overwrite-effect:{mixin}->{target}"),
        )
        .severity(Severity::Warn)
        .category(Category::Mixin)
        .title(format!("@Overwrite effect: {target}"))
        .explanation(explanation)
        .evidence(EvidenceEdge::subject(f.id))
        .affects(target)
        .tag("mixin")
        .tag("overwrite")
        .tag("mixin-effect")
        .confidence(if hot_path { 0.78 } else { 0.72 });
        for rec in &recs {
            let (text, confidence) = recommendation_as_fix(rec);
            builder = builder.fix(FixCandidate {
                description: text,
                command: None,
                confidence,
            });
            if let Some(fid) = recommendation_fact_id(ctx, site_key.as_str(), &rec.id) {
                builder = builder.evidence(EvidenceEdge::new(fid, Relation::Supports, rec.confidence));
            }
        }
        out.push(builder.build());
    }
    out
}

fn effect_summary_severity(effect: &crate::model::MixinEffect, hist_boost: u8) -> Severity {
    if (effect.hot_path && effect.operation == MixinOperation::Overwrite) || hist_boost >= 12 {
        Severity::Warn
    } else {
        Severity::Note
    }
}

fn recommendation_facts_grouped(
    ctx: &RuleCtx<'_>,
) -> std::collections::BTreeMap<String, Vec<Recommendation>> {
    let records: Vec<crate::model::MixinRecommendationRecord> = ctx
        .store
        .by_kind(kind::MIXIN_RECOMMENDATION)
        .map(|f| crate::model::MixinRecommendationRecord {
            mod_id: f.subject.clone(),
            mixin_class: f.attr("mixin").unwrap_or("").to_string(),
            target: f.attr("target").unwrap_or("").to_string(),
            site_key: f.attr("site_key").unwrap_or("").to_string(),
            recommendation: Recommendation {
                id: f.attr("rec_id").unwrap_or("").to_string(),
                title: f.attr("title").unwrap_or("").to_string(),
                description: f.attr("description").unwrap_or("").to_string(),
                rationale: f.attr("rationale").unwrap_or("").to_string(),
                confidence: f.attr_f64("confidence").unwrap_or(0.6) as f32,
                example: f.attr("example").map(str::to_string),
                doc_url: f.attr("doc_url").map(str::to_string),
            },
        })
        .collect();
    recommendations_by_site(&records)
}

fn lookup_handler_effect(
    ctx: &RuleCtx<'_>,
    mod_id: &str,
    mixin: &str,
    handler_method: &str,
) -> Option<HandlerEffect> {
    if handler_method.is_empty() {
        return None;
    }
    ctx.store
        .by_kind(kind::MIXIN_HANDLER_EFFECT)
        .find(|f| {
            f.subject == mod_id
                && f.attr("mixin") == Some(mixin)
                && f.attr("handler_method") == Some(handler_method)
        })
        .map(|f| HandlerEffect {
            handler_method: handler_method.to_string(),
            handler_local_store: f
                .attr_bool("handler_local_store")
                .or_else(|| f.attr_bool("modifies_locals"))
                .unwrap_or(false),
            modifies_return: f.attr_bool("modifies_return").unwrap_or(false),
            early_return: f.attr_bool("early_return").unwrap_or(false),
            side_effects: parse_handler_side_effects(f.attr("side_effects").unwrap_or("")),
            complexity_score: u8::try_from(
                f.attr_int("complexity_score").unwrap_or(0).clamp(0, 100),
            )
            .unwrap_or(0),
            cancels: f.attr_bool("cancels").unwrap_or(false),
            sets_return_value: f.attr_bool("sets_return_value").unwrap_or(false),
            conditional_control: f.attr_bool("conditional_control").unwrap_or(false),
            return_value_source: parse_value_source(f.attr("return_value_source").unwrap_or("")),
            writes_target_state: f.attr_bool("writes_target_state").unwrap_or(false),
            original_call_count: u32::try_from(
                f.attr_int("original_call_count").unwrap_or(0).max(0),
            )
            .unwrap_or(0),
        })
}

/// Parse a [`ValueSource`] from its kebab-case fact attribute.
fn parse_value_source(value: &str) -> crate::model::ValueSource {
    use crate::model::ValueSource;
    match value {
        "constant" => ValueSource::Constant,
        "argument" => ValueSource::Argument,
        "this" => ValueSource::ThisRef,
        "target-field" => ValueSource::TargetField,
        "target-call-result" => ValueSource::TargetCallResult,
        "computed" => ValueSource::Computed,
        "new-object" => ValueSource::NewObject,
        _ => ValueSource::Unknown,
    }
}

fn parse_handler_side_effects(value: &str) -> Vec<HandlerSideEffect> {
    value
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s {
            "reflection" => Some(HandlerSideEffect::Reflection),
            "static-target-call" => Some(HandlerSideEffect::StaticTargetCall),
            "target-field-access" => Some(HandlerSideEffect::TargetFieldAccess),
            "callback-control" => Some(HandlerSideEffect::CallbackControl),
            "exception-throw" => Some(HandlerSideEffect::ExceptionThrow),
            "target-state-write" => Some(HandlerSideEffect::TargetStateWrite),
            "global-state-write" => Some(HandlerSideEffect::GlobalStateWrite),
            "async-scheduling" => Some(HandlerSideEffect::AsyncScheduling),
            "world-mutation" => Some(HandlerSideEffect::WorldMutation),
            "heavy-allocation" => Some(HandlerSideEffect::HeavyAllocation),
            "logging-only" => Some(HandlerSideEffect::LoggingOnly),
            _ => None,
        })
        .collect()
}

/// Fallback `site_key` when legacy overwrite facts omit the attribute.
fn overwrite_recommendation_site_key(
    ctx: &RuleCtx<'_>,
    mod_id: &str,
    mixin: &str,
    target: &str,
    method: &str,
) -> String {
    ctx.store
        .by_kind(kind::MIXIN_EFFECT)
        .find(|ef| {
            ef.subject == mod_id
                && ef.attr("mixin") == Some(mixin)
                && ef.attr("target") == Some(target)
                && ef.attr("operation") == Some("overwrite")
                && (method.is_empty()
                    || ef.attr("method") == Some(method)
                    || ef.attr("site_key").is_some_and(|k| k.contains(method)))
        })
        .and_then(|ef| ef.attr("site_key"))
        .map(str::to_string)
        .unwrap_or_default()
}

fn recommendation_fact_id(ctx: &RuleCtx<'_>, site_key: &str, rec_id: &str) -> Option<FactId> {
    ctx.store
        .by_kind(kind::MIXIN_RECOMMENDATION)
        .find(|f| f.attr("site_key") == Some(site_key) && f.attr("rec_id") == Some(rec_id))
        .map(|f| f.id)
}

fn parse_operation(value: &str) -> MixinOperation {
    match value {
        "inject" => MixinOperation::Inject,
        "redirect" => MixinOperation::Redirect,
        "overwrite" => MixinOperation::Overwrite,
        "modify-arg" => MixinOperation::ModifyArg,
        "modify-variable" => MixinOperation::ModifyVariable,
        "wrap-operation" => MixinOperation::WrapOperation,
        "modify-expression-value" => MixinOperation::ModifyExpressionValue,
        "modify-return-value" => MixinOperation::ModifyReturnValue,
        "modify-receiver" => MixinOperation::ModifyReceiver,
        _ => MixinOperation::Unknown,
    }
}

fn parse_effect_kinds(value: &str) -> Vec<EffectiveEffectKind> {
    value
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| match s {
            "full-method-replacement" => EffectiveEffectKind::FullMethodReplacement,
            "entry-modification" => EffectiveEffectKind::EntryModification,
            "exit-modification" => EffectiveEffectKind::ExitModification,
            "possible-early-return" => EffectiveEffectKind::PossibleEarlyReturn,
            "call-site-replacement" => EffectiveEffectKind::CallSiteReplacement,
            "argument-mutation" => EffectiveEffectKind::ArgumentMutation,
            "local-mutation" => EffectiveEffectKind::LocalMutation,
            _ => EffectiveEffectKind::Unknown,
        })
        .collect()
}

fn legacy_overlap_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in ctx.store.by_kind(kind::MIXIN_OVERLAP) {
        let mods = split_attr(f.attr("mods"));
        let operations = split_attr(f.attr("operations"));
        let hot_path = f.attr_bool("hot_path").unwrap_or(false);
        let method_conflict = f.attr_bool("method_conflict").unwrap_or(true);
        let shared_methods = split_attr(f.attr("shared_methods"));
        let severity = if method_conflict {
            Severity::Warn
        } else {
            Severity::Note
        };
        let effect_summaries = f.attr("effect_summaries").unwrap_or("");
        let explanation = if method_conflict {
            let shared = if shared_methods.is_empty() {
                String::new()
            } else {
                format!(" Shared method(s): {}.", shared_methods.join(", "))
            };
            let effects = if effect_summaries.is_empty() {
                String::new()
            } else {
                format!(" Effects: {effect_summaries}.")
            };
            format!(
                "{} mod(s) target {} with operation(s): {}.{shared}{effects}",
                mods.len(),
                f.subject,
                operations.join(", ")
            )
        } else {
            format!(
                "{} mod(s) target {} but inject into disjoint methods — informational only.",
                mods.len(),
                f.subject,
            )
        };
        let mut b = Finding::builder(RULE_ID, format!("mixin-overlap:{}", f.subject))
            .severity(severity)
            .category(Category::Mixin)
            .title(format!("Mixin target overlap: {}", f.subject))
            .explanation(explanation)
            .evidence(EvidenceEdge::subject(f.id))
            .affects(f.subject.clone())
            .fix(FixCandidate::advice(
                "Check mod compatibility notes and prefer versions known to share this target.",
            ))
            .tag("mixin")
            .tag("overlap")
            .confidence(if hot_path { 0.75 } else { 0.7 });
        for target in ctx.store.by_kind(kind::MIXIN_TARGET) {
            if target.attr("target") == Some(f.subject.as_str()) {
                b = b.evidence(EvidenceEdge::new(target.id, Relation::ConflictsWith, 0.75));
            }
        }
        out.push(b.build());
    }
    out
}

fn legacy_overwrite_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in ctx.store.by_kind(kind::HIGH_RISK_OVERWRITE) {
        let target = f.attr("target").unwrap_or(&f.subject);
        if f.attr("effect_description").is_some_and(|d| !d.is_empty()) {
            continue;
        }
        let hot_path = f.attr_bool("hot_path").unwrap_or(false);
        out.push(
            Finding::builder(RULE_ID, format!("mixin-overwrite:{}->{target}", f.subject))
                .severity(Severity::Warn)
                .category(Category::Mixin)
                .title(format!("High-risk @Overwrite mixin: {target}"))
                .explanation(format!(
                    "{} overwrites code in {target}. @Overwrite has a high compatibility risk because it replaces target behavior.",
                    f.subject
                ))
                .evidence(EvidenceEdge::subject(f.id))
                .affects(target)
                .fix(FixCandidate::advice(
                    "Prefer versions without competing overwrites, or remove one conflicting mod.",
                ))
                .tag("mixin")
                .tag("overwrite")
                .confidence(if hot_path { 0.72 } else { 0.68 })
                .build(),
        );
    }
    out
}

fn split_attr(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}
#[cfg(test)]
mod match_quality_tests {
    use super::{class_match_quality, spark_overlap_boost, HotMethodRef, MatchQuality};
    use intermed_doctor_core::facts::FactId;

    fn hm(class: &str, percent: f64) -> HotMethodRef {
        HotMethodRef {
            class: class.into(),
            method: "tick".into(),
            percent,
            fact_id: FactId(0),
        }
    }

    #[test]
    fn fqn_beats_simple_name() {
        assert_eq!(
            class_match_quality("net.minecraft.Foo", "net.minecraft.Foo", None, None),
            Some(MatchQuality::Fqn)
        );
        // Different package, same simple name → only a SimpleName match.
        assert_eq!(
            class_match_quality("a.b.ClientWorld", "x.y.ClientWorld", None, None),
            Some(MatchQuality::SimpleName)
        );
        assert_eq!(class_match_quality("a.Foo", "b.Bar", None, None), None);
    }

    #[test]
    fn simple_name_match_earns_less_boost() {
        let fqn = spark_overlap_boost(&[hm("net.minecraft.Foo", 30.0)], "net.minecraft.Foo", None, None);
        let simple = spark_overlap_boost(&[hm("a.Foo", 30.0)], "b.Foo", None, None);
        assert_eq!(fqn.1, Some(MatchQuality::Fqn));
        assert_eq!(simple.1, Some(MatchQuality::SimpleName));
        assert!(simple.0 < fqn.0, "simple-name boost {} should be < fqn {}", simple.0, fqn.0);
    }
}

#[cfg(test)]
mod confidence_tests {
    use super::resolution_confidence;

    #[test]
    fn resolution_confidence_is_evidence_quality_not_risk() {
        // Fully resolved, intermediary-known → high confidence.
        let high = resolution_confidence(0, true);
        // Unresolved points and no intermediary bridge → much lower confidence,
        // regardless of how severe the (separately computed) risk score is.
        let low = resolution_confidence(3, false);
        assert!(high > 0.85, "clean resolution should be confident: {high}");
        assert!(low < 0.6, "unresolved + no bridge should be low: {low}");
        assert!(high > low);
        // Confidence stays within sane bounds.
        assert!(resolution_confidence(99, false) >= 0.2);
    }
}
