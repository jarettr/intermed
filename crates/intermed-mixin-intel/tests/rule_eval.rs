//! Rule-layer tests: facts → [`MixinRiskRule`] findings with recommendations.

use intermed_doctor_core::evidence::Severity;
use intermed_doctor_core::facts::{kind, FactStore};
use intermed_doctor_core::{CollectCtx, Collector, Rule, RuleCtx, Target, TargetKind};
use intermed_mixin_intel::fixtures;
use intermed_mixin_intel::{collector, rule};

mod common;
use common::{temp_dir, write_mixin_jar};

fn mods_target(mods: &std::path::Path) -> Target {
    Target {
        path: mods.to_path_buf(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods.to_path_buf()),
            game_root: None,
            layout: None,
            instance_type: None,
        spark_report: None,
    }
}

#[test]
fn overwrite_finding_attaches_inject_recommendation_via_site_key() {
    let root = temp_dir("rule-overwrite-rec");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let beta_class = fixtures::mixin_class(
        "beta/mixin/RenderMixin",
        "net/minecraft/client/render/WorldRenderer",
        &["Overwrite"],
    );
    write_mixin_jar(
        &mods.join("beta.jar"),
        "beta",
        "beta.mixins.json",
        "beta.mixin",
        &[("RenderMixin", beta_class.as_slice())],
    );

    let target = mods_target(&mods);
    let mut store = FactStore::new();
    let settings = intermed_doctor_core::DiagnosisSettings::default();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        jar_cache: None,
        settings: &settings,
    };
    let outcome = collector().collect(&mut ctx);
    assert!(outcome.facts_emitted > 0);

    let overwrite_facts: Vec<_> = store.by_kind(kind::HIGH_RISK_OVERWRITE).collect();
    assert_eq!(overwrite_facts.len(), 1);
    assert!(
        overwrite_facts[0]
            .attr("site_key")
            .is_some_and(|k| !k.is_empty())
    );
    assert!(store.by_kind(kind::MIXIN_RECOMMENDATION).count() >= 1);

    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    let overwrite = findings
        .iter()
        .find(|f| f.id.starts_with("mixin-overwrite-effect:"))
        .expect("enhanced overwrite finding");
    assert!(overwrite.explanation.contains("@Inject"));
    assert!(!overwrite.fix_candidates.is_empty());
    assert!(overwrite
        .fix_candidates
        .iter()
        .any(|c| c.description.contains("CallbackInfo")));

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn mixin_effect_summary_includes_recommendations_and_historical_boost() {
    let mut store = FactStore::new();
    store
        .fact("mixin-analyzer", kind::MIXIN_EFFECT)
        .subject("alpha")
        .attr("mixin", "alpha.mixin.RenderMixin")
        .attr("target", "net.minecraft.client.render.WorldRenderer")
        .attr("method", "m0()V")
        .attr("handler_method", "m0")
        .attr("operation", "inject")
        .attr("site_key", "m0()V@HEAD")
        .attr("at_target", "HEAD")
        .attr("hot_path", true)
        .attr("effect_description", "injects at HEAD on hot path.")
        .attr("effect_kinds", "entry-modification")
        .emit();
    store
        .fact("mixin-analyzer", kind::MIXIN_HANDLER_EFFECT)
        .subject("alpha")
        .attr("mixin", "alpha.mixin.RenderMixin")
        .attr("handler_method", "m0")
        .attr("handler_local_store", false)
        .attr("modifies_return", false)
        .attr("early_return", false)
        .attr("complexity_score", 60i64)
        .attr("side_effects", "callback-control")
        .emit();
    store
        .fact("mixin-analyzer", kind::MIXIN_RECOMMENDATION)
        .subject("alpha")
        .attr("mixin", "alpha.mixin.RenderMixin")
        .attr("target", "net.minecraft.client.render.WorldRenderer")
        .attr("site_key", "m0()V@HEAD")
        .attr("rec_id", "complex-handler:m0")
        .attr("title", "Complex handler — expect harder debugging")
        .attr("description", "Split logic into a plain helper method.")
        .attr("rationale", "high complexity")
        .attr("confidence", 0.8f64)
        .emit();
    store
        .fact("log-analyzer", kind::LOG_MIXIN_CORRELATION)
        .subject("crash")
        .attr("target", "net.minecraft.client.render.WorldRenderer")
        .attr("operation", "inject")
        .emit();

    let target = mods_target(std::path::Path::new("."));
    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    let summary = findings
        .iter()
        .find(|f| f.id == "mixin-effect-summary:m0()V@HEAD")
        .expect("effect summary finding");
    assert_eq!(summary.severity, Severity::Warn);
    assert!(summary.explanation.contains("Historical runtime logs"));
    assert!(summary.explanation.contains("Handler complexity score is 60/100"));
    assert!(summary.explanation.contains("Recommendations:"));
    assert!(!summary.fix_candidates.is_empty());
}

#[test]
fn overwrite_effect_does_not_duplicate_as_effect_summary() {
    let root = temp_dir("rule-dedup");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let beta_class = fixtures::mixin_class(
        "beta/mixin/RenderMixin",
        "net/minecraft/client/render/WorldRenderer",
        &["Overwrite"],
    );
    write_mixin_jar(
        &mods.join("beta.jar"),
        "beta",
        "beta.mixins.json",
        "beta.mixin",
        &[("RenderMixin", beta_class.as_slice())],
    );

    let target = mods_target(&mods);
    let mut store = FactStore::new();
    let settings = intermed_doctor_core::DiagnosisSettings::default();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        jar_cache: None,
        settings: &settings,
    };
    collector().collect(&mut ctx);

    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    assert!(
        findings
            .iter()
            .any(|f| f.id.starts_with("mixin-overwrite-effect:"))
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.machine_tags.iter().any(|t| t == "mixin-effect-summary")
                && f.explanation.contains("@Overwrite"))
    );

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn risk_score_spark_boost_names_hot_methods() {
    let mut store = FactStore::new();
    store
        .fact("mixin-analyzer", kind::MIXIN_RISK_SCORE)
        .subject("net.minecraft.client.render.WorldRenderer")
        .attr("score", 55i64)
        .attr("mods", "alpha,beta")
        .attr("hot_path", true)
        .attr("reasons", "Method-level injection overlap")
        .emit();
    store
        .fact("spark-importer", kind::HOT_METHOD)
        .subject("net.minecraft.client.render.WorldRenderer")
        .attr("class", "net.minecraft.client.render.WorldRenderer")
        .attr("method", "render")
        .attr("percent", 30.0f64)
        .emit();

    let target = mods_target(std::path::Path::new("."));
    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    let risk = findings
        .iter()
        .find(|f| f.id == "mixin-risk:net.minecraft.client.render.WorldRenderer")
        .expect("risk finding");
    assert!(risk.explanation.contains("render"));
    assert!(risk.explanation.contains("Overlapping mods: alpha, beta"));
    assert!(risk.machine_tags.iter().any(|t| t == "hot-path"));
}
#[test]
fn risk_finding_includes_involved_mod_capabilities() {
    let mut store = FactStore::new();
    store
        .fact("mixin-analyzer", kind::MIXIN_RISK_SCORE)
        .subject("net.minecraft.client.render.WorldRenderer")
        .attr("score", 60i64)
        .attr("mods", "sodium")
        .attr("reasons", "Hot-path target")
        .emit();
    let cap = store
        .fact("metadata-scanner", kind::MOD_CAPABILITY)
        .subject("sodium")
        .attr("capability", "modifies_rendering")
        .attr("reason", "client/render entrypoint naming")
        .emit();

    let target = mods_target(std::path::Path::new("."));
    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    let risk = findings
        .iter()
        .find(|f| f.id == "mixin-risk:net.minecraft.client.render.WorldRenderer")
        .expect("risk finding");
    // Layer B capability surfaces as context in the explanation…
    assert!(
        risk.explanation.contains("modifies_rendering") && risk.explanation.contains("sodium"),
        "explanation should carry capability context: {}",
        risk.explanation
    );
    // …and the capability fact is wired in as evidence.
    assert!(risk.evidence.iter().any(|e| e.fact == cap));
}
