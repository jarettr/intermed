//! Rule-layer tests: facts → [`MixinRiskRule`] findings with recommendations.

use intermed_doctor_core::evidence::Severity;
use intermed_doctor_core::facts::{FactStore, kind};
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
    assert!(
        overwrite
            .fix_candidates
            .iter()
            .any(|c| c.description.contains("CallbackInfo"))
    );

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
    assert!(
        summary
            .explanation
            .contains("Handler complexity score is 60/100")
    );
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
    assert!(!findings.iter().any(
        |f| f.machine_tags.iter().any(|t| t == "mixin-effect-summary")
            && f.explanation.contains("@Overwrite")
    ));

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

#[test]
fn risk_cluster_fact_becomes_a_finding_citing_failing_sites() {
    // A site-level overhaul (Phases 13/14) risk cluster, plus the failing
    // application-site it rolls up, should surface as one actionable finding that
    // cites the site fact as evidence.
    let mut store = FactStore::new();
    let site = store
        .fact("mixin-analyzer", kind::MIXIN_APPLICATION_SITE)
        .subject("modx::modx.Mixin::onTick->net.example.Foo#bar()V@INVOKE")
        .attr("mod", "modx")
        .attr("target_class", "net.example.Foo")
        .attr("target_method", "bar()V")
        .attr("selector_verification", "no-match")
        .attr("target_resolution", "exact-match")
        .attr("signature_check", "valid")
        .attr("local_capture_status", "no-local-capture")
        .emit();
    store
        .fact("mixin-analyzer", kind::MIXIN_RISK_CLUSTER)
        .subject("cluster-net.example.Foo")
        .attr("kind", "apply-failure")
        .attr("target_class", "net.example.Foo")
        .attr("severity", "warn")
        .attr("confirmation_level", "static-exact")
        .attr("headline", "1 selector issue on `net.example.Foo` (modx)")
        .attr("recommended_action", "Inspect the failing sites.")
        .emit();

    let target = mods_target(std::path::Path::new("."));
    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    let cluster = findings
        .iter()
        .find(|f| f.id == "mixin-cluster:cluster-net.example.Foo")
        .expect("risk cluster finding");
    assert_eq!(cluster.severity, Severity::Warn);
    // The failing application-site fact is cited as supporting evidence.
    assert!(
        cluster.evidence.iter().any(|e| e.fact == site),
        "cluster finding must cite the failing site fact"
    );
    assert!(cluster.machine_tags.iter().any(|t| t == "risk-cluster"));
}

#[test]
fn mixin_runtime_mutation_correlates_with_layer_m_static_conflict() {
    // A mixin hooking the recipe loader + a Layer-M static recipe conflict should
    // produce a cross-layer "may be overridden at runtime" finding citing both.
    let mut store = FactStore::new();
    let mutation = store
        .fact("mixin-analyzer", kind::MIXIN_RUNTIME_RESOURCE_MUTATION)
        .subject("recipe")
        .attr("mod", "tweakermod")
        .attr("mixin", "tweakermod.RecipeMixin")
        .attr(
            "site_id",
            "tweakermod::RecipeMixin::onApply->net.minecraft.recipe.RecipeManager#apply@HEAD",
        )
        .attr("target_class", "net.minecraft.recipe.RecipeManager")
        .attr("subsystem", "recipe")
        .attr("domain", "recipe")
        .attr("operation", "redirect")
        .attr("effect", "rewrites-load-call")
        .attr("confidence", 85)
        .emit();
    let diff = store
        .fact("resource-ast-scanner", kind::RESOURCE_SEMANTIC_DIFF)
        .subject("data/minecraft/recipe/stick.json")
        .attr("diff_kind", "recipe-output-override")
        .attr("writers", "moda,modb")
        .attr("detail", "conflicting outputs")
        .emit();

    let target = mods_target(std::path::Path::new("."));
    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    let f = findings
        .iter()
        .find(|f| f.id == "mixin-resource-override:recipe")
        .expect("cross-layer recipe override finding");
    assert_eq!(f.severity, Severity::Warn);
    assert!(f.machine_tags.iter().any(|t| t == "cross-layer"));
    // Cites BOTH the mixin mutation and the Layer-M static diff.
    assert!(f.evidence.iter().any(|e| e.fact == mutation));
    assert!(f.evidence.iter().any(|e| e.fact == diff));
}

#[test]
fn mixin_and_script_both_mutating_recipes_correlate() {
    let mut store = FactStore::new();
    store
        .fact("mixin-analyzer", kind::MIXIN_RUNTIME_RESOURCE_MUTATION)
        .subject("recipe")
        .attr("mod", "tweakermod")
        .attr("mixin", "tweakermod.RecipeMixin")
        .attr("site_id", "s")
        .attr("target_class", "net.minecraft.recipe.RecipeManager")
        .attr("subsystem", "recipe")
        .attr("domain", "recipe")
        .attr("operation", "inject")
        .attr("effect", "hooks-loader")
        .attr("confidence", 55)
        .emit();
    store
        .fact("dynamics-scanner", kind::RUNTIME_SCRIPT_MODIFIES_RECIPE)
        .subject("minecraft:stick")
        .attr("engine", "kubejs")
        .attr("via", "ServerEvents.recipes")
        .emit();

    let target = mods_target(std::path::Path::new("."));
    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    let f = findings
        .iter()
        .find(|f| f.id == "mixin-script-resource:recipe")
        .expect("mixin+script recipe finding");
    assert!(f.explanation.contains("kubejs"));
}

#[test]
fn runtime_log_confirms_a_static_site() {
    // A MixinApplyError log line naming a mixin that also exists as a static site
    // should produce a confirmed Error finding citing both facts.
    let mut store = FactStore::new();
    let site = store
        .fact("mixin-analyzer", kind::MIXIN_APPLICATION_SITE)
        .subject("modz::modz.mixin.ServerMixin::onTick->net.minecraft.Server#tick()V@HEAD")
        .attr("mod", "modz")
        .attr("mixin", "modz.mixin.ServerMixin")
        .attr("target_class", "net.minecraft.Server")
        .attr("target_method", "tick()V")
        .attr("site_key", "tick()V@HEAD")
        .emit();
    let log = store
        .fact("log-collector", kind::LOG_SIGNAL)
        .subject("MixinApplyError")
        .attr("line", 42i64)
        .attr(
            "excerpt",
            "InvalidInjectionException: @Inject could not find any targets matching 'tick()V' in somemod.mixins.json:ServerMixin",
        )
        .emit();

    let target = mods_target(std::path::Path::new("."));
    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    let f = findings
        .iter()
        .find(|f| f.id.starts_with("mixin-runtime-confirmed:"))
        .expect("runtime-confirmed finding");
    assert_eq!(f.severity, Severity::Error);
    assert!(f.evidence.iter().any(|e| e.fact == site));
    assert!(f.evidence.iter().any(|e| e.fact == log));
}

#[test]
fn mixin_security_surface_elevates_with_layer_g_capability() {
    // A mixin into the networking subsystem + a Layer-G uses_unsafe on the same mod
    // ⇒ elevated Warn finding citing both.
    let mut store = FactStore::new();
    let surface = store
        .fact("mixin-analyzer", kind::MIXIN_SECURITY_SURFACE)
        .subject("sketchymod")
        .attr("mixin", "sketchymod.NetMixin")
        .attr("site_id", "s")
        .attr("target_class", "net.minecraft.network.ClientConnection")
        .attr("subsystem", "networking")
        .attr("operation", "redirect")
        .attr("reason", "weaves into network packet / connection handling")
        .attr("confidence", 90)
        .emit();
    let unsafe_fact = store
        .fact("security-audit", kind::USES_UNSAFE)
        .subject("sketchymod")
        .emit();

    let target = mods_target(std::path::Path::new("."));
    let findings = rule().evaluate(&RuleCtx::for_test(&store, &target));
    let f = findings
        .iter()
        .find(|f| f.id == "mixin-security:sketchymod:networking")
        .expect("security finding");
    assert_eq!(f.severity, Severity::Warn);
    assert!(f.machine_tags.iter().any(|t| t == "elevated"));
    assert!(f.evidence.iter().any(|e| e.fact == surface));
    assert!(f.evidence.iter().any(|e| e.fact == unsafe_fact));
}

#[test]
fn mixin_security_surface_alone_is_a_note() {
    let mut store = FactStore::new();
    store
        .fact("mixin-analyzer", kind::MIXIN_SECURITY_SURFACE)
        .subject("netmod")
        .attr("mixin", "netmod.M")
        .attr("site_id", "s")
        .attr("target_class", "net.minecraft.network.ClientConnection")
        .attr("subsystem", "networking")
        .attr("operation", "inject")
        .attr("reason", "weaves into network packet / connection handling")
        .attr("confidence", 70)
        .emit();
    let target = mods_target(std::path::Path::new("."));
    let f = rule()
        .evaluate(&RuleCtx::for_test(&store, &target))
        .into_iter()
        .find(|f| f.id == "mixin-security:netmod:networking")
        .expect("security note");
    assert_eq!(f.severity, Severity::Note);
    assert!(!f.machine_tags.iter().any(|t| t == "elevated"));
}

#[test]
fn worldgen_resource_plus_worldgen_mixin_is_flagged() {
    // Layer M: the mod ships a worldgen file. Layer F: its mixin modifies worldgen.
    let mut store = FactStore::new();
    store
        .fact("vfs", kind::RESOURCE_WRITER)
        .subject("wgmod")
        .attr("path", "data/wgmod/worldgen/configured_feature/x.json")
        .attr("json", true)
        .emit();
    store
        .fact("mixin-analyzer", kind::MOD_CAPABILITY)
        .subject("wgmod")
        .attr("capability", "modifies_worldgen")
        .emit();
    let target = mods_target(std::path::Path::new("."));
    let f = rule()
        .evaluate(&RuleCtx::for_test(&store, &target))
        .into_iter()
        .find(|f| f.id == "worldgen-resource-plus-worldgen-mixin-risk:wgmod")
        .expect("cluster-D worldgen finding");
    assert_eq!(f.severity, Severity::Note);
    assert!(f.machine_tags.iter().any(|t| t == "cross-layer"));
    assert!(f.machine_tags.iter().any(|t| t == "worldgen"));
}

#[test]
fn worldgen_resource_without_worldgen_mixin_is_not_flagged() {
    // Shipping worldgen data without a worldgen-modifying mixin must NOT fire
    // (the join, not either side alone, is the signal).
    let mut store = FactStore::new();
    store
        .fact("vfs", kind::RESOURCE_WRITER)
        .subject("wgmod")
        .attr("path", "data/wgmod/worldgen/configured_feature/x.json")
        .attr("json", true)
        .emit();
    store
        .fact("mixin-analyzer", kind::MOD_CAPABILITY)
        .subject("wgmod")
        .attr("capability", "modifies_rendering")
        .emit();
    let target = mods_target(std::path::Path::new("."));
    assert!(
        rule()
            .evaluate(&RuleCtx::for_test(&store, &target))
            .into_iter()
            .all(|f| !f
                .id
                .starts_with("worldgen-resource-plus-worldgen-mixin-risk"))
    );
}

#[test]
fn reloadable_data_loader_hook_stays_in_the_existing_bridge_path() {
    // Regression guard against re-introducing a second consumer of the
    // resource_bridge signal: a mod shipping recipes + hooking the recipe loader
    // must NOT produce a cluster-D finding. That correlation is owned by
    // `cross_layer_resource_findings` (keyed on the bridge's `domain`), exercised by
    // `mixin_runtime_mutation_correlates_with_layer_m_static_conflict` above.
    let mut store = FactStore::new();
    store
        .fact("vfs", kind::RESOURCE_WRITER)
        .subject("datamod")
        .attr("path", "data/datamod/recipes/r.json")
        .attr("json", true)
        .emit();
    store
        .fact("mixin-analyzer", kind::MIXIN_RUNTIME_RESOURCE_MUTATION)
        .subject("recipe")
        .attr("mod", "datamod")
        .attr("domain", "recipe")
        .attr("effect", "replaces-loader")
        .attr("mixin", "datamod.M")
        .emit();
    let target = mods_target(std::path::Path::new("."));
    assert!(
        rule()
            .evaluate(&RuleCtx::for_test(&store, &target))
            .into_iter()
            .all(|f| !f.id.starts_with("resource-reload-mixin-risk"))
    );
}
