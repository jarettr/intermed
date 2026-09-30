//! Collector fact-emission contract tests.

use intermed_doctor_core::facts::FactStore;
use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{CollectCtx, Collector, DiagnosisSettings, Target, TargetKind};
use intermed_mixin_intel::fixtures;
use intermed_mixin_intel::{collector, extractor_id};

mod common;
use common::{temp_dir, write_mixin_jar};

#[test]
fn collector_emits_effect_recommendation_and_handler_facts() {
    let root = temp_dir("collect-emit");
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

    let target = Target {
        path: mods.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    let inputs = FactStore::new();
    let settings = DiagnosisSettings::default();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings: &settings,
    };
    let outcome = collector().collect(&mut ctx);
    assert!(outcome.facts_emitted > 0);

    assert_eq!(collector().id(), extractor_id());
    assert!(store.by_kind(kind::MIXIN_EFFECT).count() >= 1);
    assert!(store.by_kind(kind::MIXIN_RECOMMENDATION).count() >= 1);
    assert!(store.by_kind(kind::HIGH_RISK_OVERWRITE).count() >= 1);

    let overwrite = store.by_kind(kind::HIGH_RISK_OVERWRITE).next().unwrap();
    assert!(
        overwrite
            .attr("site_key")
            .is_some_and(|k| k.contains("@HEAD"))
    );
    assert!(
        overwrite
            .attr("effect_description")
            .is_some_and(|d| !d.is_empty())
    );

    let effect = store.by_kind(kind::MIXIN_EFFECT).next().unwrap();
    assert!(effect.attr("site_key").is_some_and(|k| !k.is_empty()));
    assert!(effect.attr("effect_kinds").is_some());

    let config = store.by_kind(kind::MIXIN_CONFIG).next().unwrap();
    assert!(
        config
            .attr("artifact_id")
            .is_some_and(|id| id.starts_with("sha256:"))
    );
    assert_eq!(
        config.attr("identity_certainty"),
        Some("unresolved-display-fallback")
    );
    assert_eq!(store.by_kind(kind::MIXIN_REFMAP_STATUS).count(), 1);
    assert_eq!(store.by_kind(kind::MIXIN_REFMAP_LOADED).count(), 0);

    // Complexity scores emit end-to-end (analysis → scan → facts), with their
    // transparent component breakdown carried on the fact.
    assert!(store.by_kind(kind::MIXIN_CLASS_COMPLEXITY).count() >= 1);
    let mod_cx = store
        .by_kind(kind::MIXIN_MOD_COMPLEXITY)
        .find(|f| f.subject == "beta")
        .expect("mod complexity fact for beta");
    assert!(mod_cx.attr_int("score").is_some_and(|s| s > 0));
    assert!(mod_cx.attr("components").is_some_and(|c| !c.is_empty()));

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn collector_uses_layer_b_active_artifact_role_for_mod_identity() {
    let root = temp_dir("canonical-role");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let jar = mods.join("display-name.jar");
    let class = fixtures::mixin_class(
        "canonical/mixin/TestMixin",
        "net/minecraft/server/MinecraftServer",
        &["Inject"],
    );
    write_mixin_jar(
        &jar,
        "descriptor-id-ignored-by-f",
        "canonical.mixins.json",
        "canonical.mixin",
        &[("TestMixin", class.as_slice())],
    );
    let target = Target {
        path: mods.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut inputs = FactStore::new();
    inputs
        .fact("metadata-scanner", kind::ARTIFACT_ROLE)
        .subject(jar.display().to_string())
        .attr("declared_id", "canonical-id")
        .attr("activation", "active")
        .attr("identity_certainty", "confirmed")
        .emit();
    let mut store = FactStore::new();
    let settings = DiagnosisSettings::default();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings: &settings,
    };
    collector().collect(&mut ctx);
    let config = store
        .by_kind(kind::MIXIN_CONFIG)
        .next()
        .expect("mixin config");
    assert_eq!(config.attr("mod"), Some("canonical-id"));
    assert_eq!(config.attr("identity_certainty"), Some("confirmed"));
    assert!(
        config
            .attr("artifact_id")
            .is_some_and(|id| id.starts_with("sha256:"))
    );
    std::fs::remove_dir_all(root).ok();
}
