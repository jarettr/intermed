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
    let settings = DiagnosisSettings::default();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
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
