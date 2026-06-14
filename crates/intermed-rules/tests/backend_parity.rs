//! Parity tests: imperative wrappers vs declarative pack interpreter.

use intermed_doctor_core::facts::{kind, FactStore};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};
use intermed_rules::{
    DeclarativeRulePack, DuplicateIdRule, LoaderMismatchRule, SideMismatchRule,
};

fn ctx(store: &FactStore) -> RuleCtx<'_> {
    static TARGET: std::sync::LazyLock<Target> = std::sync::LazyLock::new(|| Target {
        path: ".".into(),
        kind: TargetKind::ModsDir,
        mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
        spark_report: None,
    });
    RuleCtx::for_test(store, &TARGET)
}

fn finding_ids(findings: &[intermed_doctor_core::evidence::Finding]) -> Vec<String> {
    findings.iter().map(|f| f.id.clone()).collect()
}

#[test]
fn declarative_pack_matches_imperative_wrappers() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("dupe")
        .attr("file", "a.jar")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("dupe")
        .attr("file", "b.jar")
        .emit();
    store
        .fact("env", kind::ENVIRONMENT)
        .subject("instance")
        .attr("loader", "fabric")
        .attr("side", "server")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("forge-mod")
        .attr("loader", "forge")
        .emit();
    store
        .fact("meta", kind::MOD_SIDE)
        .subject("client-mod")
        .attr("side", "client")
        .emit();

    let ctx = ctx(&store);
    let pack_ids = finding_ids(&DeclarativeRulePack::default_core().evaluate(&ctx));

    let mut imperative_ids = Vec::new();
    imperative_ids.extend(finding_ids(&DuplicateIdRule.evaluate(&ctx)));
    imperative_ids.extend(finding_ids(&LoaderMismatchRule.evaluate(&ctx)));
    imperative_ids.extend(finding_ids(&SideMismatchRule.evaluate(&ctx)));
    imperative_ids.sort();
    let mut pack_sorted = pack_ids;
    pack_sorted.sort();

    for id in &imperative_ids {
        assert!(pack_sorted.contains(id), "pack missing finding {id}");
    }
}