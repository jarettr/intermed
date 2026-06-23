use intermed_deps::DependencyRule;
use intermed_doctor_core::facts::{FactStore, SourceRef, kind};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};

#[test]
fn wrong_mc_version_for_two_component_instance() {
    let mut store = FactStore::new();
    store
        .fact("env", kind::ENVIRONMENT)
        .subject("instance")
        .attr("mc_version", "1.20")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("alpha")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("alpha")
        .attr("dep", "minecraft")
        .attr("range", ">=1.21")
        .attr("mandatory", true)
        .source(SourceRef::file("alpha.jar"))
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
    let findings = DependencyRule.evaluate(&ctx);
    assert!(findings.iter().any(|f| f.id == "wrong-mc-version:alpha"));
}

#[test]
fn missing_dependency_is_error() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("alpha")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("alpha")
        .attr("dep", "fabric-api")
        .attr("range", ">=0.90.0")
        .attr("mandatory", true)
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
    let findings = DependencyRule.evaluate(&ctx);
    assert!(
        findings
            .iter()
            .any(|f| f.id == "missing-dependency:alpha->fabric-api")
    );
}

#[test]
fn wrong_version_with_fabric_space_and_range() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("alpha")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("fabric-api")
        .attr("version", "0.12.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("alpha")
        .attr("dep", "fabric-api")
        .attr("range", ">=0.11.6 <0.12.0")
        .attr("mandatory", true)
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
    let findings = DependencyRule.evaluate(&ctx);
    assert!(
        findings
            .iter()
            .any(|f| f.id == "wrong-version:alpha->fabric-api")
    );
}

#[test]
fn snapshot_mc_version_is_undecidable() {
    let mut store = FactStore::new();
    store
        .fact("env", kind::ENVIRONMENT)
        .subject("instance")
        .attr("mc_version", "23w31a")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("alpha")
        .attr("dep", "minecraft")
        .attr("range", ">=1.20")
        .attr("mandatory", true)
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
    let findings = DependencyRule.evaluate(&ctx);
    assert!(findings.is_empty());
}
