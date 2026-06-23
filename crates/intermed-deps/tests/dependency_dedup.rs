use intermed_deps::DependencyRule;
use intermed_doctor_core::facts::{FactStore, kind};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};

#[test]
fn pubgrub_unsat_suppressed_when_pairwise_missing_dependency_exists() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("iris")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("iris")
        .attr("dep", "sodium")
        .attr("range", ">=0.5.0")
        .attr("mandatory", true)
        .emit();

    let target = test_target();
    let ctx = RuleCtx::for_test(&store, &target);
    let findings = DependencyRule.evaluate(&ctx);
    assert!(
        findings
            .iter()
            .any(|f| f.id == "missing-dependency:iris->sodium")
    );
    assert!(!findings.iter().any(|f| f.id == "dependency-unsat:global"));
}

fn test_target() -> Target {
    Target {
        path: ".".into(),
        kind: TargetKind::ModsDir,
        mods_dir: None,
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    }
}
