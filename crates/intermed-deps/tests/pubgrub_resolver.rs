use intermed_deps::{DependencyRule, ResolutionOutcome, resolve_store};
use intermed_doctor_core::facts::{FactStore, kind};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};

#[test]
fn global_unsat_finding_emitted() {
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

    let outcome = resolve_store(&store).expect("resolve");
    assert!(matches!(outcome, ResolutionOutcome::Unsatisfiable { .. }));

    let target = test_target();
    let ctx = RuleCtx::for_test(&store, &target);
    let findings = DependencyRule.evaluate(&ctx);
    assert!(findings.iter().any(|f| f.id == "dependency-unsat:global"));
    assert!(
        findings
            .iter()
            .any(|f| f.id == "wrong-version:alpha->fabric-api")
    );
}

#[test]
fn provides_alias_satisfies_dependency() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("alpha")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("unofficial-fapi")
        .attr("version", "0.90.0")
        .emit();
    store
        .fact("meta", kind::PROVIDED_DEPENDENCY)
        .subject("unofficial-fapi")
        .attr("provides", "fabric-api")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("alpha")
        .attr("dep", "fabric-api")
        .attr("range", ">=0.90.0")
        .attr("mandatory", true)
        .emit();

    let outcome = resolve_store(&store).expect("resolve");
    assert!(matches!(outcome, ResolutionOutcome::Satisfied { .. }));

    let target = test_target();
    let ctx = RuleCtx::for_test(&store, &target);
    let findings = DependencyRule.evaluate(&ctx);
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("missing-dependency"))
    );
    assert!(!findings.iter().any(|f| f.id == "dependency-unsat:global"));
}

#[test]
fn missing_dependency_is_unsatisfiable() {
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

    let outcome = resolve_store(&store).expect("resolve");
    assert!(matches!(outcome, ResolutionOutcome::Unsatisfiable { .. }));
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
