use intermed_deps::{DependencyRule, ResolutionOutcome, resolve_store};
use intermed_doctor_core::facts::{FactStore, kind};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};

#[test]
fn single_wrong_version_deduplicates_global_unsat_finding() {
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
    let findings = DependencyRule.evaluate(&ctx).unwrap();
    assert!(!findings.iter().any(|f| f.id == "dependency-unsat:global"));
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
    let findings = DependencyRule.evaluate(&ctx).unwrap();
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("missing-dependency"))
    );
    assert!(!findings.iter().any(|f| f.id == "dependency-unsat:global"));
}

#[test]
fn any_compatible_alias_provider_satisfies_dependency() {
    let mut store = FactStore::new();
    for (id, version) in [
        ("consumer", "4.4.0"),
        ("old-bundle", "1.0.0"),
        ("new-bundle", "1.0.0"),
    ] {
        store
            .fact("meta", kind::MOD)
            .subject(id)
            .attr("version", version)
            .attr("loader", "fabric")
            .emit();
    }
    for (provider, version) in [
        ("old-bundle", "2.3.4+b3afc78b82"),
        ("new-bundle", "2.3.9+1802ada577"),
    ] {
        store
            .fact("meta", kind::PROVIDED_DEPENDENCY)
            .subject(provider)
            .attr("provides", "fabric-resource-conditions-api-v1")
            .attr("version", version)
            .attr("bundled", true)
            .emit();
    }
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("consumer")
        .attr("dep", "fabric-resource-conditions-api-v1")
        .attr("range", ">=2.3.8+1802ada577")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .attr("version_dialect", "fabric-extended-semver")
        .emit();

    assert!(matches!(
        resolve_store(&store).expect("resolve"),
        ResolutionOutcome::Satisfied { .. }
    ));
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

#[test]
fn fabric_loader_tagged_version_resolves_against_finite_catalog() {
    let mut store = FactStore::new();
    for (id, version) in [
        ("betterarcheology", "1.2.1-1.20.1"),
        ("yungsapi", "1.20-Fabric-4.0.6"),
    ] {
        store
            .fact("meta", kind::MOD)
            .subject(id)
            .attr("version", version)
            .attr("loader", "fabric")
            .emit();
    }
    store
        .fact("meta", kind::MOD_METADATA)
        .subject("yungsapi")
        .attr("version_raw", "1.20-Fabric-4.0.6")
        .attr("version_ambiguous", true)
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("betterarcheology")
        .attr("dep", "yungsapi")
        .attr("range", ">=1.20-Fabric-4.0.4")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .attr("version_dialect", "fabric-extended-semver")
        .emit();

    assert!(matches!(
        resolve_store(&store).expect("resolve"),
        ResolutionOutcome::Satisfied { .. }
    ));

    let target = test_target();
    let findings = DependencyRule
        .evaluate(&RuleCtx::for_test(&store, &target))
        .expect("dependency findings");
    assert!(findings.iter().all(|finding| {
        finding.id != "dependency-unsat:global"
            && !finding.id.starts_with("wrong-version:")
            && !finding.id.starts_with("version-undecidable:")
    }));
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
