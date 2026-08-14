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
    let findings = DependencyRule.evaluate(&ctx).unwrap();
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
    let findings = DependencyRule.evaluate(&ctx).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.id == "missing-dependency:alpha->fabric-api")
    );
}

#[test]
fn dependency_from_undecidable_descriptor_is_context_not_error() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("dual-loader-artifact")
        .attr("version", "1.0.0")
        .attr("loader", "fabric")
        .attr("identity_certainty", "undecidable")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("dual-loader-artifact")
        .attr("dep", "fabric-api")
        .attr("range", "*")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .attr("identity_certainty", "undecidable")
        .emit();

    let target = Target::with_kind(".", TargetKind::ModsDir);
    let findings = DependencyRule
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();
    assert!(
        findings
            .iter()
            .all(|finding| { finding.severity != intermed_doctor_core::evidence::Severity::Error })
    );
    assert!(findings.iter().any(|finding| {
        finding.id == "dependency-identity-undecidable:dual-loader-artifact->fabric-api"
    }));
    assert!(!matches!(
        intermed_deps::resolve_store(&store).unwrap(),
        intermed_deps::ResolutionOutcome::Unsatisfiable { .. }
    ));
}

#[test]
fn plausible_legacy_provider_prevents_definite_absence_claim() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("enhancedvisuals")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("enhancedvisuals")
        .attr("dep", "creativecore")
        .attr("range", "*")
        .attr("mandatory", true)
        .emit();
    store
        .fact("sbom", kind::CHECKSUM)
        .subject("CreativeCore_v1.10.71_mc1.12.2.jar")
        .attr("sha256", "00")
        .emit();

    let target = Target::with_kind(".", TargetKind::ModsDir);
    let findings = DependencyRule
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();
    assert!(
        findings
            .iter()
            .all(|finding| finding.id != "missing-dependency:enhancedvisuals->creativecore")
    );
    let unresolved = findings
        .iter()
        .find(|finding| finding.id == "provider-identity-unresolved:enhancedvisuals->creativecore")
        .expect("plausible physical artifact must remain visible");
    assert_eq!(
        unresolved.severity,
        intermed_doctor_core::evidence::Severity::Warn
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
    let findings = DependencyRule.evaluate(&ctx).unwrap();
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
    let findings = DependencyRule.evaluate(&ctx).unwrap();
    assert!(findings.is_empty());
}

#[test]
fn game_prefixed_mod_version_is_undecidable_not_wrong() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("addon")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("aether")
        .attr("version", "1.20.1-1.5.2-neoforge")
        .emit();
    store
        .fact("meta", kind::MOD_METADATA)
        .subject("aether")
        .attr("version_raw", "1.20.1-1.5.2-neoforge")
        .attr("version_ambiguous", true)
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("addon")
        .attr("dep", "aether")
        .attr("range", "[1.0.0,)")
        .attr("mandatory", true)
        .emit();

    let target = Target::with_kind(".", TargetKind::ModsDir);
    let findings = DependencyRule
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();
    assert!(
        findings
            .iter()
            .all(|finding| !finding.id.starts_with("wrong-version:"))
    );
    let undecidable = findings
        .iter()
        .find(|finding| finding.id == "version-undecidable:addon->aether")
        .expect("ambiguous versions remain visible without a false error");
    assert_eq!(
        undecidable.severity,
        intermed_doctor_core::evidence::Severity::Note
    );
    assert!(
        undecidable
            .machine_tags
            .iter()
            .any(|tag| tag == "ambiguous-version")
    );
}

#[test]
fn fabric_extended_semver_accepts_newer_core_prerelease_builds() {
    let mut store = FactStore::new();
    for (id, version) in [
        ("bettercombat", "1.0.0"),
        ("combatroll", "1.0.0"),
        ("spell_engine", "1.0.0"),
        ("archers_expansion", "1.0.0"),
        ("forcemaster_rpg", "1.0.0"),
        ("player-animator", "1.0.2-rc1+1.20"),
        ("more_rpg_classes", "1.2.19-1.20.1"),
    ] {
        store
            .fact("meta", kind::MOD)
            .subject(id)
            .attr("version", version)
            .attr("loader", "fabric")
            .emit();
    }
    for (from, to, range) in [
        ("bettercombat", "player-animator", ">=1.0.0"),
        ("combatroll", "player-animator", ">=1.0.0"),
        ("spell_engine", "player-animator", ">=0.9.9"),
        ("archers_expansion", "more_rpg_classes", ">=1.2.6-1.20.1"),
        ("forcemaster_rpg", "more_rpg_classes", ">=1.1.8"),
    ] {
        store
            .fact("meta", kind::DEPENDENCY)
            .subject(from)
            .attr("dep", to)
            .attr("range", range)
            .attr("mandatory", true)
            .attr("relation", "depends")
            .attr("version_dialect", "fabric-extended-semver")
            .emit();
    }

    let target = Target::with_kind(".", TargetKind::ModsDir);
    let findings = DependencyRule
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();
    assert!(
        findings.iter().all(|finding| {
            !finding.id.starts_with("wrong-version:") && finding.id != "dependency-unsat:global"
        }),
        "Fabric-valid Prominence constraints must not become errors: {findings:#?}"
    );
    assert!(matches!(
        intermed_deps::resolve_store(&store).unwrap(),
        intermed_deps::ResolutionOutcome::Satisfied { .. }
    ));
}
