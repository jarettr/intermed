//! Layer-C checks for NeoForge `type`-aware dependency facts from Layer B.

use std::sync::LazyLock;

use intermed_deps::DependencyRule;
use intermed_doctor_core::evidence::Severity;
use intermed_doctor_core::facts::{FactStore, kind};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};

fn test_target() -> &'static Target {
    static TARGET: LazyLock<Target> = LazyLock::new(|| Target {
        path: ".".into(),
        kind: TargetKind::ModsDir,
        mods_dir: None,
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    });
    &TARGET
}

fn ctx_from(store: &FactStore) -> RuleCtx<'_> {
    RuleCtx::for_test(store, test_target())
}

#[test]
fn optional_and_incompatible_absent_mods_do_not_emit_missing_dependency() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("create")
        .attr("version", "6.0.10")
        .emit();
    for (dep, mandatory, relation) in [
        ("sodium", false, "recommends"),
        ("lithium", false, "recommends"),
        ("radium", false, "breaks"),
        ("palladium", false, "breaks"),
    ] {
        store
            .fact("meta", kind::DEPENDENCY)
            .subject("create")
            .attr("dep", dep)
            .attr("range", "*")
            .attr("mandatory", mandatory)
            .attr("relation", relation)
            .emit();
    }

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("missing-dependency:create->")),
        "optional/incompatible deps must not surface as missing: {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("incompatible-mod:create->")),
        "incompatible deps absent from the pack must stay silent"
    );
}

#[test]
fn incompatible_mod_present_emits_error() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("create")
        .attr("version", "6.0.10")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("radium")
        .attr("version", "0.12.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("create")
        .attr("dep", "radium")
        .attr("range", "*")
        .attr("mandatory", false)
        .attr("relation", "breaks")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    let conflict = findings
        .iter()
        .find(|f| f.id == "incompatible-mod:create->radium")
        .expect("incompatible installed mod");
    assert_eq!(conflict.severity, Severity::Error);
}

#[test]
fn discouraged_mod_present_emits_warn_not_missing() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("create")
        .attr("version", "6.0.10")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("legacyopt")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("create")
        .attr("dep", "legacyopt")
        .attr("range", "*")
        .attr("mandatory", false)
        .attr("relation", "discouraged")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("missing-dependency:")),
        "discouraged is not a hard requirement"
    );
    let warn = findings
        .iter()
        .find(|f| f.id == "discouraged-dependency:create->legacyopt")
        .expect("discouraged installed mod");
    assert_eq!(warn.severity, Severity::Warn);
}

#[test]
fn loadbefore_absent_target_is_not_a_missing_dependency() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::PLUGIN)
        .subject("myplugin")
        .attr("version", "1.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("myplugin")
        .attr("dep", "OtherPlugin")
        .attr("range", "*")
        .attr("mandatory", true) // plugin.yml loadbefore is marked mandatory
        .attr("relation", "loadbefore")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("missing-dependency:")),
        "loadbefore is an ordering hint, never a missing dependency: {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn optional_wrong_version_is_warn_not_error() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("create")
        .attr("version", "6.0")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("sodium")
        .attr("version", "0.4.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("create")
        .attr("dep", "sodium")
        .attr("range", ">=0.5")
        .attr("mandatory", false)
        .attr("relation", "recommends")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    let wrong = findings
        .iter()
        .find(|f| f.id == "wrong-version:create->sodium")
        .expect("optional wrong-version still reported");
    assert_eq!(
        wrong.severity,
        Severity::Warn,
        "optional integration mismatch is not pack-breaking"
    );
}

#[test]
fn mandatory_wrong_version_stays_error() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("create")
        .attr("version", "6.0")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("flywheel")
        .attr("version", "0.6.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("create")
        .attr("dep", "flywheel")
        .attr("range", ">=1.0")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    let wrong = findings
        .iter()
        .find(|f| f.id == "wrong-version:create->flywheel")
        .expect("mandatory wrong-version reported");
    assert_eq!(wrong.severity, Severity::Error);
}

#[test]
fn discouraged_out_of_range_stays_silent() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("a")
        .attr("version", "1.0")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("b")
        .attr("version", "2.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("a")
        .attr("dep", "b")
        .attr("range", "<1.0") // b 2.0 is outside the discouraged range
        .attr("mandatory", false)
        .attr("relation", "discouraged")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("discouraged-dependency:")),
        "discouraged only fires inside its declared range"
    );
}

#[test]
fn java_and_loader_platform_version_constraints_are_checked() {
    let mut store = FactStore::new();
    store
        .fact("env", kind::ENVIRONMENT)
        .attr("loader", "fabric")
        .attr("loader_version", "0.14.9")
        .attr("mc_version", "1.20.1")
        .emit();
    store
        .fact("env", kind::JAVA_RUNTIME)
        .attr("version", "17.0.2")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("modern")
        .attr("version", "1.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("modern")
        .attr("dep", "fabricloader")
        .attr("range", ">=0.15")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("modern")
        .attr("dep", "java")
        .attr("range", ">=21")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    assert!(
        findings
            .iter()
            .any(|f| f.id == "wrong-loader-version:modern->fabricloader"),
        "fabricloader 0.14.9 < 0.15 must be flagged: {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    assert!(
        findings.iter().any(|f| f.id == "wrong-java-version:modern"),
        "java 17 < 21 must be flagged"
    );
}

#[test]
fn platform_constraints_silent_without_known_versions() {
    // No loader_version / java_runtime → cannot decide → never a false positive.
    let mut store = FactStore::new();
    store
        .fact("env", kind::ENVIRONMENT)
        .attr("loader", "fabric")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("m")
        .attr("version", "1.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("m")
        .attr("dep", "fabricloader")
        .attr("range", ">=0.15")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();
    let findings = DependencyRule.evaluate(&ctx_from(&store));
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("wrong-loader-version:"))
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("missing-dependency:m->fabricloader"))
    );
}

#[test]
fn duplicate_dependency_version_check_is_lenient_and_flagged() {
    let mut store = FactStore::new();
    // Two versions of the same id installed (a real duplicate-id situation).
    store
        .fact("meta", kind::MOD)
        .subject("lib")
        .attr("version", "1.0")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("lib")
        .attr("version", "2.0")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("consumer")
        .attr("version", "1.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("consumer")
        .attr("dep", "lib")
        .attr("range", ">=2.0") // satisfied by the 2.0 copy
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    assert!(
        !findings
            .iter()
            .any(|f| f.id == "wrong-version:consumer->lib"),
        "any installed version in range satisfies — no false wrong-version with a duplicate id"
    );
}
