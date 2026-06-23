//! Provider (`provided_dependency`) declarations must be range-checked, not
//! treated as a blanket "satisfied". A bundled library that provides the wrong
//! version is a real problem, and one with an unknown version is only a hint.

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

/// Mod A requires libfoo >= 2.0; B provides libfoo 1.0 → must NOT be silent.
#[test]
fn provider_with_out_of_range_version_is_flagged() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("moda")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("moda")
        .attr("dep", "libfoo")
        .attr("range", ">=2.0.0")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();
    store
        .fact("meta", kind::PROVIDED_DEPENDENCY)
        .subject("modb")
        .attr("provides", "libfoo")
        .attr("version", "1.0.0")
        .attr("bundled", true)
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    let f = findings
        .iter()
        .find(|f| f.id == "provided-version-mismatch:moda->libfoo")
        .expect("out-of-range provider must be flagged");
    assert_eq!(f.severity, Severity::Error);
    // Old behaviour would have emitted neither this nor missing-dependency.
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("missing-dependency:"))
    );
}

/// Provider supplies an in-range version → requirement satisfied, stays silent.
#[test]
fn provider_with_in_range_version_satisfies() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("moda")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("moda")
        .attr("dep", "libfoo")
        .attr("range", ">=2.0.0")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();
    store
        .fact("meta", kind::PROVIDED_DEPENDENCY)
        .subject("modb")
        .attr("provides", "libfoo")
        .attr("version", "2.3.0")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    assert!(
        !findings.iter().any(|f| f.id.contains("libfoo")),
        "in-range provider should satisfy the dependency: {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

/// Provider exists but declares no version → low-confidence warning, not error.
#[test]
fn provider_with_unknown_version_is_a_soft_warning() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("moda")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("moda")
        .attr("dep", "libfoo")
        .attr("range", ">=2.0.0")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();
    store
        .fact("meta", kind::PROVIDED_DEPENDENCY)
        .subject("modb")
        .attr("provides", "libfoo")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    let f = findings
        .iter()
        .find(|f| f.id == "provided-version-unknown:moda->libfoo")
        .expect("unknown-version provider should warn");
    assert_eq!(f.severity, Severity::Warn);
    assert!(
        f.confidence < 0.9,
        "unknown provider should lower confidence"
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.id.starts_with("missing-dependency:"))
    );
}

/// No provider at all → classic missing-dependency error (unchanged).
#[test]
fn absent_provider_still_missing() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("moda")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("moda")
        .attr("dep", "libfoo")
        .attr("range", ">=2.0.0")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store));
    assert!(
        findings
            .iter()
            .any(|f| f.id == "missing-dependency:moda->libfoo")
    );
}
