//! Provider (`provided_dependency`) declarations must be range-checked, not
//! treated as a blanket "satisfied". A bundled library that provides the wrong
//! version is a real problem, and one with an unknown version is only a hint.

use std::sync::LazyLock;

use intermed_deps::DependencyRule;
use intermed_doctor_core::evidence::{Impact, Severity};
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
        .attr("identity_certainty", "confirmed")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store)).unwrap();
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

#[test]
fn optional_out_of_range_provider_is_not_described_as_startup_blocking() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("consumer")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("consumer")
        .attr("dep", "optional-api")
        .attr("range", ">=5.8.0")
        .attr("mandatory", false)
        .attr("relation", "suggests")
        .emit();
    store
        .fact("meta", kind::PROVIDED_DEPENDENCY)
        .subject("compatibility-mod")
        .attr("provides", "optional-api")
        .attr("version", "4.6.1")
        .attr("identity_certainty", "confirmed")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store)).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding.id == "provided-version-mismatch:consumer->optional-api")
        .expect("optional version mismatch should remain reviewable");
    assert_eq!(finding.severity, Severity::Warn);
    assert_eq!(finding.proposed_impact, Impact::CompatibilityRisk);
    assert!(
        finding
            .explanation
            .contains("does not prevent the pack from starting")
    );
    assert!(!finding.explanation.contains("consumer requires"));
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
        .attr("identity_certainty", "confirmed")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store)).unwrap();
    assert!(
        !findings.iter().any(|f| f.id.contains("libfoo")),
        "in-range provider should satisfy the dependency: {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

/// Manifest aliases usually do not carry their own version; they inherit the
/// provider mod's installed version for dependency range checks.
#[test]
fn metadata_alias_inherits_provider_mod_version() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("moda")
        .attr("version", "1.0.0")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("fabric-api")
        .attr("version", "0.92.9")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("moda")
        .attr("dep", "fabric")
        .attr("range", ">=0.90.0")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();
    store
        .fact("meta", kind::PROVIDED_DEPENDENCY)
        .subject("fabric-api")
        .attr("provides", "fabric")
        .attr("scope", "metadata-alias")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store)).unwrap();
    assert!(
        !findings.iter().any(|f| f.id.contains("fabric")),
        "metadata alias should inherit provider mod version: {:?}",
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

    let findings = DependencyRule.evaluate(&ctx_from(&store)).unwrap();
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

    let findings = DependencyRule.evaluate(&ctx_from(&store)).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.id == "missing-dependency:moda->libfoo")
    );
}

#[test]
fn inactive_cross_loader_alias_cannot_satisfy_hard_dependency() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("consumer")
        .attr("version", "1.0.0")
        .attr("loader", "neoforge")
        .emit();
    store
        .fact("meta", kind::DEPENDENCY)
        .subject("consumer")
        .attr("dep", "bridge-api")
        .attr("range", ">=1.0.0")
        .attr("mandatory", true)
        .attr("relation", "depends")
        .emit();
    store
        .fact("meta", kind::PROVIDED_DEPENDENCY)
        .subject("fabric-candidate")
        .attr("provides", "bridge-api")
        .attr("version", "9.0.0")
        .attr("identity_certainty", "cross-loader-unresolved")
        .attr("activation", "descriptor-unresolved")
        .emit();

    let findings = DependencyRule.evaluate(&ctx_from(&store)).unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.id == "provided-version-unknown:consumer->bridge-api")
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.id == "missing-dependency:consumer->bridge-api")
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.severity == Severity::Error)
    );
}
