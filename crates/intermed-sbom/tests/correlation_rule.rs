//! Cross-layer rule: low provenance (Layer H) + dangerous capability (Layer G).

use intermed_doctor_core::facts::{kind, FactStore};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};
use intermed_sbom::correlation_rule;

fn dummy_target() -> Target {
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

/// Emit an SBOM fact (carrying the trust score) and a high-risk security fact
/// for the same archive, mirroring what the two collectors produce.
fn store_with(archive: &str, mod_id: &str, trust: i64, capability: &str) -> FactStore {
    let mut store = FactStore::new();
    store
        .fact("sbom-generator", kind::SBOM)
        .subject(archive)
        .attr("trust_score", trust)
        .attr("source_class", "unidentified")
        .emit();
    store
        .fact("security-scanner", capability)
        .subject(mod_id)
        .attr("archive", archive)
        .emit();
    store
}

#[test]
fn low_trust_plus_dangerous_capability_correlates() {
    let store = store_with("mystery.jar", "mystery", 20, kind::USES_PROCESS_SPAWN);
    let target = dummy_target();
    let findings = correlation_rule().evaluate(&RuleCtx::for_test(&store, &target));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "low-trust-capability:mystery.jar");
    assert_eq!(
        findings[0].severity,
        intermed_doctor_core::evidence::Severity::Warn
    );
    assert!(findings[0].explanation.contains("process spawn"));
    assert!(findings[0].machine_tags.iter().any(|t| t == "supply-chain"));
}

#[test]
fn well_identified_jar_is_not_correlated() {
    // A trusted (fully identified) jar with the same capability is left to the
    // plain security rule — no supply-chain escalation.
    let store = store_with("sodium.jar", "sodium", 90, kind::USES_PROCESS_SPAWN);
    let target = dummy_target();
    let findings = correlation_rule().evaluate(&RuleCtx::for_test(&store, &target));
    assert!(findings.is_empty());
}

#[test]
fn low_trust_without_dangerous_capability_is_not_correlated() {
    // Low trust alone (no high-risk capability) is the plain provenance rule's
    // job, not this correlation.
    let mut store = FactStore::new();
    store
        .fact("sbom-generator", kind::SBOM)
        .subject("mystery.jar")
        .attr("trust_score", 20i64)
        .attr("source_class", "unidentified")
        .emit();
    let target = dummy_target();
    let findings = correlation_rule().evaluate(&RuleCtx::for_test(&store, &target));
    assert!(findings.is_empty());
}

#[test]
fn multiple_capabilities_are_merged_into_one_finding() {
    let mut store = store_with("mystery.jar", "mystery", 20, kind::USES_PROCESS_SPAWN);
    store
        .fact("security-scanner", kind::USES_UNSAFE)
        .subject("mystery")
        .attr("archive", "mystery.jar")
        .emit();
    let target = dummy_target();
    let findings = correlation_rule().evaluate(&RuleCtx::for_test(&store, &target));

    assert_eq!(findings.len(), 1, "one finding per archive");
    assert!(findings[0].explanation.contains("process spawn"));
    assert!(findings[0].explanation.contains("sun.misc.Unsafe"));
}
