//! Cross-layer rule: low provenance (Layer H) + dangerous capability (Layer G).

use intermed_doctor_core::facts::{FactStore, kind};
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
    let artifact_id = format!(
        "sha256:{}",
        if archive.starts_with('s') { "b" } else { "a" }.repeat(64)
    );
    let mut store = FactStore::new();
    store
        .fact("sbom-generator", kind::SBOM)
        .subject(artifact_id.clone())
        .attr("archive", archive)
        .attr("trust_score", trust)
        .attr("source_class", "unidentified")
        .emit();
    store
        .fact("security-scanner", capability)
        .subject(mod_id)
        .attr("archive", archive)
        .attr("artifact_id", artifact_id)
        .emit();
    store
}

#[test]
fn low_trust_plus_dangerous_capability_correlates() {
    let store = store_with("mystery.jar", "mystery", 20, kind::USES_PROCESS_SPAWN);
    let target = dummy_target();
    let findings = correlation_rule()
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();

    assert_eq!(findings.len(), 1);
    assert!(findings[0].id.starts_with("low-trust-capability:sha256:"));
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
    let findings = correlation_rule()
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();
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
    let findings = correlation_rule()
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();
    assert!(findings.is_empty());
}

#[test]
fn only_shared_high_risk_capabilities_are_correlated() {
    let mut store = store_with("mystery.jar", "mystery", 20, kind::USES_PROCESS_SPAWN);
    let artifact_id = store
        .by_kind(kind::SBOM)
        .next()
        .unwrap()
        .subject
        .to_string();
    store
        .fact("security-scanner", kind::USES_UNSAFE)
        .subject("mystery")
        .attr("archive", "mystery.jar")
        .attr("artifact_id", artifact_id)
        .emit();
    let target = dummy_target();
    let findings = correlation_rule()
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();

    assert_eq!(findings.len(), 1, "one finding per archive");
    assert!(findings[0].explanation.contains("process spawn"));
    assert!(!findings[0].explanation.contains("sun.misc.Unsafe"));
}

#[test]
fn parser_failure_does_not_amplify_security_signal() {
    let mut store = FactStore::new();
    store
        .fact("sbom-generator", kind::SBOM)
        .subject(format!("sha256:{}", "c".repeat(64)))
        .attr("archive", "broken-metadata.jar")
        .attr("trust_score", 20i64)
        .attr("identity_status", "parse-failed")
        .attr("trust_base", 20i64)
        .emit();
    store
        .fact("security-scanner", kind::USES_PROCESS_SPAWN)
        .subject("mod")
        .attr("archive", "broken-metadata.jar")
        .attr("artifact_id", format!("sha256:{}", "c".repeat(64)))
        .emit();
    let target = dummy_target();
    let findings = correlation_rule()
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].severity,
        intermed_doctor_core::evidence::Severity::Note
    );
    assert!(
        findings[0]
            .machine_tags
            .iter()
            .any(|tag| tag == "identity-analysis-incomplete")
    );
}

#[test]
fn same_basename_from_another_root_does_not_cross_correlate() {
    let low_id = format!("sha256:{}", "d".repeat(64));
    let risky_id = format!("sha256:{}", "e".repeat(64));
    let mut store = FactStore::new();
    store
        .fact("sbom-generator", kind::SBOM)
        .subject(low_id)
        .attr("archive", "same.jar")
        .attr("source_locator", "/instance/mods/same.jar")
        .attr("trust_score", 20i64)
        .emit();
    store
        .fact("security-scanner", kind::USES_PROCESS_SPAWN)
        .subject("plugin")
        .attr("artifact_id", risky_id)
        .attr("archive", "same.jar")
        .attr("source_locator", "/instance/plugins/same.jar")
        .emit();

    let target = dummy_target();
    let findings = correlation_rule()
        .evaluate(&RuleCtx::for_test(&store, &target))
        .unwrap();
    assert!(findings.is_empty());
}

#[test]
fn typed_provenance_policy_outranks_display_score() {
    let artifact_id = format!("sha256:{}", "f".repeat(64));
    let mut store = FactStore::new();
    store
        .fact("sbom-generator", kind::SBOM)
        .subject(artifact_id.clone())
        .attr("archive", "opaque.jar")
        .attr("trust_score", 100i64)
        .attr("identity_status", "no-recognizable-manifest")
        .attr("identity_completeness", "unresolved")
        .attr("distribution_provenance", "unknown")
        .attr("exact_materialization", "unpinned")
        .attr("provenance_correlation_eligible", true)
        .emit();
    store
        .fact("security-scanner", kind::USES_PROCESS_SPAWN)
        .subject("opaque")
        .attr("artifact_id", artifact_id)
        .attr("archive", "opaque.jar")
        .emit();

    let target = dummy_target();
    assert_eq!(
        correlation_rule()
            .evaluate(&RuleCtx::for_test(&store, &target))
            .unwrap()
            .len(),
        1
    );
}
