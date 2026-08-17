use intermed_doctor_core::TargetCapabilities;
use intermed_doctor_core::assessment::assess_findings;
use intermed_doctor_core::evidence::{
    AssessmentDisposition, Category, CoverageGap, CoverageRequirement, CoverageState, EvidenceEdge,
    Finding, ProofKind, Severity,
};
use intermed_doctor_core::facts::{FactStore, kind};

fn complete_capabilities() -> TargetCapabilities {
    TargetCapabilities {
        authoritative_manifest: CoverageState::Complete,
        materialized_artifacts: CoverageState::Complete,
        loader_identity: CoverageState::Complete,
        minecraft_identity: CoverageState::Complete,
        mod_classpath: CoverageState::Complete,
        minecraft_classpath: CoverageState::Complete,
        loader_classpath: CoverageState::Complete,
        mappings: CoverageState::Complete,
        logs: CoverageState::Complete,
        configs: CoverageState::Complete,
        scripts: CoverageState::Complete,
        runtime_mutators: CoverageState::Complete,
        resource_blobs: CoverageState::Complete,
        datapacks: CoverageState::Complete,
        runtime_profile: CoverageState::Complete,
        vanilla_resources: CoverageState::Complete,
    }
}

fn hard_finding(requirements: &[CoverageRequirement]) -> Finding {
    let mut builder = Finding::builder("trust-corpus", "trust-corpus:case")
        .severity(Severity::Error)
        .category(Category::Dependency)
        .proof_kind(ProofKind::DeterministicDerivation)
        .title("candidate hard conclusion")
        .explanation("synthetic trust-corpus case");
    for requirement in requirements {
        builder = builder.coverage_requirement(*requirement);
    }
    builder.build()
}

#[test]
fn complete_provider_universe_allows_a_hard_dependency_conclusion() {
    let mut findings = vec![hard_finding(&[
        CoverageRequirement::CompletePack,
        CoverageRequirement::CompleteProviderUniverse,
    ])];
    assess_findings(
        &FactStore::new(),
        &complete_capabilities(),
        &mut findings,
        false,
    );
    assert_eq!(findings[0].severity, Severity::Error);
    assert_eq!(
        findings[0].assessment.disposition,
        AssessmentDisposition::Asserted
    );
}

#[test]
fn unknown_provider_universe_forces_structured_abstention() {
    let mut capabilities = complete_capabilities();
    capabilities.materialized_artifacts = CoverageState::Partial {
        gaps: vec![CoverageGap::new(
            "provider-version-unknown",
            "one plausible provider has no exact version",
        )],
    };
    let mut findings = vec![hard_finding(&[
        CoverageRequirement::CompletePack,
        CoverageRequirement::CompleteProviderUniverse,
    ])];
    assess_findings(&FactStore::new(), &capabilities, &mut findings, false);
    assert_eq!(findings[0].severity, Severity::Warn);
    assert_eq!(
        findings[0].assessment.disposition,
        AssessmentDisposition::Abstained
    );
    assert!(!findings[0].assessment.blockers.is_empty());
}

#[test]
fn ambiguous_runtime_bridge_blocks_loader_rejection() {
    let mut store = FactStore::new();
    store
        .fact("trust-corpus", kind::COMPATIBILITY_BRIDGE)
        .subject("connector")
        .attr("from_loader", "fabric")
        .attr("to_loader", "neoforge")
        .attr("scope", "mod-runtime")
        .emit();
    let mut findings = vec![hard_finding(&[
        CoverageRequirement::AuthoritativeLoader,
        CoverageRequirement::KnownBridgeSemantics,
    ])];
    assess_findings(&store, &complete_capabilities(), &mut findings, false);
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(
        findings[0]
            .assessment
            .blockers
            .iter()
            .any(|blocker| blocker.code == "bridge-compatibility-undecidable")
    );
}

#[test]
fn partial_mapping_abstains_from_mixin_absence() {
    let mut capabilities = complete_capabilities();
    capabilities.mappings = CoverageState::Partial {
        gaps: vec![CoverageGap::new(
            "mapping-edge-missing",
            "Yarn to Mojmap edge missing",
        )],
    };
    let mut findings = vec![hard_finding(&[
        CoverageRequirement::CompleteClasspath,
        CoverageRequirement::CompatibleMappings,
    ])];
    assess_findings(&FactStore::new(), &capabilities, &mut findings, false);
    assert_eq!(findings[0].severity, Severity::Warn);
    assert_eq!(
        findings[0].assessment.disposition,
        AssessmentDisposition::Abstained
    );
}

#[test]
fn non_terminal_error_cannot_be_a_hard_runtime_incident() {
    let mut store = FactStore::new();
    let signal = store
        .fact("trust-corpus", kind::LOG_SIGNAL)
        .subject("RuntimeException")
        .attr("event_id", "runtime-event:background")
        .attr("terminality", "recovered")
        .emit();
    let mut finding = hard_finding(&[
        CoverageRequirement::RuntimeEvidence,
        CoverageRequirement::TerminalRuntime,
    ]);
    finding.category = Category::Runtime;
    finding.evidence.push(EvidenceEdge::subject(signal));
    let mut findings = vec![finding];
    assess_findings(&store, &complete_capabilities(), &mut findings, false);
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(
        findings[0]
            .assessment
            .blockers
            .iter()
            .any(|blocker| blocker.code == "runtime-terminality-unconfirmed")
    );
}

#[test]
fn observed_runtime_mutator_blocks_static_resource_absence() {
    let mut store = FactStore::new();
    store
        .fact("trust-corpus", kind::MIXIN_RUNTIME_RESOURCE_MUTATION)
        .subject("dynamic-recipes")
        .attr("domain", "recipe")
        .emit();
    let mut findings = vec![hard_finding(&[
        CoverageRequirement::RelevantResources,
        CoverageRequirement::KnownRuntimeMutators,
    ])];
    assess_findings(&store, &complete_capabilities(), &mut findings, false);
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(
        findings[0]
            .assessment
            .blockers
            .iter()
            .any(|blocker| blocker.code == "runtime-mutator-coverage-unknown")
    );
}

#[test]
fn fatal_without_terminal_runtime_is_capped_to_error() {
    let mut finding = hard_finding(&[CoverageRequirement::CompletePack]);
    finding.severity = Severity::Fatal;
    let mut findings = vec![finding];
    assess_findings(
        &FactStore::new(),
        &complete_capabilities(),
        &mut findings,
        false,
    );
    assert_eq!(findings[0].severity, Severity::Error);
    assert!(
        findings[0]
            .assessment
            .adjustments
            .iter()
            .any(|adjustment| adjustment.code == "fatal-requires-terminal-runtime")
    );
}
