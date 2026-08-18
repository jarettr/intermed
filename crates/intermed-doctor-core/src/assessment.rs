//! Central trust-contract evaluation for findings.

use intermed_evidence::{
    AssessmentDisposition, CertaintyTier, ConclusionAdjustment, CoverageAssessment,
    CoverageRequirement, EvidenceOrigin, Finding, FindingAssessment, Impact, PrerequisiteFailure,
    PrerequisiteResult, ProofKind, Severity,
};
use intermed_facts::{FactStore, kind};

use crate::TargetCapabilities;

pub fn assess_findings(
    store: &FactStore,
    capabilities: &TargetCapabilities,
    findings: &mut [Finding],
    incremental: bool,
) {
    for finding in findings {
        let prior_assessment = finding.assessment.clone();
        let proposed = finding.severity;
        let proof_kind = finding.proof_kind.unwrap_or(ProofKind::Heuristic);
        let impact = if finding.proposed_impact == Impact::Informational {
            if prior_assessment.impact != Impact::Informational {
                prior_assessment.impact
            } else {
                default_impact(finding)
            }
        } else {
            finding.proposed_impact
        };
        let mut assessment = FindingAssessment {
            disposition: AssessmentDisposition::Asserted,
            impact,
            certainty: certainty_for(finding.confidence, proof_kind),
            proof_kind,
            provenance: if finding.evidence_origins.is_empty() {
                default_provenance(proof_kind)
            } else {
                finding.evidence_origins.clone()
            },
            ..FindingAssessment::default()
        };
        assessment.adjustments = prior_assessment.adjustments;
        assessment.blockers = prior_assessment.blockers;
        if prior_assessment.disposition == AssessmentDisposition::Downgraded {
            assessment.disposition = AssessmentDisposition::Downgraded;
        }

        if finding.evidence.iter().any(|edge| {
            store
                .get(edge.fact)
                .is_some_and(|fact| fact.kind == kind::SCAN_TRUNCATED)
        }) {
            assessment.blockers.push(PrerequisiteFailure {
                code: "collector-reported-incomplete".to_string(),
                requirement: CoverageRequirement::LocalArtifact,
                detail: "the cited collector explicitly reported truncated or unavailable input"
                    .to_string(),
            });
        }

        for requirement in finding.coverage_requirements.iter().copied() {
            let (region, state) = if requirement == CoverageRequirement::CompleteClasspath {
                let minecraft_target = finding.evidence.iter().any(|edge| {
                    store.get(edge.fact).is_some_and(|fact| {
                        fact.attr("target")
                            .or_else(|| fact.attr("target_class"))
                            .is_some_and(|target| {
                                let target = target.replace('.', "/");
                                target.starts_with("net/minecraft/")
                                    || target.starts_with("com/mojang/")
                            })
                    })
                });
                if minecraft_target {
                    ("minecraft-classpath", &capabilities.minecraft_classpath)
                } else {
                    ("mod-classpath", &capabilities.mod_classpath)
                }
            } else {
                capabilities.for_requirement(requirement)
            };
            assessment.coverage.push(CoverageAssessment {
                region: region.to_string(),
                state: state.clone(),
            });
            let (satisfied, detail, code) = evaluate_requirement(
                store,
                finding,
                requirement,
                state.is_complete(),
                incremental,
            );
            assessment.prerequisites.push(PrerequisiteResult {
                requirement,
                satisfied,
                detail: detail.clone(),
            });
            if !satisfied {
                assessment.blockers.push(PrerequisiteFailure {
                    code,
                    requirement,
                    detail,
                });
            }
        }

        // Every strong conclusion must opt into the typed contract. A rule that
        // proposes Error/Fatal without proof and coverage prerequisites cannot
        // silently bypass the release's central safety policy.
        if matches!(proposed, Severity::Error | Severity::Fatal) {
            if finding.proof_kind.is_none() {
                assessment.blockers.push(PrerequisiteFailure {
                    code: "strong-conclusion-has-no-proof-kind".to_string(),
                    requirement: CoverageRequirement::LocalArtifact,
                    detail: "the producing rule did not declare a proof kind".to_string(),
                });
            }
            if finding.coverage_requirements.is_empty() {
                assessment.blockers.push(PrerequisiteFailure {
                    code: "strong-conclusion-has-no-coverage-contract".to_string(),
                    requirement: CoverageRequirement::LocalArtifact,
                    detail: "the producing rule did not declare required coverage".to_string(),
                });
            }
            if assessment.certainty != CertaintyTier::Confirmed {
                assessment.blockers.push(PrerequisiteFailure {
                    code: "strong-conclusion-certainty-below-confirmed".to_string(),
                    requirement: CoverageRequirement::LocalArtifact,
                    detail: format!(
                        "the declared proof and evidence confidence support {:?}, not confirmed certainty",
                        assessment.certainty
                    ),
                });
            }
        }

        if proposed == Severity::Fatal
            && !finding
                .coverage_requirements
                .contains(&CoverageRequirement::TerminalRuntime)
        {
            finding.severity = Severity::Error;
            assessment.disposition = AssessmentDisposition::Downgraded;
            assessment.adjustments.push(ConclusionAdjustment {
                code: "fatal-requires-terminal-runtime".to_string(),
                detail: "Fatal is reserved for conclusions backed by terminal runtime evidence"
                    .to_string(),
                original_disposition: Some(AssessmentDisposition::Asserted),
                final_disposition: Some(AssessmentDisposition::Downgraded),
                from_severity: Some(Severity::Fatal),
                to_severity: Some(Severity::Error),
                contradicting_evidence: Vec::new(),
            });
        }

        if !assessment.blockers.is_empty() {
            if assessment.disposition != AssessmentDisposition::Downgraded {
                assessment.disposition = AssessmentDisposition::Abstained;
            }
            assessment.certainty = if assessment.coverage.iter().any(|coverage| {
                matches!(
                    coverage.state,
                    intermed_evidence::CoverageState::Unavailable { .. }
                )
            }) {
                CertaintyTier::Unavailable
            } else {
                CertaintyTier::Undecidable
            };
            if matches!(finding.severity, Severity::Fatal | Severity::Error) {
                finding.severity = Severity::Warn;
                finding.confidence = finding.confidence.min(0.65);
                assessment.adjustments.push(ConclusionAdjustment {
                    code: "hard-error-gated".to_string(),
                    detail: "one or more declared prerequisites were not met".to_string(),
                    original_disposition: Some(AssessmentDisposition::Asserted),
                    final_disposition: Some(assessment.disposition),
                    from_severity: Some(proposed),
                    to_severity: Some(Severity::Warn),
                    contradicting_evidence: Vec::new(),
                });
            }
            if !finding
                .machine_tags
                .iter()
                .any(|tag| tag == "why-not-error")
            {
                finding.machine_tags.push("why-not-error".to_string());
            }
        }

        let mut seen_blockers = std::collections::BTreeSet::new();
        assessment.blockers.retain(|blocker| {
            seen_blockers.insert((
                blocker.code.clone(),
                blocker.requirement,
                blocker.detail.clone(),
            ))
        });
        let mut seen_adjustments = std::collections::BTreeSet::new();
        assessment.adjustments.retain(|adjustment| {
            seen_adjustments.insert((
                adjustment.code.clone(),
                adjustment.detail.clone(),
                adjustment.from_severity,
                adjustment.to_severity,
            ))
        });
        let mut seen_coverage = Vec::new();
        assessment.coverage.retain(|coverage| {
            if seen_coverage.contains(coverage) {
                false
            } else {
                seen_coverage.push(coverage.clone());
                true
            }
        });

        finding.assessment = assessment;
    }
}

fn evaluate_requirement(
    store: &FactStore,
    finding: &Finding,
    requirement: CoverageRequirement,
    capability_complete: bool,
    incremental: bool,
) -> (bool, String, String) {
    if incremental
        && matches!(
            requirement,
            CoverageRequirement::CompletePack
                | CoverageRequirement::CompleteProviderUniverse
                | CoverageRequirement::RelevantResources
        )
    {
        return (
            false,
            "incremental input does not cover the whole target".to_string(),
            "incremental-input-is-partial".to_string(),
        );
    }
    match requirement {
        CoverageRequirement::TerminalRuntime => {
            let terminal = finding.evidence.iter().any(|edge| {
                store.get(edge.fact).is_some_and(|fact| {
                    fact.kind == kind::CRASH_ANCHOR
                        || (fact.kind == kind::LOG_SIGNAL
                            && fact.attr("event_id").is_some_and(|event_id| {
                                store
                                    .by_kind(kind::CRASH_ANCHOR)
                                    .any(|anchor| anchor.subject == event_id)
                            }))
                })
            });
            (
                terminal,
                if terminal {
                    "terminal runtime evidence is present"
                } else {
                    "no terminal/abort evidence supports this runtime conclusion"
                }
                .to_string(),
                "runtime-terminality-unconfirmed".to_string(),
            )
        }
        CoverageRequirement::ActiveDescriptor => {
            let evidence = finding
                .evidence
                .iter()
                .filter_map(|edge| store.get(edge.fact))
                .collect::<Vec<_>>();
            let undecidable = evidence.iter().any(|fact| {
                fact.attr("identity_certainty") == Some("undecidable")
                    || fact.attr_bool("active_for_instance") == Some(false)
            });
            let explicitly_active = evidence.iter().any(|fact| {
                fact.attr("identity_certainty") == Some("confirmed")
                    || fact.attr_bool("active_for_instance") == Some(true)
            });
            (
                capability_complete && explicitly_active && !undecidable,
                if undecidable {
                    "the active descriptor/identity is undecidable"
                } else if explicitly_active && capability_complete {
                    "active descriptor evidence is available"
                } else {
                    "no cited fact proves which descriptor is active for this instance"
                }
                .to_string(),
                "active-descriptor-unconfirmed".to_string(),
            )
        }
        CoverageRequirement::KnownBridgeSemantics => {
            let ambiguous_bridge = store.by_kind(kind::COMPATIBILITY_BRIDGE).any(|bridge| {
                let capabilities = bridge.attr("capabilities").unwrap_or("");
                let affects_runtime_loading = bridge.attr("scope") == Some("mod-runtime")
                    || capabilities.split(',').any(|capability| {
                        matches!(capability.trim(), "metadata" | "classloading" | "runtime")
                    });
                affects_runtime_loading
                    && (bridge.attr("coverage") != Some("complete")
                        || !capabilities
                            .split(',')
                            .any(|capability| capability.trim() == "runtime"))
            });
            (
                capability_complete && !ambiguous_bridge,
                if ambiguous_bridge {
                    "a runtime compatibility bridge is present and artifact support is undecidable"
                } else if capability_complete {
                    "no unresolved runtime bridge affects this conclusion"
                } else {
                    "loader/bridge coverage is incomplete"
                }
                .to_string(),
                "bridge-compatibility-undecidable".to_string(),
            )
        }
        CoverageRequirement::ApplicableMixin => {
            let applicable = finding.evidence.iter().any(|edge| {
                store
                    .get(edge.fact)
                    .is_some_and(|fact| fact.attr_bool("activation_applicable") == Some(true))
            });
            (
                capability_complete && applicable,
                if applicable {
                    "the mixin is applicable on the analyzed side and is not dynamically gated"
                } else {
                    "mixin activation is conditional, side-inapplicable, or unknown"
                }
                .to_string(),
                "mixin-activation-unconfirmed".to_string(),
            )
        }
        CoverageRequirement::KnownRuntimeMutators => {
            let mutator_observed = store
                .by_kind(kind::MIXIN_RUNTIME_RESOURCE_MUTATION)
                .next()
                .is_some()
                || store
                    .by_kind(kind::RUNTIME_SCRIPT_MODIFIES_RECIPE)
                    .next()
                    .is_some();
            (
                capability_complete && !mutator_observed,
                if mutator_observed {
                    "runtime mixin/script mutation can change the statically scanned resource domain"
                } else if capability_complete {
                    "runtime mutator coverage is complete and no relevant mutator was observed"
                } else {
                    "runtime mutator coverage is incomplete"
                }
                .to_string(),
                "runtime-mutator-coverage-unknown".to_string(),
            )
        }
        _ => (
            capability_complete,
            if capability_complete {
                "required coverage is complete".to_string()
            } else {
                "required coverage is partial or unavailable".to_string()
            },
            "required-coverage-incomplete".to_string(),
        ),
    }
}

fn certainty_for(confidence: f32, proof: ProofKind) -> CertaintyTier {
    match proof {
        ProofKind::Observation | ProofKind::DeterministicDerivation if confidence >= 0.9 => {
            CertaintyTier::Confirmed
        }
        ProofKind::Observation | ProofKind::DeterministicDerivation if confidence >= 0.7 => {
            CertaintyTier::Probable
        }
        ProofKind::Heuristic if confidence >= 0.7 => CertaintyTier::Possible,
        _ => CertaintyTier::Undecidable,
    }
}

fn default_provenance(proof: ProofKind) -> std::collections::BTreeSet<EvidenceOrigin> {
    [match proof {
        ProofKind::Observation => EvidenceOrigin::StaticExact,
        ProofKind::DeterministicDerivation => EvidenceOrigin::StaticInferred,
        ProofKind::Heuristic => EvidenceOrigin::Heuristic,
    }]
    .into_iter()
    .collect()
}

fn default_impact(finding: &Finding) -> Impact {
    use intermed_evidence::Category;
    match finding.category {
        Category::Log | Category::Runtime => Impact::RuntimeFailure,
        Category::Dependency | Category::Loader | Category::Mixin | Category::Environment => {
            if matches!(finding.severity, Severity::Fatal | Severity::Error) {
                Impact::StartupBlocking
            } else {
                Impact::CompatibilityRisk
            }
        }
        Category::Resource => Impact::PackHealth,
        Category::Security => Impact::SecurityReview,
        Category::Performance => Impact::PerformanceDegradation,
        Category::Metadata | Category::Packaging => Impact::PackHealth,
    }
}
