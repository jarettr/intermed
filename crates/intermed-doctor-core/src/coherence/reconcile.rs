use super::*;

/// Reconcile conclusions against exact evidence from other layers. Decisions
/// use typed semantics; finding ids remain presentation identifiers only.
pub fn reconcile_findings(store: &FactStore, graph: &mut EvidenceGraph, findings: &mut [Finding]) {
    complete_evidence_graph(store, graph, findings);
    let runtime_classes: BTreeMap<String, Vec<FactId>> = store
        .by_kind(kind::STACK_FRAME)
        .filter_map(|fact| {
            Some((
                intermed_evidence::identity::normalize_class_name(fact.attr("class")?),
                fact.id,
            ))
        })
        .fold(BTreeMap::new(), |mut out, (class, id)| {
            out.entry(class).or_default().push(id);
            out
        });
    let runtime_event_mods = runtime_mods(store);
    let known_mods = graph
        .mods
        .iter()
        .filter(|node| node.active)
        .map(|node| (node.id.declared_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let package_owners = store
        .by_kind(kind::PACKAGE_OWNER)
        .filter_map(|fact| Some((fact.attr("package")?.to_string(), fact.subject.to_string())))
        .collect::<Vec<_>>();
    let authoritative_environment = strongest_environment_fact(store);

    for finding in findings {
        let contradiction = match finding.conclusion_kind {
            ConclusionKind::ClassAbsent | ConclusionKind::MethodAbsent => finding
                .evidence
                .iter()
                .filter_map(|edge| store.get(edge.fact))
                .filter_map(|fact| fact.attr("target").or_else(|| fact.attr("target_class")))
                .find_map(|target| {
                    runtime_classes
                        .get(&intermed_evidence::identity::normalize_class_name(target))
                        .cloned()
                }),
            ConclusionKind::DependencyUnused => {
                let [from, to, ..] = finding.affected_components.as_slice() else {
                    continue;
                };
                runtime_event_mods
                    .values()
                    .find(|mods| mods.contains(from) && mods.contains(to))
                    .map(|mods| {
                        store
                            .by_kind(kind::STACK_FRAME)
                            .filter(|frame| {
                                frame.attr("mod_id").is_some_and(|id| mods.contains(id))
                            })
                            .map(|frame| frame.id)
                            .collect()
                    })
                    .or_else(|| {
                        let ids = store
                            .by_kind(kind::BYTECODE_CALL_EDGE)
                            .filter(|edge| edge.subject == *from)
                            .filter(|edge| {
                                edge.attr("target_class").is_some_and(|class| {
                                    package_owners.iter().any(|(package, owner)| {
                                        owner == to && class_under_package(class, package)
                                    })
                                })
                            })
                            .map(|edge| edge.id)
                            .collect::<Vec<_>>();
                        (!ids.is_empty()).then_some(ids)
                    })
            }
            ConclusionKind::MissingDependency => {
                let provider = finding.affected_components.get(1).map(String::as_str);
                provider
                    .and_then(|provider| known_mods.get(provider))
                    .map(|node| {
                        graph
                            .links
                            .iter()
                            .filter(|link| link.to == EntityRef::Mod(node.id.clone()))
                            .map(|link| link.source_fact)
                            .collect()
                    })
            }
            ConclusionKind::LoaderMismatch => authoritative_environment.and_then(|authoritative| {
                let cited_environment = finding
                    .evidence
                    .iter()
                    .filter_map(|edge| store.get(edge.fact))
                    .find(|fact| fact.kind == kind::ENVIRONMENT);
                cited_environment
                    .filter(|cited| cited.id != authoritative.id)
                    .map(|_| vec![authoritative.id])
            }),
            _ => None,
        };
        if let Some(mut evidence) = contradiction {
            evidence.sort_unstable();
            evidence.dedup();
            invalidate(finding, evidence);
            if finding.conclusion_kind == ConclusionKind::LoaderMismatch {
                let authoritative = authoritative_environment.expect("loader contradiction source");
                finding.id.push_str(":superseded:");
                finding
                    .id
                    .push_str(authoritative.attr("loader").unwrap_or("unknown"));
                finding.id.push(':');
                finding.id.push_str(
                    authoritative
                        .attr("loader_source")
                        .unwrap_or("environment-evidence"),
                );
            }
        }
        let mut evidence_path = graph
            .links
            .iter()
            .filter(|link| {
                finding
                    .evidence
                    .iter()
                    .any(|edge| edge.fact == link.source_fact)
            })
            .cloned()
            .collect::<Vec<_>>();
        // `EvidenceGraph::normalize` already provides a deterministic,
        // duplicate-free order; filtering preserves that order.
        if evidence_path.len() > MAX_FINDING_EVIDENCE_PATH {
            let total = evidence_path.len();
            evidence_path.truncate(MAX_FINDING_EVIDENCE_PATH);
            finding.assessment.adjustments.push(ConclusionAdjustment {
                code: "evidence-path-truncated".to_string(),
                detail: format!(
                    "the report retains {MAX_FINDING_EVIDENCE_PATH} of {total} matching graph links; the canonical evidence graph retains the complete normalized link set"
                ),
                original_disposition: None,
                final_disposition: None,
                from_severity: None,
                to_severity: None,
                contradicting_evidence: Vec::new(),
            });
        }
        finding.evidence_path = evidence_path;
    }
    graph.normalize();
}

fn strongest_environment_fact(store: &FactStore) -> Option<&Fact> {
    crate::environment::resolve_environment_field(
        store,
        "loader",
        &["loader_source", "evidence_source"],
    )
    .fact
}
fn invalidate(finding: &mut Finding, evidence: Vec<FactId>) {
    let prior_disposition = finding.assessment.disposition;
    let prior_severity = finding.severity;
    finding.severity = if finding.conclusion_kind == ConclusionKind::DependencyUnused {
        Severity::Info
    } else {
        Severity::Note
    };
    finding.visibility = FindingVisibility::ExplainOnly;
    finding.confidence = finding.confidence.min(0.2);
    finding.assessment.disposition = AssessmentDisposition::Abstained;
    finding.assessment.certainty = CertaintyTier::Undecidable;
    if !finding
        .machine_tags
        .iter()
        .any(|tag| tag == "runtime-contradicted")
    {
        finding
            .machine_tags
            .push("runtime-contradicted".to_string());
    }
    finding.explanation.push_str(
        " Exact evidence from another analysis layer contradicts this static hypothesis; the conclusion is retained only for explanation.",
    );
    finding.assessment.adjustments.push(ConclusionAdjustment {
        code: "cross-layer-contradiction".to_string(),
        detail: "exact evidence from another layer contradicts the proposed conclusion".to_string(),
        original_disposition: Some(prior_disposition),
        final_disposition: Some(AssessmentDisposition::Abstained),
        from_severity: Some(prior_severity),
        to_severity: Some(finding.severity),
        contradicting_evidence: evidence,
    });
}

fn runtime_mods(store: &FactStore) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for frame in store.by_kind(kind::STACK_FRAME) {
        if let Some(mod_id) = frame.attr("mod_id").filter(|id| !id.is_empty()) {
            out.entry(frame.subject.to_string())
                .or_insert_with(BTreeSet::new)
                .insert(mod_id.to_string());
        }
    }
    out
}
