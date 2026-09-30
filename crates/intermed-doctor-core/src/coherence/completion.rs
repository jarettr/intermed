use super::*;

pub fn complete_evidence_graph(store: &FactStore, graph: &mut EvidenceGraph, findings: &[Finding]) {
    let schema = intermed_facts::schema_contract::contract();
    let mut linked = graph
        .links
        .iter()
        .map(|link| link.source_fact)
        .collect::<BTreeSet<_>>();
    for fact_id in findings
        .iter()
        .flat_map(|finding| finding.evidence.iter().map(|edge| edge.fact))
    {
        // Several findings commonly cite the same environment or coverage
        // fact. Record one canonical self-link, not one copy per finding.
        if !linked.insert(fact_id) {
            continue;
        }
        let Some(fact) = store.get(fact_id) else {
            continue;
        };
        let Some(entity) = fact_subject_entity(fact, schema) else {
            // Unknown subject semantics remain honest coverage evidence. They
            // must not be fabricated as unresolved mod identities.
            graph.coverage_evidence.push(fact.id);
            continue;
        };
        graph.entities.push(entity.clone());
        graph.links.push(link(
            entity.clone(),
            EvidenceRelation::Corroborates,
            entity,
            if fact.extractor == "log-analyzer" {
                EvidenceOrigin::ObservedRuntime
            } else {
                EvidenceOrigin::StaticExact
            },
            EvidenceStrength::Exact,
            fact.id,
        ));
    }
}
