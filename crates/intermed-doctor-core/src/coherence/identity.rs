use super::*;

/// Assign stable semantic and physical occurrence identities from canonical
/// entities and input provenance. Presentation `id` remains backward compatible.
pub fn stabilize_finding_identities(
    store: &FactStore,
    graph: &EvidenceGraph,
    findings: &mut [Finding],
) {
    let mut input_identity = Sha256::new();
    input_identity.update(b"intermed-input-manifest-v1\0");
    let mut checksums = store
        .by_kind(kind::CHECKSUM)
        .filter_map(|fact| Some((fact.subject.as_str(), fact.attr("hex")?)))
        .collect::<Vec<_>>();
    checksums.sort_unstable();
    for (locator, hash) in checksums {
        hash_tagged(&mut input_identity, "locator", locator);
        hash_tagged(&mut input_identity, "sha256", hash);
    }
    let input_identity = format!("{:x}", input_identity.finalize());
    for finding in findings {
        let mut semantic = Sha256::new();
        semantic.update(b"intermed-semantic-finding-v1\0");
        hash_tagged(
            &mut semantic,
            "kind",
            &format!("{:?}", finding.conclusion_kind),
        );
        // `ConclusionKind` is intentionally broad (for example
        // `StaticResourceState` covers output, ingredient, serializer, and
        // condition overrides). The canonical family is the typed condition
        // discriminator; without it, two different conclusions about the same
        // entity can collide across reports even when no single report happens
        // to contain both.
        if !finding.family.is_empty() {
            hash_tagged(&mut semantic, "condition-family", &finding.family);
        }
        // Typed conditions are identified by `ConclusionKind`, canonical
        // entities and semantic evidence below. Their presentation ID is not
        // part of identity. Generic findings have no typed condition, so retain
        // their stable rule family to avoid merging unrelated generic rules.
        if finding.conclusion_kind == ConclusionKind::Generic {
            if finding.family.is_empty() {
                hash_tagged(&mut semantic, "condition-family", &finding.rule_id);
            }
            // A Generic finding has no typed condition payload. Its public ID
            // is therefore the only lossless condition key available; using
            // the rule family alone collapses distinct conclusions emitted by
            // one rule (for example a Mixin cluster and an overwrite effect on
            // the same target class). Typed conclusions remain independent of
            // presentation IDs.
            hash_tagged(&mut semantic, "generic-condition", &finding.id);
        }
        let mut semantic_entities = BTreeSet::new();
        for component in &finding.affected_components {
            let mut instances = graph
                .mods
                .iter()
                .filter(|node| node.id.declared_id == *component)
                .map(|node| node.id.to_string())
                .collect::<Vec<_>>();
            instances.sort_unstable();
            instances.dedup();
            if instances.is_empty() {
                semantic_entities.insert(("component", component.clone()));
            } else {
                for instance in instances {
                    semantic_entities.insert(("entity", instance));
                }
            }
        }
        for (tag, value) in semantic_entities {
            hash_tagged(&mut semantic, tag, &value);
        }
        {
            let mut semantic_evidence = BTreeSet::new();
            for edge in &finding.evidence {
                if let Some(fact) = store.get(edge.fact) {
                    semantic_evidence.insert((
                        fact.kind.clone(),
                        fact.subject.to_string(),
                        String::new(),
                        String::new(),
                    ));
                    for key in [
                        // Collector scope is part of the condition for typed
                        // completeness findings.  The same archive can be
                        // truncated independently by VFS, metadata, resource
                        // AST, or another bounded collector; collapsing those
                        // observations would lose both the affected coverage
                        // region and the remediation.
                        "layer",
                        "target",
                        "target_class",
                        "member",
                        "descriptor",
                        "path",
                        "dep",
                    ] {
                        if let Some(value) = fact.attr(key) {
                            semantic_evidence.insert((
                                fact.kind.clone(),
                                fact.subject.to_string(),
                                key.to_string(),
                                value.to_string(),
                            ));
                        }
                    }
                }
            }
            for (kind, subject, key, value) in semantic_evidence {
                hash_tagged(&mut semantic, "fact-kind", &kind);
                hash_tagged(&mut semantic, "fact-subject", &subject);
                if !key.is_empty() {
                    hash_tagged(&mut semantic, &key, &value);
                }
            }
        }
        let digest = format!("{:x}", semantic.finalize());
        finding.semantic_id = format!(
            "finding:{}:{}",
            format!("{:?}", finding.conclusion_kind).to_ascii_lowercase(),
            &digest[..24],
        );
        let mut occurrence = Sha256::new();
        occurrence.update(b"intermed-finding-occurrence-v1\0");
        hash_tagged(&mut occurrence, "semantic", &finding.semantic_id);
        hash_tagged(&mut occurrence, "input", &input_identity);
        let mut sources = finding
            .evidence
            .iter()
            .filter_map(|edge| store.get(edge.fact))
            .map(|fact| {
                (
                    fact.source.locator.as_str(),
                    fact.source.line.unwrap_or_default(),
                    fact.source.inner.as_deref().unwrap_or(""),
                )
            })
            .collect::<Vec<_>>();
        sources.sort_unstable();
        sources.dedup();
        for (locator, line, inner) in sources {
            hash_tagged(&mut occurrence, "source", locator);
            hash_tagged(&mut occurrence, "line", &line.to_string());
            hash_tagged(&mut occurrence, "inner", inner);
        }
        finding.occurrence_id = Some(format!("finding-occurrence:{:x}", occurrence.finalize()));
    }
}
