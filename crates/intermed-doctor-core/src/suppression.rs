//! Cross-rule finding suppression / merge.
//!
//! Different layers legitimately observe the *same* underlying situation. Layer E
//! (byte-level VFS) sees that `create` and `createaddition` both write
//! `data/create/recipes/crushing/tuff.json` — a `json-override` collision. Layer M
//! (typed AST) sees *why* it matters — the recipe outputs differ. Emitting both
//!
//! ```text
//! resource-conflict:json-override:data/create/recipes/crushing/tuff.json
//! recipe-output-override:data/create/recipes/crushing/tuff.json
//! ```
//!
//! gives the user two warnings for one path. That is noise.
//!
//! The Layer-M semantic-override finding is the *meaning* of the byte-level
//! Layer-E collision on the same path; the suppressor keeps the semantic finding
//! and folds the byte one's evidence into it (recording the contributing rule in
//! `rule_sources`) rather than dropping it.

use intermed_evidence::{
    AssessmentDisposition, ConclusionAdjustment, Finding, RuntimeMutationCoverage, Severity,
};
use intermed_facts::{FactStore, kind};
use intermed_resource_identity::ResourceKey;

/// Fold every Layer-E `resource-conflict:<class>:<path>` finding into the Layer-M
/// semantic-override finding for the *same path*, when one exists.
///
/// Layer-M override findings are tagged `semantic-override` and have the id form
/// `<diff-kind>:<path>`; Layer-E findings have `resource-conflict:<class>:<path>`.
/// Both encode the path as the id's tail, so a single pass matches any present or
/// future override domain (recipe / loot / atlas / model / blockstate /
/// advancement / predicate / registry object) without a per-pair table — the
/// path is the shared key. Returns the number of Layer-E findings folded away.
pub fn apply_semantic_override_suppression(findings: &mut Vec<Finding>) -> usize {
    // path -> index of the Layer-M semantic-override finding for that path.
    let mut winner_by_path: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        if f.machine_tags.iter().any(|t| t == "semantic-override")
            && let Some((_, path)) = f.id.split_once(':')
        {
            winner_by_path.insert(path.to_string(), i);
        }
    }
    if winner_by_path.is_empty() {
        return 0;
    }

    // Collect (winner, loser) folds for Layer-E collisions on a covered path.
    let mut folds: Vec<(usize, usize)> = Vec::new();
    for (j, f) in findings.iter().enumerate() {
        let Some(rest) = f.id.strip_prefix("resource-conflict:") else {
            continue;
        };
        // rest = "<class>:<path>" → path is everything after the first ':'.
        let Some((_, path)) = rest.split_once(':') else {
            continue;
        };
        if let Some(&winner) = winner_by_path.get(path)
            && winner != j
        {
            folds.push((winner, j));
        }
    }

    let mut remove = vec![false; findings.len()];
    for (winner, loser) in folds {
        if remove[loser] {
            continue;
        }
        let loser_evidence = findings[loser].evidence.clone();
        let loser_rule = findings[loser].rule_id.clone();
        let loser_tags = findings[loser].machine_tags.clone();
        let loser_requirements = findings[loser].coverage_requirements.clone();
        let loser_refutability = findings[loser].runtime_refutability.clone();
        let loser_proof = findings[loser].proof_kind;
        let w = &mut findings[winner];
        w.evidence.extend(loser_evidence);
        for tag in loser_tags {
            if !w.machine_tags.contains(&tag) {
                w.machine_tags.push(tag);
            }
        }
        for requirement in loser_requirements {
            if !w.coverage_requirements.contains(&requirement) {
                w.coverage_requirements.push(requirement);
            }
        }
        for refutability in loser_refutability {
            if !w.runtime_refutability.contains(&refutability) {
                w.runtime_refutability.push(refutability);
            }
        }
        if w.proof_kind.is_none() {
            w.proof_kind = loser_proof;
        }
        if loser_rule != w.rule_id && !w.rule_sources.contains(&loser_rule) {
            w.rule_sources.push(loser_rule);
        }
        remove[loser] = true;
    }

    let removed = remove.iter().filter(|&&r| r).count();
    let mut iter = remove.into_iter();
    findings.retain(|_| !iter.next().unwrap_or(false));
    removed
}

/// Downgrade a static resource finding when a data-pack script (KubeJS /
/// CraftTweaker) removes or replaces the very resource it concerns.
///
/// Layer M concludes "this recipe resolves differently by load order" from the
/// *static* files. But if a script deletes or replaces that recipe at load time,
/// the static conflict never reaches the player — warning at full severity would
/// be a false positive. We don't silently drop it (the script read is a
/// heuristic): we downgrade `Warn`→`Note`, lower confidence, and append a caveat
/// so a human can audit. Returns the number of findings downgraded.
pub fn apply_runtime_caveats(findings: &mut [Finding], store: &FactStore) -> usize {
    let mutations = store.by_kind(kind::SCRIPT_MUTATION).collect::<Vec<_>>();
    let coverage_partial = store.by_kind(kind::SCAN_TRUNCATED).any(|fact| {
        matches!(
            fact.attr("layer"),
            Some("script" | "resource" | "resource-dynamics" | "data-semantics")
        )
    }) || store
        .by_kind(kind::SCRIPT_DISCOVERY_COVERAGE)
        .any(|fact| fact.attr_bool("complete") == Some(false));
    let script_coverage_available = store
        .by_kind(kind::SCRIPT_DISCOVERY_COVERAGE)
        .next()
        .is_some();

    let mut downgraded = 0;
    for f in findings.iter_mut() {
        let path = f.affected_components.first().cloned();
        let mutable_domain = path
            .as_deref()
            .map(ResourceKey::from_path)
            .map(|key| key.domain.as_str())
            .filter(|domain| matches!(*domain, "recipe" | "loot-table" | "tag"));
        let domain_mutator_present = mutable_domain.is_some_and(|domain| {
            mutations
                .iter()
                .any(|fact| fact.attr("domain") == Some(domain) && mutation_applicable(fact))
        }) || store
            .by_kind(kind::MIXIN_RUNTIME_RESOURCE_MUTATION)
            .next()
            .is_some();
        if f.category == intermed_evidence::Category::Resource {
            f.runtime_mutation_coverage = if coverage_partial {
                RuntimeMutationCoverage::CoveragePartial
            } else if domain_mutator_present {
                RuntimeMutationCoverage::MutatorPresent
            } else if script_coverage_available {
                RuntimeMutationCoverage::NoMutatorEvidence
            } else {
                RuntimeMutationCoverage::Unavailable
            };
            if matches!(
                f.runtime_mutation_coverage,
                RuntimeMutationCoverage::MutatorPresent | RuntimeMutationCoverage::CoveragePartial
            ) && mutable_domain.is_some()
                && f.conclusion_kind == intermed_evidence::ConclusionKind::StaticResourceState
            {
                let prior = f.severity;
                if f.severity > Severity::Warn {
                    f.severity = Severity::Warn;
                }
                if prior != f.severity {
                    f.assessment.disposition = AssessmentDisposition::Downgraded;
                    f.assessment.adjustments.push(ConclusionAdjustment {
                        code: "resource-finality-unproven".to_string(),
                        detail: "runtime mutators or partial script coverage prevent treating the static resource state as final".to_string(),
                        original_disposition: Some(AssessmentDisposition::Asserted),
                        final_disposition: Some(AssessmentDisposition::Downgraded),
                        from_severity: Some(prior),
                        to_severity: Some(f.severity),
                        contradicting_evidence: Vec::new(),
                    });
                }
            }
        }
        let matching = match (f.family.as_str(), path.as_deref()) {
            (
                "recipe-output-override"
                | "recipe-type-override"
                | "recipe-ingredient-override"
                | "recipe-condition-override",
                Some(path),
            ) => matching_mutations(path, "recipe", store, &mutations),
            ("loot-table-output-override", Some(path)) => {
                matching_mutations(path, "loot-table", store, &mutations)
            }
            _ => Vec::new(),
        };
        if !matching.is_empty() {
            f.runtime_mutation_coverage = RuntimeMutationCoverage::ExactTargetModified;
            let prior = f.severity;
            let runtime_current = matching.iter().any(|fact| {
                fact.attr("origin") == Some("runtime-observed")
                    && fact.attr("session_relation") == Some("current")
            });
            let cap = if runtime_current {
                Severity::Note
            } else {
                Severity::Warn
            };
            if f.severity > cap {
                f.severity = cap;
            }
            f.assessment.disposition = AssessmentDisposition::Downgraded;
            if prior != f.severity {
                let contradicting_evidence = matching.iter().map(|fact| fact.id).collect();
                f.assessment.adjustments.push(ConclusionAdjustment {
                    code: "runtime-resource-mutator-observed".to_string(),
                    detail: if runtime_current {
                        "same-session runtime script evidence modified the static resource"
                    } else {
                        "static script intent may modify the resource when its applicable script phase runs"
                    }
                    .to_string(),
                    original_disposition: Some(AssessmentDisposition::Asserted),
                    final_disposition: Some(AssessmentDisposition::Downgraded),
                    from_severity: Some(prior),
                    to_severity: Some(f.severity),
                    contradicting_evidence,
                });
            }
            f.confidence = if runtime_current {
                (f.confidence * 0.7).min(0.7)
            } else {
                (f.confidence * 0.85).min(0.85)
            };
            if !f.explanation.contains("data-pack script") {
                f.explanation.push_str(
                    " An applicable data-pack script (KubeJS/CraftTweaker) selector may remove or replace this resource; static intent and same-session runtime observation are reported separately.",
                );
            }
            if !f.machine_tags.iter().any(|t| t == "runtime-script-caveat") {
                f.machine_tags.push("runtime-script-caveat".to_string());
            }
            downgraded += 1;
        }
    }
    downgraded
}

fn mutation_applicable(fact: &intermed_facts::Fact) -> bool {
    let wrong_script_phase = matches!(fact.attr("applicability"), Some("client" | "startup"));
    let stale_runtime_observation = fact.attr("origin") == Some("runtime-observed")
        && fact.attr("session_relation") != Some("current");
    !(wrong_script_phase || stale_runtime_observation)
}

fn matching_mutations<'a>(
    path: &str,
    domain: &str,
    store: &'a FactStore,
    mutations: &[&'a intermed_facts::Fact],
) -> Vec<&'a intermed_facts::Fact> {
    mutations
        .iter()
        .copied()
        .filter(|fact| fact.attr("domain") == Some(domain) && mutation_applicable(fact))
        .filter(|fact| mutation_selector_matches(path, fact, store))
        .collect()
}

fn mutation_selector_matches(path: &str, fact: &intermed_facts::Fact, store: &FactStore) -> bool {
    let selector_kind = fact.attr("selector_kind").unwrap_or("dynamic");
    if selector_kind == "composite" {
        let Some(json) = fact.attr("selector_json") else {
            return false;
        };
        let Ok(selectors) = serde_json::from_str::<Vec<(String, String)>>(json) else {
            return false;
        };
        return !selectors.is_empty()
            && selectors
                .iter()
                .all(|(kind, value)| selector_matches(path, kind, value, store));
    }
    selector_matches(
        path,
        selector_kind,
        fact.attr("selector_value").unwrap_or_default(),
        store,
    )
}

fn selector_matches(path: &str, kind: &str, value: &str, store: &FactStore) -> bool {
    let key = ResourceKey::from_path(path);
    match kind {
        "recipe-id" | "resource-id" | "tag" => key
            .object_id
            .as_ref()
            .is_some_and(|id| id.to_string() == value.trim_start_matches('#')),
        "recipe-namespace" => key.namespace.as_deref() == Some(value),
        "recipe-type" => store
            .by_kind(kind::RESOURCE_AST_PARSED)
            .any(|fact| fact.subject.as_ref() == path && fact.attr("recipe_type") == Some(value)),
        "input-item" | "output-item" => {
            let relation = if kind == "input-item" {
                "uses_item"
            } else {
                "produces_item"
            };
            store.by_kind(kind::RESOURCE_REFERENCE).any(|fact| {
                fact.subject.as_ref() == path
                    && fact.attr("relation") == Some(relation)
                    && fact.attr("to") == Some(value)
            })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_evidence::EvidenceEdge;
    use intermed_facts::FactId;

    fn f(id: &str, rule: &str) -> Finding {
        Finding::builder(rule, id)
            .severity(Severity::Warn)
            .evidence(EvidenceEdge::subject(FactId(1)))
            .build()
    }

    /// A Layer-M semantic-override finding (tagged `semantic-override`).
    fn semantic(id: &str) -> Finding {
        Finding::builder("resource-semantics", id)
            .severity(Severity::Warn)
            .evidence(EvidenceEdge::subject(FactId(1)))
            .tag("semantic-override")
            .build()
    }

    #[test]
    fn semantic_override_suppresses_generic_collision() {
        let path = "data/create/recipes/crushing/tuff.json";
        let mut findings = vec![
            semantic(&format!("recipe-output-override:{path}")),
            f(
                &format!("resource-conflict:json-override:{path}"),
                "resource-conflict",
            ),
        ];
        let removed = apply_semantic_override_suppression(&mut findings);
        assert_eq!(removed, 1);
        assert_eq!(findings.len(), 1);
        let kept = &findings[0];
        assert!(kept.id.starts_with("recipe-output-override:"));
        // The VFS collision's evidence was folded in (2 edges now).
        assert_eq!(kept.evidence.len(), 2);
        assert!(kept.rule_sources.contains(&"resource-conflict".to_string()));
    }

    #[test]
    fn generic_pass_folds_any_override_domain() {
        // An atlas semantic override folds the Layer-E order-dependent-atlas finding.
        let path = "assets/minecraft/atlases/blocks.json";
        let mut findings = vec![
            semantic(&format!("atlas-source-override:{path}")),
            f(
                &format!("resource-conflict:order-dependent-atlas:{path}"),
                "resource-conflict",
            ),
        ];
        assert_eq!(apply_semantic_override_suppression(&mut findings), 1);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].id.starts_with("atlas-source-override:"));
    }

    #[test]
    fn runtime_script_removal_downgrades_recipe_finding() {
        let mut store = FactStore::new();
        // A script removes recipe id `create:crushing/tuff`.
        store
            .fact("script-dynamics", kind::SCRIPT_MUTATION)
            .subject("runtime:1")
            .attr("domain", "recipe")
            .attr("selector_kind", "recipe-id")
            .attr("selector_value", "create:crushing/tuff")
            .attr("origin", "runtime-observed")
            .attr("session_relation", "current")
            .attr("applicability", "runtime")
            .emit();
        assert_eq!(store.by_kind(kind::SCRIPT_MUTATION).count(), 1);
        let mutation = store.by_kind(kind::SCRIPT_MUTATION).next().unwrap();
        assert_eq!(
            mutation.attr("selector_value"),
            Some("create:crushing/tuff")
        );
        let mut findings = vec![
            Finding::builder(
                "resource-semantics",
                "recipe-output-override:data/create/recipes/crushing/tuff.json",
            )
            .family("recipe-output-override")
            .affects("data/create/recipes/crushing/tuff.json")
            .severity(Severity::Warn)
            .build(),
        ];
        let n = apply_runtime_caveats(&mut findings, &store);
        assert_eq!(n, 1);
        assert_eq!(findings[0].severity, Severity::Note);
        assert!(
            findings[0]
                .machine_tags
                .iter()
                .any(|t| t == "runtime-script-caveat")
        );
        assert!(findings[0].explanation.contains("data-pack script"));
    }

    #[test]
    fn mod_scoped_removal_downgrades_by_namespace() {
        let mut store = FactStore::new();
        store
            .fact("static-script-scanner", kind::SCRIPT_MUTATION)
            .subject("static:1")
            .attr("domain", "recipe")
            .attr("selector_kind", "recipe-namespace")
            .attr("selector_value", "create")
            .attr("origin", "static-declared")
            .attr("session_relation", "not-applicable")
            .attr("applicability", "server")
            .emit();
        let mut findings = vec![
            Finding::builder(
                "resource-semantics",
                "recipe-output-override:data/create/recipes/x.json",
            )
            .family("recipe-output-override")
            .affects("data/create/recipes/x.json")
            .severity(Severity::Warn)
            .build(),
        ];
        assert_eq!(apply_runtime_caveats(&mut findings, &store), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
    }

    #[test]
    fn unrelated_recipe_not_downgraded() {
        let mut store = FactStore::new();
        store
            .fact("static-script-scanner", kind::RUNTIME_REMOVED_RECIPE)
            .subject("thermal:smelting/x")
            .emit();
        let mut findings = vec![
            Finding::builder(
                "resource-semantics",
                "recipe-output-override:data/create/recipes/x.json",
            )
            .family("recipe-output-override")
            .affects("data/create/recipes/x.json")
            .severity(Severity::Warn)
            .build(),
        ];
        assert_eq!(apply_runtime_caveats(&mut findings, &store), 0);
        assert_eq!(findings[0].severity, Severity::Warn);
    }

    #[test]
    fn client_script_does_not_suppress_server_recipe() {
        let mut store = FactStore::new();
        store
            .fact("static-script-scanner", kind::SCRIPT_MUTATION)
            .subject("client:1")
            .attr("domain", "recipe")
            .attr("selector_kind", "recipe-id")
            .attr("selector_value", "create:x")
            .attr("origin", "static-declared")
            .attr("session_relation", "not-applicable")
            .attr("applicability", "client")
            .emit();
        let mut findings = vec![
            Finding::builder("resource-semantics", "recipe:x")
                .family("recipe-output-override")
                .affects("data/create/recipes/x.json")
                .severity(Severity::Warn)
                .build(),
        ];
        assert_eq!(apply_runtime_caveats(&mut findings, &store), 0);
        assert_eq!(findings[0].severity, Severity::Warn);
    }

    #[test]
    fn historical_runtime_log_is_context_not_refutation() {
        let mut store = FactStore::new();
        store
            .fact("script-dynamics", kind::SCRIPT_MUTATION)
            .subject("old:1")
            .attr("domain", "recipe")
            .attr("selector_kind", "recipe-id")
            .attr("selector_value", "create:x")
            .attr("origin", "runtime-observed")
            .attr("session_relation", "historical-or-unresolved")
            .attr("applicability", "runtime")
            .emit();
        let mut findings = vec![
            Finding::builder("resource-semantics", "recipe:x")
                .family("recipe-output-override")
                .affects("data/create/recipes/x.json")
                .severity(Severity::Warn)
                .build(),
        ];
        assert_eq!(apply_runtime_caveats(&mut findings, &store), 0);
    }

    #[test]
    fn unrelated_paths_are_not_suppressed() {
        let mut findings = vec![
            semantic("recipe-output-override:data/a/recipes/x.json"),
            f(
                "resource-conflict:json-override:data/b/recipes/y.json",
                "resource-conflict",
            ),
        ];
        let removed = apply_semantic_override_suppression(&mut findings);
        assert_eq!(removed, 0);
        assert_eq!(findings.len(), 2);
    }
}
