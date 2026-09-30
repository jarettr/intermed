//! Evaluation of lossless Quilt dependency groups emitted by Layer B.

use std::collections::BTreeSet;

use serde::Deserialize;

use intermed_doctor_core::evidence::{
    Category, ConclusionKind, CoverageRequirement, EvidenceEdge, EvidenceOrigin, Finding,
    FixCandidate, Impact, ProofKind, Severity,
};
use intermed_doctor_core::facts::{FactId, FactStore, kind};

use crate::semver::VersionDialect;
use crate::{ProviderResolution, ResolvedDependencyModel};

#[derive(Debug, Deserialize)]
#[serde(tag = "operator", rename_all = "snake_case")]
enum Expr {
    Atom {
        id: String,
        versions: String,
        optional: bool,
        environment: Option<String>,
        unless: Option<Box<Expr>>,
    },
    Any {
        terms: Vec<Expr>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Truth {
    Satisfied,
    Unsatisfied,
    Unknown,
}

pub(crate) fn expression_findings(store: &FactStore, rule_id: &str) -> Vec<Finding> {
    let model = ResolvedDependencyModel::from_store(store);
    let target_side = model.environment.side.as_deref();

    let mut out = Vec::new();
    for fact in store.by_kind(kind::DEPENDENCY_EXPRESSION) {
        if fact.attr("relation") != Some("depends")
            || fact.attr("identity_certainty") != Some("confirmed")
        {
            continue;
        }
        let Some(serialized) = fact.attr("expression") else {
            continue;
        };
        let Ok(expression) = serde_json::from_str::<Expr>(serialized) else {
            out.push(undecidable_finding(
                rule_id,
                fact.id,
                fact.subject.as_str(),
                "the Quilt dependency expression could not be decoded",
            ));
            continue;
        };
        let mut ids = BTreeSet::new();
        collect_ids(&expression, &mut ids);
        match evaluate(&expression, &model, target_side) {
            Truth::Satisfied => {}
            Truth::Unknown => out.push(undecidable_finding(
                rule_id,
                fact.id,
                fact.subject.as_str(),
                "at least one provider version or environment condition is unresolved",
            )),
            Truth::Unsatisfied => {
                let alternatives = ids.iter().cloned().collect::<Vec<_>>().join(", ");
                let mut builder = Finding::builder(
                    rule_id,
                    format!(
                        "missing-dependency-expression:{}:{}",
                        fact.subject,
                        stable_suffix(serialized)
                    ),
                )
                .family("missing-dependency")
                .conclusion_kind(ConclusionKind::MissingDependency)
                .coverage_requirement(CoverageRequirement::CompletePack)
                .coverage_requirement(CoverageRequirement::CompleteProviderUniverse)
                .coverage_requirement(CoverageRequirement::ActiveDescriptor)
                .proof_kind(ProofKind::DeterministicDerivation)
                .impact(Impact::StartupBlocking)
                .evidence_origin(EvidenceOrigin::StaticExact)
                .severity(Severity::Error)
                .confidence(0.95)
                .category(Category::Dependency)
                .title(format!("Unsatisfied Quilt dependency group for {}", fact.subject))
                .explanation(format!(
                    "{} declares a Quilt dependency expression, but none of the permitted provider combinations is satisfied. Relevant providers: {alternatives}.",
                    fact.subject
                ))
                .evidence(EvidenceEdge::subject(fact.id))
                .affects(fact.subject.as_str())
                .fix(FixCandidate::advice(format!(
                    "Install a provider combination satisfying the Quilt expression ({alternatives})."
                )))
                .tag("dependency")
                .tag("quilt-expression");
                for id in ids {
                    builder = builder.affects(id);
                }
                out.push(builder.build());
            }
        }
    }
    out
}

fn evaluate(
    expression: &Expr,
    model: &ResolvedDependencyModel,
    target_side: Option<&str>,
) -> Truth {
    match expression {
        Expr::Any { terms } => combine_any(terms, model, target_side),
        Expr::Atom {
            id,
            versions,
            optional,
            environment,
            unless,
        } => {
            if *optional
                && matches!(
                    model.provider_resolution(id, "*", VersionDialect::Quilt),
                    ProviderResolution::Absent
                )
            {
                return Truth::Satisfied;
            }
            if let Some(required_side) = environment.as_deref() {
                match environment_applies(required_side, target_side) {
                    Some(false) => return Truth::Satisfied,
                    None => return Truth::Unknown,
                    Some(true) => {}
                }
            }
            if let Some(exception) = unless {
                match evaluate(exception, model, target_side) {
                    Truth::Satisfied => return Truth::Satisfied,
                    Truth::Unknown => return Truth::Unknown,
                    Truth::Unsatisfied => {}
                }
            }
            atom_status(id, versions, model)
        }
    }
}

fn atom_status(id: &str, range: &str, model: &ResolvedDependencyModel) -> Truth {
    match model.provider_resolution(id, range, VersionDialect::Quilt) {
        ProviderResolution::Satisfied { .. } => Truth::Satisfied,
        ProviderResolution::Unknown { .. } => Truth::Unknown,
        ProviderResolution::Unsatisfied { .. } | ProviderResolution::Absent => Truth::Unsatisfied,
    }
}

fn combine_any(
    terms: &[Expr],
    model: &ResolvedDependencyModel,
    target_side: Option<&str>,
) -> Truth {
    let mut unknown = false;
    for term in terms {
        match evaluate(term, model, target_side) {
            Truth::Satisfied => return Truth::Satisfied,
            Truth::Unknown => unknown = true,
            Truth::Unsatisfied => {}
        }
    }
    if unknown {
        Truth::Unknown
    } else {
        Truth::Unsatisfied
    }
}

fn environment_applies(required: &str, target: Option<&str>) -> Option<bool> {
    if matches!(required, "*" | "both") {
        return Some(true);
    }
    let target = target?;
    Some(match required {
        "client" => matches!(target, "client" | "integrated" | "both"),
        "server" | "dedicated_server" => matches!(target, "server" | "both"),
        _ => return None,
    })
}

fn collect_ids(expression: &Expr, out: &mut BTreeSet<String>) {
    match expression {
        Expr::Atom { id, unless, .. } => {
            out.insert(id.clone());
            if let Some(unless) = unless {
                collect_ids(unless, out);
            }
        }
        Expr::Any { terms } => {
            for term in terms {
                collect_ids(term, out);
            }
        }
    }
}

fn undecidable_finding(rule_id: &str, evidence: FactId, consumer: &str, reason: &str) -> Finding {
    Finding::builder(
        rule_id,
        format!(
            "dependency-expression-undecidable:{consumer}:{}",
            evidence.0
        ),
    )
    .severity(Severity::Note)
    .confidence(0.4)
    .category(Category::Dependency)
    .title(format!(
        "Cannot verify Quilt dependency group for {consumer}"
    ))
    .explanation(format!(
        "The grouped dependency is retained without guessing because {reason}."
    ))
    .evidence(EvidenceEdge::subject(evidence))
    .affects(consumer)
    .tag("dependency")
    .tag("quilt-expression")
    .tag("undecidable")
    .build()
}

fn stable_suffix(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::SourceRef;

    fn expression(store: &mut FactStore, json: &str) {
        store
            .fact("metadata", kind::DEPENDENCY_EXPRESSION)
            .subject("consumer")
            .attr("relation", "depends")
            .attr("expression", json)
            .attr("identity_certainty", "confirmed")
            .source(SourceRef::inside("consumer.jar", "quilt.mod.json"))
            .emit();
    }

    #[test]
    fn any_group_is_satisfied_by_one_in_range_provider() {
        let mut store = FactStore::new();
        expression(
            &mut store,
            r#"{"operator":"any","terms":[{"operator":"atom","id":"a","versions":">=2","optional":false},{"operator":"atom","id":"b","versions":">=3","optional":false}]}"#,
        );
        store
            .fact("metadata", kind::MOD)
            .subject("b")
            .attr("version", "3.1.0")
            .attr("identity_certainty", "confirmed")
            .emit();
        assert!(expression_findings(&store, "dependency").is_empty());
    }

    #[test]
    fn absent_any_group_is_one_hard_finding() {
        let mut store = FactStore::new();
        expression(
            &mut store,
            r#"{"operator":"any","terms":[{"operator":"atom","id":"a","versions":"*","optional":false},{"operator":"atom","id":"b","versions":"*","optional":false}]}"#,
        );
        let findings = expression_findings(&store, "dependency");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn unless_provider_suppresses_requirement() {
        let mut store = FactStore::new();
        expression(
            &mut store,
            r#"{"operator":"atom","id":"primary","versions":"*","optional":false,"unless":{"operator":"atom","id":"replacement","versions":"*","optional":false}}"#,
        );
        store
            .fact("metadata", kind::MOD)
            .subject("replacement")
            .attr("version", "1.0.0")
            .attr("identity_certainty", "confirmed")
            .emit();
        assert!(expression_findings(&store, "dependency").is_empty());
    }

    #[test]
    fn optional_dependency_is_checked_when_provider_is_present() {
        let mut store = FactStore::new();
        expression(
            &mut store,
            r#"{"operator":"atom","id":"optional_provider","versions":">=2","optional":true}"#,
        );
        store
            .fact("metadata", kind::MOD)
            .subject("optional_provider")
            .attr("version", "1.0.0")
            .attr("identity_certainty", "confirmed")
            .source(SourceRef::file("optional.jar"))
            .emit();
        let findings = expression_findings(&store, "dependency");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }
}
