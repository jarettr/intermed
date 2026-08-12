//! Layer-C doctor rule: pairwise semver checks plus PubGrub global resolution.

use std::collections::BTreeSet;

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{Rule, RuleCtx};

use crate::effective::effective_findings;
use crate::implicit::implicit_findings;
use crate::ordering::ordering_findings;
use crate::pairwise::pairwise_findings;
use crate::resolver::{ResolutionOutcome, resolve_store};

/// Layer-C dependency rule: direct semver checks and PubGrub global unsat.
pub struct DependencyRule;

impl Rule for DependencyRule {
    fn id(&self) -> &'static str {
        "dependency"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        let mut out = pairwise_findings(ctx, self.id());
        out.extend(ordering_findings(ctx, self.id()));
        out.extend(implicit_findings(ctx, self.id()));
        out.extend(effective_findings(ctx, self.id()));
        if let Some(finding) = resolution_finding(ctx, self.id(), &out) {
            out.push(finding);
        }
        Ok(out)
    }
}

/// Suppress the global PubGrub unsat when pairwise checks already surfaced a
/// plain `missing-dependency` root cause. PubGrub may choose that missing edge as
/// its derivation even when unrelated optional version warnings exist; emitting
/// both would duplicate the error and imply a false causal link.
fn should_emit_pubgrub_unsat(pairwise: &[Finding]) -> bool {
    !pairwise
        .iter()
        .any(|finding| finding.id.starts_with("missing-dependency:"))
}

/// Translate the global PubGrub resolution outcome into at most one finding.
///
/// Crucially, a *non*-unsatisfiable result is not always good news: when the
/// resolver could not run (`Skipped`) or errored, the absence of an unsat finding
/// means the layer could not evaluate the graph — not that the graph is healthy.
/// That case surfaces an informational `dependency-resolution-skipped` note so
/// the result is not silently indistinguishable from "satisfiable".
fn resolution_finding(ctx: &RuleCtx<'_>, rule_id: &str, pairwise: &[Finding]) -> Option<Finding> {
    let outcome = match resolve_store(ctx.store) {
        Ok(outcome) => outcome,
        // A genuine resolver error: surface it instead of dropping it.
        Err(e) => return Some(resolution_skipped_finding(ctx, rule_id, &e.to_string())),
    };

    match outcome {
        ResolutionOutcome::Unsatisfiable {
            explanation,
            proof_packages,
            proof_dependencies,
        } if should_emit_pubgrub_unsat(pairwise) && !explanation.trim().is_empty() => {
            Some(pubgrub_unsat_finding(
                ctx,
                rule_id,
                explanation,
                &proof_packages,
                &proof_dependencies,
            ))
        }
        // Pairwise checks already named a concrete missing dependency; the global
        // tree would be redundant. The graph *was* evaluated, so no skip note.
        ResolutionOutcome::Unsatisfiable { .. } | ResolutionOutcome::Satisfied { .. } => None,
        // The resolver could not evaluate the graph. Only worth saying so when
        // there is actually a catalog to resolve — installed mods *and* declared
        // dependencies. A bare dependency with no installed mods (or no deps at
        // all) has nothing to resolve, so a note would be pure noise.
        ResolutionOutcome::Skipped { reason } => {
            let has_mods = ctx.store.by_kind(kind::MOD).next().is_some();
            let has_deps = ctx.store.by_kind(kind::DEPENDENCY).next().is_some();
            if !has_mods || !has_deps {
                return None;
            }
            Some(resolution_skipped_finding(
                ctx,
                rule_id,
                reason.human_reason(),
            ))
        }
    }
}

fn pubgrub_unsat_finding(
    ctx: &RuleCtx<'_>,
    rule_id: &str,
    explanation: String,
    proof_packages: &[String],
    proof_dependencies: &[(String, String)],
) -> Finding {
    let mut builder = Finding::builder(rule_id, "dependency-unsat:global")
        .severity(Severity::Error)
        .category(Category::Dependency)
        .title("Dependency constraints cannot be satisfied together")
        .explanation(explanation)
        .fix(FixCandidate::advice(
            "Review the dependency chain above; adjust mod versions or remove conflicting mods.",
        ))
        .tag("dependency")
        .tag("pubgrub")
        .tag("unsat");

    let proof = proof_packages
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let proof_edges = proof_dependencies
        .iter()
        .map(|(from, to)| (from.as_str(), to.as_str()))
        .collect::<BTreeSet<_>>();

    // A global graph may contain thousands of unrelated declarations. Cite only
    // dependency edges represented by the derivation, plus the participating
    // package/version facts that make those constraints concrete.
    for dep in ctx.store.by_kind(kind::DEPENDENCY) {
        let from = dep.subject.as_str();
        let to = dep.attr("dep").unwrap_or("");
        if proof_edges.contains(&(from, to)) {
            builder = builder.evidence(EvidenceEdge::supports(dep.id));
        }
    }
    for package in ctx.store.by_kind(kind::MOD) {
        if proof.contains(package.subject.as_str()) {
            builder = builder.evidence(EvidenceEdge::supports(package.id));
        }
    }

    builder.build()
}

fn resolution_skipped_finding(ctx: &RuleCtx<'_>, rule_id: &str, reason: &str) -> Finding {
    let mut builder = Finding::builder(rule_id, "dependency-resolution-skipped")
        .severity(Severity::Note)
        .category(Category::Dependency)
        .title("Global dependency resolution was not evaluated")
        .explanation(format!(
            "PubGrub global resolution did not run: {reason}. The absence of a \
             dependency-conflict finding here does not confirm the graph is \
             satisfiable — only that this layer could not decide."
        ))
        .fix(FixCandidate::advice(
            "Treat the dependency graph as unverified; check declared versions if a conflict is suspected.",
        ))
        .tag("dependency")
        .tag("pubgrub")
        .tag("skipped");

    for dep in ctx.store.by_kind(kind::DEPENDENCY) {
        builder = builder.evidence(EvidenceEdge::supports(dep.id));
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use intermed_doctor_core::facts::{FactStore, kind};
    use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};

    use super::DependencyRule;

    fn target() -> Target {
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

    #[test]
    fn unevaluable_graph_emits_resolution_skipped_note() {
        // Dependencies exist, but no package carries a parseable version, so the
        // resolver skips. The user must learn the graph was *not* checked.
        let mut store = FactStore::new();
        store
            .fact("meta", kind::MOD)
            .subject("alpha")
            .attr("version", "not-a-version")
            .emit();
        store
            .fact("meta", kind::DEPENDENCY)
            .subject("alpha")
            .attr("dep", "beta")
            .attr("range", ">=1.0.0")
            .attr("mandatory", true)
            .emit();
        let target = target();
        let findings = DependencyRule
            .evaluate(&RuleCtx::for_test(&store, &target))
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.id == "dependency-resolution-skipped"),
            "expected a resolution-skipped note, got: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn no_dependencies_means_no_skip_note() {
        // Nothing to resolve → silence is correct (no noise note).
        let mut store = FactStore::new();
        store
            .fact("meta", kind::MOD)
            .subject("alpha")
            .attr("version", "not-a-version")
            .emit();
        let target = target();
        let findings = DependencyRule
            .evaluate(&RuleCtx::for_test(&store, &target))
            .unwrap();
        assert!(
            !findings
                .iter()
                .any(|f| f.id == "dependency-resolution-skipped")
        );
    }

    #[test]
    fn satisfiable_graph_emits_no_resolution_finding() {
        let mut store = FactStore::new();
        store
            .fact("meta", kind::MOD)
            .subject("alpha")
            .attr("version", "1.0.0")
            .emit();
        store
            .fact("meta", kind::MOD)
            .subject("beta")
            .attr("version", "2.0.0")
            .emit();
        store
            .fact("meta", kind::DEPENDENCY)
            .subject("alpha")
            .attr("dep", "beta")
            .attr("range", ">=1.0.0")
            .attr("mandatory", true)
            .emit();
        let target = target();
        let findings = DependencyRule
            .evaluate(&RuleCtx::for_test(&store, &target))
            .unwrap();
        assert!(
            !findings.iter().any(|f| {
                f.id == "dependency-resolution-skipped" || f.id == "dependency-unsat:global"
            }),
            "a satisfiable graph should emit neither, got: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn unsat_evidence_is_limited_to_derivation_packages() {
        let mut store = FactStore::new();
        for (id, version) in [
            ("alpha", "1.0.0"),
            ("beta", "1.0.0"),
            ("unrelated", "1.0.0"),
            ("also-unrelated", "1.0.0"),
        ] {
            store
                .fact("meta", kind::MOD)
                .subject(id)
                .attr("version", version)
                .emit();
        }
        let relevant = store
            .fact("meta", kind::DEPENDENCY)
            .subject("alpha")
            .attr("dep", "beta")
            .attr("range", ">=2.0.0")
            .attr("mandatory", true)
            .emit();
        let unrelated = store
            .fact("meta", kind::DEPENDENCY)
            .subject("unrelated")
            .attr("dep", "also-unrelated")
            .attr("range", ">=1.0.0")
            .attr("mandatory", true)
            .emit();

        let target = target();
        let findings = DependencyRule
            .evaluate(&RuleCtx::for_test(&store, &target))
            .unwrap();
        let unsat = findings
            .iter()
            .find(|finding| finding.id == "dependency-unsat:global")
            .expect("expected global unsat");
        assert!(unsat.evidence.iter().any(|edge| edge.fact == relevant));
        assert!(!unsat.evidence.iter().any(|edge| edge.fact == unrelated));
        assert!(unsat.evidence.len() <= 3, "evidence: {:?}", unsat.evidence);
    }
}
