//! Layer-C doctor rule: pairwise semver checks plus PubGrub global resolution.

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{Rule, RuleCtx};

use crate::implicit::implicit_findings;
use crate::ordering::ordering_findings;
use crate::pairwise::pairwise_findings;
use crate::resolver::{resolve_store, ResolutionOutcome};

/// Layer-C dependency rule: direct semver checks and PubGrub global unsat.
pub struct DependencyRule;

impl Rule for DependencyRule {
    fn id(&self) -> &'static str {
        "dependency"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut out = pairwise_findings(ctx, self.id());
        out.extend(ordering_findings(ctx, self.id()));
        out.extend(implicit_findings(ctx, self.id()));
        if should_emit_pubgrub_unsat(&out) {
            if let Some(finding) = pubgrub_finding(ctx, self.id()) {
                out.push(finding);
            }
        }
        out
    }
}

/// Suppress the global PubGrub unsat when pairwise checks already surfaced a
/// plain `missing-dependency` root cause. Version-range conflicts still emit the
/// global tree because it explains the joint unsat better than a single edge.
fn should_emit_pubgrub_unsat(pairwise: &[Finding]) -> bool {
    let has_missing = pairwise
        .iter()
        .any(|f| f.id.starts_with("missing-dependency:"));
    let has_version = pairwise.iter().any(|f| {
        f.id.starts_with("wrong-version:") || f.id.starts_with("wrong-mc-version:")
    });
    if has_version {
        return true;
    }
    !has_missing
}

fn pubgrub_finding(ctx: &RuleCtx<'_>, rule_id: &str) -> Option<Finding> {
    let outcome = resolve_store(ctx.store).ok()?;
    let ResolutionOutcome::Unsatisfiable { explanation } = outcome else {
        return None;
    };
    if explanation.trim().is_empty() {
        return None;
    }

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

    for dep in ctx.store.by_kind(kind::DEPENDENCY) {
        builder = builder.evidence(EvidenceEdge::supports(dep.id));
    }

    Some(builder.build())
}