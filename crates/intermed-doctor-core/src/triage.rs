//! Finding aggregation and presentation triage between reconciliation and
//! immutable report assembly.

use intermed_evidence::{Finding, FindingChannel, FindingVisibility, Severity};
use intermed_facts::FactStore;

use crate::{DiagnosisSettings, TargetCapabilities};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TriageOutcome {
    pub input_findings: usize,
    pub output_findings: usize,
}

/// A deterministic finding-to-finding transformation. Unlike a [`crate::Rule`],
/// this stage does not derive conclusions directly from raw facts.
pub trait FindingPostProcessor: Send + Sync {
    fn id(&self) -> &'static str;

    fn process(
        &self,
        store: &FactStore,
        capabilities: &TargetCapabilities,
        settings: &DiagnosisSettings,
        findings: &mut Vec<Finding>,
    ) -> TriageOutcome;
}

pub struct DefaultTriage;

impl FindingPostProcessor for DefaultTriage {
    fn id(&self) -> &'static str {
        "default-triage"
    }

    fn process(
        &self,
        store: &FactStore,
        _capabilities: &TargetCapabilities,
        _settings: &DiagnosisSettings,
        findings: &mut Vec<Finding>,
    ) -> TriageOutcome {
        let input_findings = findings.len();
        crate::suppression::apply_semantic_override_suppression(findings);
        crate::suppression::apply_runtime_caveats(findings, store);
        crate::report::cluster_resource_conflicts(findings, store);
        crate::report::cluster_loader_mismatches(findings, store);
        // Assessment has already run in the engine before reconciliation.
        // Calling assess_findings() here would overwrite reconciliation's
        // disposition adjustments (e.g., Abstained from cross-layer
        // contradictions would revert to Asserted). Triage is presentation-only.
        apply_visibility_policy(findings);
        apply_channel_tags(findings);
        TriageOutcome {
            input_findings,
            output_findings: findings.len(),
        }
    }
}

/// Presentation visibility must never rewrite semantic severity.
pub(crate) fn apply_visibility_policy(findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        let has_tag = |tag: &str| finding.machine_tags.iter().any(|value| value == tag);
        if has_tag("safe-merge") || has_tag("safe-crdt-merge") {
            finding.visibility = FindingVisibility::ExplainOnly;
        } else if has_tag("root-metadata") {
            finding.visibility = FindingVisibility::OverlayOnly;
        } else if finding.severity <= Severity::Note && has_tag("mixin-detail") {
            finding.visibility = FindingVisibility::Verbose;
        } else if (finding.assessment.disposition
            == intermed_evidence::AssessmentDisposition::Abstained
            || finding.assessment.certainty == intermed_evidence::CertaintyTier::Undecidable)
            && has_tag("apply-failure")
            && has_tag("mixin")
        {
            // Site-level apply hypotheses without a decidable proof remain
            // available in JSON/Explain and the Mixin coverage passport. They
            // must not turn one missing/unusable refmap into thousands of
            // default user-facing warnings.
            finding.visibility = FindingVisibility::ExplainOnly;
        }
    }
}

fn apply_channel_tags(findings: &mut [Finding]) {
    for finding in findings {
        let tag = if finding.channel == FindingChannel::Incident {
            "incident-diagnosis"
        } else {
            "pack-health-static-review"
        };
        if !finding.machine_tags.iter().any(|existing| existing == tag) {
            finding.machine_tags.push(tag.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_is_semantics_preserving() {
        let mut findings = vec![
            Finding::builder("resource", "safe")
                .severity(Severity::Note)
                .tag("safe-merge")
                .build(),
        ];
        apply_visibility_policy(&mut findings);
        assert_eq!(findings[0].severity, Severity::Note);
        assert_eq!(findings[0].visibility, FindingVisibility::ExplainOnly);
    }

    #[test]
    fn undecidable_mixin_apply_hypothesis_is_explain_only() {
        let mut finding = Finding::builder("mixin", "refmap-site")
            .severity(Severity::Warn)
            .tag("mixin")
            .tag("apply-failure")
            .build();
        finding.assessment.certainty = intermed_evidence::CertaintyTier::Undecidable;
        let mut findings = vec![finding];

        apply_visibility_policy(&mut findings);

        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(findings[0].visibility, FindingVisibility::ExplainOnly);
    }
}
