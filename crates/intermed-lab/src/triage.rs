//! Semantic mismatch clustering for campaign triage.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::eval::{FindingMatchOutcome, RuleAccuracyReport};

pub const TRIAGE_SCHEMA: &str = "intermed-lab-triage-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MismatchCluster {
    pub id: String,
    pub rule_id: String,
    pub category: String,
    pub outcome: FindingMatchOutcome,
    pub occurrences: usize,
    pub semantic_findings: Vec<String>,
    pub representative_findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageReport {
    pub schema: String,
    pub clusters: Vec<MismatchCluster>,
}

#[must_use]
pub fn cluster_accuracy(reports: &[RuleAccuracyReport]) -> TriageReport {
    let mut groups =
        BTreeMap::<(String, String, FindingMatchOutcome), Vec<(String, String)>>::new();
    for report in reports {
        for finding in &report.by_finding {
            if !matches!(
                finding.outcome,
                FindingMatchOutcome::FalsePositive | FindingMatchOutcome::InconclusiveCoverage
            ) {
                continue;
            }
            groups
                .entry((
                    finding.rule_id.clone(),
                    finding.category.clone(),
                    finding.outcome.clone(),
                ))
                .or_default()
                .push((finding.semantic_id.clone(), finding.finding_id.clone()));
        }
    }
    let mut clusters = groups
        .into_iter()
        .map(|((rule_id, category, outcome), rows)| {
            let mut semantic_findings = rows
                .iter()
                .map(|(semantic, _)| semantic.clone())
                .collect::<Vec<_>>();
            semantic_findings.sort();
            semantic_findings.dedup();
            let mut representative_findings = rows
                .iter()
                .map(|(_, occurrence)| occurrence.clone())
                .collect::<Vec<_>>();
            representative_findings.sort();
            representative_findings.dedup();
            representative_findings.truncate(10);
            let identity = format!("{rule_id}\0{category}\0{outcome:?}");
            MismatchCluster {
                id: format!("triage:{:x}", Sha256::digest(identity.as_bytes())),
                rule_id,
                category,
                outcome,
                occurrences: rows.len(),
                semantic_findings,
                representative_findings,
            }
        })
        .collect::<Vec<_>>();
    clusters.sort_by(|left, right| {
        right
            .occurrences
            .cmp(&left.occurrences)
            .then(left.id.cmp(&right.id))
    });
    TriageReport {
        schema: TRIAGE_SCHEMA.to_string(),
        clusters,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::{BlameAccuracy, FindingAccuracy, FindingLevelAccuracy, RULE_ACCURACY_SCHEMA};

    fn report() -> RuleAccuracyReport {
        RuleAccuracyReport {
            schema: RULE_ACCURACY_SCHEMA.into(),
            min_severity: "warn".into(),
            cases: 1,
            eligible_cases: 1,
            excluded_cases: 0,
            by_category: Vec::new(),
            by_rule: Vec::new(),
            by_finding: vec![
                FindingAccuracy {
                    finding_id: "a:1".into(),
                    semantic_id: "a:x".into(),
                    rule_id: "a".into(),
                    subject: "x".into(),
                    category: "missing-dependency".into(),
                    severity: "error".into(),
                    outcome: FindingMatchOutcome::FalsePositive,
                    matched_subject: None,
                },
                FindingAccuracy {
                    finding_id: "a:2".into(),
                    semantic_id: "a:y".into(),
                    rule_id: "a".into(),
                    subject: "y".into(),
                    category: "missing-dependency".into(),
                    severity: "error".into(),
                    outcome: FindingMatchOutcome::FalsePositive,
                    matched_subject: None,
                },
            ],
            finding_level: FindingLevelAccuracy {
                attributed: false,
                coverage_aware: true,
                predictions: 2,
                attributions: 0,
                true_positive: 0,
                false_positive: 2,
                false_negative: 0,
                abstained: 0,
                inconclusive_coverage: 0,
                precision: Some(0.0),
                recall: None,
                f1: None,
            },
            blame: BlameAccuracy {
                predictions: 0,
                true_positive: 0,
                false_positive: 0,
                precision: None,
                precision_lower_bound: None,
                calibration_support: 0,
                suggested_severity: "note".into(),
            },
            macro_precision_category: None,
            macro_recall_category: None,
            macro_precision_rule: None,
            macro_recall_rule: None,
        }
    }

    #[test]
    fn groups_repeated_mismatches_by_semantic_family() {
        let triage = cluster_accuracy(&[report()]);
        assert_eq!(triage.clusters.len(), 1);
        assert_eq!(triage.clusters[0].occurrences, 2);
        assert_eq!(triage.clusters[0].semantic_findings.len(), 2);
    }
}
