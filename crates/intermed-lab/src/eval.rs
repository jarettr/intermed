//! Closing the precision loop: measure the Doctor against lab ground truth.
//!
//! Two evaluation modes ship in one report:
//!
//! 1. **Category co-occurrence** ([`CategoryAccuracy`]) — first-order framework.
//!    Per (mod-set, category): was the category predicted *and* observed? One
//!    tp/fp/fn per case. Intra-case multiplicity collapses ("five overlap flags,
//!    one mixin crash" → one tp, not one tp + four fp). Loader, side, and
//!    duplicate rules share the `mod-loading-failure` bucket.
//!
//! 2. **Attributed finding-level** ([`RuleAccuracy`], [`FindingLevelAccuracy`]) —
//!    joins each qualifying Doctor finding against lab [`FailureAttribution`]
//!    subjects extracted from crash logs. Each flagged finding is its own
//!    prediction unit; unattributed lab failures do not penalize unrelated rules.
//!
//! Only *predictive* findings participate (mixin, dependency, loader/side/duplicate).
//! Reactive findings (security, SBOM, log-signal) are excluded.
//!
//! [`suggest_severity`] recommends louder severities from observed precision but
//! stays at `Note` until [`SEVERITY_CALIBRATION_MIN_SUPPORT`] predictions exist,
//! so tiny samples (tp=2, fp=0 → precision 1.0) cannot force `Error` in CI.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use intermed_doctor_core::DoctorReport;
use intermed_doctor_core::evidence::{Finding, Severity};

use crate::attribution::{
    FailureAttribution, SEVERITY_CALIBRATION_MIN_SUPPORT, subject_from_finding_id, subjects_match,
};
use crate::classify::FailureCategory;
use crate::run::{LabRun, read_run};
use crate::{LabError, read_json, write_json_atomic};

/// Schema tag for the emitted accuracy report.
pub const RULE_ACCURACY_SCHEMA: &str = "intermed-rule-accuracy-v3";
/// Schema tag for the evaluation manifest (a dataset of report/run pairs).
pub const EVAL_MANIFEST_SCHEMA: &str = "intermed-eval-manifest-v1";

/// A single Doctor prediction reduced to the failure category it forecasts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prediction {
    pub rule_id: String,
    pub finding_id: String,
    pub subject: String,
    pub category: FailureCategory,
    pub severity: Severity,
}

/// Map a finding (by its machine tags) to the load-failure category it predicts,
/// or `None` for non-predictive findings.
#[must_use]
pub fn predicted_category(tags: &[String]) -> Option<FailureCategory> {
    let has = |t: &str| tags.iter().any(|x| x == t);
    if has("mixin") {
        Some(FailureCategory::MixinApplyError)
    } else if has("dependency") {
        Some(FailureCategory::MissingDependency)
    } else if has("performance") || has("spark") || has("hot-path") {
        Some(FailureCategory::PerformanceRegression)
    } else if has("loader") || has("side") || has("duplicate") {
        Some(FailureCategory::ModLoadingFailure)
    } else {
        None
    }
}

/// Reduce a finding set to attributed predictions (one row per qualifying finding).
#[must_use]
pub fn predictions_from_findings(findings: &[Finding]) -> Vec<Prediction> {
    findings
        .iter()
        .filter_map(|f| {
            let category = predicted_category(&f.machine_tags)?;
            let subject = f
                .affected_components
                .first()
                .map(String::as_str)
                .unwrap_or_else(|| subject_from_finding_id(&f.id));
            Some(Prediction {
                rule_id: f.rule_id.clone(),
                finding_id: f.id.clone(),
                subject: subject.to_string(),
                category,
                severity: f.severity,
            })
        })
        .collect()
}

/// Reduce a Doctor report to the predictions it carries.
#[must_use]
pub fn predictions_from_report(report: &DoctorReport) -> Vec<Prediction> {
    predictions_from_findings(&report.findings)
}

/// One frame-to-jar blame the Doctor made: a mod blamed because a crash stack frame
/// (`frame_class`) falls under a package that mod exclusively owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlamePrediction {
    pub mod_id: String,
    /// The resolved stack-frame class that drove the blame (from the
    /// `frame-class:<class>` machine tag).
    pub frame_class: String,
    pub severity: Severity,
}

/// Extract the Doctor's frame-to-jar blames (`crash-blame:*` findings carrying a
/// `frame-class:<class>` tag). Ambiguous (`crash-blame-ambiguous:*`) blames are
/// excluded — they make no confident claim to score.
#[must_use]
pub fn blame_predictions_from_findings(findings: &[Finding]) -> Vec<BlamePrediction> {
    findings
        .iter()
        .filter(|f| {
            f.machine_tags.iter().any(|t| t == "crash-blame")
                && !f.machine_tags.iter().any(|t| t == "ambiguous")
        })
        .filter_map(|f| {
            let frame_class = f
                .machine_tags
                .iter()
                .find_map(|t| t.strip_prefix("frame-class:"))?
                .to_string();
            let mod_id = f
                .affected_components
                .first()
                .cloned()
                .unwrap_or_else(|| subject_from_finding_id(&f.id).to_string());
            Some(BlamePrediction {
                mod_id,
                frame_class,
                severity: f.severity,
            })
        })
        .collect()
}

/// Calibrated blame accuracy: how often a frame-to-jar blame names a frame the lab
/// actually attributed the crash to. Precision is only "trusted" (a louder
/// confidence suggested) once [`SEVERITY_CALIBRATION_MIN_SUPPORT`] blames exist.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlameAccuracy {
    pub predictions: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub precision: f64,
    pub calibration_support: usize,
    /// Suggested blame confidence, gated on support (mirrors severity calibration).
    pub suggested_severity: String,
}

/// Score frame-to-jar blames against ground-truth crash attributions. A blame is a
/// true positive when its `frame_class` matches a class the lab attributed the crash
/// to (the owning mod was correctly placed on the failing path).
fn evaluate_blame(cases: &[EvalCase]) -> BlameAccuracy {
    let (mut tp, mut fp) = (0usize, 0usize);
    for case in cases {
        for blame in &case.blame_predictions {
            let hit = case
                .attributions
                .iter()
                .any(|attr| subjects_match(&blame.frame_class, &attr.subject));
            if hit {
                tp += 1;
            } else {
                fp += 1;
            }
        }
    }
    let precision = ratio(tp, tp + fp);
    BlameAccuracy {
        predictions: tp + fp,
        true_positive: tp,
        false_positive: fp,
        precision,
        calibration_support: tp + fp,
        suggested_severity: suggest_severity(tp, fp).as_str().to_string(),
    }
}

/// Ground-truth categories the lab observed across a run (co-occurrence mode).
#[must_use]
pub fn observed_from_run(run: &LabRun) -> BTreeSet<FailureCategory> {
    let mut out = BTreeSet::new();
    for r in &run.results {
        if let Some(c) = r.failure {
            out.insert(c);
        }
        out.extend(r.additional_failures.iter().copied());
    }
    out
}

/// All attributed failures across a lab run (finding-level mode).
#[must_use]
pub fn attributions_from_run(run: &LabRun) -> Vec<FailureAttribution> {
    let mut out = Vec::new();
    for r in &run.results {
        out.extend(r.attributions.iter().cloned());
    }
    out.sort();
    out.dedup();
    out
}

/// One labelled evaluation unit: Doctor predictions vs lab observations for one mod set.
#[derive(Debug, Clone)]
pub struct EvalCase {
    pub predictions: Vec<Prediction>,
    pub observed: BTreeSet<FailureCategory>,
    pub attributions: Vec<FailureAttribution>,
    /// Frame-to-jar blames the Doctor made for this case (calibrated separately).
    pub blame_predictions: Vec<BlamePrediction>,
}

/// Per-category co-occurrence accuracy (one tp/fp/fn per case).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CategoryAccuracy {
    pub category: String,
    pub true_positive: usize,
    pub false_positive: usize,
    pub false_negative: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub suggested_severity: String,
    /// `tp + fp` across cases (not per-finding count).
    pub calibration_support: usize,
}

/// Outcome for one Doctor finding against lab attributions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingMatchOutcome {
    TruePositive,
    FalsePositive,
    /// Finding below `min_severity` — excluded from scoring.
    BelowThreshold,
}

/// Per-finding attributed accuracy row (finest eval granularity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingAccuracy {
    pub finding_id: String,
    pub rule_id: String,
    pub subject: String,
    pub category: String,
    pub severity: String,
    pub outcome: FindingMatchOutcome,
    /// Attribution subject joined on success (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_subject: Option<String>,
}

/// Per-rule attributed finding-level accuracy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleAccuracy {
    pub rule_id: String,
    pub predictions: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub false_negative: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub suggested_severity: String,
    pub calibration_support: usize,
}

/// Aggregated attributed metrics across all predictive rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingLevelAccuracy {
    /// Whether any case in the dataset carried lab attributions.
    pub attributed: bool,
    pub predictions: usize,
    pub attributions: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub false_negative: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// The full accuracy report over a dataset of cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleAccuracyReport {
    pub schema: String,
    pub min_severity: String,
    pub cases: usize,
    /// Category co-occurrence (first-order; collapses intra-case multiplicity).
    pub by_category: Vec<CategoryAccuracy>,
    /// Per-rule finding-level join (requires lab attributions).
    pub by_rule: Vec<RuleAccuracy>,
    /// One row per qualifying finding (requires lab attributions).
    pub by_finding: Vec<FindingAccuracy>,
    /// All predictive rules combined at finding granularity.
    pub finding_level: FindingLevelAccuracy,
    /// Calibrated frame-to-jar blame accuracy (crash-blame findings vs ground truth).
    pub blame: BlameAccuracy,
    pub macro_precision_category: f64,
    pub macro_recall_category: f64,
    pub macro_precision_rule: f64,
    pub macro_recall_rule: f64,
}

/// Ground severity in observed precision, gated on minimum support.
///
/// Below [`SEVERITY_CALIBRATION_MIN_SUPPORT`] flagged predictions the
/// recommendation stays `Note` regardless of precision.
#[must_use]
pub fn suggest_severity(true_positive: usize, false_positive: usize) -> Severity {
    let predicted = true_positive + false_positive;
    if predicted < SEVERITY_CALIBRATION_MIN_SUPPORT {
        return Severity::Note;
    }
    let precision = true_positive as f64 / predicted as f64;
    if precision >= 0.40 {
        Severity::Error
    } else if precision >= 0.10 {
        Severity::Warn
    } else {
        Severity::Note
    }
}

fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

fn f1(precision: f64, recall: f64) -> f64 {
    if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    }
}

fn qualifies(p: &Prediction, min_severity: Severity) -> bool {
    p.severity >= min_severity
}

/// Category co-occurrence evaluation (legacy first-order mode).
fn evaluate_by_category(cases: &[EvalCase], min_severity: Severity) -> Vec<CategoryAccuracy> {
    let mut universe: BTreeSet<FailureCategory> = BTreeSet::new();
    for c in cases {
        for p in &c.predictions {
            if qualifies(p, min_severity) {
                universe.insert(p.category);
            }
        }
        universe.extend(c.observed.iter().copied());
    }

    let mut by_category = Vec::new();
    for cat in &universe {
        let (mut tp, mut fp, mut fn_) = (0usize, 0usize, 0usize);
        for case in cases {
            let predicted = case
                .predictions
                .iter()
                .any(|p| p.category == *cat && qualifies(p, min_severity));
            let observed = case.observed.contains(cat);
            match (predicted, observed) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, true) => fn_ += 1,
                (false, false) => {}
            }
        }
        let precision = ratio(tp, tp + fp);
        let recall = ratio(tp, tp + fn_);
        by_category.push(CategoryAccuracy {
            category: cat.as_str().to_string(),
            true_positive: tp,
            false_positive: fp,
            false_negative: fn_,
            precision,
            recall,
            f1: f1(precision, recall),
            calibration_support: tp + fp,
            suggested_severity: suggest_severity(tp, fp).as_str().to_string(),
        });
    }
    by_category
}

struct RuleCounts {
    tp: usize,
    fp: usize,
    fn_: usize,
    predictions: usize,
}

/// Collect rule ids that ever predicted each category (dataset-wide).
fn rules_per_category(
    cases: &[EvalCase],
    min_severity: Severity,
) -> BTreeMap<FailureCategory, BTreeSet<String>> {
    let mut out: BTreeMap<FailureCategory, BTreeSet<String>> = BTreeMap::new();
    for case in cases {
        for pred in &case.predictions {
            if qualifies(pred, min_severity) {
                out.entry(pred.category)
                    .or_default()
                    .insert(pred.rule_id.clone());
            }
        }
    }
    out
}

/// Per-rule, per-finding, and aggregate finding-level evaluation.
fn evaluate_by_rule(
    cases: &[EvalCase],
    min_severity: Severity,
) -> (
    Vec<RuleAccuracy>,
    Vec<FindingAccuracy>,
    FindingLevelAccuracy,
) {
    let has_attributions = cases.iter().any(|c| !c.attributions.is_empty());
    if !has_attributions {
        return (
            Vec::new(),
            Vec::new(),
            FindingLevelAccuracy {
                attributed: false,
                predictions: 0,
                attributions: 0,
                true_positive: 0,
                false_positive: 0,
                false_negative: 0,
                precision: 0.0,
                recall: 0.0,
                f1: 0.0,
            },
        );
    }

    let rules_by_category = rules_per_category(cases, min_severity);

    let mut per_rule: BTreeMap<String, RuleCounts> = BTreeMap::new();
    let mut by_finding: Vec<FindingAccuracy> = Vec::new();
    let mut total_tp = 0usize;
    let mut total_fp = 0usize;
    let mut total_fn = 0usize;
    let mut total_predictions = 0usize;
    let mut total_attributions = 0usize;

    for case in cases {
        let attrs: Vec<&FailureAttribution> = case.attributions.iter().collect();
        total_attributions += attrs.len();

        let flagged: Vec<&Prediction> = case
            .predictions
            .iter()
            .filter(|p| qualifies(p, min_severity))
            .collect();
        total_predictions += flagged.len();

        for pred in &flagged {
            let entry = per_rule.entry(pred.rule_id.clone()).or_insert(RuleCounts {
                tp: 0,
                fp: 0,
                fn_: 0,
                predictions: 0,
            });
            entry.predictions += 1;

            let matched = attrs.iter().find(|attr| {
                pred.category == attr.category && subjects_match(&pred.subject, &attr.subject)
            });
            if let Some(attr) = matched {
                entry.tp += 1;
                total_tp += 1;
                by_finding.push(FindingAccuracy {
                    finding_id: pred.finding_id.clone(),
                    rule_id: pred.rule_id.clone(),
                    subject: pred.subject.clone(),
                    category: pred.category.as_str().to_string(),
                    severity: pred.severity.as_str().to_string(),
                    outcome: FindingMatchOutcome::TruePositive,
                    matched_subject: Some(attr.subject.clone()),
                });
            } else {
                entry.fp += 1;
                total_fp += 1;
                by_finding.push(FindingAccuracy {
                    finding_id: pred.finding_id.clone(),
                    rule_id: pred.rule_id.clone(),
                    subject: pred.subject.clone(),
                    category: pred.category.as_str().to_string(),
                    severity: pred.severity.as_str().to_string(),
                    outcome: FindingMatchOutcome::FalsePositive,
                    matched_subject: None,
                });
            }
        }

        for pred in case
            .predictions
            .iter()
            .filter(|p| !qualifies(p, min_severity))
        {
            by_finding.push(FindingAccuracy {
                finding_id: pred.finding_id.clone(),
                rule_id: pred.rule_id.clone(),
                subject: pred.subject.clone(),
                category: pred.category.as_str().to_string(),
                severity: pred.severity.as_str().to_string(),
                outcome: FindingMatchOutcome::BelowThreshold,
                matched_subject: None,
            });
        }

        for attr in &attrs {
            let Some(rule_ids) = rules_by_category.get(&attr.category) else {
                continue;
            };

            let any_rule_matched = flagged.iter().any(|pred| {
                pred.category == attr.category && subjects_match(&pred.subject, &attr.subject)
            });
            if !any_rule_matched {
                total_fn += 1;
            }

            for rule_id in rule_ids {
                let rule_matched = case.predictions.iter().any(|p| {
                    p.rule_id == *rule_id
                        && qualifies(p, min_severity)
                        && p.category == attr.category
                        && subjects_match(&p.subject, &attr.subject)
                });
                if !rule_matched {
                    let entry = per_rule.entry(rule_id.clone()).or_insert(RuleCounts {
                        tp: 0,
                        fp: 0,
                        fn_: 0,
                        predictions: 0,
                    });
                    entry.fn_ += 1;
                }
            }
        }
    }

    let mut by_rule = Vec::new();
    for (rule_id, counts) in per_rule {
        let precision = ratio(counts.tp, counts.tp + counts.fp);
        let recall = ratio(counts.tp, counts.tp + counts.fn_);
        by_rule.push(RuleAccuracy {
            rule_id,
            predictions: counts.predictions,
            true_positive: counts.tp,
            false_positive: counts.fp,
            false_negative: counts.fn_,
            precision,
            recall,
            f1: f1(precision, recall),
            calibration_support: counts.tp + counts.fp,
            suggested_severity: suggest_severity(counts.tp, counts.fp).as_str().to_string(),
        });
    }

    let fl_precision = ratio(total_tp, total_tp + total_fp);
    let fl_recall = ratio(total_tp, total_tp + total_fn);
    let finding_level = FindingLevelAccuracy {
        attributed: true,
        predictions: total_predictions,
        attributions: total_attributions,
        true_positive: total_tp,
        false_positive: total_fp,
        false_negative: total_fn,
        precision: fl_precision,
        recall: fl_recall,
        f1: f1(fl_precision, fl_recall),
    };

    by_finding.sort_by(|a, b| {
        a.finding_id
            .cmp(&b.finding_id)
            .then(a.rule_id.cmp(&b.rule_id))
    });

    (by_rule, by_finding, finding_level)
}

fn macro_avg(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

/// Compute the full accuracy report over labelled cases.
#[must_use]
pub fn evaluate(cases: &[EvalCase], min_severity: Severity) -> RuleAccuracyReport {
    let by_category = evaluate_by_category(cases, min_severity);
    let (by_rule, by_finding, finding_level) = evaluate_by_rule(cases, min_severity);
    let blame = evaluate_blame(cases);

    RuleAccuracyReport {
        schema: RULE_ACCURACY_SCHEMA.to_string(),
        min_severity: min_severity.as_str().to_string(),
        cases: cases.len(),
        macro_precision_category: macro_avg(
            &by_category.iter().map(|c| c.precision).collect::<Vec<_>>(),
        ),
        macro_recall_category: macro_avg(&by_category.iter().map(|c| c.recall).collect::<Vec<_>>()),
        macro_precision_rule: macro_avg(&by_rule.iter().map(|r| r.precision).collect::<Vec<_>>()),
        macro_recall_rule: macro_avg(&by_rule.iter().map(|r| r.recall).collect::<Vec<_>>()),
        by_category,
        by_rule,
        by_finding,
        finding_level,
        blame,
    }
}

// ── Dataset / IO ───────────────────────────────────────────────────────────

/// A dataset of (doctor report, lab run) pairs to evaluate together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalManifest {
    pub schema: String,
    pub cases: Vec<EvalPair>,
}

/// One report/run pair; paths are resolved relative to the manifest file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalPair {
    pub report: PathBuf,
    pub run: PathBuf,
}

fn resolve(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.parent().unwrap_or_else(|| Path::new(".")).join(p)
    }
}

/// Build one case from a doctor report file and a lab run file.
pub fn case_from_files(report_path: &Path, run_path: &Path) -> Result<EvalCase, LabError> {
    let report: DoctorReport = read_json(report_path)?;
    let run = read_run(run_path)?;
    Ok(EvalCase {
        predictions: predictions_from_report(&report),
        observed: observed_from_run(&run),
        attributions: attributions_from_run(&run),
        blame_predictions: blame_predictions_from_findings(&report.findings),
    })
}

/// `lab eval` over a single report/run pair.
pub fn evaluate_pair(
    report_path: &Path,
    run_path: &Path,
    min_severity: Severity,
    out: &Path,
) -> Result<RuleAccuracyReport, LabError> {
    let case = case_from_files(report_path, run_path)?;
    let report = evaluate(&[case], min_severity);
    write_json_atomic(out, &report)?;
    Ok(report)
}

/// `lab eval` over a manifest dataset of report/run pairs.
pub fn evaluate_manifest(
    manifest_path: &Path,
    min_severity: Severity,
    out: &Path,
) -> Result<RuleAccuracyReport, LabError> {
    let manifest: EvalManifest = read_json(manifest_path)?;
    if manifest.schema != EVAL_MANIFEST_SCHEMA {
        return Err(LabError::schema(
            manifest_path,
            EVAL_MANIFEST_SCHEMA,
            &manifest.schema,
        ));
    }
    let mut cases = Vec::with_capacity(manifest.cases.len());
    for pair in &manifest.cases {
        cases.push(case_from_files(
            &resolve(manifest_path, &pair.report),
            &resolve(manifest_path, &pair.run),
        )?);
    }
    let report = evaluate(&cases, min_severity);
    write_json_atomic(out, &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::evidence::{Category, Finding};

    fn finding(rule: &str, id: &str, sev: Severity, tags: &[&str]) -> Finding {
        let mut b = Finding::builder(rule, id)
            .severity(sev)
            .category(Category::Mixin)
            .title("t")
            .explanation("e");
        for t in tags {
            b = b.tag(*t);
        }
        b.build()
    }

    fn case(
        preds: Vec<Prediction>,
        observed: &[FailureCategory],
        attrs: Vec<FailureAttribution>,
    ) -> EvalCase {
        EvalCase {
            predictions: preds,
            observed: observed.iter().copied().collect(),
            attributions: attrs,
            blame_predictions: Vec::new(),
        }
    }

    fn blame_case(blames: Vec<BlamePrediction>, attrs: Vec<FailureAttribution>) -> EvalCase {
        EvalCase {
            predictions: Vec::new(),
            observed: BTreeSet::new(),
            attributions: attrs,
            blame_predictions: blames,
        }
    }

    fn blame(mod_id: &str, frame_class: &str) -> BlamePrediction {
        BlamePrediction {
            mod_id: mod_id.to_string(),
            frame_class: frame_class.to_string(),
            severity: Severity::Warn,
        }
    }

    fn pred(
        rule: &str,
        id: &str,
        subject: &str,
        cat: FailureCategory,
        sev: Severity,
    ) -> Prediction {
        Prediction {
            rule_id: rule.to_string(),
            finding_id: id.to_string(),
            subject: subject.to_string(),
            category: cat,
            severity: sev,
        }
    }

    fn attr(cat: FailureCategory, subject: &str) -> FailureAttribution {
        FailureAttribution {
            category: cat,
            subject: subject.to_string(),
            line_excerpt: None,
        }
    }

    #[test]
    fn maps_only_predictive_tags() {
        assert_eq!(
            predicted_category(&["mixin".into(), "overlap".into()]),
            Some(FailureCategory::MixinApplyError)
        );
        assert_eq!(predicted_category(&["security".into()]), None);
    }

    #[test]
    fn predictions_filter_to_predictive_findings() {
        let findings = vec![
            finding(
                "mixin-risk",
                "mixin-risk:WorldRenderer",
                Severity::Warn,
                &["mixin", "overlap"],
            ),
            finding(
                "security-api-risk",
                "security-api-risk:x",
                Severity::Warn,
                &["security"],
            ),
        ];
        let preds = predictions_from_findings(&findings);
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0].category, FailureCategory::MixinApplyError);
        assert_eq!(preds[0].subject, "WorldRenderer");
    }

    #[test]
    fn category_cooccurrence_collapses_multiplicity() {
        let cases = vec![case(
            vec![
                pred(
                    "mixin-risk",
                    "a",
                    "ClassA",
                    FailureCategory::MixinApplyError,
                    Severity::Warn,
                ),
                pred(
                    "mixin-risk",
                    "b",
                    "ClassB",
                    FailureCategory::MixinApplyError,
                    Severity::Warn,
                ),
                pred(
                    "mixin-risk",
                    "c",
                    "ClassC",
                    FailureCategory::MixinApplyError,
                    Severity::Warn,
                ),
                pred(
                    "mixin-risk",
                    "d",
                    "ClassD",
                    FailureCategory::MixinApplyError,
                    Severity::Warn,
                ),
                pred(
                    "mixin-risk",
                    "e",
                    "WorldRenderer",
                    FailureCategory::MixinApplyError,
                    Severity::Warn,
                ),
            ],
            &[FailureCategory::MixinApplyError],
            vec![attr(
                FailureCategory::MixinApplyError,
                "net.minecraft.client.render.WorldRenderer",
            )],
        )];
        let report = evaluate(&cases, Severity::Note);
        let mixin = report
            .by_category
            .iter()
            .find(|c| c.category == "mixin-apply-error")
            .unwrap();
        assert_eq!((mixin.true_positive, mixin.false_positive), (1, 0));
        let fl = &report.finding_level;
        assert!(fl.attributed);
        assert_eq!((fl.true_positive, fl.false_positive), (1, 4));
    }

    #[test]
    fn by_finding_records_matched_subject() {
        let cases = vec![case(
            vec![pred(
                "mixin-risk",
                "mixin-risk:Foo",
                "Foo",
                FailureCategory::MixinApplyError,
                Severity::Warn,
            )],
            &[FailureCategory::MixinApplyError],
            vec![attr(FailureCategory::MixinApplyError, "Foo")],
        )];
        let report = evaluate(&cases, Severity::Warn);
        assert_eq!(report.by_finding.len(), 1);
        assert_eq!(
            report.by_finding[0].outcome,
            FindingMatchOutcome::TruePositive
        );
        assert_eq!(report.by_finding[0].matched_subject.as_deref(), Some("Foo"));
    }

    #[test]
    fn finding_level_counts_each_prediction() {
        let cases = vec![case(
            vec![
                pred(
                    "mixin-risk",
                    "1",
                    "Foo",
                    FailureCategory::MixinApplyError,
                    Severity::Warn,
                ),
                pred(
                    "mixin-risk",
                    "2",
                    "Bar",
                    FailureCategory::MixinApplyError,
                    Severity::Warn,
                ),
            ],
            &[FailureCategory::MixinApplyError],
            vec![attr(FailureCategory::MixinApplyError, "Foo")],
        )];
        let report = evaluate(&cases, Severity::Warn);
        assert_eq!(report.finding_level.true_positive, 1);
        assert_eq!(report.finding_level.false_positive, 1);
    }

    #[test]
    fn unattributed_mixin_does_not_fn_overlap_rule() {
        let cases = vec![case(
            vec![],
            &[FailureCategory::ModLoadingFailure],
            vec![attr(FailureCategory::ModLoadingFailure, "broken-mod")],
        )];
        let report = evaluate(&cases, Severity::Warn);
        let mixin = report
            .by_category
            .iter()
            .find(|c| c.category == "mixin-apply-error");
        assert!(mixin.is_none());
        assert_eq!(report.finding_level.false_negative, 0);
    }

    #[test]
    fn min_severity_gates_predictions() {
        let cases = vec![case(
            vec![pred(
                "mixin-risk",
                "x",
                "Foo",
                FailureCategory::MixinApplyError,
                Severity::Note,
            )],
            &[FailureCategory::MixinApplyError],
            vec![attr(FailureCategory::MixinApplyError, "Foo")],
        )];
        let warned = evaluate(&cases, Severity::Warn);
        assert_eq!(warned.finding_level.true_positive, 0);
        let noted = evaluate(&cases, Severity::Note);
        assert_eq!(noted.finding_level.true_positive, 1);
    }

    #[test]
    fn blame_extracted_from_crash_blame_finding_tags() {
        let f = finding(
            "log-signal",
            "crash-blame:create",
            Severity::Warn,
            &[
                "crash-blame",
                "frame-to-jar",
                "frame-class:com.simibubi.create.Foo",
            ],
        );
        let blames = blame_predictions_from_findings(&[f]);
        assert_eq!(blames.len(), 1);
        assert_eq!(blames[0].frame_class, "com.simibubi.create.Foo");
    }

    #[test]
    fn blame_precision_scores_against_attributions() {
        // One correct blame (frame matches an attributed class), one wrong.
        let cases = vec![
            blame_case(
                vec![blame("create", "com.simibubi.create.Foo")],
                vec![attr(
                    FailureCategory::MixinApplyError,
                    "com.simibubi.create.Foo",
                )],
            ),
            blame_case(
                vec![blame("othermod", "com.other.Bar")],
                vec![attr(FailureCategory::MixinApplyError, "com.unrelated.Baz")],
            ),
        ];
        let report = evaluate(&cases, Severity::Note);
        assert_eq!(report.blame.true_positive, 1);
        assert_eq!(report.blame.false_positive, 1);
        assert!((report.blame.precision - 0.5).abs() < 1e-9);
        // Below MIN_SUPPORT → stays Note even at 0.5 precision.
        assert_eq!(report.blame.suggested_severity, "note");
    }

    #[test]
    fn severity_calibration_requires_minimum_support() {
        assert_eq!(suggest_severity(2, 0), Severity::Note);
        assert_eq!(suggest_severity(4, 6), Severity::Error);
        assert_eq!(suggest_severity(1, 99), Severity::Note);
        assert_eq!(suggest_severity(0, 0), Severity::Note);
    }
}
