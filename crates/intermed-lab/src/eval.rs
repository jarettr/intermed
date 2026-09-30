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
use intermed_doctor_core::evidence::{
    AssessmentDisposition, ConclusionKind, EntityRef, EvidenceRelation, Finding, Impact, ProofKind,
    Severity,
};

use crate::attribution::{
    FailureAttribution, SEVERITY_CALIBRATION_MIN_SUPPORT, subject_from_finding_id, subjects_match,
};
use crate::classify::FailureCategory;
use crate::observation::{ExecutionObservation, RuntimeMilestone};
use crate::run::{LabRun, SmokeResult, SmokeStatus, read_run};
use crate::{LabError, read_json, write_json_atomic};

/// Schema tag for the emitted accuracy report.
pub const RULE_ACCURACY_SCHEMA: &str = "intermed-rule-accuracy-v4";
/// Schema tag for the evaluation manifest (a dataset of report/run pairs).
pub const EVAL_MANIFEST_SCHEMA: &str = "intermed-eval-manifest-v1";

/// A single Doctor prediction reduced to the failure category it forecasts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prediction {
    pub rule_id: String,
    pub finding_id: String,
    pub semantic_id: String,
    pub subject: String,
    pub category: FailureCategory,
    pub severity: Severity,
    pub disposition: AssessmentDisposition,
    pub proof_kind: Option<ProofKind>,
    pub impact: Impact,
    pub trust_contract_complete: bool,
    /// Canonical entity keys from the coherent evidence path. Legacy reports may
    /// leave this empty and fall back to `subject` matching.
    pub entity_keys: Vec<String>,
    pub milestone_requirement: MilestoneRequirement,
}

/// Runtime coverage required before absence of an observed failure may refute a
/// static prediction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MilestoneRequirement {
    None,
    AnyOf(Vec<RuntimeMilestone>),
    AllOf(Vec<RuntimeMilestone>),
    ReachedAtLeast(RuntimeMilestone),
}

/// Map a finding (by its machine tags) to the load-failure category it predicts,
/// or `None` for non-predictive findings.
#[must_use]
pub fn predicted_category(tags: &[String]) -> Option<FailureCategory> {
    let has = |t: &str| tags.iter().any(|x| x == t);
    if has("performance") || has("spark") || has("hot-path") {
        Some(FailureCategory::PerformanceRegression)
    } else if has("mixin") {
        Some(FailureCategory::MixinApplyError)
    } else if has("dependency") {
        Some(FailureCategory::MissingDependency)
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
            let category = predicted_category_for_finding(f)?;
            let subject = f
                .evidence_path
                .first()
                .map(|link| link.from.canonical_semantic_id())
                .unwrap_or_else(|| subject_from_finding_id(&f.id).to_string());
            Some(Prediction {
                rule_id: f.rule_id.clone(),
                finding_id: f.id.clone(),
                semantic_id: if f.semantic_id.is_empty() {
                    f.id.clone()
                } else {
                    f.semantic_id.clone()
                },
                subject,
                category,
                severity: f.severity,
                disposition: f.assessment.disposition,
                proof_kind: f.proof_kind,
                impact: f.assessment.impact,
                trust_contract_complete: f.assessment.disposition
                    == AssessmentDisposition::Asserted
                    && f.assessment.blockers.is_empty()
                    && f.assessment
                        .prerequisites
                        .iter()
                        .all(|requirement| requirement.satisfied),
                entity_keys: finding_entity_keys(f),
                milestone_requirement: required_milestones(f, category),
            })
        })
        .collect()
}

fn predicted_category_for_finding(finding: &Finding) -> Option<FailureCategory> {
    match finding.conclusion_kind {
        ConclusionKind::MissingDependency | ConclusionKind::WrongVersion => {
            Some(FailureCategory::MissingDependency)
        }
        ConclusionKind::LoaderMismatch => Some(FailureCategory::ModLoadingFailure),
        ConclusionKind::ClassAbsent | ConclusionKind::MethodAbsent => {
            if finding.category == intermed_doctor_core::evidence::Category::Mixin {
                Some(FailureCategory::MixinApplyError)
            } else {
                Some(FailureCategory::ClassNotFound)
            }
        }
        ConclusionKind::RuntimeIncident => None,
        _ => match finding.category {
            intermed_doctor_core::evidence::Category::Performance => {
                Some(FailureCategory::PerformanceRegression)
            }
            intermed_doctor_core::evidence::Category::Dependency => {
                Some(FailureCategory::MissingDependency)
            }
            intermed_doctor_core::evidence::Category::Loader => {
                Some(FailureCategory::ModLoadingFailure)
            }
            _ => predicted_category(&finding.machine_tags),
        },
    }
}

fn finding_entity_keys(finding: &Finding) -> Vec<String> {
    let mut keys = finding
        .evidence_path
        .iter()
        .flat_map(|link| [&link.from, &link.to])
        .map(EntityRef::canonical_semantic_id)
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

fn required_milestones(finding: &Finding, category: FailureCategory) -> MilestoneRequirement {
    match category {
        FailureCategory::MissingDependency | FailureCategory::ModLoadingFailure => {
            MilestoneRequirement::ReachedAtLeast(RuntimeMilestone::LoaderResolution)
        }
        FailureCategory::MixinApplyError | FailureCategory::ClassNotFound => {
            MilestoneRequirement::AnyOf(vec![
                RuntimeMilestone::CommonSetup,
                RuntimeMilestone::ServerStarted,
                RuntimeMilestone::ClientInit,
            ])
        }
        FailureCategory::DatapackValidationError | FailureCategory::RegistryFreezeError => {
            MilestoneRequirement::AnyOf(vec![
                RuntimeMilestone::DatapackLoad,
                RuntimeMilestone::WorldLoaded,
            ])
        }
        FailureCategory::PerformanceRegression => {
            MilestoneRequirement::ReachedAtLeast(RuntimeMilestone::SteadyStateTicks)
        }
        _ if finding.conclusion_kind == ConclusionKind::RuntimeIncident => {
            MilestoneRequirement::None
        }
        _ => MilestoneRequirement::AnyOf(vec![
            RuntimeMilestone::ServerStarted,
            RuntimeMilestone::ClientInit,
        ]),
    }
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
            let mod_id = subject_from_finding_id(&f.id).to_string();
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
    pub precision: Option<f64>,
    pub precision_lower_bound: Option<f64>,
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
        precision_lower_bound: (tp + fp > 0).then(|| wilson_lower_bound(tp, tp + fp, 1.96)),
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
    pub reached_milestones: BTreeSet<RuntimeMilestone>,
    pub observation_coverage_available: bool,
    pub observed_entity_keys: BTreeMap<FailureCategory, BTreeSet<String>>,
    /// False for infrastructure/harness/skipped attempts. Such cases are not
    /// compatibility labels and must never contribute FP/FN counts.
    pub accuracy_eligible: bool,
}

/// Per-category co-occurrence accuracy (one tp/fp/fn per case).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CategoryAccuracy {
    pub category: String,
    pub true_positive: usize,
    pub false_positive: usize,
    pub false_negative: usize,
    #[serde(default)]
    pub inconclusive_coverage: usize,
    pub precision: Option<f64>,
    pub precision_lower_bound: Option<f64>,
    pub recall: Option<f64>,
    pub f1: Option<f64>,
    pub suggested_severity: String,
    /// `tp + fp` across cases (not per-finding count).
    pub calibration_support: usize,
}

/// Outcome for one Doctor finding against lab attributions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingMatchOutcome {
    TruePositive,
    FalsePositive,
    /// Finding below `min_severity` — excluded from scoring.
    BelowThreshold,
    /// The rule abstained under the typed trust contract; it is measured
    /// separately and never counted as a false positive.
    Abstained,
    /// The smoke run did not reach the runtime region needed to refute this
    /// prediction.
    InconclusiveCoverage,
}

/// Per-finding attributed accuracy row (finest eval granularity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingAccuracy {
    pub finding_id: String,
    #[serde(default)]
    pub semantic_id: String,
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
    #[serde(default)]
    pub inconclusive_coverage: usize,
    pub precision: Option<f64>,
    pub precision_lower_bound: Option<f64>,
    pub recall: Option<f64>,
    pub f1: Option<f64>,
    pub suggested_severity: String,
    pub calibration_support: usize,
}

/// Aggregated attributed metrics across all predictive rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingLevelAccuracy {
    /// Whether any case in the dataset carried lab attributions.
    pub attributed: bool,
    #[serde(default)]
    pub coverage_aware: bool,
    pub predictions: usize,
    pub attributions: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub false_negative: usize,
    #[serde(default)]
    pub abstained: usize,
    #[serde(default)]
    pub inconclusive_coverage: usize,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub f1: Option<f64>,
}

/// The full accuracy report over a dataset of cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleAccuracyReport {
    pub schema: String,
    pub min_severity: String,
    pub cases: usize,
    #[serde(default)]
    pub eligible_cases: usize,
    #[serde(default)]
    pub excluded_cases: usize,
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
    pub macro_precision_category: Option<f64>,
    pub macro_recall_category: Option<f64>,
    pub macro_precision_rule: Option<f64>,
    pub macro_recall_rule: Option<f64>,
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
    let lower = wilson_lower_bound(true_positive, predicted, 1.96);
    if lower >= 0.95 {
        Severity::Error
    } else if lower >= 0.80 {
        Severity::Warn
    } else {
        Severity::Note
    }
}

fn calibrated_severity<'a>(
    true_positive: usize,
    false_positive: usize,
    predictions: impl Iterator<Item = &'a Prediction>,
) -> Severity {
    let mut severity = suggest_severity(true_positive, false_positive);
    let predictions = predictions.collect::<Vec<_>>();
    let strong_contract = !predictions.is_empty()
        && predictions.iter().all(|prediction| {
            prediction.trust_contract_complete
                && matches!(
                    prediction.proof_kind,
                    Some(ProofKind::Observation | ProofKind::DeterministicDerivation)
                )
        });
    let hard_impact = !predictions.is_empty()
        && predictions.iter().all(|prediction| {
            matches!(
                prediction.impact,
                Impact::StartupBlocking | Impact::RuntimeFailure | Impact::DataLossRisk
            )
        });
    if !strong_contract {
        severity = severity.min(Severity::Note);
    } else if !hard_impact {
        severity = severity.min(Severity::Warn);
    }
    severity
}

fn ratio(num: usize, den: usize) -> Option<f64> {
    if den == 0 {
        None
    } else {
        Some(num as f64 / den as f64)
    }
}

fn f1(precision: Option<f64>, recall: Option<f64>) -> Option<f64> {
    let (precision, recall) = (precision?, recall?);
    if precision + recall == 0.0 {
        Some(0.0)
    } else {
        Some(2.0 * precision * recall / (precision + recall))
    }
}

fn wilson_lower_bound(successes: usize, trials: usize, z: f64) -> f64 {
    if trials == 0 {
        return 0.0;
    }
    let n = trials as f64;
    let p = successes as f64 / n;
    let z2 = z * z;
    (p + z2 / (2.0 * n) - z * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt()) / (1.0 + z2 / n)
}

fn qualifies(p: &Prediction, min_severity: Severity) -> bool {
    p.severity >= min_severity && p.disposition != AssessmentDisposition::Abstained
}

fn coverage_satisfies(case: &EvalCase, prediction: &Prediction) -> bool {
    if !case.accuracy_eligible || !case.observation_coverage_available {
        return false;
    }
    match &prediction.milestone_requirement {
        MilestoneRequirement::None => true,
        MilestoneRequirement::AnyOf(milestones) => milestones
            .iter()
            .any(|milestone| case.reached_milestones.contains(milestone)),
        MilestoneRequirement::AllOf(milestones) => milestones
            .iter()
            .all(|milestone| case.reached_milestones.contains(milestone)),
        MilestoneRequirement::ReachedAtLeast(milestone) => case
            .reached_milestones
            .iter()
            .any(|reached| milestone_implies(*reached, *milestone)),
    }
}

fn milestone_implies(reached: RuntimeMilestone, required: RuntimeMilestone) -> bool {
    if reached == required {
        return true;
    }
    match required {
        RuntimeMilestone::LoaderResolution => true,
        RuntimeMilestone::CommonSetup => matches!(
            reached,
            RuntimeMilestone::ClientInit
                | RuntimeMilestone::ServerStarted
                | RuntimeMilestone::WorldLoaded
                | RuntimeMilestone::PlayerJoined
                | RuntimeMilestone::SteadyStateTicks
                | RuntimeMilestone::GracefulShutdown
        ),
        RuntimeMilestone::ClientInit => matches!(
            reached,
            RuntimeMilestone::WorldLoaded
                | RuntimeMilestone::PlayerJoined
                | RuntimeMilestone::SteadyStateTicks
                | RuntimeMilestone::GracefulShutdown
        ),
        RuntimeMilestone::ServerStarted => matches!(
            reached,
            RuntimeMilestone::WorldLoaded
                | RuntimeMilestone::PlayerJoined
                | RuntimeMilestone::SteadyStateTicks
                | RuntimeMilestone::GracefulShutdown
        ),
        RuntimeMilestone::WorldLoaded => matches!(
            reached,
            RuntimeMilestone::PlayerJoined
                | RuntimeMilestone::SteadyStateTicks
                | RuntimeMilestone::GracefulShutdown
        ),
        RuntimeMilestone::PlayerJoined => matches!(
            reached,
            RuntimeMilestone::SteadyStateTicks | RuntimeMilestone::GracefulShutdown
        ),
        RuntimeMilestone::ResourceReload
        | RuntimeMilestone::DatapackLoad
        | RuntimeMilestone::SteadyStateTicks
        | RuntimeMilestone::GracefulShutdown => false,
    }
}

fn entity_match(case: &EvalCase, prediction: &Prediction) -> bool {
    !prediction.entity_keys.is_empty()
        && prediction.entity_keys.iter().any(|key| {
            case.observed_entity_keys
                .get(&prediction.category)
                .is_some_and(|observed| observed.contains(key))
        })
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
        let (mut tp, mut fp, mut fn_, mut inconclusive) = (0usize, 0usize, 0usize, 0usize);
        for case in cases {
            let predictions = case
                .predictions
                .iter()
                .filter(|p| p.category == *cat && qualifies(p, min_severity))
                .collect::<Vec<_>>();
            let predicted = !predictions.is_empty();
            let observed = case.observed.contains(cat);
            match (predicted, observed) {
                (true, true) => tp += 1,
                (true, false)
                    if predictions
                        .iter()
                        .any(|prediction| coverage_satisfies(case, prediction)) =>
                {
                    fp += 1;
                }
                (true, false) => inconclusive += 1,
                (false, true) => fn_ += 1,
                (false, false) => {}
            }
        }
        let precision = ratio(tp, tp + fp);
        let recall = ratio(tp, tp + fn_);
        let suggested = calibrated_severity(
            tp,
            fp,
            cases
                .iter()
                .flat_map(|case| case.predictions.iter())
                .filter(|prediction| prediction.category == *cat),
        );
        by_category.push(CategoryAccuracy {
            category: cat.as_str().to_string(),
            true_positive: tp,
            false_positive: fp,
            false_negative: fn_,
            inconclusive_coverage: inconclusive,
            precision,
            precision_lower_bound: (tp + fp > 0).then(|| wilson_lower_bound(tp, tp + fp, 1.96)),
            recall,
            f1: f1(precision, recall),
            calibration_support: tp + fp,
            suggested_severity: suggested.as_str().to_string(),
        });
    }
    by_category
}

struct RuleCounts {
    tp: usize,
    fp: usize,
    fn_: usize,
    predictions: usize,
    inconclusive: usize,
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
    let has_measurable_evidence = cases.iter().any(|case| {
        case.accuracy_eligible
            && (!case.attributions.is_empty() || case.observation_coverage_available)
    });
    if !has_measurable_evidence {
        return (
            Vec::new(),
            Vec::new(),
            FindingLevelAccuracy {
                attributed: false,
                coverage_aware: false,
                predictions: 0,
                attributions: 0,
                true_positive: 0,
                false_positive: 0,
                false_negative: 0,
                abstained: 0,
                inconclusive_coverage: 0,
                precision: None,
                recall: None,
                f1: None,
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
    let mut total_abstained = 0usize;
    let mut total_inconclusive = 0usize;

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
                inconclusive: 0,
            });
            entry.predictions += 1;

            let matched = attrs.iter().find(|attr| {
                pred.category == attr.category && subjects_match(&pred.subject, &attr.subject)
            });
            let category_observed = case.observed.contains(&pred.category);
            let category_attributed = attrs.iter().any(|attr| attr.category == pred.category);
            let false_positive_observable =
                coverage_satisfies(case, pred) && (!category_observed || category_attributed);
            if let Some(attr) = matched {
                entry.tp += 1;
                total_tp += 1;
                by_finding.push(FindingAccuracy {
                    finding_id: pred.finding_id.clone(),
                    semantic_id: pred.semantic_id.clone(),
                    rule_id: pred.rule_id.clone(),
                    subject: pred.subject.clone(),
                    category: pred.category.as_str().to_string(),
                    severity: pred.severity.as_str().to_string(),
                    outcome: FindingMatchOutcome::TruePositive,
                    matched_subject: Some(attr.subject.clone()),
                });
            } else if entity_match(case, pred) {
                entry.tp += 1;
                total_tp += 1;
                by_finding.push(FindingAccuracy {
                    finding_id: pred.finding_id.clone(),
                    semantic_id: pred.semantic_id.clone(),
                    rule_id: pred.rule_id.clone(),
                    subject: pred.subject.clone(),
                    category: pred.category.as_str().to_string(),
                    severity: pred.severity.as_str().to_string(),
                    outcome: FindingMatchOutcome::TruePositive,
                    matched_subject: Some("canonical-entity".to_string()),
                });
            } else if false_positive_observable {
                entry.fp += 1;
                total_fp += 1;
                by_finding.push(FindingAccuracy {
                    finding_id: pred.finding_id.clone(),
                    semantic_id: pred.semantic_id.clone(),
                    rule_id: pred.rule_id.clone(),
                    subject: pred.subject.clone(),
                    category: pred.category.as_str().to_string(),
                    severity: pred.severity.as_str().to_string(),
                    outcome: FindingMatchOutcome::FalsePositive,
                    matched_subject: None,
                });
            } else {
                entry.inconclusive += 1;
                total_inconclusive += 1;
                by_finding.push(FindingAccuracy {
                    finding_id: pred.finding_id.clone(),
                    semantic_id: pred.semantic_id.clone(),
                    rule_id: pred.rule_id.clone(),
                    subject: pred.subject.clone(),
                    category: pred.category.as_str().to_string(),
                    severity: pred.severity.as_str().to_string(),
                    outcome: FindingMatchOutcome::InconclusiveCoverage,
                    matched_subject: None,
                });
            }
        }

        for pred in case.predictions.iter().filter(|p| {
            p.disposition != AssessmentDisposition::Abstained && !qualifies(p, min_severity)
        }) {
            by_finding.push(FindingAccuracy {
                finding_id: pred.finding_id.clone(),
                semantic_id: pred.semantic_id.clone(),
                rule_id: pred.rule_id.clone(),
                subject: pred.subject.clone(),
                category: pred.category.as_str().to_string(),
                severity: pred.severity.as_str().to_string(),
                outcome: FindingMatchOutcome::BelowThreshold,
                matched_subject: None,
            });
        }
        for pred in case
            .predictions
            .iter()
            .filter(|p| p.disposition == AssessmentDisposition::Abstained)
        {
            total_abstained += 1;
            by_finding.push(FindingAccuracy {
                finding_id: pred.finding_id.clone(),
                semantic_id: pred.semantic_id.clone(),
                rule_id: pred.rule_id.clone(),
                subject: pred.subject.clone(),
                category: pred.category.as_str().to_string(),
                severity: pred.severity.as_str().to_string(),
                outcome: FindingMatchOutcome::Abstained,
                matched_subject: None,
            });
        }

        for attr in &attrs {
            let Some(rule_ids) = rules_by_category.get(&attr.category) else {
                continue;
            };

            let any_rule_matched = flagged.iter().any(|pred| {
                pred.category == attr.category
                    && (subjects_match(&pred.subject, &attr.subject) || entity_match(case, pred))
            });
            if !any_rule_matched {
                total_fn += 1;
            }

            for rule_id in rule_ids {
                let rule_matched = case.predictions.iter().any(|p| {
                    p.rule_id == *rule_id
                        && qualifies(p, min_severity)
                        && p.category == attr.category
                        && (subjects_match(&p.subject, &attr.subject) || entity_match(case, p))
                });
                if !rule_matched {
                    let entry = per_rule.entry(rule_id.clone()).or_insert(RuleCounts {
                        tp: 0,
                        fp: 0,
                        fn_: 0,
                        predictions: 0,
                        inconclusive: 0,
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
        let suggested = calibrated_severity(
            counts.tp,
            counts.fp,
            cases
                .iter()
                .flat_map(|case| case.predictions.iter())
                .filter(|prediction| prediction.rule_id == rule_id),
        );
        by_rule.push(RuleAccuracy {
            rule_id,
            predictions: counts.predictions,
            true_positive: counts.tp,
            false_positive: counts.fp,
            false_negative: counts.fn_,
            inconclusive_coverage: counts.inconclusive,
            precision,
            precision_lower_bound: (counts.tp + counts.fp > 0)
                .then(|| wilson_lower_bound(counts.tp, counts.tp + counts.fp, 1.96)),
            recall,
            f1: f1(precision, recall),
            calibration_support: counts.tp + counts.fp,
            suggested_severity: suggested.as_str().to_string(),
        });
    }

    let fl_precision = ratio(total_tp, total_tp + total_fp);
    let fl_recall = ratio(total_tp, total_tp + total_fn);
    let finding_level = FindingLevelAccuracy {
        attributed: cases.iter().any(|case| !case.attributions.is_empty()),
        coverage_aware: cases.iter().any(|case| case.observation_coverage_available),
        predictions: total_predictions,
        attributions: total_attributions,
        true_positive: total_tp,
        false_positive: total_fp,
        false_negative: total_fn,
        abstained: total_abstained,
        inconclusive_coverage: total_inconclusive,
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

fn macro_avg(values: &[Option<f64>]) -> Option<f64> {
    let values = values.iter().flatten().copied().collect::<Vec<_>>();
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}

/// Compute the full accuracy report over labelled cases.
#[must_use]
pub fn evaluate(cases: &[EvalCase], min_severity: Severity) -> RuleAccuracyReport {
    let eligible = cases
        .iter()
        .filter(|case| case.accuracy_eligible)
        .cloned()
        .collect::<Vec<_>>();
    let by_category = evaluate_by_category(&eligible, min_severity);
    let (by_rule, by_finding, finding_level) = evaluate_by_rule(&eligible, min_severity);
    let blame = evaluate_blame(&eligible);

    RuleAccuracyReport {
        schema: RULE_ACCURACY_SCHEMA.to_string(),
        min_severity: min_severity.as_str().to_string(),
        cases: cases.len(),
        eligible_cases: eligible.len(),
        excluded_cases: cases.len().saturating_sub(eligible.len()),
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

/// Build one evaluation cell per runtime environment. Coverage from one loader
/// or side must never make a prediction refutable in a different environment.
pub fn cases_from_files(report_path: &Path, run_path: &Path) -> Result<Vec<EvalCase>, LabError> {
    let report: DoctorReport = read_json(report_path)?;
    let run = read_run(run_path)?;
    Ok(run
        .results
        .iter()
        .map(|result| case_from_result(&report, result))
        .collect())
}

fn case_from_result(report: &DoctorReport, result: &SmokeResult) -> EvalCase {
    let observation = result.observation.as_ref();
    let reached_milestones = observation
        .into_iter()
        .flat_map(|value| value.coverage.reached.iter().copied())
        .collect();
    let mut observed_entity_keys = observed_entity_keys(report, observation.into_iter());
    let mut attributed_classes = BTreeMap::<FailureCategory, BTreeSet<String>>::new();
    for attribution in &result.attributions {
        if matches!(
            attribution.category,
            FailureCategory::MixinApplyError | FailureCategory::ClassNotFound
        ) {
            attributed_classes
                .entry(attribution.category)
                .or_default()
                .insert(normalize_runtime_class(&attribution.subject));
        }
    }
    for (category, classes) in attributed_classes {
        observed_entity_keys
            .entry(category)
            .or_default()
            .extend(entity_keys_for_classes(report, &classes));
    }
    let mut observed = BTreeSet::new();
    observed.extend(result.failure);
    observed.extend(result.additional_failures.iter().copied());
    let accuracy_eligible = observation.map_or_else(
        || {
            !matches!(
                result.status,
                SmokeStatus::HarnessFailure
                    | SmokeStatus::InfrastructureFailure
                    | SmokeStatus::Skipped
                    | SmokeStatus::Inconclusive
            )
        },
        |value| value.status.eligible_for_accuracy(),
    );
    EvalCase {
        predictions: predictions_from_report(report),
        observed,
        attributions: result.attributions.clone(),
        blame_predictions: blame_predictions_from_findings(&report.findings),
        reached_milestones,
        observation_coverage_available: observation.is_some(),
        observed_entity_keys,
        accuracy_eligible,
    }
}

/// Build a coverage-aware case directly from one campaign observation.
pub fn case_from_observation_files(
    report_path: &Path,
    observation_path: &Path,
) -> Result<EvalCase, LabError> {
    let report: DoctorReport = read_json(report_path)?;
    let observation: ExecutionObservation = read_json(observation_path)?;
    if observation.schema != crate::observation::OBSERVATION_SCHEMA {
        return Err(LabError::schema(
            observation_path,
            crate::observation::OBSERVATION_SCHEMA,
            &observation.schema,
        ));
    }
    let mut observed = BTreeSet::new();
    let mut attributions = Vec::new();
    for incident in &observation.incidents {
        let Some(category) = incident.category else {
            continue;
        };
        observed.insert(category);
        for subject in &incident.attributed_subjects {
            attributions.push(FailureAttribution {
                category,
                subject: subject.clone(),
                line_excerpt: incident.message.clone(),
            });
        }
    }
    attributions.sort();
    attributions.dedup();
    let observed_entity_keys = observed_entity_keys(&report, std::iter::once(&observation));
    Ok(EvalCase {
        predictions: predictions_from_report(&report),
        observed,
        attributions,
        blame_predictions: blame_predictions_from_findings(&report.findings),
        reached_milestones: observation.coverage.reached.iter().copied().collect(),
        observation_coverage_available: true,
        observed_entity_keys,
        accuracy_eligible: observation.status.eligible_for_accuracy(),
    })
}

fn observed_entity_keys<'a>(
    report: &DoctorReport,
    observations: impl Iterator<Item = &'a ExecutionObservation>,
) -> BTreeMap<FailureCategory, BTreeSet<String>> {
    let mut classes_by_category = BTreeMap::<FailureCategory, BTreeSet<String>>::new();
    for incident in observations.flat_map(|observation| observation.incidents.iter()) {
        let Some(category) = incident.category else {
            continue;
        };
        classes_by_category.entry(category).or_default().extend(
            incident
                .frame_classes
                .iter()
                .map(|class| normalize_runtime_class(class)),
        );
    }
    classes_by_category
        .into_iter()
        .map(|(category, classes)| (category, entity_keys_for_classes(report, &classes)))
        .collect()
}

fn entity_keys_for_classes(report: &DoctorReport, classes: &BTreeSet<String>) -> BTreeSet<String> {
    let keys = report
        .evidence_graph
        .entities
        .iter()
        .filter(|entity| match entity {
            EntityRef::Class(class) => classes.contains(&normalize_runtime_class(&class.name)),
            EntityRef::Method(method) => {
                classes.contains(&normalize_runtime_class(&method.owner.name))
            }
            _ => false,
        })
        .map(EntityRef::canonical_semantic_id)
        .collect::<BTreeSet<_>>();
    expand_observed_entity_keys(&report.evidence_graph, keys)
}

fn expand_observed_entity_keys(
    graph: &intermed_doctor_core::evidence::EvidenceGraph,
    mut keys: BTreeSet<String>,
) -> BTreeSet<String> {
    // Expand upward only: method/class -> owning mod -> containing artifact.
    // Traversing these relations bidirectionally would let an observed class A
    // reach its artifact and then descend into unrelated sibling class B.
    loop {
        let before = keys.len();
        for link in &graph.links {
            let from = link.from.canonical_semantic_id();
            let to = link.to.canonical_semantic_id();
            match link.relation {
                EvidenceRelation::Owns | EvidenceRelation::Contains if keys.contains(&to) => {
                    keys.insert(from);
                }
                EvidenceRelation::ObservedIn if keys.contains(&from) => {
                    keys.insert(to);
                }
                _ => {}
            }
        }
        if keys.len() == before {
            break;
        }
    }
    keys
}

fn normalize_runtime_class(value: &str) -> String {
    value.trim().trim_end_matches(".class").replace('/', ".")
}

pub fn evaluate_observation_pair(
    report_path: &Path,
    observation_path: &Path,
    min_severity: Severity,
    out: &Path,
) -> Result<RuleAccuracyReport, LabError> {
    let case = case_from_observation_files(report_path, observation_path)?;
    let report = evaluate(&[case], min_severity);
    write_json_atomic(out, &report)?;
    Ok(report)
}

/// `lab eval` over a single report/run pair.
pub fn evaluate_pair(
    report_path: &Path,
    run_path: &Path,
    min_severity: Severity,
    out: &Path,
) -> Result<RuleAccuracyReport, LabError> {
    let cases = cases_from_files(report_path, run_path)?;
    let report = evaluate(&cases, min_severity);
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
        cases.extend(cases_from_files(
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
            reached_milestones: [
                RuntimeMilestone::LoaderResolution,
                RuntimeMilestone::CommonSetup,
                RuntimeMilestone::ServerStarted,
                RuntimeMilestone::SteadyStateTicks,
            ]
            .into_iter()
            .collect(),
            observation_coverage_available: true,
            observed_entity_keys: BTreeMap::new(),
            accuracy_eligible: true,
        }
    }

    fn blame_case(blames: Vec<BlamePrediction>, attrs: Vec<FailureAttribution>) -> EvalCase {
        EvalCase {
            predictions: Vec::new(),
            observed: BTreeSet::new(),
            attributions: attrs,
            blame_predictions: blames,
            reached_milestones: BTreeSet::new(),
            observation_coverage_available: true,
            observed_entity_keys: BTreeMap::new(),
            accuracy_eligible: true,
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
            semantic_id: id.to_string(),
            subject: subject.to_string(),
            category: cat,
            severity: sev,
            disposition: AssessmentDisposition::Asserted,
            proof_kind: Some(ProofKind::DeterministicDerivation),
            impact: Impact::StartupBlocking,
            trust_contract_complete: true,
            entity_keys: Vec::new(),
            milestone_requirement: MilestoneRequirement::ReachedAtLeast(
                RuntimeMilestone::LoaderResolution,
            ),
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
        assert_eq!(
            predicted_category(&["mixin".into(), "performance".into(), "correlation".into()]),
            Some(FailureCategory::PerformanceRegression)
        );
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
        assert!((report.blame.precision.unwrap() - 0.5).abs() < 1e-9);
        // Below MIN_SUPPORT → stays Note even at 0.5 precision.
        assert_eq!(report.blame.suggested_severity, "note");
    }

    #[test]
    fn severity_calibration_requires_minimum_support() {
        assert_eq!(suggest_severity(2, 0), Severity::Note);
        assert_eq!(suggest_severity(96, 4), Severity::Warn);
        assert_eq!(suggest_severity(1000, 0), Severity::Error);
        assert_eq!(suggest_severity(4, 6), Severity::Note);
        assert_eq!(suggest_severity(1, 99), Severity::Note);
        assert_eq!(suggest_severity(0, 0), Severity::Note);
    }

    #[test]
    fn undefined_precision_is_not_reported_as_zero() {
        let report = evaluate(&[case(Vec::new(), &[], Vec::new())], Severity::Warn);
        assert_eq!(report.finding_level.precision, None);
        assert_eq!(report.macro_precision_category, None);
    }

    #[test]
    fn unavailable_execution_is_excluded_from_accuracy() {
        let mut unavailable = case(
            vec![pred(
                "missing-dependency",
                "missing:foo",
                "foo",
                FailureCategory::MissingDependency,
                Severity::Error,
            )],
            &[],
            Vec::new(),
        );
        unavailable.accuracy_eligible = false;
        let report = evaluate(&[unavailable], Severity::Warn);
        assert_eq!(report.eligible_cases, 0);
        assert_eq!(report.excluded_cases, 1);
        assert_eq!(report.finding_level.false_positive, 0);
    }

    #[test]
    fn ownership_expansion_never_reaches_sibling_classes() {
        use intermed_doctor_core::evidence::{
            ArtifactId, ClassSymbol, DescriptorKind, EvidenceGraph, EvidenceLink, EvidenceOrigin,
            EvidenceStrength, MappingGraphId, MappingNamespace, ModInstanceId,
        };
        use intermed_doctor_core::facts::FactId;

        let artifact = EntityRef::Artifact(ArtifactId::new("sha256:test"));
        let module = EntityRef::Mod(ModInstanceId {
            artifact: ArtifactId::new("sha256:test"),
            declared_id: "example".into(),
            descriptor_kind: DescriptorKind::Fabric,
            ordinal: 0,
        });
        let class = |name: &str| {
            EntityRef::Class(ClassSymbol::new(
                name,
                MappingNamespace::MojmapNamed,
                MappingGraphId::new("mapping:test"),
            ))
        };
        let class_a = class("example.A");
        let class_b = class("example.B");
        let graph = EvidenceGraph {
            entities: vec![
                artifact.clone(),
                module.clone(),
                class_a.clone(),
                class_b.clone(),
            ],
            links: vec![
                EvidenceLink {
                    from: artifact.clone(),
                    relation: EvidenceRelation::Contains,
                    to: module.clone(),
                    origin: EvidenceOrigin::StaticExact,
                    strength: EvidenceStrength::Exact,
                    source_fact: FactId(1),
                },
                EvidenceLink {
                    from: module.clone(),
                    relation: EvidenceRelation::Owns,
                    to: class_a.clone(),
                    origin: EvidenceOrigin::StaticExact,
                    strength: EvidenceStrength::Exact,
                    source_fact: FactId(2),
                },
                EvidenceLink {
                    from: module.clone(),
                    relation: EvidenceRelation::Owns,
                    to: class_b.clone(),
                    origin: EvidenceOrigin::StaticExact,
                    strength: EvidenceStrength::Exact,
                    source_fact: FactId(3),
                },
            ],
            ..EvidenceGraph::default()
        };
        let expanded = expand_observed_entity_keys(
            &graph,
            [class_a.canonical_semantic_id()].into_iter().collect(),
        );
        assert!(expanded.contains(&module.canonical_semantic_id()));
        assert!(expanded.contains(&artifact.canonical_semantic_id()));
        assert!(!expanded.contains(&class_b.canonical_semantic_id()));
    }

    #[test]
    fn incomplete_runtime_region_does_not_create_false_positive() {
        let mut prediction = pred(
            "mixin-apply",
            "mixin:Foo",
            "Foo",
            FailureCategory::MixinApplyError,
            Severity::Error,
        );
        prediction.milestone_requirement =
            MilestoneRequirement::ReachedAtLeast(RuntimeMilestone::CommonSetup);
        let case = EvalCase {
            predictions: vec![prediction],
            observed: BTreeSet::new(),
            attributions: Vec::new(),
            blame_predictions: Vec::new(),
            reached_milestones: [RuntimeMilestone::LoaderResolution].into_iter().collect(),
            observation_coverage_available: true,
            observed_entity_keys: BTreeMap::new(),
            accuracy_eligible: true,
        };
        let report = evaluate(&[case], Severity::Warn);
        assert_eq!(report.finding_level.false_positive, 0);
        assert_eq!(report.finding_level.inconclusive_coverage, 1);
        assert_eq!(report.by_category[0].false_positive, 0);
        assert_eq!(report.by_category[0].inconclusive_coverage, 1);
        assert_eq!(
            report.by_finding[0].outcome,
            FindingMatchOutcome::InconclusiveCoverage
        );
    }

    #[test]
    fn reached_runtime_region_can_refute_asserted_prediction() {
        let mut prediction = pred(
            "missing-dependency",
            "missing:foo",
            "foo",
            FailureCategory::MissingDependency,
            Severity::Error,
        );
        prediction.milestone_requirement =
            MilestoneRequirement::ReachedAtLeast(RuntimeMilestone::LoaderResolution);
        let case = EvalCase {
            predictions: vec![prediction],
            observed: BTreeSet::new(),
            attributions: Vec::new(),
            blame_predictions: Vec::new(),
            reached_milestones: [RuntimeMilestone::LoaderResolution].into_iter().collect(),
            observation_coverage_available: true,
            observed_entity_keys: BTreeMap::new(),
            accuracy_eligible: true,
        };
        let report = evaluate(&[case], Severity::Warn);
        assert_eq!(report.finding_level.false_positive, 1);
        assert_eq!(report.finding_level.inconclusive_coverage, 0);
    }

    #[test]
    fn trust_contract_abstention_is_never_a_false_positive() {
        let mut prediction = pred(
            "missing-dependency",
            "missing:foo",
            "foo",
            FailureCategory::MissingDependency,
            Severity::Warn,
        );
        prediction.disposition = AssessmentDisposition::Abstained;
        let case = EvalCase {
            predictions: vec![prediction],
            observed: BTreeSet::new(),
            attributions: Vec::new(),
            blame_predictions: Vec::new(),
            reached_milestones: [RuntimeMilestone::LoaderResolution].into_iter().collect(),
            observation_coverage_available: true,
            observed_entity_keys: BTreeMap::new(),
            accuracy_eligible: true,
        };
        let report = evaluate(&[case], Severity::Warn);
        assert_eq!(report.finding_level.false_positive, 0);
        assert_eq!(report.finding_level.abstained, 1);
        assert_eq!(report.by_finding[0].outcome, FindingMatchOutcome::Abstained);
    }

    #[test]
    fn canonical_entity_match_is_scoped_to_failure_category() {
        let mut prediction = pred(
            "missing-dependency",
            "missing:foo",
            "foo",
            FailureCategory::MissingDependency,
            Severity::Error,
        );
        prediction.entity_keys = vec!["artifact:foo".into()];
        let case = EvalCase {
            predictions: vec![prediction],
            observed: [FailureCategory::OutOfMemory].into_iter().collect(),
            attributions: Vec::new(),
            blame_predictions: Vec::new(),
            reached_milestones: [RuntimeMilestone::LoaderResolution].into_iter().collect(),
            observation_coverage_available: true,
            observed_entity_keys: [(
                FailureCategory::OutOfMemory,
                ["artifact:foo".to_string()].into_iter().collect(),
            )]
            .into_iter()
            .collect(),
            accuracy_eligible: true,
        };
        let report = evaluate(&[case], Severity::Warn);
        assert_eq!(report.finding_level.true_positive, 0);
        assert_eq!(report.finding_level.false_positive, 1);
    }
}
