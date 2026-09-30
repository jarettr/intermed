//! # intermed-lab — Layer K (Phase 8): Compatibility Lab
//!
//! Reproducible compatibility evidence. The lab pins a mod corpus, runs smoke
//! tests against bootstrapped environments, classifies the failures, and emits a
//! compatibility matrix + static HTML site. It is the project's long-term moat.
//!
//! ## What this crate implements (the evidence path)
//!
//! Unlike the diagnostic layers, the lab is **operations, not a [`Collector`]**:
//! it runs under explicit `intermed lab` subcommands, not the doctor pipeline.
//! Everything that turns runs into *reproducible evidence* is implemented here
//! and is fully offline-testable:
//!
//! * [`corpus`] — `lab discover`: a deterministic, content-addressed
//!   [`CorpusLock`](corpus::CorpusLock) built from a candidate pool.
//! * [`run`] — `lab run`: classify captured smoke outputs into a
//!   [`LabRun`](run::LabRun), with the live runner abstracted behind
//!   [`SmokeRunner`](run::SmokeRunner).
//! * [`classify`] — failure taxonomy aligned with Layer D log signals.
//! * [`report`] — `lab report`: a [`CompatibilityMatrix`](report::CompatibilityMatrix)
//!   plus a self-contained HTML page.
//!
//! Layer K also owns resumable campaigns, content-addressed materialization,
//! fail-closed sandbox execution contracts, Layer-D-compatible runtime
//! observations, coverage-aware evaluation, and semantic mismatch clustering.
//! Network acquisition and loader installation remain separate operations;
//! executing an arbitrary pack requires an explicit sandbox plan.
//!
//! All file writes use a temp-then-rename atomic discipline (see
//! [`write_atomic`]).
//!
//! [`Collector`]: intermed_doctor_core::Collector

use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

pub mod attribution;
pub mod campaign;
pub mod campaign_report;
pub mod classify;
pub mod corpus;
pub mod eval;
pub mod execution;
pub mod modrinth;
pub mod observation;
pub mod report;
pub mod run;
pub mod store;
pub mod triage;

pub use attribution::{FailureAttribution, SEVERITY_CALIBRATION_MIN_SUPPORT, extract_attributions};
pub use campaign::{
    CAMPAIGN_SCHEMA, CAMPAIGN_STATE_SCHEMA, Campaign, CampaignCase, CampaignCaseState,
    CampaignCaseStatus, CampaignExecutor, CampaignOptions, CampaignState, FileCampaignExecutor,
    read_campaign, run_campaign,
};
pub use campaign_report::{
    CAMPAIGN_REPORT_SCHEMA, CampaignReport, build_campaign_report, write_campaign_report,
};
pub use classify::{FailureCategory, FailureFamily, classify_log, classify_log_all};
pub use corpus::{
    CORPUS_CANDIDATES_SCHEMA, CORPUS_LOCK_SCHEMA, CORPUS_LOCK_SCHEMA_V1, CORPUS_LOCK_SCHEMA_V2,
    CandidateMod, CandidateProvider, CorpusCandidates, CorpusEnvironment, CorpusLock,
    FileCandidateProvider, LockedMod, VerificationCompleteness, discover_lock, read_lock,
};
pub use eval::{
    CategoryAccuracy, EVAL_MANIFEST_SCHEMA, FindingAccuracy, FindingLevelAccuracy,
    MilestoneRequirement, RULE_ACCURACY_SCHEMA, RuleAccuracy, RuleAccuracyReport,
    case_from_observation_files, cases_from_files, evaluate, evaluate_manifest,
    evaluate_observation_pair, evaluate_pair,
};
pub use execution::{
    CommandExecutionBackend, EnvironmentRunner, EnvironmentSpec, ExecutionLimits, ExecutionPlan,
    NetworkPolicy, ProcessOutcome, RunningProcess, SandboxPolicy, ServerProcessRunner,
    outcome_to_smoke,
};
pub use modrinth::lock_modrinth_manifest;
pub use observation::{
    EvidenceState, ExecutionCoverage, ExecutionObservation, IncidentObservation,
    OBSERVATION_SCHEMA, ObservationStatus, RuntimeMilestone, observe_smoke,
};
pub use report::{
    COMPAT_MATRIX_SCHEMA, CompatibilityMatrix, MatrixCell, render_html, write_report,
};
pub use run::{
    CapturedLogRunner, DEFAULT_EXCERPT_MAX, LAB_RUN_SCHEMA, LAB_RUN_SCHEMA_V1, LabRun,
    LabRunOptions, RawSmokeOutput, SMOKE_OUTPUT_SCHEMA, SmokeResult, SmokeRunner, SmokeStatus,
    capture_log, classify_with_options, read_run, run_lab, run_lab_with, run_with,
};
pub use store::{
    ArtifactStore, MaterializationRecord, STORE_MANIFEST_SCHEMA, TARGET_VERIFICATION_SCHEMA,
    TargetVerification, verify_target,
};
pub use triage::{MismatchCluster, TRIAGE_SCHEMA, TriageReport, cluster_accuracy};

/// Implementation status for the CLI's help / `--list-layers` output.
pub const STATUS: &str = "active: measured real-pack campaigns and compatibility evidence";

/// A lab operation failure.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct LabError(String);

impl LabError {
    pub fn new(message: impl Into<String>) -> Self {
        LabError(message.into())
    }

    /// Construct a uniform schema-mismatch error.
    pub(crate) fn schema(path: &Path, expected: &str, found: &str) -> Self {
        LabError(format!(
            "unsupported schema `{found}` in {} (expected {expected})",
            path.display()
        ))
    }
}

/// Read and deserialize a JSON file, mapping IO/parse errors to [`LabError`].
pub(crate) fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, LabError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| LabError::new(format!("read {}: {e}", path.display())))?;
    serde_json::from_str(&text).map_err(|e| LabError::new(format!("parse {}: {e}", path.display())))
}

/// Serialize `value` as pretty JSON and write it atomically.
pub(crate) fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), LabError> {
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| LabError::new(format!("serialize {}: {e}", path.display())))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| LabError::new(format!("create {}: {e}", parent.display())))?;
    }
    write_atomic(path, &json).map_err(|e| LabError::new(format!("write {}: {e}", path.display())))
}

// The atomic-write helper is shared with the rest of the workspace (it lives in
// `intermed-doctor-core`, which lab already depends on). Re-exported so existing
// `intermed_lab::write_atomic` callers keep working.
pub use intermed_doctor_core::write_atomic;
