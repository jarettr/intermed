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
//! ## Deferred donors (rewrite-hard, network/process)
//!
//! The *live execution* pieces stay out of the deterministic core and are added
//! later behind existing traits, so the offline evidence path never depends on
//! the network or a JVM:
//!
//! * `ModrinthClient` (corpus discovery: 50% downloads / 25% follows / 25%
//!   updated, dedupe by project id) → a networked [`CandidateProvider`](corpus::CandidateProvider).
//! * `EnvironmentBootstrap`, the loader installers
//!   (`FabricServerInstaller`/`ForgeServerInstaller`/`NeoForgeServerInstaller`),
//!   `VanillaServerFetcher`, `ServerProcessRunner` → a live
//!   [`SmokeRunner`](run::SmokeRunner) that produces the same
//!   [`RawSmokeOutput`](run::RawSmokeOutput) the in-tree
//!   [`CapturedLogRunner`](run::CapturedLogRunner) ingests today.
//!
//! All file writes use a temp-then-rename atomic discipline (see
//! [`write_atomic`]).
//!
//! [`Collector`]: intermed_doctor_core::Collector

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

pub mod attribution;
pub mod classify;
pub mod corpus;
pub mod eval;
pub mod execution;
pub mod report;
pub mod run;

pub use classify::{classify_log, classify_log_all, FailureCategory, FailureFamily};
pub use corpus::{
    discover_lock, read_lock, CandidateMod, CandidateProvider, CorpusCandidates, CorpusEnvironment,
    CorpusLock, FileCandidateProvider, LockedMod, CORPUS_CANDIDATES_SCHEMA, CORPUS_LOCK_SCHEMA,
};
pub use attribution::{extract_attributions, FailureAttribution, SEVERITY_CALIBRATION_MIN_SUPPORT};
pub use eval::{
    evaluate, evaluate_manifest, evaluate_pair, CategoryAccuracy, FindingAccuracy,
    FindingLevelAccuracy, RuleAccuracy, RuleAccuracyReport, EVAL_MANIFEST_SCHEMA,
    RULE_ACCURACY_SCHEMA,
};
pub use execution::{
    outcome_to_smoke, EnvironmentRunner, EnvironmentSpec, ProcessOutcome, RunningProcess,
    ServerProcessRunner,
};
pub use report::{
    render_html, write_report, CompatibilityMatrix, MatrixCell, COMPAT_MATRIX_SCHEMA,
};
pub use run::{
    classify_with_options, read_run, run_lab, run_lab_with, run_with, CapturedLogRunner, LabRun,
    LabRunOptions, RawSmokeOutput, SmokeResult, SmokeRunner, SmokeStatus, DEFAULT_EXCERPT_MAX,
    LAB_RUN_SCHEMA, SMOKE_OUTPUT_SCHEMA,
};

/// Implementation status for the CLI's help / `--list-layers` output.
pub const STATUS: &str = "active: Phase 8 (offline evidence path; live runner deferred)";

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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| LabError::new(format!("create {}: {e}", parent.display())))?;
        }
    }
    write_atomic(path, &json).map_err(|e| LabError::new(format!("write {}: {e}", path.display())))
}

// The atomic-write helper is shared with the rest of the workspace (it lives in
// `intermed-doctor-core`, which lab already depends on). Re-exported so existing
// `intermed_lab::write_atomic` callers keep working.
pub use intermed_doctor_core::write_atomic;
