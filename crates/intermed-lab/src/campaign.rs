//! Persistent, resumable Compatibility-Lab campaigns.
//!
//! The state file is committed after every case. A killed process can therefore
//! resume without repeating completed Minecraft launches or losing the exact
//! analyzer/runtime pairing that produced an observation.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::execution::ExecutionPlan;
use crate::execution::{CommandExecutionBackend, outcome_to_smoke};
use crate::observation::{ExecutionObservation, observe_smoke};
use crate::run::RawSmokeOutput;
use crate::{LabError, read_json, write_json_atomic};

pub const CAMPAIGN_SCHEMA: &str = "intermed-lab-campaign-v1";
pub const CAMPAIGN_STATE_SCHEMA: &str = "intermed-lab-campaign-state-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignCase {
    pub id: String,
    pub corpus_lock: PathBuf,
    /// Expected immutable lock identity. A path alone is never campaign
    /// identity because its contents can be replaced between runs.
    pub corpus_digest: String,
    /// Optional exact Doctor invocation identity for a replay/attestation run.
    /// It is case-local because the target manifest is part of Doctor's
    /// effective invocation digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctor_fingerprint: Option<DoctorFingerprintExpectation>,
    pub target: PathBuf,
    /// Original authoritative pack manifest/archive passed through to Doctor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_manifest: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctor_report: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_smoke: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Campaign {
    pub schema: String,
    pub id: String,
    pub analyzer_fingerprint: String,
    /// Additional deterministic Doctor flags applied to every static baseline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub doctor_args: Vec<String>,
    pub cases: Vec<CampaignCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorFingerprintExpectation {
    pub effective_config_sha256: String,
    pub target_manifest_sha256: String,
}

impl Campaign {
    pub fn validate(&self) -> Result<(), LabError> {
        if self.schema != CAMPAIGN_SCHEMA {
            return Err(LabError::new(format!(
                "unsupported campaign schema `{}` (expected {CAMPAIGN_SCHEMA})",
                self.schema
            )));
        }
        if self.id.trim().is_empty() {
            return Err(LabError::new("campaign id must not be empty"));
        }
        if self.analyzer_fingerprint != "auto" && !is_sha256(&self.analyzer_fingerprint) {
            return Err(LabError::new(
                "campaign analyzer_fingerprint must be a SHA-256 or `auto`",
            ));
        }
        let mut ids = BTreeSet::new();
        for case in &self.cases {
            if case.id.trim().is_empty() || !ids.insert(case.id.clone()) {
                return Err(LabError::new(format!(
                    "campaign case ids must be non-empty and unique: `{}`",
                    case.id
                )));
            }
            if case.corpus_digest.len() != 64
                || !case
                    .corpus_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(LabError::new(format!(
                    "case `{}` has an invalid corpus digest",
                    case.id
                )));
            }
            if let Some(expected) = &case.doctor_fingerprint
                && (!is_sha256(&expected.effective_config_sha256)
                    || !is_sha256(&expected.target_manifest_sha256))
            {
                return Err(LabError::new(format!(
                    "case `{}` has an invalid Doctor fingerprint expectation",
                    case.id
                )));
            }
            if case.captured_smoke.is_some() && case.execution.is_some() {
                return Err(LabError::new(format!(
                    "case `{}` cannot select both captured_smoke and execution",
                    case.id
                )));
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, LabError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| LabError::new(format!("serialize campaign identity: {error}")))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Stable identity of analyzer code, build features, and the selected rule
/// pack. Target- and invocation-specific inputs intentionally live in the
/// case-local Doctor fingerprint.
pub fn report_analyzer_fingerprint(
    report: &intermed_doctor_core::DoctorReport,
) -> Result<String, LabError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        tool_version: &'a str,
        executable_sha256: &'a Option<String>,
        git_commit: &'a Option<String>,
        git_dirty: &'a Option<bool>,
        cargo_features: Vec<&'a str>,
        rule_pack_sha256: &'a Option<String>,
    }

    let fingerprint = &report.analysis_configuration.fingerprint;
    let mut cargo_features = fingerprint
        .cargo_features
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    cargo_features.sort_unstable();
    let identity = Identity {
        tool_version: &report.tool_version,
        executable_sha256: &fingerprint.executable_sha256,
        git_commit: &fingerprint.git_commit,
        git_dirty: &fingerprint.git_dirty,
        cargo_features,
        rule_pack_sha256: &fingerprint.rule_pack_sha256,
    };
    let bytes = serde_json::to_vec(&identity)
        .map_err(|error| LabError::new(format!("serialize analyzer identity: {error}")))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn read_campaign(path: &Path) -> Result<Campaign, LabError> {
    let campaign: Campaign = read_json(path)?;
    campaign.validate()?;
    Ok(campaign)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CampaignCaseStatus {
    Pending,
    Running,
    Complete,
    /// Static Doctor analysis completed, while runtime execution was explicitly
    /// not requested. The observation itself remains `skipped`; the campaign
    /// case was not skipped.
    StaticComplete,
    InfrastructureFailure,
    HarnessFailure,
    /// Legacy 0.1.8 pre-release state spelling. Read for resumability, but new
    /// campaigns write [`Self::StaticComplete`].
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignCaseState {
    pub case_id: String,
    pub status: CampaignCaseStatus,
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctor_report: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accuracy_report: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignState {
    pub schema: String,
    pub campaign_id: String,
    pub campaign_digest: String,
    pub cases: Vec<CampaignCaseState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CampaignOptions {
    pub max_attempts: u32,
    /// Maximum simultaneous static/runtime workers. State remains committed by
    /// the coordinator after every completed case.
    pub max_parallel: usize,
}

impl Default for CampaignOptions {
    fn default() -> Self {
        Self {
            max_attempts: 2,
            max_parallel: 1,
        }
    }
}

pub trait CampaignExecutor: Sync {
    /// Produce the immutable static baseline before any runtime process starts.
    fn prepare_static(
        &self,
        _case: &CampaignCase,
        _case_dir: &Path,
    ) -> Result<Option<PathBuf>, LabError> {
        Ok(None)
    }

    fn execute(&self, case: &CampaignCase) -> Result<RawSmokeOutput, LabError>;
}

/// Default campaign executor: ingest a captured smoke artifact or execute the
/// case's explicit sandboxed command plan.
pub struct FileCampaignExecutor {
    pub base_dir: PathBuf,
    pub command_backend: CommandExecutionBackend,
    pub doctor_args: Vec<String>,
    pub doctor_config: Option<PathBuf>,
    pub expected_analyzer_fingerprint: String,
}

impl FileCampaignExecutor {
    #[must_use]
    pub fn new(
        base_dir: PathBuf,
        doctor_args: Vec<String>,
        doctor_config: Option<PathBuf>,
        expected_analyzer_fingerprint: String,
    ) -> Self {
        Self {
            base_dir,
            command_backend: CommandExecutionBackend,
            doctor_args,
            doctor_config,
            expected_analyzer_fingerprint,
        }
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_dir.join(path)
        }
    }

    fn doctor_command(
        &self,
        executable: &Path,
        case: &CampaignCase,
        target: &Path,
        report: &Path,
        profile: &Path,
    ) -> std::process::Command {
        let mut command = std::process::Command::new(executable);
        command
            .arg("doctor")
            .arg(target)
            .arg("--json")
            .arg(report)
            .arg("--exit-zero")
            .arg("--profile")
            .arg(profile);
        if let Some(config) = &self.doctor_config {
            command.arg("--config").arg(config);
        }
        if let Some(manifest) = &case.pack_manifest {
            command.arg("--pack-manifest").arg(self.resolve(manifest));
        }
        command.args(&self.doctor_args);
        command
    }
}

impl CampaignExecutor for FileCampaignExecutor {
    fn prepare_static(
        &self,
        case: &CampaignCase,
        case_dir: &Path,
    ) -> Result<Option<PathBuf>, LabError> {
        let lock_path = self.resolve(&case.corpus_lock);
        let lock = crate::corpus::read_lock(&lock_path)?;
        if !lock.digest.eq_ignore_ascii_case(&case.corpus_digest) {
            return Err(LabError::new(format!(
                "case `{}` expected corpus {}, but {} contains {}",
                case.id,
                case.corpus_digest,
                lock_path.display(),
                lock.digest
            )));
        }
        let target = self.resolve(&case.target);
        let verification = crate::store::verify_target(&lock, &target)?;
        write_json_atomic(&case_dir.join("target-verification.json"), &verification)?;
        if let Some(report) = &case.doctor_report {
            let report = self.resolve(report);
            let parsed: intermed_doctor_core::DoctorReport = read_json(&report)?;
            self.verify_report_fingerprint(case, &parsed)?;
            return Ok(Some(report));
        }
        let executable = campaign_executable()?;
        let report = case_dir.join("doctor-report.json");
        let profile = case_dir.join("doctor-profile.json");
        if report.is_file() {
            // A killed Doctor may leave a partial stdout file. Likewise, an
            // output directory may contain a valid report from a different
            // analyzer/config revision. Auto-generated baselines are cache-like
            // artifacts: reuse only after both parsing and identity checks pass;
            // otherwise regenerate them below. Explicit `doctor_report` inputs
            // above remain fail-closed and are never silently replaced.
            if let Ok(parsed) = read_json::<intermed_doctor_core::DoctorReport>(&report)
                && self.verify_report_fingerprint(case, &parsed).is_ok()
            {
                return Ok(Some(report));
            }
        }
        let stderr_path = case_dir.join("doctor-stderr.log");
        // `--json` owns the report path. Pointing stdout at that same path used
        // to create two independent writers: Doctor's atomic JSON rename and an
        // already-open terminal-output descriptor. Besides being racy, that can
        // make the rename fail on platforms that do not allow replacing an open
        // file. Keep presentation output separate from machine output.
        let stdout_path = case_dir.join("doctor-stdout.log");
        let stdout = std::fs::File::create(&stdout_path)
            .map_err(|error| LabError::new(format!("create {}: {error}", stdout_path.display())))?;
        let stderr = std::fs::File::create(&stderr_path)
            .map_err(|error| LabError::new(format!("create {}: {error}", stderr_path.display())))?;
        let mut command = self.doctor_command(&executable, case, &target, &report, &profile);
        let status = command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(stdout))
            .stderr(std::process::Stdio::from(stderr))
            .status()
            .map_err(|error| LabError::new(format!("run Doctor for {}: {error}", case.id)))?;
        if !status.success() {
            return Err(LabError::new(format!(
                "Doctor baseline for `{}` failed with status {status}; see {}",
                case.id,
                stderr_path.display()
            )));
        }
        let parsed: intermed_doctor_core::DoctorReport = read_json(&report)?;
        self.verify_report_fingerprint(case, &parsed)?;
        Ok(Some(report))
    }

    fn execute(&self, case: &CampaignCase) -> Result<RawSmokeOutput, LabError> {
        if let Some(path) = &case.captured_smoke {
            let path = self.resolve(path);
            let raw: RawSmokeOutput = read_json(&path)?;
            if raw.schema != crate::run::SMOKE_OUTPUT_SCHEMA {
                return Err(LabError::schema(
                    &path,
                    crate::run::SMOKE_OUTPUT_SCHEMA,
                    &raw.schema,
                ));
            }
            return Ok(raw);
        }
        let mut plan = case.execution.clone();
        let Some(mut plan) = plan.take() else {
            return Ok(RawSmokeOutput {
                schema: crate::run::SMOKE_OUTPUT_SCHEMA.into(),
                environment: case.id.clone(),
                exited_ok: false,
                timed_out: false,
                log: String::new(),
                exit_code: None,
                log_complete: true,
                infrastructure_failure: false,
                harness_failure: false,
                skipped: true,
                wall_time_ms: None,
                enforced_limits: Vec::new(),
                requested_limits: Vec::new(),
                isolation: "static-only".to_string(),
            });
        };
        plan.work_dir = self.resolve(&plan.work_dir);
        let outcome = self.command_backend.execute(&plan)?;
        Ok(outcome_to_smoke(&case.id, outcome))
    }
}

fn campaign_executable() -> Result<PathBuf, LabError> {
    // A campaign must keep using the coordinator's exact executable image. The
    // filesystem path returned by `current_exe` is not sufficient on Linux:
    // Cargo/package managers can atomically replace that path while a campaign
    // is running, causing later cases to use a different analyzer even though
    // the original process is still alive. The process-specific procfs link
    // remains pinned to the running image across such replacements.
    #[cfg(target_os = "linux")]
    {
        let proc_executable = PathBuf::from(format!("/proc/{}/exe", std::process::id()));
        if proc_executable.is_file() {
            return Ok(proc_executable);
        }
    }

    let executable = std::env::current_exe()
        .map_err(|error| LabError::new(format!("locate intermed executable: {error}")))?;
    if executable.is_file() {
        return Ok(executable);
    }
    Err(LabError::new(format!(
        "InterMed executable is no longer available: {}",
        executable.display()
    )))
}

impl FileCampaignExecutor {
    fn verify_report_fingerprint(
        &self,
        case: &CampaignCase,
        report: &intermed_doctor_core::DoctorReport,
    ) -> Result<(), LabError> {
        let actual_analyzer = report_analyzer_fingerprint(report)?;
        if self.expected_analyzer_fingerprint != "auto"
            && !actual_analyzer.eq_ignore_ascii_case(&self.expected_analyzer_fingerprint)
        {
            return Err(LabError::new(format!(
                "Doctor analyzer fingerprint mismatch: expected {}, found {}",
                self.expected_analyzer_fingerprint, actual_analyzer
            )));
        }
        if let Some(expected) = &case.doctor_fingerprint {
            let actual = &report.analysis_configuration.fingerprint;
            if actual.effective_config_sha256.as_deref()
                != Some(expected.effective_config_sha256.as_str())
                || actual.target_manifest_sha256.as_deref()
                    != Some(expected.target_manifest_sha256.as_str())
            {
                return Err(LabError::new(format!(
                    "Doctor invocation fingerprint does not match campaign case `{}`",
                    case.id
                )));
            }
        }
        Ok(())
    }
}

pub fn run_campaign(
    campaign: &Campaign,
    out_dir: &Path,
    executor: &dyn CampaignExecutor,
    options: CampaignOptions,
) -> Result<CampaignState, LabError> {
    campaign.validate()?;
    std::fs::create_dir_all(out_dir)
        .map_err(|error| LabError::new(format!("create {}: {error}", out_dir.display())))?;
    let state_path = out_dir.join("campaign-state.json");
    let digest = campaign.digest()?;
    let mut state = if state_path.is_file() {
        let mut state: CampaignState = read_json(&state_path)?;
        if state.schema != CAMPAIGN_STATE_SCHEMA
            || state.campaign_id != campaign.id
            || state.campaign_digest != digest
        {
            return Err(LabError::new(
                "campaign state belongs to a different campaign or campaign revision",
            ));
        }
        for case in &mut state.cases {
            if case.status == CampaignCaseStatus::Running {
                case.status = CampaignCaseStatus::Pending;
                // `attempts` is incremented before the worker starts so the
                // running state is durable. A process interruption has no
                // committed outcome, however, and must not consume the retry
                // budget; otherwise `--max-attempts 1` can never resume it.
                case.attempts = case.attempts.saturating_sub(1);
                case.error = Some(
                    "previous worker stopped before committing a result; attempt will be retried"
                        .into(),
                );
            }
        }
        state
    } else {
        CampaignState {
            schema: CAMPAIGN_STATE_SCHEMA.to_string(),
            campaign_id: campaign.id.clone(),
            campaign_digest: digest,
            cases: campaign
                .cases
                .iter()
                .map(|case| CampaignCaseState {
                    case_id: case.id.clone(),
                    status: CampaignCaseStatus::Pending,
                    attempts: 0,
                    observation: None,
                    doctor_report: None,
                    accuracy_report: None,
                    error: None,
                })
                .collect(),
        }
    };
    reconcile_case_set(campaign, &state)?;
    write_json_atomic(&state_path, &state)?;

    loop {
        let batch = state
            .cases
            .iter()
            .enumerate()
            .filter(|(_, case)| {
                matches!(
                    case.status,
                    CampaignCaseStatus::Pending | CampaignCaseStatus::InfrastructureFailure
                ) && case.attempts < options.max_attempts.max(1)
            })
            .map(|(index, _)| index)
            .take(options.max_parallel.max(1))
            .collect::<Vec<_>>();
        if batch.is_empty() {
            break;
        }
        for index in &batch {
            state.cases[*index].status = CampaignCaseStatus::Running;
            state.cases[*index].attempts += 1;
            state.cases[*index].error = None;
        }
        write_json_atomic(&state_path, &state)?;

        std::thread::scope(|scope| -> Result<(), LabError> {
            let (sender, receiver) = std::sync::mpsc::channel();
            for index in &batch {
                let index = *index;
                let case = &campaign.cases[index];
                let sender = sender.clone();
                scope.spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        execute_attempt(case, out_dir, executor)
                    }))
                    .unwrap_or_else(|_| Err(LabError::new("campaign worker panicked")));
                    let _ = sender.send((index, result));
                });
            }
            drop(sender);
            for _ in 0..batch.len() {
                let (index, result) = receiver.recv().map_err(|error| {
                    LabError::new(format!("campaign worker result channel closed: {error}"))
                })?;
                match result {
                    Ok(attempt) => {
                        state.cases[index].status = attempt.status;
                        state.cases[index].doctor_report = attempt.doctor_report;
                        state.cases[index].observation = Some(attempt.observation);
                        state.cases[index].accuracy_report = attempt.accuracy_report;
                        state.cases[index].error = None;
                    }
                    Err(error) => {
                        state.cases[index].status = CampaignCaseStatus::InfrastructureFailure;
                        state.cases[index].error = Some(error.to_string());
                    }
                }
                // Commit in completion order, not batch order. A slow sibling
                // must not make an already-finished case disappear after an
                // interruption.
                write_json_atomic(&state_path, &state)?;
            }
            Ok(())
        })?;
    }
    Ok(state)
}

struct AttemptResult {
    status: CampaignCaseStatus,
    doctor_report: Option<PathBuf>,
    observation: PathBuf,
    accuracy_report: Option<PathBuf>,
}

fn execute_attempt(
    case: &CampaignCase,
    out_dir: &Path,
    executor: &dyn CampaignExecutor,
) -> Result<AttemptResult, LabError> {
    let case_dir = out_dir.join("cases").join(safe_component(&case.id));
    std::fs::create_dir_all(&case_dir)
        .map_err(|error| LabError::new(format!("create {}: {error}", case_dir.display())))?;
    // Always re-enter `prepare_static` for a resumed, non-terminal case. The
    // default executor validates an existing report's analyzer/config/manifest
    // fingerprints before reusing it. Trusting only the path retained in state
    // would let a rebuilt analyzer silently inherit an older static baseline.
    let doctor_report = executor.prepare_static(case, &case_dir)?;
    let raw = executor.execute(case)?;
    let observation = observe_smoke(&raw);
    let observation_path = case_dir.join("observation.json");
    write_json_atomic(&observation_path, &observation)?;
    let accuracy_report = if let Some(report) = &doctor_report
        && observation.status.eligible_for_accuracy()
    {
        let accuracy_path = case_dir.join("accuracy.json");
        crate::eval::evaluate_observation_pair(
            report,
            &observation_path,
            intermed_doctor_core::evidence::Severity::Warn,
            &accuracy_path,
        )?;
        Some(accuracy_path)
    } else {
        None
    };
    Ok(AttemptResult {
        status: observation_state(&observation),
        doctor_report,
        observation: observation_path,
        accuracy_report,
    })
}

fn observation_state(observation: &ExecutionObservation) -> CampaignCaseStatus {
    use crate::observation::ObservationStatus;
    match observation.status {
        ObservationStatus::InfrastructureFailure => CampaignCaseStatus::InfrastructureFailure,
        ObservationStatus::HarnessFailure => CampaignCaseStatus::HarnessFailure,
        ObservationStatus::Skipped => CampaignCaseStatus::StaticComplete,
        _ => CampaignCaseStatus::Complete,
    }
}

fn reconcile_case_set(campaign: &Campaign, state: &CampaignState) -> Result<(), LabError> {
    let expected = campaign
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>();
    let found = state
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<Vec<_>>();
    if expected != found {
        return Err(LabError::new(
            "campaign state case order does not match the immutable campaign",
        ));
    }
    Ok(())
}

fn safe_component(value: &str) -> String {
    let mut out = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if out.is_empty() || out == "." || out == ".." {
        out = "case".to_string();
    }
    out.truncate(out.len().min(80));
    let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
    format!("{out}-{}", &digest[..12])
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    struct FakeExecutor(AtomicUsize);

    impl CampaignExecutor for FakeExecutor {
        fn execute(&self, case: &CampaignCase) -> Result<RawSmokeOutput, LabError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(RawSmokeOutput {
                schema: crate::run::SMOKE_OUTPUT_SCHEMA.into(),
                environment: case.id.clone(),
                exited_ok: true,
                timed_out: false,
                log: "Done (1.0s)!".into(),
                exit_code: Some(0),
                log_complete: true,
                infrastructure_failure: false,
                harness_failure: false,
                skipped: false,
                wall_time_ms: None,
                enforced_limits: Vec::new(),
                requested_limits: Vec::new(),
                isolation: "test".into(),
            })
        }
    }

    struct ConcurrencyExecutor {
        active: AtomicUsize,
        maximum: AtomicUsize,
    }

    struct HarnessFailureExecutor(AtomicUsize);

    struct RetryingExecutor {
        prepares: AtomicUsize,
        executions: AtomicUsize,
    }

    struct CompletionOrderExecutor {
        fast_done: AtomicBool,
        release_slow: AtomicBool,
    }

    impl CampaignExecutor for CompletionOrderExecutor {
        fn execute(&self, case: &CampaignCase) -> Result<RawSmokeOutput, LabError> {
            if case.id == "fast" {
                self.fast_done.store(true, Ordering::SeqCst);
            } else {
                while !self.release_slow.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            Ok(RawSmokeOutput {
                schema: crate::run::SMOKE_OUTPUT_SCHEMA.into(),
                environment: case.id.clone(),
                exited_ok: true,
                timed_out: false,
                log: "Done (1.0s)!".into(),
                exit_code: Some(0),
                log_complete: true,
                infrastructure_failure: false,
                harness_failure: false,
                skipped: false,
                wall_time_ms: None,
                enforced_limits: Vec::new(),
                requested_limits: Vec::new(),
                isolation: "test".into(),
            })
        }
    }

    impl CampaignExecutor for RetryingExecutor {
        fn prepare_static(
            &self,
            _case: &CampaignCase,
            _case_dir: &Path,
        ) -> Result<Option<PathBuf>, LabError> {
            self.prepares.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn execute(&self, case: &CampaignCase) -> Result<RawSmokeOutput, LabError> {
            let attempt = self.executions.fetch_add(1, Ordering::SeqCst);
            Ok(RawSmokeOutput {
                schema: crate::run::SMOKE_OUTPUT_SCHEMA.into(),
                environment: case.id.clone(),
                exited_ok: attempt > 0,
                timed_out: false,
                log: if attempt > 0 {
                    "Done (1.0s)!".into()
                } else {
                    String::new()
                },
                exit_code: (attempt > 0).then_some(0),
                log_complete: true,
                infrastructure_failure: attempt == 0,
                harness_failure: false,
                skipped: false,
                wall_time_ms: None,
                enforced_limits: Vec::new(),
                requested_limits: Vec::new(),
                isolation: "test".into(),
            })
        }
    }

    impl CampaignExecutor for HarnessFailureExecutor {
        fn execute(&self, case: &CampaignCase) -> Result<RawSmokeOutput, LabError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(RawSmokeOutput {
                schema: crate::run::SMOKE_OUTPUT_SCHEMA.into(),
                environment: case.id.clone(),
                exited_ok: false,
                timed_out: false,
                log: String::new(),
                exit_code: None,
                log_complete: false,
                infrastructure_failure: false,
                harness_failure: true,
                skipped: false,
                wall_time_ms: None,
                enforced_limits: Vec::new(),
                requested_limits: Vec::new(),
                isolation: "test".into(),
            })
        }
    }

    impl CampaignExecutor for ConcurrencyExecutor {
        fn execute(&self, case: &CampaignCase) -> Result<RawSmokeOutput, LabError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(25));
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(RawSmokeOutput {
                schema: crate::run::SMOKE_OUTPUT_SCHEMA.into(),
                environment: case.id.clone(),
                exited_ok: true,
                timed_out: false,
                log: "Done (1.0s)!".into(),
                exit_code: Some(0),
                log_complete: true,
                infrastructure_failure: false,
                harness_failure: false,
                skipped: false,
                wall_time_ms: None,
                enforced_limits: Vec::new(),
                requested_limits: Vec::new(),
                isolation: "test".into(),
            })
        }
    }

    fn temp() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "intermed-campaign-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn campaign() -> Campaign {
        Campaign {
            schema: CAMPAIGN_SCHEMA.into(),
            id: "test".into(),
            analyzer_fingerprint: "b".repeat(64),
            doctor_args: Vec::new(),
            cases: vec![CampaignCase {
                id: "one".into(),
                corpus_lock: "one.lock".into(),
                corpus_digest: "a".repeat(64),
                doctor_fingerprint: None,
                target: "one".into(),
                pack_manifest: None,
                doctor_report: None,
                captured_smoke: Some("one.json".into()),
                execution: None,
            }],
        }
    }

    #[test]
    fn completed_cases_are_not_repeated_on_resume() {
        let out = temp();
        let executor = FakeExecutor(AtomicUsize::new(0));
        let first = run_campaign(&campaign(), &out, &executor, CampaignOptions::default()).unwrap();
        assert_eq!(first.cases[0].status, CampaignCaseStatus::Complete);
        let second =
            run_campaign(&campaign(), &out, &executor, CampaignOptions::default()).unwrap();
        assert_eq!(second.cases[0].status, CampaignCaseStatus::Complete);
        assert_eq!(executor.0.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn interrupted_running_case_does_not_consume_retry_budget() {
        let out = temp();
        let manifest = campaign();
        let state = CampaignState {
            schema: CAMPAIGN_STATE_SCHEMA.to_string(),
            campaign_id: manifest.id.clone(),
            campaign_digest: manifest.digest().unwrap(),
            cases: vec![CampaignCaseState {
                case_id: manifest.cases[0].id.clone(),
                status: CampaignCaseStatus::Running,
                attempts: 1,
                observation: None,
                doctor_report: None,
                accuracy_report: None,
                error: None,
            }],
        };
        write_json_atomic(&out.join("campaign-state.json"), &state).unwrap();

        let executor = FakeExecutor(AtomicUsize::new(0));
        let resumed = run_campaign(
            &manifest,
            &out,
            &executor,
            CampaignOptions {
                max_attempts: 1,
                max_parallel: 1,
            },
        )
        .unwrap();

        assert_eq!(resumed.cases[0].status, CampaignCaseStatus::Complete);
        assert_eq!(resumed.cases[0].attempts, 1);
        assert_eq!(executor.0.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn skipped_runtime_is_a_completed_static_case() {
        let observation = ExecutionObservation {
            schema: crate::observation::OBSERVATION_SCHEMA.to_string(),
            environment: "static-only".to_string(),
            status: crate::observation::ObservationStatus::Skipped,
            evidence_state: crate::observation::EvidenceState::Unavailable,
            coverage: crate::observation::ExecutionCoverage::default(),
            incidents: Vec::new(),
            background_events: Vec::new(),
            failure_categories: Vec::new(),
            exit_code: None,
            timed_out: false,
            wall_time_ms: None,
            enforced_limits: Vec::new(),
            requested_limits: Vec::new(),
            isolation: "not-executed".to_string(),
        };
        assert_eq!(
            observation_state(&observation),
            CampaignCaseStatus::StaticComplete
        );
    }

    #[test]
    fn duplicate_case_ids_are_rejected() {
        let mut campaign = campaign();
        campaign.cases.push(campaign.cases[0].clone());
        assert!(campaign.validate().is_err());
    }

    #[test]
    fn rejects_non_digest_analyzer_identity() {
        let mut campaign = campaign();
        campaign.analyzer_fingerprint = "build".into();
        assert!(campaign.validate().is_err());
    }

    #[test]
    fn coordinator_executable_is_launchable() {
        assert!(campaign_executable().unwrap().is_file());
    }

    #[test]
    fn generated_doctor_command_writes_the_report_it_later_reads() {
        let executor = FileCampaignExecutor::new(
            PathBuf::from("/campaign"),
            vec!["--mixin-level".into(), "basic".into()],
            None,
            "auto".into(),
        );
        let case = CampaignCase {
            id: "case".into(),
            corpus_lock: "case.lock".into(),
            corpus_digest: "a".repeat(64),
            doctor_fingerprint: None,
            target: "target".into(),
            pack_manifest: Some("pack.mrpack".into()),
            doctor_report: None,
            captured_smoke: None,
            execution: None,
        };
        let report = Path::new("/out/doctor-report.json");
        let command = executor.doctor_command(
            Path::new("/bin/intermed"),
            &case,
            Path::new("/target"),
            report,
            Path::new("/out/doctor-profile.json"),
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(
            args.windows(2)
                .any(|pair| pair == ["--json", report.to_str().unwrap()])
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--pack-manifest", "/campaign/pack.mrpack"] })
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--mixin-level", "basic"])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn coordinator_executable_is_pinned_to_the_running_image() {
        assert_eq!(
            campaign_executable().unwrap(),
            PathBuf::from(format!("/proc/{}/exe", std::process::id()))
        );
    }

    #[test]
    fn scheduler_respects_parallel_bound() {
        let out = temp();
        let mut campaign = campaign();
        campaign.cases = (0..4)
            .map(|index| CampaignCase {
                id: format!("case-{index}"),
                corpus_lock: "case.lock".into(),
                corpus_digest: "a".repeat(64),
                doctor_fingerprint: None,
                target: "case".into(),
                pack_manifest: None,
                doctor_report: None,
                captured_smoke: Some("case.json".into()),
                execution: None,
            })
            .collect();
        let executor = ConcurrencyExecutor {
            active: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
        };
        let state = run_campaign(
            &campaign,
            &out,
            &executor,
            CampaignOptions {
                max_attempts: 1,
                max_parallel: 2,
            },
        )
        .unwrap();
        assert!(
            state
                .cases
                .iter()
                .all(|case| case.status == CampaignCaseStatus::Complete)
        );
        assert_eq!(executor.maximum.load(Ordering::SeqCst), 2);
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn harness_failures_are_terminal_not_retried() {
        let out = temp();
        let executor = HarnessFailureExecutor(AtomicUsize::new(0));
        let state = run_campaign(
            &campaign(),
            &out,
            &executor,
            CampaignOptions {
                max_attempts: 3,
                max_parallel: 1,
            },
        )
        .unwrap();
        assert_eq!(state.cases[0].status, CampaignCaseStatus::HarnessFailure);
        assert_eq!(executor.0.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn infrastructure_retry_revalidates_static_baseline() {
        let out = temp();
        let executor = RetryingExecutor {
            prepares: AtomicUsize::new(0),
            executions: AtomicUsize::new(0),
        };
        let state = run_campaign(
            &campaign(),
            &out,
            &executor,
            CampaignOptions {
                max_attempts: 2,
                max_parallel: 1,
            },
        )
        .unwrap();
        assert_eq!(state.cases[0].status, CampaignCaseStatus::Complete);
        assert_eq!(executor.prepares.load(Ordering::SeqCst), 2);
        assert_eq!(executor.executions.load(Ordering::SeqCst), 2);
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn completed_case_is_committed_while_sibling_is_running() {
        let out = temp();
        let mut manifest = campaign();
        manifest.cases = ["fast", "slow"]
            .into_iter()
            .map(|id| CampaignCase {
                id: id.into(),
                corpus_lock: "case.lock".into(),
                corpus_digest: "a".repeat(64),
                doctor_fingerprint: None,
                target: "case".into(),
                pack_manifest: None,
                doctor_report: None,
                captured_smoke: Some("case.json".into()),
                execution: None,
            })
            .collect();
        let executor = CompletionOrderExecutor {
            fast_done: AtomicBool::new(false),
            release_slow: AtomicBool::new(false),
        };
        let mut observed_commit = false;
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                run_campaign(
                    &manifest,
                    &out,
                    &executor,
                    CampaignOptions {
                        max_attempts: 1,
                        max_parallel: 2,
                    },
                )
            });
            for _ in 0..200 {
                if executor.fast_done.load(Ordering::SeqCst)
                    && let Ok(state) = read_json::<CampaignState>(&out.join("campaign-state.json"))
                    && state.cases[0].status == CampaignCaseStatus::Complete
                    && state.cases[1].status == CampaignCaseStatus::Running
                {
                    observed_commit = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            executor.release_slow.store(true, Ordering::SeqCst);
            worker.join().unwrap().unwrap();
        });
        assert!(observed_commit);
        std::fs::remove_dir_all(out).ok();
    }
}
