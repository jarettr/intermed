//! Live server execution interfaces (deferred donor path).
//!
//! The deterministic evidence pipeline ingests captured
//! [`RawSmokeOutput`](crate::run::RawSmokeOutput) via [`CapturedLogRunner`](crate::run::CapturedLogRunner).
//! A future live runner downloads loaders, boots a JVM, tails the log, and emits
//! the same JSON shape — without changing `lab run` classification or `lab eval`.
//!
//! This module only defines the contracts; no network or process code ships yet.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::corpus::{CorpusEnvironment, CorpusLock};
use crate::run::RawSmokeOutput;
use crate::LabError;

/// Everything required to boot one lab environment (loader + MC + side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSpec {
    pub environment: CorpusEnvironment,
    /// Directory containing corpus jars (from [`CorpusLock`]).
    pub mods_dir: PathBuf,
    /// Working directory for the server process (world, logs, configs).
    pub work_dir: PathBuf,
    /// Hard wall-clock budget for startup + soak.
    pub time_budget: Duration,
    /// TCP port the server should bind (0 = ephemeral).
    pub port: u16,
}

impl EnvironmentSpec {
    /// Build a spec from a locked corpus and output workspace.
    #[must_use]
    pub fn from_lock(lock: &CorpusLock, mods_dir: PathBuf, work_dir: PathBuf) -> Self {
        Self {
            environment: lock.environment.clone(),
            mods_dir,
            work_dir,
            time_budget: Duration::from_secs(180),
            port: 25565,
        }
    }
}

/// A launched server/client process handle.
#[derive(Debug)]
pub struct RunningProcess {
    pub pid: u32,
    pub log_path: PathBuf,
}

/// Outcome after waiting for process exit or timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    pub exited_ok: bool,
    pub timed_out: bool,
    pub log: String,
}

/// Boots environments and returns raw smoke outputs compatible with [`SmokeRunner`](crate::run::SmokeRunner).
///
/// Implementations: `CapturedLogRunner` (in-tree), future `ServerProcessRunner` (live JVM).
pub trait EnvironmentRunner: Send + Sync {
    /// Human-readable runner id (`captured-logs`, `live-server`, …).
    fn id(&self) -> &'static str;

    /// Produce one [`RawSmokeOutput`] per environment label in `specs`.
    fn run_environments(&self, specs: &[EnvironmentSpec]) -> Result<Vec<RawSmokeOutput>, LabError>;
}

/// Low-level process control for one environment (install loader, launch JVM, tail log).
///
/// `EnvironmentBootstrap` + loader installers compose into this trait; `lab run` never
/// calls it directly — only a live [`EnvironmentRunner`] implementation does.
pub trait ServerProcessRunner: Send + Sync {
    /// Prepare the working directory (download loader, lay out jars).
    fn prepare(&self, spec: &EnvironmentSpec) -> Result<(), LabError>;

    /// Launch the server and return a handle for log tailing.
    fn launch(&self, spec: &EnvironmentSpec) -> Result<RunningProcess, LabError>;

    /// Block until exit or `spec.time_budget`, returning captured log text.
    fn wait(&self, spec: &EnvironmentSpec, process: RunningProcess) -> Result<ProcessOutcome, LabError>;
}

/// Map a [`ProcessOutcome`] into the shared smoke-output schema.
#[must_use]
pub fn outcome_to_smoke(environment: &str, outcome: ProcessOutcome) -> RawSmokeOutput {
    RawSmokeOutput {
        schema: crate::run::SMOKE_OUTPUT_SCHEMA.into(),
        environment: environment.to_string(),
        exited_ok: outcome.exited_ok,
        timed_out: outcome.timed_out,
        log: outcome.log,
    }
}