//! Sandboxed live-process execution contracts for Compatibility Lab campaigns.
//!
//! The deterministic evidence pipeline ingests captured
//! [`RawSmokeOutput`](crate::run::RawSmokeOutput) or executes an explicit command
//! plan, then emits the same JSON shape for classification and evaluation.
//!
//! Acquisition and loader installation stay outside this module. The command
//! backend executes only explicit plans and refuses to run when isolation was
//! required but not configured.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::LabError;
use crate::corpus::{CorpusEnvironment, CorpusLock};
use crate::run::RawSmokeOutput;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

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
    #[serde(default)]
    pub limits: ExecutionLimits,
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
            port: 0,
            limits: ExecutionLimits::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLimits {
    /// Hard limits enforced directly by the in-process backend.
    pub wall_time_secs: u64,
    pub max_log_bytes: u64,
    /// Requested limits that require an external sandbox/cgroup/quota backend.
    /// They are never reported as enforced merely because they appear here.
    #[serde(alias = "memory_bytes")]
    pub requested_memory_bytes: u64,
    #[serde(alias = "cpu_quota_percent")]
    pub requested_cpu_quota_percent: u16,
    #[serde(alias = "max_processes")]
    pub requested_max_processes: u32,
    #[serde(alias = "max_written_bytes")]
    pub requested_max_written_bytes: u64,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            wall_time_secs: 300,
            max_log_bytes: 32 * 1024 * 1024,
            requested_memory_bytes: 8 * 1024 * 1024 * 1024,
            requested_cpu_quota_percent: 400,
            requested_max_processes: 512,
            requested_max_written_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    #[default]
    Deny,
    LoopbackOnly,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SandboxPolicy {
    /// Refuse to execute without a supported isolation backend.
    #[default]
    Required,
    /// Linux bubblewrap isolation: new namespaces, no host home, writable work
    /// directory only. Network remains isolated unless explicitly allowed.
    Bubblewrap,
    /// Use an external sandbox prefix such as `bwrap ... --`.
    External { prefix: Vec<String> },
    /// Explicit expert opt-in. Reports retain this unsafe choice.
    UnsafeHost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub id: String,
    pub command: Vec<String>,
    pub work_dir: PathBuf,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub sandbox: SandboxPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub limits: ExecutionLimits,
    /// Limits guaranteed by an external wrapper (for example a cgroup runner).
    /// These declarations are retained in the observation for audit.
    #[serde(default)]
    pub externally_enforced_limits: Vec<String>,
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
    pub exit_code: Option<i32>,
    pub log_complete: bool,
    pub infrastructure_failure: bool,
    pub harness_failure: bool,
    pub wall_time_ms: u64,
    pub enforced_limits: Vec<String>,
    pub requested_limits: Vec<String>,
    pub isolation: String,
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
    fn wait(
        &self,
        spec: &EnvironmentSpec,
        process: RunningProcess,
    ) -> Result<ProcessOutcome, LabError>;
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
        exit_code: outcome.exit_code,
        log_complete: outcome.log_complete,
        infrastructure_failure: outcome.infrastructure_failure,
        harness_failure: outcome.harness_failure,
        skipped: false,
        wall_time_ms: Some(outcome.wall_time_ms),
        enforced_limits: outcome.enforced_limits,
        requested_limits: outcome.requested_limits,
        isolation: outcome.isolation,
    }
}

/// Minimal local execution backend used by campaign workers.
///
/// It fails closed unless an external sandbox command is supplied. `UnsafeHost`
/// exists for controlled CI containers and is always visible in the plan.
#[derive(Debug, Default)]
pub struct CommandExecutionBackend;

impl CommandExecutionBackend {
    pub fn execute(&self, plan: &ExecutionPlan) -> Result<ProcessOutcome, LabError> {
        if plan.command.is_empty() {
            return Err(LabError::new("execution plan has an empty command"));
        }
        if matches!(plan.sandbox, SandboxPolicy::Required) {
            return Err(LabError::new(
                "execution refused: no sandbox backend configured (use an external sandbox prefix)",
            ));
        }
        #[cfg(not(unix))]
        if !matches!(plan.sandbox, SandboxPolicy::External { .. })
            || !plan
                .externally_enforced_limits
                .iter()
                .any(|limit| limit == "process-tree")
        {
            return Err(LabError::new(
                "live execution requires an external sandbox that attests process-tree termination on this platform",
            ));
        }
        std::fs::create_dir_all(&plan.work_dir).map_err(|error| {
            LabError::new(format!("create {}: {error}", plan.work_dir.display()))
        })?;
        let log_path = plan.work_dir.join("intermed-lab-process.log");
        let stdout = File::create(&log_path)
            .map_err(|error| LabError::new(format!("create {}: {error}", log_path.display())))?;
        let stderr = stdout.try_clone().map_err(|error| {
            LabError::new(format!("clone capture {}: {error}", log_path.display()))
        })?;

        let (program, args) = command_parts(plan)?;
        let mut command = Command::new(&program);
        command
            .args(args)
            .current_dir(&plan.work_dir)
            .env_clear()
            .envs(plan.environment.iter())
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        #[cfg(unix)]
        command.process_group(0);
        let started = std::time::Instant::now();
        let mut child = command
            .spawn()
            .map_err(|error| LabError::new(format!("launch {}: {error}", plan.id)))?;

        let deadline =
            std::time::Instant::now() + Duration::from_secs(plan.limits.wall_time_secs.max(1));
        let (status, timed_out) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (Some(status), false),
                Ok(None) if std::time::Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    kill_process_tree(&mut child);
                    break (child.wait().ok(), true);
                }
                Err(error) => {
                    kill_process_tree(&mut child);
                    return Err(LabError::new(format!("wait for {}: {error}", plan.id)));
                }
            }
        };

        let bounded = intermed_doctor_core::bounded_text::read_text_tail(
            &log_path,
            plan.limits.max_log_bytes,
        )
        .map_err(|error| LabError::new(format!("read {}: {error}", log_path.display())))?;
        let log = bounded.text;
        let log_complete = !bounded.truncated;
        let mut enforced_limits = vec!["wall-time".to_string(), "captured-log-bytes".to_string()];
        let isolation = match plan.sandbox {
            SandboxPolicy::Bubblewrap => {
                enforced_limits.push("filesystem-namespace".to_string());
                if plan.network != NetworkPolicy::Allow {
                    enforced_limits.push("network-namespace".to_string());
                }
                #[cfg(unix)]
                enforced_limits.push("process-tree".to_string());
                "bubblewrap"
            }
            SandboxPolicy::External { .. } => {
                #[cfg(unix)]
                enforced_limits.push("process-tree".to_string());
                "external-sandbox"
            }
            SandboxPolicy::UnsafeHost => {
                #[cfg(unix)]
                enforced_limits.push("process-tree".to_string());
                "unsafe-host"
            }
            SandboxPolicy::Required => unreachable!("required sandbox rejected before launch"),
        };
        if matches!(plan.sandbox, SandboxPolicy::External { .. }) {
            enforced_limits.extend(plan.externally_enforced_limits.iter().cloned());
            enforced_limits.sort();
            enforced_limits.dedup();
        }
        Ok(ProcessOutcome {
            exited_ok: status
                .as_ref()
                .is_some_and(std::process::ExitStatus::success),
            timed_out,
            log,
            exit_code: status.and_then(|status| status.code()),
            log_complete,
            infrastructure_failure: false,
            harness_failure: false,
            wall_time_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            enforced_limits,
            requested_limits: requested_resource_limits(&plan.limits),
            isolation: isolation.to_string(),
        })
    }
}

fn requested_resource_limits(limits: &ExecutionLimits) -> Vec<String> {
    let mut requested = Vec::new();
    if limits.requested_memory_bytes > 0 {
        requested.push("memory".to_string());
    }
    if limits.requested_cpu_quota_percent > 0 {
        requested.push("cpu".to_string());
    }
    if limits.requested_max_processes > 0 {
        requested.push("process-count".to_string());
    }
    if limits.requested_max_written_bytes > 0 {
        requested.push("written-bytes".to_string());
    }
    requested
}

fn command_parts(plan: &ExecutionPlan) -> Result<(String, Vec<String>), LabError> {
    match &plan.sandbox {
        SandboxPolicy::Required => Err(LabError::new("sandbox backend is required")),
        SandboxPolicy::UnsafeHost => Ok((plan.command[0].clone(), plan.command[1..].to_vec())),
        SandboxPolicy::External { prefix } => {
            let Some(program) = prefix.first() else {
                return Err(LabError::new("external sandbox prefix is empty"));
            };
            let mut args = prefix[1..].to_vec();
            args.extend(plan.command.iter().cloned());
            Ok((program.clone(), args))
        }
        SandboxPolicy::Bubblewrap => {
            let mut args = vec![
                "--die-with-parent".to_string(),
                "--new-session".to_string(),
                "--unshare-all".to_string(),
            ];
            if plan.network == NetworkPolicy::Allow {
                args.push("--share-net".to_string());
            }
            for root in [
                "/usr",
                "/lib",
                "/lib64",
                "/bin",
                "/sbin",
                "/nix/store",
                "/opt",
            ] {
                if Path::new(root).exists() {
                    args.extend(["--ro-bind".to_string(), root.to_string(), root.to_string()]);
                }
            }
            if let Some(runtime_root) = runtime_root(&plan.command[0], &plan.environment)
                && ![
                    "/usr",
                    "/lib",
                    "/lib64",
                    "/bin",
                    "/sbin",
                    "/nix/store",
                    "/opt",
                ]
                .iter()
                .any(|root| runtime_root.starts_with(root))
            {
                let root = runtime_root.display().to_string();
                args.extend(["--ro-bind".to_string(), root.clone(), root]);
            }
            args.extend([
                "--proc".to_string(),
                "/proc".to_string(),
                "--dev".to_string(),
                "/dev".to_string(),
                "--tmpfs".to_string(),
                "/tmp".to_string(),
                "--bind".to_string(),
                plan.work_dir.display().to_string(),
                "/work".to_string(),
                "--chdir".to_string(),
                "/work".to_string(),
                "--".to_string(),
            ]);
            if plan.network == NetworkPolicy::LoopbackOnly {
                let ip = ["/usr/bin/ip", "/bin/ip", "/usr/sbin/ip", "/sbin/ip"]
                    .into_iter()
                    .find(|path| Path::new(path).is_file())
                    .ok_or_else(|| {
                        LabError::new(
                            "loopback-only sandbox requires the `ip` utility to bring `lo` up",
                        )
                    })?;
                args.extend([
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    format!("{ip} link set lo up && exec \"$@\""),
                    "intermed-loopback".to_string(),
                ]);
            }
            args.extend(plan.command.iter().cloned());
            Ok(("bwrap".to_string(), args))
        }
    }
}

fn runtime_root(program: &str, environment: &BTreeMap<String, String>) -> Option<PathBuf> {
    let path = Path::new(program);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        environment
            .get("PATH")
            .into_iter()
            .flat_map(|value| std::env::split_paths(value))
            .map(|directory| directory.join(program))
            .find(|candidate| candidate.is_file())?
    };
    let canonical = resolved.canonicalize().unwrap_or(resolved);
    let parent = canonical.parent()?;
    if parent.file_name().and_then(|value| value.to_str()) == Some("bin") {
        parent.parent().map(Path::to_path_buf)
    } else {
        Some(parent.to_path_buf())
    }
}

fn kill_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        // The child is launched as process-group leader. Negative pid targets
        // every descendant that stayed in that group, not just the wrapper JVM.
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(sandbox: SandboxPolicy) -> ExecutionPlan {
        ExecutionPlan {
            id: "test".into(),
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf 'Done (1.0s)!'".into(),
            ],
            work_dir: std::env::temp_dir().join(format!(
                "intermed-exec-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )),
            environment: BTreeMap::new(),
            sandbox,
            network: NetworkPolicy::Deny,
            limits: ExecutionLimits {
                wall_time_secs: 5,
                max_log_bytes: 1024,
                ..ExecutionLimits::default()
            },
            externally_enforced_limits: Vec::new(),
        }
    }

    #[test]
    fn required_sandbox_fails_closed() {
        let error = CommandExecutionBackend
            .execute(&plan(SandboxPolicy::Required))
            .unwrap_err();
        assert!(error.to_string().contains("sandbox"));
    }

    #[test]
    fn unsafe_host_is_explicit_and_still_bounded() {
        let plan = plan(SandboxPolicy::UnsafeHost);
        let work_dir = plan.work_dir.clone();
        let outcome = CommandExecutionBackend.execute(&plan).unwrap();
        assert!(outcome.exited_ok);
        assert_eq!(outcome.isolation, "unsafe-host");
        assert!(outcome.enforced_limits.contains(&"wall-time".to_string()));
        assert!(outcome.requested_limits.contains(&"memory".to_string()));
        assert!(!outcome.enforced_limits.contains(&"memory".to_string()));
        assert!(outcome.log.contains("Done"));
        std::fs::remove_dir_all(work_dir).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn timeout_terminates_the_process_group() {
        let mut plan = plan(SandboxPolicy::UnsafeHost);
        plan.command = vec![
            "/bin/sh".into(),
            "-c".into(),
            "sleep 30 & echo $! > descendant.pid; wait".into(),
        ];
        plan.limits.wall_time_secs = 1;
        let work_dir = plan.work_dir.clone();
        let outcome = CommandExecutionBackend.execute(&plan).unwrap();
        assert!(outcome.timed_out);
        let pid: u32 = std::fs::read_to_string(work_dir.join("descendant.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        std::fs::remove_dir_all(work_dir).ok();
    }

    #[test]
    fn loopback_policy_is_not_lowered_like_network_deny() {
        if !["/usr/bin/ip", "/bin/ip", "/usr/sbin/ip", "/sbin/ip"]
            .iter()
            .any(|path| Path::new(path).is_file())
        {
            return;
        }
        let mut loopback = plan(SandboxPolicy::Bubblewrap);
        loopback.network = NetworkPolicy::LoopbackOnly;
        let (_, loopback_args) = command_parts(&loopback).unwrap();
        let deny = plan(SandboxPolicy::Bubblewrap);
        let (_, deny_args) = command_parts(&deny).unwrap();
        assert!(
            loopback_args
                .iter()
                .any(|arg| arg.contains("link set lo up"))
        );
        assert!(!deny_args.iter().any(|arg| arg.contains("link set lo up")));
    }
}
