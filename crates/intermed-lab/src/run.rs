//! Smoke-test ingestion: raw captured outputs → a classified [`LabRun`].
//!
//! Running real servers/clients (download a loader, launch a JVM, watch the log)
//! is the heavy, rewrite-hard donor work (`EnvironmentBootstrap`,
//! `ServerProcessRunner`, the loader installers). That live execution is modelled
//! as the [`SmokeRunner`] trait; the in-tree implementation
//! ([`CapturedLogRunner`]) *ingests* pre-captured outputs from disk, mirroring
//! the spark bridge's "import, don't execute" discipline. The deterministic,
//! offline-testable evidence path is fully implemented here; a live runner is a
//! later, optional plug-in behind the same trait.

use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::attribution::extract_attributions;
use crate::classify::{classify_log, classify_log_all, FailureCategory};
use crate::FailureAttribution;
use crate::corpus::{read_lock, CorpusEnvironment, CorpusLock};
use crate::{read_json, write_json_atomic, LabError};

/// Schema tag for a single raw captured smoke output.
pub const SMOKE_OUTPUT_SCHEMA: &str = "intermed-smoke-output-v1";
/// Schema tag for a classified lab run.
pub const LAB_RUN_SCHEMA: &str = "intermed-lab-run-v1";

/// Default maximum length of a stored log excerpt (overridable via config / CLI).
pub const DEFAULT_EXCERPT_MAX: usize = 280;

/// Tunables for smoke-output classification (`lab run`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabRunOptions {
    /// Maximum characters kept from a failure log line in [`SmokeResult::log_excerpt`].
    pub excerpt_max: usize,
}

impl Default for LabRunOptions {
    fn default() -> Self {
        Self {
            excerpt_max: DEFAULT_EXCERPT_MAX,
        }
    }
}

/// The raw result of one environment's smoke test, before classification. A live
/// runner produces these by launching a server; [`CapturedLogRunner`] reads them
/// from disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawSmokeOutput {
    pub schema: String,
    /// Human label for the environment combination (e.g. `fabric-1.20.1-server`).
    pub environment: String,
    /// Whether the process exited successfully (0 / clean shutdown).
    pub exited_ok: bool,
    /// Whether the run was killed for exceeding a time budget.
    #[serde(default)]
    pub timed_out: bool,
    /// Captured stdout+stderr (or log file contents).
    #[serde(default)]
    pub log: String,
}

/// Outcome of a smoke test after classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SmokeStatus {
    Pass,
    /// Clean exit but tick/MSPT regression detected in the log.
    Degraded,
    Fail,
    Crash,
    Timeout,
}

impl SmokeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SmokeStatus::Pass => "pass",
            SmokeStatus::Degraded => "degraded",
            SmokeStatus::Fail => "fail",
            SmokeStatus::Crash => "crash",
            SmokeStatus::Timeout => "timeout",
        }
    }

    pub fn is_pass(self) -> bool {
        matches!(self, SmokeStatus::Pass)
    }
}

/// A classified per-environment smoke result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmokeResult {
    pub environment: String,
    pub status: SmokeStatus,
    /// The dominant failure category (drives [`status`](SmokeResult::status)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureCategory>,
    /// Other *independent* failure categories detected in the same log beyond the
    /// dominant one (e.g. a missing dependency alongside a mixin error). Empty
    /// when the log had a single failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_failures: Vec<FailureCategory>,
    /// Attributed subjects (mod id, class, jar) extracted from the log for
    /// finding-level `lab eval` joins. Empty when the log had no parseable subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributions: Vec<FailureAttribution>,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_excerpt: Option<String>,
}

/// A classified lab run for one corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabRun {
    pub schema: String,
    /// The corpus lock digest this run was produced against (provenance).
    pub corpus_digest: String,
    pub environment: CorpusEnvironment,
    pub results: Vec<SmokeResult>,
}

/// Produces raw smoke outputs for a locked corpus. The default in-tree
/// implementation ingests captured outputs; a live server runner is a deferred
/// donor implementing this trait.
pub trait SmokeRunner {
    fn run(&self, lock: &CorpusLock) -> Result<Vec<RawSmokeOutput>, LabError>;
}

/// Ingests captured `intermed-smoke-output-v1` JSON files from a directory (one
/// per environment). Deterministic: outputs are returned sorted by environment.
pub struct CapturedLogRunner<'a> {
    pub dir: &'a Path,
}

impl SmokeRunner for CapturedLogRunner<'_> {
    fn run(&self, _lock: &CorpusLock) -> Result<Vec<RawSmokeOutput>, LabError> {
        if !self.dir.is_dir() {
            return Err(LabError::new(format!(
                "captured-output directory not found: {}",
                self.dir.display()
            )));
        }
        let mut files: Vec<PathBuf> = std::fs::read_dir(self.dir)
            .map_err(|e| LabError::new(format!("read {}: {e}", self.dir.display())))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        files.sort();

        // Parsing is independent per file; fan out, preserving order.
        let parsed: Vec<Result<RawSmokeOutput, LabError>> = files
            .par_iter()
            .map(|path| {
                let raw: RawSmokeOutput = read_json(path)?;
                if raw.schema != SMOKE_OUTPUT_SCHEMA {
                    return Err(LabError::schema(path, SMOKE_OUTPUT_SCHEMA, &raw.schema));
                }
                Ok(raw)
            })
            .collect();

        let mut outputs = Vec::with_capacity(parsed.len());
        for r in parsed {
            outputs.push(r?);
        }
        outputs.sort_by(|a, b| a.environment.cmp(&b.environment));
        Ok(outputs)
    }
}

/// Classify one raw output into a [`SmokeResult`] (default excerpt length).
#[must_use]
pub fn classify(raw: &RawSmokeOutput) -> SmokeResult {
    classify_with_options(raw, LabRunOptions::default())
}

/// Classify one raw output with explicit run options.
#[must_use]
pub fn classify_with_options(raw: &RawSmokeOutput, options: LabRunOptions) -> SmokeResult {
    let excerpt_max = options.excerpt_max;
    if raw.timed_out {
        return SmokeResult {
            environment: raw.environment.clone(),
            status: SmokeStatus::Timeout,
            failure: None,
            additional_failures: Vec::new(),
            attributions: Vec::new(),
            detail: "Smoke test exceeded its time budget".to_string(),
            log_excerpt: excerpt(&raw.log, None, excerpt_max),
        };
    }
    if raw.exited_ok {
        let perf = classify_log_all(&raw.log)
            .into_iter()
            .find(|c| *c == FailureCategory::PerformanceRegression);
        if let Some(category) = perf {
            let attributions = extract_attributions(&raw.log);
            return SmokeResult {
                environment: raw.environment.clone(),
                status: SmokeStatus::Degraded,
                failure: Some(category),
                additional_failures: Vec::new(),
                attributions,
                detail: category.title().to_string(),
                log_excerpt: excerpt(&raw.log, Some(category), excerpt_max),
            };
        }
        return SmokeResult {
            environment: raw.environment.clone(),
            status: SmokeStatus::Pass,
            failure: None,
            additional_failures: Vec::new(),
            attributions: Vec::new(),
            detail: "Clean startup".to_string(),
            log_excerpt: None,
        };
    }
    // Collect every independent failure; the first (highest-priority) is the
    // dominant one that drives the verdict, the rest are surfaced as context.
    let mut all = classify_log_all(&raw.log);
    let category = if all.is_empty() {
        FailureCategory::Unknown
    } else {
        all.remove(0)
    };
    let additional_failures = all;
    let status = match category {
        FailureCategory::OutOfMemory
        | FailureCategory::StackOverflow
        | FailureCategory::JvmCrash => SmokeStatus::Crash,
        _ => SmokeStatus::Fail,
    };
    let detail = if additional_failures.is_empty() {
        category.title().to_string()
    } else {
        format!(
            "{} (+{} other failure(s))",
            category.title(),
            additional_failures.len()
        )
    };
    let attributions = extract_attributions(&raw.log);
    SmokeResult {
        environment: raw.environment.clone(),
        status,
        failure: Some(category),
        additional_failures,
        attributions,
        detail,
        log_excerpt: excerpt(&raw.log, Some(category), excerpt_max),
    }
}

/// Pick a short, relevant excerpt: the first line matching the failure pattern
/// (so the user sees the smoking gun), else the last non-empty line.
fn excerpt(log: &str, category: Option<FailureCategory>, excerpt_max: usize) -> Option<String> {
    if log.trim().is_empty() {
        return None;
    }
    let pick = category
        .and_then(|cat| {
            log.lines()
                .find(|line| classify_log(line) == Some(cat))
                .map(str::to_string)
        })
        .or_else(|| {
            log.lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .map(str::to_string)
        })?;
    let pick = pick.trim();
    Some(if pick.len() > excerpt_max {
        format!("{}…", &pick[..floor_char_boundary(pick, excerpt_max)])
    } else {
        pick.to_string()
    })
}

/// Largest index `<= max` that lies on a UTF-8 char boundary of `s`.
///
/// `str::floor_char_boundary` is still unstable, so we reimplement it: slicing a
/// `str` at a byte index that falls inside a multi-byte codepoint panics, and
/// real Minecraft logs routinely carry non-ASCII (mod names, player nicks,
/// localized errors, emoji). Truncating to a fixed *byte* budget must therefore
/// snap down to a boundary or `lab run` panics on the first such log.
fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// `lab run`: classify captured smoke outputs against a corpus lock and write the
/// resulting [`LabRun`] to `out_dir/lab-run.json`.
pub fn run_lab(lock_path: &Path, logs_dir: &Path, out_dir: &Path) -> Result<LabRun, LabError> {
    run_lab_with(lock_path, logs_dir, out_dir, LabRunOptions::default())
}

/// Like [`run_lab`] with explicit classification options.
pub fn run_lab_with(
    lock_path: &Path,
    logs_dir: &Path,
    out_dir: &Path,
    options: LabRunOptions,
) -> Result<LabRun, LabError> {
    let lock = read_lock(lock_path)?;
    let runner = CapturedLogRunner { dir: logs_dir };
    run_with(&lock, &runner, out_dir, options)
}

/// `lab run` core, parameterised over the [`SmokeRunner`] for testability and to
/// allow a future live runner.
pub fn run_with(
    lock: &CorpusLock,
    runner: &dyn SmokeRunner,
    out_dir: &Path,
    options: LabRunOptions,
) -> Result<LabRun, LabError> {
    let raws = runner.run(lock)?;
    // Classification is pure per-output; fan out, then sort for determinism.
    let mut results: Vec<SmokeResult> = raws
        .par_iter()
        .map(|raw| classify_with_options(raw, options))
        .collect();
    results.sort_by(|a, b| a.environment.cmp(&b.environment));

    let run = LabRun {
        schema: LAB_RUN_SCHEMA.to_string(),
        corpus_digest: lock.digest.clone(),
        environment: lock.environment.clone(),
        results,
    };
    std::fs::create_dir_all(out_dir)
        .map_err(|e| LabError::new(format!("create {}: {e}", out_dir.display())))?;
    write_json_atomic(&out_dir.join("lab-run.json"), &run)?;
    Ok(run)
}

/// Load and validate a previously written lab run.
pub fn read_run(path: &Path) -> Result<LabRun, LabError> {
    let run: LabRun = read_json(path)?;
    if run.schema != LAB_RUN_SCHEMA {
        return Err(LabError::schema(path, LAB_RUN_SCHEMA, &run.schema));
    }
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(env: &str, ok: bool, log: &str) -> RawSmokeOutput {
        RawSmokeOutput {
            schema: SMOKE_OUTPUT_SCHEMA.into(),
            environment: env.into(),
            exited_ok: ok,
            timed_out: false,
            log: log.into(),
        }
    }

    #[test]
    fn clean_exit_with_mspt_is_degraded() {
        let r = classify(&raw(
            "fabric-server",
            true,
            "[Server thread/WARN]: Can't keep up! Running 120ms behind",
        ));
        assert_eq!(r.status, SmokeStatus::Degraded);
        assert_eq!(r.failure, Some(FailureCategory::PerformanceRegression));
    }

    #[test]
    fn clean_exit_is_pass() {
        let r = classify(&raw("fabric-server", true, "Done (2.1s)!"));
        assert_eq!(r.status, SmokeStatus::Pass);
        assert!(r.failure.is_none());
    }

    #[test]
    fn oom_is_crash_with_category() {
        let r = classify(&raw("fabric-server", false, "java.lang.OutOfMemoryError"));
        assert_eq!(r.status, SmokeStatus::Crash);
        assert_eq!(r.failure, Some(FailureCategory::OutOfMemory));
        assert!(r.log_excerpt.unwrap().contains("OutOfMemoryError"));
    }

    #[test]
    fn missing_dep_is_fail() {
        let r = classify(&raw(
            "fabric-server",
            false,
            "Mod create requires fabric-api which is missing",
        ));
        assert_eq!(r.status, SmokeStatus::Fail);
        assert_eq!(r.failure, Some(FailureCategory::MissingDependency));
    }

    #[test]
    fn timeout_takes_precedence() {
        let mut r = raw("fabric-server", false, "OutOfMemoryError");
        r.timed_out = true;
        assert_eq!(classify(&r).status, SmokeStatus::Timeout);
    }

    #[test]
    fn excerpt_max_is_configurable() {
        let line = "x".repeat(100);
        let raw = raw("fabric-server", false, &line);
        let short = classify_with_options(&raw, LabRunOptions { excerpt_max: 20 });
        let ex = short.log_excerpt.expect("excerpt present");
        assert!(ex.ends_with('…'));
        assert!(ex.len() <= 20 + '…'.len_utf8());
    }

    #[test]
    fn excerpt_does_not_panic_on_multibyte_boundary() {
        // A line whose byte length exceeds the excerpt cap and where the cut point
        // lands inside a multi-byte codepoint (mojibake-free German + emoji,
        // exactly the shape of a real localized crash log).
        let line = format!(
            "Schwerwiegender Fehler beim Laden des Mods „Café“ 🛑 {}",
            "ä".repeat(200)
        );
        let r = classify(&raw("forge-server", false, &line));
        let ex = r.log_excerpt.expect("excerpt present");
        // Must be valid UTF-8 (it is, by construction — the point is no panic)
        // and capped at the boundary, plus the ellipsis.
        assert!(ex.ends_with('…'));
        assert!(ex.len() <= DEFAULT_EXCERPT_MAX + '…'.len_utf8());
    }

    #[test]
    fn unclassified_failure_is_unknown() {
        let r = classify(&raw("fabric-server", false, "weird exit"));
        assert_eq!(r.failure, Some(FailureCategory::Unknown));
        assert_eq!(r.status, SmokeStatus::Fail);
    }
}
