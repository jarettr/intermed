//! Compatibility matrix aggregation and report rendering (JSON + static HTML).
//!
//! `lab report` reads a classified [`LabRun`] and emits a
//! [`CompatibilityMatrix`] plus a self-contained HTML page — the lab's public
//! artifact (the rewritten `CompatibilityMatrix` / `HtmlReportWriter` donors).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::classify::FailureCategory;
use crate::corpus::CorpusEnvironment;
use crate::run::{read_run, LabRun, SmokeStatus};
use crate::{write_atomic, write_json_atomic, LabError};

/// Schema tag for the compatibility matrix.
pub const COMPAT_MATRIX_SCHEMA: &str = "intermed-compatibility-matrix-v1";

/// One environment's cell in the matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixCell {
    pub environment: String,
    pub status: SmokeStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureCategory>,
    /// Independent failures beyond the dominant one (see
    /// [`SmokeResult::additional_failures`](crate::run::SmokeResult::additional_failures)).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_failures: Vec<FailureCategory>,
    pub detail: String,
}

/// Aggregated compatibility evidence for one corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrix {
    pub schema: String,
    pub corpus_digest: String,
    pub environment: CorpusEnvironment,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    /// Clean exit but performance regression detected.
    #[serde(default)]
    pub degraded: usize,
    pub crashed: usize,
    pub timed_out: usize,
    /// Failure-category histogram over *every* independent failure detected
    /// (dominant + additional), not just the per-environment verdict — so a log
    /// with a mixin error and a missing dependency increments both. Stable order.
    pub by_category: BTreeMap<String, usize>,
    /// The same failures rolled up into [`FailureFamily`] buckets.
    #[serde(default)]
    pub by_family: BTreeMap<String, usize>,
    pub cells: Vec<MatrixCell>,
}

impl CompatibilityMatrix {
    /// Aggregate a classified run into a matrix.
    #[must_use]
    pub fn from_run(run: &LabRun) -> Self {
        let mut passed = 0;
        let mut failed = 0;
        let mut degraded = 0;
        let mut crashed = 0;
        let mut timed_out = 0;
        let mut by_category: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_family: BTreeMap<String, usize> = BTreeMap::new();
        let mut cells = Vec::with_capacity(run.results.len());

        for r in &run.results {
            match r.status {
                SmokeStatus::Pass => passed += 1,
                SmokeStatus::Degraded => degraded += 1,
                SmokeStatus::Fail => failed += 1,
                SmokeStatus::Crash => crashed += 1,
                SmokeStatus::Timeout => timed_out += 1,
            }
            // Count every independent failure, not only the verdict, so secondary
            // failures are visible in the aggregate histograms.
            for cat in r
                .failure
                .into_iter()
                .chain(r.additional_failures.iter().copied())
            {
                *by_category.entry(cat.as_str().to_string()).or_default() += 1;
                *by_family
                    .entry(cat.family().as_str().to_string())
                    .or_default() += 1;
            }
            cells.push(MatrixCell {
                environment: r.environment.clone(),
                status: r.status,
                failure: r.failure,
                additional_failures: r.additional_failures.clone(),
                detail: r.detail.clone(),
            });
        }
        // Cells inherit the run's deterministic (env-sorted) order.

        CompatibilityMatrix {
            schema: COMPAT_MATRIX_SCHEMA.to_string(),
            corpus_digest: run.corpus_digest.clone(),
            environment: run.environment.clone(),
            total: run.results.len(),
            passed,
            failed,
            degraded,
            crashed,
            timed_out,
            by_category,
            by_family,
            cells,
        }
    }

    /// Fraction of environments that passed, in `0.0..=1.0`.
    #[must_use]
    pub fn pass_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.passed as f64 / self.total as f64
        }
    }
}

/// Paths written by [`write_report`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportArtifacts {
    pub matrix_json: String,
    pub html: String,
}

/// `lab report`: read a run, build the matrix, and write `matrix.json` +
/// `index.html` into `out_dir`.
pub fn write_report(run_path: &Path, out_dir: &Path) -> Result<CompatibilityMatrix, LabError> {
    let run = read_run(run_path)?;
    let matrix = CompatibilityMatrix::from_run(&run);
    std::fs::create_dir_all(out_dir)
        .map_err(|e| LabError::new(format!("create {}: {e}", out_dir.display())))?;

    let matrix_path = out_dir.join("matrix.json");
    write_json_atomic(&matrix_path, &matrix)?;

    let html_path = out_dir.join("index.html");
    write_atomic(&html_path, render_html(&matrix).as_bytes())
        .map_err(|e| LabError::new(format!("write {}: {e}", html_path.display())))?;

    Ok(matrix)
}

/// Artifact paths for a given output directory (without writing).
pub fn artifact_paths(out_dir: &Path) -> ReportArtifacts {
    ReportArtifacts {
        matrix_json: out_dir.join("matrix.json").display().to_string(),
        html: out_dir.join("index.html").display().to_string(),
    }
}

/// Render a self-contained static HTML page for the matrix.
#[must_use]
pub fn render_html(matrix: &CompatibilityMatrix) -> String {
    let env = &matrix.environment;
    let mut rows = String::new();
    for cell in &matrix.cells {
        // Show the dominant failure, then any independent secondary failures.
        let failure = match cell.failure {
            None => "-".to_string(),
            Some(primary) => {
                let mut s = primary.as_str().to_string();
                for extra in &cell.additional_failures {
                    s.push_str(", ");
                    s.push_str(extra.as_str());
                }
                s
            }
        };
        rows.push_str(&format!(
            "      <tr class=\"{status}\"><td>{env}</td><td>{status}</td><td>{failure}</td><td>{detail}</td></tr>\n",
            env = escape(&cell.environment),
            status = cell.status.as_str(),
            failure = escape(&failure),
            detail = escape(&cell.detail),
        ));
    }

    let categories = render_histogram(&matrix.by_category);
    let families = render_histogram(&matrix.by_family);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>InterMed Compatibility Matrix</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
  th {{ background: #f0f0f0; }}
  tr.pass td {{ background: #e8f5e9; }}
  tr.fail td {{ background: #fff3e0; }}
  tr.crash td {{ background: #ffebee; }}
  tr.timeout td {{ background: #ede7f6; }}
  .summary span {{ display: inline-block; margin-right: 1.2rem; }}
</style>
</head>
<body>
  <h1>InterMed Compatibility Matrix</h1>
  <p>Environment: <strong>{loader} {mc} ({side})</strong></p>
  <p>Corpus digest: <code>{digest}</code></p>
  <p class="summary">
    <span>Total: {total}</span>
    <span>Passed: {passed}</span>
    <span>Failed: {failed}</span>
    <span>Crashed: {crashed}</span>
    <span>Timed out: {timed_out}</span>
    <span>Pass rate: {rate:.0}%</span>
  </p>
  <h2>Failures by family</h2>
  <ul>
{families}  </ul>
  <h2>Failures by category</h2>
  <ul>
{categories}  </ul>
  <h2>Per-environment results</h2>
  <table>
    <thead><tr><th>Environment</th><th>Status</th><th>Failure</th><th>Detail</th></tr></thead>
    <tbody>
{rows}    </tbody>
  </table>
</body>
</html>
"#,
        loader = escape(&env.loader),
        mc = escape(&env.mc_version),
        side = escape(&env.side),
        digest = escape(&matrix.corpus_digest),
        total = matrix.total,
        passed = matrix.passed,
        failed = matrix.failed,
        crashed = matrix.crashed,
        timed_out = matrix.timed_out,
        rate = matrix.pass_rate() * 100.0,
        families = families,
        categories = categories,
        rows = rows,
    )
}

/// Render a `name: count` histogram as escaped `<li>` items, or a single "none"
/// item when empty.
fn render_histogram(hist: &BTreeMap<String, usize>) -> String {
    if hist.is_empty() {
        return "      <li>none</li>\n".to_string();
    }
    let mut out = String::new();
    for (name, count) in hist {
        out.push_str(&format!("      <li>{}: {}</li>\n", escape(name), count));
    }
    out
}

/// Minimal HTML text escaping for untrusted values placed in element content.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::{SmokeResult, LAB_RUN_SCHEMA};

    fn run() -> LabRun {
        LabRun {
            schema: LAB_RUN_SCHEMA.into(),
            corpus_digest: "deadbeef".into(),
            environment: CorpusEnvironment {
                loader: "fabric".into(),
                mc_version: "1.20.1".into(),
                side: "server".into(),
            },
            results: vec![
                SmokeResult {
                    environment: "a".into(),
                    status: SmokeStatus::Pass,
                    failure: None,
                    additional_failures: Vec::new(),
                    attributions: Vec::new(),
                    detail: "Clean startup".into(),
                    log_excerpt: None,
                },
                SmokeResult {
                    environment: "b".into(),
                    status: SmokeStatus::Crash,
                    failure: Some(FailureCategory::OutOfMemory),
                    additional_failures: Vec::new(),
                    attributions: Vec::new(),
                    detail: "Out of memory".into(),
                    log_excerpt: Some("OutOfMemoryError".into()),
                },
            ],
        }
    }

    #[test]
    fn matrix_counts_and_categories() {
        let m = CompatibilityMatrix::from_run(&run());
        assert_eq!(m.total, 2);
        assert_eq!(m.passed, 1);
        assert_eq!(m.crashed, 1);
        assert_eq!(m.by_category.get("out-of-memory"), Some(&1));
        assert!((m.pass_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn multi_failure_counts_all_categories_and_families() {
        let mut r = run();
        r.results.push(SmokeResult {
            environment: "c".into(),
            status: SmokeStatus::Fail,
            failure: Some(FailureCategory::MixinApplyError),
            additional_failures: vec![FailureCategory::MissingDependency],
            attributions: Vec::new(),
            detail: "Mixin failed to apply (+1 other failure(s))".into(),
            log_excerpt: None,
        });
        let m = CompatibilityMatrix::from_run(&r);
        // Both the dominant and the secondary failure are counted.
        assert_eq!(m.by_category.get("mixin-apply-error"), Some(&1));
        assert_eq!(m.by_category.get("missing-dependency"), Some(&1));
        assert_eq!(m.by_category.get("out-of-memory"), Some(&1));
        // Mixin + missing-dep both roll up into mod-integration (2), OOM into
        // resource-exhaustion (1).
        assert_eq!(m.by_family.get("mod-integration"), Some(&2));
        assert_eq!(m.by_family.get("resource-exhaustion"), Some(&1));
        // The cell preserves the secondary failure for the HTML row.
        let cell = m.cells.iter().find(|c| c.environment == "c").unwrap();
        assert_eq!(
            cell.additional_failures,
            vec![FailureCategory::MissingDependency]
        );
    }

    #[test]
    fn html_renders_family_section_and_secondary_failures() {
        let mut r = run();
        r.results.push(SmokeResult {
            environment: "c".into(),
            status: SmokeStatus::Fail,
            failure: Some(FailureCategory::MixinApplyError),
            additional_failures: vec![FailureCategory::MissingDependency],
            attributions: Vec::new(),
            detail: "Mixin failed to apply (+1 other failure(s))".into(),
            log_excerpt: None,
        });
        let html = render_html(&CompatibilityMatrix::from_run(&r));
        assert!(html.contains("Failures by family"));
        assert!(html.contains("mod-integration: 2"));
        // The secondary failure appears in the row's failure cell.
        assert!(html.contains("mixin-apply-error, missing-dependency"));
    }

    #[test]
    fn html_is_escaped_and_self_contained() {
        let mut r = run();
        r.results[0].environment = "<script>alert(1)</script>".into();
        let m = CompatibilityMatrix::from_run(&r);
        let html = render_html(&m);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("Pass rate: 50%"));
    }
}
