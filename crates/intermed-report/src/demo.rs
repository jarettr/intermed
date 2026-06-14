//! Presentation demo report generator for launcher-facing evidence bundles.
//!
//! Reads the output directory produced by [`scripts/intermed-demo-run.sh`]
//! (doctor text/JSON, profiles, SBOM) and emits three public artifacts:
//! `intermed-atlauncher-demo-summary.md`, `intermed-demo-report.html`, and
//! `intermed-demo-report-v1` JSON. The generator never re-runs diagnosis — it
//! only aggregates already-materialized run outputs.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema tag for the machine-readable presentation bundle.
pub const DEMO_REPORT_SCHEMA: &str = "intermed-demo-report-v1";

/// Default markdown filename for ATLauncher-facing summaries.
pub const DEMO_SUMMARY_MD: &str = "intermed-atlauncher-demo-summary.md";

/// Default self-contained HTML dashboard filename.
pub const DEMO_REPORT_HTML: &str = "intermed-demo-report.html";

/// Default JSON bundle filename.
pub const DEMO_REPORT_JSON: &str = "intermed-demo-report.json";

/// Errors while reading or rendering a presentation run directory.
#[derive(Debug, Error)]
pub enum DemoReportError {
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid demo corpus manifest: {detail}")]
    InvalidManifest { detail: String },
    #[error("no presentation scenarios produced doctor output in {run_dir}")]
    EmptyRun { run_dir: PathBuf },
    #[error("doctor summary missing for scenario {scenario}")]
    MissingSummary { scenario: String },
    #[error("json parse failed for {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

/// Paths written by [`write_demo_artifacts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoArtifacts {
    pub summary_md: PathBuf,
    pub report_html: PathBuf,
    pub report_json: PathBuf,
}

/// Severity histogram extracted from a doctor terminal summary line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub fatal: u32,
    pub error: u32,
    pub warn: u32,
    pub note: u32,
    pub info: u32,
    pub facts: u32,
}

/// One curated scenario from `demo/corpus.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoScenario {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub role: String,
    pub loader: String,
    pub mc_version: String,
    pub jar_count: u32,
    pub narrative: String,
}

/// Parsed `intermed-demo-corpus-v1` manifest bundled with the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoCorpus {
    pub schema: String,
    pub audience: String,
    pub title: String,
    pub description: String,
    pub root: String,
    pub scenarios: Vec<DemoScenario>,
}

/// Aggregated outcome for one scenario after reading doctor output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub scenario: DemoScenario,
    pub verdict: String,
    pub counts: SeverityCounts,
    pub headline_findings: Vec<HeadlineFinding>,
    pub profile_ms: Option<u64>,
}

/// Compact finding row for dashboards (id + severity + title).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadlineFinding {
    pub id: String,
    pub severity: String,
    pub title: String,
}

/// Machine-readable presentation bundle (`intermed-demo-report-v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoReport {
    pub schema: String,
    pub audience: String,
    pub title: String,
    pub generated_at: DateTime<Utc>,
    pub tool_version: String,
    pub run_dir: String,
    pub corpus: DemoCorpus,
    pub scenarios: Vec<ScenarioResult>,
    pub totals: DemoTotals,
    pub capabilities: Vec<String>,
    pub hero: Option<HeroArtifacts>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoTotals {
    pub scenario_count: u32,
    pub jar_count: u32,
    pub error_scenarios: u32,
    pub warning_scenarios: u32,
    pub healthy_scenarios: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeroArtifacts {
    pub scenario_id: String,
    pub html: Option<String>,
    pub profile_ms: Option<u64>,
    pub sbom_components: Option<u32>,
    pub mixin_targets: Option<u32>,
}

/// Build the presentation bundle from a completed demo run directory.
pub fn build_demo_report(run_dir: &Path, tool_version: &str) -> Result<DemoReport, DemoReportError> {
    let corpus_path = run_dir.join("corpus.json");
    let corpus_text = fs::read_to_string(&corpus_path).map_err(|source| DemoReportError::Read {
        path: corpus_path.clone(),
        source,
    })?;
    let corpus: DemoCorpus =
        serde_json::from_str(&corpus_text).map_err(|source| DemoReportError::Json {
            path: corpus_path,
            source,
        })?;
    if corpus.schema != "intermed-demo-corpus-v1" {
        return Err(DemoReportError::InvalidManifest {
            detail: format!("expected intermed-demo-corpus-v1, got {}", corpus.schema),
        });
    }

    let mut scenarios = Vec::new();
    for spec in &corpus.scenarios {
        let doctor_path = run_dir.join(format!("doctor-{}.txt", spec.id));
        if !doctor_path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&doctor_path).map_err(|source| DemoReportError::Read {
            path: doctor_path.clone(),
            source,
        })?;
        let (verdict, counts) = parse_doctor_summary(&text).ok_or_else(|| {
            DemoReportError::MissingSummary {
                scenario: spec.id.clone(),
            }
        })?;
        let json_path = run_dir.join(format!("doctor-{}-json.json", spec.id));
        let headline_findings = if json_path.is_file() {
            read_headline_findings(&json_path)?
        } else {
            read_headline_findings_from_text(&text)
        };
        let profile_ms = read_profile_ms(run_dir, &spec.id);
        scenarios.push(ScenarioResult {
            scenario: spec.clone(),
            verdict,
            counts,
            headline_findings,
            profile_ms,
        });
    }

    if scenarios.is_empty() {
        return Err(DemoReportError::EmptyRun {
            run_dir: run_dir.to_path_buf(),
        });
    }

    let totals = compute_totals(&scenarios);
    let hero = build_hero(run_dir, "fabric_clean");
    Ok(DemoReport {
        schema: DEMO_REPORT_SCHEMA.to_string(),
        audience: corpus.audience.clone(),
        title: corpus.title.clone(),
        generated_at: Utc::now(),
        tool_version: tool_version.to_string(),
        run_dir: run_dir.display().to_string(),
        corpus,
        scenarios,
        totals,
        capabilities: default_capabilities(),
        hero,
    })
}

/// Render markdown, HTML, and JSON artifacts into `out_dir`.
pub fn write_demo_artifacts(
    run_dir: &Path,
    out_dir: &Path,
    tool_version: &str,
) -> Result<(DemoReport, DemoArtifacts), DemoReportError> {
    let report = build_demo_report(run_dir, tool_version)?;
    fs::create_dir_all(out_dir).map_err(|source| DemoReportError::Write {
        path: out_dir.to_path_buf(),
        source,
    })?;

    let summary_md = out_dir.join(DEMO_SUMMARY_MD);
    let report_html = out_dir.join(DEMO_REPORT_HTML);
    let report_json = out_dir.join(DEMO_REPORT_JSON);

    fs::write(&summary_md, render_markdown(&report)).map_err(|source| DemoReportError::Write {
        path: summary_md.clone(),
        source,
    })?;
    fs::write(&report_html, render_html(&report)).map_err(|source| DemoReportError::Write {
        path: report_html.clone(),
        source,
    })?;
    let json = serde_json::to_string_pretty(&report).map_err(|source| DemoReportError::Json {
        path: report_json.clone(),
        source,
    })?;
    fs::write(&report_json, json).map_err(|source| DemoReportError::Write {
        path: report_json.clone(),
        source,
    })?;

    Ok((
        report,
        DemoArtifacts {
            summary_md,
            report_html,
            report_json,
        },
    ))
}

/// Render the ATLauncher-facing markdown summary.
#[must_use]
pub fn render_markdown(report: &DemoReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# InterMed × ATLauncher — presentation evidence run\n"
    );
    let _ = writeln!(
        out,
        "> Real Modrinth mods · {} scenarios · {} jars · generated {}\n",
        report.totals.scenario_count,
        report.totals.jar_count,
        report.generated_at.format("%Y-%m-%d %H:%M UTC")
    );
    let _ = writeln!(out, "{}\n", report.corpus.description);
    let _ = writeln!(out, "## Why this matters for launchers\n");
    let _ = writeln!(
        out,
        "ATLauncher ships instances before anyone presses Play. InterMed turns that mods folder into a **fact graph → findings → report** pipeline with full provenance — the same engine validated on larger internal corpora, here scoped to a **small, readable** set of real jars.\n"
    );
    let _ = writeln!(out, "## Scenario matrix\n");
    let _ = writeln!(
        out,
        "| Scenario | Role | Loader | Mods | Verdict | Errors | Warnings | Headline |"
    );
    let _ = writeln!(out, "|---|---|---|---:|---|---:|---:|---|");
    for row in &report.scenarios {
        let headline = row
            .headline_findings
            .first()
            .map(|f| f.title.as_str())
            .unwrap_or("—");
        let _ = writeln!(
            out,
            "| **{}** | {} | {} | {} | {} | {} | {} | {} |",
            row.scenario.title,
            row.scenario.role,
            row.scenario.loader,
            row.scenario.jar_count,
            row.verdict,
            row.counts.error,
            row.counts.warn,
            headline
        );
    }
    let _ = writeln!(out, "\n## Narrative walkthrough\n");
    for row in &report.scenarios {
        let _ = writeln!(out, "### {} — {}\n", row.scenario.title, row.scenario.subtitle);
        let _ = writeln!(out, "{}\n", row.scenario.narrative);
        let _ = writeln!(
            out,
            "- **Verdict:** {} ({} errors, {} warnings, {} facts)",
            row.verdict, row.counts.error, row.counts.warn, row.counts.facts
        );
        if !row.headline_findings.is_empty() {
            let _ = writeln!(out, "- **Headline findings:**");
            for f in &row.headline_findings {
                let _ = writeln!(out, "  - `{}` — **{}**: {}", f.severity, f.id, f.title);
            }
        }
        if let Some(ms) = row.profile_ms {
            let _ = writeln!(out, "- **Scan time:** {ms} ms");
        }
        let _ = writeln!(out);
    }
    if let Some(hero) = &report.hero {
        let _ = writeln!(out, "## Hero pack deep dive (`{}`)\n", hero.scenario_id);
        if let Some(ms) = hero.profile_ms {
            let _ = writeln!(out, "- Full diagnosis completed in **{ms} ms** on 7 real jars.");
        }
        if let Some(n) = hero.mixin_targets {
            let _ = writeln!(out, "- Mixin map enumerated **{n}** static targets.");
        }
        if let Some(n) = hero.sbom_components {
            let _ = writeln!(out, "- SPDX SBOM exported **{n}** components.");
        }
        if hero.html.is_some() {
            let _ = writeln!(
                out,
                "- Interactive HTML report: open `fabric_clean.html` from the run directory or the bundled dashboard."
            );
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(out, "## Capabilities exercised\n");
    for cap in &report.capabilities {
        let _ = writeln!(out, "- {cap}");
    }
    let _ = writeln!(
        out,
        "\n---\n*Run directory:* `{}`  \n*Tool:* {}  \n*Schema:* `{}`\n",
        report.run_dir, report.tool_version, report.schema
    );
    out
}

/// Render a self-contained HTML dashboard (inline CSS, no network).
#[must_use]
pub fn render_html(report: &DemoReport) -> String {
    let mut cards = String::new();
    for row in &report.scenarios {
        let sev = if row.counts.error > 0 {
            "error"
        } else if row.counts.warn > 0 {
            "warn"
        } else {
            "ok"
        };
        let headline = row
            .headline_findings
            .first()
            .map(|f| format!("{} — {}", f.severity, escape_html(&f.title)))
            .unwrap_or_else(|| "No blocking findings".to_string());
        cards.push_str(&format!(
            r#"<article class="card sev-{sev}">
  <header>
    <span class="role">{role}</span>
    <h3>{title}</h3>
    <p class="subtitle">{subtitle}</p>
  </header>
  <dl>
    <div><dt>Loader</dt><dd>{loader} · MC {mc}</dd></div>
    <div><dt>Mods</dt><dd>{jars}</dd></div>
    <div><dt>Verdict</dt><dd>{verdict}</dd></div>
    <div><dt>Findings</dt><dd>{errors} err · {warns} warn · {facts} facts</dd></div>
  </dl>
  <p class="headline">{headline}</p>
  <p class="narrative">{narrative}</p>
</article>
"#,
            role = escape_html(&row.scenario.role),
            title = escape_html(&row.scenario.title),
            subtitle = escape_html(&row.scenario.subtitle),
            loader = escape_html(&row.scenario.loader),
            mc = escape_html(&row.scenario.mc_version),
            jars = row.scenario.jar_count,
            verdict = escape_html(&row.verdict),
            errors = row.counts.error,
            warns = row.counts.warn,
            facts = row.counts.facts,
            headline = escape_html(&headline),
            narrative = escape_html(&row.scenario.narrative),
            sev = sev,
        ));
    }

    let caps: String = report
        .capabilities
        .iter()
        .map(|c| format!("<li>{}</li>", escape_html(c)))
        .collect();

    let hero_block = report.hero.as_ref().map(|h| {
        format!(
            r#"<section class="hero">
  <h2>Hero pack: {id}</h2>
  <ul>
    <li>Scan time: <strong>{ms} ms</strong></li>
    <li>Mixin targets: <strong>{mix}</strong></li>
    <li>SBOM components: <strong>{sbom}</strong></li>
    <li>Interactive HTML: <strong>{html}</strong></li>
  </ul>
</section>"#,
            id = escape_html(&h.scenario_id),
            ms = h
                .profile_ms
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into()),
            mix = h
                .mixin_targets
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into()),
            sbom = h
                .sbom_components
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into()),
            html = if h.html.is_some() { "yes" } else { "—" },
        )
    }).unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>InterMed presentation report — {audience}</title>
<style>
  :root {{
    --bg: #0f1419;
    --panel: #1a2332;
    --text: #e7ecf3;
    --muted: #8b9cb3;
    --ok: #3dd68c;
    --warn: #f5a524;
    --error: #ff6b6b;
    --accent: #5b9cf5;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: "Segoe UI", system-ui, sans-serif;
    background: linear-gradient(160deg, #0b1020 0%, #121a2b 45%, #0f1419 100%);
    color: var(--text);
    line-height: 1.5;
  }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 3rem; }}
  header.page {{ margin-bottom: 2rem; }}
  header.page h1 {{ margin: 0 0 .35rem; font-size: 1.85rem; }}
  header.page p {{ margin: .25rem 0; color: var(--muted); }}
  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: .75rem;
    margin: 1.25rem 0 2rem;
  }}
  .stat {{
    background: var(--panel);
    border: 1px solid #2a3a52;
    border-radius: 10px;
    padding: .9rem 1rem;
  }}
  .stat .num {{ font-size: 1.6rem; font-weight: 700; color: var(--accent); }}
  .stat .lbl {{ font-size: .8rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1rem;
  }}
  .card {{
    background: var(--panel);
    border: 1px solid #2a3a52;
    border-radius: 12px;
    padding: 1rem 1.1rem 1.15rem;
    border-left: 4px solid var(--accent);
  }}
  .card.sev-ok {{ border-left-color: var(--ok); }}
  .card.sev-warn {{ border-left-color: var(--warn); }}
  .card.sev-error {{ border-left-color: var(--error); }}
  .card h3 {{ margin: .15rem 0 .2rem; font-size: 1.1rem; }}
  .card .subtitle {{ margin: 0; color: var(--muted); font-size: .9rem; }}
  .card .role {{
    display: inline-block;
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: .06em;
    color: var(--accent);
    margin-bottom: .35rem;
  }}
  .card dl {{ display: grid; gap: .35rem; margin: .85rem 0; font-size: .88rem; }}
  .card dl div {{ display: flex; justify-content: space-between; gap: .5rem; }}
  .card dt {{ color: var(--muted); margin: 0; }}
  .card dd {{ margin: 0; text-align: right; }}
  .headline {{ font-size: .9rem; margin: .5rem 0; }}
  .narrative {{ font-size: .85rem; color: var(--muted); margin: 0; }}
  section.capabilities, section.hero {{
    margin-top: 2rem;
    background: var(--panel);
    border: 1px solid #2a3a52;
    border-radius: 12px;
    padding: 1rem 1.25rem;
  }}
  section.capabilities ul, section.hero ul {{ margin: .5rem 0 0; padding-left: 1.2rem; }}
  footer {{ margin-top: 2.5rem; color: var(--muted); font-size: .8rem; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="page">
    <h1>InterMed presentation evidence</h1>
    <p>Audience: <strong>{audience}</strong> · {title}</p>
    <p>{description}</p>
    <p>Generated {generated} · {tool}</p>
  </header>
  <div class="stats">
    <div class="stat"><div class="num">{scenarios}</div><div class="lbl">Scenarios</div></div>
    <div class="stat"><div class="num">{jars}</div><div class="lbl">Real mod jars</div></div>
    <div class="stat"><div class="num">{healthy}</div><div class="lbl">Healthy baselines</div></div>
    <div class="stat"><div class="num">{errors}</div><div class="lbl">Error scenarios</div></div>
  </div>
  <div class="grid">
{cards}  </div>
  {hero}
  <section class="capabilities">
    <h2>Capabilities demonstrated</h2>
    <ul>{caps}</ul>
  </section>
  <footer>
    Run directory: <code>{run_dir}</code> · Schema: <code>{schema}</code>
  </footer>
</div>
</body>
</html>
"#,
        audience = escape_html(&report.audience),
        title = escape_html(&report.title),
        description = escape_html(&report.corpus.description),
        generated = escape_html(&report.generated_at.to_rfc3339()),
        tool = escape_html(&report.tool_version),
        scenarios = report.totals.scenario_count,
        jars = report.totals.jar_count,
        healthy = report.totals.healthy_scenarios,
        errors = report.totals.error_scenarios,
        cards = cards,
        hero = hero_block,
        caps = caps,
        run_dir = escape_html(&report.run_dir),
        schema = escape_html(&report.schema),
    )
}

fn default_capabilities() -> Vec<String> {
    vec![
        "Layer A/B metadata scan on real Fabric, Forge, and mixed-loader jars".into(),
        "Layer C dependency resolution (missing-dependency, duplicate-id, mixed-loader-pack)".into(),
        "Layer F mixin-risk intelligence (handler effects, overlaps, overwrite detection)".into(),
        "Layer G/H security notes and SPDX SBOM export".into(),
        "Terminal, JSON (`intermed-doctor-report-v1`), SARIF, and self-contained HTML outputs".into(),
        "deps graph, mixin-map, and profile timings on the hero pack".into(),
    ]
}

fn compute_totals(scenarios: &[ScenarioResult]) -> DemoTotals {
    let mut jar_count = 0u32;
    let mut error_scenarios = 0u32;
    let mut warning_scenarios = 0u32;
    let mut healthy_scenarios = 0u32;
    for row in scenarios {
        jar_count = jar_count.saturating_add(row.scenario.jar_count);
        if row.counts.error > 0 {
            error_scenarios += 1;
        } else if row.counts.warn > 0 {
            warning_scenarios += 1;
        } else {
            healthy_scenarios += 1;
        }
    }
    DemoTotals {
        scenario_count: scenarios.len() as u32,
        jar_count,
        error_scenarios,
        warning_scenarios,
        healthy_scenarios,
    }
}

fn build_hero(run_dir: &Path, scenario_id: &str) -> Option<HeroArtifacts> {
    let html_path = run_dir.join(format!("{scenario_id}.html"));
    let html = html_path.is_file().then(|| html_path.display().to_string());
    let profile_ms = read_profile_ms(run_dir, scenario_id);
    let sbom_components = read_sbom_component_count(run_dir, scenario_id);
    let mixin_targets = read_mixin_target_count(run_dir, scenario_id);
    if html.is_none() && profile_ms.is_none() && sbom_components.is_none() && mixin_targets.is_none()
    {
        return None;
    }
    Some(HeroArtifacts {
        scenario_id: scenario_id.to_string(),
        html,
        profile_ms,
        sbom_components,
        mixin_targets,
    })
}

fn read_profile_ms(run_dir: &Path, scenario_id: &str) -> Option<u64> {
    let path = run_dir.join(format!("{scenario_id}-profile.json"));
    let text = fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("total_ms").and_then(|n| n.as_u64())
}

fn read_sbom_component_count(run_dir: &Path, scenario_id: &str) -> Option<u32> {
    let path = run_dir.join(format!("sbom-{scenario_id}.json"));
    let text = fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("packages")
        .and_then(|p| p.as_array())
        .map(|a| a.len() as u32)
}

fn read_mixin_target_count(run_dir: &Path, scenario_id: &str) -> Option<u32> {
    let path = run_dir.join(format!("mixin-map-{scenario_id}.txt"));
    let text = fs::read_to_string(path).ok()?;
    text.lines()
        .find_map(|l| {
            if let Some(rest) = l.strip_prefix("Mixin classes:") {
                rest.trim().parse().ok()
            } else {
                None
            }
        })
}

fn read_headline_findings(path: &Path) -> Result<Vec<HeadlineFinding>, DemoReportError> {
    let text = fs::read_to_string(path).map_err(|source| DemoReportError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|source| DemoReportError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    let Some(findings) = v.get("findings").and_then(|f| f.as_array()) else {
        return Ok(Vec::new());
    };
    let mut ranked: Vec<HeadlineFinding> = findings
        .iter()
        .filter_map(|f| {
            let id = f.get("id")?.as_str()?.to_string();
            let severity = f.get("severity")?.as_str()?.to_string();
            let title = f.get("title")?.as_str()?.to_string();
            Some(HeadlineFinding {
                id,
                severity,
                title,
            })
        })
        .collect();
    ranked.sort_by_key(|f| severity_rank(&f.severity));
    ranked.truncate(3);
    Ok(ranked)
}

fn read_headline_findings_from_text(text: &str) -> Vec<HeadlineFinding> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let (severity, rest) = if let Some(rest) = trimmed.strip_prefix("ERROR ") {
            ("Error", rest)
        } else if let Some(rest) = trimmed.strip_prefix("WARN ") {
            ("Warn", rest)
        } else {
            continue;
        };
        let title = rest.split(" [").next().unwrap_or(rest).trim().to_string();
        if title.is_empty() {
            continue;
        }
        let id = title
            .split(':')
            .next()
            .unwrap_or("finding")
            .trim()
            .to_ascii_lowercase()
            .replace(' ', "-");
        out.push(HeadlineFinding {
            id,
            severity: severity.to_string(),
            title,
        });
        if out.len() >= 3 {
            break;
        }
    }
    out
}

fn severity_rank(sev: &str) -> u8 {
    match sev.to_ascii_lowercase().as_str() {
        "fatal" => 0,
        "error" => 1,
        "warn" => 2,
        "note" => 3,
        _ => 4,
    }
}

/// Parse the terminal summary footer emitted by `intermed doctor`.
fn parse_doctor_summary(text: &str) -> Option<(String, SeverityCounts)> {
    let line = text
        .lines()
        .rev()
        .find(|l| l.starts_with("PROBLEMS") || l.starts_with("WARNINGS"))?;
    parse_summary_line(line)
}

fn parse_summary_line(line: &str) -> Option<(String, SeverityCounts)> {
    let verdict = if line.starts_with("PROBLEMS") {
        "PROBLEMS"
    } else if line.starts_with("WARNINGS") {
        "WARNINGS"
    } else {
        return None;
    }
    .to_string();
    let mut counts = SeverityCounts {
        fatal: 0,
        error: 0,
        warn: 0,
        note: 0,
        info: 0,
        facts: 0,
    };
    let parts: Vec<&str> = line.split_whitespace().collect();
    for pair in parts.windows(2) {
        let Ok(n) = pair[0].parse::<u32>() else {
            continue;
        };
        match pair[1].trim_end_matches(',') {
            "fatal" => counts.fatal = n,
            "error" => counts.error = n,
            "warn" => counts.warn = n,
            "note" => counts.note = n,
            "info" => counts.info = n,
            _ => {}
        }
    }
    counts.facts = line
        .split('(')
        .nth(1)
        .and_then(|s| s.trim_end_matches(" facts)").parse().ok())
        .unwrap_or(0);
    Some((verdict, counts))
}

fn escape_html(s: &str) -> String {
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

    #[test]
    fn parse_summary_extracts_counts() {
        let line = "PROBLEMS  0 fatal, 1 error, 6 warn, 340 note, 0 info  (2388 facts)";
        let (verdict, c) = parse_summary_line(line).unwrap();
        assert_eq!(verdict, "PROBLEMS");
        assert_eq!(c.error, 1);
        assert_eq!(c.warn, 6);
        assert_eq!(c.facts, 2388);
    }

    #[test]
    fn markdown_and_html_render_without_panicking() {
        let report = DemoReport {
            schema: DEMO_REPORT_SCHEMA.into(),
            audience: "ATLauncher".into(),
            title: "Test".into(),
            generated_at: Utc::now(),
            tool_version: "intermed 0.1.0-test".into(),
            run_dir: "/tmp/demo".into(),
            corpus: DemoCorpus {
                schema: "intermed-demo-corpus-v1".into(),
                audience: "ATLauncher".into(),
                title: "Test corpus".into(),
                description: "desc".into(),
                root: "/corpus".into(),
                scenarios: vec![DemoScenario {
                    id: "fabric_clean".into(),
                    title: "Healthy".into(),
                    subtitle: "Sodium".into(),
                    role: "baseline".into(),
                    loader: "fabric".into(),
                    mc_version: "1.20.1".into(),
                    jar_count: 7,
                    narrative: "story".into(),
                }],
            },
            scenarios: vec![ScenarioResult {
                scenario: DemoScenario {
                    id: "fabric_clean".into(),
                    title: "Healthy".into(),
                    subtitle: "Sodium".into(),
                    role: "baseline".into(),
                    loader: "fabric".into(),
                    mc_version: "1.20.1".into(),
                    jar_count: 7,
                    narrative: "story".into(),
                },
                verdict: "WARNINGS".into(),
                counts: SeverityCounts {
                    fatal: 0,
                    error: 0,
                    warn: 1,
                    note: 2,
                    info: 0,
                    facts: 10,
                },
                headline_findings: vec![HeadlineFinding {
                    id: "mixin-risk".into(),
                    severity: "Warn".into(),
                    title: "Mixin note".into(),
                }],
                profile_ms: Some(1200),
            }],
            totals: DemoTotals {
                scenario_count: 1,
                jar_count: 7,
                error_scenarios: 0,
                warning_scenarios: 1,
                healthy_scenarios: 0,
            },
            capabilities: default_capabilities(),
            hero: None,
        };
        let md = render_markdown(&report);
        assert!(md.contains("ATLauncher"));
        let html = render_html(&report);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("Healthy"));
    }
}