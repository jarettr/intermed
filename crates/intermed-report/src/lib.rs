//! # intermed-report
//!
//! Turns a [`DoctorReport`] into one of three output formats. Renderers are
//! pure: they read the report and produce a `String`; they never recompute
//! diagnosis. This mirrors the old `DoctorReport` "report-DNA" (ANSI render +
//! JSON + SARIF) the design doc asked us to carry forward.

use intermed_doctor_core::{DoctorReport, REPORT_SCHEMA_V1};
use intermed_facts::Fact;

mod demo;
pub mod grouping;
mod html;
mod sarif;
mod terminal;

pub use demo::{
    DEMO_REPORT_HTML, DEMO_REPORT_JSON, DEMO_REPORT_SCHEMA, DEMO_SUMMARY_MD, DemoArtifacts,
    DemoReport, DemoReportError, build_demo_report, render_html as render_demo_html,
    render_markdown as render_demo_markdown, write_demo_artifacts,
};
pub use html::{render_html, render_html_with_facts};
pub use sarif::{to_sarif, to_sarif_with_facts};
pub use terminal::render_terminal;

/// Output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Human-readable, optionally coloured.
    Terminal { color: bool },
    /// Pretty-printed canonical `intermed-doctor-report-v2` JSON.
    Json,
    /// SARIF 2.1.0 for IDE / CI ingestion.
    Sarif,
    /// Self-contained static HTML (lab-matrix style).
    Html,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportSchema {
    V1,
    V2,
}

/// Render the canonical v2 report or the temporary lossy v1 compatibility
/// projection. The v1 writer deliberately removes trust-contract fields that
/// did not exist in that schema; the v1 reader remains supported through serde
/// defaults on the v2 model.
pub fn render_json_schema(report: &DoctorReport, schema: ReportSchema) -> String {
    let mut value = match serde_json::to_value(report) {
        Ok(value) => value,
        Err(error) => return format!("{{\"error\":\"serialization failed: {error}\"}}"),
    };
    if schema == ReportSchema::V1
        && let Some(root) = value.as_object_mut()
    {
        root.insert(
            "schema".to_string(),
            serde_json::Value::String(REPORT_SCHEMA_V1.to_string()),
        );
        root.remove("target_capabilities");
        if let Some(findings) = root
            .get_mut("findings")
            .and_then(|value| value.as_array_mut())
        {
            for finding in findings {
                if let Some(finding) = finding.as_object_mut() {
                    for field in [
                        "semantic_id",
                        "occurrence_id",
                        "family",
                        "channel",
                        "proposed_impact",
                        "evidence_origins",
                        "assessment",
                    ] {
                        finding.remove(field);
                    }
                }
            }
        }
    }
    serde_json::to_string_pretty(&value)
        .unwrap_or_else(|error| format!("{{\"error\":\"serialization failed: {error}\"}}"))
}

/// Render a report in the requested format (without the fact corpus).
pub fn render(report: &DoctorReport, format: Format) -> String {
    render_with_facts(report, &[], format)
}

/// Render a report, using the run's facts where a format can show more with them
/// (SARIF physical locations, the HTML provenance/heatmap/explorer tabs).
pub fn render_with_facts(report: &DoctorReport, facts: &[Fact], format: Format) -> String {
    match format {
        Format::Terminal { color } => terminal::render_terminal_with_facts(report, color, facts),
        Format::Json => render_json_schema(report, ReportSchema::V2),
        Format::Sarif => serde_json::to_string_pretty(&to_sarif_with_facts(report, facts))
            .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}")),
        Format::Html => {
            if facts.is_empty() {
                render_html(report)
            } else {
                render_html_with_facts(report, facts)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::report::{RuleStat, assemble};
    use intermed_doctor_core::{Target, TargetKind};
    use intermed_evidence::{Category, Finding, Severity};
    use intermed_facts::FactStore;

    fn sample_report() -> DoctorReport {
        let mut store = FactStore::new();
        store
            .fact("env", intermed_facts::kind::ENVIRONMENT)
            .attr("os", "linux")
            .attr("loader", "fabric")
            .attr("mc_version", "1.20.1")
            .emit();
        let findings = vec![
            Finding::builder(
                "missing-dependency",
                "missing-dependency:create->fabric-api",
            )
            .severity(Severity::Error)
            .category(Category::Dependency)
            .title("Missing dependency: fabric-api")
            .explanation("create requires fabric-api.")
            .affects("create")
            .build(),
        ];
        let target = Target {
            path: "./mods".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        assemble(
            "0.1.0-test",
            &target,
            &store,
            findings,
            vec![],
            vec![RuleStat {
                id: "missing-dependency".into(),
                findings: 1,
            }],
            vec![],
            None,
        )
    }

    #[test]
    fn renders_all_formats_without_panicking() {
        let r = sample_report();
        let term = render(&r, Format::Terminal { color: false });
        assert!(term.contains("fabric-api"));
        assert!(term.contains("ERROR") || term.contains("error"));

        let json = render(&r, Format::Json);
        assert!(json.contains("intermed-doctor-report-v2"));

        let v1 = render_json_schema(&r, ReportSchema::V1);
        assert!(v1.contains("intermed-doctor-report-v1"));
        assert!(!v1.contains("\"assessment\""));
        let restored: DoctorReport = serde_json::from_str(&v1).expect("v1 remains readable");
        assert_eq!(restored.schema, "intermed-doctor-report-v1");
        assert_eq!(restored.findings.len(), r.findings.len());

        let sarif = render(&r, Format::Sarif);
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("InterMed Doctor"));

        let html = render(&r, Format::Html);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("fabric-api"));
    }
}
