//! # intermed-report
//!
//! Turns a [`DoctorReport`] into one of three output formats. Renderers are
//! pure: they read the report and produce a `String`; they never recompute
//! diagnosis. This mirrors the old `DoctorReport` "report-DNA" (ANSI render +
//! JSON + SARIF) the design doc asked us to carry forward.

use intermed_doctor_core::DoctorReport;

mod sarif;
mod terminal;

pub use sarif::to_sarif;
pub use terminal::render_terminal;

/// Output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Human-readable, optionally coloured.
    Terminal { color: bool },
    /// Pretty-printed `intermed-doctor-report-v1` JSON.
    Json,
    /// SARIF 2.1.0 for IDE / CI ingestion.
    Sarif,
}

/// Render a report in the requested format.
pub fn render(report: &DoctorReport, format: Format) -> String {
    match format {
        Format::Terminal { color } => render_terminal(report, color),
        Format::Json => serde_json::to_string_pretty(report)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}")),
        Format::Sarif => serde_json::to_string_pretty(&to_sarif(report))
            .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::report::{assemble, RuleStat};
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
        let findings = vec![Finding::builder(
            "missing-dependency",
            "missing-dependency:create->fabric-api",
        )
        .severity(Severity::Error)
        .category(Category::Dependency)
        .title("Missing dependency: fabric-api")
        .explanation("create requires fabric-api.")
        .affects("create")
        .build()];
        let target = Target {
            path: "./mods".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
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
        )
    }

    #[test]
    fn renders_all_formats_without_panicking() {
        let r = sample_report();
        let term = render(&r, Format::Terminal { color: false });
        assert!(term.contains("fabric-api"));
        assert!(term.contains("ERROR") || term.contains("error"));

        let json = render(&r, Format::Json);
        assert!(json.contains("intermed-doctor-report-v1"));

        let sarif = render(&r, Format::Sarif);
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("InterMed Doctor"));
    }
}
