//! Human-readable terminal rendering with optional ANSI colour. No external
//! colour crate: the codes are trivial and avoiding the dependency keeps the
//! `doctor latest.log` cold-start fast (design-doc critique #2).

use std::fmt::Write as _;

use intermed_doctor_core::DoctorReport;
use intermed_evidence::Severity;

struct Palette {
    on: bool,
}

impl Palette {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }
    fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }
    fn sev(&self, s: Severity) -> String {
        let (code, label) = match s {
            Severity::Fatal => ("1;41", "FATAL"),
            Severity::Error => ("1;31", "ERROR"),
            Severity::Warn => ("1;33", "WARN"),
            Severity::Note => ("1;36", "NOTE"),
            Severity::Info => ("1;34", "INFO"),
        };
        self.paint(code, label)
    }
}

pub fn render_terminal(report: &DoctorReport, color: bool) -> String {
    let p = Palette { on: color };
    let mut out = String::new();

    // Header
    let _ = writeln!(
        out,
        "{} {}",
        p.bold("InterMed Doctor"),
        p.dim(&format!("v{} · {}", report.tool_version, report.schema))
    );
    let _ = writeln!(
        out,
        "Target: {} ({})",
        p.bold(&report.target.path),
        report.target.kind.label()
    );

    // Environment line
    let env = &report.environment;
    let mut env_bits = Vec::new();
    if let Some(l) = &env.loader {
        env_bits.push(format!("loader={}", l.as_str()));
    }
    if let Some(m) = &env.minecraft_version {
        env_bits.push(format!("mc={m}"));
    }
    if let Some(j) = &env.java_version {
        env_bits.push(format!("java={j}"));
    }
    if let Some(o) = &env.os {
        env_bits.push(format!("os={o}"));
    }
    if !env_bits.is_empty() {
        let _ = writeln!(out, "Env:    {}", p.dim(&env_bits.join("  ")));
    }
    out.push('\n');

    // Findings
    if report.findings.is_empty() {
        let _ = writeln!(out, "{}", p.paint("1;32", "✓ No findings."));
    } else {
        for f in &report.findings {
            let _ = writeln!(out, "{} {}", p.sev(f.severity), p.bold(&f.title));
            if !f.explanation.is_empty() {
                let _ = writeln!(out, "      {}", f.explanation);
            }
            if !f.affected_components.is_empty() {
                let _ = writeln!(
                    out,
                    "      {} {}",
                    p.dim("affects:"),
                    f.affected_components.join(", ")
                );
            }
            for fix in &f.fix_candidates {
                let _ = writeln!(out, "      {} {}", p.paint("32", "→ fix:"), fix.description);
                if let Some(cmd) = &fix.command {
                    let _ = writeln!(out, "             {}", p.dim(cmd));
                }
            }
            let _ = writeln!(
                out,
                "      {}",
                p.dim(&format!("[{}] rule={}", f.id, f.rule_id))
            );
            out.push('\n');
        }
    }

    // Deferred layers (roadmap visibility)
    if !report.deferred_layers.is_empty() {
        let _ = writeln!(out, "{}", p.dim("Deferred layers:"));
        for d in &report.deferred_layers {
            let _ = writeln!(
                out,
                "  {}",
                p.dim(&format!(
                    "[{}] {} — Phase {}",
                    d.layer_code, d.layer, d.phase
                ))
            );
        }
        out.push('\n');
    }

    // Summary
    let s = &report.summary;
    let verdict = if s.is_healthy() && s.warn == 0 {
        p.paint("1;32", "HEALTHY")
    } else if s.is_healthy() {
        p.paint("1;33", "WARNINGS")
    } else {
        p.paint("1;31", "PROBLEMS")
    };
    let _ = writeln!(
        out,
        "{}  {} fatal, {} error, {} warn, {} note, {} info  ({} facts)",
        verdict,
        s.fatal,
        s.error,
        s.warn,
        s.note,
        s.info,
        report.fact_stats.values().sum::<usize>()
    );

    out
}
