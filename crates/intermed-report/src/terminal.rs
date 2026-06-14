//! Human-readable terminal rendering with optional ANSI colour. No external
//! colour crate: the codes are trivial and avoiding the dependency keeps the
//! `doctor latest.log` cold-start fast (design-doc critique #2).

use std::collections::BTreeSet;
use std::fmt::Write as _;

use intermed_doctor_core::facts::{kind, Fact};
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
    render_terminal_with_facts(report, color, &[])
}

pub fn render_terminal_with_facts(report: &DoctorReport, color: bool, facts: &[Fact]) -> String {
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
    if let Some(launcher) = &env.launcher {
        env_bits.push(format!("launcher={launcher}"));
    }
    if let Some(host) = &env.host_launcher {
        env_bits.push(format!("host={host}"));
    }
    if let Some(it) = &env.instance_type {
        env_bits.push(format!("instance={}", it.as_str()));
    }
    if let Some(layout) = &env.layout {
        env_bits.push(format!("layout={}", layout.as_str()));
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

    // Resource Semantics (Layer M) — a compact summary of the typed-AST evidence.
    if let Some(section) = resource_semantics_section(facts, &p) {
        out.push_str(&section);
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

/// A compact "Resource Semantics" block from Layer-M facts, or `None` when the
/// layer did not run / found nothing. Summary only — the detail lives in the
/// findings list above and in `vfs explain --path <p> --ast`.
fn resource_semantics_section(facts: &[Fact], p: &Palette) -> Option<String> {
    let parsed = facts.iter().filter(|f| f.kind == kind::RESOURCE_AST_PARSED).count();
    if parsed == 0 {
        return None;
    }

    let mut recipe_overrides = 0usize;
    let mut lang_conflicts = 0usize;
    for f in facts.iter().filter(|f| f.kind == kind::RESOURCE_SEMANTIC_DIFF) {
        match f.attr("diff_kind") {
            Some("recipe-output-override") => recipe_overrides += 1,
            Some("lang-key-conflict") => lang_conflicts += 1,
            _ => {}
        }
    }
    // Only the actionable subset: an unconditioned recipe-serializer reference to
    // an unowned namespace (matches what Layer C raises as a finding). The full
    // candidate set includes benign cross-mod item references and would be noise.
    let implicit: BTreeSet<&str> = facts
        .iter()
        .filter(|f| {
            f.kind == kind::IMPLICIT_DEPENDENCY_CANDIDATE
                && f.attr_bool("via_recipe_type").unwrap_or(false)
                && f.attr_bool("required").unwrap_or(false)
        })
        .map(|f| f.subject.as_str())
        .collect();
    let namespaces: BTreeSet<&str> = facts
        .iter()
        .filter(|f| f.kind == kind::NAMESPACE_OWNER)
        .map(|f| f.subject.as_str())
        .collect();

    let mut out = String::new();
    let _ = writeln!(out, "{}", p.bold("Resource Semantics (Layer M)"));
    let _ = writeln!(
        out,
        "  {}",
        p.dim(&format!(
            "{parsed} resource AST(s) across {} namespace(s)",
            namespaces.len()
        ))
    );
    if recipe_overrides > 0 {
        let _ = writeln!(
            out,
            "  • {} recipe(s) resolve to different outputs by load order (review)",
            recipe_overrides
        );
    }
    if lang_conflicts > 0 {
        let _ = writeln!(
            out,
            "  • {} locale file(s) bind a shared key to different text",
            lang_conflicts
        );
    }
    if !implicit.is_empty() {
        let _ = writeln!(
            out,
            "  • {} recipe serializer namespace(s) not provided by any installed mod",
            implicit.len()
        );
    }
    if recipe_overrides == 0 && lang_conflicts == 0 && implicit.is_empty() {
        let _ = writeln!(out, "  {}", p.paint("32", "✓ no semantic conflicts"));
    }
    out.push('\n');
    Some(out)
}
