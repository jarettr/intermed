//! # intermed-log
//!
//! Layer D. Ports the old `LogAnalyzer` (which had zero non-stdlib imports —
//! pure pattern matching, the easiest Tier-1 port). Two pieces:
//!
//! * [`LogCollector`] — scans log/crash text and emits `log_signal` facts.
//! * [`LogSignalRule`] — turns those facts into findings.
//!
//! Collector and rule live together because the failure-signature vocabulary is
//! one body of knowledge.

use std::path::PathBuf;

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::{kind, SourceRef};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, Layer, RuleCtx, Target, TargetKind,
};

use regex::Regex;

/// Stable signal-kind identifiers (the `kind` attribute on `log_signal` facts).
pub mod signal {
    pub const MIXIN_APPLY_ERROR: &str = "MixinApplyError";
    pub const CLASS_NOT_FOUND: &str = "ClassNotFound";
    pub const NO_CLASS_DEF_FOUND: &str = "NoClassDefFound";
    pub const MOD_LOADING_FAILURE: &str = "ModLoadingFailure";
    pub const MISSING_DEPENDENCY: &str = "MissingDependency";
    pub const OUT_OF_MEMORY: &str = "OutOfMemory";
    pub const STACK_OVERFLOW: &str = "StackOverflow";
    pub const JVM_CRASH: &str = "JvmCrash";
    pub const PORT_IN_USE: &str = "PortInUse";
    pub const DATAPACK_VALIDATION_ERROR: &str = "DatapackValidationError";
    pub const REGISTRY_FREEZE_ERROR: &str = "RegistryFreezeError";
}

struct Pattern {
    signal: &'static str,
    severity: Severity,
    regex: &'static str,
    title: &'static str,
}

/// The classification table. Order matters only for which signal a line is
/// attributed to first; a line can match at most one pattern here.
fn patterns() -> &'static [Pattern] {
    &[
        Pattern {
            signal: signal::MIXIN_APPLY_ERROR,
            severity: Severity::Error,
            regex: r"(?i)(InvalidMixinException|Mixin apply failed|mixin transformation .* failed)",
            title: "Mixin failed to apply",
        },
        Pattern {
            signal: signal::NO_CLASS_DEF_FOUND,
            severity: Severity::Error,
            regex: r"NoClassDefFoundError",
            title: "Missing class at runtime (NoClassDefFoundError)",
        },
        Pattern {
            signal: signal::CLASS_NOT_FOUND,
            severity: Severity::Error,
            regex: r"ClassNotFoundException",
            title: "Class not found (ClassNotFoundException)",
        },
        Pattern {
            signal: signal::MISSING_DEPENDENCY,
            severity: Severity::Error,
            regex: r"(?i)(requires .* which is missing|Missing or unsupported mandatory dependencies|requires version)",
            title: "A mod is missing a required dependency",
        },
        Pattern {
            signal: signal::MOD_LOADING_FAILURE,
            severity: Severity::Error,
            regex: r"(?i)(Failed to load mod|ModResolutionException|Could not execute entrypoint)",
            title: "A mod failed to load",
        },
        Pattern {
            signal: signal::OUT_OF_MEMORY,
            severity: Severity::Fatal,
            regex: r"OutOfMemoryError",
            title: "Out of memory",
        },
        Pattern {
            signal: signal::STACK_OVERFLOW,
            severity: Severity::Error,
            regex: r"StackOverflowError",
            title: "Stack overflow",
        },
        Pattern {
            signal: signal::JVM_CRASH,
            severity: Severity::Fatal,
            regex: r"(A fatal error has been detected by the Java Runtime|SIGSEGV|EXCEPTION_ACCESS_VIOLATION)",
            title: "JVM hard crash",
        },
        Pattern {
            signal: signal::PORT_IN_USE,
            severity: Severity::Error,
            regex: r"(?i)(Address already in use|FAILED TO BIND TO PORT)",
            title: "Server port already in use",
        },
        Pattern {
            signal: signal::DATAPACK_VALIDATION_ERROR,
            severity: Severity::Warn,
            regex: r"(?i)(Couldn't load .* datapack|Failed to load datapacks|Error while loading data pack)",
            title: "Datapack failed validation",
        },
        Pattern {
            signal: signal::REGISTRY_FREEZE_ERROR,
            severity: Severity::Error,
            regex: r"(?i)(Registry is already frozen|Trying to access unbound|registry freeze)",
            title: "Registry modified after freeze",
        },
    ]
}

fn severity_for(sig: &str) -> Severity {
    patterns()
        .iter()
        .find(|p| p.signal == sig)
        .map(|p| p.severity)
        .unwrap_or(Severity::Warn)
}
fn title_for(sig: &str) -> &'static str {
    patterns()
        .iter()
        .find(|p| p.signal == sig)
        .map(|p| p.title)
        .unwrap_or("Log signal")
}

// ── Collector ──────────────────────────────────────────────────────────────

pub struct LogCollector;

impl Collector for LogCollector {
    fn id(&self) -> &'static str {
        "log-analyzer"
    }
    fn layer(&self) -> Layer {
        Layer::Log
    }
    fn applies(&self, target: &Target) -> bool {
        target.kind.is_log() || target_has_logs(target)
    }
    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let files = log_files(ctx.target);
        if files.is_empty() {
            return CollectorOutcome::skipped("no log files found");
        }
        let compiled: Vec<(Regex, &Pattern)> = patterns()
            .iter()
            .filter_map(|p| Regex::new(p.regex).ok().map(|re| (re, p)))
            .collect();

        let mut emitted = 0usize;
        let mut scanned = 0usize;
        for file in &files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            scanned += 1;
            let locator = file.display().to_string();
            for (lineno, line) in text.lines().enumerate() {
                for (re, p) in &compiled {
                    if re.is_match(line) {
                        ctx.store
                            .fact(self.id(), kind::LOG_SIGNAL)
                            .subject(p.signal)
                            .attr("line", (lineno as i64) + 1)
                            .attr("excerpt", truncate(line, 200))
                            .source(SourceRef::at_line(locator.clone(), (lineno as u32) + 1))
                            .confidence(0.85)
                            .emit();
                        emitted += 1;
                        break; // one signal per line
                    }
                }
            }
        }
        CollectorOutcome::active(emitted, format!("{scanned} log file(s) scanned"))
    }
}

fn target_has_logs(target: &Target) -> bool {
    matches!(target.kind, TargetKind::Server | TargetKind::Instance)
        && target.path.join("logs").is_dir()
}

fn log_files(target: &Target) -> Vec<PathBuf> {
    if target.kind.is_log() {
        return vec![target.path.clone()];
    }
    let mut out = Vec::new();
    let logs = target.path.join("logs");
    for name in ["latest.log", "debug.log"] {
        let p = logs.join(name);
        if p.is_file() {
            out.push(p);
        }
    }
    // Most recent crash report, if any.
    let crashes = target.path.join("crash-reports");
    if let Ok(rd) = std::fs::read_dir(&crashes) {
        let mut reports: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("txt"))
            .collect();
        reports.sort();
        if let Some(last) = reports.pop() {
            out.push(last);
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= max {
        t.to_string()
    } else {
        let cut: String = t.chars().take(max).collect();
        format!("{cut}…")
    }
}

// ── Rule ─────────────────────────────────────────────────────────────────

pub struct LogSignalRule;

impl intermed_doctor_core::Rule for LogSignalRule {
    fn id(&self) -> &'static str {
        "log-signal"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for fact in ctx.store.by_kind(kind::LOG_SIGNAL) {
            let sig = fact.subject.as_str();
            let line = fact
                .attr_int("line")
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into());
            let excerpt = fact.attr("excerpt").unwrap_or("");
            let mut b = Finding::builder(self.id(), format!("log:{sig}:{line}"))
                .severity(severity_for(sig))
                .category(Category::Log)
                .title(title_for(sig))
                .explanation(format!("Detected at line {line}: {excerpt}"))
                .evidence(EvidenceEdge::subject(fact.id))
                .tag("log")
                .tag(sig);
            if let Some(fix) = fix_for(sig) {
                b = b.fix(fix);
            }
            out.push(b.build());
        }
        out
    }
}

fn fix_for(sig: &str) -> Option<FixCandidate> {
    Some(match sig {
        signal::OUT_OF_MEMORY => {
            FixCandidate::advice("Increase the JVM heap (e.g. -Xmx) or remove memory-heavy mods.")
                .with_command("-Xmx6G")
        }
        signal::PORT_IN_USE => FixCandidate::advice(
            "Another process holds the server port; stop it or change server-port.",
        ),
        signal::MIXIN_APPLY_ERROR => FixCandidate::advice(
            "A mixin target changed or two mods conflict; check the named mod's compatibility.",
        ),
        signal::MISSING_DEPENDENCY | signal::MOD_LOADING_FAILURE => {
            FixCandidate::advice("Install the missing/required dependency at a compatible version.")
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::{DiagnosticEngine, Target, TargetKind};

    #[test]
    fn oom_in_text_becomes_fatal_finding() {
        let dir = std::env::temp_dir().join(format!("imd-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("latest.log");
        std::fs::write(
            &log,
            "[12:00:00] [Server] java.lang.OutOfMemoryError: Java heap space\n",
        )
        .unwrap();

        let engine = DiagnosticEngine::builder()
            .collector(LogCollector)
            .rule(LogSignalRule)
            .build();
        let target = Target {
            path: log.clone(),
            kind: TargetKind::LogFile,
            mods_dir: None,
        };
        let report = engine.diagnose(&target);

        assert_eq!(report.summary.fatal, 1);
        assert!(report.findings[0]
            .machine_tags
            .iter()
            .any(|t| t == signal::OUT_OF_MEMORY));
        std::fs::remove_dir_all(&dir).ok();
    }
}
