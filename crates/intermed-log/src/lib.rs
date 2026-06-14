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

use rayon::prelude::*;
use regex::Regex;

pub mod stacktrace;

/// Line count above which a single log is scanned in parallel. Regex matching is
/// CPU-bound and per-line independent, so large logs (verbose `debug.log`s reach
/// hundreds of thousands of lines) win from fan-out; small logs stay sequential
/// to avoid thread-pool overhead.
/// Default parallel threshold (overridden via config / `CollectCtx.settings`).
pub const DEFAULT_PARALLEL_LINE_THRESHOLD: usize = 4_096;

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
    pub const SODIUM_CONFLICT: &str = "SodiumConflict";
    pub const IRIS_SHADER_ERROR: &str = "IrisShaderError";
    pub const LITHIUM_CONFLICT: &str = "LithiumConflict";
    pub const CREATE_ERROR: &str = "CreateError";
    pub const NEOFORGE_LOAD_ERROR: &str = "NeoForgeLoadError";
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
        Pattern {
            signal: signal::SODIUM_CONFLICT,
            severity: Severity::Error,
            regex: r"(?i)(Sodium has already been installed|duplicate Sodium|Rubidium is installed|Embeddium.*Sodium)",
            title: "Multiple Sodium-family renderers detected",
        },
        Pattern {
            signal: signal::IRIS_SHADER_ERROR,
            severity: Severity::Error,
            regex: r"(?i)(Iris.*Sodium|Sodium is required for Iris|shader pack failed|Iris encountered an error)",
            title: "Iris / shader pipeline failure",
        },
        Pattern {
            signal: signal::LITHIUM_CONFLICT,
            severity: Severity::Warn,
            regex: r"(?i)(Lithium|CaffeineConfig|Radium).*(mixin|conflict|incompatible)",
            title: "Lithium-family performance mod conflict",
        },
        Pattern {
            signal: signal::CREATE_ERROR,
            severity: Severity::Error,
            regex: r"(?i)(com\.simibubi\.create|Create mod|contraption.*failed|Registrate|Flywheel.*(error|exception)|Unable to launch Create)",
            title: "Create / Flywheel initialization failure",
        },
        Pattern {
            signal: signal::NEOFORGE_LOAD_ERROR,
            severity: Severity::Error,
            regex: r"(?i)(ModLoadingException|Loading errors encountered|Failed to create mod instance)",
            title: "NeoForge / Forge mod loading exception",
        },
    ]
}

/// Severity for a [`signal`] kind emitted by [`LogCollector`].
///
/// Shared by imperative [`LogSignalRule`] and declarative backends (DuckDB/Datalog)
/// so log findings stay consistent regardless of rule engine.
#[must_use]
pub fn signal_severity(sig: &str) -> Severity {
    patterns()
        .iter()
        .find(|p| p.signal == sig)
        .map(|p| p.severity)
        .unwrap_or(Severity::Warn)
}

/// Human title for a [`signal`] kind.
#[must_use]
pub fn signal_title(sig: &str) -> &'static str {
    patterns()
        .iter()
        .find(|p| p.signal == sig)
        .map(|p| p.title)
        .unwrap_or("Log signal")
}

/// Optional fix guidance for a [`signal`] kind.
#[must_use]
pub fn signal_fix(sig: &str) -> Option<FixCandidate> {
    fix_for(sig)
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
            // The expensive part (regex matching every line) is fanned out; the
            // emit stays sequential and in line order, so the fact set is byte-for
            // -byte identical to a single-threaded scan.
            for hit in scan_lines(&text, &compiled, ctx.settings.log.parallel_line_threshold) {
                ctx.store
                    .fact(self.id(), kind::LOG_SIGNAL)
                    .subject(hit.signal)
                    .attr("line", (hit.lineno as i64) + 1)
                    .attr("excerpt", hit.excerpt)
                    .source(SourceRef::at_line(locator.clone(), (hit.lineno as u32) + 1))
                    .confidence(0.85)
                    .emit();
                emitted += 1;
            }
            emitted += emit_mod_mentions(ctx, self.id(), &text, &locator);
        }
        CollectorOutcome::active(emitted, format!("{scanned} log file(s) scanned"))
    }
}

/// Parse stack traces in one log file and emit a `log_mentions_mod` fact for each
/// distinct mod the trace structurally names (a `*.mixins.json` reference or an
/// explicit `mod 'x'` phrase). Returns the number of facts emitted.
fn emit_mod_mentions(
    ctx: &mut CollectCtx<'_>,
    extractor: &'static str,
    text: &str,
    locator: &str,
) -> usize {
    use std::collections::BTreeMap;

    let metadata: BTreeMap<String, (String, String, Vec<String>)> = ctx
        .store
        .by_kind(kind::MOD_METADATA)
        .map(|f| {
            let capabilities = ctx
                .store
                .by_kind(kind::MOD_CAPABILITY)
                .filter(|cap| cap.subject == f.subject)
                .filter_map(|cap| cap.attr("capability").map(str::to_string))
                .collect();
            (
                f.subject.clone(),
                (
                    f.attr("version_raw").unwrap_or("?").to_string(),
                    f.attr("environment").unwrap_or("both").to_string(),
                    capabilities,
                ),
            )
        })
        .collect();
    let mut emitted = 0;
    for trace in stacktrace::parse_stacktraces(text) {
        let root = trace.caused_by.last().unwrap_or(&trace.exception);
        let root_mod = trace.mod_refs.first().map(|m| m.mod_id.as_str()).unwrap_or("unknown");
        ctx.store
            .fact(extractor, kind::LOG_CRASH)
            .subject(root.class.clone())
            .attr("root_cause_exception", root.class.clone())
            .attr("root_cause_mod", root_mod)
            .attr("phase", infer_crash_phase(&trace))
            .attr("severity", crash_severity(&root.class))
            .attr("line", (trace.line as i64) + 1)
            .source(SourceRef::at_line(locator.to_string(), (trace.line as u32) + 1))
            .confidence(if root_mod == "unknown" { 0.75 } else { 0.85 })
            .emit();
        emitted += 1;

        for (index, mref) in trace.mod_refs.iter().enumerate() {
            let blame_score = mention_blame_score(mref.via, index);
            let mut mention = ctx.store
                .fact(extractor, kind::LOG_MENTIONS_MOD)
                .subject(mref.mod_id.clone())
                .attr("via", mref.via)
                .attr("exception", trace.exception.class.clone())
                .attr("root_cause_exception", root.class.clone())
                .attr("blame_score", blame_score)
                .attr("line", (trace.line as i64) + 1)
                .source(SourceRef::at_line(locator.to_string(), (trace.line as u32) + 1))
                .confidence(blame_score as f32);
            if let Some((version, environment, capabilities)) = metadata.get(&mref.mod_id) {
                mention = mention
                    .attr("version", version.clone())
                    .attr("environment", environment.clone())
                    .attr("capabilities", serde_json::to_string(capabilities).unwrap_or_default());
            }
            mention.emit();
            emitted += 1;

            let mut error = ctx.store
                .fact(extractor, kind::LOG_MOD_ERROR)
                .subject(mref.mod_id.clone())
                .attr("root_cause_exception", root.class.clone())
                .attr("phase", infer_crash_phase(&trace))
                .attr("severity", crash_severity(&root.class))
                .attr("blame_score", blame_score)
                .attr("via", mref.via)
                .source(SourceRef::at_line(locator.to_string(), (trace.line as u32) + 1))
                .confidence(blame_score as f32);
            if let Some((version, environment, capabilities)) = metadata.get(&mref.mod_id) {
                error = error
                    .attr("version", version.clone())
                    .attr("environment", environment.clone())
                    .attr("capabilities", serde_json::to_string(capabilities).unwrap_or_default());
            }
            error.emit();
            emitted += 1;
        }
    }
    emitted
}

fn mention_blame_score(via: &str, index: usize) -> f64 {
    let base: f64 = if via == "mixin-config" { 0.92 } else { 0.78 };
    (base - (index as f64 * 0.08)).max(0.4)
}

fn infer_crash_phase(trace: &stacktrace::Stacktrace) -> &'static str {
    let text = format!(
        "{} {}",
        trace.exception.class,
        trace.exception.message.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    if text.contains("load") || text.contains("entrypoint") || text.contains("init") {
        "startup"
    } else if text.contains("render") || text.contains("client") {
        "client_runtime"
    } else {
        "runtime"
    }
}

fn crash_severity(exception: &str) -> &'static str {
    if exception.contains("OutOfMemory") || exception.contains("VirtualMachineError") {
        "fatal"
    } else {
        "error"
    }
}

/// One matched log line: the first pattern it hit and a truncated excerpt.
struct LineHit {
    lineno: usize,
    signal: &'static str,
    excerpt: String,
}

/// Match every line against the compiled patterns (first match wins per line),
/// returning hits in line order. Parallelised for large logs; the result is
/// order-stable and independent of the worker count.
fn scan_lines(
    text: &str,
    compiled: &[(Regex, &'static Pattern)],
    parallel_line_threshold: usize,
) -> Vec<LineHit> {
    let lines: Vec<&str> = text.lines().collect();
    let match_line = |(lineno, line): (usize, &&str)| -> Option<LineHit> {
        compiled
            .iter()
            .find(|(re, _)| re.is_match(line))
            .map(|(_, p)| LineHit {
                lineno,
                signal: p.signal,
                excerpt: truncate(line, 200),
            })
    };
    if lines.len() >= parallel_line_threshold {
        // `Vec::par_iter().enumerate()` is an indexed parallel iterator, so the
        // collected order matches the sequential pass exactly.
        lines
            .par_iter()
            .enumerate()
            .filter_map(match_line)
            .collect()
    } else {
        lines.iter().enumerate().filter_map(match_line).collect()
    }
}

fn target_has_logs(target: &Target) -> bool {
    matches!(target.kind, TargetKind::Server | TargetKind::Instance)
        // Honor launcher layouts: logs may live under `<instance>/.minecraft`.
        && target.candidate_roots().iter().any(|r| r.join("logs").is_dir())
}

fn log_files(target: &Target) -> Vec<PathBuf> {
    if target.kind.is_log() {
        return vec![target.path.clone()];
    }
    let mut out = Vec::new();
    for root in target.candidate_roots() {
        let logs = root.join("logs");
        for name in ["latest.log", "debug.log"] {
            let p = logs.join(name);
            if p.is_file() {
                out.push(p);
            }
        }
        // Most recent crash report, if any.
        let crashes = root.join("crash-reports");
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
    }
    out.dedup();
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
                .severity(signal_severity(sig))
                .category(Category::Log)
                .title(signal_title(sig))
                .explanation(format!("Detected at line {line}: {excerpt}"))
                .evidence(EvidenceEdge::subject(fact.id))
                .tag("log")
                .tag(sig);
            if let Some(fix) = fix_for(sig) {
                b = b.fix(fix);
            }
            out.push(b.build());
        }
        out.extend(mod_mention_findings(ctx));
        out
    }
}

/// Correlate crash-trace mod mentions (`log_mentions_mod`) with the installed mod
/// set (Layer B `mod` facts). A mod named in a stack trace that is *also*
/// installed is a strong triage lead ("look at this mod first"); a name with no
/// matching install is a weaker note (often a missing dependency).
fn mod_mention_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    use std::collections::{BTreeMap, BTreeSet};

    let installed: BTreeSet<&str> = ctx
        .store
        .by_kind(kind::MOD)
        .map(|f| f.subject.as_str())
        .collect();

    // Group mentions by mod id; keep the evidence facts and how it was found.
    let mut by_mod: BTreeMap<&str, Vec<&intermed_doctor_core::facts::Fact>> = BTreeMap::new();
    for f in ctx.store.by_kind(kind::LOG_MENTIONS_MOD) {
        by_mod.entry(f.subject.as_str()).or_default().push(f);
    }

    let mut out = Vec::new();
    for (mod_id, mentions) in by_mod {
        let is_installed = installed.contains(mod_id);
        let exceptions: BTreeSet<&str> = mentions
            .iter()
            .filter_map(|f| f.attr("exception"))
            .collect();
        let exception_list = exceptions.into_iter().collect::<Vec<_>>().join(", ");
        let mut b = Finding::builder("log-signal", format!("log-mentions-mod:{mod_id}"))
            .category(Category::Log)
            .severity(if is_installed {
                Severity::Warn
            } else {
                Severity::Note
            })
            .title(if is_installed {
                format!("Crash trace implicates installed mod `{mod_id}`")
            } else {
                format!("Crash trace references mod `{mod_id}`")
            })
            .explanation(if is_installed {
                format!(
                    "`{mod_id}` is installed and appears in {} crash stack trace(s) ({exception_list}). \
                     Mods named directly in a trace are the most likely culprits — check this one first.",
                    mentions.len()
                )
            } else {
                format!(
                    "A crash stack trace references mod `{mod_id}` ({exception_list}), but no mod \
                     with that id is installed — it may be a missing dependency or a renamed jar.",
                )
            })
            .affects(mod_id.to_string())
            .tag("log")
            .tag("mod-mention");
        for f in &mentions {
            b = b.evidence(EvidenceEdge::subject(f.id));
        }
        out.push(b.build());
    }
    out
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
        signal::MISSING_DEPENDENCY | signal::MOD_LOADING_FAILURE | signal::NEOFORGE_LOAD_ERROR => {
            FixCandidate::advice("Install the missing/required dependency at a compatible version.")
        }
        signal::SODIUM_CONFLICT => FixCandidate::advice(
            "Keep only one Sodium-family renderer (Sodium, Rubidium, or Embeddium).",
        ),
        signal::IRIS_SHADER_ERROR => {
            FixCandidate::advice("Install a compatible Sodium build and matching Iris/shader pack versions.")
        }
        signal::CREATE_ERROR => FixCandidate::advice(
            "Verify Create, Flywheel, and Registrate versions match your loader and Minecraft version.",
        ),
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
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let report = engine.diagnose(&target);

        assert_eq!(report.summary.fatal, 1);
        assert!(report.findings[0]
            .machine_tags
            .iter()
            .any(|t| t == signal::OUT_OF_MEMORY));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prism_instance_game_root_logs_are_collected() {
        // Prism/MultiMC layout: instance dir is the target, but logs live under
        // `<instance>/.minecraft/logs`. The collector must follow game_root.
        let base = std::env::temp_dir().join(format!("imd-prism-{}", std::process::id()));
        let game_root = base.join(".minecraft");
        std::fs::create_dir_all(game_root.join("logs")).unwrap();
        std::fs::write(
            game_root.join("logs").join("latest.log"),
            "[12:00:00] [Server] java.lang.OutOfMemoryError: Java heap space\n",
        )
        .unwrap();

        let target = Target {
            path: base.clone(),
            kind: TargetKind::Instance,
            mods_dir: None,
            game_root: Some(game_root.clone()),
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        // applies() and collection both follow the game root.
        assert!(target_has_logs(&target));
        let files = log_files(&target);
        assert!(
            files.iter().any(|p| p.ends_with("latest.log")),
            "expected latest.log under game_root, got {files:?}"
        );

        let engine = DiagnosticEngine::builder()
            .collector(LogCollector)
            .rule(LogSignalRule)
            .build();
        let report = engine.diagnose(&target);
        assert_eq!(report.summary.fatal, 1);
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn mixin_crash_log_emits_mod_mention_finding() {
        let dir = std::env::temp_dir().join(format!("imd-mention-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("latest.log");
        std::fs::write(
            &log,
            "[12:00:00] [Render thread/ERROR]: java.lang.RuntimeException: Mixin apply failed examplemod.mixins.json:FooMixin\n\tat org.spongepowered.asm.mixin.Foo(Foo.java:1)\n",
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
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let report = engine.diagnose(&target);

        assert!(
            report.findings.iter().any(|f| f.id == "log-mentions-mod:examplemod"
                && f.machine_tags.iter().any(|t| t == "mod-mention")),
            "expected a mod-mention finding for examplemod: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn crash_emits_root_cause_and_weighted_mod_error_facts() {
        use intermed_doctor_core::facts::FactStore;
        use intermed_doctor_core::{default_settings, CollectCtx, Collector};

        let dir = std::env::temp_dir().join(format!("imd-root-cause-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("latest.log");
        std::fs::write(
            &log,
            "java.lang.RuntimeException: Mixin apply failed alpha.mixins.json\n\
             \tat loader.Entry.run(Entry.java:1)\n\
             Caused by: java.lang.NullPointerException: bad state\n\
             \tat alpha.Core.tick(Core.java:2)\n",
        )
        .unwrap();
        let target = Target {
            path: log,
            kind: TargetKind::LogFile,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let mut store = FactStore::new();
        store
            .fact("metadata-scanner", kind::MOD_METADATA)
            .subject("alpha")
            .attr("version_raw", "1.2.3")
            .attr("environment", "both")
            .emit();
        let mut ctx = CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: default_settings(),
        };
        LogCollector.collect(&mut ctx);

        let crash = store.by_kind(kind::LOG_CRASH).next().expect("log_crash");
        assert_eq!(crash.attr("root_cause_exception"), Some("java.lang.NullPointerException"));
        assert_eq!(crash.attr("root_cause_mod"), Some("alpha"));
        let error = store.by_kind(kind::LOG_MOD_ERROR).next().expect("log_mod_error");
        assert_eq!(error.subject, "alpha");
        assert_eq!(error.attr("version"), Some("1.2.3"));
        assert!(error.attr_f64("blame_score").unwrap() >= 0.9);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn installed_mod_mention_is_warn_uninstalled_is_note() {
        use intermed_doctor_core::facts::FactStore;
        use intermed_doctor_core::RuleCtx;

        let mut store = FactStore::new();
        store
            .fact("metadata-scanner", kind::MOD)
            .subject("installedmod")
            .emit();
        store
            .fact("log-analyzer", kind::LOG_MENTIONS_MOD)
            .subject("installedmod")
            .attr("via", "mixin-config")
            .attr("exception", "java.lang.RuntimeException")
            .emit();
        store
            .fact("log-analyzer", kind::LOG_MENTIONS_MOD)
            .subject("ghostmod")
            .attr("via", "message")
            .attr("exception", "ModResolutionException")
            .emit();

        let target = Target {
            path: ".".into(),
            kind: TargetKind::LogFile,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = mod_mention_findings(&ctx);

        let installed = findings
            .iter()
            .find(|f| f.id == "log-mentions-mod:installedmod")
            .expect("installed mention finding");
        assert_eq!(installed.severity, Severity::Warn);
        let ghost = findings
            .iter()
            .find(|f| f.id == "log-mentions-mod:ghostmod")
            .expect("uninstalled mention finding");
        assert_eq!(ghost.severity, Severity::Note);
    }

    #[test]
    fn parallel_and_sequential_scans_agree_and_preserve_order() {
        let compiled: Vec<(Regex, &'static Pattern)> = patterns()
            .iter()
            .filter_map(|p| Regex::new(p.regex).ok().map(|re| (re, p)))
            .collect();

        // A synthetic log large enough to cross PARALLEL_LINE_THRESHOLD, with
        // matches sprinkled throughout so ordering is observable.
        let mut log = String::new();
        for i in 0..(DEFAULT_PARALLEL_LINE_THRESHOLD * 2) {
            match i % 500 {
                0 => log.push_str("java.lang.OutOfMemoryError: Java heap space\n"),
                250 => log.push_str("Caused by: java.lang.NoClassDefFoundError: foo/Bar\n"),
                _ => log.push_str("[INFO] ordinary log line, nothing to see here\n"),
            }
        }

        let hits = scan_lines(&log, &compiled, DEFAULT_PARALLEL_LINE_THRESHOLD);
        // Hits must be strictly increasing in line number (order preserved).
        assert!(hits.windows(2).all(|w| w[0].lineno < w[1].lineno));
        // Every 500th line (OOM) and every (500k+250)th (NoClassDef) matched.
        let oom = hits
            .iter()
            .filter(|h| h.signal == signal::OUT_OF_MEMORY)
            .count();
        let ncdf = hits
            .iter()
            .filter(|h| h.signal == signal::NO_CLASS_DEF_FOUND)
            .count();
        assert_eq!(oom, (DEFAULT_PARALLEL_LINE_THRESHOLD * 2) / 500 + 1);
        assert_eq!(ncdf, (DEFAULT_PARALLEL_LINE_THRESHOLD * 2) / 500);

        // A small slice of the same content (sequential path) yields the same
        // relative hits — the two paths are equivalent.
        let small = "ok\njava.lang.OutOfMemoryError\nok\nNoClassDefFoundError\n";
        let small_hits = scan_lines(small, &compiled, DEFAULT_PARALLEL_LINE_THRESHOLD);
        assert_eq!(small_hits.len(), 2);
        assert_eq!(small_hits[0].lineno, 1);
        assert_eq!(small_hits[0].signal, signal::OUT_OF_MEMORY);
        assert_eq!(small_hits[1].lineno, 3);
    }
}
