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

use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use intermed_doctor_core::evidence::{
    Category, EvidenceEdge, Finding, FindingVisibility, FixCandidate, Severity,
};
use intermed_doctor_core::facts::{FactId, SourceRef, kind};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, Layer, RuleCtx, Target, TargetKind,
};

use regex::Regex;
use sha2::{Digest, Sha256};

pub mod runtime;
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
    pub const RESOURCE_MODEL_FAILURE: &str = "ResourceModelFailure";
    pub const RESOURCE_BLOCKSTATE_FAILURE: &str = "ResourceBlockstateFailure";
    pub const RUNTIME_EXCEPTION: &str = "RuntimeException";
    pub const NATIVE_WINDOW_ERROR: &str = "NativeWindowError";
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
            regex: r"(?i)(Failed to load mod\b|ModResolutionException|Could not execute entrypoint)",
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
            regex: r"(?i)(Unable to launch Create|Flywheel.*(error|exception)|(?:Create|Registrate|contraption).*(failed|exception))",
            title: "Create / Flywheel initialization failure",
        },
        Pattern {
            signal: signal::NEOFORGE_LOAD_ERROR,
            severity: Severity::Error,
            regex: r"(?i)(ModLoadingException|Loading errors encountered|Failed to create mod instance)",
            title: "NeoForge / Forge mod loading exception",
        },
        Pattern {
            signal: signal::RESOURCE_MODEL_FAILURE,
            severity: Severity::Warn,
            regex: r"(?i)(Failed to load model\b|Unable to bake model\b)",
            title: "Resource model failed to load",
        },
        Pattern {
            signal: signal::RESOURCE_BLOCKSTATE_FAILURE,
            severity: Severity::Warn,
            regex: r"(?i)(Failed to load blockstate\b|Exception loading blockstate\b)",
            title: "Resource blockstate failed to load",
        },
        Pattern {
            signal: signal::NATIVE_WINDOW_ERROR,
            severity: Severity::Error,
            regex: r"(?i)(GLFW error|GL error off-thread|OpenGL error)",
            title: "Native window / graphics API error",
        },
    ]
}

/// Severity for a [`signal`] kind emitted by [`LogCollector`].
///
/// Shared by imperative [`LogSignalRule`] and declarative backends (DuckDB/Datalog)
/// so log findings stay consistent regardless of rule engine.
#[must_use]
pub fn signal_severity(sig: &str) -> Severity {
    if sig == signal::RUNTIME_EXCEPTION {
        return Severity::Error;
    }
    patterns()
        .iter()
        .find(|p| p.signal == sig)
        .map(|p| p.severity)
        .unwrap_or(Severity::Warn)
}

/// Human title for a [`signal`] kind.
#[must_use]
pub fn signal_title(sig: &str) -> &'static str {
    if sig == signal::RUNTIME_EXCEPTION {
        return "Runtime exception chain";
    }
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

const MAX_LOG_FILES: usize = 32;
const MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;

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
        let mut incomplete = false;
        for file in &files {
            let Ok((text, truncated, sha256)) = read_log_bounded(file) else {
                continue;
            };
            ctx.store
                .fact(self.id(), kind::CHECKSUM)
                .subject(file.display().to_string())
                .attr("algorithm", "sha256")
                .attr("hex", sha256)
                .attr("input_kind", "runtime-log")
                .source(SourceRef::file(file.display().to_string()))
                .emit();
            emitted += 1;
            if truncated {
                incomplete = true;
                ctx.store
                    .fact(self.id(), kind::SCAN_TRUNCATED)
                    .subject(file.display().to_string())
                    .attr("layer", "log")
                    .attr(
                        "reason",
                        format!("log exceeds {MAX_LOG_BYTES} bytes; analyzed bounded tail"),
                    )
                    .attr("relevant_entry", true)
                    .source(SourceRef::file(file.display().to_string()))
                    .emit();
                emitted += 1;
            }
            scanned += 1;
            let locator = file.display().to_string();
            if ctx.target.kind.is_log() {
                emitted += emit_forensic_environment(ctx, self.id(), &text, &locator);
            }
            // Normalize flattened and multiline encodings once for every Layer-D
            // path, including the legacy crash/mod-reference facts. Otherwise
            // the RuntimeEvent graph and correlation rules could disagree about
            // the same physical log.
            let normalized_lines = runtime::expand_flattened_lines(&text);
            let source_coordinates = normalized_lines
                .iter()
                .map(|line| (line.physical_line, line.normalized_fragment))
                .collect::<Vec<_>>();
            let normalized = normalized_lines
                .into_iter()
                .map(|line| line.text.trim().to_string())
                .collect::<Vec<_>>()
                .join("\n");
            emitted += emit_runtime_events(ctx, self.id(), &text, &locator, &compiled);
            emitted +=
                emit_mod_mentions(ctx, self.id(), &normalized, &source_coordinates, &locator);
        }
        let summary = format!("{scanned} log file(s) scanned");
        if incomplete {
            CollectorOutcome::incomplete(emitted, summary)
        } else {
            CollectorOutcome::active(emitted, summary)
        }
    }
}

fn emit_forensic_environment(
    ctx: &mut CollectCtx<'_>,
    extractor: &'static str,
    text: &str,
    locator: &str,
) -> usize {
    let capture = |pattern: &str, group: usize| {
        Regex::new(pattern)
            .ok()?
            .captures(text)?
            .get(group)
            .map(|value| value.as_str().to_string())
    };
    let java = capture(
        r#"(?im)(?:Java Version|Java version|Java):\s*[\"']?([0-9][0-9A-Za-z._+-]*)"#,
        1,
    )
    .or_else(|| capture(r#"(?im)^java version\s+[\"']([^\"']+)"#, 1));
    let minecraft = capture(
        r"(?im)Loading Minecraft\s+([0-9][0-9A-Za-z._+-]*)\s+with\s+(?:NeoForge|Forge|Fabric Loader|Quilt Loader)",
        1,
    )
    .or_else(|| capture(r"(?im)Minecraft Version:\s*([^\s]+)", 1));
    let loader_candidates = [
        (
            "neoforge",
            r"(?im)(?:with\s+NeoForge|NeoForge(?: Version)?[: ]+)\s*([0-9][0-9A-Za-z._+-]*)?",
        ),
        (
            "forge",
            r"(?im)(?:with\s+Forge|Forge(?: Version)?[: ]+)\s*([0-9][0-9A-Za-z._+-]*)?",
        ),
        (
            "fabric",
            r"(?im)(?:with\s+Fabric Loader|Fabric Loader(?: Version)?[: ]+)\s*([0-9][0-9A-Za-z._+-]*)?",
        ),
        (
            "quilt",
            r"(?im)(?:with\s+Quilt Loader|Quilt Loader(?: Version)?[: ]+)\s*([0-9][0-9A-Za-z._+-]*)?",
        ),
    ];
    let loader = loader_candidates.iter().find_map(|(family, pattern)| {
        Regex::new(pattern).ok()?.captures(text).map(|captures| {
            (
                *family,
                captures.get(1).map(|value| value.as_str().to_string()),
            )
        })
    });

    let mut emitted = 0;
    if java.is_some() || minecraft.is_some() || loader.is_some() {
        let mut environment = ctx
            .store
            .fact(extractor, kind::ENVIRONMENT)
            .subject("runtime-log")
            .attr("evidence_source", "runtime-log")
            .source(SourceRef::file(locator.to_string()))
            .confidence(0.98);
        if let Some(version) = minecraft {
            environment = environment
                .attr("mc_version", version)
                .attr("mc_version_source", "runtime-log");
        }
        if let Some((family, version)) = loader {
            environment = environment
                .attr("loader", family)
                .attr("loader_source", "runtime-log");
            if let Some(version) = version {
                environment = environment.attr("loader_version", version);
            }
        }
        environment.emit();
        emitted += 1;
    }
    if let Some(java) = java {
        ctx.store
            .fact(extractor, kind::JAVA_RUNTIME)
            .subject("runtime-log")
            .attr("version", java)
            .attr("source", "runtime-log")
            .source(SourceRef::file(locator.to_string()))
            .confidence(0.98)
            .emit();
        emitted += 1;
    }
    emitted
}

fn emit_runtime_events(
    ctx: &mut CollectCtx<'_>,
    extractor: &'static str,
    text: &str,
    locator: &str,
    compiled: &[(Regex, &Pattern)],
) -> usize {
    let owners = ctx
        .store
        .by_kind(kind::PACKAGE_OWNER)
        .filter_map(|fact| {
            fact.attr("package")
                .map(|package| (package.to_string(), fact.subject.clone()))
        })
        .collect::<Vec<_>>();
    let mut emitted = 0usize;
    for event in runtime::normalize_events(text, locator) {
        let level = event.level.as_deref().unwrap_or("UNKNOWN");
        let interesting =
            matches!(level, "WARN" | "ERROR" | "FATAL") || !event.exception_chain.is_empty();
        if !interesting {
            continue;
        }
        let line = event.source_line;
        let combined = std::iter::once(event.message.as_str())
            .chain(event.continuation_lines.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        let deepest_index = event
            .exception_chain
            .iter()
            .rposition(|node| !node.suppressed);
        let deepest = deepest_index.and_then(|index| event.exception_chain.get(index));
        let crash_relevance = if deepest.is_some() && matches!(level, "ERROR" | "FATAL" | "UNKNOWN")
        {
            "causal"
        } else if matches!(level, "ERROR" | "FATAL") {
            "contributing"
        } else {
            "background"
        };
        let runtime_fact = ctx
            .store
            .fact(extractor, kind::RUNTIME_EVENT)
            .subject(event.occurrence_id.clone())
            .attr("occurrence_id", event.occurrence_id.clone())
            .attr("semantic_fingerprint", event.semantic_fingerprint.clone())
            .attr("timestamp", event.timestamp.clone().unwrap_or_default())
            .attr("thread", event.thread.clone().unwrap_or_default())
            .attr("level", level)
            .attr("logger", event.logger.clone().unwrap_or_default())
            .attr("message", truncate(&event.message, 1000))
            .attr("continuation_count", event.continuation_lines.len() as i64)
            .attr("normalized_fragment", i64::from(event.source_fragment))
            .attr("crash_relevance", crash_relevance)
            .attr(
                "relevance_score",
                if crash_relevance == "causal" {
                    100i64
                } else if crash_relevance == "contributing" {
                    65
                } else {
                    15
                },
            )
            .source(SourceRef::at_line(locator.to_string(), line))
            .confidence(1.0)
            .emit();
        emitted += 1;
        if deepest.is_some() && matches!(level, "ERROR" | "FATAL" | "UNKNOWN") {
            ctx.store
                .fact(extractor, kind::CRASH_ANCHOR)
                .subject(event.occurrence_id.clone())
                .attr("semantic_fingerprint", event.semantic_fingerprint.clone())
                .attr("normalized_fragment", i64::from(event.source_fragment))
                .attr("anchor_type", "exception-chain")
                .attr(
                    "root_cause_exception",
                    deepest
                        .map(|node| node.throwable_type.as_str())
                        .unwrap_or(""),
                )
                .attr("runtime_event_fact", runtime_fact.0 as i64)
                .source(SourceRef::at_line(locator.to_string(), line))
                .confidence(0.98)
                .emit();
            emitted += 1;
        }

        for (node_index, throwable) in event.exception_chain.iter().enumerate() {
            ctx.store
                .fact(extractor, kind::THROWABLE_NODE)
                .subject(event.occurrence_id.clone())
                .attr("semantic_fingerprint", event.semantic_fingerprint.clone())
                .attr("normalized_fragment", i64::from(event.source_fragment))
                .attr("index", node_index as i64)
                .attr("type", throwable.throwable_type.clone())
                .attr("message", throwable.message.clone().unwrap_or_default())
                .attr(
                    "cause",
                    throwable.cause.map(|index| index as i64).unwrap_or(-1),
                )
                .attr("deepest", Some(node_index) == deepest_index)
                .attr("suppressed", throwable.suppressed)
                .source(SourceRef::at_line(locator.to_string(), line))
                .confidence(1.0)
                .emit();
            emitted += 1;
            for (frame_index, frame) in throwable.frames.iter().enumerate() {
                let owner = owners
                    .iter()
                    .filter(|(package, _)| class_under_package(&frame.class, package))
                    .max_by_key(|(package, _)| package.len())
                    .map(|(_, owner)| owner.as_str())
                    .unwrap_or("");
                ctx.store
                    .fact(extractor, kind::STACK_FRAME)
                    .subject(event.occurrence_id.clone())
                    .attr("semantic_fingerprint", event.semantic_fingerprint.clone())
                    .attr("normalized_fragment", i64::from(event.source_fragment))
                    .attr("throwable_index", node_index as i64)
                    .attr("frame_index", frame_index as i64)
                    .attr("class", frame.class.clone())
                    .attr("method", frame.method.clone())
                    .attr("source", frame.source.clone().unwrap_or_default())
                    .attr("source_line", frame.line.map(i64::from).unwrap_or(-1))
                    .attr("classification", frame.classification.as_str())
                    .attr("mod_id", owner)
                    .source(SourceRef::at_line(locator.to_string(), line))
                    .confidence(if owner.is_empty() { 0.8 } else { 0.98 })
                    .emit();
                emitted += 1;
            }
        }

        let matches = compiled
            .iter()
            .filter(|(regex, _)| regex.is_match(&combined))
            .map(|(_, pattern)| *pattern)
            .collect::<Vec<_>>();
        let selected = matches
            .iter()
            .max_by_key(|pattern| signal_specificity(pattern.signal))
            .copied();
        let (sig, confidence) = selected
            .map(|pattern| (pattern.signal, 0.9))
            .or_else(|| deepest.map(|_| (signal::RUNTIME_EXCEPTION, 0.98)))
            .unwrap_or(("", 0.0));
        if !sig.is_empty() {
            let root_type = deepest
                .map(|node| node.throwable_type.as_str())
                .unwrap_or("");
            ctx.store
                .fact(extractor, kind::LOG_SIGNAL)
                .subject(sig)
                .attr("line", line as i64)
                .attr("event_id", event.occurrence_id)
                .attr("semantic_fingerprint", event.semantic_fingerprint)
                .attr("normalized_fragment", i64::from(event.source_fragment))
                .attr("event_type", sig)
                .attr("level", level)
                .attr("root_cause_exception", root_type)
                .attr("crash_relevance", crash_relevance)
                .attr(
                    "relevance_score",
                    if crash_relevance == "causal" {
                        100i64
                    } else if crash_relevance == "contributing" {
                        65
                    } else {
                        15
                    },
                )
                .attr("excerpt", truncate(&combined.replace('\n', " | "), 500))
                .source(SourceRef::at_line(locator.to_string(), line))
                .confidence(confidence)
                .emit();
            emitted += 1;
        }
    }
    emitted
}

/// Parse stack traces in one log file and emit a `log_mentions_mod` fact for each
/// distinct mod the trace structurally names (a `*.mixins.json` reference or an
/// explicit `mod 'x'` phrase). Returns the number of facts emitted.
fn emit_mod_mentions(
    ctx: &mut CollectCtx<'_>,
    extractor: &'static str,
    text: &str,
    source_coordinates: &[(u32, u32)],
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
        let (physical_line, normalized_fragment) = source_coordinates
            .get(trace.line)
            .copied()
            .unwrap_or_else(|| (u32::try_from(trace.line + 1).unwrap_or(u32::MAX), 0));
        let root = trace.caused_by.last().unwrap_or(&trace.exception);
        let root_mod = trace
            .mod_refs
            .first()
            .map(|m| m.mod_id.as_str())
            .unwrap_or("unknown");
        // Candidate culprit frame classes (non-vanilla / non-JDK), root cause first,
        // for the cross-layer `crash-blame` rule to resolve against `package_owner`.
        let frame_classes = culprit_frame_classes(&trace);
        let mut crash = ctx
            .store
            .fact(extractor, kind::LOG_CRASH)
            .subject(root.class.clone())
            .attr("root_cause_exception", root.class.clone())
            .attr("root_cause_mod", root_mod)
            .attr("phase", infer_crash_phase(&trace))
            .attr("severity", crash_severity(&root.class))
            .attr("line", i64::from(physical_line))
            .attr("normalized_fragment", i64::from(normalized_fragment));
        if !frame_classes.is_empty() {
            crash = crash.attr("frame_classes", frame_classes.join(","));
        }
        crash
            .source(SourceRef::at_line(locator.to_string(), physical_line))
            .confidence(if root_mod == "unknown" { 0.75 } else { 0.85 })
            .emit();
        emitted += 1;

        for (index, mref) in trace.mod_refs.iter().enumerate() {
            let blame_score = mention_blame_score(mref.via, index);
            let mut mention = ctx
                .store
                .fact(extractor, kind::LOG_MENTIONS_MOD)
                .subject(mref.mod_id.clone())
                .attr("via", mref.via)
                .attr("exception", trace.exception.class.clone())
                .attr("root_cause_exception", root.class.clone())
                .attr("blame_score", blame_score)
                .attr("line", i64::from(physical_line))
                .attr("normalized_fragment", i64::from(normalized_fragment))
                .source(SourceRef::at_line(locator.to_string(), physical_line))
                .confidence(blame_score as f32);
            if let Some((version, environment, capabilities)) = metadata.get(&mref.mod_id) {
                mention = mention
                    .attr("version", version.clone())
                    .attr("environment", environment.clone())
                    .attr(
                        "capabilities",
                        serde_json::to_string(capabilities).unwrap_or_default(),
                    );
            }
            mention.emit();
            emitted += 1;

            let mut error = ctx
                .store
                .fact(extractor, kind::LOG_MOD_ERROR)
                .subject(mref.mod_id.clone())
                .attr("root_cause_exception", root.class.clone())
                .attr("phase", infer_crash_phase(&trace))
                .attr("severity", crash_severity(&root.class))
                .attr("blame_score", blame_score)
                .attr("via", mref.via)
                .attr("normalized_fragment", i64::from(normalized_fragment))
                .source(SourceRef::at_line(locator.to_string(), physical_line))
                .confidence(blame_score as f32);
            if let Some((version, environment, capabilities)) = metadata.get(&mref.mod_id) {
                error = error
                    .attr("version", version.clone())
                    .attr("environment", environment.clone())
                    .attr(
                        "capabilities",
                        serde_json::to_string(capabilities).unwrap_or_default(),
                    );
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

/// The candidate culprit *class* of one stack frame (`com.foo.Bar.baz(Bar.java:9)`
/// → `com.foo.Bar`), or `None` for a vanilla/JDK/loader frame that no installed mod
/// owns. The frame-to-jar blame rule resolves these against `package_owner`.
fn frame_culprit_class(frame: &str) -> Option<&str> {
    let head = frame.split('(').next().unwrap_or(frame).trim();
    let class = &head[..head.rfind('.')?];
    if class.is_empty() {
        return None;
    }
    const VANILLA_OR_JDK: &[&str] = &[
        "java.",
        "javax.",
        "jdk.",
        "sun.",
        "net.minecraft.",
        "com.mojang.",
        "net.minecraftforge.",
        "net.neoforged.",
        "net.fabricmc.loader.",
        "org.spongepowered.",
    ];
    if VANILLA_OR_JDK.iter().any(|p| class.starts_with(p)) {
        return None;
    }
    Some(class)
}

/// Distinctive culprit frame classes across a trace (root-cause exception first,
/// then its causes), deduplicated and bounded — the input to frame-to-jar blame.
fn culprit_frame_classes(trace: &stacktrace::Stacktrace) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // Root cause's own frames are the most relevant; then the outer exceptions.
    let exceptions = trace
        .caused_by
        .iter()
        .rev()
        .chain(std::iter::once(&trace.exception));
    for ex in exceptions {
        for frame in &ex.frames {
            if let Some(class) = frame_culprit_class(frame)
                && !out.iter().any(|c| c == class)
            {
                out.push(class.to_string());
                if out.len() >= 12 {
                    return out;
                }
            }
        }
    }
    out
}

/// One matched log line: the first pattern it hit and a truncated excerpt.
#[cfg(test)]
struct LineHit {
    lineno: usize,
    signal: &'static str,
}

fn signal_specificity(signal: &str) -> u8 {
    match signal {
        signal::OUT_OF_MEMORY | signal::JVM_CRASH => 100,
        signal::MIXIN_APPLY_ERROR | signal::NATIVE_WINDOW_ERROR => 90,
        signal::RESOURCE_MODEL_FAILURE | signal::RESOURCE_BLOCKSTATE_FAILURE => 80,
        signal::NEOFORGE_LOAD_ERROR | signal::MOD_LOADING_FAILURE => 70,
        signal::CLASS_NOT_FOUND | signal::NO_CLASS_DEF_FOUND => 60,
        _ => 50,
    }
}

/// Match every line against the compiled patterns (first match wins per line),
/// returning hits in line order. Parallelised for large logs; the result is
/// order-stable and independent of the worker count.
#[cfg(test)]
fn scan_lines(
    text: &str,
    compiled: &[(Regex, &'static Pattern)],
    parallel_line_threshold: usize,
) -> Vec<LineHit> {
    use rayon::prelude::*;
    let lines: Vec<&str> = text.lines().collect();
    let match_line = |(lineno, line): (usize, &&str)| -> Option<LineHit> {
        compiled
            .iter()
            .filter(|(re, _)| re.is_match(line))
            .max_by_key(|(_, pattern)| signal_specificity(pattern.signal))
            .map(|(_, p)| LineHit {
                lineno,
                signal: p.signal,
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
        && !log_files(target).is_empty()
}

fn log_files(target: &Target) -> Vec<PathBuf> {
    if target.kind.is_log() {
        return vec![target.path.clone()];
    }
    let mut out = Vec::new();
    for root in target.candidate_roots() {
        for directory in [root.join("logs"), root.join("crash-reports")] {
            collect_log_candidates(&directory, 0, 3, &mut out);
        }
        // Some launchers and reconstructed incidents keep a useful launcher log
        // directly under the instance. Inspect direct children only.
        if let Ok(entries) = std::fs::read_dir(&root) {
            for path in entries.flatten().map(|entry| entry.path()) {
                if path.is_file() && is_direct_log_candidate(&path) {
                    out.push(path);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out.sort_by(|left, right| {
        log_priority(right)
            .cmp(&log_priority(left))
            .then_with(|| modified_time(right).cmp(&modified_time(left)))
            .then_with(|| left.cmp(right))
    });
    out.truncate(MAX_LOG_FILES);
    out
}

fn collect_log_candidates(
    directory: &Path,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<PathBuf>,
) {
    if depth > max_depth || out.len() >= MAX_LOG_FILES * 4 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for path in entries.flatten().map(|entry| entry.path()) {
        if path.is_file() && is_log_candidate(&path) {
            out.push(path);
        } else if path.is_dir() {
            collect_log_candidates(&path, depth + 1, max_depth, out);
        }
    }
}

fn is_log_candidate(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("log" | "txt")
    )
}

/// Direct instance files need stronger evidence than an extension: launchers put
/// unrelated configuration text (notably `options.txt`) beside the game.
fn is_direct_log_candidate(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.ends_with(".log")
        || ((name.starts_with("crash-")
            || name.starts_with("crash_")
            || name.contains("launcher-log"))
            && name.ends_with(".txt"))
}

fn log_priority(path: &Path) -> u8 {
    match path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
    {
        "latest.log" => 4,
        "debug.log" => 3,
        name if name.starts_with("crash-") || name.starts_with("crash_") => 2,
        _ => 1,
    }
}

fn modified_time(path: &Path) -> std::time::SystemTime {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .unwrap_or(std::time::UNIX_EPOCH)
}

fn read_log_bounded(path: &Path) -> std::io::Result<(String, bool, String)> {
    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    let truncated = length > MAX_LOG_BYTES;
    let mut digest = Sha256::new();
    let mut bytes = Vec::with_capacity(length.min(MAX_LOG_BYTES) as usize);
    if truncated {
        let mut hash_buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut hash_buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&hash_buffer[..read]);
        }
        file.seek(SeekFrom::Start(length - MAX_LOG_BYTES))?;
        file.take(MAX_LOG_BYTES).read_to_end(&mut bytes)?;
    } else {
        file.read_to_end(&mut bytes)?;
        digest.update(&bytes);
    }
    if truncated && let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
        bytes.drain(..=newline);
    }
    Ok((
        String::from_utf8_lossy(&bytes).into_owned(),
        truncated,
        format!("{:x}", digest.finalize()),
    ))
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
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        let mut out = incident_findings(ctx);
        for fact in ctx.store.by_kind(kind::LOG_SIGNAL) {
            let sig = fact.subject.as_str();
            let line = fact
                .attr_int("line")
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into());
            let excerpt = fact.attr("excerpt").unwrap_or("");
            let relevance = fact.attr("crash_relevance").unwrap_or("unknown");
            let severity = if relevance == "background" {
                signal_severity(sig).min(Severity::Note)
            } else {
                signal_severity(sig)
            };
            let occurrence = fact.attr("event_id").unwrap_or(&line);
            let represented_by_incident = ctx
                .store
                .by_kind(kind::CRASH_ANCHOR)
                .any(|anchor| anchor.subject == occurrence);
            let mut b = Finding::builder(self.id(), format!("log:{sig}:{occurrence}"))
                .severity(if represented_by_incident {
                    Severity::Note
                } else {
                    severity
                })
                .confidence(if relevance == "causal" {
                    0.98
                } else if relevance == "contributing" {
                    0.8
                } else {
                    0.45
                })
                .category(Category::Log)
                .title(signal_title(sig))
                .explanation(format!(
                    "Detected at line {line} ({relevance} to the crash): {excerpt}"
                ))
                .evidence(EvidenceEdge::subject(fact.id))
                .tag("log")
                .tag(sig)
                .tag(format!("crash-relevance:{relevance}"));
            if represented_by_incident {
                b = b
                    .visibility(FindingVisibility::ExplainOnly)
                    .tag("incident-detail");
            }
            if let Some(fix) = fix_for(sig) {
                b = b.fix(fix);
            }
            out.push(b.build());
        }
        out.extend(mod_mention_findings(ctx));
        out.extend(crash_blame_findings(ctx));
        Ok(out)
    }
}

fn incident_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for anchor in ctx.store.by_kind(kind::CRASH_ANCHOR) {
        let event_id = anchor.subject.as_str();
        let event = ctx
            .store
            .by_kind(kind::RUNTIME_EVENT)
            .find(|fact| fact.subject == event_id);
        let throwable = ctx
            .store
            .by_kind(kind::THROWABLE_NODE)
            .filter(|fact| fact.subject == event_id)
            .find(|fact| fact.attr_bool("deepest") == Some(true));
        let Some(root) = throwable else {
            continue;
        };
        let root_type = root.attr("type").unwrap_or("Throwable");
        let message = root.attr("message").unwrap_or("");
        let outer = ctx
            .store
            .by_kind(kind::THROWABLE_NODE)
            .filter(|fact| fact.subject == event_id)
            .min_by_key(|fact| fact.attr_int("index").unwrap_or(i64::MAX))
            .and_then(|fact| fact.attr("type"))
            .unwrap_or(root_type);

        let mut frames = ctx
            .store
            .by_kind(kind::STACK_FRAME)
            .filter(|fact| fact.subject == event_id)
            .collect::<Vec<_>>();
        frames.sort_by_key(|fact| {
            (
                fact.attr_int("throwable_index").unwrap_or(i64::MAX),
                fact.attr_int("frame_index").unwrap_or(i64::MAX),
            )
        });
        let mut callee_to_caller = Vec::<String>::new();
        for frame in &frames {
            let Some(mod_id) = frame.attr("mod_id").filter(|id| !id.is_empty()) else {
                continue;
            };
            if callee_to_caller.last().is_none_or(|last| last != mod_id) {
                callee_to_caller.push(mod_id.to_string());
            }
        }
        let mut caller_to_callee = callee_to_caller.clone();
        caller_to_callee.reverse();
        let ownership = if caller_to_callee.is_empty() {
            "No frame could be assigned to an installed artifact.".to_string()
        } else {
            format!(
                "The ownership path from caller to callee is {}.",
                caller_to_callee.join(" -> ")
            )
        };
        let wrapper = if outer != root_type {
            format!(" `{outer}` is retained as the outer runtime context, not the root cause.")
        } else {
            String::new()
        };
        let fatal = root_type.contains("OutOfMemory") || root_type.contains("VirtualMachineError");
        let mut finding = Finding::builder("log-signal", format!("incident:{event_id}"))
            .severity(if fatal {
                Severity::Fatal
            } else {
                Severity::Error
            })
            .confidence(0.99)
            .category(Category::Log)
            .title(format!(
                "Primary crash cause: {root_type}{}",
                if message.is_empty() {
                    String::new()
                } else {
                    format!(": {message}")
                }
            ))
            .explanation(format!(
                "The deepest causal exception is `{root_type}`{}.{wrapper} {ownership}",
                if message.is_empty() {
                    String::new()
                } else {
                    format!(" with message `{message}`")
                }
            ))
            .evidence(EvidenceEdge::subject(anchor.id))
            .evidence(EvidenceEdge::supports(root.id))
            .tag("incident")
            .tag("crash-relevance:causal")
            .tag("exception-chain");
        if let Some(event) = event {
            finding = finding.evidence(EvidenceEdge::supports(event.id));
        }
        for frame in frames.iter().take(12) {
            finding = finding.evidence(EvidenceEdge::supports(frame.id));
        }
        if root_type.contains("IllegalStateException")
            && message.to_ascii_lowercase().contains("off-thread")
        {
            finding = finding.fix(FixCandidate::advice(
                "Inspect the first mod-owned caller for an API call made from the wrong thread; \
                 verify thread confinement before changing dependency versions.",
            ));
        }
        if root_type.contains("OutOfMemory") {
            finding = finding.tag(signal::OUT_OF_MEMORY);
        }
        out.push(finding.build());
    }
    out
}

/// `true` when `class` lives under (or is) package `pkg`, e.g. `com.foo.M.X` under
/// `com.foo.M`. Allocation-free prefix test.
fn class_under_package(class: &str, pkg: &str) -> bool {
    class == pkg
        || (class.len() > pkg.len()
            && class.as_bytes()[pkg.len()] == b'.'
            && class.starts_with(pkg))
}

/// Frame-to-jar blame (Layer D ↔ B): resolve a crash's stack-frame classes against
/// the `package_owner` ownership index. A frame under an *exclusively*-owned package
/// names the mod whose code is on the failing path — precise blame the heuristic log
/// scan can only guess. A frame under a package owned by ≥2 mods (a shaded/bundled
/// library) is *ambiguous*: surfaced quietly as candidates, never as a confident blame.
fn crash_blame_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    use std::collections::{BTreeMap, BTreeSet};

    // package -> owning mods (with one evidence fact id each).
    let mut owners: BTreeMap<&str, BTreeMap<&str, FactId>> = BTreeMap::new();
    for f in ctx.store.by_kind(kind::PACKAGE_OWNER) {
        if let Some(pkg) = f.attr("package") {
            owners
                .entry(pkg)
                .or_default()
                .entry(f.subject.as_str())
                .or_insert(f.id);
        }
    }
    if owners.is_empty() {
        return Vec::new();
    }

    // Dedup blame per mod (a mod blamed by several crashes → one finding) and per
    // ambiguous frame class.
    let mut blamed: BTreeMap<&str, (&str, FactId, FactId)> = BTreeMap::new(); // mod -> (class, owner_fact, crash_fact)
    let mut ambiguous: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new(); // class -> mods

    for crash in ctx.store.by_kind(kind::LOG_CRASH) {
        let Some(frames) = crash.attr("frame_classes") else {
            continue;
        };
        for class in frames.split(',').filter(|c| !c.is_empty()) {
            // Most specific (longest) owning package for this frame class.
            let best = owners
                .iter()
                .filter(|(pkg, _)| class_under_package(class, pkg))
                .max_by_key(|(pkg, _)| pkg.len());
            let Some((_, mods)) = best else {
                continue;
            };
            if mods.len() == 1 {
                let (&mod_id, &owner_fact) = mods.iter().next().unwrap();
                // Keep the deepest (root-cause-first) blame per mod.
                blamed
                    .entry(mod_id)
                    .or_insert((class, owner_fact, crash.id));
                break; // this crash's culprit found
            }
            ambiguous
                .entry(class)
                .or_default()
                .extend(mods.keys().copied());
        }
    }

    let mut out = Vec::new();
    for (mod_id, (class, owner_fact, crash_fact)) in blamed {
        out.push(
            Finding::builder("log-signal", format!("crash-blame:{mod_id}"))
                .severity(Severity::Warn)
                .category(Category::Log)
                .title(format!("Crash stack runs through `{mod_id}`'s code"))
                .explanation(format!(
                    "The crash's stack trace passes through `{class}`, a class shipped exclusively \
                     by `{mod_id}` (frame-to-jar ownership). This mod's code is on the failing path \
                     — a precise triage lead the heuristic log scan can only approximate. It may be \
                     the cause or a victim of an upstream mod; start the investigation here."
                ))
                .evidence(EvidenceEdge::subject(crash_fact))
                .evidence(EvidenceEdge::supports(owner_fact))
                .affects(mod_id.to_string())
                .fix(FixCandidate::advice(
                    "Inspect this mod around the named class; reproduce with it removed to confirm \
                     cause vs. victim.",
                ))
                .tag("log")
                .tag("crash-blame")
                .tag("frame-to-jar")
                // Machine-readable resolved frame class — lets `lab eval` join this
                // blame against a ground-truth crash attribution by exact class, for
                // calibrated blame-precision measurement.
                .tag(format!("frame-class:{class}"))
                .confidence(0.9)
                .build(),
        );
    }
    for (class, mods) in ambiguous {
        // Only when no exclusive blame already named one of these mods.
        if mods
            .iter()
            .any(|m| out.iter().any(|f| f.id == format!("crash-blame:{m}")))
        {
            continue;
        }
        let list: Vec<&str> = mods.iter().copied().collect();
        out.push(
            Finding::builder("log-signal", format!("crash-blame-ambiguous:{class}"))
                .severity(Severity::Note)
                .category(Category::Log)
                .title(format!("Crash stack runs through shared code `{class}`"))
                .explanation(format!(
                    "The crash passes through `{class}`, which is shipped by multiple mods ({}) — \
                     typically a shaded/bundled library. Ownership is ambiguous, so this is a weak \
                     lead: one of these mods bundles the failing code.",
                    list.join(", ")
                ))
                .tag("log")
                .tag("crash-blame")
                .tag("ambiguous")
                .confidence(0.4)
                .build(),
        );
    }
    out
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
        signal::IRIS_SHADER_ERROR => FixCandidate::advice(
            "Install a compatible Sodium build and matching Iris/shader pack versions.",
        ),
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
        assert!(
            report.findings[0]
                .machine_tags
                .iter()
                .any(|t| t == signal::OUT_OF_MEMORY)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn normal_create_info_is_not_failure_and_model_error_has_resource_taxonomy() {
        let dir = std::env::temp_dir().join(format!("imd-log-taxonomy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("latest.log");
        std::fs::write(
            &log,
            "[12:00:00] [Render thread/INFO]: Create 6.0.10 initializing!\n\
             [12:00:01] [Render thread/INFO]: Loaded 61 train hat configurations\n\
             [12:00:02] [Render thread/ERROR]: ModelManager: Failed to load model create_radar:block/foo\n",
        )
        .unwrap();
        let report = DiagnosticEngine::builder()
            .collector(LogCollector)
            .rule(LogSignalRule)
            .build()
            .diagnose(&Target::with_kind(log.clone(), TargetKind::LogFile));
        assert!(report.findings.iter().all(|finding| {
            !finding
                .machine_tags
                .iter()
                .any(|tag| tag == signal::CREATE_ERROR || tag == signal::MOD_LOADING_FAILURE)
        }));
        assert!(report.findings.iter().any(|finding| {
            finding
                .machine_tags
                .iter()
                .any(|tag| tag == signal::RESOURCE_MODEL_FAILURE)
        }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn forensic_log_environment_outranks_analyzer_host() {
        let dir = std::env::temp_dir().join(format!("imd-log-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("latest.log");
        std::fs::write(
            &log,
            "Java Version: 21.0.7\nLoading Minecraft 1.21.1 with NeoForge 21.1.248\n",
        )
        .unwrap();
        let report = DiagnosticEngine::builder()
            .collector(LogCollector)
            .build()
            .diagnose(&Target::with_kind(log, TargetKind::LogFile));
        assert_eq!(report.environment.java_version.as_deref(), Some("21.0.7"));
        assert_eq!(
            report.environment.minecraft_version.as_deref(),
            Some("1.21.1")
        );
        assert_eq!(
            report.environment.loader,
            Some(intermed_doctor_core::Loader::NeoForge)
        );
        assert_eq!(
            report.environment.loader_source.as_deref(),
            Some("runtime-log")
        );
        std::fs::remove_dir_all(dir).ok();
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
            report
                .findings
                .iter()
                .any(|f| f.id == "log-mentions-mod:examplemod"
                    && f.machine_tags.iter().any(|t| t == "mod-mention")),
            "expected a mod-mention finding for examplemod: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn crash_emits_root_cause_and_weighted_mod_error_facts() {
        use intermed_doctor_core::facts::FactStore;
        use intermed_doctor_core::{CollectCtx, Collector, default_settings};

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
        assert_eq!(
            crash.attr("root_cause_exception"),
            Some("java.lang.NullPointerException")
        );
        assert_eq!(crash.attr("root_cause_mod"), Some("alpha"));
        let error = store
            .by_kind(kind::LOG_MOD_ERROR)
            .next()
            .expect("log_mod_error");
        assert_eq!(error.subject, "alpha");
        assert_eq!(error.attr("version"), Some("1.2.3"));
        assert!(error.attr_f64("blame_score").unwrap() >= 0.9);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn incident_ranks_deepest_runtime_cause_and_mod_transition() {
        use intermed_doctor_core::facts::FactStore;
        use intermed_doctor_core::{CollectCtx, Collector, Rule, RuleCtx, default_settings};

        let dir = std::env::temp_dir().join(format!("imd-causal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("latest.log");
        std::fs::write(
            &log,
            "[12:00:00] [Render thread/ERROR]: net.minecraft.ReportedException: charTyped event handler\n\
             \tat com.simibubi.create.AllKeys.isKeyDown(AllKeys.java:10)\n\
             \tat com.createdieselgenerators.EntityFilterItem.appendHoverText(EntityFilterItem.java:42)\n\
             Caused by: java.lang.IllegalStateException: Encountered GL error off-thread GLFW 65539\n\
             \tat com.simibubi.create.AllKeys.shiftDown(AllKeys.java:11)\n",
        )
        .unwrap();
        let target = Target::with_kind(log, TargetKind::LogFile);
        let mut store = FactStore::new();
        for (mod_id, package) in [
            ("create", "com.simibubi.create"),
            ("createdieselgenerators", "com.createdieselgenerators"),
        ] {
            store
                .fact("metadata", kind::PACKAGE_OWNER)
                .subject(mod_id)
                .attr("package", package)
                .emit();
        }
        let mut collect = CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: default_settings(),
        };
        LogCollector.collect(&mut collect);
        let findings = LogSignalRule
            .evaluate(&RuleCtx::for_test(&store, &target))
            .unwrap();
        let incident = findings
            .iter()
            .find(|finding| finding.id.starts_with("incident:"))
            .expect("incident conclusion");
        assert!(incident.title.contains("IllegalStateException"));
        assert!(incident.explanation.contains("ReportedException"));
        assert!(incident.explanation.contains("create"));
        assert!(incident.explanation.contains("createdieselgenerators"));
        assert!(incident.confidence >= 0.98);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn flattened_runtime_facts_preserve_physical_source_line() {
        use intermed_doctor_core::facts::FactStore;
        use intermed_doctor_core::{CollectCtx, Collector, default_settings};

        let dir = std::env::temp_dir().join(format!("imd-flat-line-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("latest.log");
        std::fs::write(
            &log,
            "[12:00:00] [main/ERROR]: java.lang.RuntimeException: outer at com.example.Mod.run(Mod.java:1) Caused by: java.lang.IllegalStateException: root at com.example.Mod.root(Mod.java:2)",
        )
        .unwrap();
        let target = Target::with_kind(log, TargetKind::LogFile);
        let mut store = FactStore::new();
        let mut collect = CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: default_settings(),
        };
        LogCollector.collect(&mut collect);
        let runtime_kinds = [
            kind::RUNTIME_EVENT,
            kind::CRASH_ANCHOR,
            kind::THROWABLE_NODE,
            kind::STACK_FRAME,
            kind::LOG_CRASH,
        ];
        let facts = runtime_kinds
            .iter()
            .flat_map(|kind| store.by_kind(kind))
            .collect::<Vec<_>>();
        assert!(!facts.is_empty());
        assert!(facts.iter().all(|fact| fact.source.line == Some(1)));
        assert!(
            facts
                .iter()
                .all(|fact| fact.attr_int("normalized_fragment") == Some(0))
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn repeated_incidents_from_different_files_do_not_merge() {
        use intermed_doctor_core::facts::FactStore;
        use intermed_doctor_core::{CollectCtx, Collector, Rule, RuleCtx, default_settings};

        let dir = std::env::temp_dir().join(format!("imd-repeat-{}", std::process::id()));
        let logs = dir.join("logs");
        let crashes = dir.join("crash-reports");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::create_dir_all(&crashes).unwrap();
        let event = "[12:00:00] [main/ERROR]: java.lang.IllegalStateException: repeated\n";
        std::fs::write(logs.join("latest.log"), event).unwrap();
        std::fs::write(crashes.join("crash-repeat.txt"), event).unwrap();
        let target = Target::with_kind(&dir, TargetKind::Instance);
        let mut store = FactStore::new();
        let mut collect = CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: default_settings(),
        };
        LogCollector.collect(&mut collect);
        let events = store.by_kind(kind::RUNTIME_EVENT).collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert_ne!(events[0].subject, events[1].subject);
        assert_eq!(
            events[0].attr("semantic_fingerprint"),
            events[1].attr("semantic_fingerprint")
        );
        let findings = LogSignalRule
            .evaluate(&RuleCtx::for_test(&store, &target))
            .unwrap();
        let incident_ids = findings
            .iter()
            .filter(|finding| finding.id.starts_with("incident:"))
            .map(|finding| finding.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(incident_ids.len(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn installed_mod_mention_is_warn_uninstalled_is_note() {
        use intermed_doctor_core::RuleCtx;
        use intermed_doctor_core::facts::FactStore;

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
    fn frame_culprit_class_extracts_mod_classes_and_skips_vanilla() {
        assert_eq!(
            frame_culprit_class("com.simibubi.create.Foo.tick(Foo.java:9)"),
            Some("com.simibubi.create.Foo")
        );
        assert_eq!(
            frame_culprit_class(
                "net.minecraft.server.MinecraftServer.tick(MinecraftServer.java:1)"
            ),
            None
        );
        assert_eq!(
            frame_culprit_class("java.lang.Thread.run(Thread.java:1)"),
            None
        );
        assert_eq!(frame_culprit_class("NoDotsHere"), None);
    }

    fn blame_target() -> Target {
        Target {
            path: ".".into(),
            kind: TargetKind::LogFile,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        }
    }

    #[test]
    fn exclusive_package_owner_yields_high_confidence_crash_blame() {
        use intermed_doctor_core::RuleCtx;
        use intermed_doctor_core::facts::FactStore;
        let mut store = FactStore::new();
        store
            .fact("metadata-scanner", kind::PACKAGE_OWNER)
            .subject("create")
            .attr("package", "com.simibubi.create")
            .emit();
        store
            .fact("log-analyzer", kind::LOG_CRASH)
            .subject("java.lang.NullPointerException")
            .attr(
                "frame_classes",
                "com.simibubi.create.content.Foo,com.othermod.Bar",
            )
            .emit();
        let target = blame_target();
        let findings = crash_blame_findings(&RuleCtx::for_test(&store, &target));
        let f = findings
            .iter()
            .find(|f| f.id == "crash-blame:create")
            .expect("exclusive blame finding");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.confidence >= 0.85);
        assert!(f.machine_tags.iter().any(|t| t == "frame-to-jar"));
    }

    #[test]
    fn shared_package_owner_is_ambiguous_not_a_confident_blame() {
        use intermed_doctor_core::RuleCtx;
        use intermed_doctor_core::facts::FactStore;
        let mut store = FactStore::new();
        // Two mods ship the same shaded library package.
        for m in ["moda", "modb"] {
            store
                .fact("metadata-scanner", kind::PACKAGE_OWNER)
                .subject(m)
                .attr("package", "com.google.gson")
                .emit();
        }
        store
            .fact("log-analyzer", kind::LOG_CRASH)
            .subject("java.lang.IllegalStateException")
            .attr("frame_classes", "com.google.gson.Gson")
            .emit();
        let target = blame_target();
        let findings = crash_blame_findings(&RuleCtx::for_test(&store, &target));
        assert!(
            !findings
                .iter()
                .any(|f| f.id.starts_with("crash-blame:moda")
                    || f.id.starts_with("crash-blame:modb")),
            "ambiguous ownership must not produce a confident blame"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.id.starts_with("crash-blame-ambiguous:")),
            "ambiguous ownership should surface a weak lead"
        );
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
#[test]
fn direct_text_discovery_rejects_options_but_accepts_crash_reports() {
    assert!(!is_direct_log_candidate(Path::new("options.txt")));
    assert!(is_direct_log_candidate(Path::new("latest.log")));
    assert!(is_direct_log_candidate(Path::new(
        "crash-2026-08-14_12.00.00-client.txt"
    )));
}
