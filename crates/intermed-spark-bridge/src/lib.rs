//! # intermed-spark-bridge — Layer I (Phase 7)
//!
//! Performance evidence importer. Reads `intermed-spark-report-v1` JSON (exported
//! from Spark or hand-authored fixtures) — never forks or runs the Spark profiler.

mod config;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use intermed_doctor_core::evidence::{
    Category, CoverageRequirement, EvidenceEdge, EvidenceOrigin, Finding, FindingChannel,
    FindingVisibility, FixCandidate, Impact, ProofKind, Relation, Severity,
};
use intermed_doctor_core::facts::{SourceRef, kind};
use intermed_doctor_core::{CollectCtx, Collector, CollectorOutcome, Layer, Rule, RuleCtx, Target};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const EXTRACTOR: &str = "spark-importer";
pub const SPARK_REPORT_SCHEMA: &str = "intermed-spark-report-v1";

/// Complete collector output contract. Keeping the declaration next to the
/// emitter prevents a successful or failed import path from drifting out of
/// `CollectorScope::produces`.
const SPARK_OUTPUT_KINDS: &[&str] = &[
    kind::TICK_SPIKE,
    kind::GC_PAUSE,
    kind::HEAP_PRESSURE,
    kind::HOT_METHOD,
    kind::HOT_MOD,
    kind::THREAD_HOTSPOT,
    kind::SPARK_IMPORT_FAILURE,
];

/// Implementation status for help text.
pub const STATUS: &str = "active: Phase 7";

/// Layer-I collector.
pub fn collector() -> impl Collector {
    SparkCollector
}

pub use config::{
    DEFAULT_HIGH_CPU_PERCENT, DEFAULT_HOT_METHOD_FLOOR_PERCENT, DEFAULT_TICK_SPIKE_MS,
    PerformanceThresholds,
};

/// Layer-I performance correlation rule (default thresholds).
pub fn rule() -> impl Rule {
    rule_with_thresholds(PerformanceThresholds::default())
}

/// Layer-I performance correlation rule with explicit thresholds.
pub fn rule_with_thresholds(thresholds: PerformanceThresholds) -> impl Rule {
    PerformanceRules { thresholds }
}

/// Correlation plus user-visible notices when Spark data is missing or failed.
struct PerformanceRules {
    thresholds: PerformanceThresholds,
}

impl Rule for PerformanceRules {
    fn id(&self) -> &'static str {
        "performance"
    }

    fn requirements(&self) -> intermed_doctor_core::RuleRequirements {
        intermed_doctor_core::RuleRequirements::default()
            // Layer-I has several independent entry points (tick-only,
            // heap-only, import failure, hot method, ...), so no single fact is
            // universally required. Runtime profile observations are optional
            // inputs; the other predicates provide typed cross-layer context.
            .optional_facts([
                kind::HOT_METHOD,
                kind::HOT_MOD,
                kind::TICK_SPIKE,
                kind::GC_PAUSE,
                kind::HEAP_PRESSURE,
                kind::THREAD_HOTSPOT,
                kind::SPARK_IMPORT_FAILURE,
            ])
            .context_facts([
                kind::MIXIN_APPLICATION_SITE,
                kind::MIXIN_TARGET,
                kind::MIXIN_OPERATION,
                kind::MIXIN_OVERLAP,
                kind::HIGH_RISK_OVERWRITE,
                kind::MIXIN_HOTSPOT,
                kind::MOD_CAPABILITY,
                kind::RESOURCE_COLLISION,
                kind::RESOURCE_WRITER,
                kind::LOG_SIGNAL,
                kind::LOG_MENTIONS_MOD,
                kind::STACK_FRAME,
                kind::THROWABLE_NODE,
                kind::MOD,
                kind::PLUGIN,
            ])
            .layers([
                Layer::Performance,
                Layer::Mixin,
                Layer::Resource,
                Layer::Log,
            ])
            .regions([
                intermed_doctor_core::TargetRegion::RuntimeProfile,
                intermed_doctor_core::TargetRegion::ModClasspath,
                intermed_doctor_core::TargetRegion::Logs,
            ])
            .coverage([
                CoverageRequirement::RuntimeProfile,
                CoverageRequirement::LocalArtifact,
            ])
            .proofs([
                ProofKind::Observation,
                ProofKind::DeterministicDerivation,
                ProofKind::Heuristic,
            ])
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        self.thresholds
            .validate()
            .map_err(|error| intermed_doctor_core::RuleError::new(error.to_string()))?;
        let mut out = PerformanceCorrelationRule {
            thresholds: self.thresholds,
        }
        .evaluate(ctx)?;
        out.extend(perf_tick_mixin_hotpath_findings(ctx));
        out.extend(perf_hot_mod_resource_findings(ctx, self.thresholds));
        out.extend(perf_resource_category_hotspot_findings(
            ctx,
            self.thresholds,
        ));
        out.extend(perf_hot_method_log_findings(ctx, self.thresholds));
        out.extend(perf_runtime_observation_findings(ctx, self.thresholds));
        out.extend(performance_notice_findings(ctx));
        out.extend(performance_fallback_findings(ctx));
        out.extend(perf_log_correlation_findings(ctx));
        out.extend(perf_tick_log_correlation_findings(ctx));
        out.extend(perf_tick_heavy_handler_findings(ctx));
        apply_performance_taxonomy(&mut out);
        Ok(out)
    }
}

fn apply_performance_taxonomy(findings: &mut [Finding]) {
    for finding in findings {
        if finding
            .machine_tags
            .iter()
            .any(|tag| tag == "performance-observation")
        {
            finding.family = "performance-observation".to_string();
            finding.proof_kind.get_or_insert(ProofKind::Observation);
        } else if finding
            .machine_tags
            .iter()
            .any(|tag| tag == "performance-diagnosis")
        {
            finding.family = "performance-diagnosis".to_string();
            finding
                .proof_kind
                .get_or_insert(ProofKind::DeterministicDerivation);
        } else if finding.machine_tags.iter().any(|tag| {
            matches!(
                tag.as_str(),
                "performance-correlation" | "performance-candidate" | "performance-context"
            )
        }) {
            finding.family = "performance-correlation".to_string();
            if finding.machine_tags.iter().any(|tag| {
                matches!(
                    tag.as_str(),
                    "performance-candidate" | "performance-context"
                )
            }) {
                finding.proof_kind = Some(ProofKind::Heuristic);
            } else {
                finding
                    .proof_kind
                    .get_or_insert(ProofKind::DeterministicDerivation);
            }
        }
    }
}

/// Static tick-handler candidates shown alongside a measured spike. The two
/// observations are not runtime attribution and therefore never become a hard
/// suspect without a matching sampled method.
fn perf_tick_heavy_handler_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    if ctx.store.by_kind(kind::TICK_SPIKE).next().is_none() {
        return Vec::new();
    }

    // mod id -> (has heavy tick handler, capability fact ids)
    let mut tick_mods: std::collections::BTreeMap<&str, (bool, Vec<_>)> =
        std::collections::BTreeMap::new();
    for f in ctx.store.by_kind(kind::MOD_CAPABILITY) {
        let cap = f.attr("capability").unwrap_or("");
        let heavy = cap == "heavy_tick_handler";
        if heavy || cap == "hooks_game_tick" {
            let entry = tick_mods
                .entry(f.subject.as_str())
                .or_insert((false, Vec::new()));
            entry.0 |= heavy;
            entry.1.push(f.id);
        }
    }
    if tick_mods.is_empty() {
        return Vec::new();
    }

    let spike_facts: Vec<_> = ctx.store.by_kind(kind::TICK_SPIKE).map(|f| f.id).collect();
    let mut out = Vec::new();
    for (mod_id, (heavy, cap_ids)) in tick_mods {
        let severity = Severity::Note;
        let what = if heavy {
            "a heavy tick-event handler (large / looping / allocating bytecode)"
        } else {
            "a tick-event subscription"
        };
        let mut builder = Finding::builder("performance", format!("perf-tick-handler:{mod_id}"))
            .severity(severity)
            .category(Category::Performance)
            .title(format!(
                "`{mod_id}` runs on the game tick and the server has tick spikes"
            ))
            .explanation(format!(
                "Spark recorded server tick spikes, and bytecode analysis shows `{mod_id}` has {what}. \
                 This is a static candidate, not runtime attribution: the Spark data does not identify \
                 this handler. Profile it directly before treating the mod as a cause."
            ))
            .affects(mod_id.to_string())
            .fix(FixCandidate::advice(
                "Profile or temporarily remove this mod to confirm; if it is the cause, check its config \
                 for a way to reduce per-tick work, or report the hotspot upstream.",
            ))
            .tag("performance")
            .tag("tick")
            .tag("capability")
            .tag("performance-candidate");
        if !heavy {
            builder = builder.visibility(FindingVisibility::ExplainOnly);
        }
        for id in cap_ids {
            builder = builder.evidence(EvidenceEdge::supports(id));
        }
        for id in &spike_facts {
            builder = builder.evidence(EvidenceEdge::new(*id, Relation::CorrelatesWith, 0.7));
        }
        out.push(builder.build());
    }
    out
}

fn perf_log_correlation_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    use std::collections::BTreeMap;

    // hot mod id -> (percent, fact id)
    let hot: BTreeMap<&str, (f64, _)> = ctx
        .store
        .by_kind(kind::HOT_MOD)
        .map(|f| {
            let pct = f.attr_f64("percent").unwrap_or(0.0);
            (f.subject.as_str(), (pct, f.id))
        })
        .collect();
    if hot.is_empty() {
        return Vec::new();
    }

    let mut mentions: BTreeMap<&str, Vec<&intermed_doctor_core::facts::Fact>> = BTreeMap::new();
    for f in ctx.store.by_kind(kind::LOG_MENTIONS_MOD) {
        mentions.entry(f.subject.as_str()).or_default().push(f);
    }

    let mut out = Vec::new();
    for (mod_id, (percent, hot_fact)) in &hot {
        let Some(mention_facts) = mentions.get(mod_id) else {
            continue;
        };
        let exceptions: std::collections::BTreeSet<&str> = mention_facts
            .iter()
            .filter_map(|f| f.attr("exception"))
            .collect();
        let same_session = mention_facts
            .iter()
            .any(|mention| facts_share_session(ctx.store.get(*hot_fact), Some(mention)));
        let mut builder = Finding::builder(
            "performance",
            format!("perf-log-suspect:{}:{mod_id}", hot_fact.0),
        )
        .semantic_id(format!("perf-log-suspect:{mod_id}"))
        .occurrence_id(format!("spark-fact:{}", hot_fact.0))
        .severity(Severity::Note)
        .category(Category::Performance)
        .channel(FindingChannel::Informational)
        .title(format!("`{mod_id}` appears in both a CPU profile and error logs"))
        .explanation(format!(
            "Spark attributes {percent:.1}% of profiled time to `{mod_id}`, and it is also \
             named in {} crash/error stack trace(s){}. {}",
            mention_facts.len(),
            if exceptions.is_empty() {
                String::new()
            } else {
                format!(" ({})", exceptions.into_iter().collect::<Vec<_>>().join(", "))
            },
            if same_session {
                "The inputs declare the same session; this is a correlation, not proof of causation."
            } else {
                "No shared session or temporal identity was available, so these observations must not be treated as causal."
            },
        ))
        .evidence(EvidenceEdge::subject(*hot_fact))
        .affects(mod_id.to_string())
        .fix(FixCandidate::advice(
            "Capture the profile and log from the same run, then inspect exact stack frames before changing the pack.",
        ))
        .tag("performance")
        .tag("log")
        .tag("correlation")
        .tag("performance-context");
        if !same_session {
            builder = builder.visibility(FindingVisibility::ExplainOnly);
        }
        for f in mention_facts {
            builder = builder.evidence(EvidenceEdge::supports(f.id));
        }
        out.push(builder.build());
    }
    out
}

/// Tick and log context. Without a shared session/timeline this is deliberately
/// explain-only: mod-name co-occurrence is not a causal join.
fn perf_tick_log_correlation_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let has_spike = ctx.store.by_kind(kind::TICK_SPIKE).next().is_some();
    if !has_spike {
        return Vec::new();
    }

    let installed: std::collections::BTreeSet<&str> = ctx
        .store
        .by_kind(kind::MOD)
        .chain(ctx.store.by_kind(kind::PLUGIN))
        .map(|f| f.subject.as_str())
        .collect();

    let error_signals: std::collections::BTreeSet<&str> = ctx
        .store
        .by_kind(kind::LOG_SIGNAL)
        .filter(|f| {
            matches!(
                f.subject.as_str(),
                "MixinApplyError"
                    | "ModLoadingFailure"
                    | "MissingDependency"
                    | "ClassNotFound"
                    | "NoClassDefFound"
            )
        })
        .map(|f| f.subject.as_str())
        .collect();

    let mut by_mod: std::collections::BTreeMap<&str, Vec<&intermed_doctor_core::facts::Fact>> =
        std::collections::BTreeMap::new();
    for f in ctx.store.by_kind(kind::LOG_MENTIONS_MOD) {
        by_mod.entry(f.subject.as_str()).or_default().push(f);
    }

    let mut out = Vec::new();
    for (mod_id, mentions) in by_mod {
        if !installed.contains(mod_id) {
            continue;
        }
        let exceptions: std::collections::BTreeSet<&str> = mentions
            .iter()
            .filter_map(|f| f.attr("exception"))
            .collect();
        let same_session = ctx.store.by_kind(kind::TICK_SPIKE).any(|spike| {
            mentions
                .iter()
                .any(|mention| facts_share_session(Some(spike), Some(mention)))
        });
        let mut builder = Finding::builder(
            "performance",
            format!("perf-tick-log-suspect:{mod_id}"),
        )
        .severity(Severity::Note)
        .category(Category::Performance)
        .channel(FindingChannel::Informational)
        .title(format!(
            "Tick spikes and log mentions both involve `{mod_id}`"
        ))
        .explanation(format!(
            "Spark reported server tick spikes and `{mod_id}` is named in {} crash/error \
             stack trace(s){}. {}",
            mentions.len(),
            if exceptions.is_empty() {
                String::new()
            } else {
                format!(" ({})", exceptions.into_iter().collect::<Vec<_>>().join(", "))
            },
            if same_session {
                "The evidence is from the same declared session, but does not identify the expensive frame."
            } else {
                "The inputs have no shared session/timestamp, so this is navigation context only."
            },
        ))
        .affects(mod_id.to_string())
        .fix(FixCandidate::advice(format!(
            "Update or temporarily remove `{mod_id}`, then re-profile and re-check logs."
        )))
        .tag("performance")
        .tag("log")
        .tag("tick")
        .tag("correlation")
        .tag("performance-context");
        if !same_session {
            builder = builder.visibility(FindingVisibility::ExplainOnly);
        }
        for f in mentions {
            builder = builder.evidence(EvidenceEdge::supports(f.id));
        }
        for spike in ctx.store.by_kind(kind::TICK_SPIKE) {
            builder = builder.evidence(EvidenceEdge::supports(spike.id));
        }
        if !error_signals.is_empty() {
            builder = builder.tag("log-error");
        }
        out.push(builder.build());
    }
    out
}

/// Parsed spark report (import format).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SparkReport {
    pub schema: String,
    /// Producer supplied label. It is not used as physical provenance.
    #[serde(default)]
    pub source: String,
    /// Optional stable session identity shared with other evidence sources.
    #[serde(default)]
    pub session_fingerprint: Option<String>,
    /// Concrete file read by InterMed. Populated by [`import_file`] and never
    /// accepted from untrusted JSON.
    #[serde(default, skip_deserializing)]
    pub source_locator: String,
    #[serde(default)]
    pub tick_spikes_ms: Vec<u64>,
    #[serde(default)]
    pub gc_pauses_ms: Vec<u64>,
    #[serde(default)]
    pub heap_pressure_bytes: Option<u64>,
    #[serde(default)]
    pub hot_methods: Vec<HotMethod>,
    #[serde(default)]
    pub hot_mods: Vec<HotMod>,
    #[serde(default)]
    pub thread_hotspots: Vec<ThreadHotspot>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HotMethod {
    pub class: String,
    pub method: String,
    pub percent: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HotMod {
    pub r#mod: String,
    pub percent: f64,
    /// Optional profiler phase (`worldgen`, `resource-reload`, `model-bake`, ...).
    #[serde(default)]
    pub phase: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadHotspot {
    pub thread: String,
    pub percent: f64,
}

/// Import failure for one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkImportFailure {
    pub path: String,
    pub reason: String,
}

/// Aggregated import result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SparkImport {
    pub target: String,
    pub reports: Vec<SparkReport>,
    pub failures: Vec<SparkImportFailure>,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SparkImportError(String);

fn validate_percent(field: &str, value: f64) -> Result<(), SparkImportError> {
    if value.is_finite() && (0.0..=100.0).contains(&value) {
        Ok(())
    } else {
        Err(SparkImportError(format!(
            "{field} must be a finite percentage in 0..=100 (got {value})"
        )))
    }
}

fn validate_report(report: &SparkReport) -> Result<(), SparkImportError> {
    for (index, value) in report.tick_spikes_ms.iter().enumerate() {
        i64::try_from(*value).map_err(|_| {
            SparkImportError(format!(
                "tick_spikes_ms[{index}] exceeds the supported signed 64-bit range"
            ))
        })?;
    }
    for (index, value) in report.gc_pauses_ms.iter().enumerate() {
        i64::try_from(*value).map_err(|_| {
            SparkImportError(format!(
                "gc_pauses_ms[{index}] exceeds the supported signed 64-bit range"
            ))
        })?;
    }
    if let Some(value) = report.heap_pressure_bytes {
        i64::try_from(value).map_err(|_| {
            SparkImportError(
                "heap_pressure_bytes exceeds the supported signed 64-bit range".to_string(),
            )
        })?;
    }
    for (index, method) in report.hot_methods.iter().enumerate() {
        validate_percent(&format!("hot_methods[{index}].percent"), method.percent)?;
    }
    for (index, hot_mod) in report.hot_mods.iter().enumerate() {
        validate_percent(&format!("hot_mods[{index}].percent"), hot_mod.percent)?;
    }
    for (index, thread) in report.thread_hotspots.iter().enumerate() {
        validate_percent(&format!("thread_hotspots[{index}].percent"), thread.percent)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreadClass {
    Server,
    Render,
    GarbageCollector,
    ForkJoin,
    LoaderWorker,
    Worker,
    Unknown,
}

impl ThreadClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Render => "render",
            Self::GarbageCollector => "garbage-collector",
            Self::ForkJoin => "fork-join",
            Self::LoaderWorker => "loader-worker",
            Self::Worker => "worker",
            Self::Unknown => "unknown",
        }
    }
}

fn classify_thread(name: &str) -> ThreadClass {
    let lower = name.to_ascii_lowercase();
    if lower.contains("server thread") || lower == "main" {
        ThreadClass::Server
    } else if lower.contains("render thread") || lower.contains("client thread") {
        ThreadClass::Render
    } else if lower.contains("gc thread")
        || lower.contains("g1 ")
        || lower.contains("zgc")
        || lower.contains("shenandoah")
    {
        ThreadClass::GarbageCollector
    } else if lower.contains("forkjoin") {
        ThreadClass::ForkJoin
    } else if lower.contains("modloading")
        || lower.contains("loader-worker")
        || lower.contains("worker-main")
    {
        ThreadClass::LoaderWorker
    } else if lower.contains("worker") || lower.contains("pool-") {
        ThreadClass::Worker
    } else {
        ThreadClass::Unknown
    }
}

// ── Collector ─────────────────────────────────────────────────────────────

struct SparkCollector;

impl Collector for SparkCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }

    fn layer(&self) -> Layer {
        Layer::Performance
    }

    fn scope(&self) -> intermed_doctor_core::CollectorScope {
        intermed_doctor_core::CollectorScope::new(
            intermed_doctor_core::CompletenessModel::BoundedPartial,
        )
        // Kept as a single constant so failure-only and thread-only paths
        // cannot silently drift from the collector contract.
        .produces(SPARK_OUTPUT_KINDS.iter().copied())
        .regions([intermed_doctor_core::TargetRegion::RuntimeProfile])
    }

    fn applies(&self, target: &Target) -> bool {
        discover_report_paths(target).next().is_some()
    }

    fn not_applicable(&self, _target: &Target) -> CollectorOutcome {
        CollectorOutcome::not_applicable(
            "no spark report found (use --spark-report or place JSON under spark/)",
        )
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        match import_target(ctx.target) {
            Ok(import) => {
                let emission = emit_import(ctx, &import);
                let failure_count = import.failures.len() + emission.validation_failures;
                let outcome = if failure_count == 0 {
                    CollectorOutcome::active
                } else {
                    CollectorOutcome::incomplete
                };
                outcome(
                    emission.emitted,
                    format!(
                        "{} report(s), {} failure(s)",
                        import.reports.len(),
                        failure_count
                    ),
                )
            }
            Err(e) => CollectorOutcome::failed(e.to_string()),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct EmitSummary {
    emitted: usize,
    validation_failures: usize,
}

fn emit_import(ctx: &mut CollectCtx<'_>, import: &SparkImport) -> EmitSummary {
    let mut emitted = 0usize;
    let mut validation_failures = 0usize;
    for failure in &import.failures {
        ctx.store
            .fact(EXTRACTOR, kind::SPARK_IMPORT_FAILURE)
            .subject(failure.path.clone())
            .attr("reason", failure.reason.clone())
            .source(SourceRef::file(failure.path.clone()))
            .emit();
        emitted += 1;
    }
    for report in &import.reports {
        let locator = if report.source_locator.is_empty() {
            if report.source.is_empty() {
                import.target.clone()
            } else {
                report.source.clone()
            }
        } else {
            report.source_locator.clone()
        };
        if let Err(error) = validate_report(report) {
            ctx.store
                .fact(EXTRACTOR, kind::SPARK_IMPORT_FAILURE)
                .subject(locator.clone())
                .attr("reason", error.to_string())
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
            validation_failures += 1;
            continue;
        }
        let session = report.session_fingerprint.as_deref().unwrap_or("");
        for ms in &report.tick_spikes_ms {
            let value = i64::try_from(*ms).expect("validated Spark tick duration");
            ctx.store
                .fact(EXTRACTOR, kind::TICK_SPIKE)
                .subject(format!("tick-{ms}ms"))
                .attr("ms", value)
                .attr("session_fingerprint", session)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
        for ms in &report.gc_pauses_ms {
            let value = i64::try_from(*ms).expect("validated Spark GC duration");
            ctx.store
                .fact(EXTRACTOR, kind::GC_PAUSE)
                .subject(format!("gc-{ms}ms"))
                .attr("ms", value)
                .attr("session_fingerprint", session)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
        if let Some(bytes) = report.heap_pressure_bytes {
            let value = i64::try_from(bytes).expect("validated Spark heap size");
            ctx.store
                .fact(EXTRACTOR, kind::HEAP_PRESSURE)
                .subject("heap")
                .attr("bytes", value)
                .attr("session_fingerprint", session)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
        for hm in &report.hot_methods {
            ctx.store
                .fact(EXTRACTOR, kind::HOT_METHOD)
                .subject(hm.class.clone())
                .attr("method", hm.method.clone())
                // Numeric so threshold rules can compare; see `parse_percent`.
                .attr("percent", hm.percent)
                .attr("session_fingerprint", session)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
        for hm in &report.hot_mods {
            ctx.store
                .fact(EXTRACTOR, kind::HOT_MOD)
                .subject(hm.r#mod.clone())
                .attr("percent", hm.percent)
                .attr("phase", hm.phase.as_deref().unwrap_or(""))
                .attr("session_fingerprint", session)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
        for th in &report.thread_hotspots {
            ctx.store
                .fact(EXTRACTOR, kind::THREAD_HOTSPOT)
                .subject(th.thread.clone())
                .attr("percent", th.percent)
                .attr("thread_class", classify_thread(&th.thread).as_str())
                .attr("session_fingerprint", session)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
    }
    EmitSummary {
        emitted,
        validation_failures,
    }
}

// ── Rule ─────────────────────────────────────────────────────────────────

struct PerformanceCorrelationRule {
    thresholds: PerformanceThresholds,
}

/// Cross-layer view of mixin facts, indexed for joining against Spark evidence.
///
/// This is the join that makes Phase 7 real: it links Layer-I performance
/// evidence (hot methods / hot mods) to Layer-F mixin intelligence (which mod's
/// mixin modifies which class, and how). The previous implementation read a
/// non-existent `target` attribute off `MIXIN_HOTSPOT` facts and therefore never
/// produced a single correlation.
#[derive(Default)]
struct MixinIndex {
    /// Mixin work keyed by the **target class** it modifies (dotted FQN).
    by_class: BTreeMap<String, MixinTargetInfo>,
    /// Simple class name → set of fully-qualified targets, for fallback joins
    /// when Spark reports a class under a slightly different qualification.
    by_simple: BTreeMap<String, BTreeSet<String>>,
    /// Mixin work keyed by the **mod id** performing it.
    by_mod: BTreeMap<String, ModMixinInfo>,
    /// Alternate class names → every canonical candidate. Resolution succeeds
    /// only when the alias is unique; insertion order can never choose a winner.
    class_aliases: BTreeMap<String, BTreeSet<String>>,
    /// Descriptor-aware site index. Overloads are distinct and method aliases
    /// are recorded separately, so a mapped match can never be manufactured by
    /// simple-name equality.
    methods_by_signature: BTreeMap<String, BTreeMap<String, MethodMixinInfo>>,
    /// `(class, mapped method reference) -> canonical method candidates`.
    /// Overloads and namespace collisions remain explicitly ambiguous.
    method_aliases: BTreeMap<(String, String), BTreeSet<String>>,
}

/// Mixin work on one exact target method (Phase 12). Distinguishes a high-quality
/// hot-method match (a destructive op on the profiled method) from a class-only one.
#[derive(Default, Clone)]
struct MethodMixinInfo {
    operations: BTreeSet<String>,
    /// At least one operation rewrites/replaces this method's behaviour.
    destructive: bool,
    fact_ids: Vec<intermed_doctor_core::facts::FactId>,
}

impl MethodMixinInfo {
    fn observe(&mut self, operation: &str, fact_id: intermed_doctor_core::facts::FactId) {
        self.operations.insert(operation.to_string());
        self.destructive |= matches!(
            operation,
            "overwrite"
                | "redirect"
                | "wrap-operation"
                | "modify-variable"
                | "modify-arg"
                | "modify-args"
                | "modify-return-value"
        );
        self.fact_ids.push(fact_id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodMatchQuality {
    ExactSignature,
    ExactOwnerMethod,
    MappedOwnerMethod,
}

struct MethodMatch<'a> {
    info: &'a MethodMixinInfo,
    quality: MethodMatchQuality,
}

fn method_name(reference: &str) -> &str {
    reference.split(['(', ' ', ':']).next().unwrap_or(reference)
}

fn has_descriptor(reference: &str) -> bool {
    reference.contains('(')
}

/// What mixins do to one target class, aggregated across mods.
#[derive(Default, Clone)]
struct MixinTargetInfo {
    mods: BTreeSet<String>,
    mixins: BTreeSet<String>,
    operations: BTreeSet<String>,
    /// At least one `@Overwrite` of this class (the highest-risk operation).
    overwrite: bool,
    /// Either layer flagged this class as a hot path (overlap / overwrite fact).
    hot_path: bool,
    /// Supporting mixin fact ids, for cross-layer evidence edges.
    fact_ids: Vec<intermed_doctor_core::facts::FactId>,
}

/// What risky mixin work a single mod performs.
#[derive(Default, Clone)]
struct ModMixinInfo {
    target_classes: BTreeSet<String>,
    overwrite_classes: BTreeSet<String>,
    fact_ids: Vec<intermed_doctor_core::facts::FactId>,
}

impl MixinIndex {
    fn build(store: &intermed_doctor_core::facts::FactStore) -> Self {
        let mut index = MixinIndex::default();

        for f in store.by_kind(kind::MIXIN_TARGET) {
            let Some(target) = f.attr("target") else {
                continue;
            };
            let canonical = f.attr("target_named").unwrap_or(target).to_string();
            let entry = index.by_class.entry(canonical.clone()).or_default();
            entry.mods.insert(f.subject.to_string());
            if let Some(mixin) = f.attr("mixin") {
                entry.mixins.insert(mixin.to_string());
            }
            entry.fact_ids.push(f.id);

            let mod_entry = index.by_mod.entry(f.subject.to_string()).or_default();
            mod_entry.target_classes.insert(canonical.clone());
            mod_entry.fact_ids.push(f.id);

            index.register_class_alias(target, &canonical);
            if let Some(named) = f.attr("target_named") {
                index.register_class_alias(named, &canonical);
            }
            if let Some(inter) = f.attr("target_intermediary") {
                index.register_class_alias(inter, &canonical);
            }
        }

        for f in store.by_kind(kind::MIXIN_OPERATION) {
            let Some(target) = f.attr("target") else {
                continue;
            };
            let entry = index.by_class.entry(target.to_string()).or_default();
            if let Some(op) = f.attr("operation") {
                entry.operations.insert(op.to_string());
            }
            entry.mods.insert(f.subject.to_string());
            entry.fact_ids.push(f.id);
        }

        // Site-level method index (Phase 12): which exact methods a mixin targets,
        // and whether it does so destructively. Drives match-quality gating below.
        for f in store.by_kind(kind::MIXIN_APPLICATION_SITE) {
            let Some(target_class) = f.attr("target_class") else {
                continue;
            };
            let method = f.attr("target_method").unwrap_or("");
            let method_simple = method_name(method);
            if method_simple.is_empty() {
                continue;
            }
            let op = f.attr("operation").unwrap_or("");
            let canonical_class = index
                .unique_class_alias(target_class)
                .unwrap_or(target_class)
                .to_string();
            index
                .methods_by_signature
                .entry(canonical_class.clone())
                .or_default()
                .entry(method.to_string())
                .or_default()
                .observe(op, f.id);
            for alias in [f.attr("name_original"), f.attr("name_canonical")]
                .into_iter()
                .flatten()
            {
                if !alias.is_empty() && alias != method {
                    index
                        .method_aliases
                        .entry((canonical_class.clone(), alias.to_string()))
                        .or_default()
                        .insert(method.to_string());
                }
            }
        }

        // Overlap facts are keyed by the target class and carry the hot-path flag.
        for f in store.by_kind(kind::MIXIN_OVERLAP) {
            let entry = index.by_class.entry(f.subject.to_string()).or_default();
            if f.attr_bool("hot_path") == Some(true) {
                entry.hot_path = true;
            }
            entry.fact_ids.push(f.id);
        }

        for f in store.by_kind(kind::HIGH_RISK_OVERWRITE) {
            let Some(target) = f.attr("target") else {
                continue;
            };
            let entry = index.by_class.entry(target.to_string()).or_default();
            entry.overwrite = true;
            entry.mods.insert(f.subject.to_string());
            if let Some(mixin) = f.attr("mixin") {
                entry.mixins.insert(mixin.to_string());
            }
            if f.attr_bool("hot_path") == Some(true) {
                entry.hot_path = true;
            }
            entry.fact_ids.push(f.id);

            let mod_entry = index.by_mod.entry(f.subject.to_string()).or_default();
            mod_entry.overwrite_classes.insert(target.to_string());
            mod_entry.target_classes.insert(target.to_string());
            mod_entry.fact_ids.push(f.id);
        }

        // A mixin flagged as a hot-path target (MIXIN_HOTSPOT) confirms the
        // hot_path flag for every class that mixin modifies.
        let mut hot_mixins: BTreeSet<String> = BTreeSet::new();
        for f in store.by_kind(kind::MIXIN_HOTSPOT) {
            if let Some(mixin) = f.attr("mixin") {
                hot_mixins.insert(mixin.to_string());
            }
        }
        if !hot_mixins.is_empty() {
            for info in index.by_class.values_mut() {
                if info.mixins.iter().any(|m| hot_mixins.contains(m)) {
                    info.hot_path = true;
                }
            }
        }

        // Build the simple-name fallback index after by_class is populated.
        let simple_pairs: Vec<(String, String)> = index
            .by_class
            .keys()
            .map(|fqn| (simple_class_name(fqn).to_string(), fqn.clone()))
            .collect();
        for (simple, fqn) in simple_pairs {
            index.by_simple.entry(simple).or_default().insert(fqn);
        }

        index
    }

    fn register_class_alias(&mut self, alias: &str, canonical: &str) {
        if alias.is_empty() || alias == canonical {
            return;
        }
        self.class_aliases
            .entry(alias.to_string())
            .or_default()
            .insert(canonical.to_string());
    }

    fn unique_class_alias<'a>(&'a self, alias: &str) -> Option<&'a str> {
        let candidates = self.class_aliases.get(alias)?;
        (candidates.len() == 1)
            .then(|| candidates.first().map(String::as_str))
            .flatten()
    }

    fn unique_method_alias<'a>(&'a self, class: &str, alias: &str) -> Option<&'a str> {
        let candidates = self
            .method_aliases
            .get(&(class.to_string(), alias.to_string()))?;
        (candidates.len() == 1)
            .then(|| candidates.first().map(String::as_str))
            .flatten()
    }

    /// Resolve every mixin-target view a Spark-reported class joins to: an exact
    /// FQN match first, otherwise a simple-name match.
    fn match_class(&self, class: &str) -> Vec<&MixinTargetInfo> {
        let key = if self.by_class.contains_key(class) {
            class
        } else {
            self.unique_class_alias(class).unwrap_or(class)
        };
        if let Some(info) = self.by_class.get(key) {
            return vec![info];
        }
        let simple = simple_class_name(class);
        match self.by_simple.get(simple) {
            Some(fqns) if fqns.len() == 1 => fqns
                .first()
                .and_then(|fqn| self.by_class.get(fqn))
                .into_iter()
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Match a profiled method with explicit quality. Descriptor-bearing samples
    /// are overload-safe; samples without descriptors remain owner+name evidence.
    fn match_method(&self, class: &str, method: &str) -> Option<MethodMatch<'_>> {
        let key = if self.methods_by_signature.contains_key(class) {
            class
        } else {
            self.unique_class_alias(class).unwrap_or(class)
        };
        let class_was_mapped = key != class;
        if has_descriptor(method) {
            let mapped = self.unique_method_alias(key, method);
            let lookup = mapped.unwrap_or(method);
            let info = self.methods_by_signature.get(key)?.get(lookup)?;
            return Some(MethodMatch {
                info,
                quality: if class_was_mapped || mapped.is_some() {
                    MethodMatchQuality::MappedOwnerMethod
                } else {
                    MethodMatchQuality::ExactSignature
                },
            });
        }
        let mapped = self.unique_method_alias(key, method);
        if let Some(reference) = mapped {
            let info = self.methods_by_signature.get(key)?.get(reference)?;
            return Some(MethodMatch {
                info,
                quality: MethodMatchQuality::MappedOwnerMethod,
            });
        }
        let lookup_name = method_name(method);
        let candidates = self
            .methods_by_signature
            .get(key)?
            .iter()
            .filter(|(reference, _)| method_name(reference) == lookup_name)
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return None;
        }
        let info = candidates[0].1;
        Some(MethodMatch {
            info,
            quality: if class_was_mapped {
                MethodMatchQuality::MappedOwnerMethod
            } else {
                MethodMatchQuality::ExactOwnerMethod
            },
        })
    }
}

impl Rule for PerformanceCorrelationRule {
    fn id(&self) -> &'static str {
        "performance-correlation"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        let index = MixinIndex::build(ctx.store);
        let mut out = Vec::new();

        // 1. Flagship join: profiled-hot method ↔ class a mixin modifies.
        let mut correlated_classes: BTreeSet<String> = BTreeSet::new();
        for f in ctx.store.by_kind(kind::HOT_METHOD) {
            let class = f.subject.as_str();
            let method = f.attr("method").unwrap_or("?");
            let Some(percent) = parse_percent(f) else {
                continue;
            };
            // Floor: ignore trivially-cheap methods so correlation does not fire
            // on a 0.1% method the same as a 40% one.
            if percent < self.thresholds.hot_method_floor_percent {
                continue;
            }
            let matches = index.match_class(class);
            if matches.is_empty() {
                continue;
            }
            correlated_classes.insert(class.to_string());

            let merged = MixinTargetInfo::merge(matches.into_iter());
            let mut severity = hot_method_severity(percent, &merged, self.thresholds);

            // Phase 12 match quality: does a mixin target this *exact* hot method?
            // An exact, destructive method match pins the cost to the woven method
            // (high quality); a class-only match stays coarse and is labelled so.
            let method_match = index.match_method(class, method);
            let exact_destructive = method_match
                .as_ref()
                .is_some_and(|matched| matched.info.destructive);
            let (quality_tag, quality_note) = match method_match.as_ref() {
                Some(m) if m.info.destructive => (
                    match m.quality {
                        MethodMatchQuality::ExactSignature => "exact-signature-match",
                        MethodMatchQuality::ExactOwnerMethod => "exact-owner-method-match",
                        MethodMatchQuality::MappedOwnerMethod => "mapped-owner-method-match",
                    },
                    format!(
                        " A mixin {} targets this exact method, so the weaving cost lands directly on the hot path.",
                        m.info.operations.iter().cloned().collect::<Vec<_>>().join("/")
                    ),
                ),
                Some(m) => (
                    match m.quality {
                        MethodMatchQuality::ExactSignature => "exact-signature-match",
                        MethodMatchQuality::ExactOwnerMethod => "exact-owner-method-match",
                        MethodMatchQuality::MappedOwnerMethod => "mapped-owner-method-match",
                    },
                    " A mixin targets this exact method (non-destructive — observation/transform).".to_string(),
                ),
                None => (
                    "class-level-correlation",
                    " No mixin targets this exact method — correlation is at class granularity only, so the hot cost may be unrelated to the mixin work.".to_string(),
                ),
            };
            // An exact destructive match on a costly method justifies at least Warn;
            // a class-only correlation is never escalated above what the base allows.
            if exact_destructive && percent >= self.thresholds.hot_method_floor_percent {
                severity = severity.max(Severity::Warn);
            }
            if method_match.is_none() {
                severity = Severity::Note;
            }

            let semantic_id = format!("perf-mixin:{class}:{method}");
            let mut builder =
                Finding::builder(self.id(), format!("perf-mixin:{}:{class}:{method}", f.id.0))
                    .semantic_id(semantic_id)
                    .occurrence_id(format!("spark-fact:{}", f.id.0))
                    .coverage_requirement(CoverageRequirement::RuntimeProfile)
                    .coverage_requirement(CoverageRequirement::LocalArtifact)
                    .proof_kind(ProofKind::DeterministicDerivation)
                    .impact(Impact::PerformanceDegradation)
                    .evidence_origin(EvidenceOrigin::ObservedRuntime)
                    .severity(severity)
                    .category(Category::Performance)
                    .title(format!(
                        "Hot method `{class}.{method}` is modified by {} mixin(s)",
                        merged.mixins.len().max(1)
                    ))
                    .explanation(format!(
                        "{}{quality_note}",
                        hot_method_explanation(class, method, percent, &merged)
                    ))
                    .evidence(EvidenceEdge::subject(f.id))
                    .affects(class)
                    .fix(FixCandidate::advice(hot_method_advice(&merged)))
                    .tag("performance")
                    .tag("mixin")
                    .tag("cross-layer")
                    .tag(if method_match.is_some() {
                        "performance-correlation"
                    } else {
                        "performance-context"
                    })
                    .tag(quality_tag);
            if method_match.is_some() {
                builder = builder.tag("exact-method-match");
            }
            for mod_id in &merged.mods {
                builder = builder.affects(mod_id.clone());
            }
            // Cross-layer evidence: link the supporting mixin facts.
            for fact_id in &merged.fact_ids {
                builder = builder.evidence(EvidenceEdge::supports(*fact_id));
            }
            // Plus the exact site facts when we have a method-level match.
            if let Some(m) = method_match {
                for id in &m.info.fact_ids {
                    builder = builder.evidence(EvidenceEdge::supports(*id));
                }
            }
            out.push(builder.build());
        }

        // 2. Profiled-hot mod that also performs risky mixin work on hot paths.
        for f in ctx.store.by_kind(kind::HOT_MOD) {
            let mod_id = f.subject.as_str();
            let Some(percent) = parse_percent(f) else {
                continue;
            };
            let Some(info) = index.by_mod.get(mod_id) else {
                continue;
            };
            if info.target_classes.is_empty() {
                continue;
            }
            // Spark attributes CPU to the mod, but the existence of mixins does
            // not prove which code path consumed it. Keep this as correlation,
            // never a diagnosis or hard error.
            let severity = if percent >= self.thresholds.high_cpu_percent {
                Severity::Warn
            } else {
                Severity::Note
            };
            let mut builder = Finding::builder(
                self.id(),
                format!("perf-hot-mod:{}:{mod_id}", f.id.0),
            )
            .semantic_id(format!("perf-hot-mod:{mod_id}"))
            .occurrence_id(format!("spark-fact:{}", f.id.0))
            .coverage_requirement(CoverageRequirement::RuntimeProfile)
            .coverage_requirement(CoverageRequirement::LocalArtifact)
            .proof_kind(ProofKind::DeterministicDerivation)
            .impact(Impact::PerformanceDegradation)
            .evidence_origin(EvidenceOrigin::ObservedRuntime)
            .severity(severity)
            .category(Category::Performance)
            .title(format!(
                "Hot mod `{mod_id}` ({percent:.1}% CPU) modifies {} class(es) via mixin",
                info.target_classes.len()
            ))
            .explanation(hot_mod_explanation(mod_id, percent, info))
            .evidence(EvidenceEdge::subject(f.id))
            .affects(mod_id)
            .fix(FixCandidate::advice(
                "Temporarily remove or disable this mod and re-profile to confirm its tick cost; \
                     review its mixin targets for redundant or hot-path patches.",
            ))
            .tag("performance")
            .tag("mixin")
            .tag("cross-layer")
            .tag("performance-correlation");
            for fact_id in &info.fact_ids {
                builder = builder.evidence(EvidenceEdge::supports(*fact_id));
            }
            out.push(builder.build());
        }

        // 3. Tick spikes — standalone, but enriched when mixin hot-path overlaps exist.
        for f in ctx.store.by_kind(kind::TICK_SPIKE) {
            let ms = f.attr_int("ms").unwrap_or(0);
            if ms < self.thresholds.tick_spike_ms {
                continue;
            }
            let severity =
                if ms >= self.thresholds.tick_spike_warn_ms || !correlated_classes.is_empty() {
                    Severity::Warn
                } else {
                    Severity::Note
                };
            let explanation = if correlated_classes.is_empty() {
                "Spark reported a tick duration spike. Correlate with mixin hotspots, \
                 worldgen mods, and view-distance settings."
                    .to_string()
            } else {
                format!(
                    "Spark reported a tick duration spike alongside {} hot method(s) that mixins \
                     modify (see the cross-layer findings). Investigate those mixin targets first.",
                    correlated_classes.len()
                )
            };
            out.push(
                Finding::builder(self.id(), format!("tick-spike:{}:{ms}", f.id.0))
                    .semantic_id(format!("tick-spike:{ms}"))
                    .occurrence_id(format!("spark-fact:{}", f.id.0))
                    .severity(severity)
                    .category(Category::Performance)
                    .title(format!("Server tick spike: {ms} ms"))
                    .explanation(explanation)
                    .evidence(EvidenceEdge::subject(f.id))
                    .fix(FixCandidate::advice(
                        "Capture a Spark profile during lag and compare hot methods with the mixin map.",
                    ))
                    .tag("performance")
                    .tag("tick")
                    .tag("performance-observation")
                    .build(),
            );
        }

        Ok(out)
    }
}

/// Tick spikes co-occurring with mixin work flagged on hot paths (Layer F).
fn perf_tick_mixin_hotpath_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let spikes: Vec<_> = ctx.store.by_kind(kind::TICK_SPIKE).collect();
    if spikes.is_empty() {
        return Vec::new();
    }

    let index = MixinIndex::build(ctx.store);
    let mut out = Vec::new();
    for (mod_id, info) in &index.by_mod {
        let hot_targets: Vec<&str> = info
            .target_classes
            .iter()
            .filter(|class| {
                index
                    .by_class
                    .get(*class)
                    .is_some_and(|entry| entry.hot_path || entry.overwrite)
            })
            .map(String::as_str)
            .collect();
        if hot_targets.is_empty() {
            continue;
        }
        let max_ms = spikes
            .iter()
            .filter_map(|f| f.attr_int("ms"))
            .max()
            .unwrap_or(0);
        let mut builder = Finding::builder(
            "performance",
            format!("perf-tick-mixin-hotpath:{mod_id}"),
        )
        .severity(Severity::Note)
        .category(Category::Performance)
        .channel(FindingChannel::Informational)
        .visibility(FindingVisibility::ExplainOnly)
        .confidence(0.62)
        .title(format!(
            "Tick spikes recorded while `{mod_id}` patches {} hot-path mixin target(s)",
            hot_targets.len()
        ))
        .explanation(format!(
            "Spark reported server tick spikes (up to {max_ms} ms) and mod `{mod_id}` modifies \
             hot-path class(es): {}. This is a static candidate only: the profile did not attribute \
             the spike to these sites. Use a method-level sample before assigning cause.",
            hot_targets.join(", ")
        ))
        .affects(mod_id.clone())
        .fix(FixCandidate::advice(
            "Capture a Spark profile during lag and compare hot methods with this mod's mixin targets.",
        ))
        .tag("performance")
        .tag("mixin")
        .tag("tick")
        .tag("correlation")
        .tag("performance-candidate");
        for f in &spikes {
            builder = builder.evidence(EvidenceEdge::supports(f.id));
        }
        for fact_id in &info.fact_ids {
            builder = builder.evidence(EvidenceEdge::supports(*fact_id));
        }
        out.push(builder.build());
    }
    out
}

/// Hot mod CPU share overlapping a VFS resource collision on the same mod id.
fn perf_hot_mod_resource_findings(
    ctx: &RuleCtx<'_>,
    thresholds: PerformanceThresholds,
) -> Vec<Finding> {
    let collisions: Vec<_> = ctx.store.by_kind(kind::RESOURCE_COLLISION).collect();
    if collisions.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for hot in ctx.store.by_kind(kind::HOT_MOD) {
        let mod_id = hot.subject.as_str();
        let percent = hot.attr_f64("percent").unwrap_or(0.0);
        if percent < thresholds.hot_method_floor_percent {
            continue;
        }
        let related: Vec<_> = collisions
            .iter()
            .filter(|c| {
                c.attr("writers")
                    .is_some_and(|writers| writers.split(',').any(|w| w.trim() == mod_id))
            })
            .collect();
        if related.is_empty() {
            continue;
        }
        let paths: Vec<&str> = related.iter().map(|c| c.subject.as_str()).collect();
        let phase = hot.attr("phase").unwrap_or("");
        let phase_linked = phase_matches_resources(phase, &paths);
        let mut builder = Finding::builder(
            "performance",
            format!("perf-hot-mod-resource:{}:{mod_id}", hot.id.0),
        )
        .semantic_id(format!("perf-hot-mod-resource:{mod_id}"))
        .occurrence_id(format!("spark-fact:{}", hot.id.0))
        .severity(Severity::Note)
        .category(Category::Performance)
        .channel(FindingChannel::Informational)
        .confidence(if phase_linked { 0.68 } else { 0.45 })
        .title(format!(
            "Hot mod `{mod_id}` ({percent:.1}% CPU) also collides on {} resource path(s)",
            paths.len()
        ))
        .explanation(format!(
            "Spark attributes {percent:.1}% CPU to `{mod_id}` and it is among the writers \
             for conflicting resource path(s): {}. {}",
            paths.join(", "),
            if phase_linked {
                "The profile phase matches the resource domain, so inspect the cited resources; this is still correlation, not proof of CPU causation."
            } else {
                "The profile has no matching phase identity, so the resource and CPU observations may be unrelated."
            },
        ))
        .evidence(EvidenceEdge::subject(hot.id))
        .affects(mod_id)
        .fix(FixCandidate::advice(
            "Resolve the resource collision or temporarily remove this mod, then re-profile.",
        ))
        .tag("performance")
        .tag("vfs")
        .tag("correlation")
        .tag(if phase_linked {
            "performance-correlation"
        } else {
            "performance-context"
        });
        if !phase_linked {
            builder = builder.visibility(FindingVisibility::ExplainOnly);
        }
        for c in related {
            builder = builder.evidence(EvidenceEdge::supports(c.id));
        }
        out.push(builder.build());
    }
    out
}

/// The resource category a CPU hotspot is attributed to, with its finding shape.
struct ResourceHotspot {
    /// Substrings that place a `resource_writer` path in this category.
    matches: fn(&str) -> bool,
    /// Finding id stem (`<stem>:{mod}`).
    id: &'static str,
    /// Human label for the subsystem the hotspot likely lives in.
    subsystem: &'static str,
    /// Extra advice line specific to this category.
    advice: &'static str,
}

fn is_worldgen_path(p: &str) -> bool {
    p.contains("/worldgen/")
}
fn is_atlas_path(p: &str) -> bool {
    p.contains("/atlases/")
}
fn is_model_path(p: &str) -> bool {
    p.starts_with("assets/") && (p.contains("/models/") || p.contains("/blockstates/"))
}
fn is_reload_data_path(p: &str) -> bool {
    p.starts_with("data/")
        && (p.contains("/recipe")
            || p.contains("/loot_table")
            || p.contains("/tags/")
            || p.contains("/advancement"))
}

fn phase_matches_resources(phase: &str, paths: &[&str]) -> bool {
    let normalized = phase.to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    paths.iter().any(|path| match normalized.as_str() {
        "worldgen" | "chunk-generation" => is_worldgen_path(path),
        "resource-reload" | "reload" | "datapack-reload" => is_reload_data_path(path),
        "model-bake" | "model-baking" => is_model_path(path),
        "atlas" | "atlas-stitch" => is_atlas_path(path),
        _ => false,
    })
}

/// Cross-layer Layer-I (Spark hotspots) ↔ Layer-M (resource writers) — "cluster E".
///
/// A mod that Spark attributes CPU to AND that ships a lot of one resource category
/// gives a directed hint about *where* the hot work is: a worldgen-heavy hot mod is
/// likely hot in worldgen, a model-heavy one in model baking, etc. This narrows a
/// bare "hot mod" finding to a subsystem the user can act on. Emits at most one
/// finding per (mod, category); only fires above the hot-method floor so trivial
/// CPU shares do not generate noise.
fn perf_resource_category_hotspot_findings(
    ctx: &RuleCtx<'_>,
    thresholds: PerformanceThresholds,
) -> Vec<Finding> {
    const CATEGORIES: &[ResourceHotspot] = &[
        ResourceHotspot {
            matches: is_worldgen_path,
            id: "worldgen-hotspot",
            subsystem: "world generation",
            advice: "Profile chunk generation specifically (Spark's worldgen sampler) and check this \
                     mod's features/biomes for expensive density functions.",
        },
        ResourceHotspot {
            matches: is_atlas_path,
            id: "atlas-hotspot",
            subsystem: "texture-atlas stitching",
            advice: "Large or numerous atlas sources slow stitching at resource load; check this mod's \
                     atlas sources and sprite counts.",
        },
        ResourceHotspot {
            matches: is_model_path,
            id: "model-bake-hotspot",
            subsystem: "model baking",
            advice: "Many models/blockstates inflate model bake time; check for generated or \
                     multipart-heavy blockstates from this mod.",
        },
        ResourceHotspot {
            matches: is_reload_data_path,
            id: "resource-reload-hotspot",
            subsystem: "datapack reload",
            advice: "Many reloadable data files lengthen `/reload`; check this mod's recipe/loot/tag \
                     volume if reloads stall.",
        },
    ];

    // Resource writer counts per (mod, category index).
    let writers: Vec<_> = ctx.store.by_kind(kind::RESOURCE_WRITER).collect();
    if writers.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for hot in ctx.store.by_kind(kind::HOT_MOD) {
        let mod_id = hot.subject.as_str();
        let percent = hot.attr_f64("percent").unwrap_or(0.0);
        if percent < thresholds.hot_method_floor_percent {
            continue;
        }
        for cat in CATEGORIES {
            let related: Vec<_> = writers
                .iter()
                .filter(|w| w.subject == mod_id && w.attr("path").is_some_and(|p| (cat.matches)(p)))
                .collect();
            if related.is_empty() {
                continue;
            }
            let n = related.len();
            let mut builder = Finding::builder(
                "performance",
                format!("{}:{}:{mod_id}", cat.id, hot.id.0),
            )
                .semantic_id(format!("{}:{mod_id}", cat.id))
                .occurrence_id(format!("spark-fact:{}", hot.id.0))
                .severity(Severity::Note)
                .category(Category::Performance)
                .channel(FindingChannel::Informational)
                .visibility(FindingVisibility::ExplainOnly)
                .confidence(0.5)
                .title(format!(
                    "Hot mod `{mod_id}` also has substantial {} surface",
                    cat.subsystem
                ))
                .explanation(format!(
                    "Spark attributes {percent:.1}% CPU to `{mod_id}`, which also ships {n} \
                     {}-related resource file(s). File presence does not attribute CPU to that \
                     subsystem; profile {} specifically to verify whether the two observations are related.",
                    cat.subsystem, cat.subsystem
                ))
                .evidence(EvidenceEdge::subject(hot.id))
                .affects(mod_id)
                .fix(FixCandidate::advice(cat.advice))
                .tag("performance")
                .tag("resource")
                .tag("correlation")
                .tag("performance-context");
            for w in related.iter().take(8) {
                builder = builder.evidence(EvidenceEdge::supports(w.id));
            }
            out.push(builder.build());
        }
    }
    out
}

/// Hot profiled method observed as an exact structured runtime stack frame.
/// Free-text excerpts are intentionally excluded: names such as `run`, `tick`
/// and `load` are far too common for substring matching.
fn perf_hot_method_log_findings(
    ctx: &RuleCtx<'_>,
    thresholds: PerformanceThresholds,
) -> Vec<Finding> {
    let index = MixinIndex::build(ctx.store);
    let stack_frames: Vec<_> = ctx.store.by_kind(kind::STACK_FRAME).collect();
    if stack_frames.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for hot in ctx.store.by_kind(kind::HOT_METHOD) {
        let class = hot.subject.as_str();
        let method = hot.attr("method").unwrap_or("?");
        let Some(percent) = parse_percent(hot) else {
            continue;
        };
        if percent < thresholds.hot_method_floor_percent {
            continue;
        }
        let matching_frames: Vec<_> = stack_frames
            .iter()
            .filter(|frame| frame_matches_hot_method(&stack_frames, frame, class, method))
            .collect();
        if matching_frames.is_empty() {
            continue;
        }
        let same_session = matching_frames
            .iter()
            .any(|frame| facts_share_session(Some(hot), Some(frame)));
        let merged = MixinTargetInfo::merge(index.match_class(class).into_iter());
        let mut builder = Finding::builder(
            "performance",
            format!("perf-hot-method-log:{}:{class}:{method}", hot.id.0),
        )
        .semantic_id(format!("perf-hot-method-log:{class}:{method}"))
        .occurrence_id(format!("spark-fact:{}", hot.id.0))
        .severity(if same_session {
            Severity::Warn
        } else {
            Severity::Note
        })
        .category(Category::Performance)
        .channel(FindingChannel::Informational)
        .confidence(if same_session { 0.84 } else { 0.68 })
        .title(format!(
            "Hot method `{class}.{method}` appears in {n} structured stack frame(s)",
            n = matching_frames.len()
        ))
        .explanation(format!(
            "Spark attributes {percent:.1}% CPU to `{class}.{method}`, and Layer D parsed the exact \
             owner/method in {n} runtime stack frame(s). {session_note}",
            n = matching_frames.len(),
            session_note = if same_session {
                "The evidence declares one session, so this is a strong runtime correlation, not by itself a causal diagnosis."
            } else {
                "No shared session identity was available; the profile and exception may come from different runs."
            }
        ))
        .evidence(EvidenceEdge::subject(hot.id))
        .affects(class)
        .fix(FixCandidate::advice(
            "Capture the profile and exception in the same run, then inspect the cited exact frame and its callers.",
        ))
        .tag("performance")
        .tag("log")
        .tag("correlation")
        .tag("structured-stack-frame")
        .tag("performance-correlation");
        if !same_session {
            builder = builder.visibility(FindingVisibility::ExplainOnly);
        }
        for mod_id in &merged.mods {
            builder = builder.affects(mod_id.clone());
        }
        for f in matching_frames {
            builder = builder.evidence(EvidenceEdge::supports(f.id));
        }
        out.push(builder.build());
    }
    out
}

fn normalize_class_name(value: &str) -> String {
    value.replace('/', ".")
}

fn frame_matches_hot_method(
    all_frames: &[&intermed_doctor_core::facts::Fact],
    frame: &intermed_doctor_core::facts::Fact,
    hot_class: &str,
    hot_method: &str,
) -> bool {
    let Some(frame_class) = frame.attr("class") else {
        return false;
    };
    let Some(frame_method) = frame.attr("method") else {
        return false;
    };
    if method_name(frame_method) != method_name(hot_method) {
        return false;
    }
    let hot_class = normalize_class_name(hot_class);
    let frame_class = normalize_class_name(frame_class);
    if hot_class.contains('.') {
        return hot_class == frame_class;
    }
    let candidates = all_frames
        .iter()
        .filter_map(|candidate| candidate.attr("class"))
        .map(normalize_class_name)
        .filter(|candidate| simple_class_name(candidate) == hot_class)
        .collect::<BTreeSet<_>>();
    candidates.len() == 1 && candidates.contains(&frame_class)
}

fn facts_share_session(
    left: Option<&intermed_doctor_core::facts::Fact>,
    right: Option<&intermed_doctor_core::facts::Fact>,
) -> bool {
    let Some(left) = left.and_then(|fact| fact.attr("session_fingerprint")) else {
        return false;
    };
    let Some(right) = right.and_then(|fact| fact.attr("session_fingerprint")) else {
        return false;
    };
    !left.is_empty() && left == right
}

/// Direct profiler observations. These are kept separate from correlations and
/// diagnoses so a true GC/thread/heap measurement cannot inherit causal wording
/// from unrelated static facts.
fn perf_runtime_observation_findings(
    ctx: &RuleCtx<'_>,
    thresholds: PerformanceThresholds,
) -> Vec<Finding> {
    let mut out = Vec::new();

    for hot in ctx.store.by_kind(kind::HOT_METHOD) {
        let Some(percent) = parse_percent(hot) else {
            continue;
        };
        if percent < thresholds.hot_method_floor_percent {
            continue;
        }
        let method = hot.attr("method").unwrap_or("?");
        out.push(
            Finding::builder(
                "performance",
                format!("perf-hot-method-observed:{}", hot.id.0),
            )
            .severity(if percent >= thresholds.high_cpu_percent {
                Severity::Warn
            } else {
                Severity::Note
            })
            .category(Category::Performance)
            .channel(FindingChannel::PackHealth)
            .proof_kind(ProofKind::Observation)
            .evidence_origin(EvidenceOrigin::ObservedRuntime)
            .title(format!(
                "Hot method observed: `{}.{method}` ({percent:.1}%)",
                hot.subject.as_str()
            ))
            .explanation(
                "Spark measured this method's sample share. This observation identifies expensive code, but does not by itself identify why it is expensive.",
            )
            .evidence(EvidenceEdge::subject(hot.id))
            .affects(hot.subject.to_string())
            .tag("performance")
            .tag("method")
            .tag("performance-observation")
            .build(),
        );
    }

    for hot in ctx.store.by_kind(kind::HOT_MOD) {
        let Some(percent) = parse_percent(hot) else {
            continue;
        };
        if percent < thresholds.hot_method_floor_percent {
            continue;
        }
        out.push(
            Finding::builder(
                "performance",
                format!("perf-hot-mod-observed:{}", hot.id.0),
            )
            .severity(if percent >= thresholds.high_cpu_percent {
                Severity::Warn
            } else {
                Severity::Note
            })
            .category(Category::Performance)
            .channel(FindingChannel::PackHealth)
            .proof_kind(ProofKind::Observation)
            .evidence_origin(EvidenceOrigin::ObservedRuntime)
            .title(format!(
                "Hot mod observed: `{}` ({percent:.1}%)",
                hot.subject.as_str()
            ))
            .explanation(
                "Spark attributed this sample share to the mod. Static mixins, resources, or log mentions are reported separately and do not automatically become the cause.",
            )
            .evidence(EvidenceEdge::subject(hot.id))
            .affects(hot.subject.to_string())
            .tag("performance")
            .tag("mod")
            .tag("performance-observation")
            .build(),
        );
    }

    let mut gc_by_source: BTreeMap<&str, Vec<&intermed_doctor_core::facts::Fact>> = BTreeMap::new();
    for fact in ctx.store.by_kind(kind::GC_PAUSE) {
        gc_by_source
            .entry(fact.source.locator.as_ref())
            .or_default()
            .push(fact);
    }
    for (source, pauses) in gc_by_source {
        let long = pauses
            .iter()
            .filter_map(|fact| fact.attr_int("ms").map(|ms| (*fact, ms)))
            .filter(|(_, ms)| *ms >= thresholds.tick_spike_ms)
            .collect::<Vec<_>>();
        if long.is_empty() {
            continue;
        }
        let max_ms = long.iter().map(|(_, ms)| *ms).max().unwrap_or(0);
        let repeated = long.len() > 1;
        let mut builder = Finding::builder(
            "performance",
            format!("perf-gc-pause:{}:{}", long[0].0.id.0, long.len()),
        )
        .severity(if repeated || max_ms >= thresholds.tick_spike_warn_ms {
            Severity::Warn
        } else {
            Severity::Note
        })
        .category(Category::Performance)
        .channel(FindingChannel::PackHealth)
        .proof_kind(ProofKind::Observation)
        .evidence_origin(EvidenceOrigin::ObservedRuntime)
        .title(if repeated {
            format!("Repeated long GC pauses ({} samples, up to {max_ms} ms)", long.len())
        } else {
            format!("Long GC pause observed: {max_ms} ms")
        })
        .explanation(format!(
            "Spark report `{source}` contains {} GC pause(s) at or above {} ms. This is a measured runtime observation; it does not identify which mod allocated the memory.",
            long.len(), thresholds.tick_spike_ms
        ))
        .fix(FixCandidate::advice(
            "Inspect heap occupancy and allocation samples from the same profile before changing mods or JVM flags.",
        ))
        .tag("performance")
        .tag("gc")
        .tag("performance-observation");
        for (fact, _) in long {
            builder = builder.evidence(EvidenceEdge::subject(fact.id));
        }
        out.push(builder.build());
    }

    for heap in ctx.store.by_kind(kind::HEAP_PRESSURE) {
        let bytes = heap.attr_int("bytes").unwrap_or(0);
        let related_gc = ctx.store.by_kind(kind::GC_PAUSE).any(|pause| {
            pause.source.locator == heap.source.locator
                && pause
                    .attr_int("ms")
                    .is_some_and(|ms| ms >= thresholds.tick_spike_ms)
        });
        let oom = ctx.store.by_kind(kind::THROWABLE_NODE).find(|throwable| {
            throwable
                .attr("type")
                .is_some_and(|ty| ty.ends_with("OutOfMemoryError"))
                && facts_share_session(Some(heap), Some(throwable))
        });
        let mut builder = Finding::builder(
            "performance",
            format!("perf-heap-pressure:{}", heap.id.0),
        )
        .severity(if oom.is_some() || related_gc {
            Severity::Warn
        } else {
            Severity::Note
        })
        .category(Category::Performance)
        .channel(FindingChannel::PackHealth)
        .proof_kind(ProofKind::Observation)
        .evidence_origin(EvidenceOrigin::ObservedRuntime)
        .title(format!("Heap pressure observed: {bytes} bytes"))
        .explanation(if oom.is_some() {
            "Spark heap pressure and an OutOfMemoryError were observed in the same declared session. Allocation evidence is still required to attribute the cause.".to_string()
        } else if related_gc {
            "The same Spark report contains heap pressure and long GC pauses. This supports memory-pressure diagnosis but not mod attribution.".to_string()
        } else {
            "Spark reported heap pressure without a corroborating long GC pause or same-session OutOfMemoryError.".to_string()
        })
        .evidence(EvidenceEdge::subject(heap.id))
        .fix(FixCandidate::advice(
            "Capture allocation and heap-occupancy data from the same session to identify retained objects or allocation hotspots.",
        ))
        .tag("performance")
        .tag("memory")
        .tag("performance-observation");
        if let Some(oom) = oom {
            builder = builder.evidence(EvidenceEdge::supports(oom.id));
        }
        out.push(builder.build());
    }

    for thread in ctx.store.by_kind(kind::THREAD_HOTSPOT) {
        let percent = thread.attr_f64("percent").unwrap_or(0.0);
        if percent < thresholds.hot_method_floor_percent {
            continue;
        }
        let class = thread.attr("thread_class").unwrap_or("unknown");
        let gc_corroborated = class == "garbage-collector"
            && ctx.store.by_kind(kind::GC_PAUSE).any(|pause| {
                pause.source.locator == thread.source.locator
                    && pause
                        .attr_int("ms")
                        .is_some_and(|ms| ms >= thresholds.tick_spike_ms)
            });
        let mut builder = Finding::builder(
            "performance",
            format!("perf-thread-hotspot:{}", thread.id.0),
        )
        .severity(if gc_corroborated {
            Severity::Warn
        } else {
            Severity::Note
        })
        .category(Category::Performance)
        .channel(FindingChannel::Informational)
        .proof_kind(ProofKind::Observation)
        .evidence_origin(EvidenceOrigin::ObservedRuntime)
        .title(format!(
            "{} thread hotspot `{}`: {percent:.1}%",
            class,
            thread.subject.as_str()
        ))
        .explanation(if gc_corroborated {
            "Spark attributes substantial time to a GC thread and the same report contains long GC pauses.".to_string()
        } else {
            format!(
                "Spark attributes {percent:.1}% to a thread classified as `{class}`. A thread-level sample is an observation; inspect its method stack before attributing it to a mod."
            )
        })
        .evidence(EvidenceEdge::subject(thread.id))
        .tag("performance")
        .tag("thread")
        .tag("performance-observation");
        if class == "unknown" {
            builder = builder.visibility(FindingVisibility::ExplainOnly);
        }
        out.push(builder.build());
    }

    out
}

/// When Spark data is absent, surface cross-layer hints from mixin, VFS, and logs
/// instead of only a generic inactive notice.
fn performance_fallback_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let has_perf = ctx.store.by_kind(kind::HOT_METHOD).next().is_some()
        || ctx.store.by_kind(kind::HOT_MOD).next().is_some()
        || ctx.store.by_kind(kind::TICK_SPIKE).next().is_some()
        || ctx.store.by_kind(kind::GC_PAUSE).next().is_some()
        || ctx.store.by_kind(kind::HEAP_PRESSURE).next().is_some()
        || ctx.store.by_kind(kind::THREAD_HOTSPOT).next().is_some();
    if has_perf {
        return Vec::new();
    }
    if ctx
        .store
        .by_kind(kind::SPARK_IMPORT_FAILURE)
        .next()
        .is_some()
    {
        return Vec::new();
    }

    let index = MixinIndex::build(ctx.store);
    let hot_path_mods: usize = index
        .by_mod
        .iter()
        .filter(|(_, info)| {
            info.target_classes.iter().any(|class| {
                index
                    .by_class
                    .get(class)
                    .is_some_and(|entry| entry.hot_path || entry.overwrite)
            })
        })
        .count();
    let resource_collisions = ctx.store.by_kind(kind::RESOURCE_COLLISION).count();
    let log_mentions = ctx.store.by_kind(kind::LOG_MENTIONS_MOD).count();
    let log_signals = ctx.store.by_kind(kind::LOG_SIGNAL).count();

    if hot_path_mods == 0 && resource_collisions == 0 && log_mentions == 0 && log_signals == 0 {
        return Vec::new();
    }

    let mut hints = Vec::new();
    if hot_path_mods > 0 {
        hints.push(format!(
            "{hot_path_mods} mod(s) patch mixin hot-path targets — import a Spark report to correlate CPU"
        ));
    }
    if resource_collisions > 0 {
        hints.push(format!(
            "{resource_collisions} resource collision(s) — hot-mod joins need Spark `hot_mod` facts"
        ));
    }
    if log_mentions > 0 || log_signals > 0 {
        hints.push(format!(
            "{} log mention(s) and {} log signal(s) — available for perf×log correlation once Spark is imported",
            log_mentions, log_signals
        ));
    }

    vec![Finding::builder("performance", "performance-heuristic-fallback")
        .severity(Severity::Note)
        .category(Category::Performance)
        .confidence(0.55)
        .title("No Spark profile — partial performance hints from other layers")
        .explanation(format!(
            "Layer I is enabled but no Spark facts were imported. Without a profile, CPU attribution \
             is unavailable; however other layers already provide partial lag suspects: {}. Pass \
             `--spark-report PATH` (schema `{SPARK_REPORT_SCHEMA}`) during lag to unlock full \
             cross-layer correlation.",
            hints.join("; ")
        ))
        .fix(FixCandidate::advice(
            "Capture a Spark profile during lag and pass it with `--performance --spark-report`.",
        ))
        .tag("performance")
        .tag("heuristic")
        .tag("inactive")
        .build()]
}

fn performance_notice_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in ctx.store.by_kind(kind::SPARK_IMPORT_FAILURE) {
        let path = f.subject.as_str();
        let reason = f.attr("reason").unwrap_or("parse error");
        out.push(
            Finding::builder("performance", format!("spark-import-failure:{path}"))
                .severity(Severity::Warn)
                .category(Category::Performance)
                .title(format!("Spark report import failed: {path}"))
                .explanation(format!("Could not import Spark profile `{path}`: {reason}."))
                .evidence(EvidenceEdge::subject(f.id))
                .fix(FixCandidate::advice(
                    "Fix the report JSON (schema `intermed-spark-report-v1`) or regenerate it from Spark.",
                ))
                .tag("performance")
                .tag("spark")
                .build(),
        );
    }

    let has_perf = ctx.store.by_kind(kind::HOT_METHOD).next().is_some()
        || ctx.store.by_kind(kind::HOT_MOD).next().is_some()
        || ctx.store.by_kind(kind::TICK_SPIKE).next().is_some()
        || ctx.store.by_kind(kind::GC_PAUSE).next().is_some()
        || ctx.store.by_kind(kind::HEAP_PRESSURE).next().is_some()
        || ctx.store.by_kind(kind::THREAD_HOTSPOT).next().is_some();
    if !has_perf && out.is_empty() {
        out.push(
            Finding::builder("performance", "performance-inactive")
                .severity(Severity::Note)
                .category(Category::Performance)
                .confidence(0.5)
                .title("Performance layer inactive: no Spark report data")
                .explanation(
                    "The performance layer was enabled but no Spark profile facts were imported. \
                     Pass `--spark-report PATH` or place `intermed-spark-report-v1` JSON under \
                     `spark/` or `profiler/` in the target directory. With mixin, VFS, or log layers \
                     enabled, partial heuristic hints may still appear when those facts are present.",
                )
                .fix(FixCandidate::advice(
                    "Capture a Spark profile during lag and pass it with `--performance --spark-report`.",
                ))
                .tag("performance")
                .tag("inactive")
                .build(),
        );
    }
    out
}

impl MixinTargetInfo {
    /// Merge several per-class views (from FQN + simple-name matches) into one.
    fn merge<'a>(infos: impl Iterator<Item = &'a MixinTargetInfo>) -> MixinTargetInfo {
        let mut out = MixinTargetInfo::default();
        for info in infos {
            out.mods.extend(info.mods.iter().cloned());
            out.mixins.extend(info.mixins.iter().cloned());
            out.operations.extend(info.operations.iter().cloned());
            out.overwrite |= info.overwrite;
            out.hot_path |= info.hot_path;
            out.fact_ids.extend(info.fact_ids.iter().copied());
        }
        out.fact_ids.sort_unstable();
        out.fact_ids.dedup();
        out
    }
}

fn hot_method_severity(
    percent: f64,
    info: &MixinTargetInfo,
    thresholds: PerformanceThresholds,
) -> Severity {
    if info.overwrite || percent >= thresholds.high_cpu_percent || info.mods.len() > 1 {
        Severity::Warn
    } else {
        Severity::Note
    }
}

fn hot_method_explanation(
    class: &str,
    method: &str,
    percent: f64,
    info: &MixinTargetInfo,
) -> String {
    let mods = join_set(&info.mods);
    let ops = if info.operations.is_empty() {
        "mixin injection".to_string()
    } else {
        join_set(&info.operations)
    };
    let mut explanation = format!(
        "Spark attributes {percent:.1}% CPU to `{class}.{method}`, and Layer-F mixin intelligence \
         shows mod(s) {mods} modifying this class via {ops}."
    );
    if info.overwrite {
        explanation.push_str(
            " At least one mixin @Overwrite replaces the original method wholesale — the most \
             invasive correlated transformation and the first one to measure in an isolation run.",
        );
    }
    if info.mods.len() > 1 {
        explanation.push_str(
            " Multiple mods target the same hot class, so their mixins also risk interacting.",
        );
    }
    explanation
}

fn hot_method_advice(info: &MixinTargetInfo) -> String {
    if info.overwrite {
        "Audit the @Overwrite mixin(s) on this class; prefer @Inject/@Redirect, or disable the \
         offending mod and re-profile."
            .to_string()
    } else {
        "Review the mixins targeting this class and re-profile with each disabled to isolate the cost."
            .to_string()
    }
}

fn hot_mod_explanation(mod_id: &str, percent: f64, info: &ModMixinInfo) -> String {
    let mut explanation = format!(
        "Spark attributes {percent:.1}% CPU to mod `{mod_id}`, which modifies {} class(es) via mixin.",
        info.target_classes.len()
    );
    if !info.overwrite_classes.is_empty() {
        explanation.push_str(&format!(
            " It @Overwrites {}: {}.",
            info.overwrite_classes.len(),
            join_set(&info.overwrite_classes),
        ));
    }
    explanation.push_str(
        " The profile attributes CPU to the mod, but does not by itself attribute that CPU to these mixins.",
    );
    explanation
}

/// Read the `percent` attribute as a native number (`Float`/`Int` only).
fn parse_percent(fact: &intermed_doctor_core::facts::Fact) -> Option<f64> {
    fact.attr_f64("percent")
        .filter(|value| value.is_finite() && (0.0..=100.0).contains(value))
}

fn join_set(set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        "(none)".to_string()
    } else {
        set.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn simple_class_name(class: &str) -> &str {
    class.rsplit('.').next().unwrap_or(class)
}

// ── Import ───────────────────────────────────────────────────────────────

pub fn import_target(target: &Target) -> Result<SparkImport, SparkImportError> {
    let paths: Vec<PathBuf> = discover_report_paths(target).collect();
    if paths.is_empty() {
        return Err(SparkImportError("no spark report files discovered".into()));
    }

    // Reports parse independently; fan out across cores. `par_iter().map()`
    // preserves order, so aggregation is deterministic.
    let parsed: Vec<Result<SparkReport, SparkImportFailure>> = paths
        .par_iter()
        .map(|path| {
            import_file(path).map_err(|e| SparkImportFailure {
                path: path.display().to_string(),
                reason: e.to_string(),
            })
        })
        .collect();

    let mut reports = Vec::new();
    let mut failures = Vec::new();
    for result in parsed {
        match result {
            Ok(report) => reports.push(report),
            Err(failure) => failures.push(failure),
        }
    }

    Ok(SparkImport {
        target: target.path.display().to_string(),
        reports,
        failures,
    })
}

pub fn import_file(path: &Path) -> Result<SparkReport, SparkImportError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| SparkImportError(format!("read {}: {e}", path.display())))?;
    let mut report: SparkReport = serde_json::from_str(&text)
        .map_err(|e| SparkImportError(format!("parse {}: {e}", path.display())))?;
    if report.schema != SPARK_REPORT_SCHEMA {
        return Err(SparkImportError(format!(
            "unsupported schema `{}` in {} (expected {SPARK_REPORT_SCHEMA})",
            report.schema,
            path.display()
        )));
    }
    validate_report(&report)
        .map_err(|error| SparkImportError(format!("validate {}: {error}", path.display())))?;
    report.source_locator = path.display().to_string();
    Ok(report)
}

fn discover_report_paths(target: &Target) -> impl Iterator<Item = PathBuf> + '_ {
    let mut paths = Vec::new();
    if let Some(explicit) = &target.spark_report {
        // An explicit source is an isolation boundary. Do not silently merge
        // unrelated auto-discovered profiles (including malformed leftovers)
        // into the requested analysis.
        paths.push(explicit.clone());
        return paths.into_iter();
    }
    for sub in ["spark", "profiler"] {
        let dir = target.path.join(sub);
        if dir.is_dir()
            && let Ok(rd) = std::fs::read_dir(&dir)
        {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    paths.push(p);
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths.into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::TargetKind;

    #[test]
    fn parses_minimal_spark_report() {
        let json = r#"{
            "schema": "intermed-spark-report-v1",
            "tick_spikes_ms": [120],
            "hot_methods": [{"class": "net.minecraft.server.MinecraftServer", "method": "tick", "percent": 42.0}]
        }"#;
        let report: SparkReport = serde_json::from_str(json).unwrap();
        assert_eq!(report.tick_spikes_ms, vec![120]);
        assert_eq!(report.hot_methods.len(), 1);
    }

    #[test]
    fn discovers_spark_subdirectory() {
        let root = std::env::temp_dir().join(format!("intermed-spark-{}", std::process::id()));
        let spark = root.join("spark");
        std::fs::create_dir_all(&spark).unwrap();
        std::fs::write(
            spark.join("profile.json"),
            r#"{"schema":"intermed-spark-report-v1","tick_spikes_ms":[80]}"#,
        )
        .unwrap();
        let target = Target {
            path: root.clone(),
            kind: TargetKind::Server,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let import = import_target(&target).unwrap();
        assert_eq!(import.reports.len(), 1);
        assert_eq!(import.reports[0].tick_spikes_ms, vec![80]);
        assert_eq!(
            import.reports[0].source_locator,
            spark.join("profile.json").display().to_string()
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn rejects_out_of_range_numbers_at_import_boundary() {
        let root = std::env::temp_dir().join(format!(
            "intermed-spark-invalid-numeric-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let percent = root.join("percent.json");
        std::fs::write(
            &percent,
            r#"{"schema":"intermed-spark-report-v1","hot_mods":[{"mod":"x","percent":100.1}]}"#,
        )
        .unwrap();
        assert!(import_file(&percent).is_err());

        let integer = root.join("integer.json");
        std::fs::write(
            &integer,
            r#"{"schema":"intermed-spark-report-v1","heap_pressure_bytes":18446744073709551615}"#,
        )
        .unwrap();
        assert!(import_file(&integer).is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn collector_scope_covers_every_emission_path() {
        let mut report: SparkReport = serde_json::from_str(
            r#"{
                "schema":"intermed-spark-report-v1",
                "session_fingerprint":"session-a",
                "tick_spikes_ms":[80],
                "gc_pauses_ms":[90],
                "heap_pressure_bytes":1024,
                "hot_methods":[{"class":"a.A","method":"tick","percent":10.0}],
                "hot_mods":[{"mod":"a","percent":20.0,"phase":"worldgen"}],
                "thread_hotspots":[{"thread":"Server thread","percent":30.0}]
            }"#,
        )
        .unwrap();
        report.source_locator = "/tmp/profile.json".to_string();
        let import = SparkImport {
            target: "/tmp".to_string(),
            reports: vec![report],
            failures: vec![SparkImportFailure {
                path: "/tmp/bad.json".to_string(),
                reason: "malformed".to_string(),
            }],
        };
        let target = dummy_target();
        let inputs = FactStore::new();
        let mut output = FactStore::new();
        let settings = intermed_doctor_core::DiagnosisSettings::default();
        let mut ctx = CollectCtx {
            target: &target,
            store: &mut output,
            inputs: &inputs,
            jar_cache: None,
            settings: &settings,
        };
        let summary = emit_import(&mut ctx, &import);
        assert_eq!(summary.validation_failures, 0);
        let emitted = output
            .all()
            .iter()
            .map(|fact| fact.kind.as_ref())
            .collect::<BTreeSet<_>>();
        let declared = SparkCollector.scope().produces;
        assert_eq!(
            emitted,
            SPARK_OUTPUT_KINDS.iter().copied().collect::<BTreeSet<_>>()
        );
        assert!(emitted.iter().all(|kind| declared.contains(*kind)));
        assert!(
            output
                .all()
                .iter()
                .filter(|fact| { fact.kind.as_ref() != kind::SPARK_IMPORT_FAILURE })
                .all(|fact| fact.source.locator.as_ref() == "/tmp/profile.json")
        );
    }

    #[test]
    fn malformed_report_is_incomplete_not_a_collector_contract_violation() {
        let root =
            std::env::temp_dir().join(format!("intermed-spark-contract-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let report_path = root.join("bad.json");
        std::fs::write(&report_path, "not-json").unwrap();
        let target = Target {
            path: root.clone(),
            kind: TargetKind::Server,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: Some(report_path),
        };
        let engine = intermed_doctor_core::DiagnosticEngine::builder()
            .tool_version("test")
            .collector(collector())
            .rule(rule())
            .build_checked()
            .unwrap();
        let report = engine.diagnose(&target);
        let spark = report
            .collectors
            .iter()
            .find(|collector| collector.id == EXTRACTOR)
            .unwrap();
        assert_eq!(spark.status, "incomplete");
        assert!(report.operational_errors.iter().all(|error| {
            !(error.stage == "collector-contract" && error.component == EXTRACTOR)
        }));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id.starts_with("spark-import-failure:"))
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn explicit_report_excludes_auto_discovered_files() {
        let root =
            std::env::temp_dir().join(format!("intermed-spark-explicit-{}", std::process::id()));
        let spark = root.join("spark");
        std::fs::create_dir_all(&spark).unwrap();
        std::fs::write(spark.join("bad.json"), "not json").unwrap();
        let explicit = root.join("chosen.json");
        std::fs::write(
            &explicit,
            r#"{"schema":"intermed-spark-report-v1","tick_spikes_ms":[90]}"#,
        )
        .unwrap();
        let target = Target {
            path: root.clone(),
            kind: TargetKind::Server,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: Some(explicit),
        };
        let import = import_target(&target).unwrap();
        assert_eq!(import.reports.len(), 1);
        assert!(import.failures.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    // ── Correlation rule ───────────────────────────────────────────────────

    use intermed_doctor_core::facts::FactStore;

    fn dummy_target() -> Target {
        Target {
            path: ".".into(),
            kind: TargetKind::Server,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        }
    }

    fn evaluate(store: &FactStore) -> Vec<Finding> {
        let target = dummy_target();
        let ctx = RuleCtx::for_test(store, &target);
        rule().evaluate(&ctx).unwrap()
    }

    /// Emit a `HOT_METHOD` fact like the spark importer does (numeric percent).
    fn emit_hot_method(store: &mut FactStore, class: &str, method: &str, percent: f64) {
        store
            .fact(EXTRACTOR, kind::HOT_METHOD)
            .subject(class)
            .attr("method", method)
            .attr("percent", percent)
            .emit();
    }

    /// Emit a `MIXIN_TARGET` fact like mixin-intel does (subject = mod id).
    fn emit_mixin_target(store: &mut FactStore, mod_id: &str, target: &str, mixin: &str) {
        store
            .fact("mixin-analyzer", kind::MIXIN_TARGET)
            .subject(mod_id)
            .attr("target", target)
            .attr("mixin", mixin)
            .emit();
    }

    fn emit_mixin_target_with_aliases(
        store: &mut FactStore,
        mod_id: &str,
        target: &str,
        named: &str,
        intermediary: &str,
        mixin: &str,
    ) {
        store
            .fact("mixin-analyzer", kind::MIXIN_TARGET)
            .subject(mod_id)
            .attr("target", target)
            .attr("target_named", named)
            .attr("target_intermediary", intermediary)
            .attr("mixin", mixin)
            .emit();
    }

    #[test]
    fn hot_method_correlates_with_mixin_target() {
        let mut store = FactStore::new();
        emit_mixin_target(
            &mut store,
            "lithium",
            "net.minecraft.server.MinecraftServer",
            "MixinMinecraftServer",
        );
        emit_hot_method(
            &mut store,
            "net.minecraft.server.MinecraftServer",
            "tick",
            42.0,
        );

        let findings = evaluate(&store);
        let f = findings
            .iter()
            .find(|f| f.semantic_id == "perf-mixin:net.minecraft.server.MinecraftServer:tick")
            .expect("correlation finding");
        assert_eq!(f.severity, Severity::Note);
        assert!(f.machine_tags.iter().any(|t| t == "cross-layer"));
        // Cross-layer evidence: the spark fact plus the mixin fact.
        assert!(f.evidence.len() >= 2);
        assert!(f.affected_components.iter().any(|c| c == "lithium"));
    }

    fn emit_site(store: &mut FactStore, mod_id: &str, target_class: &str, method: &str, op: &str) {
        store
            .fact("mixin-analyzer", kind::MIXIN_APPLICATION_SITE)
            .subject(format!("{mod_id}::M::h->{target_class}#{method}"))
            .attr("mod", mod_id)
            .attr("mixin", format!("{mod_id}.M"))
            .attr("target_class", target_class)
            .attr("target_method", method)
            .attr("operation", op)
            .emit();
    }

    #[test]
    fn exact_method_match_is_higher_quality_than_class_only() {
        // A destructive mixin on the *exact* hot method ⇒ exact-method-match + Warn.
        let mut store = FactStore::new();
        emit_mixin_target(
            &mut store,
            "modx",
            "net.minecraft.server.MinecraftServer",
            "M",
        );
        emit_site(
            &mut store,
            "modx",
            "net.minecraft.server.MinecraftServer",
            "tick()V",
            "redirect",
        );
        emit_hot_method(
            &mut store,
            "net.minecraft.server.MinecraftServer",
            "tick",
            30.0,
        );
        let findings = evaluate(&store);
        let f = findings
            .iter()
            .find(|f| f.semantic_id == "perf-mixin:net.minecraft.server.MinecraftServer:tick")
            .expect("correlation finding");
        assert!(f.machine_tags.iter().any(|t| t == "exact-method-match"));
        assert!(f.severity >= Severity::Warn);

        // A mixin on a *different* method of the same class ⇒ class-level only.
        let mut store2 = FactStore::new();
        emit_mixin_target(
            &mut store2,
            "mody",
            "net.minecraft.server.MinecraftServer",
            "M",
        );
        emit_site(
            &mut store2,
            "mody",
            "net.minecraft.server.MinecraftServer",
            "loadWorld()V",
            "redirect",
        );
        emit_hot_method(
            &mut store2,
            "net.minecraft.server.MinecraftServer",
            "tick",
            30.0,
        );
        let f2 = evaluate(&store2)
            .into_iter()
            .find(|f| f.semantic_id == "perf-mixin:net.minecraft.server.MinecraftServer:tick")
            .expect("correlation finding");
        assert!(
            f2.machine_tags
                .iter()
                .any(|t| t == "class-level-correlation")
        );
    }

    #[test]
    fn descriptor_mismatch_does_not_join_an_overload() {
        let mut store = FactStore::new();
        emit_mixin_target(&mut store, "modx", "net.example.Target", "M");
        emit_site(
            &mut store,
            "modx",
            "net.example.Target",
            "work(I)V",
            "redirect",
        );
        emit_hot_method(
            &mut store,
            "net.example.Target",
            "work(Ljava/lang/String;)V",
            30.0,
        );
        let finding = evaluate(&store)
            .into_iter()
            .find(|finding| finding.id.starts_with("perf-mixin:"))
            .expect("class-level correlation remains visible");
        assert!(
            finding
                .machine_tags
                .iter()
                .any(|tag| tag == "class-level-correlation")
        );
        assert!(
            finding
                .machine_tags
                .iter()
                .all(|tag| tag != "exact-method-match")
        );
    }

    #[test]
    fn mapped_owner_method_is_a_real_production_match() {
        let mut store = FactStore::new();
        emit_mixin_target_with_aliases(
            &mut store,
            "modx",
            "net.minecraft.class_3215",
            "net.minecraft.server.MinecraftServer",
            "net.minecraft.class_3215",
            "M",
        );
        store
            .fact("mixin-analyzer", kind::MIXIN_APPLICATION_SITE)
            .subject("mapped-site")
            .attr("mod", "modx")
            .attr("mixin", "M")
            .attr("target_class", "net.minecraft.class_3215")
            .attr("target_method", "method_123()V")
            .attr("name_original", "tick()V")
            .attr("name_canonical", "method_123()V")
            .attr("operation", "redirect")
            .emit();
        emit_hot_method(
            &mut store,
            "net.minecraft.server.MinecraftServer",
            "tick()V",
            30.0,
        );
        let finding = evaluate(&store)
            .into_iter()
            .find(|finding| finding.id.starts_with("perf-mixin:"))
            .expect("mapped correlation");
        assert!(
            finding
                .machine_tags
                .iter()
                .any(|tag| tag == "mapped-owner-method-match")
        );
        assert!(
            finding
                .machine_tags
                .iter()
                .any(|tag| tag == "exact-method-match")
        );
    }

    #[test]
    fn dead_code_regression_hotspot_only_used_to_break_correlation() {
        // Before the fix, the rule read a non-existent `target` attr off
        // MIXIN_HOTSPOT and never correlated. Emitting only a hotspot fact (no
        // MIXIN_TARGET) must still not crash and must not fabricate a join.
        let mut store = FactStore::new();
        store
            .fact("mixin-analyzer", kind::MIXIN_HOTSPOT)
            .subject("server-tick")
            .attr("mod", "lithium")
            .attr("mixin", "MixinMinecraftServer")
            .emit();
        emit_hot_method(
            &mut store,
            "net.minecraft.server.MinecraftServer",
            "tick",
            42.0,
        );

        assert!(
            evaluate(&store)
                .iter()
                .all(|f| !f.id.starts_with("perf-mixin:"))
        );
    }

    #[test]
    fn overwrite_on_hot_class_without_exact_site_remains_context() {
        let mut store = FactStore::new();
        emit_mixin_target(
            &mut store,
            "badmod",
            "net.minecraft.world.entity.Entity",
            "MixinEntity",
        );
        store
            .fact("mixin-analyzer", kind::HIGH_RISK_OVERWRITE)
            .subject("badmod")
            .attr("target", "net.minecraft.world.entity.Entity")
            .attr("mixin", "MixinEntity")
            .attr("hot_path", true)
            .emit();
        emit_hot_method(
            &mut store,
            "net.minecraft.world.entity.Entity",
            "tick",
            12.0,
        );

        let f = evaluate(&store)
            .into_iter()
            .find(|f| f.semantic_id == "perf-mixin:net.minecraft.world.entity.Entity:tick")
            .expect("finding");
        assert_eq!(f.severity, Severity::Note);
        assert!(f.explanation.contains("@Overwrite"));
    }

    #[test]
    fn simple_name_fallback_join() {
        // Spark reports an obfuscated/short class; mixin targets the FQN.
        let mut store = FactStore::new();
        emit_mixin_target(
            &mut store,
            "sodium",
            "net.minecraft.client.render.WorldRenderer",
            "MixinWR",
        );
        emit_hot_method(&mut store, "WorldRenderer", "render", 30.0);

        assert!(
            evaluate(&store)
                .iter()
                .any(|f| f.semantic_id == "perf-mixin:WorldRenderer:render")
        );
    }

    #[test]
    fn below_floor_hot_method_does_not_correlate() {
        // A mixin targets the class, but the method is only 0.5% CPU — noise.
        let mut store = FactStore::new();
        emit_mixin_target(
            &mut store,
            "lithium",
            "net.minecraft.server.MinecraftServer",
            "MixinMS",
        );
        emit_hot_method(
            &mut store,
            "net.minecraft.server.MinecraftServer",
            "tick",
            0.5,
        );
        assert!(
            evaluate(&store)
                .iter()
                .all(|f| !f.id.starts_with("perf-mixin:"))
        );

        // The same class at 6% (above the 5% floor) does correlate.
        let mut store = FactStore::new();
        emit_mixin_target(
            &mut store,
            "lithium",
            "net.minecraft.server.MinecraftServer",
            "MixinMS",
        );
        emit_hot_method(
            &mut store,
            "net.minecraft.server.MinecraftServer",
            "tick",
            6.0,
        );
        assert!(
            evaluate(&store)
                .iter()
                .any(|f| f.semantic_id == "perf-mixin:net.minecraft.server.MinecraftServer:tick")
        );
    }

    #[test]
    fn string_percent_attribute_is_not_comparable() {
        // `percent` must be stored as `AttrValue::Float` (or `Int`); formatted
        // strings are not coerced and the correlation rule skips such facts.
        let mut store = FactStore::new();
        emit_mixin_target(
            &mut store,
            "lithium",
            "net.minecraft.server.MinecraftServer",
            "MixinMS",
        );
        store
            .fact(EXTRACTOR, kind::HOT_METHOD)
            .subject("net.minecraft.server.MinecraftServer")
            .attr("method", "tick")
            .attr("percent", "41.00")
            .emit();
        assert!(
            evaluate(&store)
                .iter()
                .all(|f| !f.id.starts_with("perf-mixin:"))
        );
    }

    #[test]
    fn hot_method_without_mixin_does_not_correlate() {
        let mut store = FactStore::new();
        emit_hot_method(&mut store, "net.minecraft.util.Mth", "sqrt", 80.0);
        assert!(
            evaluate(&store)
                .iter()
                .all(|f| !f.id.starts_with("perf-mixin:"))
        );
    }

    #[test]
    fn hot_mod_with_overwrite_is_correlation_not_hard_error() {
        let mut store = FactStore::new();
        emit_mixin_target(
            &mut store,
            "laggy",
            "net.minecraft.server.MinecraftServer",
            "MixinMS",
        );
        store
            .fact("mixin-analyzer", kind::HIGH_RISK_OVERWRITE)
            .subject("laggy")
            .attr("target", "net.minecraft.server.MinecraftServer")
            .attr("mixin", "MixinMS")
            .attr("hot_path", true)
            .emit();
        store
            .fact(EXTRACTOR, kind::HOT_MOD)
            .subject("laggy")
            .attr("percent", 63.0)
            .emit();

        let f = evaluate(&store)
            .into_iter()
            .find(|f| f.semantic_id == "perf-hot-mod:laggy")
            .expect("hot mod finding");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.explanation.contains("@Overwrite"));
    }

    #[test]
    fn tick_spike_is_enriched_when_correlation_present() {
        let mut store = FactStore::new();
        emit_mixin_target(
            &mut store,
            "lithium",
            "net.minecraft.server.MinecraftServer",
            "MixinMS",
        );
        emit_hot_method(
            &mut store,
            "net.minecraft.server.MinecraftServer",
            "tick",
            20.0,
        );
        store
            .fact(EXTRACTOR, kind::TICK_SPIKE)
            .subject("tick-70ms")
            .attr("ms", 70i64)
            .emit();

        let f = evaluate(&store)
            .into_iter()
            .find(|f| f.semantic_id == "tick-spike:70")
            .expect("tick spike finding");
        assert!(f.explanation.contains("hot method"));
    }

    #[test]
    fn repeated_equal_tick_samples_keep_distinct_occurrences() {
        let mut store = FactStore::new();
        for _ in 0..2 {
            store
                .fact(EXTRACTOR, kind::TICK_SPIKE)
                .subject("tick-70ms")
                .attr("ms", 70_i64)
                .emit();
        }
        let findings = evaluate(&store)
            .into_iter()
            .filter(|finding| finding.semantic_id == "tick-spike:70")
            .collect::<Vec<_>>();
        assert_eq!(findings.len(), 2);
        assert_ne!(findings[0].id, findings[1].id);
        assert_ne!(findings[0].occurrence_id, findings[1].occurrence_id);
    }

    #[test]
    fn small_tick_spike_below_threshold_is_ignored() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::TICK_SPIKE)
            .subject("tick-10ms")
            .attr("ms", 10i64)
            .emit();
        assert!(
            evaluate(&store)
                .iter()
                .all(|f| !f.id.starts_with("tick-spike:"))
        );
    }

    #[test]
    fn named_spark_class_joins_intermediary_mixin_target() {
        let mut store = FactStore::new();
        emit_mixin_target_with_aliases(
            &mut store,
            "lithium",
            "net.minecraft.class_3215",
            "net.minecraft.server.MinecraftServer",
            "net.minecraft.class_3215",
            "MixinMS",
        );
        emit_hot_method(
            &mut store,
            "net.minecraft.server.MinecraftServer",
            "tick",
            22.5,
        );
        assert!(
            evaluate(&store).iter().any(|f| {
                f.semantic_id == "perf-mixin:net.minecraft.server.MinecraftServer:tick"
            })
        );
    }

    #[test]
    fn performance_inactive_note_when_no_spark_facts() {
        let store = FactStore::new();
        assert!(
            evaluate(&store)
                .iter()
                .any(|f| f.id == "performance-inactive")
        );
    }

    #[test]
    fn spark_import_failure_surfaces_as_finding() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::SPARK_IMPORT_FAILURE)
            .subject("/tmp/bad.json")
            .attr("reason", "parse error")
            .emit();
        assert!(
            evaluate(&store)
                .iter()
                .any(|f| f.id == "spark-import-failure:/tmp/bad.json")
        );
    }

    #[test]
    fn tick_spike_with_log_mention_flags_tick_log_suspect() {
        let mut store = FactStore::new();
        store.fact("metadata", kind::MOD).subject("laggy").emit();
        store
            .fact(EXTRACTOR, kind::TICK_SPIKE)
            .subject("tick-120ms")
            .attr("ms", 120_i64)
            .emit();
        store
            .fact("log-analyzer", kind::LOG_MENTIONS_MOD)
            .subject("laggy")
            .attr("exception", "java.lang.RuntimeException")
            .emit();

        let findings = evaluate(&store);
        assert!(
            findings
                .iter()
                .any(|f| f.id == "perf-tick-log-suspect:laggy")
        );
    }

    #[test]
    fn heavy_tick_handler_with_spikes_is_static_candidate() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::TICK_SPIKE)
            .subject("80")
            .attr("ms", 80i64)
            .emit();
        store
            .fact("metadata-scanner", kind::MOD_CAPABILITY)
            .subject("laggymod")
            .attr("capability", "heavy_tick_handler")
            .emit();
        store
            .fact("metadata-scanner", kind::MOD_CAPABILITY)
            .subject("tickmod")
            .attr("capability", "hooks_game_tick")
            .emit();

        let findings = evaluate(&store);
        let heavy = findings
            .iter()
            .find(|f| f.id == "perf-tick-handler:laggymod")
            .expect("heavy tick handler finding");
        assert_eq!(heavy.severity, Severity::Note);
        assert!(
            heavy
                .machine_tags
                .iter()
                .any(|tag| tag == "performance-candidate")
        );
        // A plain tick subscriber (no proven-heavy handler) is a lower-severity note.
        let plain = findings
            .iter()
            .find(|f| f.id == "perf-tick-handler:tickmod")
            .expect("tick subscriber finding");
        assert_eq!(plain.severity, Severity::Note);
    }

    #[test]
    fn no_tick_spike_means_no_tick_handler_finding() {
        let mut store = FactStore::new();
        store
            .fact("metadata-scanner", kind::MOD_CAPABILITY)
            .subject("laggymod")
            .attr("capability", "heavy_tick_handler")
            .emit();
        assert!(
            !evaluate(&store)
                .iter()
                .any(|f| f.id.starts_with("perf-tick-handler:"))
        );
    }

    #[test]
    fn hot_mod_named_in_unscoped_logs_is_explain_only_context() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::HOT_MOD)
            .subject("laggymod")
            .attr("percent", 17.5)
            .emit();
        store
            .fact("log-analyzer", kind::LOG_MENTIONS_MOD)
            .subject("laggymod")
            .attr("via", "mixin-config")
            .attr("exception", "java.lang.RuntimeException")
            .emit();
        // A mod that is hot but NOT in the logs must not produce the correlation.
        store
            .fact(EXTRACTOR, kind::HOT_MOD)
            .subject("fastmod")
            .attr("percent", 30.0)
            .emit();

        let findings = evaluate(&store);
        assert!(
            findings.iter().any(|f| {
                f.semantic_id == "perf-log-suspect:laggymod"
                    && f.severity == Severity::Note
                    && f.visibility == FindingVisibility::ExplainOnly
                    && f.explanation.contains("17.5%")
            }),
            "expected non-causal context finding for laggymod"
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.semantic_id == "perf-log-suspect:fastmod"),
            "a hot mod absent from logs must not correlate"
        );
    }

    #[test]
    fn hot_mod_shipping_worldgen_data_gets_a_directed_hotspot() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::HOT_MOD)
            .subject("wgmod")
            .attr("percent", 28.0)
            .emit();
        store
            .fact("vfs", kind::RESOURCE_WRITER)
            .subject("wgmod")
            .attr("path", "data/wgmod/worldgen/configured_feature/x.json")
            .attr("json", true)
            .emit();

        let f = evaluate(&store)
            .into_iter()
            .find(|f| f.semantic_id == "worldgen-hotspot:wgmod")
            .expect("cluster-E worldgen hotspot");
        assert_eq!(f.severity, Severity::Note);
        assert!(f.machine_tags.iter().any(|t| t == "resource"));
        assert!(f.explanation.contains("world generation"));
    }

    #[test]
    fn hot_mod_without_matching_resources_has_no_directed_hotspot() {
        // A hot mod that ships no categorized resources must not get a cluster-E hint.
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::HOT_MOD)
            .subject("ticky")
            .attr("percent", 40.0)
            .emit();
        store
            .fact("vfs", kind::RESOURCE_WRITER)
            .subject("ticky")
            .attr("path", "META-INF/MANIFEST.MF")
            .attr("json", false)
            .emit();

        assert!(evaluate(&store).into_iter().all(|f| {
            !f.id.ends_with(":ticky")
                || !(f.id.starts_with("worldgen-hotspot")
                    || f.id.starts_with("atlas-hotspot")
                    || f.id.starts_with("model-bake-hotspot")
                    || f.id.starts_with("resource-reload-hotspot"))
        }));
    }

    #[test]
    fn rule_read_set_is_declared() {
        let mut store = FactStore::new();
        for fact_kind in [
            kind::HOT_METHOD,
            kind::HOT_MOD,
            kind::TICK_SPIKE,
            kind::GC_PAUSE,
            kind::HEAP_PRESSURE,
            kind::THREAD_HOTSPOT,
            kind::SPARK_IMPORT_FAILURE,
            kind::MIXIN_APPLICATION_SITE,
            kind::MIXIN_TARGET,
            kind::MIXIN_OPERATION,
            kind::MIXIN_OVERLAP,
            kind::HIGH_RISK_OVERWRITE,
            kind::MIXIN_HOTSPOT,
            kind::MOD_CAPABILITY,
            kind::RESOURCE_COLLISION,
            kind::RESOURCE_WRITER,
            kind::LOG_SIGNAL,
            kind::LOG_MENTIONS_MOD,
            kind::STACK_FRAME,
            kind::THROWABLE_NODE,
            kind::MOD,
            kind::PLUGIN,
        ] {
            store.fact("fixture", fact_kind).subject("fixture").emit();
        }
        store.enable_read_tracking();
        let performance_rule = rule();
        let requirements = performance_rule.requirements();
        let target = dummy_target();
        let ctx = RuleCtx::for_test(&store, &target);
        performance_rule.evaluate(&ctx).unwrap();
        let undeclared = store
            .recorded_reads()
            .difference(&requirements.declared_fact_kinds())
            .cloned()
            .collect::<Vec<_>>();
        assert!(undeclared.is_empty(), "undeclared reads: {undeclared:?}");
    }

    #[test]
    fn ambiguous_simple_class_does_not_join() {
        let mut store = FactStore::new();
        emit_mixin_target(&mut store, "a", "com.a.Manager", "A");
        emit_mixin_target(&mut store, "b", "com.b.Manager", "B");
        emit_hot_method(&mut store, "Manager", "run", 40.0);
        assert!(
            evaluate(&store)
                .iter()
                .all(|finding| !finding.id.starts_with("perf-mixin:"))
        );
    }

    #[test]
    fn overloaded_name_without_descriptor_is_not_exact() {
        let mut store = FactStore::new();
        emit_mixin_target(&mut store, "a", "com.a.Target", "A");
        emit_site(&mut store, "a", "com.a.Target", "work(I)V", "redirect");
        emit_site(
            &mut store,
            "a",
            "com.a.Target",
            "work(Ljava/lang/String;)V",
            "redirect",
        );
        emit_hot_method(&mut store, "com.a.Target", "work", 40.0);
        let finding = evaluate(&store)
            .into_iter()
            .find(|finding| finding.id.starts_with("perf-mixin:"))
            .unwrap();
        assert!(
            finding
                .machine_tags
                .iter()
                .any(|tag| tag == "class-level-correlation")
        );
        assert!(
            finding
                .machine_tags
                .iter()
                .all(|tag| tag != "exact-method-match")
        );
    }

    #[test]
    fn hot_method_log_join_uses_structured_exact_frame() {
        let mut store = FactStore::new();
        emit_hot_method(&mut store, "com.example.Worker", "run", 20.0);
        store
            .fact("log", kind::LOG_SIGNAL)
            .subject("RuntimeException")
            .attr("excerpt", "unrelated runner text containing run")
            .emit();
        assert!(
            evaluate(&store)
                .iter()
                .all(|finding| !finding.id.starts_with("perf-hot-method-log:"))
        );
        store
            .fact("log", kind::STACK_FRAME)
            .subject("event")
            .attr("class", "com.example.Worker")
            .attr("method", "run")
            .emit();
        assert!(
            evaluate(&store)
                .iter()
                .any(|finding| finding.id.starts_with("perf-hot-method-log:"))
        );
    }

    #[test]
    fn configurable_floor_applies_to_resource_correlations() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::HOT_MOD)
            .subject("wgmod")
            .attr("percent", 10.0)
            .emit();
        store
            .fact("vfs", kind::RESOURCE_WRITER)
            .subject("wgmod")
            .attr("path", "data/wgmod/worldgen/biome/x.json")
            .emit();
        let target = dummy_target();
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = rule_with_thresholds(PerformanceThresholds {
            hot_method_floor_percent: 20.0,
            ..PerformanceThresholds::default()
        })
        .evaluate(&ctx)
        .unwrap();
        assert!(
            findings
                .iter()
                .all(|finding| finding.semantic_id != "worldgen-hotspot:wgmod")
        );
    }

    #[test]
    fn gc_and_thread_observations_are_analyzed() {
        let mut store = FactStore::new();
        for ms in [80_i64, 120_i64] {
            store
                .fact(EXTRACTOR, kind::GC_PAUSE)
                .subject(format!("gc-{ms}"))
                .attr("ms", ms)
                .source(SourceRef::file("profile.json"))
                .emit();
        }
        store
            .fact(EXTRACTOR, kind::THREAD_HOTSPOT)
            .subject("G1 Main Marker")
            .attr("percent", 30.0)
            .attr("thread_class", "garbage-collector")
            .source(SourceRef::file("profile.json"))
            .emit();
        let findings = evaluate(&store);
        assert!(
            findings
                .iter()
                .any(|finding| finding.id.starts_with("perf-gc-pause:"))
        );
        assert!(findings.iter().any(|finding| {
            finding.id.starts_with("perf-thread-hotspot:") && finding.severity == Severity::Warn
        }));
    }

    #[test]
    fn hot_mod_and_method_are_direct_observations() {
        let mut store = FactStore::new();
        emit_hot_method(&mut store, "com.example.Work", "run", 12.5);
        store
            .fact(EXTRACTOR, kind::HOT_MOD)
            .subject("example")
            .attr("percent", 18.0)
            .emit();
        let findings = evaluate(&store);
        assert!(findings.iter().any(|finding| {
            finding.id.starts_with("perf-hot-method-observed:")
                && finding.family == "performance-observation"
        }));
        assert!(findings.iter().any(|finding| {
            finding.id.starts_with("perf-hot-mod-observed:")
                && finding.family == "performance-observation"
        }));
    }

    #[test]
    fn thread_only_profile_is_not_reported_inactive() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::THREAD_HOTSPOT)
            .subject("Server thread")
            .attr("percent", 15.0)
            .attr("thread_class", "server")
            .emit();
        let findings = evaluate(&store);
        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "performance-inactive")
        );
    }
}
