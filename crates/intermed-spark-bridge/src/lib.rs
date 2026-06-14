//! # intermed-spark-bridge — Layer I (Phase 7)
//!
//! Performance evidence importer. Reads `intermed-spark-report-v1` JSON (exported
//! from Spark or hand-authored fixtures) — never forks or runs the Spark profiler.

mod config;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Relation, Severity};
use intermed_doctor_core::facts::{kind, SourceRef};
use intermed_doctor_core::{CollectCtx, Collector, CollectorOutcome, Layer, Rule, RuleCtx, Target};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const EXTRACTOR: &str = "spark-importer";
pub const SPARK_REPORT_SCHEMA: &str = "intermed-spark-report-v1";

/// Implementation status for help text.
pub const STATUS: &str = "active: Phase 7";

/// Layer-I collector.
pub fn collector() -> impl Collector {
    SparkCollector
}

pub use config::{
    PerformanceThresholds, DEFAULT_HIGH_CPU_PERCENT, DEFAULT_HOT_METHOD_FLOOR_PERCENT,
    DEFAULT_TICK_SPIKE_MS,
};

/// Layer-I performance correlation rule (default thresholds).
pub fn rule() -> impl Rule {
    rule_with_thresholds(PerformanceThresholds::default())
}

/// Layer-I performance correlation rule with explicit thresholds.
pub fn rule_with_thresholds(thresholds: PerformanceThresholds) -> impl Rule {
    PerformanceRules {
        thresholds,
    }
}

/// Correlation plus user-visible notices when Spark data is missing or failed.
struct PerformanceRules {
    thresholds: PerformanceThresholds,
}

impl Rule for PerformanceRules {
    fn id(&self) -> &'static str {
        "performance"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut out = PerformanceCorrelationRule {
            thresholds: self.thresholds,
        }
        .evaluate(ctx);
        out.extend(perf_tick_mixin_hotpath_findings(ctx));
        out.extend(perf_hot_mod_resource_findings(ctx));
        out.extend(perf_hot_method_log_findings(ctx));
        out.extend(performance_notice_findings(ctx));
        out.extend(performance_fallback_findings(ctx));
        out.extend(perf_log_correlation_findings(ctx));
        out.extend(perf_tick_log_correlation_findings(ctx));
        out.extend(perf_tick_heavy_handler_findings(ctx));
        out
    }
}

/// Cross-layer correlation (Layer I × Layer D): a mod that is **both** a Spark CPU
/// hotspot (`hot_mod`) **and** named in a crash/error stack trace
/// (`log_mentions_mod`) is the prime suspect — it is simultaneously slow and
/// failing. Either signal alone is weaker; together they point at one mod.
/// Killer cross-layer connection (Layer B × Layer I): the server has **tick
/// spikes** and a mod is known (from bytecode capability analysis) to have a
/// **heavy tick-event handler** — code that runs every tick and is large / loops /
/// allocates. That is the single most direct "this mod is likely causing your
/// lag" signal the metadata layer enables. Falls back to `hooks_game_tick` (a
/// tick subscriber without a proven-heavy handler) at lower severity.
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
            let entry = tick_mods.entry(f.subject.as_str()).or_insert((false, Vec::new()));
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
        let severity = if heavy { Severity::Warn } else { Severity::Note };
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
                 Tick handlers run every tick, so this mod is a prime suspect for the lag — profile it \
                 with `/spark profiler` while watching its handler."
            ))
            .affects(mod_id.to_string())
            .fix(FixCandidate::advice(
                "Profile or temporarily remove this mod to confirm; if it is the cause, check its config \
                 for a way to reduce per-tick work, or report the hotspot upstream.",
            ))
            .tag("performance")
            .tag("tick")
            .tag("capability");
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
            let pct = f.attr("percent").and_then(|p| p.parse::<f64>().ok()).unwrap_or(0.0);
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
        let mut builder = Finding::builder(
            "performance",
            format!("perf-log-suspect:{mod_id}"),
        )
        .severity(Severity::Warn)
        .category(Category::Performance)
        .title(format!("`{mod_id}` is both a CPU hotspot and appears in error logs"))
        .explanation(format!(
            "Spark attributes {percent:.1}% of profiled time to `{mod_id}`, and it is also \
             named in {} crash/error stack trace(s){}. A mod that is simultaneously slow and \
             failing is the prime suspect — investigate it before the rest.",
            mention_facts.len(),
            if exceptions.is_empty() {
                String::new()
            } else {
                format!(" ({})", exceptions.into_iter().collect::<Vec<_>>().join(", "))
            }
        ))
        .evidence(EvidenceEdge::subject(*hot_fact))
        .affects(mod_id.to_string())
        .fix(FixCandidate::advice(
            "Update or remove this mod and re-profile; its CPU cost and its errors likely share a cause.",
        ))
        .tag("performance")
        .tag("log")
        .tag("correlation");
        for f in mention_facts {
            builder = builder.evidence(EvidenceEdge::supports(f.id));
        }
        out.push(builder.build());
    }
    out
}

/// D3 extension: tick spikes co-occurring with crash/error log mod mentions.
///
/// Wall-clock alignment of spikes to log lines is not attempted (Spark ms vs log
/// line numbers share no timeline). Mod-level join is the sound correlation.
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
                "MixinApplyError" | "ModLoadingFailure" | "MissingDependency" | "ClassNotFound"
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
        let mut builder = Finding::builder(
            "performance",
            format!("perf-tick-log-suspect:{mod_id}"),
        )
        .severity(Severity::Warn)
        .category(Category::Performance)
        .title(format!(
            "`{mod_id}` appears in error logs while tick spikes were recorded"
        ))
        .explanation(format!(
            "Spark reported server tick spikes and `{mod_id}` is named in {} crash/error \
             stack trace(s){}. Investigate this mod first — lag and failures may share a root cause.",
            mentions.len(),
            if exceptions.is_empty() {
                String::new()
            } else {
                format!(" ({})", exceptions.into_iter().collect::<Vec<_>>().join(", "))
            }
        ))
        .affects(mod_id.to_string())
        .fix(FixCandidate::advice(format!(
            "Update or temporarily remove `{mod_id}`, then re-profile and re-check logs."
        )))
        .tag("performance")
        .tag("log")
        .tag("tick")
        .tag("correlation");
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
    #[serde(default)]
    pub source: String,
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

// ── Collector ─────────────────────────────────────────────────────────────

struct SparkCollector;

impl Collector for SparkCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }

    fn layer(&self) -> Layer {
        Layer::Performance
    }

    fn applies(&self, target: &Target) -> bool {
        discover_report_paths(target).next().is_some()
    }

    fn not_applicable(&self, _target: &Target) -> CollectorOutcome {
        CollectorOutcome::skipped(
            "no spark report found (use --spark-report or place JSON under spark/)",
        )
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        match import_target(ctx.target) {
            Ok(import) => {
                let emitted = emit_import(ctx, &import);
                CollectorOutcome::active(
                    emitted,
                    format!(
                        "{} report(s), {} failure(s)",
                        import.reports.len(),
                        import.failures.len()
                    ),
                )
            }
            Err(e) => CollectorOutcome::failed(e.to_string()),
        }
    }
}

fn emit_import(ctx: &mut CollectCtx<'_>, import: &SparkImport) -> usize {
    let mut emitted = 0usize;
    for failure in &import.failures {
        ctx.store
            .fact(EXTRACTOR, kind::SPARK_IMPORT_FAILURE)
            .subject(failure.path.clone())
            .attr("reason", failure.reason.clone())
            .source(SourceRef::file(failure.path.clone()))
            .emit();
        emitted += 1;
    }
    for (report_idx, report) in import.reports.iter().enumerate() {
        let locator = format!("spark-report-{report_idx}");
        for ms in &report.tick_spikes_ms {
            ctx.store
                .fact(EXTRACTOR, kind::TICK_SPIKE)
                .subject(format!("tick-{ms}ms"))
                .attr("ms", *ms as i64)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
        for ms in &report.gc_pauses_ms {
            ctx.store
                .fact(EXTRACTOR, kind::GC_PAUSE)
                .subject(format!("gc-{ms}ms"))
                .attr("ms", *ms as i64)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
        if let Some(bytes) = report.heap_pressure_bytes {
            ctx.store
                .fact(EXTRACTOR, kind::HEAP_PRESSURE)
                .subject("heap")
                .attr("bytes", bytes as i64)
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
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
        for hm in &report.hot_mods {
            ctx.store
                .fact(EXTRACTOR, kind::HOT_MOD)
                .subject(hm.r#mod.clone())
                .attr("percent", hm.percent)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
        for th in &report.thread_hotspots {
            ctx.store
                .fact(EXTRACTOR, kind::THREAD_HOTSPOT)
                .subject(th.thread.clone())
                .attr("percent", th.percent)
                .source(SourceRef::file(locator.clone()))
                .emit();
            emitted += 1;
        }
    }
    emitted
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
    /// Alternate class names (intermediary, named, simple) → canonical `by_class` key.
    class_aliases: BTreeMap<String, String>,
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
            let canonical = f
                .attr("target_named")
                .unwrap_or(target)
                .to_string();
            let entry = index.by_class.entry(canonical.clone()).or_default();
            entry.mods.insert(f.subject.clone());
            if let Some(mixin) = f.attr("mixin") {
                entry.mixins.insert(mixin.to_string());
            }
            entry.fact_ids.push(f.id);

            let mod_entry = index.by_mod.entry(f.subject.clone()).or_default();
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
            entry.mods.insert(f.subject.clone());
            entry.fact_ids.push(f.id);
        }

        // Overlap facts are keyed by the target class and carry the hot-path flag.
        for f in store.by_kind(kind::MIXIN_OVERLAP) {
            let entry = index.by_class.entry(f.subject.clone()).or_default();
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
            entry.mods.insert(f.subject.clone());
            if let Some(mixin) = f.attr("mixin") {
                entry.mixins.insert(mixin.to_string());
            }
            if f.attr_bool("hot_path") == Some(true) {
                entry.hot_path = true;
            }
            entry.fact_ids.push(f.id);

            let mod_entry = index.by_mod.entry(f.subject.clone()).or_default();
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
            .insert(alias.to_string(), canonical.to_string());
    }

    /// Resolve every mixin-target view a Spark-reported class joins to: an exact
    /// FQN match first, otherwise a simple-name match.
    fn match_class(&self, class: &str) -> Vec<&MixinTargetInfo> {
        let key = self
            .class_aliases
            .get(class)
            .map(String::as_str)
            .unwrap_or(class);
        if let Some(info) = self.by_class.get(key) {
            return vec![info];
        }
        let simple = simple_class_name(class);
        match self.by_simple.get(simple) {
            Some(fqns) => fqns
                .iter()
                .filter_map(|fqn| self.by_class.get(fqn))
                .collect(),
            None => Vec::new(),
        }
    }
}

impl Rule for PerformanceCorrelationRule {
    fn id(&self) -> &'static str {
        "performance-correlation"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
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
            let severity = hot_method_severity(percent, &merged, self.thresholds);

            let mut builder = Finding::builder(self.id(), format!("perf-mixin:{class}:{method}"))
                .severity(severity)
                .category(Category::Performance)
                .title(format!(
                    "Hot method `{class}.{method}` is modified by {} mixin(s)",
                    merged.mixins.len().max(1)
                ))
                .explanation(hot_method_explanation(class, method, percent, &merged))
                .evidence(EvidenceEdge::subject(f.id))
                .affects(class)
                .fix(FixCandidate::advice(hot_method_advice(&merged)))
                .tag("performance")
                .tag("mixin")
                .tag("cross-layer");
            for mod_id in &merged.mods {
                builder = builder.affects(mod_id.clone());
            }
            // Cross-layer evidence: link the supporting mixin facts.
            for fact_id in &merged.fact_ids {
                builder = builder.evidence(EvidenceEdge::supports(*fact_id));
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
            let severity = if !info.overwrite_classes.is_empty()
                || percent >= self.thresholds.high_cpu_percent
            {
                Severity::Error
            } else {
                Severity::Warn
            };
            let mut builder = Finding::builder(self.id(), format!("perf-hot-mod:{mod_id}"))
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
                .tag("cross-layer");
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
                Finding::builder(self.id(), format!("tick-spike:{ms}"))
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
                    .build(),
            );
        }

        out
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
        .severity(if max_ms >= 100 { Severity::Warn } else { Severity::Note })
        .category(Category::Performance)
        .confidence(0.78)
        .title(format!(
            "Tick spikes recorded while `{mod_id}` patches {} hot-path mixin target(s)",
            hot_targets.len()
        ))
        .explanation(format!(
            "Spark reported server tick spikes (up to {max_ms} ms) and mod `{mod_id}` modifies \
             hot-path class(es): {}. Mixin work on tick-critical targets is a prime lag suspect — \
             profile with Spark and review these targets first.",
            hot_targets.join(", ")
        ))
        .affects(mod_id.clone())
        .fix(FixCandidate::advice(
            "Capture a Spark profile during lag and compare hot methods with this mod's mixin targets.",
        ))
        .tag("performance")
        .tag("mixin")
        .tag("tick")
        .tag("correlation");
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
fn perf_hot_mod_resource_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let collisions: Vec<_> = ctx.store.by_kind(kind::RESOURCE_COLLISION).collect();
    if collisions.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for hot in ctx.store.by_kind(kind::HOT_MOD) {
        let mod_id = hot.subject.as_str();
        let percent = hot.attr_f64("percent").unwrap_or(0.0);
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
        let mut builder = Finding::builder("performance", format!("perf-hot-mod-resource:{mod_id}"))
            .severity(Severity::Warn)
            .category(Category::Performance)
            .confidence(0.74)
            .title(format!(
                "Hot mod `{mod_id}` ({percent:.1}% CPU) also collides on {} resource path(s)",
                paths.len()
            ))
            .explanation(format!(
                "Spark attributes {percent:.1}% CPU to `{mod_id}` and it is among the writers \
                 for conflicting resource path(s): {}. Heavy tick cost plus pack resource \
                 contention often points at the same mod — try disabling it and re-profiling.",
                paths.join(", ")
            ))
            .evidence(EvidenceEdge::subject(hot.id))
            .affects(mod_id)
            .fix(FixCandidate::advice(
                "Resolve the resource collision or temporarily remove this mod, then re-profile.",
            ))
            .tag("performance")
            .tag("vfs")
            .tag("correlation");
        for c in related {
            builder = builder.evidence(EvidenceEdge::supports(c.id));
        }
        out.push(builder.build());
    }
    out
}

/// Hot profiled method whose target class is also named in error logs.
fn perf_hot_method_log_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let index = MixinIndex::build(ctx.store);
    let log_signals: Vec<_> = ctx.store.by_kind(kind::LOG_SIGNAL).collect();
    if log_signals.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for hot in ctx.store.by_kind(kind::HOT_METHOD) {
        let class = hot.subject.as_str();
        let method = hot.attr("method").unwrap_or("?");
        let Some(percent) = parse_percent(hot) else {
            continue;
        };
        if percent < DEFAULT_HOT_METHOD_FLOOR_PERCENT {
            continue;
        }
        let simple = simple_class_name(class);
        let matching_logs: Vec<_> = log_signals
            .iter()
            .filter(|f| {
                f.attr("excerpt").is_some_and(|ex| {
                    ex.contains(class) || ex.contains(simple) || ex.contains(method)
                })
            })
            .collect();
        if matching_logs.is_empty() {
            continue;
        }
        let merged = MixinTargetInfo::merge(index.match_class(class).into_iter());
        let mut builder = Finding::builder(
            "performance",
            format!("perf-hot-method-log:{class}:{method}"),
        )
        .severity(Severity::Warn)
        .category(Category::Performance)
        .confidence(0.76)
        .title(format!(
            "Hot method `{class}.{method}` matches {n} log signal(s)",
            n = matching_logs.len()
        ))
        .explanation(format!(
            "Spark attributes {percent:.1}% CPU to `{class}.{method}` and the latest logs contain \
             {n} matching error/lag signal(s) referencing that class or method. The failing stack \
             and the expensive frame likely share a root cause.",
            n = matching_logs.len()
        ))
        .evidence(EvidenceEdge::subject(hot.id))
        .affects(class)
        .fix(FixCandidate::advice(
            "Inspect the cited log excerpts and disable mixins or mods touching this class, then re-profile.",
        ))
        .tag("performance")
        .tag("log")
        .tag("correlation");
        for mod_id in &merged.mods {
            builder = builder.affects(mod_id.clone());
        }
        for f in matching_logs {
            builder = builder.evidence(EvidenceEdge::supports(f.id));
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
        || ctx.store.by_kind(kind::HEAP_PRESSURE).next().is_some();
    if has_perf {
        return Vec::new();
    }
    if ctx.store.by_kind(kind::SPARK_IMPORT_FAILURE).next().is_some() {
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
        || ctx.store.by_kind(kind::HEAP_PRESSURE).next().is_some();
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
        Severity::Error
    } else {
        Severity::Warn
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
             likely cause of the regression and the first thing to audit.",
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
    explanation
}

/// Read the `percent` attribute as a native number (`Float`/`Int` only).
fn parse_percent(fact: &intermed_doctor_core::facts::Fact) -> Option<f64> {
    fact.attr_f64("percent")
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
    let report: SparkReport = serde_json::from_str(&text)
        .map_err(|e| SparkImportError(format!("parse {}: {e}", path.display())))?;
    if report.schema != SPARK_REPORT_SCHEMA {
        return Err(SparkImportError(format!(
            "unsupported schema `{}` in {} (expected {SPARK_REPORT_SCHEMA})",
            report.schema,
            path.display()
        )));
    }
    Ok(report)
}

fn discover_report_paths(target: &Target) -> impl Iterator<Item = PathBuf> + '_ {
    let mut paths = Vec::new();
    if let Some(explicit) = &target.spark_report {
        if explicit.is_file() {
            paths.push(explicit.clone());
        }
    }
    for sub in ["spark", "profiler"] {
        let dir = target.path.join(sub);
        if dir.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    if p.extension().and_then(|e| e.to_str()) == Some("json") {
                        paths.push(p);
                    }
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
        rule().evaluate(&ctx)
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
            .find(|f| f.id == "perf-mixin:net.minecraft.server.MinecraftServer:tick")
            .expect("correlation finding");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.machine_tags.iter().any(|t| t == "cross-layer"));
        // Cross-layer evidence: the spark fact plus the mixin fact.
        assert!(f.evidence.len() >= 2);
        assert!(f.affected_components.iter().any(|c| c == "lithium"));
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

        assert!(evaluate(&store)
            .iter()
            .all(|f| !f.id.starts_with("perf-mixin:")));
    }

    #[test]
    fn overwrite_on_hot_class_escalates_to_error() {
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
            .find(|f| f.id == "perf-mixin:net.minecraft.world.entity.Entity:tick")
            .expect("finding");
        assert_eq!(f.severity, Severity::Error);
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

        assert!(evaluate(&store)
            .iter()
            .any(|f| f.id == "perf-mixin:WorldRenderer:render"));
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
        assert!(evaluate(&store)
            .iter()
            .all(|f| !f.id.starts_with("perf-mixin:")));

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
        assert!(evaluate(&store)
            .iter()
            .any(|f| f.id == "perf-mixin:net.minecraft.server.MinecraftServer:tick"));
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
        assert!(evaluate(&store)
            .iter()
            .all(|f| !f.id.starts_with("perf-mixin:")));
    }

    #[test]
    fn hot_method_without_mixin_does_not_correlate() {
        let mut store = FactStore::new();
        emit_hot_method(&mut store, "net.minecraft.util.Mth", "sqrt", 80.0);
        assert!(evaluate(&store)
            .iter()
            .all(|f| !f.id.starts_with("perf-mixin:")));
    }

    #[test]
    fn hot_mod_with_overwrite_is_error_finding() {
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
            .find(|f| f.id == "perf-hot-mod:laggy")
            .expect("hot mod finding");
        assert_eq!(f.severity, Severity::Error);
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
            .find(|f| f.id == "tick-spike:70")
            .expect("tick spike finding");
        assert!(f.explanation.contains("hot method"));
    }

    #[test]
    fn small_tick_spike_below_threshold_is_ignored() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::TICK_SPIKE)
            .subject("tick-10ms")
            .attr("ms", 10i64)
            .emit();
        assert!(evaluate(&store)
            .iter()
            .all(|f| !f.id.starts_with("tick-spike:")));
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
        assert!(evaluate(&store).iter().any(|f| {
            f.id == "perf-mixin:net.minecraft.server.MinecraftServer:tick"
        }));
    }

    #[test]
    fn performance_inactive_note_when_no_spark_facts() {
        let store = FactStore::new();
        assert!(evaluate(&store)
            .iter()
            .any(|f| f.id == "performance-inactive"));
    }

    #[test]
    fn spark_import_failure_surfaces_as_finding() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::SPARK_IMPORT_FAILURE)
            .subject("/tmp/bad.json")
            .attr("reason", "parse error")
            .emit();
        assert!(evaluate(&store)
            .iter()
            .any(|f| f.id == "spark-import-failure:/tmp/bad.json"));
    }

    #[test]
    fn tick_spike_with_log_mention_flags_tick_log_suspect() {
        let mut store = FactStore::new();
        store
            .fact("metadata", kind::MOD)
            .subject("laggy")
            .emit();
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
        assert!(findings.iter().any(|f| f.id == "perf-tick-log-suspect:laggy"));
    }

    #[test]
    fn heavy_tick_handler_with_spikes_is_flagged_warn() {
        let mut store = FactStore::new();
        store.fact(EXTRACTOR, kind::TICK_SPIKE).subject("80").attr("ms", 80i64).emit();
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
        assert_eq!(heavy.severity, Severity::Warn);
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
        assert!(!evaluate(&store)
            .iter()
            .any(|f| f.id.starts_with("perf-tick-handler:")));
    }

    #[test]
    fn hot_mod_named_in_logs_is_flagged_as_prime_suspect() {
        let mut store = FactStore::new();
        store
            .fact(EXTRACTOR, kind::HOT_MOD)
            .subject("laggymod")
            .attr("percent", 42.0)
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
            findings.iter().any(|f| f.id == "perf-log-suspect:laggymod"
                && f.severity == Severity::Warn),
            "expected prime-suspect finding for laggymod"
        );
        assert!(
            !findings.iter().any(|f| f.id == "perf-log-suspect:fastmod"),
            "a hot mod absent from logs must not correlate"
        );
    }
}
