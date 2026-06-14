//! The diagnosis engine: run collectors → fact store → run rules → assemble
//! report. The engine knows nothing concrete about Minecraft, logs, or
//! dependencies — it only orchestrates [`Collector`]s and [`Rule`]s that the
//! composition root (the CLI) registers. Adding a layer never touches this file.

use std::time::Instant;

use intermed_evidence::Finding;
use intermed_facts::{Fact, FactStore};

use crate::collector::{CollectCtx, Collector};
use crate::jar_cache::JarCache;
use crate::profile::{DiagnosticProfile, PhaseTiming};
use crate::report::{self, DoctorReport, RuleStat};
use crate::rule::{Rule, RuleCtx};
use crate::settings::DiagnosisSettings;
use crate::target::Target;

/// Holds the registered collectors and rules for a diagnosis run.
pub struct DiagnosticEngine {
    tool_version: String,
    collectors: Vec<Box<dyn Collector>>,
    rules: Vec<Box<dyn Rule>>,
    jar_cache: Option<JarCache>,
    settings: DiagnosisSettings,
}

/// Complete result of one pipeline execution.
///
/// [`DoctorReport`] intentionally carries compact report data; Phase 2 CLI
/// affordances such as `--dump-facts` and `--explain` need the fact snapshot
/// alongside it without running collectors twice.
#[derive(Debug, Clone)]
pub struct DiagnosticRun {
    pub report: DoctorReport,
    pub facts: Vec<Fact>,
    pub profile: DiagnosticProfile,
}

impl DiagnosticEngine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            collectors: Vec::new(),
            rules: Vec::new(),
            jar_cache: None,
            settings: DiagnosisSettings::default(),
        }
    }

    /// Run the full pipeline against a detected target.
    pub fn diagnose(&self, target: &Target) -> DoctorReport {
        self.diagnose_with_facts(target).report
    }

    /// Run the full pipeline and keep the fact snapshot for provenance output.
    pub fn diagnose_with_facts(&self, target: &Target) -> DiagnosticRun {
        let started = Instant::now();
        let mut store = FactStore::new();
        let mut collector_outcomes = Vec::with_capacity(self.collectors.len());
        let mut collector_timings = Vec::with_capacity(self.collectors.len());
        let jar_cache_ref = self.jar_cache.as_ref();

        for c in &self.collectors {
            let phase_start = Instant::now();
            let outcome = if c.applies(target) {
                let mut ctx = CollectCtx {
                    target,
                    store: &mut store,
                    jar_cache: jar_cache_ref,
                    settings: &self.settings,
                };
                c.collect(&mut ctx)
            } else {
                c.not_applicable(target)
            };
            collector_timings.push(PhaseTiming {
                id: c.id().to_string(),
                duration_ms: phase_start.elapsed().as_millis() as u64,
            });
            collector_outcomes.push((c.id(), c.layer(), outcome));
        }

        // Rules evaluate against the **full** fact store. Compaction must not run
        // first: retention only keeps a fixed predicate set, so dropping verbose
        // facts (mixin bytecode, spark hotspots, advanced predicates) before
        // rules would silently rob advanced/out-of-tree rules of their evidence
        // and produce false negatives. We compact afterwards, for the snapshot.
        let rctx = RuleCtx::new(&store, target, &self.settings);
        let mut findings: Vec<Finding> = Vec::new();
        let mut rule_stats: Vec<RuleStat> = Vec::with_capacity(self.rules.len());
        let mut rule_timings = Vec::with_capacity(self.rules.len());
        for r in &self.rules {
            let phase_start = Instant::now();
            let produced = r.evaluate(&rctx);
            rule_timings.push(PhaseTiming {
                id: r.id().to_string(),
                duration_ms: phase_start.elapsed().as_millis() as u64,
            });
            rule_stats.push(RuleStat {
                id: r.id().to_string(),
                findings: produced.len(),
            });
            findings.extend(produced);
        }

        // Incremental scan (`--changed-since`) sees only changed jars, so the fact
        // universe is partial. Rules that reason over the *whole* pack (missing
        // dependency, duplicate id, resource collisions, SBOM correlation) can
        // then draw false absence-based conclusions — downgrade them and flag the
        // run as partial so a stale-scan artifact is never reported as a hard error.
        if self.settings.scan.changed_since.is_some() {
            mark_partial_analysis(&mut findings);
        }

        // Now that findings (and their evidence edges) are computed, compact the
        // store so the persisted/exported snapshot stays bounded. Compaction is
        // *evidence-aware*: every fact cited by a finding's evidence edge is
        // preserved regardless of the retention predicate, so provenance never
        // degrades to a bare `fact #N` with no kind/subject/source in the report.
        let cited_facts: std::collections::BTreeSet<_> = findings
            .iter()
            .flat_map(|f| f.evidence.iter())
            .map(|e| e.fact)
            .collect();
        let facts_dropped =
            store.compact_preserving(&self.settings.facts.retention, &cited_facts);

        let embed_profile = self.jar_cache.as_ref().is_some_and(JarCache::is_enabled);
        // Measure on-disk size only when the profile is actually surfaced — the
        // directory walk is wasted work otherwise.
        let cache_stats = self
            .jar_cache
            .as_ref()
            .map(|c| {
                if embed_profile {
                    c.stats_with_disk_usage()
                } else {
                    c.stats()
                }
            })
            .unwrap_or_default();
        let profile = DiagnosticProfile::new(
            started.elapsed().as_millis() as u64,
            collector_timings,
            rule_timings,
            cache_stats,
        )
        .with_facts_dropped(facts_dropped);

        let report = report::assemble(
            &self.tool_version,
            target,
            &store,
            findings,
            collector_outcomes,
            rule_stats,
            embed_profile.then(|| profile.clone()),
        );
        DiagnosticRun {
            report,
            facts: store.all().to_vec(),
            profile,
        }
    }
}

/// Fluent registration of collectors and rules.
pub struct EngineBuilder {
    tool_version: String,
    collectors: Vec<Box<dyn Collector>>,
    rules: Vec<Box<dyn Rule>>,
    jar_cache: Option<JarCache>,
    settings: DiagnosisSettings,
}

impl EngineBuilder {
    pub fn tool_version(mut self, v: impl Into<String>) -> Self {
        self.tool_version = v.into();
        self
    }

    pub fn collector(mut self, c: impl Collector + 'static) -> Self {
        self.collectors.push(Box::new(c));
        self
    }

    pub fn boxed_collector(mut self, c: Box<dyn Collector>) -> Self {
        self.collectors.push(c);
        self
    }

    pub fn rule(mut self, r: impl Rule + 'static) -> Self {
        self.rules.push(Box::new(r));
        self
    }

    pub fn jar_cache(mut self, cache: Option<JarCache>) -> Self {
        self.jar_cache = cache;
        self
    }

    pub fn settings(mut self, settings: DiagnosisSettings) -> Self {
        self.settings = settings;
        self
    }

    pub fn build(self) -> DiagnosticEngine {
        DiagnosticEngine {
            tool_version: self.tool_version,
            collectors: self.collectors,
            rules: self.rules,
            jar_cache: self.jar_cache,
            settings: self.settings,
        }
    }
}

/// Prefixes of finding ids that conclude something about the *whole* pack and so
/// become unreliable on an incremental (`--changed-since`) scan that only saw
/// some jars.
const PARTIAL_SENSITIVE_PREFIXES: &[&str] = &[
    "missing-dependency:",
    "duplicate-id:",
    "resource-conflict:",
    "dependency-unsat",
    "sbom-security-correlation",
    "modpack-incomplete:",
];

/// Downgrade whole-pack findings to at most `Warn`, annotate them as possibly a
/// stale-scan artifact, and append a single partial-analysis caveat finding.
fn mark_partial_analysis(findings: &mut Vec<Finding>) {
    use intermed_evidence::{Category, Finding as F, Severity};

    let caveat = " (partial scan: only changed jars were analyzed — re-run a full \
                   scan to confirm this is not a stale-scan artifact)";
    for f in findings.iter_mut() {
        if PARTIAL_SENSITIVE_PREFIXES
            .iter()
            .any(|p| f.id.starts_with(p))
        {
            if matches!(f.severity, Severity::Error | Severity::Fatal) {
                f.severity = Severity::Warn;
            }
            f.confidence = (f.confidence * 0.6).min(0.6);
            if !f.explanation.ends_with(')') || !f.explanation.contains("partial scan") {
                f.explanation.push_str(caveat);
            }
            f.machine_tags.push("partial-analysis".to_string());
        }
    }

    findings.push(
        F::builder("analysis-partial", "analysis-partial")
            .severity(Severity::Note)
            .category(Category::Packaging)
            .title("Incremental (partial) analysis")
            .explanation(
                "This run analyzed only jars changed since the given timestamp \
                 (--changed-since). Whole-pack checks (missing dependency, duplicate id, \
                 resource collisions, SBOM correlation) cover only the changed set and may \
                 be incomplete — run a full scan for authoritative results.",
            )
            .confidence(0.95)
            .tag("partial-analysis")
            .build(),
    );
}

#[cfg(test)]
mod partial_tests {
    use super::mark_partial_analysis;
    use intermed_evidence::{Category, Finding, Severity};

    #[test]
    fn partial_downgrades_whole_pack_findings_and_adds_caveat() {
        let mut findings = vec![
            Finding::builder("dependency", "missing-dependency:a->b")
                .severity(Severity::Error)
                .category(Category::Dependency)
                .title("Missing dependency: b")
                .explanation("a requires b.")
                .build(),
            Finding::builder("mixin-risk", "mixin-risk:net.minecraft.Foo")
                .severity(Severity::Error)
                .category(Category::Mixin)
                .title("risk")
                .explanation("e")
                .build(),
        ];
        mark_partial_analysis(&mut findings);

        let dep = findings.iter().find(|f| f.id == "missing-dependency:a->b").unwrap();
        assert_eq!(dep.severity, Severity::Warn, "whole-pack finding downgraded");
        assert!(dep.explanation.contains("partial scan"));
        assert!(dep.machine_tags.iter().any(|t| t == "partial-analysis"));

        // A non-universe finding (mixin risk on a present jar) is untouched.
        let mixin = findings.iter().find(|f| f.id.starts_with("mixin-risk:")).unwrap();
        assert_eq!(mixin.severity, Severity::Error);

        assert!(findings.iter().any(|f| f.id == "analysis-partial"));
    }
}
