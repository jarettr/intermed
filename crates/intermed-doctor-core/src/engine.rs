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
use crate::report::{self, DoctorReport, OperationalError, RuleStat};
use crate::rule::{Rule, RuleCtx};
use crate::settings::DiagnosisSettings;
use crate::target::Target;

fn process_peak_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let kib = status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?;
        kib.checked_mul(1024)
    }
    #[cfg(not(target_os = "linux"))]
    None
}

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
        // Collection must remain semantically lossless until every registered
        // rule has evaluated.  In particular, external/declarative rules may
        // consume predicates that the snapshot retention policy considers
        // verbose.  Compacting here would turn a memory policy into analysis
        // semantics and could silently remove findings.
        let mut store = FactStore::new();
        let mut collector_outcomes = Vec::with_capacity(self.collectors.len());
        let collector_scopes = self
            .collectors
            .iter()
            .map(|collector| (collector.id(), collector.scope()))
            .collect::<Vec<_>>();
        let mut collector_timings = Vec::with_capacity(self.collectors.len());
        let jar_cache_ref = self.jar_cache.as_ref();

        for c in &self.collectors {
            let phase_start = Instant::now();
            let facts_before = store.len();
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
                input_facts: facts_before,
                output_records: outcome.facts_emitted,
                store_facts_after: store.len(),
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
        let mut operational_errors = Vec::new();
        for r in &self.rules {
            let phase_start = Instant::now();
            let result = r.evaluate(&rctx);
            rule_timings.push(PhaseTiming {
                id: r.id().to_string(),
                duration_ms: phase_start.elapsed().as_millis() as u64,
                input_facts: store.len(),
                output_records: result.as_ref().map_or(0, Vec::len),
                store_facts_after: store.len(),
            });
            let produced = match result {
                Ok(findings) => findings,
                Err(error) => {
                    operational_errors.push(OperationalError {
                        stage: "rule".to_string(),
                        component: r.id().to_string(),
                        message: error.to_string(),
                    });
                    Vec::new()
                }
            };
            rule_stats.push(RuleStat {
                id: r.id().to_string(),
                findings: produced.len(),
            });
            findings.extend(produced);
        }

        let incremental = self.settings.scan.changed_since.is_some();
        if incremental {
            append_partial_analysis_notice(&mut findings);
        }
        let capabilities = crate::TargetCapabilities::derive_with_scopes(
            target,
            &store,
            &collector_outcomes,
            &collector_scopes,
            &self.settings,
        );
        crate::assessment::assess_findings(&store, &capabilities, &mut findings, incremental);
        let mut evidence_graph = crate::coherence::build_evidence_graph(&store);
        crate::coherence::reconcile_findings(&store, &mut evidence_graph, &mut findings);
        crate::coherence::stabilize_finding_identities(&store, &evidence_graph, &mut findings);

        // Now that findings (and their evidence edges) are computed, compact the
        // store so the persisted/exported snapshot stays bounded. Compaction is
        // *evidence-aware*: every fact cited by a finding's evidence edge is
        // preserved regardless of the retention predicate, so provenance never
        // degrades to a bare `fact #N` with no kind/subject/source in the report.
        let mut cited_facts: std::collections::BTreeSet<_> = findings
            .iter()
            .flat_map(|f| f.evidence.iter())
            .map(|e| e.fact)
            .collect();
        cited_facts.extend(evidence_graph.cited_facts());
        let generated_fact_stats = store.emitted_stats();
        let snapshot_facts_dropped =
            store.compact_preserving(&self.settings.facts.retention, &cited_facts);
        let facts_dropped = snapshot_facts_dropped;
        let retained_fact_stats = store.stats();

        // The on-disk cache walk is the only expensive part of profiling, so it
        // stays gated on the cache being enabled. Per-phase (collector/rule)
        // timings are always embedded in the report: the unique-id/grouping work
        // downstream wants per-rule timing regardless of whether a jar cache ran.
        let measure_disk = self.jar_cache.as_ref().is_some_and(JarCache::is_enabled);
        let cache_stats = self
            .jar_cache
            .as_ref()
            .map(|c| {
                if measure_disk {
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
        .with_facts_dropped(facts_dropped)
        .with_fact_inventory(generated_fact_stats, retained_fact_stats)
        .with_peak_rss(process_peak_rss_bytes());

        let report = report::assemble_with_settings_and_capabilities(
            &self.tool_version,
            target,
            &store,
            findings,
            collector_outcomes,
            rule_stats,
            operational_errors,
            Some(profile.clone()),
            &self.settings,
            capabilities,
        );
        DiagnosticRun {
            report,
            facts: store.all().to_vec(),
            profile,
        }
    }
}

/// Resolve conclusions that require evidence from more than one layer. Rules
/// intentionally remain local; this pass prevents a local hard assertion from
/// surviving when another layer supplies direct counter-evidence or lowers a
/// prerequisite's certainty.
#[cfg(test)]
fn apply_runtime_contradictions(store: &FactStore, findings: &mut [Finding]) {
    use intermed_evidence::{ConclusionKind, RuntimeRefutability};
    // Compatibility for in-process v1/v2 rules: convert the old typed
    // refutability declaration into the canonical conclusion kind once.
    for finding in findings
        .iter_mut()
        .filter(|f| f.conclusion_kind == ConclusionKind::Generic)
    {
        finding.conclusion_kind = if finding
            .runtime_refutability
            .contains(&RuntimeRefutability::DependencyUse)
        {
            ConclusionKind::DependencyUnused
        } else if finding
            .runtime_refutability
            .contains(&RuntimeRefutability::ExactMethodPresence)
        {
            ConclusionKind::MethodAbsent
        } else if finding
            .runtime_refutability
            .contains(&RuntimeRefutability::ClassPresence)
        {
            ConclusionKind::ClassAbsent
        } else {
            ConclusionKind::Generic
        };
    }
    let mut graph = crate::coherence::build_evidence_graph(store);
    crate::coherence::reconcile_findings(store, &mut graph, findings);
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

/// Add one explicit incremental-coverage notice. Individual findings are gated
/// by their typed coverage requirements in the assessment engine.
fn append_partial_analysis_notice(findings: &mut Vec<Finding>) {
    use intermed_evidence::{Category, EvidenceOrigin, Finding as F, Impact, ProofKind, Severity};

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
            .impact(Impact::Informational)
            .proof_kind(ProofKind::Observation)
            .evidence_origin(EvidenceOrigin::HostObservation)
            .tag("partial-analysis")
            .build(),
    );
}

#[cfg(test)]
mod partial_tests {
    use super::{append_partial_analysis_notice, apply_runtime_contradictions};
    use crate::TargetCapabilities;
    use crate::assessment::assess_findings;
    use intermed_evidence::{
        Category, CoverageRequirement, CoverageState, Finding, ProofKind, RuntimeRefutability,
        Severity,
    };
    use intermed_facts::{FactStore, kind};

    fn complete_capabilities() -> TargetCapabilities {
        TargetCapabilities {
            authoritative_manifest: CoverageState::Complete,
            materialized_artifacts: CoverageState::Complete,
            loader_identity: CoverageState::Complete,
            minecraft_identity: CoverageState::Complete,
            mod_classpath: CoverageState::Complete,
            minecraft_classpath: CoverageState::Complete,
            loader_classpath: CoverageState::Complete,
            mappings: CoverageState::Complete,
            logs: CoverageState::Complete,
            configs: CoverageState::Complete,
            scripts: CoverageState::Complete,
            runtime_mutators: CoverageState::Complete,
            resource_blobs: CoverageState::Complete,
            datapacks: CoverageState::Complete,
            runtime_profile: CoverageState::Complete,
            vanilla_resources: CoverageState::Complete,
        }
    }

    #[test]
    fn partial_downgrades_whole_pack_findings_and_adds_caveat() {
        let mut findings = vec![
            Finding::builder("dependency", "missing-dependency:a->b")
                .coverage_requirement(CoverageRequirement::CompletePack)
                .proof_kind(ProofKind::DeterministicDerivation)
                .severity(Severity::Error)
                .category(Category::Dependency)
                .title("Missing dependency: b")
                .explanation("a requires b.")
                .build(),
            Finding::builder("mixin-risk", "mixin-risk:net.minecraft.Foo")
                .coverage_requirement(CoverageRequirement::LocalArtifact)
                .proof_kind(ProofKind::DeterministicDerivation)
                .severity(Severity::Error)
                .category(Category::Mixin)
                .title("risk")
                .explanation("e")
                .build(),
        ];
        append_partial_analysis_notice(&mut findings);
        assess_findings(
            &FactStore::new(),
            &complete_capabilities(),
            &mut findings,
            true,
        );

        let dep = findings
            .iter()
            .find(|f| f.id == "missing-dependency:a->b")
            .unwrap();
        assert_eq!(
            dep.severity,
            Severity::Warn,
            "whole-pack finding downgraded"
        );
        assert!(dep.machine_tags.iter().any(|t| t == "why-not-error"));

        // A non-universe finding (mixin risk on a present jar) is untouched.
        let mixin = findings
            .iter()
            .find(|f| f.id.starts_with("mixin-risk:"))
            .unwrap();
        assert_eq!(mixin.severity, Severity::Error);

        assert!(findings.iter().any(|f| f.id == "analysis-partial"));
    }

    #[test]
    fn compatibility_bridge_prevents_hard_loader_rejection() {
        let mut store = FactStore::new();
        store
            .fact("env", kind::ENVIRONMENT)
            .attr("loader", "neoforge")
            .emit();
        store
            .fact("metadata", kind::COMPATIBILITY_BRIDGE)
            .subject("connector")
            .attr("from_loader", "fabric")
            .attr("to_loader", "neoforge")
            .attr("scope", "mod-runtime")
            .emit();
        let mut findings = vec![
            Finding::builder("loader", "loader-mismatch:fabric-mod")
                .severity(Severity::Error)
                .category(Category::Loader)
                .coverage_requirement(CoverageRequirement::KnownBridgeSemantics)
                .proof_kind(ProofKind::DeterministicDerivation)
                .title("wrong loader")
                .explanation("fabric on neoforge")
                .build(),
        ];
        assess_findings(&store, &complete_capabilities(), &mut findings, false);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0]
                .assessment
                .blockers
                .iter()
                .any(|blocker| blocker.code == "bridge-compatibility-undecidable")
        );
    }

    #[test]
    fn api_surface_bridge_does_not_claim_arbitrary_fabric_mod_compatibility() {
        let mut store = FactStore::new();
        store
            .fact("env", kind::ENVIRONMENT)
            .attr("loader", "forge")
            .emit();
        store
            .fact("metadata", kind::COMPATIBILITY_BRIDGE)
            .subject("fabric_api")
            .attr("from_loader", "fabric-api")
            .attr("to_loader", "forge")
            .attr("scope", "api-surface")
            .emit();
        let mut findings = vec![
            Finding::builder("loader", "loader-mismatch:unrelated-fabric-mod")
                .severity(Severity::Error)
                .category(Category::Loader)
                .coverage_requirement(CoverageRequirement::KnownBridgeSemantics)
                .proof_kind(ProofKind::DeterministicDerivation)
                .title("wrong loader")
                .explanation("fabric on forge")
                .build(),
        ];
        assess_findings(&store, &complete_capabilities(), &mut findings, false);
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn unknown_loader_blocks_hard_dependency_absence() {
        let store = FactStore::new();
        let mut findings = vec![
            Finding::builder("dependency", "missing-dependency:a->fabric-api")
                .coverage_requirement(CoverageRequirement::CompletePack)
                .proof_kind(ProofKind::DeterministicDerivation)
                .severity(Severity::Error)
                .category(Category::Dependency)
                .title("missing")
                .explanation("not installed")
                .build(),
        ];
        assess_findings(&store, &TargetCapabilities::default(), &mut findings, false);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0]
                .machine_tags
                .iter()
                .any(|tag| tag == "why-not-error")
        );
        assert!(!findings[0].assessment.blockers.is_empty());
    }

    #[test]
    fn runtime_execution_invalidates_static_unused_dependency() {
        let mut store = FactStore::new();
        for mod_id in ["addon", "api"] {
            store
                .fact("log", kind::STACK_FRAME)
                .subject("runtime-event:1")
                .attr("mod_id", mod_id)
                .attr("class", format!("{mod_id}.Example"))
                .emit();
        }
        let mut findings = vec![
            Finding::builder("dependency", "dependency-declared-but-unused:addon->api")
                .coverage_requirement(CoverageRequirement::CompletePack)
                .proof_kind(ProofKind::Heuristic)
                .runtime_refutability(RuntimeRefutability::DependencyUse)
                .severity(Severity::Warn)
                .category(Category::Dependency)
                .title("unused")
                .explanation("static heuristic")
                .affects("addon")
                .affects("api")
                .build(),
        ];
        assess_findings(&store, &complete_capabilities(), &mut findings, false);
        apply_runtime_contradictions(&store, &mut findings);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(
            findings[0].visibility,
            intermed_evidence::FindingVisibility::ExplainOnly
        );
        assert!(
            findings[0]
                .machine_tags
                .iter()
                .any(|tag| tag == "runtime-contradicted")
        );
    }

    #[test]
    fn certainty_policy_is_independent_of_finding_id() {
        let store = FactStore::new();
        let mut findings = vec![
            Finding::builder("renamed-rule", "completely-renamed-occurrence")
                .coverage_requirement(CoverageRequirement::CompletePack)
                .proof_kind(ProofKind::DeterministicDerivation)
                .severity(Severity::Error)
                .category(Category::Dependency)
                .title("missing")
                .explanation("not installed")
                .build(),
        ];
        assess_findings(&store, &TargetCapabilities::default(), &mut findings, false);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(
            findings[0]
                .machine_tags
                .iter()
                .any(|tag| tag == "why-not-error")
        );
    }

    #[test]
    fn assessment_is_idempotent_across_engine_and_report_passes() {
        let store = FactStore::new();
        let mut findings = vec![
            Finding::builder("rule", "candidate")
                .coverage_requirement(CoverageRequirement::CompletePack)
                .proof_kind(ProofKind::DeterministicDerivation)
                .severity(Severity::Error)
                .category(Category::Dependency)
                .title("candidate")
                .explanation("candidate")
                .build(),
        ];
        let unavailable = TargetCapabilities::default();
        assess_findings(&store, &unavailable, &mut findings, false);
        let once = findings[0].assessment.clone();
        assess_findings(&store, &unavailable, &mut findings, false);
        assert_eq!(findings[0].assessment, once);
        assert_eq!(findings[0].severity, Severity::Warn);
    }
}
