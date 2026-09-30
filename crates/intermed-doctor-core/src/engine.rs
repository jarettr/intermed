//! The diagnosis engine: run collectors → fact store → run rules → assemble
//! report. The engine knows nothing concrete about Minecraft, logs, or
//! dependencies — it only orchestrates [`Collector`]s and [`Rule`]s that the
//! composition root (the CLI) registers. Adding a layer never touches this file.

use std::time::Instant;

use intermed_evidence::Finding;
use intermed_facts::{Fact, FactStore};
use thiserror::Error;

use crate::collector::{CollectCtx, Collector};
use crate::jar_cache::JarCache;
use crate::profile::{DiagnosticProfile, PhaseTiming};
use crate::reconciler::{CrossLayerReconciler, Reconciler};
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
    reconcilers: Vec<Box<dyn Reconciler>>,
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
            reconcilers: vec![Box::new(CrossLayerReconciler)],
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
        let mut collector_contract_errors = Vec::new();
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
            let scope = c.scope();
            let mut outcome = if c.applies(target) {
                let inputs = intermed_facts::FilteredFactView::new(&store, &scope.consumes);
                let mut staged = store.staging_after();
                let mut ctx = CollectCtx {
                    target,
                    store: &mut staged,
                    inputs: &inputs,
                    jar_cache: jar_cache_ref,
                    settings: &self.settings,
                };
                let outcome = c.collect(&mut ctx);
                store.append_staged(staged);
                outcome
            } else {
                c.not_applicable(target)
            };
            let facts_after = store.len();
            let facts_emitted = facts_after.saturating_sub(facts_before);
            outcome.facts_emitted = facts_emitted;
            if !scope.produces.is_empty() {
                let undeclared = store.all()[facts_before..facts_after]
                    .iter()
                    .filter(|fact| !scope.produces.contains(fact.kind.as_str()))
                    .map(|fact| fact.kind.clone())
                    .collect::<std::collections::BTreeSet<_>>();
                if !undeclared.is_empty() {
                    let message = format!(
                        "collector emitted predicates absent from its scope: {}",
                        undeclared.into_iter().collect::<Vec<_>>().join(", ")
                    );
                    collector_contract_errors.push(OperationalError {
                        stage: "collector-contract".to_string(),
                        component: c.id().to_string(),
                        message: message.clone(),
                    });
                    if matches!(
                        outcome.status,
                        crate::CollectorStatus::Active | crate::CollectorStatus::CompleteEmpty
                    ) {
                        outcome.status = crate::CollectorStatus::Incomplete;
                        outcome.message = format!("{}; {message}", outcome.message);
                    }
                }
            }
            collector_timings.push(PhaseTiming {
                id: c.id().to_string(),
                duration_ms: phase_start.elapsed().as_millis() as u64,
                input_facts: facts_before,
                output_records: outcome.facts_emitted,
                store_facts_after: facts_after,
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
        let mut operational_errors = collector_contract_errors;
        for r in &self.rules {
            let phase_start = Instant::now();
            let requirements = r.requirements();
            let result = r.evaluate(&rctx);
            rule_timings.push(PhaseTiming {
                id: r.id().to_string(),
                duration_ms: phase_start.elapsed().as_millis() as u64,
                input_facts: store.len(),
                output_records: result.as_ref().map_or(0, Vec::len),
                store_facts_after: store.len(),
            });
            let mut produced = match result {
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
            let mut contract_violations = Vec::new();
            for finding in &mut produced {
                let proof_is_invalid = finding.proof_kind.is_some_and(|proof| {
                    !requirements.permitted_proof_kinds.is_empty()
                        && !requirements.permitted_proof_kinds.contains(&proof)
                }) || (finding.proof_kind.is_none()
                    && finding.severity >= intermed_evidence::Severity::Error
                    && !requirements.permitted_proof_kinds.is_empty());
                if proof_is_invalid {
                    contract_violations.push(format!(
                        "finding `{}` used proof {:?} outside {:?}",
                        finding.id, finding.proof_kind, requirements.permitted_proof_kinds
                    ));
                    mark_rule_contract_violation(finding, "rule-proof-contract-violation");
                }
                let undeclared_coverage = finding
                    .coverage_requirements
                    .iter()
                    .filter(|requirement| {
                        !requirements.minimum_coverage.is_empty()
                            && !requirements.minimum_coverage.contains(requirement)
                    })
                    .copied()
                    .collect::<Vec<_>>();
                if !undeclared_coverage.is_empty() {
                    contract_violations.push(format!(
                        "finding `{}` used undeclared coverage requirements {:?}",
                        finding.id, undeclared_coverage
                    ));
                    mark_rule_contract_violation(finding, "rule-coverage-contract-violation");
                }
            }
            if !contract_violations.is_empty() {
                operational_errors.push(OperationalError {
                    stage: "rule-contract".to_string(),
                    component: r.id().to_string(),
                    message: contract_violations.join("; "),
                });
            }
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
        let mut pipeline_timings = Vec::new();
        let phase_start = Instant::now();
        let capabilities = crate::TargetCapabilities::derive_with_scopes(
            target,
            &store,
            &collector_outcomes,
            &collector_scopes,
            &self.settings,
        );
        pipeline_timings.push(PhaseTiming {
            id: "coverage".to_string(),
            duration_ms: phase_start.elapsed().as_millis() as u64,
            input_facts: store.len(),
            output_records: 1,
            store_facts_after: store.len(),
        });
        let phase_start = Instant::now();
        crate::assessment::assess_findings(&store, &capabilities, &mut findings, incremental);
        pipeline_timings.push(PhaseTiming {
            id: "assessment".to_string(),
            duration_ms: phase_start.elapsed().as_millis() as u64,
            input_facts: store.len(),
            output_records: findings.len(),
            store_facts_after: store.len(),
        });
        let phase_start = Instant::now();
        let mut evidence_graph = crate::coherence::build_evidence_graph(&store);
        pipeline_timings.push(PhaseTiming {
            id: "coherence-graph".to_string(),
            duration_ms: phase_start.elapsed().as_millis() as u64,
            input_facts: store.len(),
            output_records: evidence_graph.links.len(),
            store_facts_after: store.len(),
        });
        for reconciler in &self.reconcilers {
            let phase_start = Instant::now();
            match reconciler.reconcile(&store, &mut evidence_graph, &mut findings) {
                Ok(outcome) => pipeline_timings.push(PhaseTiming {
                    id: format!("reconciliation:{}", reconciler.id()),
                    duration_ms: phase_start.elapsed().as_millis() as u64,
                    input_facts: store.len(),
                    output_records: outcome.findings_adjusted,
                    store_facts_after: store.len(),
                }),
                Err(error) => {
                    operational_errors.push(OperationalError {
                        stage: "reconciler".to_string(),
                        component: reconciler.id().to_string(),
                        message: error.to_string(),
                    });
                    pipeline_timings.push(PhaseTiming {
                        id: format!("reconciliation:{}", reconciler.id()),
                        duration_ms: phase_start.elapsed().as_millis() as u64,
                        input_facts: store.len(),
                        output_records: 0,
                        store_facts_after: store.len(),
                    });
                }
            }
        }
        let phase_start = Instant::now();
        crate::coherence::stabilize_finding_identities(&store, &evidence_graph, &mut findings);
        pipeline_timings.push(PhaseTiming {
            id: "identity".to_string(),
            duration_ms: phase_start.elapsed().as_millis() as u64,
            input_facts: store.len(),
            output_records: findings.len(),
            store_facts_after: store.len(),
        });

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
        let phase_start = Instant::now();
        let snapshot_facts_dropped =
            store.compact_preserving(&self.settings.facts.retention, &cited_facts);
        let facts_dropped = snapshot_facts_dropped;
        let retained_fact_stats = store.stats();
        pipeline_timings.push(PhaseTiming {
            id: "compaction".to_string(),
            duration_ms: phase_start.elapsed().as_millis() as u64,
            input_facts: generated_fact_stats.values().sum(),
            output_records: store.len(),
            store_facts_after: store.len(),
        });

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
        let mut profile = DiagnosticProfile::new(
            started.elapsed().as_millis() as u64,
            collector_timings,
            rule_timings,
            cache_stats,
        )
        .with_pipeline(pipeline_timings)
        .with_facts_dropped(facts_dropped)
        .with_fact_inventory(generated_fact_stats, retained_fact_stats)
        .with_peak_rss(process_peak_rss_bytes());

        let phase_start = Instant::now();
        let mut report = report::assemble_with_settings_and_capabilities(
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
        // Report assembly appends the explicitly modelled triage,
        // recommendation, and incident-synthesis phases.
        if let Some(report_profile) = report.profile.take() {
            profile = report_profile;
        }
        profile.pipeline.push(PhaseTiming {
            id: "report-postprocess".to_string(),
            duration_ms: phase_start.elapsed().as_millis() as u64,
            input_facts: store.len(),
            output_records: report.findings.len(),
            store_facts_after: store.len(),
        });
        profile.total_ms = started.elapsed().as_millis() as u64;
        profile.peak_rss_bytes = process_peak_rss_bytes();
        report.profile = Some(profile.clone());
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
    reconcilers: Vec<Box<dyn Reconciler>>,
    jar_cache: Option<JarCache>,
    settings: DiagnosisSettings,
}

/// Invalid collector/rule wiring detected before a production analysis starts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid diagnostic engine configuration: {issues}", issues = .issues.join("; "))]
pub struct EngineConfigError {
    pub issues: Vec<String>,
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

    pub fn reconciler(mut self, reconciler: impl Reconciler + 'static) -> Self {
        self.reconcilers.push(Box::new(reconciler));
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
            reconcilers: self.reconcilers,
            jar_cache: self.jar_cache,
            settings: self.settings,
        }
    }

    /// Validate the registered analysis graph before constructing the engine.
    ///
    /// The unchecked [`EngineBuilder::build`] remains available for small
    /// third-party/test engines during the 0.1 series. Production composition
    /// roots should use this method so a forgotten producer cannot silently
    /// turn into missing findings.
    pub fn build_checked(self) -> Result<DiagnosticEngine, EngineConfigError> {
        let mut issues = Vec::new();
        let mut collector_ids = std::collections::BTreeSet::new();
        let mut rule_ids = std::collections::BTreeSet::new();
        let mut reconciler_ids = std::collections::BTreeSet::new();
        let mut produced = std::collections::BTreeSet::new();
        let mut covered_regions = std::collections::BTreeSet::new();

        for collector in &self.collectors {
            if !collector_ids.insert(collector.id()) {
                issues.push(format!("duplicate collector id `{}`", collector.id()));
            }
            let scope = collector.scope();
            for prerequisite in &scope.prerequisites {
                if !covered_regions.contains(&prerequisite.region) {
                    issues.push(format!(
                        "collector `{}` requires region `{:?}` (`{}`), but no earlier registered collector declares it",
                        collector.id(), prerequisite.region, prerequisite.id
                    ));
                }
            }
            for consumed in &scope.consumes {
                if !produced.contains(consumed) {
                    issues.push(format!(
                        "collector `{}` consumes `{consumed}`, but no earlier registered collector declares that predicate",
                        collector.id()
                    ));
                }
            }
            produced.extend(scope.produces);
            covered_regions.extend(scope.target_regions);
        }
        for rule in &self.rules {
            if !rule_ids.insert(rule.id()) {
                issues.push(format!("duplicate rule id `{}`", rule.id()));
            }
            let requirements = rule.requirements();
            for required in requirements.required_fact_kinds {
                if !produced.contains(&required) {
                    issues.push(format!(
                        "rule `{}` requires `{required}`, but no registered collector declares that predicate",
                        rule.id()
                    ));
                }
            }
            // Required regions are runtime capabilities, not necessarily
            // collector-owned predicates. External classpaths and mappings may
            // legitimately be absent; central assessment must then abstain.
        }
        for reconciler in &self.reconcilers {
            if !reconciler_ids.insert(reconciler.id()) {
                issues.push(format!("duplicate reconciler id `{}`", reconciler.id()));
            }
        }
        issues.sort();
        issues.dedup();
        if issues.is_empty() {
            Ok(self.build())
        } else {
            Err(EngineConfigError { issues })
        }
    }
}

fn mark_rule_contract_violation(finding: &mut Finding, tag: &str) {
    finding.severity = finding.severity.min(intermed_evidence::Severity::Warn);
    if !finding.machine_tags.iter().any(|existing| existing == tag) {
        finding.machine_tags.push(tag.to_string());
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
            bridge_semantics: CoverageState::Complete,
            mappings: CoverageState::Complete,
            logs: CoverageState::Complete,
            configs: CoverageState::Complete,
            script_sources: CoverageState::Complete,
            runtime_mutation_logs: CoverageState::Complete,
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
    fn single_cross_loader_descriptor_is_conclusive_for_loader_mismatch_only() {
        use intermed_evidence::EvidenceEdge;

        let mut store = FactStore::new();
        let mod_fact = store
            .fact("metadata", kind::MOD)
            .subject("geckolib3")
            .attr("loader", "fabric")
            .attr("identity_certainty", "cross-loader-unresolved")
            .attr("descriptor_candidates", "fabric.mod.json")
            .emit();
        let make_finding = |category, conclusion_kind, id| {
            Finding::builder("test", id)
                .severity(Severity::Error)
                .category(category)
                .conclusion_kind(conclusion_kind)
                .coverage_requirement(CoverageRequirement::ActiveDescriptor)
                .proof_kind(ProofKind::DeterministicDerivation)
                .evidence(EvidenceEdge::subject(mod_fact))
                .title("test")
                .explanation("test")
                .build()
        };
        let mut findings = vec![
            make_finding(
                Category::Loader,
                intermed_evidence::ConclusionKind::LoaderMismatch,
                "loader-mismatch:geckolib3",
            ),
            make_finding(
                Category::Dependency,
                intermed_evidence::ConclusionKind::MissingDependency,
                "missing-dependency:geckolib3->fabric",
            ),
        ];

        assess_findings(&store, &complete_capabilities(), &mut findings, false);

        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[1].severity, Severity::Warn);
        assert_eq!(
            findings[1].assessment.disposition,
            intermed_evidence::AssessmentDisposition::Abstained
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

#[cfg(test)]
mod contract_tests {
    use super::*;
    use crate::{
        CollectorOutcome, CollectorScope, CompletenessModel, Layer, RuleRequirements, TargetKind,
    };
    use intermed_evidence::{Finding, ProofKind, Severity};
    use intermed_facts::kind;

    struct Producer {
        id: &'static str,
    }

    impl Collector for Producer {
        fn id(&self) -> &'static str {
            self.id
        }

        fn layer(&self) -> Layer {
            Layer::Metadata
        }

        fn scope(&self) -> CollectorScope {
            CollectorScope::new(CompletenessModel::AllOrNothing).produces([kind::MOD, kind::PLUGIN])
        }

        fn applies(&self, _target: &Target) -> bool {
            true
        }

        fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
            ctx.store.fact(self.id, kind::MOD).subject("visible").emit();
            ctx.store
                .fact(self.id, kind::PLUGIN)
                .subject("not-declared-as-input")
                .emit();
            CollectorOutcome::active(2, "produced")
        }
    }

    struct Consumer;

    impl Collector for Consumer {
        fn id(&self) -> &'static str {
            "consumer"
        }

        fn layer(&self) -> Layer {
            Layer::Dependency
        }

        fn scope(&self) -> CollectorScope {
            CollectorScope::new(CompletenessModel::AllOrNothing)
                .consumes([kind::MOD])
                .produces([kind::DEPENDENCY])
        }

        fn applies(&self, _target: &Target) -> bool {
            true
        }

        fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
            assert_eq!(ctx.inputs.by_kind(kind::MOD).count(), 1);
            assert_eq!(ctx.inputs.by_kind(kind::PLUGIN).count(), 0);
            ctx.store
                .fact(self.id(), kind::DEPENDENCY)
                .subject("visible")
                .attr("dep", "api")
                .emit();
            CollectorOutcome::active(1, "enriched")
        }
    }

    struct UndeclaredProducer;

    impl Collector for UndeclaredProducer {
        fn id(&self) -> &'static str {
            "undeclared-producer"
        }

        fn layer(&self) -> Layer {
            Layer::Metadata
        }

        fn scope(&self) -> CollectorScope {
            CollectorScope::new(CompletenessModel::AllOrNothing).produces([kind::MOD])
        }

        fn applies(&self, _target: &Target) -> bool {
            true
        }

        fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
            ctx.store
                .fact(self.id(), kind::PLUGIN)
                .subject("undeclared")
                .emit();
            CollectorOutcome::active(99, "bad count and kind")
        }
    }

    struct ContractRule;

    impl Rule for ContractRule {
        fn id(&self) -> &'static str {
            "contract-rule"
        }

        fn requirements(&self) -> RuleRequirements {
            RuleRequirements::default()
                .facts([kind::DEPENDENCY])
                .proofs([ProofKind::Observation])
        }

        fn evaluate(&self, _ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, crate::RuleError> {
            Ok(vec![
                Finding::builder(self.id(), "contract-violation")
                    .severity(Severity::Error)
                    .proof_kind(ProofKind::Heuristic)
                    .build(),
            ])
        }
    }

    struct CoverageRule;

    impl Rule for CoverageRule {
        fn id(&self) -> &'static str {
            "coverage-rule"
        }

        fn requirements(&self) -> RuleRequirements {
            RuleRequirements::default()
                .facts([kind::DEPENDENCY])
                .coverage([intermed_evidence::CoverageRequirement::CompletePack])
                .proofs([ProofKind::DeterministicDerivation])
        }

        fn evaluate(&self, _ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, crate::RuleError> {
            Ok(vec![
                Finding::builder(self.id(), "undeclared-coverage")
                    .severity(Severity::Error)
                    .proof_kind(ProofKind::DeterministicDerivation)
                    .coverage_requirement(intermed_evidence::CoverageRequirement::CompleteClasspath)
                    .build(),
            ])
        }
    }

    fn target() -> Target {
        Target::with_kind("/does/not/exist", TargetKind::Unknown)
    }

    #[test]
    fn checked_builder_rejects_duplicate_ids_and_missing_producers() {
        let result = DiagnosticEngine::builder()
            .collector(Producer { id: "duplicate" })
            .collector(Producer { id: "duplicate" })
            .rule(ContractRule)
            .build_checked();
        let error = match result {
            Ok(_) => panic!("invalid graph must fail before analysis"),
            Err(error) => error,
        };
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("duplicate collector id `duplicate`"))
        );
        assert!(
            error
                .issues
                .iter()
                .any(|issue| issue.contains("requires `dependency`"))
        );
    }

    #[test]
    fn checked_builder_rejects_out_of_order_collector_inputs() {
        let result = DiagnosticEngine::builder()
            .collector(Consumer)
            .collector(Producer { id: "producer" })
            .build_checked();
        let error = match result {
            Ok(_) => panic!("consumers must follow their declared producers"),
            Err(error) => error,
        };
        assert!(error.issues.iter().any(|issue| {
            issue.contains("collector `consumer` consumes `mod`")
                && issue.contains("no earlier registered collector")
        }));
    }

    #[test]
    fn collector_receives_only_declared_predicates() {
        let engine = DiagnosticEngine::builder()
            .collector(Producer { id: "producer" })
            .collector(Consumer)
            .build_checked()
            .expect("valid graph");
        let run = engine.diagnose_with_facts(&target());
        assert_eq!(
            run.facts
                .iter()
                .filter(|fact| fact.kind == kind::DEPENDENCY)
                .count(),
            1
        );
    }

    #[test]
    fn undeclared_collector_output_is_incomplete_and_operational() {
        let report = DiagnosticEngine::builder()
            .collector(UndeclaredProducer)
            .build_checked()
            .expect("registration itself is structurally valid")
            .diagnose(&target());
        let collector = report
            .collectors
            .iter()
            .find(|collector| collector.id == "undeclared-producer")
            .expect("collector report");
        assert_eq!(collector.status, "incomplete");
        assert_eq!(collector.facts_emitted, 1, "engine owns the actual count");
        assert!(report.operational_errors.iter().any(|error| {
            error.stage == "collector-contract"
                && error.component == "undeclared-producer"
                && error.message.contains("plugin")
        }));
    }

    #[test]
    fn undeclared_rule_proof_is_capped_and_reported_operationally() {
        let engine = DiagnosticEngine::builder()
            .collector(Producer { id: "producer" })
            .collector(Consumer)
            .rule(ContractRule)
            .build_checked()
            .expect("valid graph");
        let report = engine.diagnose(&target());
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.id == "contract-violation")
            .expect("finding retained");
        assert!(finding.severity <= Severity::Warn);
        assert!(
            finding
                .machine_tags
                .iter()
                .any(|tag| tag == "rule-proof-contract-violation")
        );
        assert!(
            report.operational_errors.iter().any(|error| {
                error.stage == "rule-contract" && error.component == "contract-rule"
            })
        );
    }

    #[test]
    fn undeclared_rule_coverage_is_capped_and_reported_operationally() {
        let engine = DiagnosticEngine::builder()
            .collector(Producer { id: "producer" })
            .collector(Consumer)
            .rule(CoverageRule)
            .build_checked()
            .expect("valid graph");
        let report = engine.diagnose(&target());
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.id == "undeclared-coverage")
            .expect("finding retained");
        assert!(finding.severity <= Severity::Warn);
        assert!(
            finding
                .machine_tags
                .iter()
                .any(|tag| tag == "rule-coverage-contract-violation")
        );
        assert!(
            report.operational_errors.iter().any(|error| {
                error.stage == "rule-contract" && error.component == "coverage-rule"
            })
        );
    }

    #[test]
    fn profile_includes_every_post_rule_stage() {
        let engine = DiagnosticEngine::builder()
            .build_checked()
            .expect("empty engine is valid");
        let run = engine.diagnose_with_facts(&target());
        let ids = run
            .profile
            .pipeline
            .iter()
            .map(|phase| phase.id.as_str())
            .collect::<Vec<_>>();
        for required in [
            "coverage",
            "assessment",
            "coherence-graph",
            "reconciliation:cross-layer-coherence",
            "identity",
            "compaction",
            "triage:default-triage",
            "recommendations",
            "incident-synthesis",
            "report-postprocess",
        ] {
            assert!(ids.contains(&required), "missing profile phase {required}");
        }
        assert_eq!(run.report.profile.as_ref(), Some(&run.profile));
    }
}
