//! # intermed-doctor-core
//!
//! The diagnosis pipeline and its contracts. Everything else plugs in here:
//!
//! ```text
//!   Target ──▶ [Collectors] ──▶ FactStore ──▶ [Rules] ──▶ Findings ──▶ DoctorReport
//! ```
//!
//! * [`Collector`] — observes a [`Target`], writes facts. One per layer.
//! * [`Rule`] — reads facts, emits [`Finding`](intermed_evidence::Finding)s.
//! * [`DiagnosticEngine`] — orchestrates the two and assembles a
//!   [`DoctorReport`].
//!
//! The engine depends on neither Minecraft nor logs nor any concrete layer; the
//! composition root (`intermed-cli`) registers the collectors and rules. This is
//! the seam that keeps later phases cheap: a new layer is a new `Collector`
//! impl plus one registration line.

pub mod assessment;
pub mod bounded_zip;
pub mod coherence;
pub mod collector;
pub mod engine;
pub mod fabric_json;
pub mod instance_layout;
pub mod io_util;
pub mod jar_cache;
pub mod jar_meta;
pub mod layer;
pub mod modpack;
pub mod modpack_manifest;
pub mod profile;
pub mod report;
pub mod rule;
pub mod scan_filter;
pub mod scope;
pub mod settings;
pub mod suppression;
pub mod target;

pub use collector::{
    CollectCtx, Collector, CollectorOutcome, CollectorStatus, DeferredCollector, GatedCollector,
};
pub use engine::{DiagnosticEngine, DiagnosticRun, EngineBuilder};
pub use instance_layout::{
    LayoutKind, ResolvedLayout, find_mods_directory, resolve_game_root, resolve_layout,
};
pub use io_util::write_atomic;
pub use jar_cache::{
    CACHE_SCHEMA as JAR_CACHE_SCHEMA, CacheStats, DEFAULT_CACHE_MAX_AGE_DAYS,
    DEFAULT_CACHE_MAX_BYTES, DEFAULT_CACHE_MIN_BYTES, DEFAULT_FINGERPRINT_REVERIFY_DAYS,
    DEFAULT_PRUNE_INTERVAL_DAYS, JarCache, JarCacheConfig, LocalDirRemoteTier, RemoteCacheTier,
};
pub use layer::Layer;
pub use modpack::{ModpackError, ModpackMount, materialize_modpack_archive};
pub use modpack_manifest::{ModpackIntegrityRule, ModpackManifestCollector};
pub use profile::{DiagnosticProfile, PROFILE_SCHEMA, PhaseTiming};
pub use report::{
    DoctorReport, OperationalError, REPORT_SCHEMA, REPORT_SCHEMA_V1, REPORT_SCHEMA_V2,
};
pub use rule::{Rule, RuleCtx, RuleError};
pub use scan_filter::{filter_jar_paths, list_jar_archives, parse_changed_since, should_scan_path};
pub use scope::{
    CollectorScope, CompletenessModel, InputRequirement, RuleRequirements, TargetCapabilities,
    TargetRegion,
};
pub use settings::{
    DiagnosisSettings, FactStoreSettings, LogSettings, MetadataLevel, MetadataSettings, MixinLevel,
    MixinSettings, ResourceAstLevel, ResourceSettings, SbomSettings, ScanSettings,
    SecuritySettings, default_settings,
};
pub use target::{
    Environment, InstanceType, Loader, Side, Target, TargetKind, detect_target, target_from_layout,
};

// Re-export the foundational crates so collector/rule crates can depend on just
// `intermed-doctor-core` and still speak facts/findings.
pub use intermed_evidence as evidence;
pub use intermed_facts as facts;

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_evidence::{Category, Finding, Severity};

    struct DummyCollector;
    impl Collector for DummyCollector {
        fn id(&self) -> &'static str {
            "dummy"
        }
        fn layer(&self) -> Layer {
            Layer::Metadata
        }
        fn applies(&self, _t: &Target) -> bool {
            true
        }
        fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
            ctx.store
                .fact("dummy", facts::kind::MOD)
                .subject("sodium")
                .emit();
            CollectorOutcome::active(1, "emitted one mod fact")
        }
    }

    struct DummyRule;
    impl Rule for DummyRule {
        fn id(&self) -> &'static str {
            "dummy-rule"
        }
        fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, RuleError> {
            Ok(ctx
                .store
                .by_kind(facts::kind::MOD)
                .map(|m| {
                    Finding::builder("dummy-rule", format!("seen:{}", m.subject))
                        .severity(Severity::Note)
                        .category(Category::Metadata)
                        .title(format!("Saw mod {}", m.subject))
                        .build()
                })
                .collect())
        }
    }

    struct FailingCollector;
    impl Collector for FailingCollector {
        fn id(&self) -> &'static str {
            "failing-collector"
        }
        fn layer(&self) -> Layer {
            Layer::Metadata
        }
        fn applies(&self, _t: &Target) -> bool {
            true
        }
        fn collect(&self, _ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
            CollectorOutcome::failed("collector exploded")
        }
    }

    struct FailingRule;
    impl Rule for FailingRule {
        fn id(&self) -> &'static str {
            "failing-rule"
        }
        fn evaluate(&self, _ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, RuleError> {
            Err(RuleError::new("backend exploded"))
        }
    }

    struct RetentionFixtureCollector;
    impl Collector for RetentionFixtureCollector {
        fn id(&self) -> &'static str {
            "retention-fixture"
        }
        fn layer(&self) -> Layer {
            Layer::Mixin
        }
        fn applies(&self, _target: &Target) -> bool {
            true
        }
        fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
            ctx.store
                .fact(self.id(), facts::kind::LOG_SIGNAL)
                .subject("MixinApplyError")
                .emit();
            ctx.store
                .fact(self.id(), facts::kind::MIXIN_APPLICATION_SITE)
                .subject("fixture-site")
                .emit();
            ctx.store
                .fact(self.id(), facts::kind::MIXIN_HANDLER_BODY)
                .subject("reflective-handler")
                .emit();
            ctx.store
                .fact(self.id(), facts::kind::MIXIN_INJECTION_POINT)
                .subject("external-predicate")
                .emit();
            for index in 0..128 {
                ctx.store
                    .fact(self.id(), facts::kind::MIXIN_HANDLER_BODY)
                    .subject(format!("bulk-{index}"))
                    .emit();
            }
            CollectorOutcome::active(132, "retention parity fixture")
        }
    }

    /// Models built-in and out-of-tree consumers of predicates that snapshot
    /// retention is allowed to drop. All four conclusions must be derived before
    /// compaction regardless of the configured snapshot limit.
    struct RetentionFixtureRule;
    impl Rule for RetentionFixtureRule {
        fn id(&self) -> &'static str {
            "external-retention-fixture"
        }
        fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, RuleError> {
            let site = ctx
                .store
                .by_kind(facts::kind::MIXIN_APPLICATION_SITE)
                .next();
            let log = ctx.store.by_kind(facts::kind::LOG_SIGNAL).next();
            let body = ctx
                .store
                .by_kind(facts::kind::MIXIN_HANDLER_BODY)
                .find(|fact| fact.subject == "reflective-handler");
            let external = ctx.store.by_kind(facts::kind::MIXIN_INJECTION_POINT).next();
            let mut out = Vec::new();
            if let (Some(site), Some(log)) = (site, log) {
                out.push(
                    Finding::builder(self.id(), "retention:runtime-confirmed-mixin")
                        .severity(Severity::Error)
                        .category(Category::Mixin)
                        .title("runtime-confirmed mixin")
                        .evidence(intermed_evidence::EvidenceEdge::supports(site.id))
                        .evidence(intermed_evidence::EvidenceEdge::supports(log.id))
                        .build(),
                );
                out.push(
                    Finding::builder(self.id(), "retention:performance-mixin-correlation")
                        .severity(Severity::Warn)
                        .category(Category::Performance)
                        .title("performance correlation")
                        .evidence(intermed_evidence::EvidenceEdge::supports(site.id))
                        .build(),
                );
            }
            if let Some(body) = body {
                out.push(
                    Finding::builder(self.id(), "retention:reflective-mixin-security")
                        .severity(Severity::Warn)
                        .category(Category::Security)
                        .title("reflective handler")
                        .evidence(intermed_evidence::EvidenceEdge::supports(body.id))
                        .build(),
                );
            }
            if let Some(external) = external {
                out.push(
                    Finding::builder(self.id(), "retention:external-rule")
                        .severity(Severity::Note)
                        .category(Category::Mixin)
                        .title("external predicate")
                        .evidence(intermed_evidence::EvidenceEdge::supports(external.id))
                        .build(),
                );
            }
            Ok(out)
        }
    }

    #[test]
    fn engine_runs_collectors_then_rules() {
        let engine = DiagnosticEngine::builder()
            .collector(DummyCollector)
            .collector(DeferredCollector::new("vfs", Layer::Resource))
            .rule(DummyRule)
            .build();

        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: Some(".".into()),
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let run = engine.diagnose_with_facts(&target);
        let report = &run.report;

        assert_eq!(report.schema, REPORT_SCHEMA);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.summary.note, 1);
        // The deferred VFS layer is surfaced even though it never ran.
        assert_eq!(report.deferred_layers.len(), 1);
        assert_eq!(report.deferred_layers[0].layer_code, "E");
        assert_eq!(report.exit_code(), 0);
        assert_eq!(run.profile.schema, PROFILE_SCHEMA);
        let phase_sum: u64 = run
            .profile
            .collectors
            .iter()
            .chain(run.profile.rules.iter())
            .map(|p| p.duration_ms)
            .sum();
        assert!(run.profile.total_ms >= phase_sum);
    }

    #[test]
    fn operational_failures_are_not_domain_findings() {
        let engine = DiagnosticEngine::builder()
            .collector(FailingCollector)
            .rule(FailingRule)
            .build();
        let target = Target::with_kind(".", TargetKind::ModsDir);
        let report = engine.diagnose(&target);

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.total, 0);
        assert_eq!(report.operational_errors.len(), 2);
        assert!(
            report.operational_errors.iter().any(|error| {
                error.stage == "collector" && error.component == "failing-collector"
            })
        );
        assert!(
            report
                .operational_errors
                .iter()
                .any(|error| error.stage == "rule" && error.component == "failing-rule")
        );
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn tiny_snapshot_retention_does_not_change_finding_identities() {
        fn diagnose(max_facts: usize) -> DiagnosticRun {
            let mut settings = DiagnosisSettings::default();
            settings.facts.retention.max_facts = max_facts;
            DiagnosticEngine::builder()
                .collector(RetentionFixtureCollector)
                .rule(RetentionFixtureRule)
                .settings(settings)
                .build()
                .diagnose_with_facts(&Target::with_kind(".", TargetKind::ModsDir))
        }

        let unbounded = diagnose(usize::MAX);
        let bounded = diagnose(1);
        let ids = |run: &DiagnosticRun| {
            run.report
                .findings
                .iter()
                .map(|finding| finding.id.clone())
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(ids(&unbounded), ids(&bounded));
        assert_eq!(ids(&bounded).len(), 4);
        assert!(bounded.profile.facts_dropped > 0);
        for finding in &bounded.report.findings {
            assert!(
                finding
                    .evidence
                    .iter()
                    .all(|edge| bounded.facts.iter().any(|fact| fact.id == edge.fact)),
                "cited evidence for {} must survive snapshot compaction",
                finding.id
            );
        }
    }
}
