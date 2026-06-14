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

pub mod collector;
pub mod engine;
pub mod io_util;
pub mod jar_cache;
pub mod layer;
pub mod instance_layout;
pub mod modpack;
pub mod modpack_manifest;
pub mod profile;
pub mod report;
pub mod rule;
pub mod scan_filter;
pub mod settings;
pub mod target;

pub use collector::{CollectCtx, Collector, CollectorOutcome, CollectorStatus, DeferredCollector};
pub use engine::{DiagnosticEngine, DiagnosticRun, EngineBuilder};
pub use io_util::write_atomic;
pub use jar_cache::{
    CacheStats, JarCache, JarCacheConfig, LocalDirRemoteTier, RemoteCacheTier,
    CACHE_SCHEMA as JAR_CACHE_SCHEMA, DEFAULT_CACHE_MAX_AGE_DAYS, DEFAULT_CACHE_MAX_BYTES,
    DEFAULT_CACHE_MIN_BYTES, DEFAULT_FINGERPRINT_REVERIFY_DAYS, DEFAULT_PRUNE_INTERVAL_DAYS,
};
pub use layer::Layer;
pub use profile::{DiagnosticProfile, PhaseTiming, PROFILE_SCHEMA};
pub use report::{DoctorReport, REPORT_SCHEMA};
pub use rule::{Rule, RuleCtx};
pub use modpack::{materialize_modpack_archive, ModpackError, ModpackMount};
pub use modpack_manifest::{ModpackIntegrityRule, ModpackManifestCollector};
pub use scan_filter::{
    filter_jar_paths, list_jar_archives, parse_changed_since, should_scan_path,
};
pub use settings::{
    default_settings, DiagnosisSettings, FactStoreSettings, LogSettings, MetadataLevel,
    MetadataSettings, MixinLevel, MixinSettings, ResourceAstLevel, ResourceSettings, ScanSettings,
    SbomSettings, SecuritySettings,
};
pub use instance_layout::{
    find_mods_directory, resolve_layout, resolve_game_root, LayoutKind, ResolvedLayout,
};
pub use target::{
    detect_target, target_from_layout, Environment, InstanceType, Loader, Side, Target, TargetKind,
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
        fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
            ctx.store
                .by_kind(facts::kind::MOD)
                .map(|m| {
                    Finding::builder("dummy-rule", format!("seen:{}", m.subject))
                        .severity(Severity::Note)
                        .category(Category::Metadata)
                        .title(format!("Saw mod {}", m.subject))
                        .build()
                })
                .collect()
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
}
