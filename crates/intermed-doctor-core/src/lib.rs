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
pub mod layer;
pub mod report;
pub mod rule;
pub mod target;

pub use collector::{CollectCtx, Collector, CollectorOutcome, CollectorStatus, DeferredCollector};
pub use engine::{DiagnosticEngine, DiagnosticRun, EngineBuilder};
pub use layer::Layer;
pub use report::{DoctorReport, REPORT_SCHEMA};
pub use rule::{Rule, RuleCtx};
pub use target::{detect_target, Environment, Loader, Side, Target, TargetKind};

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
        };
        let report = engine.diagnose(&target);

        assert_eq!(report.schema, REPORT_SCHEMA);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.summary.note, 1);
        // The deferred VFS layer is surfaced even though it never ran.
        assert_eq!(report.deferred_layers.len(), 1);
        assert_eq!(report.deferred_layers[0].layer_code, "E");
        assert_eq!(report.exit_code(), 0);
    }
}
