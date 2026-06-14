//! The [`Collector`] contract.
//!
//! A collector observes a [`Target`] and writes [`Fact`](intermed_facts::Fact)s.
//! It never produces findings and never reads other collectors' output —
//! collectors are pure observation, rules are pure inference. This is what lets
//! a future phase add a whole layer by writing one `Collector` impl and
//! registering it; nothing else changes.

use intermed_facts::FactStore;

use crate::jar_cache::JarCache;
use crate::layer::Layer;
use crate::settings::DiagnosisSettings;
use crate::target::Target;

/// Context handed to a collector: the target and the store to write into.
pub struct CollectCtx<'a> {
    pub target: &'a Target,
    pub store: &'a mut FactStore,
    /// Per-jar scan cache (`None` when `--no-cache` or cache disabled).
    pub jar_cache: Option<&'a JarCache>,
    pub settings: &'a DiagnosisSettings,
}

/// What happened when a collector ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorStatus {
    /// Ran and (possibly) produced facts.
    Active,
    /// Intentionally did not run (target not applicable).
    Skipped,
    /// Layer not implemented yet — reserved for a later phase.
    Deferred,
    /// Ran but errored.
    Failed,
}

/// Outcome record for the report.
#[derive(Debug, Clone)]
pub struct CollectorOutcome {
    pub status: CollectorStatus,
    pub facts_emitted: usize,
    pub message: String,
}

impl CollectorOutcome {
    pub fn active(facts_emitted: usize, message: impl Into<String>) -> Self {
        Self {
            status: CollectorStatus::Active,
            facts_emitted,
            message: message.into(),
        }
    }
    pub fn skipped(message: impl Into<String>) -> Self {
        Self {
            status: CollectorStatus::Skipped,
            facts_emitted: 0,
            message: message.into(),
        }
    }
    pub fn deferred(message: impl Into<String>) -> Self {
        Self {
            status: CollectorStatus::Deferred,
            facts_emitted: 0,
            message: message.into(),
        }
    }
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            status: CollectorStatus::Failed,
            facts_emitted: 0,
            message: message.into(),
        }
    }
}

/// A unit of observation for one diagnostic layer.
pub trait Collector: Send + Sync {
    /// Stable id, e.g. `metadata-scanner`.
    fn id(&self) -> &'static str;

    /// The layer this collector belongs to.
    fn layer(&self) -> Layer;

    /// Whether this collector should run against the given target.
    fn applies(&self, target: &Target) -> bool;

    /// Observe the target and write facts. Implementations should be
    /// side-effect free with respect to the target (read-only).
    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome;

    /// Called by the engine when [`Collector::applies`] returned `false`, so the
    /// collector can explain *why* it did not run (skipped vs deferred). The
    /// default reports a plain skip.
    fn not_applicable(&self, _target: &Target) -> CollectorOutcome {
        CollectorOutcome::skipped(format!(
            "{} not applicable to this target.",
            self.layer().label()
        ))
    }
}

/// Convenience base for not-yet-implemented layers: declares the layer, never
/// runs, and reports itself as deferred to its phase. Filling a layer later
/// means replacing this with a real `Collector` — the engine wiring is
/// identical.
pub struct DeferredCollector {
    id: &'static str,
    layer: Layer,
}

impl DeferredCollector {
    pub const fn new(id: &'static str, layer: Layer) -> Self {
        Self { id, layer }
    }
}

impl Collector for DeferredCollector {
    fn id(&self) -> &'static str {
        self.id
    }
    fn layer(&self) -> Layer {
        self.layer
    }
    fn applies(&self, _target: &Target) -> bool {
        false
    }
    fn collect(&self, _ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        self.deferred_outcome()
    }
    fn not_applicable(&self, _target: &Target) -> CollectorOutcome {
        self.deferred_outcome()
    }
}

impl DeferredCollector {
    fn deferred_outcome(&self) -> CollectorOutcome {
        CollectorOutcome::deferred(format!(
            "Layer {} ({}) lands in Phase {}.",
            self.layer.code(),
            self.layer.label(),
            self.layer.phase()
        ))
    }
}
