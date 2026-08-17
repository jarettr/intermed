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
use crate::scope::{CollectorScope, CompletenessModel};
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
    /// Registered in the pipeline but explicitly disabled by effective config.
    Disabled,
    /// Ran and (possibly) produced facts.
    Active,
    /// Ran and produced useful facts, but relevant input was truncated or failed.
    Incomplete,
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
    pub fn disabled(message: impl Into<String>) -> Self {
        Self {
            status: CollectorStatus::Disabled,
            facts_emitted: 0,
            message: message.into(),
        }
    }
    pub fn active(facts_emitted: usize, message: impl Into<String>) -> Self {
        Self {
            status: CollectorStatus::Active,
            facts_emitted,
            message: message.into(),
        }
    }
    pub fn incomplete(facts_emitted: usize, message: impl Into<String>) -> Self {
        Self {
            status: CollectorStatus::Incomplete,
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

/// A collector registration whose enabled state is part of the report.
///
/// Optional subsystems must remain visible even when disabled; absence from the
/// collector list is ambiguous with a wiring bug. This wrapper keeps the real
/// collector id/layer while returning an explicit disabled outcome when its
/// effective configuration gate is closed.
pub struct GatedCollector<C> {
    inner: C,
    enabled: bool,
    disabled_reason: String,
}

impl<C> GatedCollector<C> {
    pub fn new(inner: C, enabled: bool, disabled_reason: impl Into<String>) -> Self {
        Self {
            inner,
            enabled,
            disabled_reason: disabled_reason.into(),
        }
    }
}

impl<C: Collector> Collector for GatedCollector<C> {
    fn id(&self) -> &'static str {
        self.inner.id()
    }

    fn layer(&self) -> Layer {
        self.inner.layer()
    }

    fn applies(&self, target: &Target) -> bool {
        self.enabled && self.inner.applies(target)
    }

    fn scope(&self) -> CollectorScope {
        self.inner.scope()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        self.inner.collect(ctx)
    }

    fn not_applicable(&self, target: &Target) -> CollectorOutcome {
        if self.enabled {
            self.inner.not_applicable(target)
        } else {
            CollectorOutcome::disabled(self.disabled_reason.clone())
        }
    }
}

/// A unit of observation for one diagnostic layer.
pub trait Collector: Send + Sync {
    /// Stable id, e.g. `metadata-scanner`.
    fn id(&self) -> &'static str;

    /// The layer this collector belongs to.
    fn layer(&self) -> Layer;

    /// Static declaration of facts/target regions owned by this collector.
    /// Collectors should override this; the empty scope is retained only for
    /// compatibility with third-party collectors compiled against 0.1.x.
    fn scope(&self) -> CollectorScope {
        CollectorScope::new(CompletenessModel::BoundedPartial)
    }

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
    fn scope(&self) -> CollectorScope {
        CollectorScope::new(CompletenessModel::AllOrNothing)
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
