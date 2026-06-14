//! The [`Rule`] contract.
//!
//! A rule reads the [`FactStore`] (read-only) and emits [`Finding`]s. Phase 1
//! rules are plain imperative Rust; Phase 5 introduces a Datalog backend behind
//! this same trait (a `DatalogRulePack` that implements `Rule`), so the engine
//! and CLI never learn which backend produced a finding.

use intermed_evidence::Finding;
use intermed_facts::FactStore;

use crate::settings::DiagnosisSettings;
use crate::target::Target;

/// Context handed to a rule during evaluation.
pub struct RuleCtx<'a> {
    pub store: &'a FactStore,
    pub target: &'a Target,
    pub settings: &'a DiagnosisSettings,
}

impl<'a> RuleCtx<'a> {
    pub fn new(store: &'a FactStore, target: &'a Target, settings: &'a DiagnosisSettings) -> Self {
        Self {
            store,
            target,
            settings,
        }
    }

    /// Test helper: borrows a process-wide default [`DiagnosisSettings`].
    pub fn for_test(store: &'a FactStore, target: &'a Target) -> Self {
        use std::sync::LazyLock;
        static DEFAULT: LazyLock<DiagnosisSettings> = LazyLock::new(DiagnosisSettings::default);
        Self::new(store, target, &DEFAULT)
    }
}

/// A derivation from facts to findings.
pub trait Rule: Send + Sync {
    /// Stable id, e.g. `missing-dependency`.
    fn id(&self) -> &'static str;

    /// Evaluate against the fact store and return any findings.
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding>;
}
