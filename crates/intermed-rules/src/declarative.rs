//! Declarative rule-pack runtime (interpreter-backed [`Rule`] impl).

use intermed_doctor_core::evidence::Finding;
use intermed_doctor_core::{Rule, RuleCtx};

use crate::RulePackError;
use crate::interpreter::{dedupe_by_subject, evaluate_pack};
use crate::model::RulePack;
use crate::pack::{default_core_pack_v2, default_core_pack_without_mixin};
use crate::validate::validate_rule_pack;

/// Interpreter-backed rule pack — single runtime for imperative and Datalog modes.
pub struct DeclarativeRulePack {
    pack: RulePack,
}

impl DeclarativeRulePack {
    pub fn new(pack: RulePack) -> Result<Self, RulePackError> {
        validate_rule_pack(&pack)?;
        Ok(Self { pack })
    }

    pub fn default_core() -> Self {
        Self::new(default_core_pack_v2()).expect("embedded core rule pack is valid")
    }

    /// Metadata / loader / resource / SBOM rules only — defers mixin to Layer F imperative rule.
    pub fn default_core_without_mixin() -> Self {
        Self::new(default_core_pack_without_mixin()).expect("embedded core rule pack is valid")
    }

    pub fn pack(&self) -> &RulePack {
        &self.pack
    }
}

impl Rule for DeclarativeRulePack {
    fn id(&self) -> &'static str {
        // Stable wire id retained for reports, CLI e2e, and `--logic datalog` users.
        "datalog-rule-pack"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        dedupe_by_subject(evaluate_pack(&self.pack, ctx))
    }
}

/// Backward-compatible alias used by CLI `--logic datalog`.
pub type DatalogRulePack = DeclarativeRulePack;
