//! Thin imperative rule wrappers delegating to the declarative interpreter.
//!
//! These exist for backward-compatible imports and parity tests. New code should
//! register [`crate::DeclarativeRulePack`] instead of individual rules.

use std::collections::BTreeSet;

use intermed_doctor_core::evidence::{
    Category, CoverageRequirement, EvidenceEdge, EvidenceOrigin, Finding, FixCandidate, Impact,
    ProofKind, Severity,
};
use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{Rule, RuleCtx};

use crate::declarative::DeclarativeRulePack;
use crate::interpreter::evaluate_pack;
use crate::pack::default_core_pack_v3;

/// Two artifacts claim the same id.
pub struct DuplicateIdRule;

impl Rule for DuplicateIdRule {
    fn id(&self) -> &'static str {
        "duplicate-id"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        Ok(evaluate_pack(&default_core_pack_v3(), ctx)
            .into_iter()
            .filter(|f| f.rule_id == "duplicate-id")
            .collect())
    }
}

/// A mod's loader differs from the instance loader.
pub struct LoaderMismatchRule;

impl Rule for LoaderMismatchRule {
    fn id(&self) -> &'static str {
        "loader-mismatch"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        Ok(evaluate_pack(&default_core_pack_v3(), ctx)
            .into_iter()
            .filter(|f| f.rule_id == "loader-mismatch")
            .collect())
    }
}

/// Bare mods directory mixes incompatible loaders with no instance baseline.
pub struct MixedLoaderPackRule;

impl Rule for MixedLoaderPackRule {
    fn id(&self) -> &'static str {
        "mixed-loader-pack"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        let env_loader = ctx
            .store
            .by_kind(kind::ENVIRONMENT)
            .find_map(|f| f.attr("loader"))
            .filter(|l| is_mod_loader(l));
        if env_loader.is_some() {
            return Ok(Vec::new());
        }

        let mut loaders = BTreeSet::new();
        for f in ctx
            .store
            .by_kind(kind::MOD)
            .filter(|fact| fact.attr("identity_certainty") != Some("undecidable"))
        {
            if let Some(loader) = f.attr("loader")
                && is_mod_loader(loader)
            {
                loaders.insert(loader.to_string());
            }
        }
        if loaders.len() < 2 {
            return Ok(Vec::new());
        }

        let list: Vec<&str> = loaders.iter().map(String::as_str).collect();
        let bridges = ctx
            .store
            .by_kind(kind::COMPATIBILITY_BRIDGE)
            .filter(|fact| fact.attr("scope") == Some("mod-runtime"))
            .collect::<Vec<_>>();
        let bridge_ids = bridges
            .iter()
            .map(|fact| fact.subject.as_str())
            .collect::<Vec<_>>();
        let bridge_detected = !bridges.is_empty();
        let explanation = if bridge_detected {
            format!(
                "This directory contains descriptors for multiple loaders ({}) and runtime bridge evidence ({}) but no authoritative instance loader. The mixed-loader state is observed; whether every bridged artifact is supported is undecidable without the target loader and bridge compatibility contract.",
                list.join(", "),
                bridge_ids.join(", ")
            )
        } else {
            format!(
                "This directory contains descriptors for multiple loaders ({}) but no authoritative instance loader or supported runtime bridge was detected. Compatibility cannot be asserted until the target loader is known.",
                list.join(", ")
            )
        };
        let mut builder = Finding::builder(self.id(), "mixed-loader-pack:mods-dir")
            .severity(Severity::Warn)
            .category(Category::Loader)
            .title(if bridge_detected {
                "Mixed loaders with compatibility bridge"
            } else {
                "Mixed mod loaders; target loader unknown"
            })
            .explanation(explanation)
            .fix(FixCandidate::advice(
                "Analyze the full instance or supply its pack manifest. If a bridge is intentional, verify that it supports each affected artifact and target loader version.",
            ))
            .coverage_requirement(CoverageRequirement::AuthoritativeLoader)
            .coverage_requirement(CoverageRequirement::KnownBridgeSemantics)
            .proof_kind(ProofKind::Observation)
            .impact(Impact::CompatibilityRisk)
            .evidence_origin(EvidenceOrigin::StaticExact)
            .tag("loader")
            .tag("mixed-pack");
        for bridge in bridges {
            builder = builder.evidence(EvidenceEdge::subject(bridge.id));
        }
        Ok(vec![builder.build()])
    }
}

fn is_mod_loader(loader: &str) -> bool {
    matches!(loader, "fabric" | "quilt" | "forge" | "neoforge")
}

/// A client-only mod on a server (or vice versa).
pub struct SideMismatchRule;

impl Rule for SideMismatchRule {
    fn id(&self) -> &'static str {
        "side-mismatch"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        Ok(evaluate_pack(&default_core_pack_v3(), ctx)
            .into_iter()
            .filter(|f| f.id.starts_with("side-mismatch:"))
            .collect())
    }
}

/// All Phase-1 generic rules via one declarative pack (preferred registration path).
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(DeclarativeRulePack::default_core())]
}
