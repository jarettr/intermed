//! Thin imperative rule wrappers delegating to the declarative interpreter.
//!
//! These exist for backward-compatible imports and parity tests. New code should
//! register [`crate::DeclarativeRulePack`] instead of individual rules.

use std::collections::BTreeSet;

use intermed_doctor_core::evidence::{Category, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{Rule, RuleCtx};

use crate::declarative::DeclarativeRulePack;
use crate::interpreter::evaluate_pack;
use crate::pack::default_core_pack_v2;

/// Two artifacts claim the same id.
pub struct DuplicateIdRule;

impl Rule for DuplicateIdRule {
    fn id(&self) -> &'static str {
        "duplicate-id"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        evaluate_pack(&default_core_pack_v2(), ctx)
            .into_iter()
            .filter(|f| f.rule_id == "duplicate-id")
            .collect()
    }
}

/// A mod's loader differs from the instance loader.
pub struct LoaderMismatchRule;

impl Rule for LoaderMismatchRule {
    fn id(&self) -> &'static str {
        "loader-mismatch"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        evaluate_pack(&default_core_pack_v2(), ctx)
            .into_iter()
            .filter(|f| f.rule_id == "loader-mismatch")
            .collect()
    }
}

/// Bare mods directory mixes incompatible loaders with no instance baseline.
pub struct MixedLoaderPackRule;

impl Rule for MixedLoaderPackRule {
    fn id(&self) -> &'static str {
        "mixed-loader-pack"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let env_loader = ctx
            .store
            .by_kind(kind::ENVIRONMENT)
            .find_map(|f| f.attr("loader"))
            .filter(|l| is_mod_loader(l));
        if env_loader.is_some() {
            return Vec::new();
        }

        let mut loaders = BTreeSet::new();
        for f in ctx.store.by_kind(kind::MOD) {
            if let Some(loader) = f.attr("loader") {
                if is_mod_loader(loader) {
                    loaders.insert(loader.to_string());
                }
            }
        }
        if loaders.len() < 2 {
            return Vec::new();
        }

        let list: Vec<&str> = loaders.iter().map(String::as_str).collect();
        vec![
            Finding::builder(self.id(), "mixed-loader-pack:mods-dir")
                .severity(Severity::Warn)
                .category(Category::Loader)
                .title("Mixed mod loaders in directory")
                .explanation(format!(
                    "This directory contains mods for multiple loaders ({}) but no instance \
                     loader was detected, so per-mod loader-mismatch rules did not run. Such a \
                     mix cannot load together in one Minecraft instance.",
                    list.join(", ")
                ))
                .fix(FixCandidate::advice(
                    "Split mods by loader into separate instance directories, or point \
                     intermed at a full instance/server root so the environment loader is known.",
                ))
                .tag("loader")
                .tag("mixed-pack")
                .build(),
        ]
    }
}

fn is_mod_loader(loader: &str) -> bool {
    matches!(
        loader,
        "fabric" | "quilt" | "forge" | "neoforge"
    )
}

/// A client-only mod on a server (or vice versa).
pub struct SideMismatchRule;

impl Rule for SideMismatchRule {
    fn id(&self) -> &'static str {
        "side-mismatch"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        evaluate_pack(&default_core_pack_v2(), ctx)
            .into_iter()
            .filter(|f| f.id.starts_with("side-mismatch:"))
            .collect()
    }
}

/// All Phase-1 generic rules via one declarative pack (preferred registration path).
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(DeclarativeRulePack::default_core())]
}