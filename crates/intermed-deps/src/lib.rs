//! # intermed-deps
//!
//! Layer C — dependency / version reasoning over metadata facts.
//!
//! Phase 1 shipped conservative pairwise semver checks. This crate now adds a
//! **PubGrub** global resolver (via the [`pubgrub`] crate and
//! [`creeper-semver-pubgrub`] range bridging) for joint satisfiability and
//! human-readable unsat explanations — the behavior the legacy
//! `PubGrubResolver` provided in the Java donor.
//!
//! ## Architecture
//!
//! ```text
//! FactStore ──▶ ModpackGraph ──▶ ModpackProvider ──▶ pubgrub::resolve
//!                    │                                      │
//!                    └──────────── DependencyRule ◀───────────┘
//!                              (pairwise + global unsat)
//! ```
//!
//! Pairwise checks remain for precise finding ids (`missing-dependency`,
//! `wrong-version`, `wrong-mc-version`). PubGrub adds `dependency-unsat:global`
//! with a derivation-tree explanation when the installed catalog is jointly
//! inconsistent.

mod effective;
mod explain;
mod graph;
mod impact;
mod implicit;
mod ordering;
mod pairwise;
mod provider;
mod ranges;
mod report;
mod resolver;
mod rule;
mod semver;

pub use effective::{DeclaredDep, EffectiveModel, ImplicitDep};
pub use explain::{
    DepEdge, DependencyIndex, EdgeKind, ImplicitRef, WhyReport, implicit_for_namespace,
    path as dependency_path, why, why_missing,
};
pub use graph::{
    MODPACK_ROOT_ID, ModDependencyEdge, ModPackage, ModpackGraph, PLATFORM_IDS, ProvidedAlias,
    SkipReason, SkippedPackage, build_graph,
};
pub use impact::{
    BreakingDep, ImplicitDependent, RemoveImpact, ReverseResourceImpact, UpdateImpact,
    remove_impact, update_impact,
};
pub use provider::{ModpackProvider, ProviderError, build_provider};
pub use ranges::{ModRange, parse_mod_range};
pub use report::{format_derivation_tree, format_unsat_tree};
pub use resolver::{
    ResolutionOutcome, ResolutionSkipReason, ResolverError, resolve_graph, resolve_store,
};
pub use rule::DependencyRule;
pub use semver::{parse_lenient, parse_mod_version, parse_version_reqs, version_in_range};

/// Implementation status string for CLI help and deferred-layer listings.
pub const STATUS: &str = "active: pairwise semver + PubGrub global resolver";

/// Layer-C dependency rule (pairwise + PubGrub).
pub fn rule() -> DependencyRule {
    DependencyRule
}

/// Serialize a [`ModpackGraph`] or [`ResolutionOutcome`] for `intermed deps`.
pub fn graph_to_json(graph: &ModpackGraph) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(graph)
}

/// Serialize resolution outcome for CLI / tooling.
pub fn resolution_to_json(outcome: &ResolutionOutcome) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(outcome)
}
