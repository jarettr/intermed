//! Semantic layer: cross-resource reasoning over the typed summaries.
//!
//! `namespace` is the shared primitive (ids → owners). The reference graph,
//! cross-writer diffs, merge plans, condition handling, and fact lowering build on
//! it (added as the layer comes online).

pub mod diff;
pub mod facts;
pub mod impact;
pub mod namespace;
pub mod refs;
