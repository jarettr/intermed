//! # intermed-resource-ast — Layer M (resource / data semantics)
//!
//! A typed-AST layer over the Layer-E VFS. Where Layer E sees *bytes and
//! collisions*, Layer M sees *meaning*: a recipe's type and outputs, a tag's
//! entries and replace mode, a model's parent and textures, and the reference
//! graph that ties them together.
//!
//! It preserves InterMed's philosophy strictly — **the AST never emits findings**:
//!
//! ```text
//! resource bytes → syntax AST → typed domain AST → semantic summary → facts → rules → findings
//! ```
//!
//! [`collector`] groups VFS resource writers, parses them in parallel (cached
//! per-jar via the shared [`JarCache`](intermed_doctor_core::JarCache)), and emits
//! compact facts; rules in [`rule`] turn those facts into findings. Depth is
//! controlled by [`ResourceLevel`] (`--resource-level basic|semantic|full`).

pub mod collector;
pub mod domain;
pub mod model;
pub mod rule;
pub mod scan;
pub mod semantic;
pub mod syntax;

pub use collector::{collector, scan_mods_dir, ResourceAstScan};
pub use rule::rule;
pub use semantic::diff;
pub use semantic::refs::{ResourceAstRecord, ResourceGraph};
pub use domain::{parse_resource, parser_version, RESOURCE_AST_CACHE_SCHEMA};
pub use model::{
    CachedResourceAst, ParseStatus, RefRelation, ResourceDomain, ResourceLevel,
    ResourceParseDiagnostic, ResourceReference, ResourceSummary,
};

/// Implementation status, shown in CLI help and `STATUS.md`.
pub const STATUS: &str = "active experimental: Layer M (resource AST)";
