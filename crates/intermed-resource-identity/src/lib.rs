//! # intermed-resource-identity
//!
//! The canonical Minecraft resource identity model. A resource path
//! (`data/create/recipes/crushing/tuff.json`) is parsed **once** into a
//! [`ResourceKey`] — domain, namespace, registry, object id, side — that Layer E
//! (the byte-level VFS), Layer M (the typed resource AST), implicit-dependency
//! resolution, overlay/PackOps, and the report all read instead of each
//! re-parsing the path their own way.
//!
//! Having one parser is a deliberate guard against the "every layer parses paths
//! differently" drift the roadmap calls out: domain classification and namespace
//! extraction live here and nowhere else.

mod alias;
mod domain;
mod key;
mod namespace;
mod resolve;
mod writer;

pub use alias::{is_satisfied_by, namespace_aliases};
pub use domain::{ResourceDomain, classify};
pub use key::{ResourceId, ResourceKey, Side};
pub use namespace::{is_platform_namespace, namespace_of, path_namespace};
pub use resolve::{NamespaceClass, ResolveState, classify_namespace, resolve_state};
pub use writer::mod_id_from_mods_toml;

/// Identity-model version. Bump when path parsing / object-id derivation changes
/// in a way that would invalidate cached `ResourceKey`s or persisted facts that
/// embed derived ids.
pub const IDENTITY_MODEL_VERSION: &str = "resource-identity-r1";
