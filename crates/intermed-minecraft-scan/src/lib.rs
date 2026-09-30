//! # intermed-minecraft-scan
//!
//! Layer A (environment detection) and Layer B (mod/plugin metadata) collectors.
//! Pure Rust — no JVM or mod code execution. Layer B performs bounded structural
//! class inspection where identity and lifecycle metadata require it (legacy
//! Forge `@Mod`, entrypoints, package ownership and references). Layer F remains
//! responsible for Mixin transformation and injection semantics.

mod access;
mod entrypoint_analysis;
mod env;
mod forge_annotation;
pub mod identity;
mod knowledge;
mod metadata;

pub use env::EnvironmentCollector;
pub use identity::{
    ArtifactDescriptorSet, ArtifactIdentity, ArtifactIdentityResolution, DescriptorCandidate,
    DescriptorFailure, IdentityResolutionCertainty, detect_from_zip as detect_artifact_identity,
    detect_from_zip_for_loader, mod_id_or_stem,
};
pub use metadata::MetadataCollector;
