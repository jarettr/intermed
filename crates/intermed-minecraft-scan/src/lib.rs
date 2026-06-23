//! # intermed-minecraft-scan
//!
//! Layer A (environment detection) and Layer B (mod/plugin metadata) collectors.
//! Pure Rust — `zip` + `serde_json` / `toml` / `serde_yaml`. No JVM, no
//! bytecode: the dividing line from the Java codebase is `org.objectweb.asm`,
//! and nothing here crosses it. Deep class/annotation analysis is Layer F.

mod access;
mod entrypoint_analysis;
mod env;
mod forge_annotation;
pub mod identity;
mod knowledge;
mod metadata;

pub use env::EnvironmentCollector;
pub use identity::{ArtifactIdentity, detect_from_zip as detect_artifact_identity, mod_id_or_stem};
pub use metadata::MetadataCollector;
