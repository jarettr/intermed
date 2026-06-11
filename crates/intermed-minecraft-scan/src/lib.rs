//! # intermed-minecraft-scan
//!
//! Layer A (environment detection) and Layer B (mod/plugin metadata) collectors.
//! Pure Rust — `zip` + `serde_json` / `toml` / `serde_yaml`. No JVM, no
//! bytecode: the dividing line from the Java codebase is `org.objectweb.asm`,
//! and nothing here crosses it. Deep class/annotation analysis is Layer F.

mod env;
mod metadata;

pub use env::EnvironmentCollector;
pub use metadata::MetadataCollector;
