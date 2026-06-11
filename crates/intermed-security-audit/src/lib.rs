//! # intermed-security-audit — Layer G (Phase 6)
//!
//! Static security & supply-chain audit — no enforcement, no instrumentation.
//!
//! **Will emit facts:** `uses_process_spawn(mod)`, `uses_socket(mod)`,
//! `uses_reflection_set_accessible(mod)`, `uses_unsafe(mod)`,
//! `uses_native_library(mod)`, `uses_dynamic_class_definition(mod)`,
//! `writes_files(mod, pattern)`, `unknown_origin(jar)`, `checksum(jar)`.
//!
//! **⚠ Tier 2 — the JVM frontier.** Ports the *analysis* half of the old
//! `SecurityHookTransformer` (which used ASM to find file/network/process/
//! native/varhandle/dynamic-class-definition usage) into a **static scanner**,
//! not a transformer. Same Rust class-file parser vs JVM-worker choice as
//! Layer F.
//!
//! **Donors (research-only):** `SecurityHookTransformer` (its API-usage
//! detection, not its bytecode rewriting), `CapabilityManager`, `SecurityPolicy`.

use intermed_doctor_core::{Collector, DeferredCollector, Layer};

/// The (currently deferred) Layer-G collector.
pub fn collector() -> impl Collector {
    DeferredCollector::new("security-scanner", Layer::Security)
}
