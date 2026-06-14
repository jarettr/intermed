//! # intermed-runtime-preflight — Layer L (Phase 9)
//!
//! The bridge toward the (future, optional) runtime. Doctor is designed so it
//! can later *accept* a runtime, but in the first public year this is diagnosis
//! only — **no enforcement** ("Doctor and PackOps explain. Runtime enforces.").
//!
//! ## Status: intentionally deferred (~1 year)
//!
//! This layer is **explicitly held in a deferred state until the evidence engine
//! stabilizes — on the order of a year**. It is not on the critical path for the
//! project's current goal (a static modpack/server *evidence* engine). It is
//! registered as a [`DeferredCollector`] so the roadmap is visible in reports,
//! but it emits no facts and performs no enforcement. Do not promote it to an
//! active layer until the diagnostic layers (A–K) are stable; runtime work is a
//! research track, not a shipping feature, during this period.
//!
//! **Will emit facts (once activated):** `contract_manifest`, `declared_domain`,
//! `declared_effect`, `declared_permission`, `backend_capability`,
//! `runtime_profile`, `activation_blocker`, `semantic_plan`.
//!
//! **Donors (research-only until justified):** `SemanticBus`,
//! `IntentValidationPipeline`, `RuntimeProfileCatalog`, `SynthesisLayer`,
//! `ContractManifest`, `InterMedContractParser`, `BackendEvidenceMatrix`.

use intermed_doctor_core::{Collector, DeferredCollector, Layer};

/// Implementation status for the CLI's help output. This layer is deliberately
/// deferred until the evidence engine stabilizes (~1 year): diagnosis-oriented
/// work comes first, and the runtime is **explain-only, never enforce**.
pub const STATUS: &str =
    "deferred (~1 year, until stabilization): no facts, no enforcement — Runtime enforces, Doctor explains";

/// The (currently deferred) Layer-L collector.
pub fn collector() -> impl Collector {
    DeferredCollector::new("runtime-preflight", Layer::RuntimePreflight)
}
