//! # intermed-runtime-preflight — Layer L (Phase 9)
//!
//! The bridge toward the (future, optional) runtime. Doctor is designed so it
//! can later *accept* a runtime, but in the first public year this is diagnosis
//! only — **no enforcement** ("Doctor and PackOps explain. Runtime enforces.").
//!
//! **Will emit facts:** `contract_manifest`, `declared_domain`,
//! `declared_effect`, `declared_permission`, `backend_capability`,
//! `runtime_profile`, `activation_blocker`, `semantic_plan`.
//!
//! **Donors (research-only until justified):** `SemanticBus`,
//! `IntentValidationPipeline`, `RuntimeProfileCatalog`, `SynthesisLayer`,
//! `ContractManifest`, `InterMedContractParser`, `BackendEvidenceMatrix`.

use intermed_doctor_core::{Collector, DeferredCollector, Layer};

/// The (currently deferred) Layer-L collector.
pub fn collector() -> impl Collector {
    DeferredCollector::new("runtime-preflight", Layer::RuntimePreflight)
}
