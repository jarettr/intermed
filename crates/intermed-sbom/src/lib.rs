//! # intermed-sbom — Layer H (Phase 6)
//!
//! SBOM / provenance / packaging hygiene. Scans jar checksums, mod id/version,
//! known source URLs (Modrinth/CurseForge), signatures, nested libs.
//!
//! **Will emit facts:** `sbom(...)`, `trust_score(jar)`, `unknown_source(jar)`,
//! `signature_status(jar)`, `checksum(jar)`, `artifact_identity(jar)`.
//!
//! **Tier 1 (pure Rust):** checksums + metadata only — no bytecode. Donors:
//! `ModSbomGenerator`, `PackagingService` (its inspect/verify/checksum logic;
//! `.imod`/`.impack` handling, Ed25519 verification).

use intermed_doctor_core::{Collector, DeferredCollector, Layer};

/// The (currently deferred) Layer-H collector.
pub fn collector() -> impl Collector {
    DeferredCollector::new("sbom-generator", Layer::Sbom)
}
