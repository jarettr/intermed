//! # intermed-sbom — Layer H (Phase 6)
//!
//! SBOM / provenance / packaging hygiene. Read-only jar scanning: checksums,
//! mod identity, JAR signing status, and trust heuristics. No bytecode execution.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rayon::prelude::*;

use intermed_doctor_core::evidence::{
    CapabilityRiskClass, Category, CoverageRequirement, EvidenceEdge, EvidenceOrigin, Finding,
    FindingVisibility, FixCandidate, ProofKind, Severity, capability_risk_class,
};
use intermed_doctor_core::facts::{SourceRef, kind};
use intermed_doctor_core::jar_meta;
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, JarCache, Layer, Rule, RuleCtx, Target,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod export;

pub use export::{SbomExportFormat, export_scan};

const EXTRACTOR: &str = "sbom-generator";
/// Cache key version for this collector's payload. The crate version invalidates
/// the cache automatically on every release; bump the trailing revision when the
/// scan logic changes within a single release.
const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-r14");
const CORPUS_LOCK_SCHEMA_V1: &str = "intermed-corpus-lock-v1";
const CORPUS_LOCK_SCHEMA_V2: &str = "intermed-corpus-lock-v2";
const MATERIALIZATION_SCHEMA_V1: &str = "intermed-lab-materialization-v1";

#[derive(Debug, Default)]
struct CorpusProvenance {
    mod_ids: BTreeSet<String>,
    artifact_sha256: BTreeSet<String>,
}

impl CorpusProvenance {
    fn match_quality(&self, record: &JarSbomRecord) -> CorpusMatchQuality {
        if self.artifact_sha256.contains(&record.sha256) {
            CorpusMatchQuality::ExactArtifactPin
        } else if record
            .mod_id
            .as_ref()
            .is_some_and(|id| self.mod_ids.contains(id))
        {
            CorpusMatchQuality::KnownProjectIdentity
        } else {
            CorpusMatchQuality::None
        }
    }

    fn is_empty(&self) -> bool {
        self.mod_ids.is_empty() && self.artifact_sha256.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorpusMatchQuality {
    ExactArtifactPin,
    KnownProjectIdentity,
    #[default]
    None,
}

impl CorpusMatchQuality {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExactArtifactPin => "exact-artifact-pin",
            Self::KnownProjectIdentity => "known-project-identity",
            Self::None => "none",
        }
    }
}

/// Implementation status for help text.
pub const STATUS: &str = "active: Phase 6";

/// Layer-H collector.
pub fn collector() -> impl Collector {
    SbomCollector
}

/// Layer-H provenance rule.
pub fn rule() -> impl Rule {
    SbomProvenanceRule
}

/// Cross-layer rule: correlate unresolved provenance (Layer H) with dangerous
/// capabilities (Layer G). Either signal alone is routine; together they are the
/// supply-chain smell worth surfacing.
pub fn correlation_rule() -> impl Rule {
    SbomSecurityCorrelationRule
}

/// How well a jar's provenance could be established, as a graded classification
/// rather than a single "unknown" bool. The previous binary flag conflated a jar
/// with *no* loader manifest at all (genuinely opaque) with one that has a
/// recognized manifest but is missing an id/version (a bundled library or
/// slightly malformed metadata) — quite different supply-chain situations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceClass {
    /// Recognized manifest with mod id **and** a known distribution platform id
    /// (Modrinth / CurseForge metadata or homepage link).
    PlatformListed,
    /// A recognized loader manifest with a mod id — fully identifiable.
    Identified,
    /// A recognized loader manifest is present, but the id (and possibly version)
    /// is absent: a bundled library jar or incomplete metadata, not an opaque
    /// artifact.
    PartiallyIdentified,
    /// No recognizable Fabric/Quilt/Forge/NeoForge manifest at all.
    Unidentified,
}

impl SourceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceClass::PlatformListed => "platform-listed",
            SourceClass::Identified => "identified",
            SourceClass::PartiallyIdentified => "partially-identified",
            SourceClass::Unidentified => "unidentified",
        }
    }

    /// Classify from the parsed identity: a present `loader` means a manifest was
    /// found, a present `mod_id` means it was fully identifying, and a platform
    /// hint upgrades the grade when distribution provenance is explicit.
    fn of(identity: &JarIdentity) -> Self {
        if identity.mod_id.is_some() {
            if identity.platform.is_some() {
                SourceClass::PlatformListed
            } else {
                SourceClass::Identified
            }
        } else if identity.loader.is_some() {
            SourceClass::PartiallyIdentified
        } else {
            SourceClass::Unidentified
        }
    }
}

/// Depth of JAR signing material found under `META-INF/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureStrength {
    /// No `META-INF/*.SF` signature manifest.
    Unsigned,
    /// `.SF` present without a PKCS block (`.RSA` / `.DSA` / `.EC`).
    ManifestOnly,
    /// `.SF` plus a certificate block. This describes material presence only;
    /// it does not imply that the signature has verified.
    Certified,
}

impl SignatureStrength {
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureStrength::Unsigned => "unsigned",
            SignatureStrength::ManifestOnly => "manifest-only",
            SignatureStrength::Certified => "certified",
        }
    }
}

/// Result of cryptographically verifying the JAR signature and entry digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureVerification {
    Unsigned,
    Incomplete,
    Verified,
    Invalid,
    Unavailable,
}

impl SignatureVerification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Incomplete => "incomplete",
            Self::Verified => "verified",
            Self::Invalid => "invalid",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityStatus {
    Parsed,
    ParseFailed,
    NoRecognizableManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityOrigin {
    CanonicalLayerB,
    LocalDescriptorFallback,
    Unresolved,
}

impl IdentityOrigin {
    fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalLayerB => "canonical-layer-b",
            Self::LocalDescriptorFallback => "local-descriptor-fallback",
            Self::Unresolved => "unresolved",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityCompleteness {
    Canonical,
    DescriptorComplete,
    Partial,
    ParseFailed,
    Unresolved,
}

impl IdentityCompleteness {
    fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::DescriptorComplete => "descriptor-complete",
            Self::Partial => "partial",
            Self::ParseFailed => "parse-failed",
            Self::Unresolved => "unresolved",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DistributionProvenance {
    KnownProjectIdentity,
    PlatformDeclared,
    Unknown,
}

impl DistributionProvenance {
    fn as_str(self) -> &'static str {
        match self {
            Self::KnownProjectIdentity => "known-project-identity",
            Self::PlatformDeclared => "platform-declared",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BinaryIntegrity {
    ContentHashed,
    SignatureVerified,
    SignatureIncomplete,
    SignatureInvalid,
}

impl BinaryIntegrity {
    fn as_str(self) -> &'static str {
        match self {
            Self::ContentHashed => "content-hashed",
            Self::SignatureVerified => "signature-verified",
            Self::SignatureIncomplete => "signature-incomplete",
            Self::SignatureInvalid => "signature-invalid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExactMaterialization {
    Pinned,
    Unpinned,
}

impl ExactMaterialization {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Unpinned => "unpinned",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptographicAuthenticity {
    Unsigned,
    Unestablished,
    Unavailable,
}

impl CryptographicAuthenticity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Unestablished => "unestablished",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceAssessment {
    pub identity: IdentityCompleteness,
    pub distribution: DistributionProvenance,
    pub binary_integrity: BinaryIntegrity,
    pub exact_materialization: ExactMaterialization,
    pub cryptographic_authenticity: CryptographicAuthenticity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalArtifactIdentity {
    pub mod_id: String,
    pub version: String,
    pub loader: String,
    pub descriptor: String,
    pub ordinal: u16,
}

impl IdentityStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Parsed => "parsed",
            Self::ParseFailed => "parse-failed",
            Self::NoRecognizableManifest => "no-recognizable-manifest",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustScoreBreakdown {
    pub base: u8,
    pub mod_id: u8,
    pub version: u8,
    pub loader: u8,
    pub platform: u8,
    pub contact: u8,
    pub corpus_lock: u8,
    pub verified_signature: u8,
}

impl TrustScoreBreakdown {
    fn total(&self) -> u8 {
        self.base
            .saturating_add(self.mod_id)
            .saturating_add(self.version)
            .saturating_add(self.loader)
            .saturating_add(self.platform)
            .saturating_add(self.contact)
            .saturating_add(self.corpus_lock)
            .saturating_add(self.verified_signature)
            .min(100)
    }
}

/// Known third-party distribution platform referenced by jar metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DistributionPlatform {
    Modrinth,
    CurseForge,
}

/// One jar's provenance record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JarSbomRecord {
    /// Stable content identity. This is the primary cross-layer join key.
    #[serde(default)]
    pub artifact_id: String,
    /// Exact physical locator in the analyzed target; never an identity key.
    #[serde(default)]
    pub source_locator: String,
    /// Display-only basename retained for human-facing output compatibility.
    pub archive: String,
    pub mod_id: Option<String>,
    pub version: Option<String>,
    pub loader: Option<String>,
    pub sha256: String,
    pub signed: bool,
    pub signature_strength: SignatureStrength,
    pub signature_verification: SignatureVerification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_detail: Option<String>,
    /// Modrinth / CurseForge hint when declared in manifest metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<DistributionPlatform>,
    /// Backward-compatible summary: true for either a known project identity or
    /// an exact materialized binary pin. Consult `corpus_match` for reasoning.
    #[serde(default)]
    pub in_corpus_lock: bool,
    #[serde(default)]
    pub corpus_match: CorpusMatchQuality,
    /// Derived display score in `0..=100`, not a safety verdict or a policy
    /// input. Rules consume the typed `provenance` axes instead.
    pub trust_score: u8,
    pub trust_breakdown: TrustScoreBreakdown,
    pub identity_status: IdentityStatus,
    pub identity_origin: IdentityOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_detail: Option<String>,
    /// Graded provenance classification (replaces the old `unknown_source` bool).
    #[serde(default = "default_source_class")]
    pub source_class: SourceClass,
    pub provenance: ProvenanceAssessment,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub canonical_identities: Vec<CanonicalArtifactIdentity>,
}

fn default_source_class() -> SourceClass {
    SourceClass::Unidentified
}

impl JarSbomRecord {
    /// True only when *no* loader manifest was found (the strict "unknown" case
    /// that still warrants a provenance finding).
    #[must_use]
    pub fn is_unidentified(&self) -> bool {
        self.source_class == SourceClass::Unidentified
    }
}

/// Tolerated scan failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomScanFailure {
    pub archive: String,
    pub reason: String,
}

/// Result of an SBOM scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomScan {
    pub target: String,
    pub records: Vec<JarSbomRecord>,
    pub failures: Vec<SbomScanFailure>,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SbomScanError(String);

// ── Collector ─────────────────────────────────────────────────────────────

struct SbomCollector;

impl Collector for SbomCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }

    fn layer(&self) -> Layer {
        Layer::Sbom
    }

    fn scope(&self) -> intermed_doctor_core::CollectorScope {
        intermed_doctor_core::CollectorScope::new(
            intermed_doctor_core::CompletenessModel::PerArtifact,
        )
        .produces([
            kind::CHECKSUM,
            kind::SIGNATURE_STATUS,
            kind::TRUST_SCORE,
            kind::ARTIFACT_IDENTITY,
            kind::UNKNOWN_SOURCE,
            kind::SBOM,
            kind::UNPARSEABLE_ARCHIVE,
        ])
        .consumes([kind::ARTIFACT_ROLE])
        .regions([intermed_doctor_core::TargetRegion::Artifacts])
    }

    fn applies(&self, target: &Target) -> bool {
        !target.artifact_roots().is_empty()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let instance_root = ctx
            .target
            .game_root
            .as_deref()
            .or_else(|| ctx.target.mods_dir.as_deref().and_then(Path::parent))
            .or_else(|| ctx.target.path.parent());
        let corpus_provenance = load_corpus_provenance(instance_root);
        match scan_target_inner(
            ctx.target,
            ctx.jar_cache,
            &ctx.settings.scan,
            &ctx.settings.sbom,
            corpus_provenance.as_ref(),
        ) {
            Ok(mut scan) => {
                apply_canonical_metadata_identities(
                    &mut scan,
                    ctx.inputs,
                    corpus_provenance.as_ref(),
                );
                let emitted = emit_scan(ctx, &scan);
                let outcome = if scan.failures.is_empty() {
                    CollectorOutcome::active
                } else {
                    CollectorOutcome::incomplete
                };
                outcome(
                    emitted,
                    format!(
                        "{} artifact(s), {} scan failure(s)",
                        scan.records.len(),
                        scan.failures.len()
                    ),
                )
            }
            Err(e) => CollectorOutcome::failed(e.to_string()),
        }
    }
}

fn apply_canonical_metadata_identities(
    scan: &mut SbomScan,
    facts: &dyn intermed_doctor_core::facts::FactRead,
    corpus_provenance: Option<&CorpusProvenance>,
) {
    let mut identities: BTreeMap<String, Vec<CanonicalArtifactIdentity>> = BTreeMap::new();
    for fact in facts.by_kind(kind::ARTIFACT_ROLE) {
        if fact.attr("identity_certainty") != Some("confirmed")
            || !matches!(
                fact.attr("activation"),
                Some("active" | "self-loader-bootstrap")
            )
        {
            continue;
        }
        let (Some(mod_id), Some(version), Some(loader), Some(descriptor)) = (
            fact.attr("declared_id"),
            fact.attr("version"),
            fact.attr("loader"),
            fact.attr("descriptor"),
        ) else {
            continue;
        };
        identities
            .entry(normalize_locator(&fact.subject))
            .or_default()
            .push(CanonicalArtifactIdentity {
                mod_id: mod_id.to_string(),
                version: version.to_string(),
                loader: loader.to_string(),
                descriptor: descriptor.to_string(),
                ordinal: fact
                    .attr_int("ordinal")
                    .and_then(|value| u16::try_from(value).ok())
                    .unwrap_or(0),
            });
    }
    for record in &mut scan.records {
        let Some(canonical) = identities.get(&normalize_locator(&record.source_locator)) else {
            continue;
        };
        let mut canonical = canonical.clone();
        canonical.sort_by(|left, right| {
            left.ordinal
                .cmp(&right.ordinal)
                .then_with(|| left.descriptor.cmp(&right.descriptor))
                .then_with(|| left.mod_id.cmp(&right.mod_id))
        });
        canonical.dedup();
        if let Some(primary) = canonical.first() {
            let local_identity_agrees = record.identity_status == IdentityStatus::Parsed
                && record.mod_id.as_deref() == Some(primary.mod_id.as_str());
            let fallback_problem = (record.identity_status != IdentityStatus::Parsed).then(|| {
                let status = record.identity_status.as_str();
                record.identity_detail.as_ref().map_or_else(
                    || format!("local fallback status was {status}"),
                    |detail| format!("local fallback status was {status}: {detail}"),
                )
            });
            record.mod_id = Some(primary.mod_id.clone());
            record.version = Some(primary.version.clone());
            record.loader = Some(primary.loader.clone());
            if !local_identity_agrees {
                // Platform/contact fields extracted from a different or broken
                // descriptor are not provenance for the canonical mod role.
                record.platform = None;
                record.trust_breakdown.contact = 0;
            }
            record.identity_status = IdentityStatus::Parsed;
            record.identity_origin = IdentityOrigin::CanonicalLayerB;
            record.identity_detail = Some(match fallback_problem {
                Some(problem) => {
                    format!("identity established by canonical Layer B artifact role; {problem}")
                }
                None => "identity established by canonical Layer B artifact role".to_string(),
            });
            record.source_class = if record.platform.is_some() {
                SourceClass::PlatformListed
            } else {
                SourceClass::Identified
            };
            record.canonical_identities = canonical;
            if let Some(provenance) = corpus_provenance {
                record.corpus_match = provenance.match_quality(record);
                record.in_corpus_lock = record.corpus_match != CorpusMatchQuality::None;
            }
            recompute_provenance(record);
        }
    }
}

fn normalize_locator(locator: &str) -> String {
    locator.replace('\\', "/")
}

fn emit_scan(ctx: &mut CollectCtx<'_>, scan: &SbomScan) -> usize {
    let mut emitted = 0usize;
    for r in &scan.records {
        let report_locator =
            intermed_doctor_core::portable_artifact_locator(&r.source_locator, &r.archive);
        ctx.store
            .fact(EXTRACTOR, kind::CHECKSUM)
            .subject(r.artifact_id.clone())
            .attr("algorithm", "sha256")
            .attr("hex", r.sha256.clone())
            .attr("archive", r.archive.clone())
            .attr("source_locator", r.source_locator.clone())
            .source(SourceRef::file(report_locator.clone()))
            .emit();
        emitted += 1;

        ctx.store
            .fact(EXTRACTOR, kind::SIGNATURE_STATUS)
            .subject(r.artifact_id.clone())
            .attr("status", r.signature_verification.as_str())
            .attr("material", r.signature_strength.as_str())
            .attr("jar_signed", r.signed)
            .attr("archive", r.archive.clone())
            .attr("source_locator", r.source_locator.clone())
            .source(SourceRef::file(report_locator.clone()))
            .emit();
        emitted += 1;

        ctx.store
            .fact(EXTRACTOR, kind::TRUST_SCORE)
            .subject(r.artifact_id.clone())
            .attr("score", r.trust_score as i64)
            .attr("archive", r.archive.clone())
            .attr("source_locator", r.source_locator.clone())
            .source(SourceRef::file(report_locator.clone()))
            .emit();
        emitted += 1;

        if let (Some(mod_id), Some(version)) = (&r.mod_id, &r.version) {
            ctx.store
                .fact(EXTRACTOR, kind::ARTIFACT_IDENTITY)
                .subject(r.artifact_id.clone())
                .attr("mod_id", mod_id.clone())
                .attr("version", version.clone())
                .attr("archive", r.archive.clone())
                .attr("source_locator", r.source_locator.clone())
                .attr("sha256", r.sha256.clone())
                .attr("identity_origin", r.identity_origin.as_str())
                .source(SourceRef::file(report_locator.clone()))
                .emit();
            emitted += 1;
        }

        // Only a *fully* unidentified jar warrants the provenance warning; a
        // partially-identified one (manifest present, id missing) is recorded on
        // the SBOM fact below but does not raise a finding.
        if r.identity_status == IdentityStatus::NoRecognizableManifest {
            ctx.store
                .fact(EXTRACTOR, kind::UNKNOWN_SOURCE)
                .subject(r.artifact_id.clone())
                .attr("reason", "no recognizable mod manifest")
                .attr("archive", r.archive.clone())
                .attr("source_locator", r.source_locator.clone())
                .source(SourceRef::file(report_locator.clone()))
                .emit();
            emitted += 1;
        }

        let loader = r.loader.as_deref().unwrap_or("unknown");
        let mod_id = r.mod_id.as_deref().unwrap_or("unknown");
        let version = r.version.as_deref().unwrap_or("unknown");
        let mut sbom = ctx
            .store
            .fact(EXTRACTOR, kind::SBOM)
            .subject(r.artifact_id.clone())
            .attr("artifact_id", r.artifact_id.clone())
            .attr("archive", r.archive.clone())
            .attr("source_locator", r.source_locator.clone())
            .attr("mod_id", mod_id)
            .attr("version", version)
            .attr("loader", loader)
            .attr("sha256", r.sha256.clone())
            .attr("signed", r.signed)
            .attr("signature_strength", r.signature_strength.as_str())
            .attr("signature_verification", r.signature_verification.as_str())
            .attr("source_class", r.source_class.as_str())
            .attr("trust_score", r.trust_score as i64)
            .attr("identity_status", r.identity_status.as_str())
            .attr("identity_origin", r.identity_origin.as_str())
            .attr("corpus_match", r.corpus_match.as_str())
            .attr("identity_completeness", r.provenance.identity.as_str())
            .attr(
                "distribution_provenance",
                r.provenance.distribution.as_str(),
            )
            .attr("binary_integrity", r.provenance.binary_integrity.as_str())
            .attr(
                "exact_materialization",
                r.provenance.exact_materialization.as_str(),
            )
            .attr(
                "cryptographic_authenticity",
                r.provenance.cryptographic_authenticity.as_str(),
            )
            .attr(
                "provenance_correlation_eligible",
                provenance_is_weak(&r.provenance),
            )
            .attr("trust_base", r.trust_breakdown.base as i64)
            .attr("trust_mod_id", r.trust_breakdown.mod_id as i64)
            .attr("trust_version", r.trust_breakdown.version as i64)
            .attr("trust_loader", r.trust_breakdown.loader as i64)
            .attr("trust_platform", r.trust_breakdown.platform as i64)
            .attr("trust_contact", r.trust_breakdown.contact as i64)
            .attr("trust_corpus_lock", r.trust_breakdown.corpus_lock as i64)
            .attr(
                "trust_verified_signature",
                r.trust_breakdown.verified_signature as i64,
            )
            .attr("in_corpus_lock", r.in_corpus_lock)
            .source(SourceRef::file(report_locator));
        if let Some(detail) = &r.identity_detail {
            sbom = sbom.attr("identity_detail", detail.clone());
        }
        if let Some(detail) = &r.signature_detail {
            sbom = sbom.attr("signature_detail", detail.clone());
        }
        if let Some(platform) = &r.platform {
            sbom = sbom.attr(
                "platform",
                match platform {
                    DistributionPlatform::Modrinth => "modrinth",
                    DistributionPlatform::CurseForge => "curseforge",
                },
            );
        }
        sbom.emit();
        emitted += 1;
    }

    for failure in &scan.failures {
        ctx.store
            .fact(EXTRACTOR, kind::UNPARSEABLE_ARCHIVE)
            .subject(failure.archive.clone())
            .attr("reason", failure.reason.clone())
            .source(SourceRef::file(failure.archive.clone()))
            .confidence(0.9)
            .emit();
        emitted += 1;
    }
    emitted
}

// ── Rule ─────────────────────────────────────────────────────────────────

struct SbomProvenanceRule;

impl Rule for SbomProvenanceRule {
    fn id(&self) -> &'static str {
        "sbom-provenance"
    }

    fn requirements(&self) -> intermed_doctor_core::RuleRequirements {
        intermed_doctor_core::RuleRequirements::default()
            .facts([kind::SBOM])
            .optional_facts([kind::UNKNOWN_SOURCE, kind::SIGNATURE_STATUS])
            .layers([Layer::Sbom])
            .regions([intermed_doctor_core::TargetRegion::Artifacts])
            .coverage([CoverageRequirement::LocalArtifact])
            .proofs([ProofKind::Observation, ProofKind::DeterministicDerivation])
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        let mut out = Vec::new();
        for f in ctx.store.by_kind(kind::UNKNOWN_SOURCE) {
            let artifact_id = f.subject.as_str();
            let archive = f.attr("archive").unwrap_or(artifact_id);
            out.push(
                Finding::builder(self.id(), format!("unknown-source:{artifact_id}"))
                    .severity(Severity::Note)
                    .category(Category::Metadata)
                    .proof_kind(ProofKind::Observation)
                    .coverage_requirement(CoverageRequirement::LocalArtifact)
                    .evidence_origin(EvidenceOrigin::StaticExact)
                    .title(format!(
                        "Artifact identity could not be established: {archive}"
                    ))
                    .explanation(
                        "This jar has no recognizable modern or legacy loader descriptor. \
                         Its mod identity could not be established from packaging metadata; \
                         this is a packaging/provenance limitation, not evidence that the \
                         artifact is unsafe.",
                    )
                    .evidence(EvidenceEdge::subject(f.id))
                    .affects(artifact_id)
                    .fix(FixCandidate::advice(
                        "Prefer mods from Modrinth or CurseForge with verifiable metadata.",
                    ))
                    .tag("sbom")
                    .tag("provenance")
                    .build(),
            );
        }

        for f in ctx.store.by_kind(kind::SIGNATURE_STATUS) {
            let status = f.attr("status").unwrap_or("unavailable");
            if status == "verified" {
                continue;
            }
            let artifact_id = f.subject.as_str();
            let archive = f.attr("archive").unwrap_or(artifact_id);
            let (severity, title, explanation) = match status {
                "unsigned" => (
                    Severity::Note,
                    format!("Jar is not JAR-signed: {archive}"),
                    "No META-INF/*.SF signature manifest was found. Most Fabric/Forge mods ship \
                     unsigned; this is informational only."
                        .to_string(),
                ),
                "incomplete" => (
                    Severity::Warn,
                    format!("Incomplete JAR signature material: {archive}"),
                    "A signature manifest exists without a matching PKCS signature block; no \
                     cryptographic trust is assigned."
                        .to_string(),
                ),
                "invalid" => (
                    Severity::Warn,
                    format!("JAR signature verification failed: {archive}"),
                    "The JDK verifier rejected the signature or a signed entry digest; the JAR is \
                     not treated as signed."
                        .to_string(),
                ),
                _ => (
                    Severity::Note,
                    format!("JAR signature could not be verified: {archive}"),
                    "Signature material exists, but a cryptographic verifier was unavailable; no \
                     trust points are assigned."
                        .to_string(),
                ),
            };
            out.push({
                let visibility = if status == "unsigned" {
                    FindingVisibility::ExplainOnly
                } else {
                    FindingVisibility::Default
                };
                Finding::builder(
                    self.id(),
                    format!("artifact-signature-status:{status}:{artifact_id}"),
                )
                .severity(severity)
                .category(Category::Security)
                .visibility(visibility)
                .proof_kind(ProofKind::Observation)
                .coverage_requirement(CoverageRequirement::LocalArtifact)
                .evidence_origin(EvidenceOrigin::StaticExact)
                .confidence(0.95)
                .title(title)
                .explanation(explanation)
                .evidence(EvidenceEdge::subject(f.id))
                .affects(artifact_id)
                .fix(FixCandidate::advice(
                    "Verify mod source manually if supply-chain trust matters.",
                ))
                .tag("sbom")
                .tag("signature")
                .build()
            });
        }
        Ok(out)
    }
}

// ── Cross-layer correlation rule ───────────────────────────────────────────

struct SbomSecurityCorrelationRule;

struct SbomTrustEvidence {
    score: i64,
    identity_status: String,
    identity_completeness: Option<String>,
    distribution_provenance: Option<String>,
    exact_materialization: Option<String>,
    correlation_eligible: Option<bool>,
    archive: String,
    decomposition: String,
    evidence: intermed_doctor_core::facts::FactId,
}

impl SbomTrustEvidence {
    fn is_weak(&self, legacy_score_threshold: i64) -> bool {
        if let Some(eligible) = self.correlation_eligible {
            return eligible;
        }
        let Some(identity) = self.identity_completeness.as_deref() else {
            return self.score < legacy_score_threshold;
        };
        let identity_unresolved = matches!(identity, "partial" | "parse-failed" | "unresolved");
        let distribution_unknown = self.distribution_provenance.as_deref() == Some("unknown");
        let materialization_unpinned = self.exact_materialization.as_deref() != Some("pinned");
        identity_unresolved && distribution_unknown && materialization_unpinned
    }
}

/// Capability labels are presentation only; risk is assigned by the shared
/// `CapabilityRiskClass` policy used by both G and H.
const SECURITY_CAPABILITIES: &[(&str, &str)] = &[
    (kind::USES_PROCESS_SPAWN, "process spawn"),
    (kind::USES_UNSAFE, "sun.misc.Unsafe"),
    (
        kind::USES_DYNAMIC_CLASS_DEFINITION,
        "dynamic class definition",
    ),
    (kind::USES_SCRIPT_ENGINE, "script engine eval"),
];

impl Rule for SbomSecurityCorrelationRule {
    fn id(&self) -> &'static str {
        "sbom-security-correlation"
    }

    fn requirements(&self) -> intermed_doctor_core::RuleRequirements {
        intermed_doctor_core::RuleRequirements::default()
            .facts([kind::SBOM])
            .optional_facts(SECURITY_CAPABILITIES.iter().map(|(kind, _)| *kind))
            .layers([Layer::Sbom, Layer::Security])
            .regions([intermed_doctor_core::TargetRegion::Artifacts])
            .coverage([CoverageRequirement::LocalArtifact])
            .proofs([ProofKind::DeterministicDerivation])
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, intermed_doctor_core::RuleError> {
        use std::collections::BTreeMap;

        // ArtifactId -> score, identity status, display locator, decomposition,
        // and SBOM evidence.
        let mut trust_by_artifact: BTreeMap<String, SbomTrustEvidence> = BTreeMap::new();
        for f in ctx.store.by_kind(kind::SBOM) {
            if let Some(score) = f.attr_int("trust_score") {
                let components = [
                    ("base", f.attr_int("trust_base")),
                    ("mod id", f.attr_int("trust_mod_id")),
                    ("version", f.attr_int("trust_version")),
                    ("loader", f.attr_int("trust_loader")),
                    ("platform", f.attr_int("trust_platform")),
                    ("contact", f.attr_int("trust_contact")),
                    ("corpus lock", f.attr_int("trust_corpus_lock")),
                    ("verified signature", f.attr_int("trust_verified_signature")),
                ]
                .into_iter()
                .filter_map(|(label, value)| value.map(|value| format!("{label} +{value}")))
                .collect::<Vec<_>>()
                .join(", ");
                trust_by_artifact.insert(
                    f.subject.to_string(),
                    SbomTrustEvidence {
                        score,
                        identity_status: f.attr("identity_status").unwrap_or("unknown").to_string(),
                        identity_completeness: f.attr("identity_completeness").map(str::to_string),
                        distribution_provenance: f
                            .attr("distribution_provenance")
                            .map(str::to_string),
                        exact_materialization: f.attr("exact_materialization").map(str::to_string),
                        correlation_eligible: f.attr_bool("provenance_correlation_eligible"),
                        archive: f.attr("archive").unwrap_or(f.subject.as_str()).to_string(),
                        decomposition: components,
                        evidence: f.id,
                    },
                );
            }
        }

        // ArtifactId -> (sorted capability labels, one evidence fact id).
        let mut risky: BTreeMap<String, (Vec<&str>, intermed_doctor_core::facts::FactId)> =
            BTreeMap::new();
        for (fact_kind, label) in SECURITY_CAPABILITIES {
            if capability_risk_class(fact_kind) != Some(CapabilityRiskClass::High) {
                continue;
            }
            for f in ctx.store.by_kind(fact_kind) {
                let Some(artifact_id) = f.attr("artifact_id") else {
                    continue;
                };
                let entry = risky
                    .entry(artifact_id.to_string())
                    .or_insert_with(|| (Vec::new(), f.id));
                entry.0.push(label);
            }
        }

        let mut out = Vec::new();
        for (artifact_id, (mut labels, evidence)) in risky {
            // Only correlate when provenance is weak: a well-identified jar with
            // a dangerous capability is already covered by the security rule.
            let Some(trust_evidence) = trust_by_artifact.get(artifact_id.as_str()) else {
                // A capability without the matching ArtifactId-level SBOM record
                // has no provenance assessment to correlate. Missing evidence is
                // not equivalent to low provenance.
                continue;
            };
            if !trust_evidence.is_weak(ctx.settings.sbom.well_identified_trust) {
                continue;
            }
            let trust = trust_evidence.score;
            let identity_status = trust_evidence.identity_status.as_str();
            let archive = trust_evidence.archive.as_str();
            let decomposition = trust_evidence.decomposition.as_str();
            let sbom_evidence = trust_evidence.evidence;
            labels.sort_unstable();
            labels.dedup();

            let parse_failed = identity_status == "parse-failed";
            let mut builder = Finding::builder(
                self.id(),
                format!("low-trust-capability:{artifact_id}"),
            )
                    .severity(if parse_failed { Severity::Note } else { Severity::Warn })
                    .confidence(if parse_failed { 0.45 } else { 0.8 })
                    .category(Category::Security)
                    .proof_kind(ProofKind::DeterministicDerivation)
                    .coverage_requirement(CoverageRequirement::LocalArtifact)
                    .evidence_origin(EvidenceOrigin::StaticExact)
                    .title(if parse_failed {
                        format!("Identity analysis incomplete for high-risk jar `{archive}`")
                    } else {
                        format!("Unresolved artifact provenance with high-risk capability: `{archive}`")
                    })
                    .explanation(format!(
                        "`{archive}` has identity status `{identity_status}` and trust score \
                         {trust}/100 (components: {decomposition}), below {}. It statically \
                         references: {}. {}",
                        ctx.settings.sbom.well_identified_trust,
                        labels.join(", "),
                        if parse_failed {
                            "Because the low score comes from an identity parse failure, it is not \
                             treated as independent evidence of suspicious provenance."
                        } else {
                            "Unresolved distribution provenance combined with a dangerous \
                             capability warrants source verification, but is not a malware verdict."
                        }
                    ))
                    .evidence(EvidenceEdge::subject(evidence))
                    .affects(&artifact_id)
                    .fix(FixCandidate::advice(
                        "Establish the mod's provenance (known project or exact binary pin) before \
                         trusting a jar that spawns processes, defines classes, or evaluates scripts; \
                         signature integrity alone does not identify the signer.",
                    ))
                    .tag("sbom")
                    .tag("security")
                    .tag("supply-chain");
            builder = builder.evidence(EvidenceEdge::supports(sbom_evidence));
            if parse_failed {
                builder = builder.tag("identity-analysis-incomplete");
            }
            out.push(builder.build());
        }
        Ok(out)
    }
}

// ── Scanner ──────────────────────────────────────────────────────────────

pub fn scan_target(target: &Target) -> Result<SbomScan, SbomScanError> {
    let provenance_root = target
        .game_root
        .as_deref()
        .or_else(|| target.mods_dir.as_deref().and_then(Path::parent))
        .or_else(|| target.path.parent());
    let corpus_provenance = load_corpus_provenance(provenance_root);
    scan_target_inner(
        target,
        None,
        &intermed_doctor_core::ScanSettings::default(),
        &intermed_doctor_core::SbomSettings::default(),
        corpus_provenance.as_ref(),
    )
}

fn scan_target_inner(
    target: &Target,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
    sbom: &intermed_doctor_core::SbomSettings,
    corpus_provenance: Option<&CorpusProvenance>,
) -> Result<SbomScan, SbomScanError> {
    let roots = target.artifact_roots();
    if roots.is_empty() {
        return Err(SbomScanError("target has no artifact roots".into()));
    }
    let mut jars = Vec::new();
    for root in roots {
        let mut root_jars = intermed_doctor_core::list_jar_archives(&root.path, scan)
            .map_err(|e| SbomScanError(format!("read {}: {e}", root.path.display())))?;
        jars.append(&mut root_jars);
    }
    jars.sort();
    jars.dedup();
    scan_jars(
        &jars,
        cache,
        sbom,
        corpus_provenance,
        &target.path.display().to_string(),
    )
}

pub fn scan_mods_dir(dir: &Path) -> Result<SbomScan, SbomScanError> {
    scan_mods_dir_with_cache(dir, None)
}

pub fn scan_mods_dir_with_cache(
    dir: &Path,
    cache: Option<&JarCache>,
) -> Result<SbomScan, SbomScanError> {
    let corpus_provenance = load_corpus_provenance(dir.parent());
    scan_mods_dir_inner(
        dir,
        cache,
        &intermed_doctor_core::ScanSettings::default(),
        &intermed_doctor_core::SbomSettings::default(),
        corpus_provenance.as_ref(),
    )
}

/// Like [`scan_mods_dir_with_cache`] but honors incremental [`ScanSettings`].
pub fn scan_mods_dir_filtered(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
) -> Result<SbomScan, SbomScanError> {
    let corpus_provenance = load_corpus_provenance(dir.parent());
    scan_mods_dir_inner(
        dir,
        cache,
        scan,
        &intermed_doctor_core::SbomSettings::default(),
        corpus_provenance.as_ref(),
    )
}

fn scan_mods_dir_inner(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
    sbom: &intermed_doctor_core::SbomSettings,
    corpus_provenance: Option<&CorpusProvenance>,
) -> Result<SbomScan, SbomScanError> {
    if !dir.is_dir() {
        return Err(SbomScanError(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }

    let jars = intermed_doctor_core::list_jar_archives(dir, scan)
        .map_err(|e| SbomScanError(format!("read {}: {e}", dir.display())))?;

    scan_jars(
        &jars,
        cache,
        sbom,
        corpus_provenance,
        &dir.display().to_string(),
    )
}

fn scan_jars(
    jars: &[PathBuf],
    cache: Option<&JarCache>,
    sbom: &intermed_doctor_core::SbomSettings,
    corpus_provenance: Option<&CorpusProvenance>,
    target_label: &str,
) -> Result<SbomScan, SbomScanError> {
    // Independent per-jar hashing + manifest parsing; fan out across cores.
    // `par_iter().map()` preserves order for deterministic aggregation.
    let timeout = Duration::from_secs(sbom.signature_verify_timeout_secs.max(1));
    let cache_version = format!("{CACHE_VERSION}-signature-timeout-{}s", timeout.as_secs());
    let scanned: Vec<(String, String, CachedSbomJar)> = jars
        .par_iter()
        .map(|jar| {
            let archive = file_name_of(jar);
            let source_locator = normalize_locator(&jar.display().to_string());
            let cached = match cache {
                Some(c) => c.get_or_scan(EXTRACTOR, &cache_version, jar, || {
                    scan_jar_cached(jar, timeout)
                }),
                None => scan_jar_cached(jar, timeout),
            };
            (archive, source_locator, cached)
        })
        .collect();

    let mut records = Vec::new();
    let mut failures = Vec::new();
    for (archive, source_locator, cached) in scanned {
        match cached {
            CachedSbomJar::Ok(record) => {
                let mut record = *record;
                // The payload is shared by content hash; the locator is specific
                // to the current pack and must not leak from the first cache fill.
                record.archive = archive;
                record.source_locator = source_locator;
                record.corpus_match = corpus_provenance
                    .map(|provenance| provenance.match_quality(&record))
                    .unwrap_or_default();
                record.in_corpus_lock = record.corpus_match != CorpusMatchQuality::None;
                recompute_provenance(&mut record);
                records.push(record);
            }
            CachedSbomJar::Err(reason) => failures.push(SbomScanFailure { archive, reason }),
        }
    }

    Ok(SbomScan {
        target: target_label.to_string(),
        records,
        failures,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CachedSbomJar {
    Ok(Box<JarSbomRecord>),
    Err(String),
}

fn scan_jar_cached(jar: &Path, timeout: Duration) -> CachedSbomJar {
    match scan_jar(jar, timeout) {
        Ok(record) => CachedSbomJar::Ok(Box::new(record)),
        Err(e) => CachedSbomJar::Err(e.to_string()),
    }
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string()
}

fn scan_jar(jar: &Path, signature_timeout: Duration) -> Result<JarSbomRecord, SbomScanError> {
    let archive = file_name_of(jar);

    let sha256 = sha256_file(jar)?;
    let file = std::fs::File::open(jar)
        .map_err(|e| SbomScanError(format!("open {}: {e}", jar.display())))?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| SbomScanError(format!("zip {}: {e}", jar.display())))?;

    let identity_detection = detect_identity(&mut zip);
    let identity = identity_detection.identity;
    let signature_strength = jar_signature_strength(&mut zip);
    let (signature_verification, signature_detail) =
        verify_jar_signature(jar, signature_strength, signature_timeout);
    let signed = signature_verification == SignatureVerification::Verified;
    // Corpus/materialization provenance is pack-specific and therefore applied
    // after the content-addressed cache lookup in `scan_mods_dir_inner`.
    let in_corpus_lock = false;
    let corpus_match = CorpusMatchQuality::None;
    let source_class = SourceClass::of(&identity);
    let trust_breakdown =
        compute_trust_score(&identity, signature_verification, CorpusMatchQuality::None);
    let trust_score = trust_breakdown.total();

    let identity_status = identity_detection.status;
    let identity_origin = if identity_status == IdentityStatus::Parsed {
        IdentityOrigin::LocalDescriptorFallback
    } else {
        IdentityOrigin::Unresolved
    };
    let artifact_id = intermed_doctor_core::evidence::ArtifactId::from_sha256(&sha256)
        .expect("sha256_file always returns a 64-character hexadecimal digest")
        .to_string();
    let provenance = provenance_assessment(
        identity_status,
        identity_origin,
        source_class,
        corpus_match,
        signature_verification,
    );

    Ok(JarSbomRecord {
        artifact_id,
        source_locator: normalize_locator(&jar.display().to_string()),
        archive,
        mod_id: identity.mod_id,
        version: identity.version,
        loader: identity.loader,
        sha256,
        signed,
        signature_strength,
        signature_verification,
        signature_detail,
        platform: identity.platform,
        in_corpus_lock,
        corpus_match,
        trust_score,
        trust_breakdown,
        identity_status,
        identity_origin,
        identity_detail: identity_detection.detail,
        source_class,
        provenance,
        canonical_identities: Vec::new(),
    })
}

#[derive(Debug, Clone, Default)]
struct JarIdentity {
    mod_id: Option<String>,
    version: Option<String>,
    loader: Option<String>,
    platform: Option<DistributionPlatform>,
    has_contact: bool,
}

struct IdentityDetection {
    identity: JarIdentity,
    status: IdentityStatus,
    detail: Option<String>,
}

impl IdentityDetection {
    fn parsed(identity: JarIdentity) -> Self {
        Self {
            identity,
            status: IdentityStatus::Parsed,
            detail: None,
        }
    }

    fn parsed_nested(identity: JarIdentity, path: String) -> Self {
        Self {
            identity,
            status: IdentityStatus::Parsed,
            detail: Some(format!(
                "identity established by authoritative descriptor in nested artifact {path}"
            )),
        }
    }

    fn parsed_nested_container(nested: &[(String, JarIdentity)]) -> Self {
        let mut members = nested
            .iter()
            .filter_map(|(path, identity)| {
                identity
                    .mod_id
                    .as_deref()
                    .map(|id| format!("{id} at {path}"))
            })
            .collect::<Vec<_>>();
        members.sort();
        Self {
            identity: JarIdentity {
                loader: Some("jarjar".to_string()),
                ..JarIdentity::default()
            },
            status: IdentityStatus::Parsed,
            detail: Some(format!(
                "descriptorless container has multiple authoritative nested identities: {}",
                members.join(", ")
            )),
        }
    }

    fn parsed_service_container(identity: JarIdentity, detail: String) -> Self {
        Self {
            identity,
            status: IdentityStatus::Parsed,
            detail: Some(detail),
        }
    }
}

/// Extract the primary mod identity from Forge/NeoForge `mods.toml` (`[[mods]]`).
fn forge_identity_from_toml(v: &toml::Value, loader: &str) -> Option<JarIdentity> {
    let entry = v.get("mods").and_then(|m| m.as_array())?.first()?;
    Some(JarIdentity {
        mod_id: entry
            .get("modId")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        version: entry
            .get("version")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        loader: Some(loader.to_string()),
        platform: None,
        has_contact: false,
    })
}

fn detect_identity(archive: &mut zip::ZipArchive<std::fs::File>) -> IdentityDetection {
    detect_identity_bounded(archive, 2)
}

fn detect_identity_bounded<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    nested_depth: u8,
) -> IdentityDetection {
    let mut parse_failure = None;
    if let Some(text) = read_zip_text(archive, "fabric.mod.json") {
        match intermed_doctor_core::fabric_json::parse_value(&text) {
            Ok(v) => return IdentityDetection::parsed(json_loader_identity(&v, "fabric")),
            Err(error) => parse_failure = Some(format!("fabric.mod.json: {error}")),
        }
    }
    if let Some(text) = read_zip_text(archive, "quilt.mod.json") {
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) => return IdentityDetection::parsed(json_loader_identity(&v, "quilt")),
            Err(error) => {
                parse_failure.get_or_insert_with(|| format!("quilt.mod.json: {error}"));
            }
        }
    }
    if let Some(text) = read_zip_text(archive, "META-INF/mods.toml") {
        if let Ok(v) = toml::from_str::<toml::Value>(&text) {
            if let Some(mut identity) = forge_identity_from_toml(&v, "forge") {
                resolve_jar_version_placeholder(archive, &mut identity);
                return IdentityDetection::parsed(identity);
            }
        } else if let Err(error) = toml::from_str::<toml::Value>(&text) {
            parse_failure.get_or_insert_with(|| format!("META-INF/mods.toml: {error}"));
        }
    }
    if let Some(text) = read_zip_text(archive, "mcmod.info") {
        match intermed_doctor_core::legacy_forge::parse_mcmod_info(&text) {
            Ok(mods) if !mods.is_empty() => {
                let first = &mods[0];
                return IdentityDetection::parsed(JarIdentity {
                    mod_id: Some(first.mod_id.clone()),
                    version: first.version.clone(),
                    loader: Some("forge".to_string()),
                    platform: None,
                    has_contact: false,
                });
            }
            Ok(_) => {
                parse_failure.get_or_insert_with(|| "mcmod.info: no mod entries".to_string());
            }
            Err(error) => {
                parse_failure.get_or_insert_with(|| format!("mcmod.info: {error}"));
            }
        }
    }
    if let Some(text) = read_zip_text(archive, "plugin.yml") {
        if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
            return IdentityDetection::parsed(JarIdentity {
                mod_id: v.get("name").and_then(|x| x.as_str()).map(str::to_string),
                version: v
                    .get("version")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                loader: Some("bukkit".into()),
                platform: None,
                has_contact: false,
            });
        } else if let Err(error) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
            parse_failure.get_or_insert_with(|| format!("plugin.yml: {error}"));
        }
    }
    if let Some(text) = read_zip_text(archive, "paper-plugin.yml") {
        if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
            return IdentityDetection::parsed(JarIdentity {
                mod_id: v.get("name").and_then(|x| x.as_str()).map(str::to_string),
                version: v
                    .get("version")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                loader: Some("paper".into()),
                platform: None,
                has_contact: false,
            });
        } else if let Err(error) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
            parse_failure.get_or_insert_with(|| format!("paper-plugin.yml: {error}"));
        }
    }
    if let Some(text) = read_zip_text(archive, "META-INF/neoforge.mods.toml") {
        if let Ok(v) = toml::from_str::<toml::Value>(&text) {
            if let Some(mut identity) = forge_identity_from_toml(&v, "neoforge") {
                resolve_jar_version_placeholder(archive, &mut identity);
                return IdentityDetection::parsed(identity);
            }
        } else if let Err(error) = toml::from_str::<toml::Value>(&text) {
            parse_failure.get_or_insert_with(|| format!("META-INF/neoforge.mods.toml: {error}"));
        }
    }
    if let Some(bridge) = intermed_doctor_core::bootstrap_bridge::detect_connector(archive)
        .or_else(|| intermed_doctor_core::bootstrap_bridge::detect_essential_loader(archive))
    {
        return IdentityDetection::parsed(JarIdentity {
            mod_id: Some(bridge.id),
            version: bridge.version,
            loader: Some(bridge.loader_family),
            platform: None,
            has_contact: false,
        });
    }
    if jar_meta::manifest_attribute(archive, "FMLModType").as_deref() == Some("LANGPROVIDER")
        && (archive
            .by_name("META-INF/services/net.minecraftforge.forgespi.language.IModLanguageProvider")
            .is_ok()
            || archive
                .by_name("META-INF/services/net.neoforged.neoforgespi.language.IModLanguageLoader")
                .is_ok())
    {
        let title = jar_meta::manifest_attribute(archive, "Implementation-Title")
            .or_else(|| jar_meta::manifest_attribute(archive, "Specification-Title"));
        let version = jar_meta::manifest_attribute(archive, "Implementation-Version")
            .or_else(|| jar_meta::manifest_attribute(archive, "Specification-Version"));
        return IdentityDetection::parsed_service_container(
            JarIdentity {
                version,
                loader: Some("forge-language-provider".to_string()),
                has_contact: jar_meta::manifest_attribute(archive, "Implementation-URL").is_some(),
                ..JarIdentity::default()
            },
            format!(
                "Forge language-provider service{}",
                title
                    .as_deref()
                    .map(|title| format!(" declared as {title}"))
                    .unwrap_or_default()
            ),
        );
    }
    if nested_depth > 0 {
        let names = (0..archive.len())
            .filter_map(|index| {
                let name = archive.by_index(index).ok()?.name().to_string();
                ((name.starts_with("META-INF/jarjar/") || name.starts_with("META-INF/jars/"))
                    && name.ends_with(".jar"))
                .then_some(name)
            })
            .collect::<Vec<_>>();
        let mut nested_identities = Vec::new();
        for name in names {
            let Ok(Some(bytes)) = intermed_doctor_core::bounded_zip::read_zip_bytes_bounded(
                archive,
                &name,
                intermed_doctor_core::bounded_zip::MAX_NESTED_JAR_BYTES,
            ) else {
                continue;
            };
            let Ok(mut nested) = zip::ZipArchive::new(Cursor::new(bytes)) else {
                continue;
            };
            let detected = detect_identity_bounded(&mut nested, nested_depth - 1);
            if detected.status == IdentityStatus::Parsed && detected.identity.mod_id.is_some() {
                nested_identities.push((name, detected.identity));
            }
        }
        // A single authoritative nested mod describes a descriptorless JarJar
        // container (KotlinForForge is the common real-world case). Multiple
        // nested mods cannot be collapsed into SBOM's singular identity field;
        // leave those containers explicit rather than choosing arbitrarily.
        if nested_identities.len() == 1 {
            let (path, identity) = nested_identities.pop().expect("length checked");
            return IdentityDetection::parsed_nested(identity, path);
        } else if !nested_identities.is_empty() {
            return IdentityDetection::parsed_nested_container(&nested_identities);
        }
    }
    IdentityDetection {
        identity: JarIdentity::default(),
        status: if parse_failure.is_some() {
            IdentityStatus::ParseFailed
        } else {
            IdentityStatus::NoRecognizableManifest
        },
        detail: parse_failure,
    }
}

/// Resolve Forge's `${file.jarVersion}` placeholder on a parsed identity, using
/// the shared [`jar_meta`] helper so the substitution matches the metadata and
/// identity scanners. Without it the SBOM/PURL carries the raw template.
fn resolve_jar_version_placeholder<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    identity: &mut JarIdentity,
) {
    if let Some(version) = identity.version.as_ref() {
        identity.version = Some(jar_meta::resolve_jar_version(version, archive));
    }
}

fn jar_signature_strength(archive: &mut zip::ZipArchive<std::fs::File>) -> SignatureStrength {
    let mut has_sf = false;
    let mut has_cert_block = false;
    for i in 0..archive.len() {
        let Ok(name) = archive.by_index(i).map(|e| e.name().to_string()) else {
            continue;
        };
        if !name.starts_with("META-INF/") {
            continue;
        }
        if name.ends_with(".SF") {
            has_sf = true;
        }
        if name.ends_with(".RSA") || name.ends_with(".DSA") || name.ends_with(".EC") {
            has_cert_block = true;
        }
    }
    match (has_sf, has_cert_block) {
        (false, _) => SignatureStrength::Unsigned,
        (true, false) => SignatureStrength::ManifestOnly,
        (true, true) => SignatureStrength::Certified,
    }
}

/// Verify signature integrity with the JDK verifier. This is deliberately run
/// only when a complete `.SF` + signature-block structure exists. `-strict` is
/// used to distinguish unsigned entries and certificate-policy warnings;
/// certificate-policy failures do not by themselves imply broken signature
/// integrity.
fn verify_jar_signature(
    jar: &Path,
    material: SignatureStrength,
    timeout: Duration,
) -> (SignatureVerification, Option<String>) {
    match material {
        SignatureStrength::Unsigned => return (SignatureVerification::Unsigned, None),
        SignatureStrength::ManifestOnly => {
            return (
                SignatureVerification::Incomplete,
                Some("signature manifest exists without a PKCS signature block".to_string()),
            );
        }
        SignatureStrength::Certified => {}
    }

    // Each `jarsigner` is a JVM. Keep verification serialized even when the JAR
    // scan uses a large Rayon pool, otherwise a signed pack could multiply JVM
    // heaps and trigger host OOM.
    let _permit = SignatureVerifierPermit::acquire();

    let mut command = Command::new("jarsigner");
    command
        // Bound each verifier JVM; scans already parallelize at the jar level.
        .arg("-J-Xmx128m")
        .arg("-J-Duser.language=en")
        .arg("-J-Duser.country=US")
        .arg("-verify")
        .arg("-strict")
        .arg("-verbose:summary")
        .arg(jar);
    let output = run_command_bounded(&mut command, timeout);
    match output {
        Ok(BoundedCommandOutput::Completed {
            status,
            stdout,
            stderr,
        }) => {
            let code = status.code().unwrap_or(1);
            let stdout = String::from_utf8_lossy(&stdout);
            let stderr = String::from_utf8_lossy(&stderr);
            let combined = format!("{stdout}\n{stderr}");
            if code & 16 != 0 {
                return (
                    SignatureVerification::Incomplete,
                    Some(
                        "valid signature material, but one or more archive entries are unsigned"
                            .to_string(),
                    ),
                );
            }
            if code != 1 && combined.contains("jar verified") {
                let detail = (code != 0).then(|| {
                    format!(
                        "signature integrity verified; certificate-policy warnings (jarsigner strict code {code})"
                    )
                });
                return (SignatureVerification::Verified, detail);
            }
            let detail = stderr
                .lines()
                .chain(stdout.lines())
                .find(|line| !line.trim().is_empty())
                .unwrap_or("jarsigner rejected the signature")
                .trim()
                .chars()
                .take(512)
                .collect();
            (SignatureVerification::Invalid, Some(detail))
        }
        Ok(BoundedCommandOutput::TimedOut) => (
            SignatureVerification::Unavailable,
            Some(format!(
                "jarsigner verification timed out after {} second(s)",
                timeout.as_secs()
            )),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            SignatureVerification::Unavailable,
            Some("jarsigner is not available in PATH".to_string()),
        ),
        Err(error) => (
            SignatureVerification::Unavailable,
            Some(format!("could not run jarsigner: {error}")),
        ),
    }
}

enum BoundedCommandOutput {
    Completed {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    TimedOut,
}

const MAX_SIGNATURE_VERIFIER_OUTPUT_BYTES: usize = 64 * 1024;

fn drain_output_bounded(mut reader: impl Read) -> Vec<u8> {
    let mut kept = Vec::with_capacity(MAX_SIGNATURE_VERIFIER_OUTPUT_BYTES);
    let mut buffer = [0u8; 8 * 1024];
    while let Ok(read) = reader.read(&mut buffer) {
        if read == 0 {
            break;
        }
        let remaining = MAX_SIGNATURE_VERIFIER_OUTPUT_BYTES.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..read.min(remaining)]);
        // Continue draining after the diagnostic cap so the child can never
        // block on a full pipe, but do not retain attacker-controlled output.
    }
    kept
}

/// Run a subprocess with both bounded wall time and concurrently drained output
/// pipes. Draining is important: waiting on a child with piped output can itself
/// deadlock when an adversarial archive makes the verifier verbose enough to
/// fill an OS pipe.
fn run_command_bounded(
    command: &mut Command,
    timeout: Duration,
) -> std::io::Result<BoundedCommandOutput> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .map(|pipe| std::thread::spawn(move || drain_output_bounded(pipe)));
    let stderr = child
        .stderr
        .take()
        .map(|pipe| std::thread::spawn(move || drain_output_bounded(pipe)));
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let stdout = stdout
                .and_then(|reader| reader.join().ok())
                .unwrap_or_default();
            let stderr = stderr
                .and_then(|reader| reader.join().ok())
                .unwrap_or_default();
            return Ok(BoundedCommandOutput::Completed {
                status,
                stdout,
                stderr,
            });
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(reader) = stdout {
                let _ = reader.join();
            }
            if let Some(reader) = stderr {
                let _ = reader.join();
            }
            return Ok(BoundedCommandOutput::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct SignatureVerifierPermit;

impl SignatureVerifierPermit {
    fn acquire() -> Self {
        let (busy, ready) = signature_verifier_state();
        let mut busy = busy.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while *busy {
            busy = ready
                .wait(busy)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        *busy = true;
        Self
    }
}

impl Drop for SignatureVerifierPermit {
    fn drop(&mut self) {
        release_signature_verifier();
    }
}

fn signature_verifier_state() -> &'static (Mutex<bool>, Condvar) {
    static STATE: OnceLock<(Mutex<bool>, Condvar)> = OnceLock::new();
    STATE.get_or_init(|| (Mutex::new(false), Condvar::new()))
}

fn release_signature_verifier() {
    let (busy, ready) = signature_verifier_state();
    let mut busy = busy.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *busy = false;
    ready.notify_one();
}

/// Parse Fabric/Quilt `*.mod.json` identity plus platform hints from `custom.*`
/// and `contact` homepage links.
fn json_loader_identity(v: &serde_json::Value, loader: &str) -> JarIdentity {
    let mod_id = v.get("id").and_then(|x| x.as_str()).map(str::to_string);
    let version = v
        .get("version")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let platform = platform_from_json(v);
    let has_contact = v
        .get("contact")
        .and_then(|c| c.as_object())
        .is_some_and(|c| {
            c.get("homepage")
                .or_else(|| c.get("sources"))
                .and_then(|x| x.as_str())
                .is_some_and(|url| !url.is_empty())
        });
    JarIdentity {
        mod_id,
        version,
        loader: Some(loader.to_string()),
        platform,
        has_contact,
    }
}

fn platform_from_json(v: &serde_json::Value) -> Option<DistributionPlatform> {
    if let Some(custom) = v.get("custom").and_then(|c| c.as_object()) {
        if custom.contains_key("modrinth") {
            return Some(DistributionPlatform::Modrinth);
        }
        if custom.contains_key("curseforge") {
            return Some(DistributionPlatform::CurseForge);
        }
    }
    let urls: Vec<&str> = v
        .get("contact")
        .and_then(|c| c.as_object())
        .map(|c| {
            ["homepage", "sources", "issues"]
                .iter()
                .filter_map(|k| c.get(*k).and_then(|x| x.as_str()))
                .collect()
        })
        .unwrap_or_default();
    for url in urls {
        if url.contains("modrinth.com") {
            return Some(DistributionPlatform::Modrinth);
        }
        if url.contains("curseforge.com") {
            return Some(DistributionPlatform::CurseForge);
        }
    }
    None
}

/// Load pack-specific identity evidence.  A project id from either corpus-lock
/// schema can corroborate a descriptor identity, while a materialization hash
/// can corroborate even descriptorless embedded/library jars exactly.  This
/// context is deliberately kept outside the content-addressed SBOM cache.
fn load_corpus_provenance(instance_root: Option<&Path>) -> Option<CorpusProvenance> {
    let root = instance_root?;
    let mut provenance = CorpusProvenance::default();

    #[derive(Deserialize)]
    struct LockFile {
        schema: String,
        #[serde(default)]
        mods: Vec<LockedModEntry>,
    }
    #[derive(Deserialize)]
    struct LockedModEntry {
        project_id: String,
    }

    if let Ok(text) = std::fs::read_to_string(root.join("corpus.lock"))
        && let Ok(lock) = serde_json::from_str::<LockFile>(&text)
        && matches!(
            lock.schema.as_str(),
            CORPUS_LOCK_SCHEMA_V1 | CORPUS_LOCK_SCHEMA_V2
        )
    {
        provenance
            .mod_ids
            .extend(lock.mods.into_iter().map(|m| m.project_id));
    }

    #[derive(Deserialize)]
    struct Materialization {
        schema: String,
        #[serde(default)]
        artifacts: Vec<MaterializedArtifact>,
    }
    #[derive(Deserialize)]
    struct MaterializedArtifact {
        sha256: String,
    }

    if let Ok(text) = std::fs::read_to_string(root.join("intermed-materialization.json"))
        && let Ok(materialization) = serde_json::from_str::<Materialization>(&text)
        && materialization.schema == MATERIALIZATION_SCHEMA_V1
    {
        provenance.artifact_sha256.extend(
            materialization
                .artifacts
                .into_iter()
                .map(|a| a.sha256.to_ascii_lowercase())
                .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())),
        );
    }

    (!provenance.is_empty()).then_some(provenance)
}

/// Heuristic identifiability score in `0..=100`, **not** a safety or malware
/// verdict: it answers "how confidently can we say what this jar *is*", which is
/// what an SBOM needs. A higher score means more corroborating identity metadata
/// was present.
///
/// The score is an additive sum of independent, self-describing-ness signals,
/// clamped to 100:
///
/// | Signal                         | Points | Rationale                                   |
/// |--------------------------------|-------:|---------------------------------------------|
/// | Base (any parseable jar)       |     20 | A readable archive is the floor.            |
/// | `mod_id` present               |     40 | The single strongest identifier.            |
/// | `version` present              |     20 | Pins the artifact to a release.             |
/// | `loader` declared              |     10 | Confirms the ecosystem (fabric/forge/…).    |
/// | Platform listed (Modrinth/CF)  |      8 | explicit distribution metadata.               |
/// | Contact / homepage present     |      5 | author-linked provenance.                   |
/// | Known project identity         |      4 | project-level corpus association.           |
/// | Exact pack materialization     |      7 | this precise binary was pinned by hash.     |
/// | Cryptographically verified JAR |     10 | signature and signed entry digests verified.|
///
/// So a fully-described, platform-listed, verified mod can reach `100`; a bare
/// jar with no manifest metadata floors at `20`.
fn compute_trust_score(
    identity: &JarIdentity,
    signature: SignatureVerification,
    corpus_match: CorpusMatchQuality,
) -> TrustScoreBreakdown {
    const BASE: u8 = 20;
    const MOD_ID: u8 = 40;
    const VERSION: u8 = 20;
    const LOADER: u8 = 10;
    const PLATFORM: u8 = 8;
    const CONTACT: u8 = 5;
    const CORPUS: u8 = 7;
    const VERIFIED_SIGNATURE: u8 = 10;

    TrustScoreBreakdown {
        base: BASE,
        mod_id: if identity.mod_id.is_some() { MOD_ID } else { 0 },
        version: if identity.version.is_some() {
            VERSION
        } else {
            0
        },
        loader: if identity.loader.is_some() { LOADER } else { 0 },
        platform: if identity.platform.is_some() {
            PLATFORM
        } else {
            0
        },
        contact: if identity.has_contact { CONTACT } else { 0 },
        corpus_lock: match corpus_match {
            CorpusMatchQuality::ExactArtifactPin => CORPUS,
            CorpusMatchQuality::KnownProjectIdentity => 4,
            CorpusMatchQuality::None => 0,
        },
        verified_signature: if signature == SignatureVerification::Verified {
            VERIFIED_SIGNATURE
        } else {
            0
        },
    }
}

fn recompute_provenance(record: &mut JarSbomRecord) {
    let identity = JarIdentity {
        mod_id: record.mod_id.clone(),
        version: record.version.clone(),
        loader: record.loader.clone(),
        platform: record.platform.clone(),
        // Contact provenance is not part of canonical B identity. Preserve the
        // local descriptor observation without letting it own identity truth.
        has_contact: record.trust_breakdown.contact > 0,
    };
    record.trust_breakdown = compute_trust_score(
        &identity,
        record.signature_verification,
        record.corpus_match,
    );
    record.trust_score = record.trust_breakdown.total();
    record.provenance = provenance_assessment(
        record.identity_status,
        record.identity_origin,
        record.source_class,
        record.corpus_match,
        record.signature_verification,
    );
}

fn provenance_assessment(
    identity_status: IdentityStatus,
    identity_origin: IdentityOrigin,
    source_class: SourceClass,
    corpus_match: CorpusMatchQuality,
    signature: SignatureVerification,
) -> ProvenanceAssessment {
    let identity = match (identity_origin, identity_status, source_class) {
        (IdentityOrigin::CanonicalLayerB, _, _) => IdentityCompleteness::Canonical,
        (_, IdentityStatus::ParseFailed, _) => IdentityCompleteness::ParseFailed,
        (_, IdentityStatus::NoRecognizableManifest, _) => IdentityCompleteness::Unresolved,
        (_, _, SourceClass::PartiallyIdentified) => IdentityCompleteness::Partial,
        _ => IdentityCompleteness::DescriptorComplete,
    };
    let distribution = match corpus_match {
        CorpusMatchQuality::KnownProjectIdentity => DistributionProvenance::KnownProjectIdentity,
        _ if source_class == SourceClass::PlatformListed => {
            DistributionProvenance::PlatformDeclared
        }
        _ => DistributionProvenance::Unknown,
    };
    let binary_integrity = match signature {
        SignatureVerification::Verified => BinaryIntegrity::SignatureVerified,
        SignatureVerification::Incomplete => BinaryIntegrity::SignatureIncomplete,
        SignatureVerification::Invalid => BinaryIntegrity::SignatureInvalid,
        SignatureVerification::Unsigned | SignatureVerification::Unavailable => {
            BinaryIntegrity::ContentHashed
        }
    };
    let cryptographic_authenticity = match signature {
        SignatureVerification::Unsigned => CryptographicAuthenticity::Unsigned,
        SignatureVerification::Unavailable => CryptographicAuthenticity::Unavailable,
        SignatureVerification::Incomplete
        | SignatureVerification::Verified
        | SignatureVerification::Invalid => CryptographicAuthenticity::Unestablished,
    };
    ProvenanceAssessment {
        identity,
        distribution,
        binary_integrity,
        exact_materialization: if corpus_match == CorpusMatchQuality::ExactArtifactPin {
            ExactMaterialization::Pinned
        } else {
            ExactMaterialization::Unpinned
        },
        cryptographic_authenticity,
    }
}

fn provenance_is_weak(assessment: &ProvenanceAssessment) -> bool {
    matches!(
        assessment.identity,
        IdentityCompleteness::Partial
            | IdentityCompleteness::ParseFailed
            | IdentityCompleteness::Unresolved
    ) && assessment.distribution == DistributionProvenance::Unknown
        && assessment.exact_materialization == ExactMaterialization::Unpinned
}

fn sha256_file(path: &Path) -> Result<String, SbomScanError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| SbomScanError(format!("open {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| SbomScanError(format!("read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Bounded manifest read. All callers read loader manifests / `MANIFEST.MF`, so
/// the manifest cap applies; an oversized or crafted entry yields `None` instead
/// of driving unbounded decompression. Per-jar truncation is already surfaced by
/// the metadata layer (which scans the same jars).
fn read_zip_text<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, name: &str) -> Option<String> {
    intermed_doctor_core::bounded_zip::read_zip_text_opt(
        archive,
        name,
        intermed_doctor_core::bounded_zip::MAX_MANIFEST_BYTES,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::FactStore;
    use std::io::Write;

    fn unresolved_record(locator: &str, hash_byte: char) -> JarSbomRecord {
        let sha256 = hash_byte.to_string().repeat(64);
        JarSbomRecord {
            artifact_id: format!("sha256:{sha256}"),
            source_locator: locator.to_string(),
            archive: "same.jar".to_string(),
            mod_id: None,
            version: None,
            loader: None,
            sha256,
            signed: false,
            signature_strength: SignatureStrength::Unsigned,
            signature_verification: SignatureVerification::Unsigned,
            signature_detail: None,
            platform: None,
            in_corpus_lock: false,
            corpus_match: CorpusMatchQuality::None,
            trust_score: 20,
            trust_breakdown: TrustScoreBreakdown {
                base: 20,
                ..TrustScoreBreakdown::default()
            },
            identity_status: IdentityStatus::ParseFailed,
            identity_origin: IdentityOrigin::Unresolved,
            identity_detail: Some("bad local descriptor".to_string()),
            source_class: SourceClass::Unidentified,
            provenance: provenance_assessment(
                IdentityStatus::ParseFailed,
                IdentityOrigin::Unresolved,
                SourceClass::Unidentified,
                CorpusMatchQuality::None,
                SignatureVerification::Unsigned,
            ),
            canonical_identities: Vec::new(),
        }
    }

    #[test]
    fn canonical_layer_b_identity_replaces_and_recomputes_local_fallback() {
        let mut facts = FactStore::new();
        facts
            .fact("metadata-scanner", kind::ARTIFACT_ROLE)
            .subject("/instance/mods/same.jar")
            .attr("declared_id", "foo")
            .attr("version", "1.4.0")
            .attr("loader", "forge")
            .attr("descriptor", "META-INF/mods.toml")
            .attr("ordinal", 0i64)
            .attr("activation", "active")
            .attr("identity_certainty", "confirmed")
            .emit();
        let mut scan = SbomScan {
            target: "/instance".to_string(),
            records: vec![unresolved_record("/instance/mods/same.jar", 'a')],
            failures: Vec::new(),
        };

        let provenance = CorpusProvenance {
            mod_ids: BTreeSet::from(["foo".to_string()]),
            artifact_sha256: BTreeSet::new(),
        };
        apply_canonical_metadata_identities(&mut scan, &facts, Some(&provenance));

        let record = &scan.records[0];
        assert_eq!(record.mod_id.as_deref(), Some("foo"));
        assert_eq!(record.version.as_deref(), Some("1.4.0"));
        assert_eq!(record.loader.as_deref(), Some("forge"));
        assert_eq!(record.identity_origin, IdentityOrigin::CanonicalLayerB);
        assert_eq!(record.identity_status, IdentityStatus::Parsed);
        assert_eq!(record.source_class, SourceClass::Identified);
        assert_eq!(record.provenance.identity, IdentityCompleteness::Canonical);
        assert_eq!(
            record.corpus_match,
            CorpusMatchQuality::KnownProjectIdentity
        );
        assert_eq!(
            record.provenance.distribution,
            DistributionProvenance::KnownProjectIdentity
        );
        assert_eq!(record.trust_score, 94);
    }

    #[test]
    fn canonical_rebind_never_uses_a_colliding_basename() {
        let mut facts = FactStore::new();
        facts
            .fact("metadata-scanner", kind::ARTIFACT_ROLE)
            .subject("/instance/mods/same.jar")
            .attr("declared_id", "mod-copy")
            .attr("version", "1")
            .attr("loader", "forge")
            .attr("descriptor", "META-INF/mods.toml")
            .attr("ordinal", 0i64)
            .attr("activation", "active")
            .attr("identity_certainty", "confirmed")
            .emit();
        let mut scan = SbomScan {
            target: "/instance".to_string(),
            records: vec![
                unresolved_record("/instance/mods/same.jar", 'a'),
                unresolved_record("/instance/plugins/same.jar", 'b'),
            ],
            failures: Vec::new(),
        };

        apply_canonical_metadata_identities(&mut scan, &facts, None);

        assert_eq!(scan.records[0].mod_id.as_deref(), Some("mod-copy"));
        assert_eq!(scan.records[1].mod_id, None);
        assert_eq!(scan.records[1].identity_status, IdentityStatus::ParseFailed);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_subprocess_is_killed_at_wall_clock_limit() {
        let started = Instant::now();
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 2"]);
        let result = run_command_bounded(&mut command, Duration::from_millis(40)).unwrap();
        assert!(matches!(result, BoundedCommandOutput::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn signature_verifier_output_retention_is_bounded() {
        let input = vec![b'x'; MAX_SIGNATURE_VERIFIER_OUTPUT_BYTES * 2];
        let kept = drain_output_bounded(Cursor::new(input));
        assert_eq!(kept.len(), MAX_SIGNATURE_VERIFIER_OUTPUT_BYTES);
    }

    #[test]
    fn layer_h_rules_declare_typed_inputs_and_coverage() {
        let provenance = rule().requirements();
        assert!(provenance.required_fact_kinds.contains(kind::SBOM));
        assert!(
            provenance
                .optional_fact_kinds
                .contains(kind::SIGNATURE_STATUS)
        );
        assert!(
            provenance
                .minimum_coverage
                .contains(&CoverageRequirement::LocalArtifact)
        );

        let correlation = correlation_rule().requirements();
        assert!(correlation.required_fact_kinds.contains(kind::SBOM));
        assert!(
            correlation
                .optional_fact_kinds
                .contains(kind::USES_PROCESS_SPAWN)
        );
        assert!(correlation.input_layers.contains(&Layer::Security));
    }

    #[test]
    fn target_scan_includes_plugin_artifact_root() {
        let root = std::env::temp_dir().join(format!(
            "intermed-sbom-plugin-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).unwrap();
        let mut zip =
            zip::ZipWriter::new(std::fs::File::create(plugins.join("plugin.jar")).unwrap());
        zip.start_file("plugin.yml", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"name: Plugin\nversion: 1\nmain: example.Plugin\n")
            .unwrap();
        zip.finish().unwrap();
        let target = Target {
            path: root.clone(),
            kind: intermed_doctor_core::TargetKind::Server,
            mods_dir: None,
            game_root: Some(root.clone()),
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let scan = scan_target(&target).unwrap();
        assert_eq!(scan.records.len(), 1);
        assert_eq!(scan.records[0].archive, "plugin.jar");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn trust_score_prefers_manifest_and_signing() {
        let full = JarIdentity {
            mod_id: Some("alpha".into()),
            version: Some("1.0.0".into()),
            loader: Some("fabric".into()),
            platform: None,
            has_contact: false,
        };
        assert_eq!(
            compute_trust_score(
                &full,
                SignatureVerification::Verified,
                CorpusMatchQuality::None,
            )
            .total(),
            100
        );
        assert_eq!(
            compute_trust_score(
                &JarIdentity::default(),
                SignatureVerification::Unsigned,
                CorpusMatchQuality::None
            )
            .total(),
            20
        );
    }

    #[test]
    fn source_class_grades_identity() {
        let full = JarIdentity {
            mod_id: Some("alpha".into()),
            version: Some("1.0.0".into()),
            loader: Some("fabric".into()),
            platform: None,
            has_contact: false,
        };
        assert_eq!(SourceClass::of(&full), SourceClass::Identified);

        let listed = JarIdentity {
            platform: Some(DistributionPlatform::Modrinth),
            ..full.clone()
        };
        assert_eq!(SourceClass::of(&listed), SourceClass::PlatformListed);

        // Manifest found (loader known) but no id — a library jar, say.
        let partial = JarIdentity {
            mod_id: None,
            version: None,
            loader: Some("fabric".into()),
            platform: None,
            has_contact: false,
        };
        assert_eq!(SourceClass::of(&partial), SourceClass::PartiallyIdentified);

        // No manifest at all.
        assert_eq!(
            SourceClass::of(&JarIdentity::default()),
            SourceClass::Unidentified
        );
    }

    #[test]
    fn sha256_is_deterministic() {
        let dir = std::env::temp_dir().join(format!("intermed-sbom-sha-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.bin");
        std::fs::write(&path, b"abc").unwrap();
        let a = sha256_file(&path).unwrap();
        let b = sha256_file(&path).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            a,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_dir_all(dir).ok();
    }
}
