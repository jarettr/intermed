//! # intermed-sbom — Layer H (Phase 6)
//!
//! SBOM / provenance / packaging hygiene. Read-only jar scanning: checksums,
//! mod identity, JAR signing status, and trust heuristics. No bytecode execution.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::{SourceRef, kind};
use intermed_doctor_core::jar_meta;
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, JarCache, Layer, Rule, RuleCtx, Target, TargetKind,
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
const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-r5");
const CORPUS_LOCK_SCHEMA: &str = "intermed-corpus-lock-v1";

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

/// Cross-layer rule: correlate low provenance (Layer H) with dangerous
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
    /// `.SF` plus a certificate block — full JAR signature structure.
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

    /// Legacy boolean: any signing material was found.
    pub fn is_signed(self) -> bool {
        !matches!(self, SignatureStrength::Unsigned)
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
    pub archive: String,
    pub mod_id: Option<String>,
    pub version: Option<String>,
    pub loader: Option<String>,
    pub sha256: String,
    pub signed: bool,
    pub signature_strength: SignatureStrength,
    /// Modrinth / CurseForge hint when declared in manifest metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<DistributionPlatform>,
    /// True when the mod id appears in a sibling `corpus.lock` (popular-pack pin).
    #[serde(default)]
    pub in_corpus_lock: bool,
    /// Identifiability score in `0..=100` — how confidently the jar describes
    /// what it *is*, not a safety verdict. See [`compute_trust_score`] for the
    /// exact weighting.
    pub trust_score: u8,
    /// Graded provenance classification (replaces the old `unknown_source` bool).
    #[serde(default = "default_source_class")]
    pub source_class: SourceClass,
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

    fn applies(&self, target: &Target) -> bool {
        mods_dir(target).is_some()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let Some(dir) = mods_dir(ctx.target) else {
            return CollectorOutcome::skipped("no mods directory for SBOM scan");
        };
        let instance_root = ctx
            .target
            .mods_dir
            .as_ref()
            .and_then(|p| p.parent())
            .or_else(|| ctx.target.path.parent());
        let corpus_ids = load_corpus_mod_ids(instance_root);
        match scan_mods_dir_inner(&dir, ctx.jar_cache, &ctx.settings.scan, corpus_ids.as_ref()) {
            Ok(scan) => {
                let emitted = emit_scan(ctx, &scan);
                CollectorOutcome::active(
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

fn emit_scan(ctx: &mut CollectCtx<'_>, scan: &SbomScan) -> usize {
    let mut emitted = 0usize;
    for r in &scan.records {
        ctx.store
            .fact(EXTRACTOR, kind::CHECKSUM)
            .subject(r.archive.clone())
            .attr("algorithm", "sha256")
            .attr("hex", r.sha256.clone())
            .source(SourceRef::file(r.archive.clone()))
            .emit();
        emitted += 1;

        ctx.store
            .fact(EXTRACTOR, kind::SIGNATURE_STATUS)
            .subject(r.archive.clone())
            .attr("status", r.signature_strength.as_str())
            .attr("jar_signed", r.signed)
            .source(SourceRef::file(r.archive.clone()))
            .emit();
        emitted += 1;

        ctx.store
            .fact(EXTRACTOR, kind::TRUST_SCORE)
            .subject(r.archive.clone())
            .attr("score", r.trust_score as i64)
            .source(SourceRef::file(r.archive.clone()))
            .emit();
        emitted += 1;

        if let (Some(mod_id), Some(version)) = (&r.mod_id, &r.version) {
            ctx.store
                .fact(EXTRACTOR, kind::ARTIFACT_IDENTITY)
                .subject(mod_id.clone())
                .attr("version", version.clone())
                .attr("archive", r.archive.clone())
                .attr("sha256", r.sha256.clone())
                .source(SourceRef::file(r.archive.clone()))
                .emit();
            emitted += 1;
        }

        // Only a *fully* unidentified jar warrants the provenance warning; a
        // partially-identified one (manifest present, id missing) is recorded on
        // the SBOM fact below but does not raise a finding.
        if r.is_unidentified() {
            ctx.store
                .fact(EXTRACTOR, kind::UNKNOWN_SOURCE)
                .subject(r.archive.clone())
                .attr("reason", "no recognizable mod manifest")
                .source(SourceRef::file(r.archive.clone()))
                .emit();
            emitted += 1;
        }

        let loader = r.loader.as_deref().unwrap_or("unknown");
        let mod_id = r.mod_id.as_deref().unwrap_or("unknown");
        let version = r.version.as_deref().unwrap_or("unknown");
        let mut sbom = ctx
            .store
            .fact(EXTRACTOR, kind::SBOM)
            .subject(r.archive.clone())
            .attr("mod_id", mod_id)
            .attr("version", version)
            .attr("loader", loader)
            .attr("sha256", r.sha256.clone())
            .attr("signed", r.signed)
            .attr("signature_strength", r.signature_strength.as_str())
            .attr("source_class", r.source_class.as_str())
            .attr("trust_score", r.trust_score as i64)
            .attr("in_corpus_lock", r.in_corpus_lock)
            .source(SourceRef::file(r.archive.clone()));
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

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in ctx.store.by_kind(kind::UNKNOWN_SOURCE) {
            let archive = f.subject.as_str();
            out.push(
                Finding::builder(self.id(), format!("unknown-source:{archive}"))
                    .severity(Severity::Warn)
                    .category(Category::Security)
                    .title(format!("Unknown mod provenance: {archive}"))
                    .explanation(
                        "This jar has no recognizable Fabric/Quilt/Forge manifest. \
                         Provenance and supply-chain trust cannot be established.",
                    )
                    .evidence(EvidenceEdge::subject(f.id))
                    .affects(archive)
                    .fix(FixCandidate::advice(
                        "Prefer mods from Modrinth or CurseForge with verifiable metadata.",
                    ))
                    .tag("sbom")
                    .tag("provenance")
                    .build(),
            );
        }

        for f in ctx.store.by_kind(kind::SIGNATURE_STATUS) {
            if f.attr("status") != Some("unsigned") {
                continue;
            }
            let archive = f.subject.as_str();
            out.push(
                Finding::builder(
                    self.id(),
                    format!("artifact-signature-status:unsigned:{archive}"),
                )
                .severity(Severity::Note)
                .category(Category::Security)
                .confidence(0.95)
                .title(format!("Jar is not JAR-signed: {archive}"))
                .explanation(
                    "No META-INF/*.SF signature manifest was found. \
                         Most Fabric/Forge mods ship unsigned; this is informational only.",
                )
                .evidence(EvidenceEdge::subject(f.id))
                .affects(archive)
                .fix(FixCandidate::advice(
                    "Verify mod source manually if supply-chain trust matters.",
                ))
                .tag("sbom")
                .tag("signature")
                .build(),
            );
        }
        out
    }
}

// ── Cross-layer correlation rule ───────────────────────────────────────────

struct SbomSecurityCorrelationRule;

/// High-risk capability fact kinds (mirrors `SecuritySignal::is_high_risk`) with
/// a human label for the finding. Kept local so SBOM does not depend on the
/// security crate — only on the shared fact vocabulary.
const HIGH_RISK_CAPABILITIES: &[(&str, &str)] = &[
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

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        use std::collections::BTreeMap;

        // archive -> trust_score, from the SBOM facts (subject is the archive).
        let mut trust_by_archive: BTreeMap<&str, i64> = BTreeMap::new();
        for f in ctx.store.by_kind(kind::SBOM) {
            if let Some(score) = f.attr_int("trust_score") {
                trust_by_archive.insert(f.subject.as_str(), score);
            }
        }

        // archive -> (sorted capability labels, one evidence fact id), from the
        // high-risk security facts (subject is the mod id, archive is an attr).
        let mut risky: BTreeMap<String, (Vec<&str>, intermed_doctor_core::facts::FactId)> =
            BTreeMap::new();
        for (fact_kind, label) in HIGH_RISK_CAPABILITIES {
            for f in ctx.store.by_kind(fact_kind) {
                let Some(archive) = f.attr("archive") else {
                    continue;
                };
                let entry = risky
                    .entry(archive.to_string())
                    .or_insert_with(|| (Vec::new(), f.id));
                entry.0.push(label);
            }
        }

        let mut out = Vec::new();
        for (archive, (mut labels, evidence)) in risky {
            // Only correlate when provenance is weak: a well-identified jar with
            // a dangerous capability is already covered by the security rule.
            let trust = trust_by_archive.get(archive.as_str()).copied().unwrap_or(0);
            if trust >= ctx.settings.sbom.well_identified_trust {
                continue;
            }
            labels.sort_unstable();
            labels.dedup();

            out.push(
                Finding::builder(self.id(), format!("low-trust-capability:{archive}"))
                    .severity(Severity::Warn)
                    .category(Category::Security)
                    .title(format!(
                        "Low-provenance jar `{archive}` exercises high-risk capability"
                    ))
                    .explanation(format!(
                        "`{archive}` could not be confidently identified (trust score {trust}/100, \
                         below {}) yet statically references high-risk \
                         capability/capabilities: {}. Unknown provenance combined with a dangerous \
                         capability is a stronger supply-chain concern than either signal alone.",
                        ctx.settings.sbom.well_identified_trust,
                        labels.join(", ")
                    ))
                    .evidence(EvidenceEdge::subject(evidence))
                    .affects(&archive)
                    .fix(FixCandidate::advice(
                        "Establish the mod's provenance (known platform + signed/manifest) before \
                         trusting a jar that spawns processes, loads native code, or evaluates scripts.",
                    ))
                    .tag("sbom")
                    .tag("security")
                    .tag("supply-chain")
                    .build(),
            );
        }
        out
    }
}

// ── Scanner ──────────────────────────────────────────────────────────────

pub fn scan_target(target: &Target) -> Result<SbomScan, SbomScanError> {
    let Some(dir) = mods_dir(target) else {
        return Err(SbomScanError("target has no mods directory".into()));
    };
    scan_mods_dir(&dir)
}

pub fn scan_mods_dir(dir: &Path) -> Result<SbomScan, SbomScanError> {
    scan_mods_dir_with_cache(dir, None)
}

pub fn scan_mods_dir_with_cache(
    dir: &Path,
    cache: Option<&JarCache>,
) -> Result<SbomScan, SbomScanError> {
    let corpus_ids = load_corpus_mod_ids(dir.parent());
    scan_mods_dir_inner(
        dir,
        cache,
        &intermed_doctor_core::ScanSettings::default(),
        corpus_ids.as_ref(),
    )
}

/// Like [`scan_mods_dir_with_cache`] but honors incremental [`ScanSettings`].
pub fn scan_mods_dir_filtered(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
) -> Result<SbomScan, SbomScanError> {
    let corpus_ids = load_corpus_mod_ids(dir.parent());
    scan_mods_dir_inner(dir, cache, scan, corpus_ids.as_ref())
}

fn scan_mods_dir_inner(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
    corpus_mod_ids: Option<&BTreeSet<String>>,
) -> Result<SbomScan, SbomScanError> {
    if !dir.is_dir() {
        return Err(SbomScanError(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }

    let jars = intermed_doctor_core::list_jar_archives(dir, scan)
        .map_err(|e| SbomScanError(format!("read {}: {e}", dir.display())))?;

    // Independent per-jar hashing + manifest parsing; fan out across cores.
    // `par_iter().map()` preserves order for deterministic aggregation.
    let scanned: Vec<(String, CachedSbomJar)> = jars
        .par_iter()
        .map(|jar| {
            let archive = file_name_of(jar);
            let cached = match cache {
                Some(c) => c.get_or_scan(EXTRACTOR, CACHE_VERSION, jar, || {
                    scan_jar_cached(jar, corpus_mod_ids)
                }),
                None => scan_jar_cached(jar, corpus_mod_ids),
            };
            (archive, cached)
        })
        .collect();

    let mut records = Vec::new();
    let mut failures = Vec::new();
    for (archive, cached) in scanned {
        match cached {
            CachedSbomJar::Ok(record) => records.push(record),
            CachedSbomJar::Err(reason) => failures.push(SbomScanFailure { archive, reason }),
        }
    }

    Ok(SbomScan {
        target: dir.display().to_string(),
        records,
        failures,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CachedSbomJar {
    Ok(JarSbomRecord),
    Err(String),
}

fn scan_jar_cached(jar: &Path, corpus_mod_ids: Option<&BTreeSet<String>>) -> CachedSbomJar {
    match scan_jar(jar, corpus_mod_ids) {
        Ok(record) => CachedSbomJar::Ok(record),
        Err(e) => CachedSbomJar::Err(e.to_string()),
    }
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string()
}

fn scan_jar(
    jar: &Path,
    corpus_mod_ids: Option<&BTreeSet<String>>,
) -> Result<JarSbomRecord, SbomScanError> {
    let archive = file_name_of(jar);

    let sha256 = sha256_file(jar)?;
    let file = std::fs::File::open(jar)
        .map_err(|e| SbomScanError(format!("open {}: {e}", jar.display())))?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| SbomScanError(format!("zip {}: {e}", jar.display())))?;

    let identity = detect_identity(&mut zip);
    let signature_strength = jar_signature_strength(&mut zip);
    let signed = signature_strength.is_signed();
    let in_corpus_lock = identity
        .mod_id
        .as_ref()
        .is_some_and(|id| corpus_mod_ids.is_some_and(|set| set.contains(id)));
    let source_class = SourceClass::of(&identity);
    let trust_score = compute_trust_score(&identity, signature_strength, in_corpus_lock);

    Ok(JarSbomRecord {
        archive,
        mod_id: identity.mod_id,
        version: identity.version,
        loader: identity.loader,
        sha256,
        signed,
        signature_strength,
        platform: identity.platform,
        in_corpus_lock,
        trust_score,
        source_class,
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

fn detect_identity(archive: &mut zip::ZipArchive<std::fs::File>) -> JarIdentity {
    if let Some(text) = read_zip_text(archive, "fabric.mod.json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            return json_loader_identity(&v, "fabric");
        }
    }
    if let Some(text) = read_zip_text(archive, "quilt.mod.json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            return json_loader_identity(&v, "quilt");
        }
    }
    if let Some(text) = read_zip_text(archive, "META-INF/mods.toml") {
        if let Ok(v) = toml::from_str::<toml::Value>(&text) {
            if let Some(mut identity) = forge_identity_from_toml(&v, "forge") {
                resolve_jar_version_placeholder(archive, &mut identity);
                return identity;
            }
        }
    }
    if let Some(text) = read_zip_text(archive, "plugin.yml") {
        if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
            return JarIdentity {
                mod_id: v.get("name").and_then(|x| x.as_str()).map(str::to_string),
                version: v
                    .get("version")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                loader: Some("bukkit".into()),
                platform: None,
                has_contact: false,
            };
        }
    }
    if let Some(text) = read_zip_text(archive, "paper-plugin.yml") {
        if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
            return JarIdentity {
                mod_id: v.get("name").and_then(|x| x.as_str()).map(str::to_string),
                version: v
                    .get("version")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                loader: Some("paper".into()),
                platform: None,
                has_contact: false,
            };
        }
    }
    if let Some(text) = read_zip_text(archive, "META-INF/neoforge.mods.toml") {
        if let Ok(v) = toml::from_str::<toml::Value>(&text) {
            if let Some(mut identity) = forge_identity_from_toml(&v, "neoforge") {
                resolve_jar_version_placeholder(archive, &mut identity);
                return identity;
            }
        }
    }
    JarIdentity::default()
}

/// Resolve Forge's `${file.jarVersion}` placeholder on a parsed identity, using
/// the shared [`jar_meta`] helper so the substitution matches the metadata and
/// identity scanners. Without it the SBOM/PURL carries the raw template.
fn resolve_jar_version_placeholder(
    archive: &mut zip::ZipArchive<std::fs::File>,
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

/// Load mod project ids pinned by a sibling `corpus.lock` (lab popular-pack list).
fn load_corpus_mod_ids(instance_root: Option<&Path>) -> Option<BTreeSet<String>> {
    let root = instance_root?;
    let lock_path = root.join("corpus.lock");
    let text = std::fs::read_to_string(&lock_path).ok()?;
    #[derive(Deserialize)]
    struct LockFile {
        schema: String,
        mods: Vec<LockedModEntry>,
    }
    #[derive(Deserialize)]
    struct LockedModEntry {
        project_id: String,
    }
    let lock: LockFile = serde_json::from_str(&text).ok()?;
    if lock.schema != CORPUS_LOCK_SCHEMA {
        return None;
    }
    Some(lock.mods.into_iter().map(|m| m.project_id).collect())
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
/// | In sibling `corpus.lock`       |      7 | pinned by a popular-pack lab corpus.        |
/// | Manifest-only sign (`.SF`)     |      5 | partial JAR signature material.             |
/// | Certified sign (`.SF`+PKCS)    |     +5 | full certificate block present.             |
///
/// So a fully-described, platform-listed, certified mod can reach `100`; a bare
/// jar with no manifest metadata floors at `20`.
fn compute_trust_score(
    identity: &JarIdentity,
    signature: SignatureStrength,
    in_corpus_lock: bool,
) -> u8 {
    const BASE: u8 = 20;
    const MOD_ID: u8 = 40;
    const VERSION: u8 = 20;
    const LOADER: u8 = 10;
    const PLATFORM: u8 = 8;
    const CONTACT: u8 = 5;
    const CORPUS: u8 = 7;
    const MANIFEST_SIGN: u8 = 5;
    const CERT_SIGN: u8 = 5;

    let mut score = BASE;
    if identity.mod_id.is_some() {
        score = score.saturating_add(MOD_ID);
    }
    if identity.version.is_some() {
        score = score.saturating_add(VERSION);
    }
    if identity.loader.is_some() {
        score = score.saturating_add(LOADER);
    }
    if identity.platform.is_some() {
        score = score.saturating_add(PLATFORM);
    }
    if identity.has_contact {
        score = score.saturating_add(CONTACT);
    }
    if in_corpus_lock {
        score = score.saturating_add(CORPUS);
    }
    match signature {
        SignatureStrength::Unsigned => {}
        SignatureStrength::ManifestOnly => {
            score = score.saturating_add(MANIFEST_SIGN);
        }
        SignatureStrength::Certified => {
            score = score.saturating_add(MANIFEST_SIGN);
            score = score.saturating_add(CERT_SIGN);
        }
    }
    score.min(100)
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
fn read_zip_text(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Option<String> {
    intermed_doctor_core::bounded_zip::read_zip_text_opt(
        archive,
        name,
        intermed_doctor_core::bounded_zip::MAX_MANIFEST_BYTES,
    )
}

fn mods_dir(target: &Target) -> Option<PathBuf> {
    target.mods_dir.clone().or_else(|| {
        if target.kind == TargetKind::ModsDir {
            Some(target.path.clone())
        } else {
            let dir = target.path.join("mods");
            dir.is_dir().then_some(dir)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            compute_trust_score(&full, SignatureStrength::Certified, false),
            100
        );
        assert_eq!(
            compute_trust_score(&JarIdentity::default(), SignatureStrength::Unsigned, false),
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
