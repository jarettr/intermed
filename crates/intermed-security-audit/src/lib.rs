//! # intermed-security-audit — Layer G (Phase 6)
//!
//! Static security audit — detection only, no enforcement or instrumentation.
//!
//! Pipeline per mod jar:
//! 1. Walk zip entries ending in `.class` (magic `0xCAFEBABE` verified).
//! 2. Parse constant pools via [`cafebabe`] with [`noak`] fallback.
//! 3. Match **method references** (`MethodRef` / `InterfaceMethodRef`) against
//!    risky API rules — bare UTF-8 strings are ignored.
//! 4. Emit per-signal facts; rule [`rule`] groups them into one finding per mod.

mod collapse;
mod cp;
mod detect;

#[doc(hidden)]
pub mod fixtures;

pub use collapse::collapse_per_capability;
pub use cp::{is_class_file, ClassEvidence, CLASS_MAGIC};
pub use detect::{
    combined_severity, corroborate_with_strings, detect_signals, security_finding_confidence,
    should_emit_finding, should_emit_finding_with, structural_signals, DetectedSignal,
    EvidenceStrength, SecuritySignal, SignalProvenance, CORROBORATED_CONFIDENCE,
    MIN_NOTE_SIGNALS_FOR_FINDING,
};

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::{kind, SourceRef};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, JarCache, Layer, Rule, RuleCtx, Target, TargetKind,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const EXTRACTOR: &str = "security-scanner";
/// Cache key version for this collector's payload. The crate version invalidates
/// the cache automatically on every release; bump the trailing revision when the
/// detection logic changes within a single release.
const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-r4");

/// Implementation status for help text.
pub const STATUS: &str = "active: Phase 6";

/// Layer-G collector.
pub fn collector() -> impl Collector {
    SecurityCollector
}

/// Layer-G security rule.
pub fn rule() -> impl Rule {
    SecurityApiRule
}

/// Per-mod security signals aggregated from all classes in a jar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModSecurityRecord {
    pub archive: String,
    pub mod_id: String,
    /// Detected signals, each tagged with its provenance (structural vs
    /// reflection-corroborated).
    pub signals: Vec<DetectedSignal>,
    /// Total `.class` files inspected in the jar.
    pub classes_scanned: usize,
    /// How many of those classes contained at least one *structural* dangerous
    /// call (a real member reference), as opposed to only a suspicious string.
    /// A high ratio of dangerous-to-scanned classes is a stronger smell than a
    /// single hit in a large jar. Defaults to `0` for older cached records.
    #[serde(default)]
    pub dangerous_classes: usize,
    /// Per-capability count of classes with at least one structural hit for that
    /// capability. Populated by the scanner; empty for older cached records.
    #[serde(default)]
    pub signal_class_counts: BTreeMap<SecuritySignal, usize>,
    /// Reasons this jar's class scan was truncated by a resource limit (DoS
    /// guard). Empty when the jar scanned fully.
    #[serde(default)]
    pub truncations: Vec<String>,
}

impl ModSecurityRecord {
    /// True if a signal of the given capability was detected, regardless of provenance.
    pub fn has_signal(&self, signal: SecuritySignal) -> bool {
        self.signals.iter().any(|d| d.signal == signal)
    }

    /// The set of distinct capabilities detected for this mod.
    pub fn signal_set(&self) -> BTreeSet<SecuritySignal> {
        self.signals.iter().map(|d| d.signal).collect()
    }
}

/// A mod is *suppressed* when it carries at least one signal but the set is below
/// the grouped-finding threshold (so the rule emits nothing for it).
fn is_suppressed(record: &ModSecurityRecord) -> bool {
    let signals = record.signal_set();
    !signals.is_empty() && !should_emit_finding_with(&signals, MIN_NOTE_SIGNALS_FOR_FINDING)
}

/// Tolerated scan failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityScanFailure {
    pub archive: String,
    pub reason: String,
}

/// Result of a security scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityScan {
    pub target: String,
    pub records: Vec<ModSecurityRecord>,
    pub failures: Vec<SecurityScanFailure>,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SecurityScanError(String);

// ── Collector ─────────────────────────────────────────────────────────────

struct SecurityCollector;

impl Collector for SecurityCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }

    fn layer(&self) -> Layer {
        Layer::Security
    }

    fn applies(&self, target: &Target) -> bool {
        mods_dir(target).is_some()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let Some(dir) = mods_dir(ctx.target) else {
            return CollectorOutcome::skipped("no mods directory for security scan");
        };
        match scan_mods_dir_filtered(&dir, ctx.jar_cache, &ctx.settings.scan) {
            Ok(scan) => {
                let emitted = emit_scan(ctx, &scan);
                // Mods that carry signals but sit below the finding threshold
                // (`should_emit_finding`) are otherwise invisible — surface the
                // count so the threshold's filtering is observable rather than
                // silent.
                let suppressed = scan.records.iter().filter(|r| is_suppressed(r)).count();
                let mut summary = format!(
                    "{} mod signal set(s), {} scan failure(s)",
                    scan.records.len(),
                    scan.failures.len()
                );
                if suppressed > 0 {
                    summary.push_str(&format!(", {suppressed} mod(s) below finding threshold"));
                }
                CollectorOutcome::active(emitted, summary)
            }
            Err(e) => CollectorOutcome::failed(e.to_string()),
        }
    }
}

/// Numeric counts are emitted as typed `Int` attributes, never strings: the typed
/// fact model and the DuckDB `val_int` column both require it, and writing a count
/// as a string silently produced `NULL` in SQL aggregation (a backend divergence).
fn count_attr(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn emit_scan(ctx: &mut CollectCtx<'_>, scan: &SecurityScan) -> usize {
    let mut emitted = 0usize;
    for r in &scan.records {
        for reason in &r.truncations {
            ctx.store
                .fact(EXTRACTOR, kind::SCAN_TRUNCATED)
                .subject(r.archive.clone())
                .attr("layer", "security")
                .attr("reason", reason.clone())
                .source(SourceRef::file(r.archive.clone()))
                .confidence(0.95)
                .emit();
            emitted += 1;
        }
        for detection in &r.signals {
            ctx.store
                .fact(EXTRACTOR, detection.signal.fact_kind())
                .subject(r.mod_id.clone())
                .attr("archive", r.archive.clone())
                .attr("provenance", detection.provenance.as_str())
                .attr("evidence_strength", detection.strength.as_str())
                .attr("dangerous_classes", count_attr(r.dangerous_classes))
                .attr("classes_scanned", count_attr(r.classes_scanned))
                .attr(
                    "affected_classes",
                    count_attr(
                        r.signal_class_counts
                            .get(&detection.signal)
                            .copied()
                            .unwrap_or(0),
                    ),
                )
                .source(SourceRef::inside(r.archive.clone(), "classes"))
                .confidence(
                    detection
                        .provenance
                        .confidence_with(ctx.settings.security.corroborated_confidence),
                )
                .emit();
            emitted += 1;
        }
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

struct SecurityApiRule;

/// Per-mod aggregation state shared by imperative and DuckDB SQL backends.
///
/// SQL selects raw signal rows; both backends fold them into this structure
/// before thresholding and finding emission so severity logic stays single-sourced.
#[derive(Default)]
pub struct SecurityModDraft {
    pub archive: String,
    pub signals: BTreeSet<SecuritySignal>,
    /// Capabilities established only by reflection-corroborated (string) evidence.
    pub corroborated_only: BTreeSet<SecuritySignal>,
    pub strength: BTreeMap<SecuritySignal, EvidenceStrength>,
    pub dangerous_classes: usize,
    pub classes_scanned: usize,
    /// Max `affected_classes` seen per capability across contributing facts.
    pub affected_classes: BTreeMap<SecuritySignal, usize>,
    pub fact_ids: Vec<intermed_doctor_core::facts::FactId>,
    structural: BTreeSet<SecuritySignal>,
}

impl SecurityModDraft {
    /// Fold one security signal row (from facts or a SQL projection) into the draft.
    // The parameters mirror one projected signal row (fact + provenance + metrics);
    // bundling them into a struct would only move the same fields one layer out.
    #[allow(clippy::too_many_arguments)]
    pub fn record_signal(
        &mut self,
        signal: SecuritySignal,
        fact_id: intermed_doctor_core::facts::FactId,
        archive: &str,
        provenance: Option<&str>,
        evidence_strength: Option<&str>,
        dangerous_classes: Option<i64>,
        classes_scanned: Option<i64>,
        affected_classes: Option<i64>,
    ) {
        if !archive.is_empty() {
            self.archive = archive.to_string();
        }
        self.signals.insert(signal);
        self.fact_ids.push(fact_id);
        if let Some(strength) = evidence_strength {
            let strength = EvidenceStrength::from_token(strength);
            self.strength
                .entry(signal)
                .and_modify(|cur| *cur = (*cur).max(strength))
                .or_insert(strength);
        }
        if let Some(n) = dangerous_classes {
            self.dangerous_classes = n as usize;
        }
        if let Some(n) = classes_scanned {
            self.classes_scanned = n as usize;
        }
        if let Some(n) = affected_classes {
            self.affected_classes
                .entry(signal)
                .and_modify(|cur| *cur = (*cur).max(n as usize))
                .or_insert(n as usize);
        }
        let corroborated =
            provenance == Some(SignalProvenance::ReflectionCorroborated.as_str());
        if corroborated {
            self.corroborated_only.insert(signal);
        } else {
            self.structural.insert(signal);
        }
    }

    /// Drop corroborated-only flags when a structural fact also backs the signal.
    pub fn finalize_corroboration(&mut self) {
        self.corroborated_only
            .retain(|signal| !self.structural.contains(signal));
    }
}

/// Aggregate Layer-G signal facts from a [`RuleCtx`] store.
#[must_use]
pub fn aggregate_security_drafts(ctx: &RuleCtx<'_>) -> BTreeMap<String, SecurityModDraft> {
    let signal_kinds = [
        kind::USES_PROCESS_SPAWN,
        kind::USES_SOCKET,
        kind::USES_REFLECTION_SET_ACCESSIBLE,
        kind::USES_UNSAFE,
        kind::USES_NATIVE_LIBRARY,
        kind::USES_DYNAMIC_CLASS_DEFINITION,
        kind::USES_REFLECTIVE_INVOCATION,
        kind::USES_SCRIPT_ENGINE,
        kind::USES_DESERIALIZATION,
        kind::USES_SYSTEM_EXIT,
        kind::USES_METHOD_HANDLES,
    ];

    let mut by_mod: BTreeMap<String, SecurityModDraft> = BTreeMap::new();
    for kind_name in signal_kinds {
        let Some(signal) = signal_for_fact_kind(kind_name) else {
            continue;
        };
        for f in ctx.store.by_kind(kind_name) {
            let draft = by_mod.entry(f.subject.clone()).or_default();
            draft.record_signal(
                signal,
                f.id,
                f.attr("archive").unwrap_or(""),
                f.attr("provenance"),
                f.attr("evidence_strength"),
                f.attr_int("dangerous_classes"),
                f.attr_int("classes_scanned"),
                f.attr_int("affected_classes"),
            );
        }
    }
    for draft in by_mod.values_mut() {
        draft.finalize_corroboration();
    }
    by_mod
}

/// Emit grouped security findings from finalized [`SecurityModDraft`] maps.
#[must_use]
pub fn security_findings_from_drafts(
    drafts: BTreeMap<String, SecurityModDraft>,
    min_note_signals: usize,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (mod_id, draft) in drafts {
        if !should_emit_finding_with(&draft.signals, min_note_signals) {
            continue;
        }

        let severity = combined_severity(&draft.signals);
        let structural_labels: Vec<_> = draft
            .signals
            .iter()
            .filter(|s| !draft.corroborated_only.contains(s))
            .map(|signal| {
                let base = match draft.strength.get(signal) {
                    Some(strength) => format!("{} [{}]", signal.label(), strength.as_str()),
                    None => signal.label().to_string(),
                };
                match draft.affected_classes.get(signal) {
                    Some(n) if *n > 0 => format!("{base} ({n} class(es))"),
                    _ => base,
                }
            })
            .collect();
        let structural_label_refs: Vec<&str> =
            structural_labels.iter().map(String::as_str).collect();
        let inferred_labels: Vec<_> = draft
            .corroborated_only
            .iter()
            .map(|signal| signal.label())
            .collect();

        let mut explanation = format!(
            "Static method-reference evidence in `{}` ({} of {} class(es) carry direct dangerous \
             calls) indicates: {}. These are preflight hints from constant-pool analysis \
             (MethodRef/InterfaceMethodRef), not proof of malicious runtime behavior.",
            draft.archive,
            draft.dangerous_classes,
            draft.classes_scanned,
            join_labels(&structural_label_refs),
        );
        if !inferred_labels.is_empty() {
            explanation.push_str(&format!(
                " Additionally inferred (low confidence) from string constants seen alongside \
                 reflective dispatch machinery — the obfuscated reflection pattern that leaves no \
                 direct method reference: {}.",
                join_labels(&inferred_labels),
            ));
        }

        let confidence = security_finding_confidence(
            &draft.signals,
            &draft.structural,
            &draft.corroborated_only,
            &draft.strength,
            draft.dangerous_classes,
            draft.classes_scanned,
        );

        let mut builder = Finding::builder("security-api-risk", format!("security-api-risk:{mod_id}"))
            .severity(severity)
            .category(Category::Security)
            .confidence(confidence)
            .title(format!(
                "Mod `{mod_id}` — {} security API signal(s) in {} of {} class(es)",
                draft.signals.len(),
                draft.dangerous_classes,
                draft.classes_scanned,
            ))
            .explanation(explanation)
            .affects(&mod_id)
            .fix(FixCandidate::advice(finding_advice(severity)))
            .tag("security")
            .tag("grouped");

        if !draft.corroborated_only.is_empty() {
            builder = builder.tag("reflection-corroborated");
        }
        for signal in &draft.signals {
            builder = builder.tag(signal.fact_kind());
        }
        for fact_id in draft.fact_ids {
            builder = builder.evidence(EvidenceEdge::subject(fact_id));
        }
        out.push(builder.build());
    }
    out
}

impl Rule for SecurityApiRule {
    fn id(&self) -> &'static str {
        "security-api-risk"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let drafts = aggregate_security_drafts(ctx);
        security_findings_from_drafts(drafts, ctx.settings.security.min_note_signals)
    }
}

/// Join capability labels into a human-readable list, never empty.
fn join_labels(labels: &[&str]) -> String {
    if labels.is_empty() {
        "no direct API references".to_string()
    } else {
        labels.join(", ")
    }
}

fn finding_advice(severity: Severity) -> &'static str {
    match severity {
        Severity::Warn => {
            "Review mod source and expected capabilities; remove if process spawn, unsafe memory access, \
             or dynamic class loading is unexpected for this mod."
        }
        Severity::Note => {
            "Informational preflight signal — many mods use networking, reflection, or native libraries \
             legitimately for compatibility."
        }
        _ => "Review mod documentation and source before installing.",
    }
}

/// Map a Layer-G fact predicate to its capability enum.
///
/// Declarative backends (DuckDB SQL) reuse this mapping when aggregating
/// per-mod signal rows into grouped findings.
#[must_use]
pub fn signal_for_fact_kind(kind_name: &str) -> Option<SecuritySignal> {
    Some(match kind_name {
        k if k == kind::USES_PROCESS_SPAWN => SecuritySignal::ProcessSpawn,
        k if k == kind::USES_SOCKET => SecuritySignal::Socket,
        k if k == kind::USES_REFLECTION_SET_ACCESSIBLE => SecuritySignal::ReflectionSetAccessible,
        k if k == kind::USES_UNSAFE => SecuritySignal::Unsafe,
        k if k == kind::USES_NATIVE_LIBRARY => SecuritySignal::NativeLibrary,
        k if k == kind::USES_DYNAMIC_CLASS_DEFINITION => SecuritySignal::DynamicClassDefinition,
        k if k == kind::USES_REFLECTIVE_INVOCATION => SecuritySignal::ReflectiveInvocation,
        k if k == kind::USES_SCRIPT_ENGINE => SecuritySignal::ScriptEngine,
        k if k == kind::USES_DESERIALIZATION => SecuritySignal::Deserialization,
        k if k == kind::USES_SYSTEM_EXIT => SecuritySignal::SystemExit,
        k if k == kind::USES_METHOD_HANDLES => SecuritySignal::MethodHandles,
        _ => return None,
    })
}

// ── Scanner ──────────────────────────────────────────────────────────────

pub fn scan_target(target: &Target) -> Result<SecurityScan, SecurityScanError> {
    let Some(dir) = mods_dir(target) else {
        return Err(SecurityScanError("target has no mods directory".into()));
    };
    scan_mods_dir(&dir)
}

pub fn scan_mods_dir(dir: &Path) -> Result<SecurityScan, SecurityScanError> {
    scan_mods_dir_with_cache(dir, None)
}

pub fn scan_mods_dir_with_cache(
    dir: &Path,
    cache: Option<&JarCache>,
) -> Result<SecurityScan, SecurityScanError> {
    scan_mods_dir_filtered(dir, cache, &intermed_doctor_core::ScanSettings::default())
}

/// Like [`scan_mods_dir_with_cache`] but honors incremental [`ScanSettings`].
pub fn scan_mods_dir_filtered(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
) -> Result<SecurityScan, SecurityScanError> {
    if !dir.is_dir() {
        return Err(SecurityScanError(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }

    let jars = intermed_doctor_core::list_jar_archives(dir, scan)
        .map_err(|e| SecurityScanError(format!("read {}: {e}", dir.display())))?;

    // Each jar is parsed independently; fan out across cores. `par_iter().map()`
    // preserves input order, so the aggregated output stays deterministic.
    let scanned: Vec<(String, CachedSecurityJar)> = jars
        .par_iter()
        .map(|jar| {
            let archive = file_name_of(jar);
            let cached = match cache {
                Some(c) => c.get_or_scan(EXTRACTOR, CACHE_VERSION, jar, || scan_jar_cached(jar)),
                None => scan_jar_cached(jar),
            };
            (archive, cached)
        })
        .collect();

    let mut records = Vec::new();
    let mut failures = Vec::new();
    for (archive, cached) in scanned {
        match cached {
            CachedSecurityJar::Ok(partial) => records.push(ModSecurityRecord {
                archive,
                mod_id: partial.mod_id,
                signals: partial.signals,
                classes_scanned: partial.classes_scanned,
                dangerous_classes: partial.dangerous_classes,
                signal_class_counts: partial.signal_class_counts,
                truncations: partial.truncations,
            }),
            CachedSecurityJar::Err(reason) => {
                failures.push(SecurityScanFailure { archive, reason })
            }
        }
    }

    Ok(SecurityScan {
        target: dir.display().to_string(),
        records,
        failures,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSecurityPartial {
    mod_id: String,
    signals: Vec<DetectedSignal>,
    classes_scanned: usize,
    #[serde(default)]
    dangerous_classes: usize,
    #[serde(default)]
    signal_class_counts: BTreeMap<SecuritySignal, usize>,
    #[serde(default)]
    truncations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CachedSecurityJar {
    Ok(CachedSecurityPartial),
    Err(String),
}

fn scan_jar_cached(jar: &Path) -> CachedSecurityJar {
    match scan_jar(jar) {
        Ok(partial) => CachedSecurityJar::Ok(partial),
        Err(e) => CachedSecurityJar::Err(e.to_string()),
    }
}

fn scan_jar(jar: &Path) -> Result<CachedSecurityPartial, SecurityScanError> {
    let archive = jar
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string();

    let file = std::fs::File::open(jar)
        .map_err(|e| SecurityScanError(format!("open {}: {e}", jar.display())))?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| SecurityScanError(format!("zip {}: {e}", jar.display())))?;

    // Use the shared identity detector so security facts carry the *same*
    // mod id as the SBOM/metadata layers (Fabric/Quilt/Forge/NeoForge/Bukkit/
    // Paper), not just a Fabric id or the bare file stem. Keeps cross-layer
    // correlation, dedupe and affected_components aligned.
    let mod_id = intermed_minecraft_scan::mod_id_or_stem(&mut zip, &archive);
    let mut all_signals = BTreeSet::new();
    let mut classes_scanned = 0usize;
    let mut dangerous_classes = 0usize;
    let mut signal_class_counts: BTreeMap<SecuritySignal, usize> = BTreeMap::new();
    let mut truncations: Vec<String> = Vec::new();
    let mut total_bytes: u64 = 0;

    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| SecurityScanError(format!("read {} entry {i}: {e}", jar.display())))?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        if !is_class_entry(&name) {
            continue;
        }
        if classes_scanned >= MAX_CLASSES {
            truncations.push(format!("stopped after {MAX_CLASSES} classes (archive has more)"));
            break;
        }
        if entry.size() > MAX_CLASS_BYTES {
            truncations.push(format!(
                "{name}: {} bytes exceeds {MAX_CLASS_BYTES} byte class cap, skipped",
                entry.size()
            ));
            continue;
        }
        if total_bytes >= MAX_TOTAL_CLASS_BYTES {
            truncations.push(format!(
                "reached {MAX_TOTAL_CLASS_BYTES} byte total cap; remaining classes skipped"
            ));
            break;
        }
        let mut bytes = Vec::new();
        std::io::Read::take(&mut entry, MAX_CLASS_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| SecurityScanError(format!("read {}!{name}: {e}", jar.display())))?;
        if bytes.len() as u64 > MAX_CLASS_BYTES {
            truncations.push(format!(
                "{name}: decompressed past {MAX_CLASS_BYTES} byte cap, skipped"
            ));
            continue;
        }
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        if !cp::is_class_file(&bytes) {
            continue;
        }
        if let Some(evidence) = cp::extract_class_evidence(&bytes) {
            let structural = structural_signals(&evidence);
            // A class is "dangerous" only on a structural reference, not a bare
            // string — the same precision bar the signals themselves use.
            if !structural.is_empty() {
                dangerous_classes += 1;
            }
            for signal in &structural {
                *signal_class_counts.entry(*signal).or_insert(0) += 1;
            }
            all_signals.extend(detect_signals(&evidence));
        }
        classes_scanned += 1;
    }

    Ok(CachedSecurityPartial {
        mod_id,
        signals: collapse::collapse_per_capability(all_signals),
        classes_scanned,
        dangerous_classes,
        signal_class_counts,
        truncations,
    })
}

/// Per-jar `.class` scan limits — untrusted archives can declare a huge class, a
/// zip bomb, or a flood of entries. Exceeding one records a `scan_truncated`
/// diagnostic rather than silently dropping evidence.
const MAX_CLASS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_CLASS_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CLASSES: usize = 100_000;

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

fn is_class_entry(name: &str) -> bool {
    name.ends_with(".class") && !name.contains("..")
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use detect::EvidenceStrength;

    fn record_with(signals: &[SecuritySignal]) -> ModSecurityRecord {
        ModSecurityRecord {
            archive: "m.jar".into(),
            mod_id: "m".into(),
            signals: signals
                .iter()
                .map(|&signal| DetectedSignal {
                    signal,
                    provenance: SignalProvenance::Structural,
                    strength: EvidenceStrength::Medium,
                })
                .collect(),
            classes_scanned: 1,
            dangerous_classes: 1,
            signal_class_counts: BTreeMap::new(),
            truncations: Vec::new(),
        }
    }

    #[test]
    fn emitted_numeric_attrs_are_typed_ints_not_strings() {
        use intermed_doctor_core::facts::{AttrValue, FactStore};
        use intermed_doctor_core::settings::DiagnosisSettings;

        let mut rec = record_with(&[SecuritySignal::Unsafe]);
        rec.classes_scanned = 42;
        rec.dangerous_classes = 7;
        rec.signal_class_counts.insert(SecuritySignal::Unsafe, 3);
        let scan = SecurityScan {
            target: ".".into(),
            records: vec![rec],
            failures: Vec::new(),
        };

        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let mut store = FactStore::new();
        let settings = DiagnosisSettings::default();
        let mut ctx = CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: &settings,
        };
        emit_scan(&mut ctx, &scan);

        let fact = store
            .by_kind(SecuritySignal::Unsafe.fact_kind())
            .next()
            .expect("one signal fact");
        // The DuckDB backend selects these via `val_int`; they MUST be typed Int,
        // not Str, or SQL aggregation silently reads NULL.
        assert_eq!(fact.attributes.get("classes_scanned"), Some(&AttrValue::Int(42)));
        assert_eq!(fact.attributes.get("dangerous_classes"), Some(&AttrValue::Int(7)));
        assert_eq!(fact.attributes.get("affected_classes"), Some(&AttrValue::Int(3)));
    }

    #[test]
    fn suppressed_only_for_sub_threshold_signal_sets() {
        // No signals → not "suppressed" (nothing to show).
        assert!(!is_suppressed(&record_with(&[])));
        // One note-level signal → below threshold → suppressed.
        assert!(is_suppressed(&record_with(&[SecuritySignal::Socket])));
        // A high-risk signal always emits → not suppressed.
        assert!(!is_suppressed(&record_with(&[
            SecuritySignal::ProcessSpawn
        ])));
        // Two note-level signals reach the threshold → not suppressed.
        assert!(!is_suppressed(&record_with(&[
            SecuritySignal::Socket,
            SecuritySignal::NativeLibrary,
        ])));
    }
}
