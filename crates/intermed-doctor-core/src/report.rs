//! The `intermed-doctor-report-v2` model — the single structured artifact a
//! diagnosis produces. Renderers (`intermed-report`) turn it into terminal /
//! JSON / SARIF output; they never recompute anything.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use intermed_evidence::{
    AssessmentDisposition, CertaintyTier, EvidenceSummaryItem, Finding, FindingVisibility,
    FixCandidate, Severity,
};
use intermed_facts::{Fact, FactStore, kind};

use crate::collector::{CollectorOutcome, CollectorStatus};
use crate::instance_layout::LayoutKind;
use crate::layer::Layer;
use crate::profile::DiagnosticProfile;
use crate::scope::TargetCapabilities;
use crate::target::{Environment, InstanceType, Loader, Side, Target, TargetKind};

/// Schema identifier embedded in every report (mirrors the old
/// `intermed-release-check-v1` convention).
pub const REPORT_SCHEMA_V1: &str = "intermed-doctor-report-v1";
pub const REPORT_SCHEMA_V2: &str = "intermed-doctor-report-v2";
pub const REPORT_SCHEMA: &str = REPORT_SCHEMA_V2;

/// Compact view of the target for the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetView {
    pub path: String,
    pub kind: TargetKind,
}

/// Environment of the InterMed process itself. It is deliberately separate
/// from [`DoctorReport::environment`], which describes the analyzed target.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisEnvironment {
    pub os: Option<String>,
    pub java_version: Option<String>,
}

/// Severity histogram + overall verdict.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub fatal: usize,
    pub error: usize,
    pub warn: usize,
    pub note: usize,
    pub info: usize,
    pub total: usize,
    /// Default-surface fatal/error conclusions with sufficient certainty.
    #[serde(default)]
    pub confirmed_problems: usize,
    /// Default-surface warnings that require human review.
    #[serde(default)]
    pub needs_review: usize,
    /// Findings or operational results that explicitly mark analysis incomplete.
    #[serde(default)]
    pub incomplete_analysis: usize,
    /// Default-surface note/info context, not a confirmed problem.
    #[serde(default)]
    pub context: usize,
    /// Raw detail retained outside the default report surface.
    #[serde(default)]
    pub hidden_details: usize,
    /// Highest severity present, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worst: Option<Severity>,
}

impl Summary {
    fn tally(findings: &[Finding]) -> Self {
        let mut s = Summary::default();
        for f in findings {
            match f.severity {
                Severity::Fatal => s.fatal += 1,
                Severity::Error => s.error += 1,
                Severity::Warn => s.warn += 1,
                Severity::Note => s.note += 1,
                Severity::Info => s.info += 1,
            }
            s.worst = Some(s.worst.map_or(f.severity, |w| w.max(f.severity)));
            if f.visibility != FindingVisibility::Default {
                s.hidden_details += 1;
                continue;
            }
            let incomplete = !f.assessment.blockers.is_empty()
                || f.assessment
                    .coverage
                    .iter()
                    .any(|coverage| !coverage.state.is_complete())
                || (matches!(f.severity, Severity::Fatal | Severity::Error)
                    && (f.assessment.disposition != AssessmentDisposition::Asserted
                        || f.assessment.certainty != CertaintyTier::Confirmed));
            if incomplete {
                s.incomplete_analysis += 1;
            } else {
                match f.severity {
                    Severity::Fatal | Severity::Error => s.confirmed_problems += 1,
                    Severity::Warn => s.needs_review += 1,
                    Severity::Note | Severity::Info => s.context += 1,
                }
            }
        }
        s.total = findings.len();
        s
    }

    /// True when nothing at `Error` or above was found.
    pub fn is_healthy(&self) -> bool {
        self.fatal == 0 && self.error == 0
    }
}

/// Per-collector record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectorReport {
    pub id: String,
    pub layer: Layer,
    pub layer_code: String,
    pub phase: u8,
    pub status: String,
    pub facts_emitted: usize,
    pub message: String,
}

/// Effective analysis configuration recorded with the result, after config,
/// environment, and CLI precedence have all been resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisConfiguration {
    pub enabled_collectors: Vec<String>,
    pub disabled_collectors: Vec<String>,
    pub mixin: MixinAnalysisConfiguration,
    /// Reproduction identity for the analyzer build and effective inputs.
    #[serde(default)]
    pub fingerprint: AnalyzerFingerprint,
    /// Content-addressed inputs observed by collectors (primarily mod JARs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_manifest: Vec<InputFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputFingerprint {
    pub kind: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerFingerprint {
    pub git_commit: Option<String>,
    pub git_dirty: Option<bool>,
    pub cargo_features: Vec<String>,
    pub effective_config_sha256: Option<String>,
    pub rule_pack_sha256: Option<String>,
    pub minecraft_jar_sha256: Option<String>,
    pub mappings_sha256: Option<String>,
    pub target_manifest_sha256: Option<String>,
    pub cache_mode: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinAnalysisConfiguration {
    pub enabled: bool,
    pub level: String,
    pub handler_effects: bool,
    pub recommendations: bool,
    pub minecraft_jar_supplied: bool,
    pub mappings_supplied: bool,
}

/// Auditable passport for Layer F. Counts describe what was actually discovered
/// and resolved, while hashes bind the result to the supplied game/mapping data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinCoveragePassport {
    pub status: String,
    pub reason: String,
    pub configs_discovered: usize,
    pub configs_parsed: usize,
    pub mixin_classes: usize,
    pub target_classes: usize,
    pub target_classes_resolved: usize,
    pub target_methods: usize,
    pub target_methods_resolved: usize,
    pub namespaces: Vec<String>,
    pub classpath_level: Option<String>,
    pub minecraft_classes: usize,
    pub mod_classes: usize,
    pub minecraft_namespace: Option<String>,
    pub unresolved_targets: usize,
    pub truncations: usize,
    pub minecraft_jar_sha256: Option<String>,
    pub mappings_source: Option<String>,
    pub mappings_sha256: Option<String>,
}

impl Default for MixinCoveragePassport {
    fn default() -> Self {
        Self {
            status: "unavailable".to_string(),
            reason: "Layer F was not registered in this report".to_string(),
            configs_discovered: 0,
            configs_parsed: 0,
            mixin_classes: 0,
            target_classes: 0,
            target_classes_resolved: 0,
            target_methods: 0,
            target_methods_resolved: 0,
            namespaces: Vec::new(),
            classpath_level: None,
            minecraft_classes: 0,
            mod_classes: 0,
            minecraft_namespace: None,
            unresolved_targets: 0,
            truncations: 0,
            minecraft_jar_sha256: None,
            mappings_source: None,
            mappings_sha256: None,
        }
    }
}

/// Per-rule record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleStat {
    pub id: String,
    pub findings: usize,
}

/// A pipeline component failed to complete. Kept separate from domain findings
/// so `--exit-zero` cannot turn an incomplete analysis into a successful run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalError {
    pub stage: String,
    pub component: String,
    pub message: String,
}

/// A consolidated remediation item in the fix plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixPlanItem {
    pub finding_id: String,
    pub severity: Severity,
    pub fix: FixCandidate,
}

/// A layer that did not run because it belongs to a later phase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeferredLayer {
    pub layer_code: String,
    pub layer: String,
    pub phase: u8,
    pub note: String,
}

/// The full diagnosis result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema: String,
    pub tool_version: String,
    pub generated_at: DateTime<Utc>,
    pub target: TargetView,
    #[serde(default)]
    pub analysis_environment: AnalysisEnvironment,
    pub environment: Environment,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub fix_plan: Vec<FixPlanItem>,
    pub fact_stats: BTreeMap<String, usize>,
    pub collectors: Vec<CollectorReport>,
    #[serde(default)]
    pub analysis_configuration: AnalysisConfiguration,
    #[serde(default)]
    pub mixin_coverage: MixinCoveragePassport,
    #[serde(default)]
    pub target_capabilities: TargetCapabilities,
    pub rules: Vec<RuleStat>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operational_errors: Vec<OperationalError>,
    pub deferred_layers: Vec<DeferredLayer>,
    /// Wall-clock phase timings and jar-cache counters (present in `--json` output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<DiagnosticProfile>,
    // evidence_graph: serialized per-finding via `findings[].evidence` in v1.
    // attachments: reserved for Phase 7+ (spark/JFR payloads).
}

impl DoctorReport {
    /// Process exit code convention: 0 healthy, 1 warnings only, 2 errors+.
    pub fn exit_code(&self) -> i32 {
        if !self.operational_errors.is_empty() || !self.summary.is_healthy() {
            2
        } else if self.summary.warn > 0 {
            1
        } else {
            0
        }
    }
}

/// Build the [`Environment`] projection from environment-level facts.
fn environment_from_facts(store: &FactStore) -> Environment {
    let mut env = Environment::default();
    let mut filesystem_loader = None;
    if let Some(f) = store.by_kind(kind::ENVIRONMENT).next() {
        env.os = f.attr("os").map(str::to_string);
        env.loader = f.attr("loader").and_then(Loader::parse);
        env.loader_source = f.attr("loader_source").map(str::to_string);
        if env.loader_source.as_deref() == Some("filesystem-heuristic") {
            filesystem_loader = env.loader.take();
            env.loader_source = None;
        }
        env.minecraft_version = f.attr("mc_version").map(str::to_string);
        env.launcher = f.attr("launcher").map(str::to_string);
        env.host_launcher = f.attr("host_launcher").map(str::to_string);
        env.layout = f.attr("layout").and_then(parse_layout_kind);
        env.instance_type = f.attr("instance_type").and_then(parse_instance_type);
        env.side = f
            .attr("side")
            .and_then(parse_side)
            .or_else(|| env.instance_type.map(InstanceType::to_side));
    }
    if let Some(f) = store.by_kind(kind::JAVA_RUNTIME).next() {
        env.java_version = f.attr("version").map(str::to_string);
    }
    // A bare mods dir (or any target without a real instance) carries no loader /
    // Minecraft version of its own. The scanned mods do, though: every `mod` fact
    // records its loader, and the `minecraft` dependency ranges pin the game
    // version. Infer both so the report does not show "?" for facts it can derive.
    if env.loader.is_none() {
        env.loader = infer_loader_from_mods(store);
        if env.loader.is_some() {
            env.loader_source = Some("artifact-consensus".to_string());
        }
    }
    if env.loader.is_none() {
        env.loader = filesystem_loader;
        if env.loader.is_some() {
            env.loader_source = Some("filesystem-heuristic".to_string());
        }
    }
    if env.minecraft_version.is_none() {
        env.minecraft_version = infer_minecraft_version(store);
    }
    env
}

fn analysis_environment_from_facts(store: &FactStore) -> AnalysisEnvironment {
    let Some(fact) = store.by_kind(kind::ANALYSIS_ENVIRONMENT).next() else {
        return AnalysisEnvironment::default();
    };
    AnalysisEnvironment {
        os: fact.attr("os").map(str::to_string),
        java_version: fact.attr("java").map(str::to_string),
    }
}

/// The loader the scanned content targets (consensus of the per-mod / per-plugin
/// `loader` facts). Covers both mod loaders (Fabric/Forge/NeoForge) and server
/// plugin platforms (Bukkit/Spigot/Paper), which ship `plugin` facts, not `mod`.
fn infer_loader_from_mods(store: &FactStore) -> Option<Loader> {
    let mut loaders = std::collections::BTreeSet::new();
    for f in store
        .by_kind(kind::MOD)
        .chain(store.by_kind(kind::PLUGIN))
        .filter(|fact| fact.attr("identity_certainty") != Some("undecidable"))
    {
        if let Some(l) = f.attr("loader")
            && Loader::parse(l).is_some()
        {
            loaders.insert(l);
        }
    }
    // A majority is not an instance baseline: one foreign-loader jar is exactly
    // the situation the mixed-loader rule must expose. Infer only a unanimous
    // loader family; otherwise keep it unknown.
    (loaders.len() == 1)
        .then(|| loaders.first().copied())
        .flatten()
        .and_then(Loader::parse)
}

/// Infer Minecraft only from a cross-artifact consensus. A single malformed
/// descriptor must not define the whole instance (legacy coremods sometimes
/// carry copied `mods.toml` templates with the wrong game version).
fn infer_minecraft_version(store: &FactStore) -> Option<String> {
    let mut candidates_by_artifact: BTreeMap<String, std::collections::BTreeSet<String>> =
        BTreeMap::new();
    let mod_files: BTreeMap<&str, &str> = store
        .by_kind(kind::MOD)
        .filter(|fact| fact.attr("identity_certainty") != Some("undecidable"))
        .filter_map(|fact| fact.attr("file").map(|file| (fact.subject.as_str(), file)))
        .collect();
    for f in store.by_kind(kind::DEPENDENCY) {
        if f.attr("identity_certainty") == Some("undecidable") {
            continue;
        }
        if f.attr("dep") != Some("minecraft") {
            continue;
        }
        let Some(range) = f.attr("range") else {
            continue;
        };
        for token in version_tokens(range) {
            if plausible_minecraft_version(&token) {
                candidates_by_artifact
                    .entry(
                        mod_files
                            .get(f.subject.as_str())
                            .copied()
                            .unwrap_or(f.subject.as_str())
                            .to_string(),
                    )
                    .or_default()
                    .insert(token);
            }
        }
    }

    // Filenames are secondary corroboration, not authority. They are useful for
    // old Forge packs whose descriptors omit Minecraft entirely. If one mod's
    // filename and descriptor disagree, that mod casts no vote.
    for f in store
        .by_kind(kind::MOD)
        .filter(|fact| fact.attr("identity_certainty") != Some("undecidable"))
    {
        let Some(file) = f.attr("file") else {
            continue;
        };
        for token in version_tokens(file) {
            if plausible_minecraft_version(&token) {
                candidates_by_artifact
                    .entry(file.to_string())
                    .or_default()
                    .insert(token);
            }
        }
    }

    // Legacy Forge jars often have no recognized modern descriptor at all.
    // Checksums are emitted once per scanned archive, so their subjects provide
    // a complete filename census without counting the same jar once per alias.
    for f in store
        .by_kind(kind::CHECKSUM)
        .filter(|fact| fact.attr("input_kind") != Some("runtime-log"))
    {
        for token in version_tokens(&f.subject) {
            if plausible_minecraft_version(&token) {
                candidates_by_artifact
                    .entry(f.subject.clone())
                    .or_default()
                    .insert(token);
            }
        }
    }

    let mut patch: BTreeMap<String, usize> = BTreeMap::new();
    let mut minor: BTreeMap<String, usize> = BTreeMap::new();
    for candidates in candidates_by_artifact.values() {
        if candidates.len() != 1 {
            continue;
        }
        let candidate = candidates.iter().next().expect("one candidate").clone();
        if candidate.matches('.').count() >= 2 {
            *patch.entry(candidate).or_default() += 1;
        } else {
            *minor.entry(candidate).or_default() += 1;
        }
    }
    consensus_version(patch).or_else(|| consensus_version(minor))
}

fn plausible_minecraft_version(version: &str) -> bool {
    let mut parts = version.split('.');
    matches!(parts.next(), Some("1"))
        && parts
            .next()
            .and_then(|minor| minor.parse::<u16>().ok())
            .is_some_and(|minor| (7..=99).contains(&minor))
}

/// Require at least two agreeing artifacts and a unique winner. With weaker
/// evidence, leaving the environment unknown is safer than inventing a version.
fn consensus_version(counts: BTreeMap<String, usize>) -> Option<String> {
    let mut ranked: Vec<_> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
    let (version, support) = ranked.first()?;
    if *support < 2 || ranked.get(1).is_some_and(|(_, next)| next == support) {
        return None;
    }
    Some(version.clone())
}

/// Extract dotted version tokens (`1.21`, `1.21.1`) that the pack actually targets
/// from a dependency range string. Operators / wildcards are ignored
/// (`>=1.21 <=1.21.1`, `1.21.x`, `~1.20`), and **exclusive upper bounds are
/// skipped** — in `[1.21.1,1.21.2)` the `1.21.2` is the excluded ceiling (the real
/// target is `1.21.1`), so counting it would bias the inferred version too high.
/// A token is an exclusive upper bound when it is immediately followed by `)` or
/// immediately preceded by `<` (but not `<=`, which is inclusive).
fn version_tokens(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        let tok = s[start..i].trim_matches('.');
        let after_excludes = bytes.get(i) == Some(&b')');
        let prev = s[..start].trim_end();
        let before_excludes = prev.ends_with('<') && !prev.ends_with("<=");
        if tok.contains('.') && !after_excludes && !before_excludes {
            out.push(tok.to_string());
        }
    }
    out
}

fn parse_side(value: &str) -> Option<Side> {
    match value {
        "client" => Some(Side::Client),
        "server" => Some(Side::Server),
        "both" => Some(Side::Both),
        _ => None,
    }
}

fn parse_instance_type(value: &str) -> Option<InstanceType> {
    match value {
        "server" => Some(InstanceType::Server),
        "client" => Some(InstanceType::Client),
        "integrated" => Some(InstanceType::Integrated),
        _ => None,
    }
}

fn parse_layout_kind(value: &str) -> Option<LayoutKind> {
    match value {
        "prism-instance" => Some(LayoutKind::PrismInstance),
        "multimc-instance" => Some(LayoutKind::MultiMcInstance),
        "dot-minecraft" => Some(LayoutKind::DotMinecraft),
        "curseforge-pack" => Some(LayoutKind::CurseForgePack),
        "modrinth-pack" => Some(LayoutKind::ModrinthPack),
        "dedicated-server" => Some(LayoutKind::DedicatedServer),
        "bare-mods-dir" => Some(LayoutKind::BareModsDir),
        "unknown" => Some(LayoutKind::Unknown),
        _ => None,
    }
}

/// Merge findings that share an `id` so that **`finding.id` is unique within a
/// report** — the contract grouping, diffing, and history all depend on.
///
/// A finding's `id` is its occurrence identity. When two rules produce the same
/// id they are, by contract, describing the same occurrence (e.g. the imperative
/// `sbom-provenance` rule and the declarative `unsigned-jar` rule both flagging
/// the same unsigned jar). Rather than emit a duplicate, we fold them into one:
/// keep the higher-severity copy as the base, union the evidence edges and tags,
/// and record every contributing rule id in `rule_sources`. If two rules want to
/// say *semantically different* things they must use *different* ids.
fn merge_findings_by_id(findings: &mut Vec<Finding>) {
    let mut by_id: BTreeMap<String, usize> = BTreeMap::new();
    let mut keep = vec![true; findings.len()];
    for i in 0..findings.len() {
        let id = findings[i].id.clone();
        match by_id.get(&id).copied() {
            None => {
                by_id.insert(id, i);
            }
            Some(base) => {
                // Decide which copy is the base (higher severity wins; ties keep
                // the earlier one for stable ordering).
                let (winner, loser) = if findings[i].severity > findings[base].severity {
                    by_id.insert(id, i);
                    keep[base] = false;
                    (i, base)
                } else {
                    keep[i] = false;
                    (base, i)
                };
                merge_into(findings, winner, loser);
            }
        }
    }
    let mut iter = keep.into_iter();
    findings.retain(|_| iter.next().unwrap_or(true));
}

/// Fold `loser`'s provenance into `winner` (evidence, tags, rule sources, fixes).
fn merge_into(findings: &mut [Finding], winner: usize, loser: usize) {
    let loser_evidence = findings[loser].evidence.clone();
    let loser_tags = findings[loser].machine_tags.clone();
    let loser_rule = findings[loser].rule_id.clone();
    let loser_sources = findings[loser].rule_sources.clone();
    let loser_fixes = findings[loser].fix_candidates.clone();
    let loser_components = findings[loser].affected_components.clone();
    let loser_requirements = findings[loser].coverage_requirements.clone();
    let loser_refutability = findings[loser].runtime_refutability.clone();
    let loser_proof = findings[loser].proof_kind;

    let w = &mut findings[winner];
    for e in loser_evidence {
        if !w
            .evidence
            .iter()
            .any(|x| x.fact == e.fact && x.relation == e.relation)
        {
            w.evidence.push(e);
        }
    }
    for tag in loser_tags {
        if !w.machine_tags.contains(&tag) {
            w.machine_tags.push(tag);
        }
    }
    for comp in loser_components {
        if !w.affected_components.contains(&comp) {
            w.affected_components.push(comp);
        }
    }
    for requirement in loser_requirements {
        if !w.coverage_requirements.contains(&requirement) {
            w.coverage_requirements.push(requirement);
        }
    }
    for refutability in loser_refutability {
        if !w.runtime_refutability.contains(&refutability) {
            w.runtime_refutability.push(refutability);
        }
    }
    if w.proof_kind.is_none() {
        w.proof_kind = loser_proof;
    }
    for fix in loser_fixes {
        if !w
            .fix_candidates
            .iter()
            .any(|x| x.description == fix.description)
        {
            w.fix_candidates.push(fix);
        }
    }
    // Record both rule ids as contributing sources (skip the winner's own id).
    for src in std::iter::once(loser_rule).chain(loser_sources) {
        if src != w.rule_id && !w.rule_sources.contains(&src) {
            w.rule_sources.push(src);
        }
    }
    w.rule_sources.sort();
    w.rule_sources.dedup();
}

/// Build a structured [`EvidenceSummaryItem`] from a fact, lifting the salient
/// attributes so report consumers don't have to resolve fact ids against a dump.
fn evidence_summary_item(fact: &Fact) -> EvidenceSummaryItem {
    let mut item = EvidenceSummaryItem::new(fact.kind.clone());
    // Prefer an explicit `path` attribute (e.g. a `resource_writer`'s subject is
    // the mod id, but its `path` attr is the actual resource path); fall back to
    // the subject for facts whose subject *is* the path (collisions, diffs).
    item.path = fact
        .attr("path")
        .map(str::to_string)
        .or_else(|| (!fact.subject.is_empty()).then(|| fact.subject.clone()));
    let writers = fact
        .attr("writers")
        .or_else(|| fact.attr("archives"))
        .map(split_csv)
        .unwrap_or_default();
    item.writers = writers;
    // A `resource_writer` fact's subject is the single writing mod; surface it as
    // a writer when the fact carried a resource `path` rather than a writer list.
    if item.writers.is_empty() && fact.attr("path").is_some() && !fact.subject.is_empty() {
        item.writers = vec![fact.subject.clone()];
    }
    item.classification = fact.attr("class").map(str::to_string);
    item.diff_kind = fact.attr("diff_kind").map(str::to_string);
    // Domain-specific salient values worth showing inline.
    if let Some(detail) = fact.attr("detail") {
        item.detail.insert("detail".to_string(), detail.to_string());
    }
    if let Some(reason) = fact.attr("reason") {
        item.detail.insert("reason".to_string(), reason.to_string());
    }
    for key in ["occurrence_id", "semantic_fingerprint"] {
        if let Some(value) = fact.attr(key) {
            item.detail.insert(key.to_string(), value.to_string());
        }
    }
    item
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Some(format!("{:x}", hash.finalize()))
}

fn fact_usize(fact: &Fact, attr: &str) -> usize {
    fact.attr_int(attr)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0)
}

fn mixin_coverage_passport(
    store: &FactStore,
    collectors: &[CollectorReport],
    settings: &crate::settings::DiagnosisSettings,
) -> MixinCoveragePassport {
    let collector = collectors
        .iter()
        .find(|collector| collector.layer == Layer::Mixin);
    let coverage = store.by_kind(kind::MIXIN_CLASSPATH_COVERAGE).next();
    let mut passport = MixinCoveragePassport {
        status: collector
            .map(|collector| collector.status.clone())
            .unwrap_or_else(|| "unavailable".to_string()),
        reason: collector
            .map(|collector| collector.message.clone())
            .unwrap_or_else(|| "Layer F was not registered".to_string()),
        minecraft_jar_sha256: settings.minecraft_jar.as_deref().and_then(sha256_file),
        mappings_source: settings
            .minecraft_mappings
            .as_ref()
            .map(|path| path.display().to_string()),
        mappings_sha256: settings.minecraft_mappings.as_deref().and_then(sha256_file),
        ..Default::default()
    };
    if let Some(fact) = coverage {
        passport.configs_discovered = fact_usize(fact, "configs_discovered");
        passport.configs_parsed = fact_usize(fact, "configs_parsed");
        passport.mixin_classes = fact_usize(fact, "mixin_classes");
        passport.target_classes = fact_usize(fact, "target_classes");
        passport.target_classes_resolved = fact_usize(fact, "target_classes_resolved");
        passport.target_methods = fact_usize(fact, "target_methods");
        passport.target_methods_resolved = fact_usize(fact, "target_methods_resolved");
        passport.namespaces = fact.attr("namespaces").map(split_csv).unwrap_or_default();
        passport.classpath_level = fact.attr("level").map(str::to_string);
        passport.minecraft_classes = fact_usize(fact, "minecraft_classes");
        passport.mod_classes = fact_usize(fact, "mod_classes");
        passport.minecraft_namespace = fact.attr("minecraft_namespace").map(str::to_string);
        passport.unresolved_targets = fact_usize(fact, "unresolved_targets");
        passport.truncations = fact_usize(fact, "truncations");
    }
    passport
}

/// Classify findings that describe a *normal state* rather than a problem so the
/// default report can collapse them instead of dumping one line each.
///
/// Two cases the roadmap calls out explicitly:
/// * **Safe CRDT merges** — a set-union tag merge is the correct, expected result;
///   195 of them is not 195 problems. → `ExplainOnly`.
/// * **`pack.mcmeta` overrides** — every resource pack ships one; 20 jars carrying
///   20 `pack.mcmeta` is expected. The override only matters when an overlay is
///   generated (which carries its own). → `OverlayOnly`.
///
/// These are demoted to `Info` so they never dominate the severity histogram, but
/// stay in the JSON for `--explain` / overlay tooling.
fn apply_visibility_policy(findings: &mut [Finding]) {
    for f in findings.iter_mut() {
        let has_tag = |t: &str| f.machine_tags.iter().any(|x| x == t);
        // Any proven-safe merge (CRDT set union, disjoint object union) is a
        // normal state, not a problem.
        if has_tag("safe-merge") || has_tag("safe-crdt-merge") {
            f.visibility = FindingVisibility::ExplainOnly;
            if f.severity < Severity::Warn {
                f.severity = Severity::Info;
            }
        } else if has_tag("root-metadata") {
            // Root pack metadata (pack.mcmeta): expected, only matters for overlays.
            f.visibility = FindingVisibility::OverlayOnly;
            if f.severity < Severity::Warn {
                f.severity = Severity::Info;
            }
        } else if f.severity <= Severity::Note && has_tag("mixin-detail") {
            // Full mixin mode intentionally emits site-level evidence, but tens
            // of thousands of informational rows must not bury errors/warnings
            // in human reports. The records remain in JSON and explain views.
            f.visibility = FindingVisibility::Verbose;
        }
    }
}

/// Populate each finding's `evidence_summary` from the facts its evidence cites.
/// Centralized here so every rule benefits without per-rule code.
fn populate_evidence_summaries(findings: &mut [Finding], store: &FactStore) {
    for f in findings.iter_mut() {
        if !f.evidence_summary.is_empty() {
            continue; // a rule provided its own richer summary; respect it.
        }
        let mut summary = Vec::new();
        for edge in &f.evidence {
            if let Some(fact) = store.get(edge.fact) {
                summary.push(evidence_summary_item(fact));
            }
        }
        f.evidence_summary = summary;
    }
}

fn cluster_resource_conflicts(findings: &mut Vec<Finding>, store: &FactStore) {
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        if !finding.id.starts_with("recipe-output-override:") {
            continue;
        }
        let writers = finding.evidence.iter().find_map(|edge| {
            store
                .get(edge.fact)
                .and_then(|fact| fact.attr("writers"))
                .map(|writers| {
                    let mut writers = split_csv(writers);
                    writers.sort();
                    writers.join(" <-> ")
                })
        });
        if let Some(writers) = writers.filter(|writers| !writers.is_empty()) {
            groups.entry(writers).or_default().push(index);
        }
    }

    let mut clustered = Vec::new();
    for (writers, indexes) in groups.into_iter().filter(|(_, indexes)| indexes.len() >= 3) {
        let severity = indexes
            .iter()
            .map(|index| findings[*index].severity)
            .max()
            .unwrap_or(Severity::Warn);
        let paths = indexes
            .iter()
            .filter_map(|index| findings[*index].affected_components.first().cloned())
            .collect::<Vec<_>>();
        let sample = paths
            .iter()
            .take(12)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let id_pair = writers
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
            .collect::<String>();
        let mut builder = Finding::builder(
            "resource-semantics",
            format!("recipe-output-override-cluster:{id_pair}"),
        )
        .severity(severity)
        .category(intermed_evidence::Category::Resource)
        .title(format!(
            "{} recipe output overrides between {writers}",
            indexes.len()
        ))
        .explanation(format!(
            "The same writer pair overrides {} recipe outputs. Review this as one load-order \
             decision. Resources: {}{}",
            indexes.len(),
            sample,
            if paths.len() > 12 {
                format!(" … and {} more", paths.len() - 12)
            } else {
                String::new()
            }
        ))
        .tag("resource")
        .tag("recipe")
        .tag("cluster")
        .confidence(0.9)
        .affects(writers.clone())
        .fix(FixCandidate::advice(
            "Choose the intended recipe owner for this writer pair and encode that decision in a small compatibility data pack instead of relying on load order.",
        ));
        for index in &indexes {
            findings[*index].visibility = FindingVisibility::ExplainOnly;
            findings[*index]
                .machine_tags
                .push("clustered-detail".to_string());
            for evidence in &findings[*index].evidence {
                builder = builder.evidence(evidence.clone());
            }
        }
        clustered.push(builder.build());
    }
    findings.extend(clustered);
}

/// Assemble a report with default analysis settings.
#[allow(clippy::too_many_arguments)]
pub fn assemble(
    tool_version: &str,
    target: &Target,
    store: &FactStore,
    findings: Vec<Finding>,
    collectors: Vec<(&'static str, Layer, CollectorOutcome)>,
    rule_stats: Vec<RuleStat>,
    operational_errors: Vec<OperationalError>,
    profile: Option<DiagnosticProfile>,
) -> DoctorReport {
    assemble_with_settings(
        tool_version,
        target,
        store,
        findings,
        collectors,
        rule_stats,
        operational_errors,
        profile,
        &crate::settings::DiagnosisSettings::default(),
    )
}

/// Assemble the final report from everything gathered during a configured run.
#[allow(clippy::too_many_arguments)]
pub fn assemble_with_settings(
    tool_version: &str,
    target: &Target,
    store: &FactStore,
    findings: Vec<Finding>,
    collectors: Vec<(&'static str, Layer, CollectorOutcome)>,
    rule_stats: Vec<RuleStat>,
    operational_errors: Vec<OperationalError>,
    profile: Option<DiagnosticProfile>,
    settings: &crate::settings::DiagnosisSettings,
) -> DoctorReport {
    let target_capabilities = TargetCapabilities::derive(target, store, &collectors, settings);
    assemble_with_settings_and_capabilities(
        tool_version,
        target,
        store,
        findings,
        collectors,
        rule_stats,
        operational_errors,
        profile,
        settings,
        target_capabilities,
    )
}

/// Assemble a configured report using the scope-derived capabilities evaluated
/// by the engine before snapshot compaction.
#[allow(clippy::too_many_arguments)]
pub fn assemble_with_settings_and_capabilities(
    tool_version: &str,
    target: &Target,
    store: &FactStore,
    mut findings: Vec<Finding>,
    collectors: Vec<(&'static str, Layer, CollectorOutcome)>,
    rule_stats: Vec<RuleStat>,
    mut operational_errors: Vec<OperationalError>,
    profile: Option<DiagnosticProfile>,
    settings: &crate::settings::DiagnosisSettings,
    target_capabilities: TargetCapabilities,
) -> DoctorReport {
    // 1. Collapse findings that share an id into one (unique-id contract).
    merge_findings_by_id(&mut findings);
    // 2. Fold cross-layer duplicates (Layer-E collision ↔ Layer-M semantic diff
    //    on the same path) into the more meaningful finding.
    crate::suppression::apply_semantic_override_suppression(&mut findings);
    // 2b. Downgrade static resource findings a data-pack script removes/replaces.
    crate::suppression::apply_runtime_caveats(&mut findings, store);
    // 2c. Turn repetitive writer-pair recipe overrides into one actionable card;
    // raw per-resource findings remain in JSON/ExplainOnly.
    cluster_resource_conflicts(&mut findings, store);
    // Report-generated aggregate findings pass through the same trust contract
    // as rule output. Re-assessment is idempotent and preserves explicit
    // contradiction adjustments made by the cross-layer engine.
    crate::assessment::assess_findings(
        store,
        &target_capabilities,
        &mut findings,
        settings.scan.changed_since.is_some(),
    );
    // 3. Demote "normal state" findings (safe merges, pack.mcmeta) so the default
    //    report can collapse them.
    apply_visibility_policy(&mut findings);
    for finding in &mut findings {
        let channel = if finding.channel == "incident" {
            "incident-diagnosis"
        } else {
            "pack-health-static-review"
        };
        if !finding.machine_tags.iter().any(|tag| tag == channel) {
            finding.machine_tags.push(channel.to_string());
        }
    }
    // 4. Lift the cited facts into an inline, structured evidence summary.
    populate_evidence_summaries(&mut findings, store);

    debug_assert!(
        {
            let mut ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
            ids.sort_unstable();
            let before = ids.len();
            ids.dedup();
            ids.len() == before
        },
        "finding ids must be unique within a report after merge"
    );

    // Stable ordering: worst severity first, then by id.
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));

    let mut summary = Summary::tally(&findings);

    let mut seen_fixes = std::collections::BTreeSet::new();
    let mut fix_plan = Vec::new();
    for finding in findings
        .iter()
        .filter(|finding| finding.visibility == FindingVisibility::Default)
    {
        for fix in &finding.fix_candidates {
            let key = (fix.description.clone(), fix.command.clone());
            if seen_fixes.insert(key) {
                fix_plan.push(FixPlanItem {
                    finding_id: finding.id.clone(),
                    severity: finding.severity,
                    fix: fix.clone(),
                });
            }
        }
    }

    let mut collector_reports = Vec::new();
    let mut deferred_layers = Vec::new();
    for (id, layer, outcome) in collectors {
        if outcome.status == CollectorStatus::Failed {
            operational_errors.push(OperationalError {
                stage: "collector".to_string(),
                component: id.to_string(),
                message: outcome.message.clone(),
            });
        }
        if outcome.status == CollectorStatus::Deferred {
            deferred_layers.push(DeferredLayer {
                layer_code: layer.code().to_string(),
                layer: layer.label().to_string(),
                phase: layer.phase(),
                note: outcome.message.clone(),
            });
        }
        let status = match outcome.status {
            CollectorStatus::Disabled => "disabled",
            CollectorStatus::Active => "active",
            CollectorStatus::Incomplete => "incomplete",
            CollectorStatus::Skipped => "skipped",
            CollectorStatus::Deferred => "deferred",
            CollectorStatus::Failed => "failed",
        };
        collector_reports.push(CollectorReport {
            id: id.to_string(),
            layer,
            layer_code: layer.code().to_string(),
            phase: layer.phase(),
            status: status.to_string(),
            facts_emitted: outcome.facts_emitted,
            message: outcome.message,
        });
    }
    summary.incomplete_analysis += collector_reports
        .iter()
        .filter(|collector| matches!(collector.status.as_str(), "incomplete" | "failed"))
        .count();
    summary.incomplete_analysis += operational_errors
        .iter()
        .filter(|error| error.stage != "collector")
        .count();

    let enabled_collectors = collector_reports
        .iter()
        .filter(|collector| collector.status != "disabled")
        .map(|collector| collector.id.clone())
        .collect();
    let disabled_collectors = collector_reports
        .iter()
        .filter(|collector| collector.status == "disabled")
        .map(|collector| collector.id.clone())
        .collect();
    let mixin_enabled = collector_reports
        .iter()
        .any(|collector| collector.layer == Layer::Mixin && collector.status != "disabled");
    let analysis_configuration = AnalysisConfiguration {
        enabled_collectors,
        disabled_collectors,
        mixin: MixinAnalysisConfiguration {
            enabled: mixin_enabled,
            level: settings.mixin.level.as_str().to_string(),
            handler_effects: settings.mixin.handler_effects,
            recommendations: settings.mixin.recommendations,
            minecraft_jar_supplied: settings.minecraft_jar.is_some(),
            mappings_supplied: settings.minecraft_mappings.is_some(),
        },
        fingerprint: AnalyzerFingerprint::default(),
        input_manifest: store
            .by_kind(kind::CHECKSUM)
            .filter(|fact| fact.attr("algorithm") == Some("sha256"))
            .filter_map(|fact| {
                fact.attr("hex").map(|sha256| InputFingerprint {
                    kind: fact.attr("input_kind").unwrap_or("mod-archive").to_string(),
                    path: fact.subject.clone(),
                    sha256: sha256.to_string(),
                })
            })
            .collect(),
    };
    let mixin_coverage = mixin_coverage_passport(store, &collector_reports, settings);

    DoctorReport {
        schema: REPORT_SCHEMA.to_string(),
        tool_version: tool_version.to_string(),
        generated_at: Utc::now(),
        target: TargetView {
            path: target.path.display().to_string(),
            kind: target.kind,
        },
        analysis_environment: analysis_environment_from_facts(store),
        environment: environment_from_facts(store),
        summary,
        findings,
        fix_plan,
        fact_stats: store.stats(),
        collectors: collector_reports,
        analysis_configuration,
        mixin_coverage,
        target_capabilities,
        rules: rule_stats,
        operational_errors,
        deferred_layers,
        profile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_id: &str, id: &str, sev: Severity) -> Finding {
        Finding::builder(rule_id, id).severity(sev).build()
    }

    #[test]
    fn version_tokens_skip_exclusive_upper_bounds() {
        // `[1.21.1,1.21.2)` targets 1.21.1; 1.21.2 is the excluded ceiling.
        assert_eq!(version_tokens("[1.21.1,1.21.2)"), vec!["1.21.1"]);
        // `<` exclusive upper is skipped, `<=` inclusive is kept.
        assert_eq!(version_tokens(">=1.21 <1.22"), vec!["1.21"]);
        assert_eq!(version_tokens(">=1.21 <=1.21.1"), vec!["1.21", "1.21.1"]);
        // Exact pins, wildcards, tildes.
        assert_eq!(version_tokens("[1.21.1]"), vec!["1.21.1"]);
        assert_eq!(version_tokens("1.21.x"), vec!["1.21"]);
        assert_eq!(version_tokens("~1.20"), vec!["1.20"]);
    }

    #[test]
    fn version_consensus_rejects_ties() {
        let mut m = BTreeMap::new();
        m.insert("1.21.1".to_string(), 2);
        m.insert("1.21.2".to_string(), 2);
        assert_eq!(consensus_version(m), None);
    }

    #[test]
    fn recipe_overrides_cluster_by_writer_pair_without_losing_raw_detail() {
        let mut store = FactStore::new();
        let mut findings = Vec::new();
        for index in 0..4 {
            let path = format!("data/example/recipe/{index}.json");
            let fact = store
                .fact("resource", kind::RESOURCE_SEMANTIC_DIFF)
                .subject(path.clone())
                .attr("writers", "addon,base")
                .emit();
            findings.push(
                Finding::builder("resource", format!("recipe-output-override:{path}"))
                    .severity(Severity::Warn)
                    .category(intermed_evidence::Category::Resource)
                    .evidence(intermed_evidence::EvidenceEdge::subject(fact))
                    .affects(path)
                    .build(),
            );
        }
        cluster_resource_conflicts(&mut findings, &store);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.id.starts_with("recipe-output-override-cluster:"))
                .count(),
            1
        );
        assert!(
            findings
                .iter()
                .filter(|finding| finding.id.starts_with("recipe-output-override:data/"))
                .all(|finding| finding.visibility == FindingVisibility::ExplainOnly)
        );
    }

    #[test]
    fn artifact_consensus_outranks_filesystem_loader_hint() {
        let mut store = FactStore::new();
        store
            .fact("environment-detector", kind::ENVIRONMENT)
            .attr("loader", "forge")
            .attr("loader_source", "filesystem-heuristic")
            .emit();
        for id in ["fabric-a", "fabric-b"] {
            store
                .fact("metadata", kind::MOD)
                .subject(id)
                .attr("loader", "fabric")
                .emit();
        }
        let environment = environment_from_facts(&store);
        assert_eq!(environment.loader, Some(Loader::Fabric));
        assert_eq!(
            environment.loader_source.as_deref(),
            Some("artifact-consensus")
        );
    }

    #[test]
    fn filesystem_loader_is_last_resort_after_ambiguous_artifacts() {
        let mut store = FactStore::new();
        store
            .fact("environment-detector", kind::ENVIRONMENT)
            .attr("loader", "forge")
            .attr("loader_source", "filesystem-heuristic")
            .emit();
        for (id, loader) in [("fabric-mod", "fabric"), ("forge-mod", "forge")] {
            store
                .fact("metadata", kind::MOD)
                .subject(id)
                .attr("loader", loader)
                .emit();
        }
        let environment = environment_from_facts(&store);
        assert_eq!(environment.loader, Some(Loader::Forge));
        assert_eq!(
            environment.loader_source.as_deref(),
            Some("filesystem-heuristic")
        );
    }

    #[test]
    fn environment_version_uses_cross_artifact_consensus() {
        let mut store = FactStore::new();
        for (id, file) in [
            ("good-a", "GoodA-1.12.2-2.0.jar"),
            ("good-b", "GoodB-mc1.12.2-3.0.jar"),
            ("bad-a", "BadA-1.12.2-1.0.jar"),
            ("bad-b", "BadB-1.12.2-1.0.jar"),
        ] {
            store
                .fact("test", kind::MOD)
                .subject(id)
                .attr("file", file)
                .emit();
        }
        // Copied or otherwise incorrect descriptors disagree with their own
        // archives and therefore cannot redefine the whole instance.
        for id in ["bad-a", "bad-b"] {
            store
                .fact("test", kind::DEPENDENCY)
                .subject(id)
                .attr("dep", "minecraft")
                .attr("range", "[1.14.4]")
                .emit();
        }
        assert_eq!(infer_minecraft_version(&store).as_deref(), Some("1.12.2"));
    }

    #[test]
    fn one_dependency_cannot_define_an_unknown_instance() {
        let mut store = FactStore::new();
        store
            .fact("test", kind::DEPENDENCY)
            .subject("one-mod")
            .attr("dep", "minecraft")
            .attr("range", "[1.14.4]")
            .emit();
        assert_eq!(infer_minecraft_version(&store), None);
    }

    #[test]
    fn legacy_filename_census_outvotes_copied_modern_descriptors() {
        let mut store = FactStore::new();
        for n in 0..12 {
            store
                .fact("test", kind::CHECKSUM)
                .subject(format!("legacy-{n}-mc1.12.2-2.0.jar"))
                .attr("sha256", format!("{n:064x}"))
                .emit();
        }
        for n in 0..2 {
            let id = format!("bad-{n}");
            let file = format!("addon-{n}-3.0.0.jar");
            store
                .fact("test", kind::MOD)
                .subject(id.clone())
                .attr("file", file)
                .emit();
            store
                .fact("test", kind::DEPENDENCY)
                .subject(id)
                .attr("dep", "minecraft")
                .attr("range", "[1.14.4]")
                .emit();
        }
        assert_eq!(infer_minecraft_version(&store).as_deref(), Some("1.12.2"));

        let retention = intermed_facts::FactRetentionPolicy {
            max_facts: 0,
            ..Default::default()
        };
        store.compact(&retention);
        assert_eq!(
            infer_minecraft_version(&store).as_deref(),
            Some("1.12.2"),
            "environment evidence must survive full-scan compaction"
        );
    }

    #[test]
    fn merge_collapses_distinct_rules_sharing_an_id() {
        let mut findings = vec![
            finding("rule-a", "foo", Severity::Warn),
            finding("rule-b", "foo", Severity::Error),
        ];
        merge_findings_by_id(&mut findings);
        // Same id from different rules → one finding (unique-id contract), with
        // the higher severity and both rules recorded as sources.
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].rule_id, "rule-b");
        assert!(findings[0].rule_sources.contains(&"rule-a".to_string()));
    }

    #[test]
    fn safe_crdt_merge_is_explain_only_and_demoted() {
        let mut findings = vec![
            Finding::builder(
                "resource-conflict",
                "resource-conflict:safe-crdt-merge:data/c/tags/items/x.json",
            )
            .severity(Severity::Note)
            .tag("safe-crdt-merge")
            .build(),
        ];
        apply_visibility_policy(&mut findings);
        assert_eq!(findings[0].visibility, FindingVisibility::ExplainOnly);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn pack_mcmeta_override_is_overlay_only() {
        let mut findings = vec![
            Finding::builder(
                "resource-conflict",
                "resource-conflict:root-metadata:pack.mcmeta",
            )
            .severity(Severity::Note)
            .tag("root-metadata")
            .build(),
        ];
        apply_visibility_policy(&mut findings);
        assert_eq!(findings[0].visibility, FindingVisibility::OverlayOnly);
        // A non-pack.mcmeta json-override stays default-visible.
        let mut other = vec![
            Finding::builder(
                "resource-conflict",
                "resource-conflict:json-override:data/c/recipes/x.json",
            )
            .severity(Severity::Warn)
            .build(),
        ];
        apply_visibility_policy(&mut other);
        assert_eq!(other[0].visibility, FindingVisibility::Default);
    }

    #[test]
    fn informational_mixin_site_details_are_verbose_but_warnings_remain_visible() {
        let mut findings = vec![
            Finding::builder("mixin-risk", "mixin-effect-summary:site-a")
                .severity(Severity::Note)
                .tag("mixin-detail")
                .build(),
            Finding::builder("mixin-risk", "mixin-interaction:site-b")
                .severity(Severity::Warn)
                .tag("mixin-detail")
                .build(),
        ];
        apply_visibility_policy(&mut findings);
        assert_eq!(findings[0].visibility, FindingVisibility::Verbose);
        assert_eq!(findings[1].visibility, FindingVisibility::Default);
    }

    #[test]
    fn merge_collapses_same_rule_keeping_higher_severity() {
        let mut findings = vec![
            finding("rule-a", "foo", Severity::Warn),
            finding("rule-a", "foo", Severity::Error),
        ];
        merge_findings_by_id(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        // Same rule on both copies → no spurious self-reference in sources.
        assert!(findings[0].rule_sources.is_empty());
    }
}
