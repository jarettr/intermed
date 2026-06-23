//! The `intermed-doctor-report-v1` model — the single structured artifact a
//! diagnosis produces. Renderers (`intermed-report`) turn it into terminal /
//! JSON / SARIF output; they never recompute anything.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use intermed_evidence::{EvidenceSummaryItem, Finding, FindingVisibility, FixCandidate, Severity};
use intermed_facts::{Fact, FactStore, kind};

use crate::collector::{CollectorOutcome, CollectorStatus};
use crate::instance_layout::LayoutKind;
use crate::layer::Layer;
use crate::profile::DiagnosticProfile;
use crate::target::{Environment, InstanceType, Loader, Side, Target, TargetKind};

/// Schema identifier embedded in every report (mirrors the old
/// `intermed-release-check-v1` convention).
pub const REPORT_SCHEMA: &str = "intermed-doctor-report-v1";

/// Compact view of the target for the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetView {
    pub path: String,
    pub kind: TargetKind,
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

/// Per-rule record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleStat {
    pub id: String,
    pub findings: usize,
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
    pub environment: Environment,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub fix_plan: Vec<FixPlanItem>,
    pub fact_stats: BTreeMap<String, usize>,
    pub collectors: Vec<CollectorReport>,
    pub rules: Vec<RuleStat>,
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
        if !self.summary.is_healthy() {
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
    if let Some(f) = store.by_kind(kind::ENVIRONMENT).next() {
        env.os = f.attr("os").map(str::to_string);
        env.loader = f.attr("loader").and_then(Loader::parse);
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
    }
    if env.minecraft_version.is_none() {
        env.minecraft_version = infer_minecraft_version(store);
    }
    env
}

/// The loader the scanned content targets (consensus of the per-mod / per-plugin
/// `loader` facts). Covers both mod loaders (Fabric/Forge/NeoForge) and server
/// plugin platforms (Bukkit/Spigot/Paper), which ship `plugin` facts, not `mod`.
fn infer_loader_from_mods(store: &FactStore) -> Option<Loader> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in store.by_kind(kind::MOD).chain(store.by_kind(kind::PLUGIN)) {
        if let Some(l) = f.attr("loader") {
            *counts.entry(l).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .and_then(|(l, _)| Loader::parse(l))
}

/// The Minecraft version the scanned mods target, derived from their `minecraft`
/// dependency ranges: the most common explicit patch version (`1.21.1`), falling
/// back to the most common minor (`1.21`) when no patch is pinned.
fn infer_minecraft_version(store: &FactStore) -> Option<String> {
    let mut patch: BTreeMap<String, usize> = BTreeMap::new();
    let mut minor: BTreeMap<String, usize> = BTreeMap::new();
    for f in store.by_kind(kind::DEPENDENCY) {
        if f.attr("dep") != Some("minecraft") {
            continue;
        }
        let Some(range) = f.attr("range") else {
            continue;
        };
        for tok in version_tokens(range) {
            if tok.matches('.').count() >= 2 {
                *patch.entry(tok).or_default() += 1;
            } else {
                *minor.entry(tok).or_default() += 1;
            }
        }
    }
    most_common(patch).or_else(|| most_common(minor))
}

/// The key with the highest count; ties break toward the higher version string
/// (BTreeMap iterates ascending, `max_by_key` keeps the last maximum).
fn most_common(counts: BTreeMap<String, usize>) -> Option<String> {
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(k, _)| k)
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
    item
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
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
        if has_tag("safe-merge")
            || has_tag("safe-crdt-merge")
            || f.id.contains(":safe-crdt-merge:")
            || f.id.contains(":safe-json-object-merge:")
        {
            f.visibility = FindingVisibility::ExplainOnly;
            if f.severity < Severity::Warn {
                f.severity = Severity::Info;
            }
        } else if has_tag("root-metadata") || is_pack_mcmeta_override(f) {
            // Root pack metadata (pack.mcmeta): expected, only matters for overlays.
            f.visibility = FindingVisibility::OverlayOnly;
            if f.severity < Severity::Warn {
                f.severity = Severity::Info;
            }
        }
    }
}

/// A byte-level resource-conflict finding whose subject path is a `pack.mcmeta`.
fn is_pack_mcmeta_override(f: &Finding) -> bool {
    f.id.starts_with("resource-conflict:")
        && (f.id.ends_with("/pack.mcmeta") || f.id.ends_with(":pack.mcmeta"))
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

/// Assemble the final report from everything gathered during a run.
#[allow(clippy::too_many_arguments)]
pub fn assemble(
    tool_version: &str,
    target: &Target,
    store: &FactStore,
    mut findings: Vec<Finding>,
    collectors: Vec<(&'static str, Layer, CollectorOutcome)>,
    rule_stats: Vec<RuleStat>,
    profile: Option<DiagnosticProfile>,
) -> DoctorReport {
    // 1. Collapse findings that share an id into one (unique-id contract).
    merge_findings_by_id(&mut findings);
    // 2. Fold cross-layer duplicates (Layer-E collision ↔ Layer-M semantic diff
    //    on the same path) into the more meaningful finding.
    crate::suppression::apply_semantic_override_suppression(&mut findings);
    // 2b. Downgrade static resource findings a data-pack script removes/replaces.
    crate::suppression::apply_runtime_caveats(&mut findings, store);
    // 3. Demote "normal state" findings (safe merges, pack.mcmeta) so the default
    //    report can collapse them.
    apply_visibility_policy(&mut findings);
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

    let summary = Summary::tally(&findings);

    let fix_plan = findings
        .iter()
        .flat_map(|f| {
            f.fix_candidates.iter().map(move |fc| FixPlanItem {
                finding_id: f.id.clone(),
                severity: f.severity,
                fix: fc.clone(),
            })
        })
        .collect();

    let mut collector_reports = Vec::new();
    let mut deferred_layers = Vec::new();
    for (id, layer, outcome) in collectors {
        if outcome.status == CollectorStatus::Deferred {
            deferred_layers.push(DeferredLayer {
                layer_code: layer.code().to_string(),
                layer: layer.label().to_string(),
                phase: layer.phase(),
                note: outcome.message.clone(),
            });
        }
        let status = match outcome.status {
            CollectorStatus::Active => "active",
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

    DoctorReport {
        schema: REPORT_SCHEMA.to_string(),
        tool_version: tool_version.to_string(),
        generated_at: Utc::now(),
        target: TargetView {
            path: target.path.display().to_string(),
            kind: target.kind,
        },
        environment: environment_from_facts(store),
        summary,
        findings,
        fix_plan,
        fact_stats: store.stats(),
        collectors: collector_reports,
        rules: rule_stats,
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
    fn most_common_breaks_ties_toward_higher_version() {
        // The neoforge_new tie (1.21.1 ×3 vs 1.21.2 ×3) must resolve to 1.21.1 once
        // the excluded `1.21.2)` ceilings are dropped by version_tokens; here we
        // only check the tie-break direction of most_common itself.
        let mut m = BTreeMap::new();
        m.insert("1.21.1".to_string(), 2);
        m.insert("1.21.2".to_string(), 2);
        assert_eq!(most_common(m).as_deref(), Some("1.21.2"));
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
                "resource-conflict:json-override:assets/foo/pack.mcmeta",
            )
            .severity(Severity::Note)
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
