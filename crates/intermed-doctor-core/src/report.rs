//! The `intermed-doctor-report-v1` model — the single structured artifact a
//! diagnosis produces. Renderers (`intermed-report`) turn it into terminal /
//! JSON / SARIF output; they never recompute anything.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use intermed_evidence::{Finding, FixCandidate, Severity};
use intermed_facts::{kind, FactStore};

use crate::collector::{CollectorOutcome, CollectorStatus};
use crate::layer::Layer;
use crate::profile::DiagnosticProfile;
use crate::instance_layout::LayoutKind;
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
    env
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

/// De-duplicate findings by `(rule_id, id)`.
///
/// The identity of a finding occurrence is the pair `(rule_id, id)`. The *same*
/// rule re-emitting the same id is a true duplicate (e.g. the imperative and
/// declarative backends of one rule agreeing). Two *different* rules that happen
/// to pick the same id are distinct findings and must both survive — collapsing
/// them by bare id would silently hide a backend disagreement. On a genuine
/// within-rule duplicate we keep the higher-severity copy.
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut by_key: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut keep = vec![true; findings.len()];
    for i in 0..findings.len() {
        let key = (findings[i].rule_id.clone(), findings[i].id.clone());
        if let Some(&prev) = by_key.get(&key) {
            if findings[i].severity > findings[prev].severity {
                keep[prev] = false;
                by_key.insert(key, i);
            } else {
                keep[i] = false;
            }
        } else {
            by_key.insert(key, i);
        }
    }
    let mut iter = keep.into_iter();
    findings.retain(|_| iter.next().unwrap_or(true));
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
    dedup_findings(&mut findings);

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
    fn dedup_keeps_distinct_rules_sharing_an_id() {
        let mut findings = vec![
            finding("rule-a", "foo", Severity::Warn),
            finding("rule-b", "foo", Severity::Error),
        ];
        dedup_findings(&mut findings);
        // Different rules, same id → both kept (backend disagreement visible).
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn dedup_collapses_same_rule_keeping_higher_severity() {
        let mut findings = vec![
            finding("rule-a", "foo", Severity::Warn),
            finding("rule-a", "foo", Severity::Error),
        ];
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
    }
}
