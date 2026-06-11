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
use crate::target::{Environment, Loader, Side, Target, TargetKind};

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
        env.side = match f.attr("side") {
            Some("client") => Some(Side::Client),
            Some("server") => Some(Side::Server),
            Some("both") => Some(Side::Both),
            _ => None,
        };
    }
    if let Some(f) = store.by_kind(kind::JAVA_RUNTIME).next() {
        env.java_version = f.attr("version").map(str::to_string);
    }
    env
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
) -> DoctorReport {
    // Defensive de-duplication: a finding id identifies one occurrence, so if
    // two rules (or two facts) produced the same id, keep the first.
    {
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| seen.insert(f.id.clone()));
    }

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
    }
}
