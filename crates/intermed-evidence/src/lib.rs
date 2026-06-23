//! # intermed-evidence
//!
//! Rules turn [`Fact`](intermed_facts::Fact)s into [`Finding`]s. A finding
//! always carries the [`EvidenceEdge`]s that justify it, so the eventual
//! `--explain <finding>` output (Phase 2) can show *why* InterMed concluded
//! something — never an unsourced verdict.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use intermed_facts::FactId;

/// How serious a finding is. Ordered: `Info` < `Note` < `Warn` < `Error` < `Fatal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Purely informational (e.g. "VFS layer deferred to Phase 3").
    Info,
    /// Worth knowing, not a problem.
    Note,
    /// Likely to cause trouble.
    Warn,
    /// Will very likely break the instance.
    Error,
    /// Cannot start at all.
    Fatal,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Note => "note",
            Severity::Warn => "warn",
            Severity::Error => "error",
            Severity::Fatal => "fatal",
        }
    }

    /// SARIF level mapping (`error` | `warning` | `note`).
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Fatal | Severity::Error => "error",
            Severity::Warn => "warning",
            Severity::Note | Severity::Info => "note",
        }
    }
}

/// Broad classification used for grouping and rule-pack organisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Environment,
    Metadata,
    Dependency,
    Loader,
    Log,
    Resource,
    Mixin,
    Security,
    Performance,
    Packaging,
    Runtime,
}

/// How prominently a finding is surfaced in the default report.
///
/// Not every true statement is a *problem*. A safe set-union tag merge or the 20
/// `pack.mcmeta` files in 20 jars are normal states, not findings to dump on the
/// user. Visibility lets a rule record the fact without spamming the default
/// report: it stays in the JSON (machine consumers / `--explain`) but the
/// terminal collapses it to a one-line summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingVisibility {
    /// Shown in the default report.
    #[default]
    Default,
    /// Hidden by default; shown with `--verbose`.
    Verbose,
    /// Only surfaced by explain views (e.g. `--vfs-explain-safe`). Used for
    /// "this is fine" states like safe CRDT merges.
    ExplainOnly,
    /// Only relevant when generating an overlay/PackOps preview (e.g. the
    /// `pack.mcmeta` the overlay must itself carry). Not a user-facing problem.
    OverlayOnly,
}

impl FindingVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingVisibility::Default => "default",
            FindingVisibility::Verbose => "verbose",
            FindingVisibility::ExplainOnly => "explain-only",
            FindingVisibility::OverlayOnly => "overlay-only",
        }
    }

    /// Whether this finding appears in the default (non-verbose) terminal report.
    pub fn shown_by_default(self) -> bool {
        matches!(self, FindingVisibility::Default)
    }
}

/// A structured, human-and-machine-readable summary of one piece of evidence.
///
/// Findings carry raw [`EvidenceEdge`] fact ids for full provenance, but an
/// external consumer should not have to cross-reference a fact dump to learn
/// *what* the evidence said. `evidence_summary` lifts the salient fields
/// (resource path, writers, classification, semantic diff) inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummaryItem {
    /// The fact predicate this summarizes (e.g. `resource_collision`).
    pub kind: String,
    /// Resource path / subject, when the evidence concerns one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Mods that wrote the resource, when applicable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writers: Vec<String>,
    /// Collision/merge class (`json-override`, `safe-crdt-merge`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    /// Semantic diff kind (`recipe-output-override`, `lang-key-conflict`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_kind: Option<String>,
    /// Sample values that differ (e.g. the conflicting recipe outputs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<String>,
    /// Forward-compatible escape hatch for fields not yet promoted to columns.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub detail: BTreeMap<String, String>,
}

impl EvidenceSummaryItem {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            path: None,
            writers: Vec::new(),
            classification: None,
            diff_kind: None,
            outputs: Vec::new(),
            detail: BTreeMap::new(),
        }
    }
}

/// Relation kinds for [`EvidenceEdge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// The fact directly supports the finding.
    Supports,
    /// The fact is the thing being complained about.
    Subject,
    /// The fact mentions / references another.
    Mentions,
    /// The fact contradicts an expectation.
    Violates,
    /// Two facts conflict with each other.
    ConflictsWith,
    /// Statistical / heuristic correlation.
    CorrelatesWith,
}

/// An edge in the evidence graph: a fact justifying (or relating to) a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEdge {
    pub fact: FactId,
    pub relation: Relation,
    /// 0.0..=1.0 contribution weight.
    pub weight: f32,
}

impl EvidenceEdge {
    pub fn supports(fact: FactId) -> Self {
        Self {
            fact,
            relation: Relation::Supports,
            weight: 1.0,
        }
    }
    pub fn subject(fact: FactId) -> Self {
        Self {
            fact,
            relation: Relation::Subject,
            weight: 1.0,
        }
    }
    pub fn new(fact: FactId, relation: Relation, weight: f32) -> Self {
        Self {
            fact,
            relation,
            weight: weight.clamp(0.0, 1.0),
        }
    }
}

/// A proposed remediation. Phase 1 emits human-readable candidates; later
/// phases may attach machine-applicable patches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixCandidate {
    pub description: String,
    /// Optional concrete command the user can run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// 0.0..=1.0 confidence that this fix is correct.
    pub confidence: f32,
}

impl FixCandidate {
    pub fn advice(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            command: None,
            confidence: 0.6,
        }
    }
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }
}

/// A diagnosis result: a problem (or note) with full provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable, unique id for this occurrence (e.g. `missing-dependency:create->fabric-api`).
    pub id: String,
    /// Id of the rule that produced it.
    pub rule_id: String,
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    /// Human explanation in plain language.
    pub explanation: String,
    pub evidence: Vec<EvidenceEdge>,
    /// Structured, inline summary of the cited evidence. Populated centrally at
    /// report-assembly time from the evidence facts, so consumers don't have to
    /// resolve fact ids against a dump. Empty until then.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_summary: Vec<EvidenceSummaryItem>,
    pub confidence: f32,
    /// Mods / plugins / paths this finding concerns.
    pub affected_components: Vec<String>,
    pub fix_candidates: Vec<FixCandidate>,
    /// Stable tags for machine consumers / CI filters (e.g. `["dependency", "missing"]`).
    pub machine_tags: Vec<String>,
    /// How prominently this finding is surfaced (default report vs explain-only).
    #[serde(default)]
    pub visibility: FindingVisibility,
    /// Rule ids that contributed to this finding after merge. Empty means the
    /// single `rule_id` is authoritative; populated when findings sharing an `id`
    /// from different rules are merged (e.g. a Layer-E collision absorbed into a
    /// Layer-M semantic finding, or SBOM correlation enriching a signature note).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_sources: Vec<String>,
}

/// Fluent builder so rules read declaratively.
pub struct FindingBuilder {
    finding: Finding,
}

impl Finding {
    pub fn builder(rule_id: &str, id: impl Into<String>) -> FindingBuilder {
        FindingBuilder {
            finding: Finding {
                id: id.into(),
                rule_id: rule_id.to_string(),
                severity: Severity::Warn,
                category: Category::Environment,
                title: String::new(),
                explanation: String::new(),
                evidence: Vec::new(),
                evidence_summary: Vec::new(),
                confidence: 0.9,
                affected_components: Vec::new(),
                fix_candidates: Vec::new(),
                machine_tags: Vec::new(),
                visibility: FindingVisibility::Default,
                rule_sources: Vec::new(),
            },
        }
    }
}

impl FindingBuilder {
    pub fn severity(mut self, s: Severity) -> Self {
        self.finding.severity = s;
        self
    }
    pub fn category(mut self, c: Category) -> Self {
        self.finding.category = c;
        self
    }
    pub fn title(mut self, t: impl Into<String>) -> Self {
        self.finding.title = t.into();
        self
    }
    pub fn explanation(mut self, e: impl Into<String>) -> Self {
        self.finding.explanation = e.into();
        self
    }
    pub fn evidence(mut self, e: EvidenceEdge) -> Self {
        self.finding.evidence.push(e);
        self
    }
    pub fn affects(mut self, component: impl Into<String>) -> Self {
        self.finding.affected_components.push(component.into());
        self
    }
    pub fn fix(mut self, f: FixCandidate) -> Self {
        self.finding.fix_candidates.push(f);
        self
    }
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.finding.machine_tags.push(t.into());
        self
    }
    pub fn confidence(mut self, c: f32) -> Self {
        self.finding.confidence = c.clamp(0.0, 1.0);
        self
    }
    /// Set how prominently the finding is surfaced (default vs explain-only).
    pub fn visibility(mut self, v: FindingVisibility) -> Self {
        self.finding.visibility = v;
        self
    }
    pub fn build(self) -> Finding {
        self.finding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering_and_sarif() {
        assert!(Severity::Fatal > Severity::Warn);
        assert_eq!(Severity::Warn.sarif_level(), "warning");
        assert_eq!(Severity::Fatal.sarif_level(), "error");
    }

    #[test]
    fn builds_finding_with_evidence() {
        let f = Finding::builder(
            "missing-dependency",
            "missing-dependency:create->fabric-api",
        )
        .severity(Severity::Error)
        .category(Category::Dependency)
        .title("Missing dependency: fabric-api")
        .explanation("create requires fabric-api but it is not installed.")
        .evidence(EvidenceEdge::subject(FactId(3)))
        .affects("create")
        .fix(FixCandidate::advice("Install fabric-api"))
        .tag("dependency")
        .tag("missing")
        .build();
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.evidence.len(), 1);
        assert_eq!(f.machine_tags, vec!["dependency", "missing"]);
    }
}
