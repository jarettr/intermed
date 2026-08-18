//! # intermed-evidence
//!
//! Rules turn [`Fact`](intermed_facts::Fact)s into [`Finding`]s. A finding
//! always carries the [`EvidenceEdge`]s that justify it, so the eventual
//! `--explain <finding>` output (Phase 2) can show *why* InterMed concluded
//! something — never an unsourced verdict.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use intermed_facts::FactId;

pub mod graph;
pub mod identity;
pub mod incident;

pub use graph::{
    ArtifactNode, BridgeCapability, CompatibilityBridge, EvidenceGraph, EvidenceLink,
    EvidenceRelation, EvidenceStrength, ModInstanceNode,
};
pub use identity::{
    ArtifactId, ClassSymbol, DependencyEdgeId, DescriptorKind, EntityRef, MappingGraphId,
    MappingNamespace, MethodDescriptor, MethodSymbol, MixinSiteId, ModInstanceId, RecommendationId,
    ResourceKey, RuntimeOccurrenceId, ThrowableId,
};
pub use incident::{CausalNode, CausalTransition, Contributor, Incident};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

/// Coverage which must be trustworthy before a finding may be treated as a
/// conclusive absence/incompatibility assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageRequirement {
    LocalArtifact,
    CompletePack,
    CompleteClasspath,
    RuntimeEvidence,
    RuntimeProfile,
    CompleteProviderUniverse,
    AuthoritativeLoader,
    ActiveDescriptor,
    KnownBridgeSemantics,
    CompatibleMappings,
    ApplicableMixin,
    CompleteResourceBlobs,
    RelevantResources,
    CompleteVanillaBaseline,
    KnownRuntimeMutators,
    TerminalRuntime,
}

/// Strength of the derivation represented by a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofKind {
    Observation,
    DeterministicDerivation,
    Heuristic,
}

/// Runtime observation capable of refuting a static conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeRefutability {
    ClassPresence,
    ExactMethodPresence,
    AppliedMixin,
    DependencyUse,
}

/// Provenance class of evidence contributing to a conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceOrigin {
    ObservedRuntime,
    StaticExact,
    StaticInferred,
    Heuristic,
    ReconstructedInput,
    HostObservation,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssessmentDisposition {
    Asserted,
    Downgraded,
    #[default]
    Abstained,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertaintyTier {
    Confirmed,
    Probable,
    Possible,
    #[default]
    Undecidable,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Impact {
    StartupBlocking,
    RuntimeFailure,
    DataLossRisk,
    CompatibilityRisk,
    PerformanceDegradation,
    SecurityReview,
    PackHealth,
    #[default]
    Informational,
}

/// Product surface on which a conclusion belongs. This is semantic report
/// policy, not a presentation tag.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingChannel {
    Incident,
    Compatibility,
    #[default]
    PackHealth,
    DeveloperLint,
    Informational,
}

/// Semantic condition proposed by a rule. Cross-layer reconciliation dispatches
/// on this type rather than parsing presentation ids or tags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConclusionKind {
    MissingDependency,
    WrongVersion,
    LoaderMismatch,
    ClassAbsent,
    MethodAbsent,
    DependencyUnused,
    StaticResourceState,
    RuntimeIncident,
    #[default]
    Generic,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMutationCoverage {
    NoMutatorEvidence,
    MutatorPresent,
    ExactTargetModified,
    CoveragePartial,
    #[default]
    Unavailable,
}

impl FindingChannel {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incident => "incident",
            Self::Compatibility => "compatibility",
            Self::PackHealth => "pack-health",
            Self::DeveloperLint => "developer-lint",
            Self::Informational => "informational",
        }
    }
}

impl From<&str> for FindingChannel {
    fn from(value: &str) -> Self {
        match value {
            "incident" | "incident-diagnosis" => Self::Incident,
            "compatibility" => Self::Compatibility,
            "developer-lint" => Self::DeveloperLint,
            "informational" | "context" => Self::Informational,
            _ => Self::PackHealth,
        }
    }
}

impl From<String> for FindingChannel {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrerequisiteResult {
    pub requirement: CoverageRequirement,
    pub satisfied: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageAssessment {
    pub region: String,
    pub state: CoverageState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrerequisiteFailure {
    pub code: String,
    pub requirement: CoverageRequirement,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConclusionAdjustment {
    pub code: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_disposition: Option<AssessmentDisposition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_disposition: Option<AssessmentDisposition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contradicting_evidence: Vec<FactId>,
}

/// Final trust contract produced by the assessment engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingAssessment {
    pub disposition: AssessmentDisposition,
    pub impact: Impact,
    pub certainty: CertaintyTier,
    pub proof_kind: ProofKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prerequisites: Vec<PrerequisiteResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage: Vec<CoverageAssessment>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub provenance: BTreeSet<EvidenceOrigin>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<PrerequisiteFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adjustments: Vec<ConclusionAdjustment>,
}

impl Default for FindingAssessment {
    fn default() -> Self {
        Self {
            disposition: AssessmentDisposition::Abstained,
            impact: Impact::Informational,
            certainty: CertaintyTier::Undecidable,
            proof_kind: ProofKind::Heuristic,
            prerequisites: Vec::new(),
            coverage: Vec::new(),
            provenance: BTreeSet::new(),
            blockers: Vec::new(),
            adjustments: Vec::new(),
        }
    }
}

/// A machine-readable reason why an input region is not fully covered.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CoverageGap {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub detail: String,
}

impl CoverageGap {
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            scope: None,
            detail: detail.into(),
        }
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

/// Completeness of one evidence/input region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum CoverageState {
    Complete,
    Partial { gaps: Vec<CoverageGap> },
    Unavailable { reasons: Vec<CoverageGap> },
}

impl Default for CoverageState {
    fn default() -> Self {
        Self::Unavailable {
            reasons: vec![CoverageGap::new(
                "coverage-not-recorded",
                "the source report predates explicit coverage state",
            )],
        }
    }
}

impl CoverageState {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    pub fn gaps(&self) -> &[CoverageGap] {
        match self {
            Self::Complete => &[],
            Self::Partial { gaps } => gaps,
            Self::Unavailable { reasons } => reasons,
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendationAction {
    Install,
    Update,
    Remove,
    Replace,
    Configure,
    ProvideInput,
    Inspect,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecommendationSafety {
    ReadOnly,
    Reversible,
    ReviewRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: RecommendationId,
    pub action: RecommendationAction,
    pub target: EntityRef,
    pub rationale: String,
    pub safety: RecommendationSafety,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<FactId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_findings: Vec<String>,
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
    /// Stable semantic identity used to compare equivalent conclusions across
    /// runs. Unlike `id`, it need not identify a physical occurrence.
    #[serde(default)]
    pub semantic_id: String,
    /// Physical occurrence identity, when the conclusion is occurrence-bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence_id: Option<String>,
    /// Stable conclusion family for grouping and policy; never inferred from an
    /// id prefix by the assessment engine.
    #[serde(default)]
    pub family: String,
    /// Product surface such as `incident`, `pack-health`, or `context`.
    #[serde(default)]
    pub channel: FindingChannel,
    #[serde(default)]
    pub conclusion_kind: ConclusionKind,
    /// Id of the rule that produced it.
    pub rule_id: String,
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    /// Human explanation in plain language.
    pub explanation: String,
    pub evidence: Vec<EvidenceEdge>,
    /// Typed, traversable path through the cross-layer evidence graph.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_path: Vec<EvidenceLink>,
    /// Structured, inline summary of the cited evidence. Populated centrally at
    /// report-assembly time from the evidence facts, so consumers don't have to
    /// resolve fact ids against a dump. Empty until then.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_summary: Vec<EvidenceSummaryItem>,
    pub confidence: f32,
    /// Mods / plugins / paths this finding concerns.
    pub affected_components: Vec<String>,
    pub fix_candidates: Vec<FixCandidate>,
    /// Stable, deduplicated recommendation objects are stored at report level.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommendation_ids: Vec<RecommendationId>,
    #[serde(default)]
    pub runtime_mutation_coverage: RuntimeMutationCoverage,
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
    /// Typed prerequisites used by cross-layer certainty policy. This replaces
    /// safety decisions based on finding-id naming conventions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_requirements: Vec<CoverageRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_kind: Option<ProofKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_refutability: Vec<RuntimeRefutability>,
    /// Candidate impact proposed by the rule before central assessment.
    #[serde(default)]
    pub proposed_impact: Impact,
    /// Evidence provenance declared by the producing rule.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub evidence_origins: BTreeSet<EvidenceOrigin>,
    /// Canonical v2 trust assessment. Populated centrally before reporting.
    #[serde(default)]
    pub assessment: FindingAssessment,
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
                semantic_id: String::new(),
                occurrence_id: None,
                family: String::new(),
                channel: FindingChannel::default(),
                conclusion_kind: ConclusionKind::default(),
                rule_id: rule_id.to_string(),
                severity: Severity::Warn,
                category: Category::Environment,
                title: String::new(),
                explanation: String::new(),
                evidence: Vec::new(),
                evidence_path: Vec::new(),
                evidence_summary: Vec::new(),
                confidence: 0.9,
                affected_components: Vec::new(),
                fix_candidates: Vec::new(),
                recommendation_ids: Vec::new(),
                runtime_mutation_coverage: RuntimeMutationCoverage::Unavailable,
                machine_tags: Vec::new(),
                visibility: FindingVisibility::Default,
                rule_sources: Vec::new(),
                coverage_requirements: Vec::new(),
                proof_kind: None,
                runtime_refutability: Vec::new(),
                proposed_impact: Impact::Informational,
                evidence_origins: BTreeSet::new(),
                assessment: FindingAssessment::default(),
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
    pub fn coverage_requirement(mut self, requirement: CoverageRequirement) -> Self {
        if !self.finding.coverage_requirements.contains(&requirement) {
            self.finding.coverage_requirements.push(requirement);
        }
        self
    }
    pub fn proof_kind(mut self, proof_kind: ProofKind) -> Self {
        self.finding.proof_kind = Some(proof_kind);
        self
    }
    pub fn impact(mut self, impact: Impact) -> Self {
        self.finding.proposed_impact = impact;
        self
    }
    pub fn evidence_origin(mut self, origin: EvidenceOrigin) -> Self {
        self.finding.evidence_origins.insert(origin);
        self
    }
    pub fn family(mut self, family: impl Into<String>) -> Self {
        self.finding.family = family.into();
        self
    }
    pub fn channel(mut self, channel: impl Into<FindingChannel>) -> Self {
        self.finding.channel = channel.into();
        self
    }
    pub fn conclusion_kind(mut self, kind: ConclusionKind) -> Self {
        self.finding.conclusion_kind = kind;
        self
    }
    pub fn semantic_id(mut self, semantic_id: impl Into<String>) -> Self {
        self.finding.semantic_id = semantic_id.into();
        self
    }
    pub fn occurrence_id(mut self, occurrence_id: impl Into<String>) -> Self {
        self.finding.occurrence_id = Some(occurrence_id.into());
        self
    }
    pub fn runtime_refutability(mut self, refutability: RuntimeRefutability) -> Self {
        if !self.finding.runtime_refutability.contains(&refutability) {
            self.finding.runtime_refutability.push(refutability);
        }
        self
    }
    /// Set how prominently the finding is surfaced (default vs explain-only).
    pub fn visibility(mut self, v: FindingVisibility) -> Self {
        self.finding.visibility = v;
        self
    }
    pub fn build(self) -> Finding {
        let mut finding = self.finding;
        if finding.semantic_id.is_empty() {
            finding.semantic_id = finding.id.clone();
        }
        if finding.family.is_empty() {
            finding.family = finding.rule_id.clone();
        }
        if finding.channel == FindingChannel::PackHealth {
            finding.channel = match finding.category {
                Category::Runtime | Category::Log => FindingChannel::Incident,
                Category::Dependency | Category::Loader | Category::Environment => {
                    FindingChannel::Compatibility
                }
                Category::Mixin if finding.visibility != FindingVisibility::Default => {
                    FindingChannel::DeveloperLint
                }
                Category::Metadata
                | Category::Resource
                | Category::Mixin
                | Category::Security
                | Category::Performance
                | Category::Packaging => FindingChannel::PackHealth,
            };
        }
        finding
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
