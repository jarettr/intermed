//! Declarative rule-pack data model (v1 + v2).
//!
//! v2 extends v1 with [`RuleKind::Join`], [`RuleKind::Aggregate`], and
//! [`RuleKind::Correlation`] so one JSON pack can drive the interpreter,
//! DuckDB SQL codegen, and Soufflé Datalog codegen.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Unsigned legacy rule-pack schema.
pub const RULE_PACK_SCHEMA: &str = "intermed-rule-pack-v1";

/// Signed distributable rule-pack schema with extended rule kinds.
pub const RULE_PACK_SCHEMA_V2: &str = "intermed-rule-pack-v2";

/// Rule-pack marketplace / auto-update index schema.
pub const RULE_REGISTRY_SCHEMA: &str = "intermed-rule-registry-v1";

/// Declarative evaluation strategy supported by all rule backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleKind {
    /// Group matching facts and emit one finding when at least `min_count`
    /// distinct values exist in the group.
    GroupDistinct,
    /// Emit one finding for each matching fact.
    FactFinding,
    /// Join two fact sources and emit one finding per matching row pair.
    Join,
    /// Group rows from one source and filter with `having`.
    Aggregate,
    /// Correlate an anchor fact with related facts (e.g. SBOM × security).
    Correlation,
}

/// A small, backend-neutral rule pack. Facts are selected by predicate and
/// attributes; findings are emitted from templates with evidence edges back to
/// source facts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RulePack {
    pub schema: String,
    pub id: String,
    /// Semver string for marketplace updates (v2 packs; defaults for v1).
    #[serde(default)]
    pub version: String,
    /// Publisher id matching a registry entry.
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
    /// Detached Ed25519 signature (v2 only).
    #[serde(default)]
    pub signature: Option<crate::signing::RulePackSignature>,
}

/// One declarative rule. v1 rules use `input_kinds` / `where_all`; v2 join and
/// aggregate rules use [`FactSource`] arms and expression strings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleSpec {
    pub id: String,
    pub kind: RuleKind,
    #[serde(default)]
    pub input_kinds: Vec<String>,
    /// Binding alias for a `fact-finding` rule's `where` expression (default `f`),
    /// e.g. `alias: "m"` + `where: "m.loader = 'fabric'"`.
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub where_all: BTreeMap<String, String>,
    #[serde(default)]
    pub where_not: BTreeMap<String, String>,
    #[serde(default)]
    pub group_by: Option<String>,
    #[serde(default)]
    pub group_by_fields: Vec<String>,
    #[serde(default)]
    pub distinct: Option<String>,
    #[serde(default = "default_min_count")]
    pub min_count: usize,
    #[serde(default)]
    pub left: Option<FactSource>,
    #[serde(default)]
    pub right: Option<FactSource>,
    #[serde(default)]
    pub on: Option<String>,
    #[serde(default)]
    pub r#where: Option<String>,
    #[serde(default)]
    pub having: Option<String>,
    #[serde(default)]
    pub input: Option<FactSource>,
    #[serde(default)]
    pub anchor: Option<FactSource>,
    #[serde(default)]
    pub related_kinds: Vec<String>,
    #[serde(default)]
    pub match_on: Option<String>,
    #[serde(default)]
    pub settings_refs: BTreeMap<String, String>,
    #[serde(default)]
    pub evidence: Option<RelatedEvidenceSpec>,
    pub finding: FindingTemplate,
}

/// One arm of a join / aggregate / correlation rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactSource {
    pub kind: String,
    pub alias: String,
    #[serde(default)]
    pub select: Vec<String>,
}

/// Optional extra evidence edges beyond the primary matched facts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelatedEvidenceSpec {
    pub kind: String,
    /// Expression relating primary alias to related facts, e.g.
    /// `primary.subject = related.attr:path`.
    pub on: String,
    #[serde(default = "default_conflicts_with")]
    pub relation: String,
    #[serde(default = "default_evidence_weight")]
    pub weight: f32,
}

/// Finding fields with `{alias.field}` / `{attr:name}` template placeholders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingTemplate {
    pub id: String,
    /// Override [`RuleSpec::id`] on emitted findings (stable parent rule id).
    #[serde(default)]
    pub rule_id: Option<String>,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub explanation: String,
    #[serde(default)]
    pub fix: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Components this finding affects, as `{alias.field}` / `{attr:name}` /
    /// literal templates. Defaults to the primary fact's subject when empty, but
    /// a join finding (e.g. `known-incompatible`) should declare *both* sides so
    /// "issues affecting mod X" surfaces it from either mod.
    #[serde(default)]
    pub affects: Vec<String>,
}

fn default_min_count() -> usize {
    1
}

fn default_conflicts_with() -> String {
    "conflicts_with".to_string()
}

fn default_evidence_weight() -> f32 {
    0.8
}