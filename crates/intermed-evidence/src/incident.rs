//! Structured, cross-layer runtime incident model.

use serde::{Deserialize, Serialize};

use crate::{EntityRef, EvidenceLink, FindingAssessment, RecommendationId, RuntimeOccurrenceId};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalNode {
    pub throwable_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub entity: EntityRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalTransition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<EntityRef>,
    pub callee: EntityRef,
    pub rationale: String,
    pub ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contributor {
    pub entity: EntityRef,
    pub role: String,
    pub evidence: Vec<intermed_facts::FactId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub semantic_id: String,
    pub strict_fingerprint: String,
    pub fuzzy_fingerprint: String,
    pub occurrences: Vec<RuntimeOccurrenceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_cause: Option<CausalNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_transition: Option<CausalTransition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributors: Vec<Contributor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub background_events: Vec<RuntimeOccurrenceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_entities: Vec<EntityRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_path: Vec<EvidenceLink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommendations: Vec<RecommendationId>,
    pub assessment: FindingAssessment,
}
