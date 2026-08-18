//! Typed cross-layer evidence and artifact-containment graph.

use std::collections::{BTreeMap, BTreeSet};

use intermed_facts::FactId;
use serde::{Deserialize, Serialize};

use crate::{ArtifactId, CoverageState, EntityRef, EvidenceOrigin, ModInstanceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRelation {
    Contains,
    Embeds,
    Declares,
    Provides,
    Owns,
    Ships,
    References,
    Loads,
    Calls,
    Transforms,
    AppliesTo,
    ConflictsWith,
    Corroborates,
    Contradicts,
    Refines,
    CausedBy,
    ObservedIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceStrength {
    Exact,
    Strong,
    Corroborating,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLink {
    pub from: EntityRef,
    pub relation: EvidenceRelation,
    pub to: EntityRef,
    pub origin: EvidenceOrigin,
    pub strength: EvidenceStrength,
    pub source_fact: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BridgeCapability {
    ApiSurface,
    MetadataCompatibility,
    ClassloadingCompatibility,
    RuntimeCompatibility,
    ResourceCompatibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityBridge {
    pub artifact: ArtifactId,
    pub source_family: String,
    pub target_family: String,
    pub capabilities: BTreeSet<BridgeCapability>,
    pub evidence: Vec<FactId>,
    pub coverage: CoverageState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactNode {
    pub id: ArtifactId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locators: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedded_artifacts: Vec<ArtifactId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModInstanceNode {
    pub id: ModInstanceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loader: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGraph {
    #[serde(default)]
    pub call_slice_coverage: CoverageState,
    #[serde(default)]
    pub resource_graph_coverage: CoverageState,
    /// Facts establishing graph completeness. These remain addressable after
    /// post-rule snapshot compaction even when no finding cites them directly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_evidence: Vec<FactId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mods: Vec<ModInstanceNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<EntityRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<EvidenceLink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bridges: Vec<CompatibilityBridge>,
}

impl EvidenceGraph {
    pub fn normalize(&mut self) {
        let mut artifacts = BTreeMap::<ArtifactId, ArtifactNode>::new();
        for mut artifact in self.artifacts.drain(..) {
            artifact.locators.sort();
            artifact.locators.dedup();
            artifact.embedded_artifacts.sort();
            artifact.embedded_artifacts.dedup();
            artifacts
                .entry(artifact.id.clone())
                .and_modify(|current| {
                    current.locators.extend(artifact.locators.clone());
                    current
                        .embedded_artifacts
                        .extend(artifact.embedded_artifacts.clone());
                    current.locators.sort();
                    current.locators.dedup();
                    current.embedded_artifacts.sort();
                    current.embedded_artifacts.dedup();
                })
                .or_insert(artifact);
        }
        self.artifacts = artifacts.into_values().collect();
        self.mods.sort_by(|left, right| left.id.cmp(&right.id));
        self.mods.dedup_by(|left, right| left.id == right.id);
        self.entities.sort();
        self.entities.dedup();
        self.links.sort_by(|left, right| {
            (&left.from, left.relation, &left.to, left.source_fact).cmp(&(
                &right.from,
                right.relation,
                &right.to,
                right.source_fact,
            ))
        });
        self.links.dedup();
        let mut bridges = BTreeMap::<(ArtifactId, String, String), CompatibilityBridge>::new();
        for mut bridge in self.bridges.drain(..) {
            bridge.evidence.sort();
            bridge.evidence.dedup();
            let key = (
                bridge.artifact.clone(),
                bridge.source_family.clone(),
                bridge.target_family.clone(),
            );
            bridges
                .entry(key)
                .and_modify(|current| {
                    current
                        .capabilities
                        .extend(bridge.capabilities.iter().copied());
                    current.evidence.extend(bridge.evidence.iter().copied());
                    current.evidence.sort();
                    current.evidence.dedup();
                    current.coverage =
                        merge_coverage(current.coverage.clone(), bridge.coverage.clone());
                })
                .or_insert(bridge);
        }
        self.bridges = bridges.into_values().collect();
        self.coverage_evidence.sort();
        self.coverage_evidence.dedup();
    }

    #[must_use]
    pub fn cited_facts(&self) -> BTreeSet<FactId> {
        self.links
            .iter()
            .map(|link| link.source_fact)
            .chain(
                self.bridges
                    .iter()
                    .flat_map(|bridge| bridge.evidence.iter().copied()),
            )
            .chain(self.coverage_evidence.iter().copied())
            .collect()
    }
}

fn merge_coverage(left: CoverageState, right: CoverageState) -> CoverageState {
    match (left, right) {
        (CoverageState::Complete, CoverageState::Complete) => CoverageState::Complete,
        (
            CoverageState::Unavailable { mut reasons },
            CoverageState::Unavailable { reasons: other },
        ) => {
            reasons.extend(other);
            reasons.sort();
            reasons.dedup();
            CoverageState::Unavailable { reasons }
        }
        (CoverageState::Unavailable { mut reasons }, CoverageState::Partial { gaps })
        | (CoverageState::Partial { gaps }, CoverageState::Unavailable { mut reasons }) => {
            reasons.extend(gaps);
            reasons.sort();
            reasons.dedup();
            CoverageState::Unavailable { reasons }
        }
        (CoverageState::Unavailable { reasons }, CoverageState::Complete)
        | (CoverageState::Complete, CoverageState::Unavailable { reasons }) => {
            CoverageState::Unavailable { reasons }
        }
        (CoverageState::Partial { mut gaps }, CoverageState::Partial { gaps: other }) => {
            gaps.extend(other);
            gaps.sort();
            gaps.dedup();
            CoverageState::Partial { gaps }
        }
        (CoverageState::Partial { gaps }, CoverageState::Complete)
        | (CoverageState::Complete, CoverageState::Partial { gaps }) => {
            CoverageState::Partial { gaps }
        }
    }
}
