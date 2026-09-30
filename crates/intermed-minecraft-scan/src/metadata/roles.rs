//! Target-aware roles declared by one physical archive.

use serde::{Deserialize, Serialize};

use super::{Artifact, Descriptor, Loader};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct ArtifactRole {
    pub declared_id: String,
    pub version: String,
    pub loader: String,
    pub descriptor: String,
    pub ordinal: u16,
    pub activation: String,
}

pub(super) fn classify(
    candidates: &[(Descriptor, Vec<Artifact>)],
    selected: usize,
    expected_loader: Option<Loader>,
    identity_certainty: &str,
) -> Vec<ArtifactRole> {
    let mut roles = Vec::new();
    for (candidate_index, (descriptor, candidate_artifacts)) in candidates.iter().enumerate() {
        for (ordinal, artifact) in candidate_artifacts.iter().enumerate() {
            let activation = if candidate_index == selected {
                match identity_certainty {
                    "confirmed" => "active",
                    "cross-loader-unresolved" => "inactive-cross-loader",
                    _ => "unresolved",
                }
            } else if expected_loader.is_some_and(|loader| descriptor.matches_loader(loader)) {
                "compatible-candidate"
            } else if expected_loader.is_some() {
                "inactive-cross-loader"
            } else {
                "unresolved"
            };
            roles.push(ArtifactRole {
                declared_id: artifact.id.clone(),
                version: artifact.version.clone(),
                loader: artifact.loader.as_str().to_string(),
                descriptor: descriptor.manifest_name().to_string(),
                ordinal: ordinal.min(u16::MAX as usize) as u16,
                activation: activation.to_string(),
            });
        }
    }
    roles
}
