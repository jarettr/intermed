//! Canonical resolution of target-environment evidence.
//!
//! Environment facts are consumed by capability gating, report projection and
//! cross-layer reconciliation. Keeping source ranking and conflict handling in
//! one module prevents those consumers from silently selecting different
//! target loaders or Minecraft versions.

use std::collections::BTreeSet;

use intermed_facts::{Fact, FactId, FactRead, kind};

/// Stable taxonomy for the provenance of target-environment values.
/// Wire tokens remain compatible, while authority decisions are typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnvironmentEvidenceSource {
    ExplicitPackManifest,
    PackManifest,
    LauncherManifest,
    InstanceManifest,
    RuntimeLog,
    StaleRuntimeLog,
    ArtifactConsensus,
    FilesystemHeuristic,
    Undecidable,
    Unknown,
}

impl EnvironmentEvidenceSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitPackManifest => "explicit-pack-manifest",
            Self::PackManifest => "pack-manifest",
            Self::LauncherManifest => "launcher-manifest",
            Self::InstanceManifest => "instance-manifest",
            Self::RuntimeLog => "runtime-log",
            Self::StaleRuntimeLog => "runtime-log-stale",
            Self::ArtifactConsensus => "artifact-consensus",
            Self::FilesystemHeuristic => "filesystem-heuristic",
            Self::Undecidable => "undecidable",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn parse(token: Option<&str>) -> Self {
        match token.unwrap_or("") {
            "explicit-pack-manifest" => Self::ExplicitPackManifest,
            "pack-manifest" | "modrinth-manifest" | "curseforge-manifest" => Self::PackManifest,
            "launcher-manifest" => Self::LauncherManifest,
            "instance-manifest" | "instance-metadata" => Self::InstanceManifest,
            "runtime-log" => Self::RuntimeLog,
            "runtime-log-stale" => Self::StaleRuntimeLog,
            "artifact-consensus" => Self::ArtifactConsensus,
            "filesystem-heuristic" => Self::FilesystemHeuristic,
            "undecidable" => Self::Undecidable,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn authority(self) -> u8 {
        match self {
            Self::ExplicitPackManifest | Self::PackManifest => 100,
            Self::LauncherManifest | Self::InstanceManifest => 90,
            Self::RuntimeLog => 80,
            Self::StaleRuntimeLog => 20,
            Self::ArtifactConsensus => 50,
            Self::Unknown => 40,
            Self::FilesystemHeuristic => 10,
            Self::Undecidable => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnvironmentResolution<'a> {
    pub fact: Option<&'a Fact>,
    pub value: Option<&'a str>,
    pub source: Option<&'a str>,
    pub priority: u8,
    pub conflicts: Vec<FactId>,
}

impl EnvironmentResolution<'_> {
    #[must_use]
    pub fn is_conflicted(&self) -> bool {
        !self.conflicts.is_empty()
    }

    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        self.value.is_some() && !self.is_conflicted() && source_is_authoritative(self.source)
    }
}

/// One canonical priority table for every environment consumer.
#[must_use]
pub fn source_priority(source: Option<&str>) -> u8 {
    EnvironmentEvidenceSource::parse(source).authority()
}

#[must_use]
pub fn source_is_authoritative(source: Option<&str>) -> bool {
    source_priority(source) >= source_priority(Some("runtime-log"))
}

/// Resolve one environment field at the strongest evidence priority.
/// Equally authoritative disagreement produces no value and retains every
/// conflicting fact id; enumeration order can never pick an arbitrary winner.
#[must_use]
pub fn resolve_environment_field<'a>(
    store: &'a dyn FactRead,
    value_attr: &str,
    source_attrs: &[&str],
) -> EnvironmentResolution<'a> {
    let facts = store
        .by_kind(kind::ENVIRONMENT)
        .filter(|fact| fact.attr(value_attr).is_some())
        .collect::<Vec<_>>();
    let priority = facts
        .iter()
        .map(|fact| source_priority(fact_source(fact, source_attrs)))
        .max()
        .unwrap_or(0);
    let mut candidates = facts
        .into_iter()
        .filter(|fact| source_priority(fact_source(fact, source_attrs)) == priority)
        .collect::<Vec<_>>();
    candidates.sort_by_key(|fact| fact.id);
    let values = candidates
        .iter()
        .filter_map(|fact| fact.attr(value_attr))
        .collect::<BTreeSet<_>>();
    if values.len() > 1 {
        return EnvironmentResolution {
            fact: None,
            value: None,
            source: None,
            priority,
            conflicts: candidates.iter().map(|fact| fact.id).collect(),
        };
    }
    let fact = candidates.first().copied();
    EnvironmentResolution {
        fact,
        value: fact.and_then(|fact| fact.attr(value_attr)),
        source: fact.and_then(|fact| fact_source(fact, source_attrs)),
        priority,
        conflicts: Vec::new(),
    }
}

fn fact_source<'a>(fact: &'a Fact, attrs: &[&str]) -> Option<&'a str> {
    attrs.iter().find_map(|attr| fact.attr(attr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_facts::FactStore;

    #[test]
    fn explicit_manifest_outranks_runtime_and_filesystem() {
        let mut store = FactStore::new();
        for (loader, source) in [
            ("forge", "filesystem-heuristic"),
            ("neoforge", "runtime-log"),
            ("fabric", "explicit-pack-manifest"),
        ] {
            store
                .fact("test", kind::ENVIRONMENT)
                .attr("loader", loader)
                .attr("loader_source", source)
                .emit();
        }
        let resolved =
            resolve_environment_field(&store, "loader", &["loader_source", "evidence_source"]);
        assert_eq!(resolved.value, Some("fabric"));
        assert!(resolved.is_authoritative());
    }

    #[test]
    fn equal_priority_conflict_abstains() {
        let mut store = FactStore::new();
        for loader in ["forge", "fabric"] {
            store
                .fact("test", kind::ENVIRONMENT)
                .attr("loader", loader)
                .attr("loader_source", "runtime-log")
                .emit();
        }
        let resolved = resolve_environment_field(&store, "loader", &["loader_source"]);
        assert!(resolved.value.is_none());
        assert_eq!(resolved.conflicts.len(), 2);
    }

    #[test]
    fn stale_runtime_evidence_is_not_authoritative() {
        assert!(
            source_priority(Some("runtime-log-stale"))
                < source_priority(Some("artifact-consensus"))
        );
        assert!(!source_is_authoritative(Some("runtime-log-stale")));
    }
}
