//! [`OfflineDependencyProvider`] population from a [`ModpackGraph`].

use std::collections::{BTreeMap, HashMap, HashSet};

use creeper_semver_pubgrub::SmallVersion;
use pubgrub::OfflineDependencyProvider;
use thiserror::Error;

use crate::graph::{is_platform_dep, ModpackGraph, MODPACK_ROOT_ID};
use crate::ranges::{ModRange, parse_mod_range};
use crate::semver::parse_mod_version;

/// PubGrub provider type used for modpack resolution.
pub type ModpackProvider = OfflineDependencyProvider<String, ModRange>;

/// Root version pinned for the synthetic modpack package.
const ROOT_VERSION: &str = "1.0.0";

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("modpack root version is not semver: {0}")]
    RootVersion(String),
}

/// Build a PubGrub provider catalog from an installed modpack graph.
///
/// Each installed mod id contributes one or more pinned versions. Dependency
/// edges with parseable ranges become constraints. `provides` aliases register
/// additional package versions when the alias id is not already installed.
pub fn build_provider(graph: &ModpackGraph) -> Result<ModpackProvider, ProviderError> {
    let root = parse_mod_version(ROOT_VERSION)
        .ok_or_else(|| ProviderError::RootVersion(ROOT_VERSION.to_string()))?;

    let mut provider = ModpackProvider::new();
    let mut versions_by_id: HashMap<String, BTreeMap<SmallVersion, String>> = HashMap::new();

    for package in &graph.packages {
        let Some(parsed) = parse_mod_version(&package.version) else {
            continue;
        };
        versions_by_id
            .entry(package.id.clone())
            .or_default()
            .insert(parsed, package.version.clone());
    }

    for alias in &graph.provides {
        if versions_by_id.contains_key(&alias.alias_id) {
            continue;
        }
        let Some(parsed) = parse_mod_version(&alias.provider_version) else {
            continue;
        };
        versions_by_id
            .entry(alias.alias_id.clone())
            .or_default()
            .insert(parsed, alias.provider_version.clone());
    }

    let package_ids: HashSet<String> = versions_by_id.keys().cloned().collect();

    for (package_id, versions) in &versions_by_id {
        for parsed_version in versions.keys() {
            let deps = dependency_constraints(graph, package_id, &package_ids);
            provider.add_dependencies(package_id.clone(), parsed_version.clone(), deps);
        }
    }

    let root_deps: Vec<(String, ModRange)> = graph
        .packages
        .iter()
        .filter(|p| p.id != MODPACK_ROOT_ID)
        .filter_map(|p| {
            let parsed = parse_mod_version(&p.version)?;
            Some((p.id.clone(), ModRange::singleton(parsed)))
        })
        .collect();

    provider.add_dependencies(MODPACK_ROOT_ID.to_string(), root, root_deps);
    Ok(provider)
}

fn dependency_constraints(
    graph: &ModpackGraph,
    from_id: &str,
    known_packages: &HashSet<String>,
) -> Vec<(String, ModRange)> {
    let mut merged: HashMap<String, ModRange> = HashMap::new();
    for edge in &graph.edges {
        if edge.from != from_id
            || !edge.mandatory
            || edge.relation != "depends"
            || is_platform_dep(&edge.to)
        {
            continue;
        }
        if !known_packages.contains(&edge.to) && !graph.provides.iter().any(|a| a.alias_id == edge.to)
        {
            // Missing packages are modeled by absence from the provider catalog;
            // still emit the constraint so PubGrub can explain the gap.
        }
        let Some(range) = parse_mod_range(&edge.range) else {
            continue;
        };
        merged
            .entry(edge.to.clone())
            .and_modify(|existing| *existing = existing.intersection(&range))
            .or_insert(range);
    }
    merged.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::{kind, FactStore};

    use crate::graph::build_graph;

    #[test]
    fn provider_registers_installed_mod() {
        let mut store = FactStore::new();
        store
            .fact("meta", kind::MOD)
            .subject("alpha")
            .attr("version", "1.0.0")
            .emit();
        let graph = build_graph(&store);
        let provider = build_provider(&graph).expect("provider");
        assert!(provider.versions(&"alpha".to_string()).is_some());
    }
}