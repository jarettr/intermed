//! [`OfflineDependencyProvider`] population from a [`ModpackGraph`].

use std::collections::{BTreeMap, HashMap, HashSet};

use creeper_semver_pubgrub::SmallVersion;
use pubgrub::OfflineDependencyProvider;
use thiserror::Error;

use crate::graph::{MODPACK_ROOT_ID, ModpackGraph, is_platform_dep};
use crate::ranges::ModRange;
use crate::semver::{parse_mod_version, version_in_range_with_dialect};

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
    let installed_ids: HashSet<&str> = graph
        .packages
        .iter()
        .map(|package| package.id.as_str())
        .collect();

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
        // A real installed package owns its id. Otherwise retain *every*
        // provider candidate: the first bundled copy may be out of range while
        // a later one satisfies the dependency (common with Fabric API modules).
        if installed_ids.contains(alias.alias_id.as_str()) {
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

    for (package_id, versions) in &versions_by_id {
        for parsed_version in versions.keys() {
            let deps = dependency_constraints(graph, package_id, &versions_by_id);
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
    versions_by_id: &HashMap<String, BTreeMap<SmallVersion, String>>,
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
        let Some(range) = catalog_constraint(edge, versions_by_id.get(&edge.to)) else {
            continue;
        };
        merged
            .entry(edge.to.clone())
            .and_modify(|existing| *existing = existing.intersection(&range))
            .or_insert(range);
    }
    merged.into_iter().collect()
}

/// Lower a loader-specific predicate to the finite installed catalog PubGrub
/// actually solves. This avoids translating Fabric predicates through Cargo's
/// prerelease rules: each installed raw version is checked by the authoritative
/// dialect evaluator, then represented as an exact PubGrub singleton.
fn catalog_constraint(
    edge: &crate::graph::ModDependencyEdge,
    versions: Option<&BTreeMap<SmallVersion, String>>,
) -> Option<ModRange> {
    let Some(versions) = versions else {
        // Keep a valid missing dependency as a real constraint: PubGrub will see
        // that the package catalog is absent. Invalid/opaque comparator syntax is
        // skipped rather than turned into a false global contradiction.
        return version_in_range_with_dialect("0.0.0", &edge.range, edge.version_dialect)
            .map(|_| ModRange::full());
    };

    let mut allowed = ModRange::empty();
    for (parsed, raw) in versions {
        match version_in_range_with_dialect(raw, &edge.range, edge.version_dialect) {
            Some(true) | None => {
                // `None` is deliberately included. Pairwise reports it as
                // undecidable; global resolution must not upgrade uncertainty
                // into a hard unsat.
                allowed = allowed.union(&ModRange::singleton(parsed.clone()));
            }
            Some(false) => {}
        }
    }
    Some(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::{FactStore, kind};

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
