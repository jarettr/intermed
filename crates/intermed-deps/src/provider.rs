//! [`OfflineDependencyProvider`] population from a [`ModpackGraph`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use creeper_semver_pubgrub::SmallVersion;
use pubgrub::OfflineDependencyProvider;
use semver::Version;
use thiserror::Error;

use crate::graph::{MODPACK_ROOT_ID, ModpackGraph, is_platform_dep};
use crate::ranges::ModRange;
use crate::relation::DependencyRelation;
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
    let unknown_provider_ids = graph
        .provides
        .iter()
        .filter(|alias| alias.provider_version.is_none())
        .map(|alias| alias.alias_id.clone())
        .collect::<HashSet<_>>();
    let versions_by_id = catalog_versions(graph);

    for (package_id, versions) in &versions_by_id {
        for parsed_version in versions.keys() {
            let deps =
                dependency_constraints(graph, package_id, &versions_by_id, &unknown_provider_ids);
            provider.add_dependencies(package_id.clone(), parsed_version.clone(), deps);
        }
    }

    let root_deps: Vec<(String, ModRange)> = graph
        .packages
        .iter()
        .filter(|p| p.id != MODPACK_ROOT_ID)
        .filter_map(|p| {
            let parsed = versions_by_id
                .get(&p.id)?
                .iter()
                .find_map(|(token, raw)| (raw == &p.version).then(|| token.clone()))?;
            Some((p.id.clone(), ModRange::singleton(parsed)))
        })
        .collect();

    provider.add_dependencies(MODPACK_ROOT_ID.to_string(), root, root_deps);
    Ok(provider)
}

/// Assign stable, semantically opaque PubGrub versions to every raw installed
/// version. Loader-specific predicates are evaluated against the raw strings;
/// these tokens only identify members of that finite catalog.
pub(crate) fn catalog_versions(
    graph: &ModpackGraph,
) -> HashMap<String, BTreeMap<SmallVersion, String>> {
    let installed_ids = graph
        .packages
        .iter()
        .map(|package| package.id.as_str())
        .collect::<HashSet<_>>();
    let mut raw = BTreeMap::<String, BTreeSet<String>>::new();
    for package in &graph.packages {
        raw.entry(package.id.clone())
            .or_default()
            .insert(package.version.clone());
    }
    for alias in &graph.provides {
        if installed_ids.contains(alias.alias_id.as_str()) {
            continue;
        }
        if let Some(version) = &alias.provider_version {
            raw.entry(alias.alias_id.clone())
                .or_default()
                .insert(version.clone());
        }
    }
    surrogate_catalog(raw)
}

fn surrogate_catalog(
    raw_versions: BTreeMap<String, BTreeSet<String>>,
) -> HashMap<String, BTreeMap<SmallVersion, String>> {
    raw_versions
        .into_iter()
        .map(|(id, versions)| {
            let catalog = versions
                .into_iter()
                .enumerate()
                .map(|(index, raw)| {
                    let ordinal = u64::try_from(index + 1).unwrap_or(u64::MAX);
                    (SmallVersion::from(Version::new(0, 0, ordinal)), raw)
                })
                .collect();
            (id, catalog)
        })
        .collect()
}

fn dependency_constraints(
    graph: &ModpackGraph,
    from_id: &str,
    versions_by_id: &HashMap<String, BTreeMap<SmallVersion, String>>,
    unknown_provider_ids: &HashSet<String>,
) -> Vec<(String, ModRange)> {
    let mut merged: HashMap<String, ModRange> = HashMap::new();
    for edge in &graph.edges {
        if edge.from != from_id
            || !edge.mandatory
            || !DependencyRelation::parse(&edge.relation).contributes_to_solver()
            || is_platform_dep(&edge.to)
        {
            continue;
        }
        // An observed provider with an unresolved version may satisfy the edge.
        // Omitting this one constraint is the conservative PubGrub equivalent
        // of pairwise ProviderStatus::Unknown; treating it as absent would create
        // a false global UNSAT.
        if unknown_provider_ids.contains(&edge.to) {
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

    #[test]
    fn unknown_provider_version_suppresses_false_global_unsat_constraint() {
        let mut store = FactStore::new();
        store
            .fact("meta", kind::MOD)
            .subject("consumer")
            .attr("version", "1.0.0")
            .attr("loader", "fabric")
            .emit();
        store
            .fact("meta", kind::DEPENDENCY)
            .subject("consumer")
            .attr("dep", "runtime-module")
            .attr("range", ">=0.5.0")
            .attr("mandatory", true)
            .attr("relation", "depends")
            .attr("version_dialect", "fabric-extended-semver")
            .emit();
        store
            .fact("environment", kind::PROVIDED_DEPENDENCY)
            .subject("fabricloader")
            .attr("provides", "runtime-module")
            .attr("scope", "loader-runtime")
            .emit();
        let graph = build_graph(&store);
        assert_eq!(graph.provides[0].provider_version, None);
        let versions = HashMap::from([(
            "consumer".to_string(),
            BTreeMap::from([(
                parse_mod_version("1.0.0").expect("version"),
                "1.0.0".to_string(),
            )]),
        )]);
        let constraints = dependency_constraints(
            &graph,
            "consumer",
            &versions,
            &HashSet::from(["runtime-module".to_string()]),
        );
        assert!(constraints.is_empty());
    }
}
