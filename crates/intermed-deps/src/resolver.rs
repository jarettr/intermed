//! PubGrub-based global dependency resolution for installed modpacks.

use std::collections::BTreeMap;

use pubgrub::{PubGrubError, SelectedDependencies, resolve};

use crate::provider::ModpackProvider;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::graph::{MODPACK_ROOT_ID, ModpackGraph, build_graph};
use crate::provider::build_provider;
use crate::report::format_unsat_tree;
use crate::semver::parse_mod_version;
use intermed_doctor_core::facts::FactStore;

const ROOT_VERSION: &str = "1.0.0";

/// Outcome of attempting global PubGrub resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ResolutionOutcome {
    /// All constraints are jointly satisfiable with the installed catalog.
    Satisfied {
        /// Selected package versions (excludes the synthetic root).
        selection: BTreeMap<String, String>,
    },
    /// The installed set cannot satisfy all dependency constraints together.
    Unsatisfiable {
        /// PubGrub derivation rendered for humans.
        explanation: String,
    },
    /// Not enough semver-parseable packages to run PubGrub safely.
    Skipped { reason: ResolutionSkipReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionSkipReason {
    NoResolvablePackages,
    RootVersionUnparseable,
    ProviderBuildFailed,
}

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("provider build failed: {0}")]
    Provider(#[from] crate::provider::ProviderError),
    #[error("unexpected PubGrub failure: {0:?}")]
    Unexpected(Box<PubGrubError<ModpackProvider>>),
}

/// Resolve dependencies for a [`FactStore`] snapshot.
pub fn resolve_store(store: &FactStore) -> Result<ResolutionOutcome, ResolverError> {
    let graph = build_graph(store);
    resolve_graph(&graph)
}

/// Resolve dependencies for a pre-built [`ModpackGraph`].
pub fn resolve_graph(graph: &ModpackGraph) -> Result<ResolutionOutcome, ResolverError> {
    if !graph.has_resolvable_packages() {
        return Ok(ResolutionOutcome::Skipped {
            reason: ResolutionSkipReason::NoResolvablePackages,
        });
    }

    let root = match parse_mod_version(ROOT_VERSION) {
        Some(v) => v,
        None => {
            return Ok(ResolutionOutcome::Skipped {
                reason: ResolutionSkipReason::RootVersionUnparseable,
            });
        }
    };

    let provider = match build_provider(graph) {
        Ok(p) => p,
        Err(_) => {
            return Ok(ResolutionOutcome::Skipped {
                reason: ResolutionSkipReason::ProviderBuildFailed,
            });
        }
    };

    Ok(run_resolve(&provider, root, graph))
}

fn run_resolve(
    provider: &ModpackProvider,
    root_version: creeper_semver_pubgrub::SmallVersion,
    graph: &ModpackGraph,
) -> ResolutionOutcome {
    match resolve(provider, MODPACK_ROOT_ID.to_string(), root_version) {
        Ok(selection) => ResolutionOutcome::Satisfied {
            selection: selection_to_strings(&selection, graph),
        },
        Err(PubGrubError::NoSolution(tree)) => ResolutionOutcome::Unsatisfiable {
            explanation: format_unsat_tree(tree),
        },
        Err(_other) => ResolutionOutcome::Skipped {
            reason: ResolutionSkipReason::ProviderBuildFailed,
        },
    }
}

fn selection_to_strings(
    selection: &SelectedDependencies<ModpackProvider>,
    graph: &ModpackGraph,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (package, version) in selection.iter() {
        if package == MODPACK_ROOT_ID {
            continue;
        }
        let display = graph
            .packages
            .iter()
            .find(|p| p.id == *package)
            .map(|p| p.version.clone())
            .unwrap_or_else(|| version.to_string());
        out.insert(package.clone(), display);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::{FactStore, kind};

    #[test]
    fn satisfied_when_versions_match() {
        let mut store = FactStore::new();
        store
            .fact("meta", kind::MOD)
            .subject("alpha")
            .attr("version", "1.0.0")
            .emit();
        store
            .fact("meta", kind::MOD)
            .subject("fabric-api")
            .attr("version", "0.90.0")
            .emit();
        store
            .fact("meta", kind::DEPENDENCY)
            .subject("alpha")
            .attr("dep", "fabric-api")
            .attr("range", ">=0.90.0")
            .attr("mandatory", true)
            .emit();
        let outcome = resolve_store(&store).expect("resolve");
        assert!(matches!(outcome, ResolutionOutcome::Satisfied { .. }));
    }

    #[test]
    fn unsatisfiable_when_version_wrong() {
        let mut store = FactStore::new();
        store
            .fact("meta", kind::MOD)
            .subject("alpha")
            .attr("version", "1.0.0")
            .emit();
        store
            .fact("meta", kind::MOD)
            .subject("fabric-api")
            .attr("version", "0.12.0")
            .emit();
        store
            .fact("meta", kind::DEPENDENCY)
            .subject("alpha")
            .attr("dep", "fabric-api")
            .attr("range", ">=0.11.6 <0.12.0")
            .attr("mandatory", true)
            .emit();
        let outcome = resolve_store(&store).expect("resolve");
        assert!(matches!(outcome, ResolutionOutcome::Unsatisfiable { .. }));
    }
}
