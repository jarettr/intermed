//! Build a modpack dependency graph from doctor facts.

use std::collections::HashMap;

use creeper_semver_pubgrub::SmallVersion;
use intermed_doctor_core::facts::{kind, FactId, FactStore};
use serde::{Deserialize, Serialize};

use crate::ranges::ModRange;
use crate::semver;

/// Pseudo-dependencies that name the platform, not an installable mod.
pub const PLATFORM_IDS: &[&str] = &[
    "minecraft",
    "java",
    "fabricloader",
    "fabric-loader",
    "quilt_loader",
    "quilt_base",
    "minecraft_quilt_loader",
    "forge",
    "neoforge",
];

/// Synthetic root package anchoring PubGrub resolution to the whole instance.
pub const MODPACK_ROOT_ID: &str = "__intermed_modpack__";

/// The loader family a platform dependency id names, for matching against the
/// detected environment loader (`environment.loader`). `None` for non-loader
/// platform ids (`minecraft`, `java`), which are checked separately.
pub(crate) fn platform_loader_family(dep_id: &str) -> Option<&'static str> {
    match dep_id {
        "fabricloader" | "fabric-loader" => Some("fabric"),
        "quilt_loader" | "quilt_base" | "minecraft_quilt_loader" => Some("quilt"),
        "forge" => Some("forge"),
        "neoforge" => Some("neoforge"),
        _ => None,
    }
}

/// One installed mod or plugin with optional parsed semver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModPackage {
    pub id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsed_version: Option<String>,
}

/// Directed dependency edge extracted from a `dependency` fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModDependencyEdge {
    pub from: String,
    pub to: String,
    pub range: String,
    pub mandatory: bool,
    /// Manifest relation: `depends`, `breaks`, `suggests`, `recommends`, `loadbefore`.
    pub relation: String,
    pub fact_id: FactId,
}

/// Virtual id satisfied by a mod's `provides` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvidedAlias {
    pub alias_id: String,
    pub provider_mod: String,
    pub provider_version: String,
    pub fact_id: FactId,
}

/// Why a package could not participate in PubGrub (conservative skip).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedPackage {
    pub id: String,
    pub version: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    UnparseableVersion,
}

/// Snapshot of the modpack dependency graph used by the resolver and CLI export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModpackGraph {
    pub packages: Vec<ModPackage>,
    pub edges: Vec<ModDependencyEdge>,
    pub provides: Vec<ProvidedAlias>,
    pub mc_version: Option<String>,
    pub skipped: Vec<SkippedPackage>,
}

impl ModpackGraph {
    /// True when at least one package has a parseable version for PubGrub.
    pub fn has_resolvable_packages(&self) -> bool {
        self.packages.iter().any(|p| p.parsed_version.is_some())
    }

    /// Lookup parsed version for a package id (first matching entry).
    pub fn parsed_version_of(&self, id: &str) -> Option<SmallVersion> {
        self.packages
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.parsed_version.as_ref())
            .and_then(|v| semver::parse_mod_version(v))
    }

    /// Outgoing semver-resolvable edges for `from`, keyed by target id.
    pub fn resolved_edges_from(&self, from: &str) -> HashMap<String, ModRange> {
        let mut out = HashMap::new();
        for edge in &self.edges {
            if edge.from != from || !edge.mandatory || edge.relation != "depends" {
                continue;
            }
            if is_platform_dep(&edge.to) {
                continue;
            }
            if let Some(range) = crate::ranges::parse_mod_range(&edge.range) {
                out.insert(edge.to.clone(), range);
            }
        }
        out
    }
}

/// Materialize a [`ModpackGraph`] from a collected [`FactStore`].
pub fn build_graph(store: &FactStore) -> ModpackGraph {
    let mut packages = Vec::new();
    let mut skipped = Vec::new();

    for f in store.by_kind(kind::MOD).chain(store.by_kind(kind::PLUGIN)) {
        let version = f.attr("version").unwrap_or("0").to_string();
        let parsed = semver::parse_mod_version(&version).map(|v| v.to_string());
        if parsed.is_some() {
            packages.push(ModPackage {
                id: f.subject.clone(),
                version: version.clone(),
                parsed_version: parsed,
            });
        } else {
            skipped.push(SkippedPackage {
                id: f.subject.clone(),
                version,
                reason: SkipReason::UnparseableVersion,
            });
        }
    }

    let mc_version = store
        .by_kind(kind::ENVIRONMENT)
        .next()
        .and_then(|f| f.attr("mc_version").map(str::to_string));

    if let Some(mc) = &mc_version {
        if semver::parse_mod_version(mc).is_some() {
            let already = packages.iter().any(|p| p.id == "minecraft");
            if !already {
                packages.push(ModPackage {
                    id: "minecraft".to_string(),
                    version: mc.clone(),
                    parsed_version: Some(mc.clone()),
                });
            }
        }
    }

    let mut edges = Vec::new();
    for dep in store.by_kind(kind::DEPENDENCY) {
        let dep_id = dep.attr("dep").unwrap_or("").to_string();
        if dep_id.is_empty() {
            continue;
        }
        edges.push(ModDependencyEdge {
            from: dep.subject.clone(),
            to: dep_id,
            range: dep.attr("range").unwrap_or("*").to_string(),
            mandatory: dep.attr_bool("mandatory").unwrap_or(true),
            relation: dep
                .attr("relation")
                .unwrap_or("depends")
                .to_string(),
            fact_id: dep.id,
        });
    }

    let mut provides = Vec::new();
    for f in store.by_kind(kind::PROVIDED_DEPENDENCY) {
        if let Some(alias) = f.attr("provides") {
            // A bundled (Jar-in-Jar) module carries its own version on the fact;
            // a plain `provides` alias inherits the provider mod's version.
            let provider_version = f
                .attr("version")
                .map(str::to_string)
                .or_else(|| {
                    packages
                        .iter()
                        .find(|p| p.id == f.subject)
                        .map(|p| p.version.clone())
                })
                .unwrap_or_else(|| "0".to_string());
            provides.push(ProvidedAlias {
                alias_id: alias.to_string(),
                provider_mod: f.subject.clone(),
                provider_version,
                fact_id: f.id,
            });
        }
    }

    ModpackGraph {
        packages,
        edges,
        provides,
        mc_version,
        skipped,
    }
}

pub(crate) fn is_platform_dep(dep_id: &str) -> bool {
    PLATFORM_IDS.contains(&dep_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::FactStore;

    #[test]
    fn graph_collects_packages_and_edges() {
        let mut store = FactStore::new();
        store
            .fact("meta", kind::MOD)
            .subject("alpha")
            .attr("version", "1.0.0")
            .emit();
        store
            .fact("meta", kind::DEPENDENCY)
            .subject("alpha")
            .attr("dep", "fabric-api")
            .attr("range", ">=0.90.0")
            .attr("mandatory", true)
            .emit();
        let graph = build_graph(&store);
        assert_eq!(graph.packages.len(), 1);
        assert_eq!(graph.edges.len(), 1);
        assert!(graph.has_resolvable_packages());
    }
}