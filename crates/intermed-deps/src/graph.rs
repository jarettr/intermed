//! Build a modpack dependency graph from doctor facts.

use creeper_semver_pubgrub::SmallVersion;
use intermed_doctor_core::facts::{FactId, FactStore, kind};
use serde::{Deserialize, Serialize};

use crate::model::{ConstraintApplicability, ResolvedDependencyModel};
use crate::semver::{self, VersionDialect};

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

/// One installed mod or plugin. `parsed_version` is diagnostic/display metadata;
/// solver eligibility never depends on it.
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
    #[serde(default)]
    pub version_dialect: VersionDialect,
    pub fact_id: FactId,
}

/// Virtual id satisfied by a mod's `provides` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvidedAlias {
    pub alias_id: String,
    pub provider_mod: String,
    /// `None` means the provider is observed but its runtime-supplied version is
    /// not known. It must keep dependency resolution undecidable rather than be
    /// fabricated as version zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_version: Option<String>,
    pub fact_id: FactId,
}

/// Why a raw version could not be represented as generic SemVer. These records
/// still participate in PubGrub through surrogate finite-catalog tokens.
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
    AmbiguousVersion,
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
    /// True when at least one installed package can enter the finite catalog.
    /// Raw versions do not need to be SemVer: PubGrub receives surrogate tokens.
    pub fn has_resolvable_packages(&self) -> bool {
        !self.packages.is_empty()
    }

    /// Lookup parsed version for a package id (first matching entry).
    pub fn parsed_version_of(&self, id: &str) -> Option<SmallVersion> {
        self.packages
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.parsed_version.as_ref())
            .and_then(|v| semver::parse_mod_version(v))
    }
}

/// Materialize a [`ModpackGraph`] from a collected [`FactStore`].
pub fn build_graph(store: &FactStore) -> ModpackGraph {
    let model = ResolvedDependencyModel::from_store(store);
    let mut packages = Vec::new();
    let mut skipped = Vec::new();
    let ambiguous_versions: std::collections::HashSet<String> = store
        .by_kind(kind::MOD_METADATA)
        .filter(|fact| fact.attr_bool("version_ambiguous").unwrap_or(false))
        .map(|fact| fact.subject.to_string())
        .collect();
    for package in model.confirmed_packages() {
        let version = package.version.clone().unwrap_or_else(|| "0".to_string());
        // `version_ambiguous` describes the generic display normalizer, not the
        // loader's comparison language. Fabric/Quilt order valid raw extended
        // versions directly, so strings such as `1.20-Fabric-4.0.6` must remain
        // in the finite PubGrub catalog.
        let dialect = package
            .loader
            .as_deref()
            .map(VersionDialect::from_loader)
            .unwrap_or_default();
        let ambiguous = ambiguous_versions.contains(package.id.as_str())
            && !dialect.orders_raw_extended_versions();
        let parsed = (!ambiguous)
            .then(|| semver::parse_mod_version(&version).map(|v| v.to_string()))
            .flatten();
        packages.push(ModPackage {
            id: package.id.clone(),
            version: version.clone(),
            parsed_version: parsed.clone(),
        });
        if parsed.is_none() {
            skipped.push(SkippedPackage {
                id: package.id.clone(),
                version,
                reason: if ambiguous {
                    SkipReason::AmbiguousVersion
                } else {
                    SkipReason::UnparseableVersion
                },
            });
        }
    }

    let mc_version = model.environment.minecraft_version.clone();

    if let Some(mc) = &mc_version
        && semver::parse_mod_version(mc).is_some()
    {
        let already = packages.iter().any(|p| p.id == "minecraft");
        if !already {
            packages.push(ModPackage {
                id: "minecraft".to_string(),
                version: mc.clone(),
                parsed_version: Some(mc.clone()),
            });
        }
    }

    let mut edges = Vec::new();
    for dependency in model
        .constraints
        .iter()
        .filter(|constraint| constraint.applicability == ConstraintApplicability::Active)
    {
        if dependency.to.is_empty() {
            continue;
        }
        edges.push(ModDependencyEdge {
            from: dependency.from.clone(),
            to: dependency.to.clone(),
            range: dependency.range.clone(),
            mandatory: dependency.mandatory,
            relation: dependency.relation.canonical_token().to_string(),
            version_dialect: dependency.dialect,
            fact_id: dependency.fact_id,
        });
    }

    let mut provides = Vec::new();
    for provider in model.providers.values().flatten() {
        if provider.activation != ConstraintApplicability::Inactive {
            let provider_version = (provider.identity.is_confirmed()
                && provider.activation == ConstraintApplicability::Active)
                .then(|| provider.version.clone())
                .flatten();
            provides.push(ProvidedAlias {
                alias_id: provider.id.clone(),
                provider_mod: provider.owner.clone(),
                provider_version,
                fact_id: provider.fact_id,
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
