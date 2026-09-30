//! One certainty-aware dependency model shared by all Layer-C consumers.

use std::collections::{BTreeMap, BTreeSet};

use intermed_doctor_core::environment::resolve_environment_field;
use intermed_doctor_core::evidence::{CoverageGap, CoverageState};
use intermed_doctor_core::facts::{FactId, FactStore, kind};

use crate::relation::DependencyRelation;
use crate::semver::{VersionDialect, version_in_range_with_dialect};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityState {
    Confirmed,
    Plausible,
    Unresolved,
}

impl IdentityState {
    fn from_attr(value: Option<&str>) -> Self {
        match value {
            None | Some("confirmed") => Self::Confirmed,
            Some("plausible") | Some("plausible-unresolved") => Self::Plausible,
            Some(_) => Self::Unresolved,
        }
    }

    pub const fn is_confirmed(self) -> bool {
        matches!(self, Self::Confirmed)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub id: String,
    pub version: Option<String>,
    pub loader: Option<String>,
    pub identity: IdentityState,
    pub fact_id: FactId,
}

#[derive(Debug, Clone)]
pub struct ResolvedProvider {
    pub id: String,
    pub owner: String,
    pub version: Option<String>,
    pub identity: IdentityState,
    pub activation: ConstraintApplicability,
    pub scope: String,
    /// Loader-declared Jar-in-Jar provider. A direct installed package with the
    /// same id wins candidate selection; the bundled fallback must not satisfy
    /// or violate ranges as though both versions were active simultaneously.
    pub bundled: bool,
    pub fact_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintApplicability {
    Active,
    Inactive,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ResolvedConstraint {
    pub from: String,
    pub to: String,
    pub range: String,
    pub relation: DependencyRelation,
    pub mandatory: bool,
    pub dialect: VersionDialect,
    pub side: Option<String>,
    pub feature: Option<String>,
    pub condition: Option<String>,
    pub identity: IdentityState,
    pub applicability: ConstraintApplicability,
    pub fact_id: FactId,
}

#[derive(Debug, Clone)]
pub struct ResolvedTargetContext {
    pub minecraft_version: Option<String>,
    pub loader: Option<String>,
    pub loader_version: Option<String>,
    pub side: Option<String>,
    pub java_version: Option<String>,
    pub environment_conflicted: bool,
}

#[derive(Debug, Clone)]
pub struct DependencyCoverage {
    pub package_catalog: CoverageState,
    pub provider_universe: CoverageState,
    pub descriptor_activation: CoverageState,
    pub version_semantics: CoverageState,
    pub environment: CoverageState,
    pub applicability: CoverageState,
}

#[derive(Debug)]
pub struct ResolvedDependencyModel {
    pub packages: Vec<ResolvedPackage>,
    pub providers: BTreeMap<String, Vec<ResolvedProvider>>,
    pub constraints: Vec<ResolvedConstraint>,
    pub namespace_providers: BTreeSet<String>,
    pub environment: ResolvedTargetContext,
    pub coverage: DependencyCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderResolution {
    Satisfied { evidence: FactId },
    Unknown { evidence: FactId },
    Unsatisfied { evidence: FactId },
    Absent,
}

impl ResolvedDependencyModel {
    #[must_use]
    pub fn from_store(store: &FactStore) -> Self {
        let packages = store
            .by_kind(kind::MOD)
            .chain(store.by_kind(kind::PLUGIN))
            .map(|fact| ResolvedPackage {
                id: fact.subject.to_string(),
                version: fact.attr("version").map(str::to_string),
                loader: fact.attr("loader").map(str::to_string),
                identity: IdentityState::from_attr(fact.attr("identity_certainty")),
                fact_id: fact.id,
            })
            .collect::<Vec<_>>();

        let package_identity = packages.iter().fold(
            BTreeMap::<&str, IdentityState>::new(),
            |mut map, package| {
                map.entry(package.id.as_str())
                    .and_modify(|state| {
                        if package.identity.is_confirmed() {
                            *state = IdentityState::Confirmed;
                        }
                    })
                    .or_insert(package.identity);
                map
            },
        );

        let mut providers: BTreeMap<String, Vec<ResolvedProvider>> = BTreeMap::new();
        for fact in store.by_kind(kind::PROVIDED_DEPENDENCY) {
            let Some(id) = fact.attr("provides") else {
                continue;
            };
            // Old facts did not carry certainty.  They are accepted only when
            // their owning active mod is independently confirmed; detached or
            // inactive aliases remain plausible and can only block absence.
            let identity = match fact.attr("identity_certainty") {
                Some(value) => IdentityState::from_attr(Some(value)),
                None => package_identity
                    .get(fact.subject.as_str())
                    .copied()
                    .unwrap_or(IdentityState::Unresolved),
            };
            let activation = match fact.attr("activation") {
                Some("inactive" | "cross-loader-inactive") => ConstraintApplicability::Inactive,
                Some("descriptor-unresolved") => ConstraintApplicability::Unknown,
                Some("active-descriptor" | "loader-declared") if identity.is_confirmed() => {
                    ConstraintApplicability::Active
                }
                Some(_) => ConstraintApplicability::Unknown,
                None if identity.is_confirmed() => ConstraintApplicability::Active,
                None => ConstraintApplicability::Unknown,
            };
            let inherited_version = packages
                .iter()
                .find(|package| fact.subject == package.id && package.identity.is_confirmed())
                .and_then(|package| package.version.clone());
            providers
                .entry(id.to_string())
                .or_default()
                .push(ResolvedProvider {
                    id: id.to_string(),
                    owner: fact.subject.to_string(),
                    version: fact
                        .attr("version")
                        .map(str::to_string)
                        .or(inherited_version),
                    identity,
                    activation,
                    scope: fact.attr("scope").unwrap_or("global").to_string(),
                    bundled: fact.attr_bool("bundled").unwrap_or(false),
                    fact_id: fact.id,
                });
        }

        let loader_by_mod = packages
            .iter()
            .filter(|package| package.identity.is_confirmed())
            .filter_map(|package| {
                package
                    .loader
                    .as_deref()
                    .map(|loader| (package.id.as_str(), loader))
            })
            .collect::<BTreeMap<_, _>>();
        let environment = resolved_environment(store);
        let constraints = store
            .by_kind(kind::DEPENDENCY)
            .filter_map(|fact| {
                let to = fact.attr("dep")?;
                let identity = IdentityState::from_attr(fact.attr("identity_certainty"));
                let descriptor_applicability = match identity {
                    IdentityState::Confirmed => ConstraintApplicability::Active,
                    IdentityState::Plausible => ConstraintApplicability::Unknown,
                    IdentityState::Unresolved => {
                        if fact.attr("identity_certainty") == Some("cross-loader-inactive") {
                            ConstraintApplicability::Inactive
                        } else {
                            ConstraintApplicability::Unknown
                        }
                    }
                };
                let side = fact.attr("side").map(str::to_string);
                let applicability = combine_applicability([
                    descriptor_applicability,
                    side_applicability(side.as_deref(), environment.side.as_deref()),
                    if fact.attr("feature").is_some() || fact.attr("condition").is_some() {
                        ConstraintApplicability::Unknown
                    } else {
                        ConstraintApplicability::Active
                    },
                ]);
                let dialect = fact
                    .attr("version_dialect")
                    .and_then(VersionDialect::parse)
                    .or_else(|| {
                        loader_by_mod
                            .get(fact.subject.as_str())
                            .map(|loader| VersionDialect::from_loader(loader))
                    })
                    .unwrap_or_default();
                Some(ResolvedConstraint {
                    from: fact.subject.to_string(),
                    to: to.to_string(),
                    range: fact.attr("range").unwrap_or("*").to_string(),
                    relation: DependencyRelation::parse(fact.attr("relation").unwrap_or("depends")),
                    mandatory: fact.attr_bool("mandatory").unwrap_or(true),
                    dialect,
                    side,
                    feature: fact.attr("feature").map(str::to_string),
                    condition: fact.attr("condition").map(str::to_string),
                    identity,
                    applicability,
                    fact_id: fact.id,
                })
            })
            .collect::<Vec<_>>();

        let namespace_providers = store
            .by_kind(kind::NAMESPACE_OWNER)
            .map(|fact| fact.subject.to_string())
            .collect();
        let coverage =
            dependency_coverage(store, &packages, &providers, &constraints, &environment);
        Self {
            packages,
            providers,
            constraints,
            namespace_providers,
            environment,
            coverage,
        }
    }

    pub fn confirmed_packages(&self) -> impl Iterator<Item = &ResolvedPackage> {
        self.packages
            .iter()
            .filter(|package| package.identity.is_confirmed())
    }

    #[must_use]
    pub fn confirmed_versions(&self, id: &str) -> Vec<&str> {
        self.confirmed_packages()
            .filter(|package| package.id == id)
            .filter_map(|package| package.version.as_deref())
            .collect()
    }

    #[must_use]
    pub fn provider_resolution(
        &self,
        id: &str,
        range: &str,
        dialect: VersionDialect,
    ) -> ProviderResolution {
        let unconstrained = matches!(range.trim(), "" | "*" | "any");
        let mut unknown = None;
        let mut out_of_range = None;
        for package in self.packages.iter().filter(|package| package.id == id) {
            if !package.identity.is_confirmed() {
                unknown.get_or_insert(package.fact_id);
                continue;
            }
            if unconstrained {
                return ProviderResolution::Satisfied {
                    evidence: package.fact_id,
                };
            }
            let Some(version) = package.version.as_deref() else {
                unknown.get_or_insert(package.fact_id);
                continue;
            };
            match version_in_range_with_dialect(version, range, dialect) {
                Some(true) => {
                    return ProviderResolution::Satisfied {
                        evidence: package.fact_id,
                    };
                }
                Some(false) => out_of_range.get_or_insert(package.fact_id),
                None => unknown.get_or_insert(package.fact_id),
            };
        }
        if let Some(providers) = self.providers.get(id) {
            for provider in providers {
                if provider.bundled && self.packages.iter().any(|package| package.id == id) {
                    continue;
                }
                if provider.activation == ConstraintApplicability::Inactive {
                    continue;
                }
                if !provider.identity.is_confirmed()
                    || provider.activation != ConstraintApplicability::Active
                {
                    unknown.get_or_insert(provider.fact_id);
                    continue;
                }
                if unconstrained {
                    return ProviderResolution::Satisfied {
                        evidence: provider.fact_id,
                    };
                }
                let Some(version) = provider.version.as_deref() else {
                    unknown.get_or_insert(provider.fact_id);
                    continue;
                };
                match version_in_range_with_dialect(version, range, dialect) {
                    Some(true) => {
                        return ProviderResolution::Satisfied {
                            evidence: provider.fact_id,
                        };
                    }
                    Some(false) => out_of_range.get_or_insert(provider.fact_id),
                    None => unknown.get_or_insert(provider.fact_id),
                };
            }
        }
        if let Some(evidence) = unknown {
            ProviderResolution::Unknown { evidence }
        } else if let Some(evidence) = out_of_range {
            ProviderResolution::Unsatisfied { evidence }
        } else {
            ProviderResolution::Absent
        }
    }

    #[must_use]
    pub fn confirmed_provider_ids(&self) -> BTreeSet<String> {
        let mut ids = self
            .confirmed_packages()
            .map(|package| package.id.clone())
            .collect::<BTreeSet<_>>();
        ids.extend(
            self.providers
                .iter()
                .filter(|(_, providers)| {
                    providers.iter().any(|provider| {
                        provider.identity.is_confirmed()
                            && provider.activation == ConstraintApplicability::Active
                    })
                })
                .map(|(id, _)| id.clone()),
        );
        ids.extend(self.namespace_providers.iter().cloned());
        ids
    }

    #[must_use]
    pub fn has_unresolved_provider(&self, id: &str) -> bool {
        self.packages
            .iter()
            .any(|package| package.id == id && !package.identity.is_confirmed())
            || self.providers.get(id).is_some_and(|providers| {
                providers.iter().any(|provider| {
                    !provider.identity.is_confirmed()
                        || provider.activation == ConstraintApplicability::Unknown
                })
            })
    }
}

fn combine_applicability(
    states: impl IntoIterator<Item = ConstraintApplicability>,
) -> ConstraintApplicability {
    let mut unknown = false;
    for state in states {
        match state {
            ConstraintApplicability::Inactive => return ConstraintApplicability::Inactive,
            ConstraintApplicability::Unknown => unknown = true,
            ConstraintApplicability::Active => {}
        }
    }
    if unknown {
        ConstraintApplicability::Unknown
    } else {
        ConstraintApplicability::Active
    }
}

fn side_applicability(required: Option<&str>, target: Option<&str>) -> ConstraintApplicability {
    let Some(required) = required.map(str::trim).filter(|side| !side.is_empty()) else {
        return ConstraintApplicability::Active;
    };
    if matches!(required.to_ascii_lowercase().as_str(), "both" | "*") {
        return ConstraintApplicability::Active;
    }
    let Some(target) = target else {
        return ConstraintApplicability::Unknown;
    };
    let target = target.to_ascii_lowercase();
    let applies = match required.to_ascii_lowercase().as_str() {
        "client" => matches!(target.as_str(), "client" | "integrated" | "both"),
        "server" | "dedicated_server" | "dedicated-server" => {
            matches!(
                target.as_str(),
                "server" | "dedicated_server" | "dedicated-server" | "both"
            )
        }
        _ => return ConstraintApplicability::Unknown,
    };
    if applies {
        ConstraintApplicability::Active
    } else {
        ConstraintApplicability::Inactive
    }
}

fn resolved_environment(store: &FactStore) -> ResolvedTargetContext {
    let resolve = |field| {
        resolve_environment_field(
            store,
            field,
            &["loader_source", "minecraft_source", "evidence_source"],
        )
    };
    let minecraft = resolve("mc_version");
    let loader = resolve("loader");
    let loader_version = resolve("loader_version");
    let side = resolve("side");
    let instance_type = resolve("instance_type");
    let java_version = store
        .by_kind(kind::JAVA_RUNTIME)
        .find(|fact| fact.attr("source") != Some("analyzer-host"))
        .and_then(|fact| fact.attr("version"))
        .map(str::to_string);
    let conflicted = [&minecraft, &loader, &loader_version, &side, &instance_type]
        .iter()
        .any(|resolution| resolution.is_conflicted());
    ResolvedTargetContext {
        minecraft_version: minecraft.value.map(str::to_string),
        loader: loader.value.map(str::to_string),
        loader_version: loader_version.value.map(str::to_string),
        side: side.value.or(instance_type.value).map(str::to_string),
        java_version,
        environment_conflicted: conflicted,
    }
}

fn dependency_coverage(
    store: &FactStore,
    packages: &[ResolvedPackage],
    providers: &BTreeMap<String, Vec<ResolvedProvider>>,
    constraints: &[ResolvedConstraint],
    environment: &ResolvedTargetContext,
) -> DependencyCoverage {
    let partial = |code: &str, detail: &str| CoverageState::Partial {
        gaps: vec![CoverageGap::new(code, detail)],
    };
    // Dependency completeness is collector-specific. A truncated music, VFS,
    // security, or resource-AST scan says nothing about the package/provider
    // universe and must not downgrade Layer C. Metadata gaps and archives that
    // metadata could not open are the relevant boundary here.
    let has_metadata_gap = store.by_kind(kind::SCAN_TRUNCATED).any(|fact| {
        fact.extractor.as_str() == "metadata-scanner" || fact.attr("layer") == Some("metadata")
    }) || store
        .by_kind(kind::UNPARSEABLE_ARCHIVE)
        .any(|fact| fact.extractor.as_str() == "metadata-scanner");
    let package_catalog = if has_metadata_gap {
        partial(
            "dependency-artifact-scan-partial",
            "artifact scanning was truncated, so the installed package catalog may be incomplete",
        )
    } else {
        CoverageState::Complete
    };
    let provider_universe = if has_metadata_gap
        || providers.values().flatten().any(|provider| {
            !provider.identity.is_confirmed()
                || provider.activation == ConstraintApplicability::Unknown
        }) {
        partial(
            "provider-universe-partial",
            "one or more provider identities or artifact scans are unresolved",
        )
    } else {
        CoverageState::Complete
    };
    let descriptor_activation = if packages
        .iter()
        .any(|package| !package.identity.is_confirmed())
        || constraints
            .iter()
            .any(|constraint| !constraint.identity.is_confirmed())
    {
        partial(
            "descriptor-activation-unresolved",
            "one or more descriptor candidates could not be selected authoritatively",
        )
    } else {
        CoverageState::Complete
    };
    let version_semantics = if constraints.iter().any(|constraint| {
        matches!(constraint.dialect, VersionDialect::Opaque)
            || matches!(constraint.applicability, ConstraintApplicability::Active)
                && self_test_range(&constraint.range, constraint.dialect).is_none()
    }) {
        partial(
            "dependency-version-language-unresolved",
            "one or more active dependency predicates use an unsupported version language",
        )
    } else {
        CoverageState::Complete
    };
    let environment_coverage = if environment.environment_conflicted {
        partial(
            "dependency-environment-conflict",
            "equally authoritative target-environment evidence conflicts",
        )
    } else {
        CoverageState::Complete
    };
    let applicability = if constraints
        .iter()
        .any(|constraint| constraint.applicability == ConstraintApplicability::Unknown)
    {
        partial(
            "dependency-applicability-unresolved",
            "one or more dependency constraints have unresolved activation",
        )
    } else {
        CoverageState::Complete
    };
    DependencyCoverage {
        package_catalog,
        provider_universe,
        descriptor_activation,
        version_semantics,
        environment: environment_coverage,
        applicability,
    }
}

fn self_test_range(range: &str, dialect: VersionDialect) -> Option<bool> {
    // Syntax probe only. A false result is still a successfully interpreted
    // predicate; `None` denotes an unsupported language.
    version_in_range_with_dialect("0.0.0", range, dialect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_provider_dominates_known_out_of_range_provider() {
        let mut store = FactStore::new();
        store
            .fact("test", kind::MOD)
            .subject("api")
            .attr("version", "1.0.0")
            .emit();
        store
            .fact("test", kind::PROVIDED_DEPENDENCY)
            .subject("inactive")
            .attr("provides", "api")
            .attr("identity_certainty", "cross-loader-unresolved")
            .emit();
        let model = ResolvedDependencyModel::from_store(&store);
        assert!(matches!(
            model.provider_resolution("api", ">=2.0.0", VersionDialect::GenericSemver),
            ProviderResolution::Unknown { .. }
        ));
    }

    #[test]
    fn explicitly_inactive_provider_does_not_block_absence() {
        let mut store = FactStore::new();
        store
            .fact("test", kind::PROVIDED_DEPENDENCY)
            .subject("foreign")
            .attr("provides", "api")
            .attr("version", "9.0.0")
            .attr("identity_certainty", "confirmed")
            .attr("activation", "cross-loader-inactive")
            .emit();
        let model = ResolvedDependencyModel::from_store(&store);
        assert_eq!(
            model.provider_resolution("api", "*", VersionDialect::GenericSemver),
            ProviderResolution::Absent
        );
    }

    #[test]
    fn direct_package_shadows_bundled_copy_with_same_id() {
        let mut store = FactStore::new();
        store
            .fact("test", kind::MOD)
            .subject("fabric-api")
            .attr("version", "0.158.0+26.2")
            .attr("identity_certainty", "confirmed")
            .emit();
        store
            .fact("test", kind::PROVIDED_DEPENDENCY)
            .subject("container")
            .attr("provides", "fabric-api")
            .attr("version", "0.149.0+26.2")
            .attr("identity_certainty", "confirmed")
            .attr("activation", "loader-declared")
            .attr("bundled", true)
            .emit();

        let model = ResolvedDependencyModel::from_store(&store);
        assert!(matches!(
            model.provider_resolution(
                "fabric-api",
                "<0.152.1+26.2",
                VersionDialect::FabricExtendedSemver,
            ),
            ProviderResolution::Unsatisfied { .. }
        ));
        assert!(matches!(
            model.provider_resolution(
                "fabric-api",
                ">=0.152.1+26.2",
                VersionDialect::FabricExtendedSemver,
            ),
            ProviderResolution::Satisfied { .. }
        ));
    }

    #[test]
    fn unrelated_collector_truncation_does_not_reduce_dependency_coverage() {
        let mut store = FactStore::new();
        store
            .fact("resource-ast-scanner", kind::SCAN_TRUNCATED)
            .subject("music-pack.jar")
            .attr("layer", "resource-ast")
            .attr("reason", "large sound asset")
            .emit();
        let model = ResolvedDependencyModel::from_store(&store);
        assert!(matches!(
            model.coverage.package_catalog,
            CoverageState::Complete
        ));
        assert!(matches!(
            model.coverage.provider_universe,
            CoverageState::Complete
        ));
    }
}
