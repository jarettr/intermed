//! Typed collector/rule scope and target coverage contracts.

use std::collections::BTreeSet;

use intermed_evidence::{CoverageGap, CoverageRequirement, CoverageState, ProofKind};
use intermed_facts::{Fact, FactStore, kind};
use serde::{Deserialize, Serialize};

use crate::collector::{CollectorOutcome, CollectorStatus};
use crate::{DiagnosisSettings, Layer, Target};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetRegion {
    Manifest,
    Artifacts,
    Metadata,
    ModClasspath,
    MinecraftClasspath,
    LoaderClasspath,
    Mappings,
    Logs,
    Configs,
    Scripts,
    ResourceBlobs,
    Datapacks,
    RuntimeProfile,
    VanillaResources,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletenessModel {
    AllOrNothing,
    PerArtifact,
    BoundedPartial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRequirement {
    pub id: String,
    pub region: TargetRegion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorScope {
    pub produces: BTreeSet<String>,
    pub target_regions: BTreeSet<TargetRegion>,
    pub prerequisites: Vec<InputRequirement>,
    pub completeness_model: CompletenessModel,
}

impl CollectorScope {
    pub fn new(completeness_model: CompletenessModel) -> Self {
        Self {
            produces: BTreeSet::new(),
            target_regions: BTreeSet::new(),
            prerequisites: Vec::new(),
            completeness_model,
        }
    }

    pub fn produces(mut self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.produces.extend(kinds.into_iter().map(Into::into));
        self
    }

    pub fn regions(mut self, regions: impl IntoIterator<Item = TargetRegion>) -> Self {
        self.target_regions.extend(regions);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleRequirements {
    pub input_layers: BTreeSet<Layer>,
    pub required_fact_kinds: BTreeSet<String>,
    pub required_regions: BTreeSet<TargetRegion>,
    pub minimum_coverage: BTreeSet<CoverageRequirement>,
    pub permitted_proof_kinds: BTreeSet<ProofKind>,
}

impl RuleRequirements {
    pub fn facts(mut self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.required_fact_kinds
            .extend(kinds.into_iter().map(Into::into));
        self
    }

    pub fn layers(mut self, layers: impl IntoIterator<Item = Layer>) -> Self {
        self.input_layers.extend(layers);
        self
    }

    pub fn regions(mut self, regions: impl IntoIterator<Item = TargetRegion>) -> Self {
        self.required_regions.extend(regions);
        self
    }

    pub fn coverage(mut self, requirements: impl IntoIterator<Item = CoverageRequirement>) -> Self {
        self.minimum_coverage.extend(requirements);
        self
    }

    pub fn proofs(mut self, kinds: impl IntoIterator<Item = ProofKind>) -> Self {
        self.permitted_proof_kinds.extend(kinds);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetCapabilities {
    pub authoritative_manifest: CoverageState,
    pub materialized_artifacts: CoverageState,
    pub loader_identity: CoverageState,
    pub minecraft_identity: CoverageState,
    pub mod_classpath: CoverageState,
    pub minecraft_classpath: CoverageState,
    pub loader_classpath: CoverageState,
    pub mappings: CoverageState,
    pub logs: CoverageState,
    pub configs: CoverageState,
    pub scripts: CoverageState,
    pub runtime_mutators: CoverageState,
    pub resource_blobs: CoverageState,
    pub datapacks: CoverageState,
    pub runtime_profile: CoverageState,
    pub vanilla_resources: CoverageState,
}

impl TargetCapabilities {
    pub fn derive(
        target: &Target,
        store: &FactStore,
        outcomes: &[(&'static str, Layer, CollectorOutcome)],
        settings: &DiagnosisSettings,
    ) -> Self {
        Self::derive_with_scopes(target, store, outcomes, &[], settings)
    }

    pub fn derive_with_scopes(
        target: &Target,
        store: &FactStore,
        outcomes: &[(&'static str, Layer, CollectorOutcome)],
        scopes: &[(&'static str, CollectorScope)],
        settings: &DiagnosisSettings,
    ) -> Self {
        let env_facts = store.by_kind(kind::ENVIRONMENT).collect::<Vec<_>>();
        let (best_loader, loader_conflict) =
            strongest_environment_fact(&env_facts, "loader", &["loader_source", "evidence_source"]);
        let (best_minecraft, minecraft_conflict) = strongest_environment_fact(
            &env_facts,
            "mc_version",
            &["mc_version_source", "loader_source", "evidence_source"],
        );
        let manifest_source = best_loader
            .and_then(|fact| fact.attr("loader_source"))
            .or_else(|| best_minecraft.and_then(|fact| fact.attr("mc_version_source")));
        let authoritative_manifest = if settings.pack_manifest.is_some()
            || matches!(manifest_source, Some("explicit-pack-manifest"))
        {
            CoverageState::Complete
        } else {
            unavailable(
                "authoritative-manifest-not-provided",
                "no authoritative pack manifest was supplied",
            )
        };

        let metadata = coverage_for_region_or_layer(
            outcomes,
            scopes,
            TargetRegion::Metadata,
            Layer::Metadata,
            "metadata",
        );
        let materialized_artifacts = if store.by_kind(kind::MODPACK_INCOMPLETE).next().is_some() {
            partial(
                "materialized-pack-incomplete",
                "the source manifest declares artifacts that are absent from the materialized target",
            )
        } else if target.mods_dir.as_ref().is_some_and(|path| path.is_dir())
            || (target.kind.has_mods() && target.path.is_dir())
        {
            metadata.clone()
        } else {
            unavailable(
                "materialized-artifacts-unavailable",
                "no materialized mod artifact directory is available",
            )
        };
        let loader_identity = match best_loader.and_then(|fact| fact.attr("loader")) {
            Some(_) if loader_conflict => partial(
                "loader-identity-conflict",
                "equally authoritative environment sources disagree on the target loader",
            ),
            Some(_)
                if matches!(
                    manifest_source,
                    Some("explicit-pack-manifest" | "instance-manifest" | "runtime-log")
                ) =>
            {
                CoverageState::Complete
            }
            Some(_) => partial(
                "loader-identity-inferred",
                "loader identity is inferred rather than authoritative",
            ),
            None => unavailable(
                "loader-identity-unknown",
                "the target loader could not be established",
            ),
        };
        let minecraft_identity = match best_minecraft.and_then(|fact| fact.attr("mc_version")) {
            Some(_) if minecraft_conflict => partial(
                "minecraft-identity-conflict",
                "equally authoritative environment sources disagree on the Minecraft version",
            ),
            Some(_)
                if matches!(
                    best_minecraft.and_then(|fact| fact.attr("mc_version_source")),
                    Some("explicit-pack-manifest" | "instance-manifest" | "runtime-log")
                ) =>
            {
                CoverageState::Complete
            }
            Some(_) => partial(
                "minecraft-identity-inferred",
                "Minecraft version is inferred rather than authoritative",
            ),
            None => unavailable(
                "minecraft-identity-unknown",
                "the target Minecraft version could not be established",
            ),
        };

        let mixin = coverage_for_region_or_layer(
            outcomes,
            scopes,
            TargetRegion::ModClasspath,
            Layer::Mixin,
            "mixin",
        );
        let mixin_passport = store.by_kind(kind::MIXIN_CLASSPATH_COVERAGE).next();
        let mod_classpath = if mixin_passport
            .and_then(|fact| fact.attr_int("mod_classes"))
            .is_some_and(|count| count > 0)
        {
            mixin.clone()
        } else {
            unavailable("mod-classpath-unavailable", "mod classpath was not indexed")
        };
        let minecraft_classpath = if settings
            .minecraft_jar
            .as_ref()
            .is_some_and(|path| path.is_file())
            && mixin_passport
                .and_then(|fact| fact.attr_int("minecraft_classes"))
                .is_some_and(|count| count > 0)
        {
            mixin.clone()
        } else {
            unavailable(
                "minecraft-classpath-unavailable",
                "a verified Minecraft classpath was not indexed",
            )
        };
        let mappings = if settings
            .minecraft_mappings
            .as_ref()
            .is_some_and(|path| path.is_file())
        {
            mixin.clone()
        } else {
            unavailable(
                "mappings-unavailable",
                "compatible mappings were not supplied",
            )
        };
        let loader_classpath = if loader_identity.is_complete() && mod_classpath.is_complete() {
            CoverageState::Complete
        } else {
            partial(
                "loader-classpath-unverified",
                "loader classes are not independently known to be complete",
            )
        };
        let scripts = coverage_for_region_or_collector(
            outcomes,
            scopes,
            TargetRegion::Scripts,
            "static-script-scanner",
            true,
            "scripts",
        );
        let runtime_mutators = combine_coverage(
            &scripts,
            &mixin,
            "runtime-mutator-coverage-incomplete",
            "script and Mixin mutation surfaces were not both completely inspected",
        );

        Self {
            authoritative_manifest,
            materialized_artifacts,
            loader_identity,
            minecraft_identity,
            mod_classpath,
            minecraft_classpath,
            loader_classpath,
            mappings,
            logs: coverage_for_region_or_layer(
                outcomes,
                scopes,
                TargetRegion::Logs,
                Layer::Log,
                "logs",
            ),
            configs: target_region_presence(target, "config", "configs-unavailable"),
            scripts,
            runtime_mutators,
            resource_blobs: coverage_for_region_or_layer(
                outcomes,
                scopes,
                TargetRegion::ResourceBlobs,
                Layer::Resource,
                "resource-blobs",
            ),
            datapacks: coverage_for_region_or_layer(
                outcomes,
                scopes,
                TargetRegion::Datapacks,
                Layer::DataSemantics,
                "datapacks",
            ),
            runtime_profile: coverage_for_region_or_layer(
                outcomes,
                scopes,
                TargetRegion::RuntimeProfile,
                Layer::Performance,
                "runtime-profile",
            ),
            vanilla_resources: if settings.minecraft_jar.is_some() {
                let base = coverage_for_region_or_layer(
                    outcomes,
                    scopes,
                    TargetRegion::VanillaResources,
                    Layer::DataSemantics,
                    "vanilla-resources",
                );
                if store
                    .by_kind(kind::SCAN_TRUNCATED)
                    .any(|fact| fact.attr("coverage_scope") == Some("vanilla-resources"))
                {
                    partial(
                        "vanilla-index-incomplete",
                        "the requested vanilla resource index was incomplete",
                    )
                } else {
                    base
                }
            } else {
                unavailable(
                    "vanilla-baseline-not-requested",
                    "no vanilla resource baseline was requested",
                )
            },
        }
    }

    pub fn for_requirement(
        &self,
        requirement: CoverageRequirement,
    ) -> (&'static str, &CoverageState) {
        match requirement {
            CoverageRequirement::LocalArtifact => {
                ("materialized-artifacts", &self.materialized_artifacts)
            }
            CoverageRequirement::CompletePack | CoverageRequirement::CompleteProviderUniverse => {
                ("materialized-artifacts", &self.materialized_artifacts)
            }
            CoverageRequirement::CompleteClasspath => {
                ("minecraft-classpath", &self.minecraft_classpath)
            }
            CoverageRequirement::RuntimeEvidence | CoverageRequirement::TerminalRuntime => {
                ("logs", &self.logs)
            }
            CoverageRequirement::RuntimeProfile => ("runtime-profile", &self.runtime_profile),
            CoverageRequirement::AuthoritativeLoader => ("loader-identity", &self.loader_identity),
            CoverageRequirement::ActiveDescriptor => {
                ("materialized-artifacts", &self.materialized_artifacts)
            }
            CoverageRequirement::KnownBridgeSemantics => {
                ("loader-classpath", &self.loader_classpath)
            }
            CoverageRequirement::CompatibleMappings => ("mappings", &self.mappings),
            CoverageRequirement::ApplicableMixin => ("mod-classpath", &self.mod_classpath),
            CoverageRequirement::CompleteResourceBlobs => ("resource-blobs", &self.resource_blobs),
            CoverageRequirement::RelevantResources => ("datapacks", &self.datapacks),
            CoverageRequirement::CompleteVanillaBaseline => {
                ("vanilla-resources", &self.vanilla_resources)
            }
            CoverageRequirement::KnownRuntimeMutators => {
                ("runtime-mutators", &self.runtime_mutators)
            }
        }
    }
}

fn combine_coverage(
    left: &CoverageState,
    right: &CoverageState,
    code: &str,
    detail: &str,
) -> CoverageState {
    if left.is_complete() && right.is_complete() {
        CoverageState::Complete
    } else if matches!(left, CoverageState::Unavailable { .. })
        || matches!(right, CoverageState::Unavailable { .. })
    {
        unavailable(code, detail)
    } else {
        partial(code, detail)
    }
}

fn coverage_for_region_or_layer(
    outcomes: &[(&'static str, Layer, CollectorOutcome)],
    scopes: &[(&'static str, CollectorScope)],
    region: TargetRegion,
    fallback_layer: Layer,
    label: &str,
) -> CoverageState {
    if scopes.is_empty() {
        return layer_coverage(outcomes, fallback_layer, label);
    }
    region_coverage(outcomes, scopes, region, label)
}

fn coverage_for_region_or_collector(
    outcomes: &[(&'static str, Layer, CollectorOutcome)],
    scopes: &[(&'static str, CollectorScope)],
    region: TargetRegion,
    fallback_collector: &str,
    skipped_is_complete: bool,
    label: &str,
) -> CoverageState {
    if scopes.is_empty() {
        return collector_coverage(outcomes, fallback_collector, skipped_is_complete, label);
    }
    region_coverage(outcomes, scopes, region, label)
}

fn region_coverage(
    outcomes: &[(&'static str, Layer, CollectorOutcome)],
    scopes: &[(&'static str, CollectorScope)],
    region: TargetRegion,
    label: &str,
) -> CoverageState {
    let collector_ids = scopes
        .iter()
        .filter(|(_, scope)| scope.target_regions.contains(&region))
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    let matching = outcomes
        .iter()
        .filter(|(id, _, _)| collector_ids.contains(id))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return unavailable(
            &format!("{label}-collector-unavailable"),
            "no registered collector declares this target region",
        );
    }
    let gaps = matching
        .iter()
        .filter(|(_, _, outcome)| {
            matches!(
                outcome.status,
                CollectorStatus::Incomplete | CollectorStatus::Failed
            )
        })
        .map(|(id, _, outcome)| format!("{id}: {}", outcome.message))
        .collect::<Vec<_>>();
    if !gaps.is_empty() {
        return partial(&format!("{label}-collector-incomplete"), &gaps.join("; "));
    }
    if matching
        .iter()
        .any(|(_, _, outcome)| outcome.status == CollectorStatus::Active)
        || (region == TargetRegion::Scripts
            && matching
                .iter()
                .any(|(_, _, outcome)| outcome.status == CollectorStatus::Skipped))
    {
        CoverageState::Complete
    } else {
        unavailable(
            &format!("{label}-collector-unavailable"),
            &matching
                .iter()
                .map(|(id, _, outcome)| format!("{id}: {}", outcome.message))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

fn layer_coverage(
    outcomes: &[(&'static str, Layer, CollectorOutcome)],
    layer: Layer,
    scope: &str,
) -> CoverageState {
    let matching = outcomes
        .iter()
        .filter(|(_, candidate, _)| *candidate == layer)
        .collect::<Vec<_>>();
    if matching
        .iter()
        .any(|(_, _, outcome)| outcome.status == CollectorStatus::Incomplete)
    {
        return partial(
            &format!("{scope}-collector-incomplete"),
            &matching
                .iter()
                .filter(|(_, _, outcome)| outcome.status == CollectorStatus::Incomplete)
                .map(|(_, _, outcome)| outcome.message.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    if matching
        .iter()
        .any(|(_, _, outcome)| outcome.status == CollectorStatus::Failed)
    {
        return unavailable(
            &format!("{scope}-collector-failed"),
            &matching
                .iter()
                .filter(|(_, _, outcome)| outcome.status == CollectorStatus::Failed)
                .map(|(_, _, outcome)| outcome.message.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    if matching
        .iter()
        .any(|(_, _, outcome)| outcome.status == CollectorStatus::Active)
    {
        CoverageState::Complete
    } else {
        unavailable(
            &format!("{scope}-collector-unavailable"),
            "collector did not run",
        )
    }
}

fn collector_coverage(
    outcomes: &[(&'static str, Layer, CollectorOutcome)],
    collector_id: &str,
    skipped_is_complete: bool,
    scope: &str,
) -> CoverageState {
    let Some((_, _, outcome)) = outcomes.iter().find(|(id, _, _)| *id == collector_id) else {
        return unavailable(
            &format!("{scope}-collector-unavailable"),
            "collector was not registered",
        );
    };
    match outcome.status {
        CollectorStatus::Active => CoverageState::Complete,
        CollectorStatus::Skipped if skipped_is_complete => CoverageState::Complete,
        CollectorStatus::Incomplete => {
            partial(&format!("{scope}-collector-incomplete"), &outcome.message)
        }
        CollectorStatus::Failed => {
            unavailable(&format!("{scope}-collector-failed"), &outcome.message)
        }
        CollectorStatus::Disabled | CollectorStatus::Deferred | CollectorStatus::Skipped => {
            unavailable(&format!("{scope}-collector-unavailable"), &outcome.message)
        }
    }
}

fn environment_evidence_priority(source: Option<&str>) -> u8 {
    match source.unwrap_or("") {
        "explicit-pack-manifest"
        | "pack-manifest"
        | "modrinth-manifest"
        | "curseforge-manifest" => 100,
        "instance-manifest" | "launcher-manifest" | "instance-metadata" => 90,
        "runtime-log" => 80,
        "artifact-consensus" => 50,
        "filesystem-heuristic" => 10,
        _ => 40,
    }
}

fn strongest_environment_fact<'a>(
    facts: &[&'a Fact],
    value_attr: &str,
    source_attrs: &[&str],
) -> (Option<&'a Fact>, bool) {
    let best_priority = facts
        .iter()
        .filter(|fact| fact.attr(value_attr).is_some())
        .map(|fact| environment_evidence_priority(environment_fact_source(fact, source_attrs)))
        .max();
    let Some(best_priority) = best_priority else {
        return (None, false);
    };
    let mut candidates = facts
        .iter()
        .copied()
        .filter(|fact| {
            fact.attr(value_attr).is_some()
                && environment_evidence_priority(environment_fact_source(fact, source_attrs))
                    == best_priority
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|fact| fact.id);
    let values = candidates
        .iter()
        .filter_map(|fact| fact.attr(value_attr))
        .collect::<BTreeSet<_>>();
    (candidates.first().copied(), values.len() > 1)
}

fn environment_fact_source<'a>(fact: &'a Fact, attrs: &[&str]) -> Option<&'a str> {
    attrs.iter().find_map(|attr| fact.attr(attr))
}

fn target_region_presence(target: &Target, name: &str, code: &str) -> CoverageState {
    if target
        .candidate_roots()
        .iter()
        .any(|root| root.join(name).is_dir())
    {
        CoverageState::Complete
    } else {
        unavailable(code, &format!("target has no `{name}` region"))
    }
}

fn partial(code: &str, detail: &str) -> CoverageState {
    CoverageState::Partial {
        gaps: vec![CoverageGap::new(code, detail)],
    }
}

fn unavailable(code: &str, detail: &str) -> CoverageState {
    CoverageState::Unavailable {
        reasons: vec![CoverageGap::new(code, detail)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(region: TargetRegion) -> CollectorScope {
        CollectorScope::new(CompletenessModel::BoundedPartial).regions([region])
    }

    #[test]
    fn skipped_log_collector_is_unavailable_not_complete() {
        let outcomes = vec![("log", Layer::Log, CollectorOutcome::skipped("no log input"))];
        let scopes = vec![("log", scope(TargetRegion::Logs))];
        assert!(matches!(
            region_coverage(&outcomes, &scopes, TargetRegion::Logs, "logs"),
            CoverageState::Unavailable { .. }
        ));
    }

    #[test]
    fn completed_empty_script_discovery_proves_no_scripts() {
        let outcomes = vec![(
            "scripts",
            Layer::Resource,
            CollectorOutcome::skipped("no script roots"),
        )];
        let scopes = vec![("scripts", scope(TargetRegion::Scripts))];
        assert_eq!(
            region_coverage(&outcomes, &scopes, TargetRegion::Scripts, "scripts"),
            CoverageState::Complete
        );
    }

    #[test]
    fn any_incomplete_region_consumer_makes_coverage_partial() {
        let outcomes = vec![
            ("a", Layer::Log, CollectorOutcome::active(1, "complete")),
            (
                "b",
                Layer::Log,
                CollectorOutcome::incomplete(1, "truncated"),
            ),
        ];
        let scopes = vec![
            ("a", scope(TargetRegion::Logs)),
            ("b", scope(TargetRegion::Logs)),
        ];
        assert!(matches!(
            region_coverage(&outcomes, &scopes, TargetRegion::Logs, "logs"),
            CoverageState::Partial { .. }
        ));
    }

    #[test]
    fn runtime_environment_outranks_filesystem_inference_for_capability_gating() {
        assert!(
            environment_evidence_priority(Some("runtime-log"))
                > environment_evidence_priority(Some("filesystem-heuristic"))
        );
    }
}
