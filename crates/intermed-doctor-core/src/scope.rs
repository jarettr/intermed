//! Typed collector/rule scope and target coverage contracts.

use std::collections::BTreeSet;

use intermed_evidence::{CoverageGap, CoverageRequirement, CoverageState, ProofKind};
use intermed_facts::{FactStore, kind};
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
    ScriptSources,
    RuntimeMutationLogs,
    /// Compatibility aggregate retained for older scope consumers.
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
    /// Facts from earlier collectors that this collector may read for
    /// cross-layer enrichment. The engine supplies only this declared subset.
    pub consumes: BTreeSet<String>,
    pub target_regions: BTreeSet<TargetRegion>,
    pub prerequisites: Vec<InputRequirement>,
    pub completeness_model: CompletenessModel,
}

impl CollectorScope {
    pub fn new(completeness_model: CompletenessModel) -> Self {
        Self {
            produces: BTreeSet::new(),
            consumes: BTreeSet::new(),
            target_regions: BTreeSet::new(),
            prerequisites: Vec::new(),
            completeness_model,
        }
    }

    pub fn produces(mut self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.produces.extend(kinds.into_iter().map(Into::into));
        self
    }

    pub fn consumes(mut self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.consumes.extend(kinds.into_iter().map(Into::into));
        self
    }

    pub fn regions(mut self, regions: impl IntoIterator<Item = TargetRegion>) -> Self {
        self.target_regions.extend(regions);
        self
    }

    /// Declare a target region that must be produced by an earlier collector.
    /// The checked engine builder validates the dependency order.
    pub fn requires(mut self, id: impl Into<String>, region: TargetRegion) -> Self {
        self.prerequisites.push(InputRequirement {
            id: id.into(),
            region,
        });
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleRequirements {
    pub input_layers: BTreeSet<Layer>,
    /// Predicates without which the rule's core conclusion cannot run.
    pub required_fact_kinds: BTreeSet<String>,
    /// Predicates that enrich explanations or enable additional low-severity
    /// conclusions, but whose absence must not disable the core rule.
    pub optional_fact_kinds: BTreeSet<String>,
    /// Counter-evidence predicates that can invalidate/downgrade a conclusion.
    /// They are semantically distinct from enrichment even though both are
    /// optional at engine-construction time.
    pub refutation_fact_kinds: BTreeSet<String>,
    /// Predicates used only to add context or low-confidence navigation. They
    /// cannot make a hard conclusion valid and their absence is not a coverage
    /// failure.
    pub context_fact_kinds: BTreeSet<String>,
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

    pub fn optional_facts(mut self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.optional_fact_kinds
            .extend(kinds.into_iter().map(Into::into));
        self
    }

    pub fn refutation_facts(mut self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.refutation_fact_kinds
            .extend(kinds.into_iter().map(Into::into));
        self
    }

    pub fn context_facts(mut self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.context_fact_kinds
            .extend(kinds.into_iter().map(Into::into));
        self
    }

    /// Every predicate the rule is allowed to read, independent of its role.
    pub fn declared_fact_kinds(&self) -> BTreeSet<String> {
        self.required_fact_kinds
            .iter()
            .chain(&self.optional_fact_kinds)
            .chain(&self.refutation_fact_kinds)
            .chain(&self.context_fact_kinds)
            .cloned()
            .collect()
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
    /// Completeness of the materialized compatibility-bridge inventory. This is
    /// intentionally separate from loader implementation classes: a complete
    /// mod directory can prove that no external bridge artifact is present even
    /// when the loader JAR itself was not supplied to the analyzer.
    #[serde(default)]
    pub bridge_semantics: CoverageState,
    pub mappings: CoverageState,
    pub logs: CoverageState,
    pub configs: CoverageState,
    #[serde(default)]
    pub script_sources: CoverageState,
    #[serde(default)]
    pub runtime_mutation_logs: CoverageState,
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
        let best_loader = crate::environment::resolve_environment_field(
            store,
            "loader",
            &["loader_source", "evidence_source"],
        );
        let best_minecraft = crate::environment::resolve_environment_field(
            store,
            "mc_version",
            &["mc_version_source", "loader_source", "evidence_source"],
        );
        // The report may derive a conservative cross-artifact consensus when
        // no target-owned environment fact exists. Capabilities must describe
        // that same value as inferred/partial rather than contradicting the
        // report with `unknown`.
        let inferred_loader = crate::report::infer_loader_from_mods(store);
        let inferred_minecraft = crate::report::infer_minecraft_version(store);
        let manifest_source = best_loader.source.or(best_minecraft.source);
        let manifest_provenance =
            crate::environment::EnvironmentEvidenceSource::parse(manifest_source);
        let authoritative_manifest = if settings.pack_manifest.is_some()
            || matches!(
                manifest_provenance,
                crate::environment::EnvironmentEvidenceSource::ExplicitPackManifest
                    | crate::environment::EnvironmentEvidenceSource::PackManifest
            ) {
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
        let loader_identity = match best_loader.value {
            _ if best_loader.is_conflicted() => partial(
                "loader-identity-conflict",
                "equally authoritative environment sources disagree on the target loader",
            ),
            Some(_) if best_loader.is_authoritative() => CoverageState::Complete,
            Some(_) => partial(
                "loader-identity-inferred",
                "loader identity is inferred rather than authoritative",
            ),
            None if inferred_loader.is_some() => partial(
                "loader-identity-inferred",
                "loader identity is inferred from active artifact descriptors rather than authoritative target metadata",
            ),
            None => unavailable(
                "loader-identity-unknown",
                "the target loader could not be established",
            ),
        };
        let minecraft_identity = match best_minecraft.value {
            _ if best_minecraft.is_conflicted() => partial(
                "minecraft-identity-conflict",
                "equally authoritative environment sources disagree on the Minecraft version",
            ),
            Some(_) if best_minecraft.is_authoritative() => CoverageState::Complete,
            Some(_) => partial(
                "minecraft-identity-inferred",
                "Minecraft version is inferred rather than authoritative",
            ),
            None if inferred_minecraft.is_some() => partial(
                "minecraft-identity-inferred",
                "Minecraft version is inferred from cross-artifact metadata consensus rather than authoritative target metadata",
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
        // Loader identity/version from a manifest does not materialize the
        // loader's own libraries. In particular it cannot prove which virtual
        // modules the runtime bundles. Keep this honest until a loader artifact
        // is explicitly indexed.
        let loader_classpath = unavailable(
            "loader-classpath-unavailable",
            "loader implementation classes were not independently indexed",
        );
        let bridge_semantics = materialized_artifacts.clone();
        let script_sources = coverage_for_region_or_collector(
            outcomes,
            scopes,
            TargetRegion::ScriptSources,
            "static-script-scanner",
            "script sources",
        );
        let runtime_mutation_logs = coverage_for_region_or_collector(
            outcomes,
            scopes,
            TargetRegion::RuntimeMutationLogs,
            "script-dynamics",
            "runtime mutation logs",
        );
        let scripts = combine_coverage(
            &script_sources,
            &runtime_mutation_logs,
            "script-evidence-incomplete",
            "static script sources and runtime mutation logs were not both completely inspected",
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
            bridge_semantics,
            mappings,
            logs: coverage_for_region_or_layer(
                outcomes,
                scopes,
                TargetRegion::Logs,
                Layer::Log,
                "logs",
            ),
            configs: target_region_presence(target, "config", "configs-unavailable"),
            script_sources,
            runtime_mutation_logs,
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
                ("bridge-semantics", &self.bridge_semantics)
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
        && matches!(right, CoverageState::Unavailable { .. })
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
    label: &str,
) -> CoverageState {
    if scopes.is_empty() {
        return collector_coverage(outcomes, fallback_collector, label);
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
    let failed = matching
        .iter()
        .filter(|(_, _, outcome)| outcome.status == CollectorStatus::Failed)
        .map(|(id, _, outcome)| format!("{id}: {}", outcome.message))
        .collect::<Vec<_>>();
    if !failed.is_empty() {
        return unavailable(&format!("{label}-collector-failed"), &failed.join("; "));
    }
    let incomplete = matching
        .iter()
        .filter(|(_, _, outcome)| outcome.status == CollectorStatus::Incomplete)
        .map(|(id, _, outcome)| (*id, outcome.message.as_str()))
        .collect::<Vec<_>>();
    if !incomplete.is_empty() {
        let all_or_nothing = incomplete.iter().any(|(id, _)| {
            scopes.iter().any(|(scope_id, scope)| {
                scope_id == id && scope.completeness_model == CompletenessModel::AllOrNothing
            })
        });
        let detail = incomplete
            .iter()
            .map(|(id, message)| format!("{id}: {message}"))
            .collect::<Vec<_>>()
            .join("; ");
        return if all_or_nothing {
            unavailable(&format!("{label}-collector-incomplete"), &detail)
        } else {
            partial(&format!("{label}-collector-incomplete"), &detail)
        };
    }
    if matching.iter().any(|(_, _, outcome)| {
        matches!(
            outcome.status,
            CollectorStatus::Active | CollectorStatus::CompleteEmpty
        )
    }) {
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
    if matching.iter().any(|(_, _, outcome)| {
        matches!(
            outcome.status,
            CollectorStatus::Active | CollectorStatus::CompleteEmpty
        )
    }) {
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
        CollectorStatus::CompleteEmpty => CoverageState::Complete,
        CollectorStatus::Incomplete => {
            partial(&format!("{scope}-collector-incomplete"), &outcome.message)
        }
        CollectorStatus::Failed => {
            unavailable(&format!("{scope}-collector-failed"), &outcome.message)
        }
        CollectorStatus::Disabled | CollectorStatus::Deferred | CollectorStatus::NotApplicable => {
            unavailable(&format!("{scope}-collector-unavailable"), &outcome.message)
        }
    }
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
        let outcomes = vec![(
            "log",
            Layer::Log,
            CollectorOutcome::not_applicable("no log input"),
        )];
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
            CollectorOutcome::complete_empty(0, "no script roots"),
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
    fn all_or_nothing_incomplete_region_is_unavailable() {
        let outcomes = vec![(
            "atomic",
            Layer::Metadata,
            CollectorOutcome::incomplete(1, "could not finish"),
        )];
        let scopes = vec![(
            "atomic",
            CollectorScope::new(CompletenessModel::AllOrNothing).regions([TargetRegion::Metadata]),
        )];
        assert!(matches!(
            region_coverage(&outcomes, &scopes, TargetRegion::Metadata, "metadata"),
            CoverageState::Unavailable { .. }
        ));
    }

    #[test]
    fn failed_region_is_unavailable_not_partial() {
        let outcomes = vec![(
            "bounded",
            Layer::Log,
            CollectorOutcome::failed("read failed"),
        )];
        let scopes = vec![("bounded", scope(TargetRegion::Logs))];
        assert!(matches!(
            region_coverage(&outcomes, &scopes, TargetRegion::Logs, "logs"),
            CoverageState::Unavailable { .. }
        ));
    }

    #[test]
    fn aggregate_coverage_is_partial_when_one_surface_was_inspected() {
        let complete = CoverageState::Complete;
        let missing = unavailable("runtime-log-unavailable", "no runtime mutation log");
        assert!(matches!(
            combine_coverage(
                &complete,
                &missing,
                "scripts-partial",
                "one surface missing"
            ),
            CoverageState::Partial { .. }
        ));

        assert!(matches!(
            combine_coverage(&missing, &missing, "scripts-unavailable", "both missing"),
            CoverageState::Unavailable { .. }
        ));
    }

    #[test]
    fn runtime_environment_outranks_filesystem_inference_for_capability_gating() {
        assert!(
            crate::environment::source_priority(Some("runtime-log"))
                > crate::environment::source_priority(Some("filesystem-heuristic"))
        );
    }

    #[test]
    fn artifact_consensus_is_partial_identity_not_unknown() {
        let mut store = FactStore::new();
        store
            .fact("test", kind::MOD)
            .subject("example")
            .attr("loader", "fabric")
            .attr("file", "example-1.21.1.jar")
            .attr("identity_certainty", "confirmed")
            .emit();
        store
            .fact("test", kind::DEPENDENCY)
            .subject("example")
            .attr("dep", "minecraft")
            .attr("range", ">=1.21.1")
            .attr("identity_certainty", "confirmed")
            .emit();
        store
            .fact("test", kind::MOD)
            .subject("example-two")
            .attr("loader", "fabric")
            .attr("file", "example-two-1.21.1.jar")
            .attr("identity_certainty", "confirmed")
            .emit();
        store
            .fact("test", kind::DEPENDENCY)
            .subject("example-two")
            .attr("dep", "minecraft")
            .attr("range", ">=1.21.1")
            .attr("identity_certainty", "confirmed")
            .emit();

        let capabilities = TargetCapabilities::derive(
            &Target::with_kind(".", crate::TargetKind::ModsDir),
            &store,
            &[],
            &DiagnosisSettings::default(),
        );
        assert!(matches!(
            capabilities.loader_identity,
            CoverageState::Partial { .. }
        ));
        assert!(matches!(
            capabilities.minecraft_identity,
            CoverageState::Partial { .. }
        ));
    }
}
