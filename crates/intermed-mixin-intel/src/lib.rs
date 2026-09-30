//! # intermed-mixin-intel — Layer F
//!
//! Static mixin intelligence with refmap resolution, structural class models,
//! interaction graphs, and composite risk scoring. This crate does not
//! transform classes or execute mod code; it reads mixin JSON configs and
//! class-file annotations only.
//!
//! Entry points: [`scan_mods_dir`], [`collector`], [`rule`], [`build_interaction_graph`].
//! Cache revision: [`cache_version`] (bump when parse/analysis logic changes in a release).

mod activation;
mod analyzer;
mod annotation;
mod apply_failure;
mod bloat;
mod bytecode;
mod class_parser;
mod classpath;
mod clusters;
mod collect;
mod complexity;
mod composition;
mod dataflow;
mod effect;
mod graph;
mod handler_effect;
mod hierarchy;
mod hot_path;
mod injection_point;
mod locals;
mod metrics;
mod model;
mod naming;
mod perf_match;
mod profile;
mod recommendation;
mod refmap;
mod resource_bridge;
mod rule;
mod runtime_log;
mod scan;
mod selector;
mod semantics;
mod signature;
mod site;
mod subsystem;
mod target_res;
mod trace;

#[doc(hidden)]
pub mod fixtures;

pub use analyzer::MixinInteractionEngine;
pub use apply_failure::{ApplyFailure, ApplyFailureKind, TargetClassIndex};
pub use class_parser::{ClassParseResult, parse_mixin_class, parse_mixin_class_with_hierarchy};
pub use classpath::{ClasspathCoverage, CoverageLevel};
pub use clusters::{ClusterKind, MixinVerdictStrength, RiskCluster, build_clusters};
pub use composition::{
    CoApplication, CompositionClass, HandlerRole, SiteComposition, analyze_compositions,
};
pub use graph::MixinInteractionGraph;
pub use hot_path::{HotPathRules, default_rules};
pub use locals::LocalCaptureStatus;
pub use metrics::DataflowMetrics;
pub use model::{
    ActivationStatus, CallKind, ComplexityComponent, ConflictEdgeType, EffectiveEffectKind,
    GraphEdge, GraphNode, HandlerEffect, HandlerSideEffect, HighRiskOverwrite, ImpreciseReason,
    InteractionType, MemberKind, MixinAddedMember, MixinAnalysis, MixinBloatAssessment, MixinCall,
    MixinClassComplexity, MixinClassModel, MixinClassRecord, MixinConfigRecord,
    MixinConflictEdgeRecord, MixinEffect, MixinGraphExport, MixinInteractionRecord,
    MixinModComplexity, MixinOperation, MixinOverlap, MixinPriorityConflictRecord,
    MixinRecommendationRecord, MixinRiskAssessment, MixinScan, MixinScanFailure, MixinShadowMember,
    PrecisionLevel, Recommendation, ResolvedInjectionPoint, STATUS, Side,
};
pub use naming::{NameSource, ResolvedName};
pub use perf_match::{
    MatchQuality, allows_high_severity, allows_high_severity_for_site, grade_match,
    grade_match_with_mappings, is_destructive_operation,
};
pub use profile::{PrecisionProfile, effective_profile, escalation_reasons};
pub use recommendation::{recommend_for_scan, redirect_counts_by_method};
pub use refmap::{
    MappingCompatibility, MappingContext, Namespace, Refmap, RefmapStatus, TinyMappings,
    dotted_name,
};
pub use resource_bridge::{
    ResourceEffectEvidence, ResourceSubsystem, RuntimeResourceMutation, classify_resource_loader,
    detect_resource_mutations,
};
pub use runtime_log::{
    RuntimeCandidateMatch, RuntimeFailureReason, RuntimeMatchStrength, RuntimeMixinFailure,
    RuntimeSiteIdentity, SiteConfirmation, confirm_sites, match_failure_to_candidates,
    match_failure_to_site, parse_runtime_failures,
};
pub use scan::{
    MixinScanError, cache_version, extractor_id, scan_mods_dir, scan_mods_dir_with_cache,
    scan_target,
};
pub use selector::SelectorVerification;
pub use signature::{SignatureCheck, check_handler_signature_with_target};
pub use site::{ApplicationSite, SitePrecision, build_application_sites};
pub use subsystem::{
    MixinCapability, MixinSecuritySurface, Subsystem, classify_subsystem, derive_subsystems,
};
pub use target_res::TargetResolution;
pub use trace::{PrecisionTrace, site_trace};

use intermed_doctor_core::{CollectCtx, Collector, CollectorOutcome, Layer, Rule, Target};

use collect::emit_scan;
use rule::MixinRiskRule;
use scan::mods_dir;

/// Layer-F collector.
pub fn collector() -> impl Collector {
    MixinCollector
}

/// Layer-F composite risk rule.
pub fn rule() -> impl Rule {
    MixinRiskRule
}

/// Build the interaction graph for a scan result.
#[must_use]
pub fn build_interaction_graph(scan: &MixinScan) -> MixinInteractionGraph {
    MixinInteractionGraph::build(
        &scan.classes,
        &scan.interactions,
        &scan.conflict_edges,
        &scan.priority_conflicts,
    )
}

/// Export the interaction graph as Graphviz DOT.
///
/// An empty scan (e.g. a Bukkit/Paper plugin pack with no Mixins) is a valid
/// result, not an error: it yields a well-formed empty graph. The `Option`
/// signature is retained for API symmetry with [`graph_to_json`].
pub fn graph_to_dot(scan: &MixinScan) -> Option<String> {
    Some(build_interaction_graph(scan).to_dot())
}

/// Export the interaction graph as GraphML.
///
/// An empty scan yields a well-formed empty document (see [`graph_to_dot`]).
pub fn graph_to_graphml(scan: &MixinScan) -> Option<String> {
    Some(build_interaction_graph(scan).to_graphml())
}

/// Export a self-contained interactive HTML visualization.
///
/// An empty scan yields a well-formed empty page (see [`graph_to_dot`]).
pub fn graph_to_html(scan: &MixinScan, title: &str) -> Option<String> {
    Some(build_interaction_graph(scan).to_html(title))
}

/// Export the interaction graph as JSON (`MixinGraphExport`).
///
/// An empty scan serializes to an empty node/edge set. `None` is reserved for a
/// genuine serialization failure.
pub fn graph_to_json(scan: &MixinScan) -> Option<String> {
    serde_json::to_string(&build_interaction_graph(scan).export()).ok()
}

struct MixinCollector;

impl Collector for MixinCollector {
    fn id(&self) -> &'static str {
        scan::extractor_id()
    }

    fn layer(&self) -> Layer {
        Layer::Mixin
    }

    fn scope(&self) -> intermed_doctor_core::CollectorScope {
        intermed_doctor_core::CollectorScope::new(
            intermed_doctor_core::CompletenessModel::PerArtifact,
        )
        .produces([
            intermed_doctor_core::facts::kind::MIXIN_ACTIVATION,
            intermed_doctor_core::facts::kind::MIXIN_CONFIG,
            intermed_doctor_core::facts::kind::MIXIN_ADDED_MEMBER,
            intermed_doctor_core::facts::kind::MIXIN_APPLICATION_SITE,
            intermed_doctor_core::facts::kind::MIXIN_BLOAT,
            intermed_doctor_core::facts::kind::MIXIN_CALLS,
            intermed_doctor_core::facts::kind::MIXIN_CLASS,
            intermed_doctor_core::facts::kind::MIXIN_CLASSPATH_COVERAGE,
            intermed_doctor_core::facts::kind::MIXIN_CLASS_COMPLEXITY,
            intermed_doctor_core::facts::kind::MIXIN_COMPOSITION,
            intermed_doctor_core::facts::kind::MIXIN_CONFIG_PLUGIN,
            intermed_doctor_core::facts::kind::MIXIN_CONFLICT_EDGE,
            intermed_doctor_core::facts::kind::MIXIN_DATAFLOW_METRICS,
            intermed_doctor_core::facts::kind::MIXIN_EFFECT,
            intermed_doctor_core::facts::kind::MIXIN_HANDLER_BODY,
            intermed_doctor_core::facts::kind::MIXIN_HANDLER_EFFECT,
            intermed_doctor_core::facts::kind::MIXIN_HIERARCHY,
            intermed_doctor_core::facts::kind::MIXIN_HOTSPOT,
            intermed_doctor_core::facts::kind::MIXIN_INJECTION_POINT,
            intermed_doctor_core::facts::kind::MIXIN_INTERACTION,
            intermed_doctor_core::facts::kind::MIXIN_MOD_COMPLEXITY,
            intermed_doctor_core::facts::kind::MIXIN_OPERATION,
            intermed_doctor_core::facts::kind::MIXIN_OVERLAP,
            intermed_doctor_core::facts::kind::MIXIN_PRIORITY_CONFLICT,
            intermed_doctor_core::facts::kind::MIXIN_RECOMMENDATION,
            intermed_doctor_core::facts::kind::MIXIN_REFMAP_LOADED,
            intermed_doctor_core::facts::kind::MIXIN_REFMAP_STATUS,
            intermed_doctor_core::facts::kind::MIXIN_RISK_CLUSTER,
            intermed_doctor_core::facts::kind::MIXIN_RISK_SCORE,
            intermed_doctor_core::facts::kind::MIXIN_RUNTIME_RESOURCE_MUTATION,
            intermed_doctor_core::facts::kind::MIXIN_RESOURCE_HOOK,
            intermed_doctor_core::facts::kind::MIXIN_SECURITY_SURFACE,
            intermed_doctor_core::facts::kind::MIXIN_SHADOW,
            intermed_doctor_core::facts::kind::MIXIN_TARGET,
            intermed_doctor_core::facts::kind::HIGH_RISK_OVERWRITE,
            intermed_doctor_core::facts::kind::MOD_CAPABILITY,
            intermed_doctor_core::facts::kind::SCAN_TRUNCATED,
            "mixin_apply_target_class_missing",
            "mixin_apply_target_method_missing",
            "mixin_apply_descriptor_mismatch",
            "mixin_apply_require_unsatisfied",
            "mixin_apply_refmap_missing",
            "mixin_apply_refmap_unavailable",
            "mixin_apply_remap_false_suspicious",
            "mixin_apply_ordinal_out_of_range",
        ])
        .regions([
            intermed_doctor_core::TargetRegion::ModClasspath,
            intermed_doctor_core::TargetRegion::MinecraftClasspath,
            intermed_doctor_core::TargetRegion::Mappings,
        ])
        .consumes([
            intermed_doctor_core::facts::kind::ENVIRONMENT,
            intermed_doctor_core::facts::kind::COMPATIBILITY_BRIDGE,
            intermed_doctor_core::facts::kind::ARTIFACT_ROLE,
        ])
    }

    fn applies(&self, target: &Target) -> bool {
        mods_dir(target).is_some()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let Some(dir) = mods_dir(ctx.target) else {
            return CollectorOutcome::not_applicable("no mods directory for mixin scan");
        };

        // Use canonical environment resolution from A layer instead of find_map,
        // which would take an arbitrary fact and ignore authority ranking and
        // equal-priority conflicts.
        let mc_resolution = intermed_doctor_core::environment::resolve_environment_field(
            ctx.inputs,
            "mc_version",
            &["mc_version_source", "evidence_source"],
        );
        let loader_resolution = intermed_doctor_core::environment::resolve_environment_field(
            ctx.inputs,
            "loader",
            &["loader_source", "evidence_source"],
        );
        let side_resolution = intermed_doctor_core::environment::resolve_environment_field(
            ctx.inputs,
            "side",
            &[
                "side_source",
                "instance_type_source",
                "evidence_source",
                "loader_source",
            ],
        );

        let target_minecraft_version = mc_resolution.value;
        let target_loader = loader_resolution
            .value
            .and_then(intermed_doctor_core::Loader::parse);
        let target_side = match side_resolution.value {
            Some("client") => crate::model::Side::Client,
            Some("server" | "dedicated-server") => crate::model::Side::Server,
            Some("both" | "integrated") => crate::model::Side::Both,
            _ => crate::model::Side::Unknown,
        };

        // Environment conflict degrades mixin analysis certainty: activation,
        // runtime namespace, foreign descriptor selection, mapping compatibility,
        // and apply-failure proofs all depend on knowing the authoritative loader.
        let environment_conflicted = mc_resolution.is_conflicted()
            || loader_resolution.is_conflicted()
            || side_resolution.is_conflicted();

        let allow_foreign_configs = ctx
            .inputs
            .by_kind(intermed_doctor_core::facts::kind::COMPATIBILITY_BRIDGE)
            .any(|bridge| {
                bridge.attr("scope") == Some("mod-runtime")
                    && target_loader.is_some_and(|loader| {
                        bridge.attr("to_loader").is_some_and(|target| {
                            target == loader.as_str()
                                || (target == "forge-family"
                                    && matches!(
                                        loader,
                                        intermed_doctor_core::Loader::Forge
                                            | intermed_doctor_core::Loader::NeoForge
                                    ))
                        })
                    })
            });
        let mut exact_role_candidates: std::collections::BTreeMap<String, Vec<(String, String)>> =
            std::collections::BTreeMap::new();
        let mut basename_role_candidates: std::collections::BTreeMap<
            String,
            Vec<(String, String)>,
        > = std::collections::BTreeMap::new();
        for role in ctx
            .inputs
            .by_kind(intermed_doctor_core::facts::kind::ARTIFACT_ROLE)
        {
            if !matches!(
                role.attr("activation"),
                Some("active" | "self-loader-bootstrap")
            ) {
                continue;
            }
            let Some(declared_id) = role.attr("declared_id") else {
                continue;
            };
            let file_name = std::path::Path::new(role.subject.as_str())
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(role.subject.as_str())
                .to_string();
            let candidate = (
                declared_id.to_string(),
                role.attr("identity_certainty")
                    .unwrap_or("undecidable")
                    .to_string(),
            );
            exact_role_candidates
                .entry(role.subject.to_string())
                .or_default()
                .push(candidate.clone());
            basename_role_candidates
                .entry(file_name)
                .or_default()
                .push(candidate);
        }
        let make_binding = |mut candidates: Vec<(String, String)>| {
            candidates.sort();
            candidates.dedup();
            if candidates.len() == 1 {
                let (mod_id, certainty) = candidates.pop().expect("one candidate");
                scan::ArtifactBinding {
                    mod_id: Some(mod_id),
                    identity_certainty: certainty,
                }
            } else {
                scan::ArtifactBinding {
                    mod_id: None,
                    identity_certainty: "ambiguous-active-roles".to_string(),
                }
            }
        };
        let mut identity_bindings = exact_role_candidates
            .into_iter()
            .map(|(path, candidates)| (format!("path:{path}"), make_binding(candidates)))
            .collect::<std::collections::BTreeMap<_, _>>();
        // A basename is only a fallback for launchers whose metadata reports a
        // relative locator. If two physical artifacts share it, keep the binding
        // explicitly ambiguous rather than borrowing either artifact's identity.
        identity_bindings.extend(
            basename_role_candidates
                .into_iter()
                .map(|(name, candidates)| (format!("name:{name}"), make_binding(candidates))),
        );

        match scan::scan_mods_dir_filtered_with_identity(
            &dir,
            ctx.jar_cache,
            &ctx.settings.scan,
            ctx.settings.mixin,
            ctx.settings.minecraft_jar.as_deref(),
            ctx.settings.minecraft_mappings.as_deref(),
            target_minecraft_version,
            target_loader,
            target_side,
            allow_foreign_configs,
            environment_conflicted,
            &identity_bindings,
        ) {
            Ok(scan) => {
                let emitted = emit_scan(ctx, &scan);
                let summary = format!(
                    "{} config(s), {} mixin class(es), {} overlap(s), {} effect(s), {} recommendation(s), {} risk score(s)",
                    scan.configs.len(),
                    scan.classes.len(),
                    scan.overlaps.len(),
                    scan.mixin_effects.len(),
                    scan.recommendations.len(),
                    scan.risk_assessments.len()
                );
                if scan.failures.is_empty() {
                    CollectorOutcome::active(emitted, summary)
                } else {
                    CollectorOutcome::incomplete(
                        emitted,
                        format!(
                            "{summary}; {} relevant input failure(s)",
                            scan.failures.len()
                        ),
                    )
                }
            }
            Err(e) => CollectorOutcome::failed(e.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class_parser::parse_mixin_class;
    use crate::fixtures;
    use crate::hierarchy::HierarchyIndex;
    use crate::model::MixinConfigRecord;
    use crate::refmap::Refmap;
    use crate::scan::{analyze_class as scan_analyze, join_class_name};

    fn analyze_class(
        config: &MixinConfigRecord,
        mixin: &str,
        class_path: &str,
        bytes: &[u8],
        mapping: &mut MappingContext,
        hierarchy: &HierarchyIndex,
    ) -> MixinClassRecord {
        scan_analyze(config, mixin, class_path, bytes, mapping, hierarchy)
    }

    #[test]
    fn detects_operations_and_targets_from_mixin_annotation() {
        let bytes = fixtures::mixin_class(
            "example/mixin/RenderMixin",
            "net/minecraft/client/render/WorldRenderer",
            &["injection/Redirect"],
        );
        let class = MixinConfigRecord {
            archive: "a.jar".into(),
            artifact_id: "sha256:test".into(),
            path: "a.mixins.json".into(),
            mod_id: "alpha".into(),
            identity_certainty: "confirmed".into(),
            package: "example.mixin".into(),
            priority: 1000,
            refmap: None,
            refmap_status: crate::refmap::RefmapStatus::NotDeclared,
            mixins: vec!["RenderMixin".into()],
            plugin: None,
            mixin_sides: Default::default(),
        };
        let record = analyze_class(
            &class,
            "RenderMixin",
            "example/mixin/RenderMixin.class",
            &bytes,
            &mut MappingContext::new(),
            &HierarchyIndex::new(),
        );
        assert_eq!(record.operations, vec![MixinOperation::Redirect]);
        assert_eq!(
            record.targets,
            vec!["net.minecraft.client.render.WorldRenderer"]
        );
        assert_eq!(record.hot_paths, vec!["world-render"]);
    }

    #[test]
    fn detects_string_form_targets() {
        let bytes = fixtures::mixin_class_string_target(
            "example/mixin/AccessorMixin",
            "net.minecraft.server.MinecraftServer",
            &["injection/Inject"],
        );
        let parsed = parse_mixin_class(&bytes);
        assert_eq!(parsed.targets, vec!["net.minecraft.server.MinecraftServer"]);
        assert_eq!(
            parsed.operations.into_iter().collect::<Vec<_>>(),
            vec![MixinOperation::Inject]
        );
    }

    #[test]
    fn refmap_resolves_injection_points() {
        let json =
            r#"{"mappings":{"net/minecraft/server/MinecraftServer":{"method_1574":"tick()V"}}}"#;
        let refmap = Refmap::parse(json).unwrap();
        let mut mapping = MappingContext::new().with_refmap(refmap);
        let bytes = fixtures::mixin_class_with_inject_method(
            "example/mixin/TickMixin",
            "net/minecraft/server/MinecraftServer",
            "method_1574",
        );
        let class = MixinConfigRecord {
            archive: "a.jar".into(),
            artifact_id: "sha256:test".into(),
            path: "a.mixins.json".into(),
            mod_id: "alpha".into(),
            identity_certainty: "confirmed".into(),
            package: "example.mixin".into(),
            priority: 1000,
            refmap: Some("a.refmap.json".into()),
            refmap_status: crate::refmap::RefmapStatus::DeclaredAndLoaded {
                path: "a.refmap.json".into(),
            },
            mixins: vec!["TickMixin".into()],
            plugin: None,
            mixin_sides: Default::default(),
        };
        let record = analyze_class(
            &class,
            "TickMixin",
            "example/mixin/TickMixin.class",
            &bytes,
            &mut mapping,
            &HierarchyIndex::new(),
        );
        assert_eq!(record.injected_methods.len(), 1);
        assert_eq!(record.injected_methods[0].resolved, "tick()V");
        assert!(record.injected_methods[0].resolved_via_refmap);
    }

    #[test]
    fn graph_to_json_exports_nodes_for_scan() {
        let bytes = fixtures::mixin_class(
            "example/mixin/RenderMixin",
            "net/minecraft/client/render/WorldRenderer",
            &["injection/Inject"],
        );
        let root = std::env::temp_dir().join(format!("intermed-graph-json-{}", std::process::id()));
        let mods = root.join("mods");
        std::fs::create_dir_all(&mods).unwrap();
        let jar = mods.join("alpha.jar");
        {
            use std::io::Write;
            let file = std::fs::File::create(&jar).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("fabric.mod.json", options).unwrap();
            write!(
                zip,
                r#"{{"schemaVersion":1,"id":"alpha","version":"1.0.0","mixins":["a.mixins.json"]}}"#
            )
            .unwrap();
            zip.start_file("a.mixins.json", options).unwrap();
            write!(
                zip,
                r#"{{"required":true,"package":"alpha.mixin","mixins":["RenderMixin"]}}"#
            )
            .unwrap();
            zip.start_file("alpha/mixin/RenderMixin.class", options)
                .unwrap();
            zip.write_all(&bytes).unwrap();
            zip.finish().unwrap();
        }
        let scan = scan_mods_dir(&mods).expect("scan");
        let json = graph_to_json(&scan).expect("graph json");
        assert!(json.contains("RenderMixin"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn empty_scan_exports_valid_empty_graph() {
        // A pack with no Mixins (e.g. Bukkit/Paper plugins) is a valid result,
        // not an error: every export format must yield a well-formed document.
        let scan = MixinScan::default();
        let json = graph_to_json(&scan).expect("empty json");
        assert!(json.contains("\"nodes\""));
        assert!(json.contains("\"edges\""));
        assert!(graph_to_dot(&scan).expect("empty dot").contains("digraph"));
        assert!(
            graph_to_graphml(&scan)
                .expect("empty graphml")
                .contains("<graphml")
        );
        assert!(
            graph_to_html(&scan, "T")
                .expect("empty html")
                .contains("<html")
        );
    }

    #[test]
    fn join_class_name_respects_package() {
        // Simple entry, no sub-package.
        assert_eq!(
            join_class_name("alpha.mixin", "RenderMixin"),
            "alpha.mixin.RenderMixin"
        );
        // Sub-package entry (the common real case, e.g. Create's `accessor.*`):
        // the dot is a sub-package separator and must still be prefixed with the
        // config package — never treated as an already-qualified name.
        assert_eq!(
            join_class_name(
                "com.simibubi.create.foundation.mixin",
                "accessor.FooAccessor"
            ),
            "com.simibubi.create.foundation.mixin.accessor.FooAccessor"
        );
        // No package declared → the entry is used as-is.
        assert_eq!(join_class_name("", "fully.Qualified"), "fully.Qualified");
    }
}
