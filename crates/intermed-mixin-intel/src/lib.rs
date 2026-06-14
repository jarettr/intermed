//! # intermed-mixin-intel — Layer F
//!
//! Static mixin intelligence with refmap resolution, structural class models,
//! interaction graphs, and composite risk scoring. This crate does not
//! transform classes or execute mod code; it reads mixin JSON configs and
//! class-file annotations only.
//!
//! Entry points: [`scan_mods_dir`], [`collector`], [`rule`], [`build_interaction_graph`].
//! Cache revision: [`cache_version`] (bump when parse/analysis logic changes in a release).

mod analyzer;
mod annotation;
mod apply_failure;
mod bloat;
mod bytecode;
mod class_parser;
mod collect;
mod complexity;
mod dataflow;
mod effect;
mod graph;
mod handler_effect;
mod hierarchy;
mod hot_path;
mod injection_point;
mod model;
mod recommendation;
mod refmap;
mod rule;
mod scan;
mod semantics;

#[doc(hidden)]
pub mod fixtures;

pub use analyzer::MixinInteractionEngine;
pub use graph::MixinInteractionGraph;
pub use hot_path::{default_rules, HotPathRules};
pub use model::{
    CallKind, ComplexityComponent, ConflictEdgeType, EffectiveEffectKind, GraphEdge, GraphNode,
    HandlerEffect, HandlerSideEffect, HighRiskOverwrite, InteractionType, MemberKind,
    MixinAddedMember, MixinAnalysis, MixinBloatAssessment, MixinCall, MixinClassComplexity,
    MixinClassModel, MixinClassRecord, MixinConfigRecord, MixinConflictEdgeRecord, MixinEffect,
    MixinGraphExport, MixinInteractionRecord, MixinModComplexity, MixinOperation, MixinOverlap,
    MixinPriorityConflictRecord, MixinRecommendationRecord, MixinRiskAssessment, MixinScan,
    MixinScanFailure, MixinShadowMember, Recommendation, ResolvedInjectionPoint, STATUS,
};
pub use class_parser::{parse_mixin_class, parse_mixin_class_with_hierarchy, ClassParseResult};
pub use recommendation::{recommend_for_scan, redirect_counts_by_method};
pub use refmap::{dotted_name, MappingContext, Refmap, TinyMappings};
pub use scan::{
    cache_version, extractor_id, scan_mods_dir, scan_mods_dir_with_cache, scan_target,
    MixinScanError,
};

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

fn graph_available(scan: &MixinScan) -> bool {
    !scan.classes.is_empty()
        || !scan.interactions.is_empty()
        || !scan.conflict_edges.is_empty()
}

/// Export the interaction graph as Graphviz DOT.
pub fn graph_to_dot(scan: &MixinScan) -> Option<String> {
    if !graph_available(scan) {
        return None;
    }
    Some(build_interaction_graph(scan).to_dot())
}

/// Export the interaction graph as GraphML.
pub fn graph_to_graphml(scan: &MixinScan) -> Option<String> {
    if !graph_available(scan) {
        return None;
    }
    Some(build_interaction_graph(scan).to_graphml())
}

/// Export a self-contained interactive HTML visualization.
pub fn graph_to_html(scan: &MixinScan, title: &str) -> Option<String> {
    if !graph_available(scan) {
        return None;
    }
    Some(build_interaction_graph(scan).to_html(title))
}

/// Export the interaction graph as JSON (`MixinGraphExport`).
pub fn graph_to_json(scan: &MixinScan) -> Option<String> {
    if !graph_available(scan) {
        return None;
    }
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

    fn applies(&self, target: &Target) -> bool {
        mods_dir(target).is_some()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let Some(dir) = mods_dir(ctx.target) else {
            return CollectorOutcome::skipped("no mods directory for mixin scan");
        };

        match scan::scan_mods_dir_filtered(
            &dir,
            ctx.jar_cache,
            &ctx.settings.scan,
            ctx.settings.mixin,
            ctx.settings.minecraft_jar.as_deref(),
            ctx.settings.minecraft_mappings.as_deref(),
        ) {
            Ok(scan) => {
                let emitted = emit_scan(ctx, &scan);
                CollectorOutcome::active(
                    emitted,
                    format!(
                        "{} config(s), {} mixin class(es), {} overlap(s), {} effect(s), {} recommendation(s), {} risk score(s)",
                        scan.configs.len(),
                        scan.classes.len(),
                        scan.overlaps.len(),
                        scan.mixin_effects.len(),
                        scan.recommendations.len(),
                        scan.risk_assessments.len()
                    ),
                )
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
    use crate::model::MixinConfigRecord;
    use crate::refmap::Refmap;
    use crate::hierarchy::HierarchyIndex;
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
            path: "a.mixins.json".into(),
            mod_id: "alpha".into(),
            package: "example.mixin".into(),
            priority: 1000,
            refmap: None,
            mixins: vec!["RenderMixin".into()],
            plugin: None,
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
        assert_eq!(parsed.operations.into_iter().collect::<Vec<_>>(), vec![MixinOperation::Inject]);
    }

    #[test]
    fn refmap_resolves_injection_points() {
        let json = r#"{"mappings":{"net/minecraft/server/MinecraftServer":{"method_1574":"tick()V"}}}"#;
        let refmap = Refmap::parse(json).unwrap();
        let mut mapping = MappingContext::new().with_refmap(refmap);
        let bytes = fixtures::mixin_class_with_inject_method(
            "example/mixin/TickMixin",
            "net/minecraft/server/MinecraftServer",
            "method_1574",
        );
        let class = MixinConfigRecord {
            archive: "a.jar".into(),
            path: "a.mixins.json".into(),
            mod_id: "alpha".into(),
            package: "example.mixin".into(),
            priority: 1000,
            refmap: Some("a.refmap.json".into()),
            mixins: vec!["TickMixin".into()],
            plugin: None,
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
        let root = std::env::temp_dir().join(format!(
            "intermed-graph-json-{}",
            std::process::id()
        ));
        let mods = root.join("mods");
        std::fs::create_dir_all(&mods).unwrap();
        let jar = mods.join("alpha.jar");
        {
            use std::io::Write;
            let file = std::fs::File::create(&jar).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options =
                zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
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
            zip.start_file("alpha/mixin/RenderMixin.class", options).unwrap();
            zip.write_all(&bytes).unwrap();
            zip.finish().unwrap();
        }
        let scan = scan_mods_dir(&mods).expect("scan");
        let json = graph_to_json(&scan).expect("graph json");
        assert!(json.contains("RenderMixin"));
        std::fs::remove_dir_all(root).ok();
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
            join_class_name("com.simibubi.create.foundation.mixin", "accessor.FooAccessor"),
            "com.simibubi.create.foundation.mixin.accessor.FooAccessor"
        );
        // No package declared → the entry is used as-is.
        assert_eq!(join_class_name("", "fully.Qualified"), "fully.Qualified");
    }
}