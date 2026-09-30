//! Canonical cross-layer entity graph and pre-report consistency audit.

use std::collections::{BTreeMap, BTreeSet};

use intermed_evidence::{
    ArtifactId, ArtifactNode, AssessmentDisposition, BridgeCapability, CausalNode,
    CausalTransition, CertaintyTier, ClassSymbol, CompatibilityBridge, ConclusionAdjustment,
    ConclusionKind, Contributor, DependencyEdgeId, DescriptorKind, EntityRef, EnvironmentId,
    EvidenceGraph, EvidenceLink, EvidenceOrigin, EvidenceRelation, EvidenceStrength, Finding,
    FindingAssessment, FindingVisibility, Impact, Incident, JavaRuntimeId, MappingGraphId,
    MappingNamespace, MethodDescriptor, MethodSymbol, MixinSiteId, ModInstanceId, ModInstanceNode,
    ProofKind, ResourceKey, RuntimeOccurrenceId, Severity, ThrowableId,
};
use intermed_facts::{Fact, FactId, FactStore, kind};
use sha2::{Digest, Sha256};

const UNMAPPED_GRAPH: &str = "mapping:unavailable";
const MAX_RESOURCE_GRAPH_LINKS: usize = 10_000;
const MAX_CALL_SLICE_NODES: usize = 4_096;
const MAX_CALL_SLICE_EDGES: usize = 8_192;
const MAX_CALL_SLICE_DEPTH: usize = 4;
// A finding needs a compact, inspectable route through the graph, not every
// parallel link contributed by a large cluster. The graph itself retains the
// complete normalized link set.
const MAX_FINDING_EVIDENCE_PATH: usize = 256;

mod completion;
mod graph;
mod identity;
mod incident;
mod reconcile;
mod shared;

pub use completion::complete_evidence_graph;
pub use graph::build_evidence_graph;
pub use identity::stabilize_finding_identities;
pub use incident::synthesize_incidents;
pub use reconcile::reconcile_findings;
use shared::*;

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_evidence::EvidenceEdge;
    use intermed_facts::SourceRef;

    #[test]
    fn content_identity_connects_artifact_mod_and_runtime_class() {
        let mut store = FactStore::new();
        let archive = "/mods/a.jar";
        store
            .fact("sbom", kind::CHECKSUM)
            .subject(archive)
            .attr("algorithm", "sha256")
            .attr("hex", "a".repeat(64))
            .source(SourceRef::file(archive))
            .emit();
        store
            .fact("metadata", kind::MOD)
            .subject("a")
            .attr("file", archive)
            .attr("loader", "fabric")
            .source(SourceRef::inside(archive, "fabric.mod.json"))
            .emit();
        store
            .fact("log", kind::STACK_FRAME)
            .subject("event:1")
            .attr("class", "a.Main")
            .attr("method", "run")
            .attr("mod_id", "a")
            .emit();
        let graph = build_evidence_graph(&store);
        assert_eq!(
            graph.artifacts[0].id.as_str(),
            format!("sha256:{}", "a".repeat(64))
        );
        assert!(
            graph
                .links
                .iter()
                .any(|link| link.relation == EvidenceRelation::Contains)
        );
        assert!(
            graph
                .links
                .iter()
                .any(|link| link.relation == EvidenceRelation::ObservedIn)
        );
    }

    #[test]
    fn duplicate_mod_ids_keep_dependencies_on_their_containing_artifact() {
        let mut store = FactStore::new();
        let first = "/mods/first.jar";
        let second = "/mods/second.jar";
        for (archive, digest) in [(first, "a".repeat(64)), (second, "b".repeat(64))] {
            store
                .fact("sbom", kind::CHECKSUM)
                .subject(archive)
                .attr("algorithm", "sha256")
                .attr("hex", digest)
                .source(SourceRef::file(archive))
                .emit();
            store
                .fact("metadata", kind::MOD)
                .subject("duplicate")
                .attr("loader", "fabric")
                .source(SourceRef::inside(archive, "fabric.mod.json"))
                .emit();
        }
        let first_dependency = store
            .fact("metadata", kind::DEPENDENCY)
            .subject("duplicate")
            .attr("dep", "first-api")
            .attr("range", ">=1")
            .source(SourceRef::inside(first, "fabric.mod.json"))
            .emit();
        let second_dependency = store
            .fact("metadata", kind::DEPENDENCY)
            .subject("duplicate")
            .attr("dep", "second-api")
            .attr("range", ">=1")
            .source(SourceRef::inside(second, "fabric.mod.json"))
            .emit();

        let graph = build_evidence_graph(&store);
        let declared_by = |fact_id| {
            graph
                .links
                .iter()
                .filter(|link| {
                    link.source_fact == fact_id && link.relation == EvidenceRelation::Declares
                })
                .map(|link| match &link.from {
                    EntityRef::Mod(instance) => instance.artifact.clone(),
                    other => panic!("dependency source is not a mod instance: {other:?}"),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            declared_by(first_dependency),
            vec![ArtifactId::from_sha256(&"a".repeat(64)).unwrap()]
        );
        assert_eq!(
            declared_by(second_dependency),
            vec![ArtifactId::from_sha256(&"b".repeat(64)).unwrap()]
        );

        let rebuilt = build_evidence_graph(&store);
        assert_eq!(graph.entities, rebuilt.entities);
    }

    #[test]
    fn one_content_artifact_preserves_every_physical_locator() {
        let mut store = FactStore::new();
        for archive in ["/mods/copy-a.jar", "/mods/copy-b.jar"] {
            store
                .fact("sbom", kind::CHECKSUM)
                .subject(archive)
                .attr("algorithm", "sha256")
                .attr("hex", "c".repeat(64))
                .source(SourceRef::file(archive))
                .emit();
        }
        let graph = build_evidence_graph(&store);
        assert_eq!(graph.artifacts.len(), 1);
        assert_eq!(
            graph.artifacts[0].locators,
            vec!["/mods/copy-a.jar", "/mods/copy-b.jar"]
        );
    }

    #[test]
    fn typed_class_absence_is_abstained_by_runtime_evidence() {
        let mut store = FactStore::new();
        let site = store
            .fact("mixin", kind::MIXIN_APPLICATION_SITE)
            .subject("site")
            .attr("target", "example.Target")
            .emit();
        let runtime = store
            .fact("log", kind::STACK_FRAME)
            .subject("event:1")
            .attr("class", "example.Target")
            .attr("method", "tick")
            .emit();
        let mut graph = build_evidence_graph(&store);
        let mut findings = vec![
            Finding::builder("mixin", "presentation-id-can-change")
                .conclusion_kind(ConclusionKind::ClassAbsent)
                .severity(Severity::Error)
                .evidence(intermed_evidence::EvidenceEdge::subject(site))
                .build(),
        ];
        reconcile_findings(&store, &mut graph, &mut findings);
        assert_eq!(
            findings[0].assessment.disposition,
            AssessmentDisposition::Abstained
        );
        assert_eq!(
            findings[0].assessment.adjustments[0].contradicting_evidence,
            vec![runtime]
        );
    }

    #[test]
    fn repeated_terminal_occurrences_group_without_merging_physical_ids() {
        let mut store = FactStore::new();
        for occurrence in ["event:1", "event:2"] {
            store
                .fact("log-analyzer", kind::RUNTIME_EVENT)
                .subject(occurrence)
                .attr("semantic_fingerprint", "strict")
                .attr("fuzzy_fingerprint", "fuzzy")
                .attr("terminality", "process-fatal")
                .emit();
            store
                .fact("log-analyzer", kind::CRASH_ANCHOR)
                .subject(occurrence)
                .attr("semantic_fingerprint", "strict")
                .attr("fuzzy_fingerprint", "fuzzy")
                .emit();
            store
                .fact("log-analyzer", kind::THROWABLE_NODE)
                .subject(occurrence)
                .attr("index", 1i64)
                .attr("deepest", true)
                .attr("type", "java.lang.IllegalStateException")
                .attr("message", "boom")
                .emit();
        }
        let graph = build_evidence_graph(&store);
        let incidents = synthesize_incidents(&store, &graph);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].occurrences.len(), 2);
        assert_ne!(incidents[0].occurrences[0], incidents[0].occurrences[1]);
    }

    #[test]
    fn incident_transition_runs_from_stack_caller_to_callee() {
        let mut store = FactStore::new();
        store
            .fact("log-analyzer", kind::RUNTIME_EVENT)
            .subject("event:1")
            .attr("semantic_fingerprint", "strict")
            .attr("fuzzy_fingerprint", "fuzzy")
            .attr("terminality", "process-fatal")
            .emit();
        store
            .fact("log-analyzer", kind::CRASH_ANCHOR)
            .subject("event:1")
            .attr("semantic_fingerprint", "strict")
            .attr("fuzzy_fingerprint", "fuzzy")
            .emit();
        store
            .fact("log-analyzer", kind::THROWABLE_NODE)
            .subject("event:1")
            .attr("index", 0i64)
            .attr("deepest", true)
            .attr("type", "java.lang.IllegalStateException")
            .emit();
        // Stack order is callee first, then its caller.
        for (class, method, mod_id) in [
            ("com.api.Keys", "isDown", "api"),
            ("com.addon.Tooltip", "append", "addon"),
        ] {
            store
                .fact("log-analyzer", kind::STACK_FRAME)
                .subject("event:1")
                .attr("class", class)
                .attr("method", method)
                .attr("mod_id", mod_id)
                .emit();
        }
        let graph = build_evidence_graph(&store);
        let incident = synthesize_incidents(&store, &graph).remove(0);
        let transition = incident.caller_transition.expect("owned transition");
        let EntityRef::Method(caller) = transition.caller.expect("distinct caller") else {
            panic!("caller should be a method");
        };
        let EntityRef::Method(callee) = transition.callee else {
            panic!("callee should be a method");
        };
        assert_eq!(caller.owner.name, "com.addon.Tooltip");
        assert_eq!(callee.owner.name, "com.api.Keys");
    }

    #[test]
    fn finding_evidence_path_is_bounded_without_truncating_the_graph() {
        let mut store = FactStore::new();
        let mut evidence = Vec::new();
        for index in 0..(MAX_FINDING_EVIDENCE_PATH + 10) {
            evidence.push(
                store
                    .fact("log-analyzer", kind::STACK_FRAME)
                    .subject(format!("event:{index}"))
                    .attr("class", format!("example.Frame{index}"))
                    .attr("method", "run")
                    .emit(),
            );
        }
        let mut graph = build_evidence_graph(&store);
        assert!(graph.links.len() > MAX_FINDING_EVIDENCE_PATH);
        let mut finding = Finding::builder("test", "large-evidence")
            .conclusion_kind(ConclusionKind::Generic)
            .build();
        finding.evidence = evidence.into_iter().map(EvidenceEdge::subject).collect();
        let mut findings = vec![finding];
        reconcile_findings(&store, &mut graph, &mut findings);
        assert_eq!(findings[0].evidence_path.len(), MAX_FINDING_EVIDENCE_PATH);
        assert!(
            findings[0]
                .assessment
                .adjustments
                .iter()
                .any(|adjustment| adjustment.code == "evidence-path-truncated")
        );
        assert!(graph.links.len() > findings[0].evidence_path.len());
    }

    #[test]
    fn environment_evidence_does_not_become_a_fake_mod_entity() {
        let mut store = FactStore::new();
        let environment = store
            .fact("environment", kind::ENVIRONMENT)
            .subject("instance")
            .attr("loader", "forge")
            .emit();
        let findings = ["first", "second"]
            .into_iter()
            .map(|id| {
                Finding::builder("test", id)
                    .evidence(EvidenceEdge::subject(environment))
                    .build()
            })
            .collect::<Vec<_>>();
        let mut graph = EvidenceGraph::default();
        complete_evidence_graph(&store, &mut graph, &findings);
        assert_eq!(
            graph
                .links
                .iter()
                .filter(|link| link.source_fact == environment)
                .count(),
            1,
            "shared environment evidence has one canonical typed link"
        );
        assert!(graph.entities.iter().any(|entity| matches!(
            entity,
            EntityRef::Environment(id) if id.as_str() == "target-environment"
        )));
        assert!(
            !graph
                .entities
                .iter()
                .any(|entity| matches!(entity, EntityRef::Mod(_)))
        );
    }

    #[test]
    fn shared_unmodeled_evidence_is_coverage_not_a_fabricated_entity() {
        let mut store = FactStore::new();
        let evidence = store
            .fact("metadata", kind::INVALID_METADATA)
            .subject("broken.jar")
            .emit();
        let findings = ["first", "second"]
            .into_iter()
            .map(|id| {
                Finding::builder("test", id)
                    .evidence(EvidenceEdge::subject(evidence))
                    .build()
            })
            .collect::<Vec<_>>();
        let mut graph = EvidenceGraph::default();

        complete_evidence_graph(&store, &mut graph, &findings);

        assert_eq!(
            graph
                .links
                .iter()
                .filter(|link| link.source_fact == evidence)
                .count(),
            0
        );
        assert_eq!(graph.coverage_evidence, vec![evidence]);
        assert!(graph.entities.is_empty());
    }

    #[test]
    fn mixin_conflict_evidence_names_the_real_target_class() {
        let mut store = FactStore::new();
        let conflict = store
            .fact("mixin", kind::MIXIN_CONFLICT_EDGE)
            .subject("edge-1")
            .attr("edge_type", "overwrite-vs-injector")
            .attr("target_class", "net.minecraft.client.render.WorldRenderer")
            .emit();
        let mut graph = build_evidence_graph(&store);
        let mut findings = vec![
            Finding::builder("mixin-risk", "mixin-conflict-pair:alpha<->beta")
                .evidence(EvidenceEdge::subject(conflict))
                .build(),
        ];

        reconcile_findings(&store, &mut graph, &mut findings);

        assert!(findings[0].evidence_path.iter().any(|link| {
            matches!(
                &link.to,
                EntityRef::Class(class)
                    if class.name == "net.minecraft.client.render.WorldRenderer"
            )
        }));
        assert!(!findings[0].evidence_path.iter().any(|link| {
            matches!(
                &link.from,
                EntityRef::Mod(instance) if instance.declared_id == "edge-1"
            )
        }));
    }

    #[test]
    fn descriptorless_container_still_owns_its_nested_mod_entity() {
        let mut store = FactStore::new();
        let nested_fact = store
            .fact("metadata", kind::NESTED_JAR)
            .subject("container:kotlinforforge.jar")
            .attr("nested", "kotlinforforge")
            .attr("version", "5.11.0")
            .attr("container", "kotlinforforge.jar")
            .attr(
                "nested_path",
                "META-INF/jarjar/thedarkcolour.kffmod-5.11.0.jar",
            )
            .emit();

        let graph = build_evidence_graph(&store);
        let nested_mod = graph
            .mods
            .iter()
            .find(|node| node.id.declared_id == "kotlinforforge")
            .expect("nested mod entity");
        assert_eq!(nested_mod.version.as_deref(), Some("5.11.0"));
        assert!(graph.links.iter().any(|link| {
            link.source_fact == nested_fact
                && link.relation == EvidenceRelation::Embeds
                && matches!(&link.from, EntityRef::Artifact(_))
                && matches!(&link.to, EntityRef::Artifact(_))
        }));
    }

    #[test]
    fn targeted_call_slice_follows_runtime_root_and_refutes_unused_dependency() {
        let mut store = FactStore::new();
        store
            .fact("metadata", kind::MOD)
            .subject("addon")
            .attr("file", "addon.jar")
            .emit();
        store
            .fact("metadata", kind::MOD)
            .subject("api")
            .attr("file", "api.jar")
            .emit();
        store
            .fact("metadata", kind::PACKAGE_OWNER)
            .subject("api")
            .attr("package", "com.api")
            .emit();
        store
            .fact("metadata", kind::CALL_SLICE_COVERAGE)
            .subject("addon")
            .attr("truncated", false)
            .emit();
        store
            .fact("log-analyzer", kind::STACK_FRAME)
            .subject("event")
            .attr("class", "com.addon.Entry")
            .attr("method", "run")
            .attr("mod_id", "addon")
            .emit();
        let call = store
            .fact("metadata", kind::BYTECODE_CALL_EDGE)
            .subject("addon")
            .attr("caller_class", "com.addon.Entry")
            .attr("caller_method", "run")
            .attr("caller_descriptor", "()V")
            .attr("target_class", "com.api.Service")
            .attr("target_method", "call")
            .attr("target_descriptor", "()V")
            .attr("dispatch", "exact")
            .attr("archive", "addon.jar")
            .emit();
        let mut graph = build_evidence_graph(&store);
        assert!(
            graph
                .links
                .iter()
                .any(|link| link.source_fact == call && link.relation == EvidenceRelation::Calls)
        );
        let mut findings = vec![
            Finding::builder("dependency", "old-presentation-id")
                .conclusion_kind(ConclusionKind::DependencyUnused)
                .severity(Severity::Note)
                .affects("addon")
                .affects("api")
                .build(),
        ];
        reconcile_findings(&store, &mut graph, &mut findings);
        assert_eq!(
            findings[0].assessment.disposition,
            AssessmentDisposition::Abstained
        );
        assert!(
            findings[0].assessment.adjustments[0]
                .contradicting_evidence
                .contains(&call)
        );
    }

    #[test]
    fn semantic_identity_does_not_depend_on_presentation_id() {
        let store = FactStore::new();
        let graph = build_evidence_graph(&store);
        let build = |id: &str| {
            Finding::builder("dependency", id)
                .conclusion_kind(ConclusionKind::MissingDependency)
                .affects("consumer")
                .affects("provider")
                .build()
        };
        let mut findings = vec![build("old-id"), build("renamed-id")];
        stabilize_finding_identities(&store, &graph, &mut findings);
        assert_eq!(findings[0].semantic_id, findings[1].semantic_id);
        assert_eq!(findings[0].occurrence_id, findings[1].occurrence_id);
    }

    #[test]
    fn typed_condition_family_distinguishes_same_resource_entity() {
        let store = FactStore::new();
        let graph = build_evidence_graph(&store);
        let build = |family: &str| {
            Finding::builder(
                "resource-semantics",
                format!("{family}:data/example/recipe.json"),
            )
            .family(family)
            .conclusion_kind(ConclusionKind::StaticResourceState)
            .affects("data/example/recipe.json")
            .build()
        };
        let mut findings = vec![
            build("recipe-output-override"),
            build("recipe-ingredient-override"),
        ];
        stabilize_finding_identities(&store, &graph, &mut findings);
        assert_ne!(findings[0].semantic_id, findings[1].semantic_id);
        assert_ne!(findings[0].occurrence_id, findings[1].occurrence_id);
    }

    #[test]
    fn occurrence_identity_is_independent_of_evidence_order() {
        let mut store = FactStore::new();
        let a = store
            .fact("a", kind::UNKNOWN_SOURCE)
            .subject("artifact.jar")
            .source(SourceRef::at_line("latest.log", 10))
            .emit();
        let b = store
            .fact("b", kind::TRUST_SCORE)
            .subject("artifact.jar")
            .source(SourceRef::at_line("latest.log", 11))
            .emit();
        let graph = build_evidence_graph(&store);
        let build = |first, second| {
            Finding::builder("producer", "condition:artifact.jar")
                .evidence(intermed_evidence::EvidenceEdge::subject(first))
                .evidence(intermed_evidence::EvidenceEdge::supports(second))
                .build()
        };
        let mut findings = vec![build(a, b), build(b, a)];
        stabilize_finding_identities(&store, &graph, &mut findings);
        assert_eq!(findings[0].semantic_id, findings[1].semantic_id);
        assert_eq!(findings[0].occurrence_id, findings[1].occurrence_id);
    }

    #[test]
    fn generic_conditions_on_one_component_keep_distinct_machine_identities() {
        let mut store = FactStore::new();
        let cluster = store
            .fact("mixin", kind::MIXIN_RISK_CLUSTER)
            .subject("net.minecraft.Target")
            .emit();
        let effect = store
            .fact("mixin", kind::MIXIN_HANDLER_EFFECT)
            .subject("net.minecraft.Target")
            .emit();
        let graph = build_evidence_graph(&store);
        let mut findings = vec![
            Finding::builder("mixin-risk", "mixin-cluster:net.minecraft.Target")
                .affects("net.minecraft.Target")
                .evidence(EvidenceEdge::subject(cluster))
                .build(),
            Finding::builder(
                "mixin-risk",
                "mixin-overwrite-effect:Mixin->net.minecraft.Target",
            )
            .affects("net.minecraft.Target")
            .evidence(EvidenceEdge::subject(effect))
            .build(),
        ];
        stabilize_finding_identities(&store, &graph, &mut findings);
        assert_ne!(findings[0].semantic_id, findings[1].semantic_id);
        assert_ne!(findings[0].occurrence_id, findings[1].occurrence_id);
    }

    #[test]
    fn incomplete_findings_keep_collector_scopes_distinct() {
        let mut store = FactStore::new();
        let resource = store
            .fact("vfs-scanner", kind::SCAN_TRUNCATED)
            .subject("large.jar")
            .attr("layer", "resource")
            .attr("reason", "entry limit reached")
            .source(SourceRef::file("large.jar"))
            .emit();
        let data_semantics = store
            .fact("resource-ast-scanner", kind::SCAN_TRUNCATED)
            .subject("large.jar")
            .attr("layer", "data-semantics")
            .attr("reason", "entry limit reached")
            .source(SourceRef::file("large.jar"))
            .emit();
        let graph = build_evidence_graph(&store);
        let build = |id: &str, fact| {
            Finding::builder("scan-incomplete", id)
                .conclusion_kind(ConclusionKind::AnalysisIncomplete)
                .affects("large.jar")
                .evidence(EvidenceEdge::subject(fact))
                .build()
        };
        let mut findings = vec![
            build("scan-incomplete:resource:large.jar", resource),
            build("scan-incomplete:data-semantics:large.jar", data_semantics),
        ];
        stabilize_finding_identities(&store, &graph, &mut findings);
        assert_ne!(findings[0].semantic_id, findings[1].semantic_id);
        assert_ne!(findings[0].occurrence_id, findings[1].occurrence_id);
    }
}
