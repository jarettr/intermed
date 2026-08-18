//! Canonical cross-layer entity graph and pre-report consistency audit.

use std::collections::{BTreeMap, BTreeSet};

use intermed_evidence::{
    ArtifactId, ArtifactNode, AssessmentDisposition, BridgeCapability, CausalNode,
    CausalTransition, CertaintyTier, ClassSymbol, CompatibilityBridge, ConclusionAdjustment,
    ConclusionKind, Contributor, DescriptorKind, EntityRef, EvidenceGraph, EvidenceLink,
    EvidenceOrigin, EvidenceRelation, EvidenceStrength, Finding, FindingAssessment,
    FindingVisibility, Impact, Incident, MappingGraphId, MappingNamespace, MethodDescriptor,
    MethodSymbol, MixinSiteId, ModInstanceId, ModInstanceNode, ProofKind, ResourceKey,
    RuntimeOccurrenceId, Severity, ThrowableId,
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

/// Build one canonical graph from facts emitted by every collector. Physical
/// paths are locators; content hashes, when present, are artifact identities.
#[must_use]
pub fn build_evidence_graph(store: &FactStore) -> EvidenceGraph {
    let mut graph = EvidenceGraph::default();
    let mut artifact_by_locator = BTreeMap::<String, ArtifactId>::new();

    for fact in store
        .by_kind(kind::CHECKSUM)
        .filter(|f| f.attr("algorithm") == Some("sha256"))
    {
        if let Some(id) = fact.attr("hex").and_then(ArtifactId::from_sha256) {
            artifact_by_locator.insert(fact.subject.clone(), id.clone());
            graph.artifacts.push(ArtifactNode {
                id: id.clone(),
                locators: vec![fact.subject.clone()],
                embedded_artifacts: Vec::new(),
            });
            graph.entities.push(EntityRef::Artifact(id));
        }
    }
    for fact in store.by_kind(kind::SBOM) {
        let id = fact
            .attr("sha256")
            .and_then(ArtifactId::from_sha256)
            .unwrap_or_else(|| ArtifactId::unresolved(&fact.subject));
        artifact_by_locator
            .entry(fact.subject.clone())
            .or_insert_with(|| id.clone());
        graph.artifacts.push(ArtifactNode {
            id: id.clone(),
            locators: vec![fact.subject.clone()],
            embedded_artifacts: Vec::new(),
        });
        graph.entities.push(EntityRef::Artifact(id));
    }

    let mut mods_by_declared = BTreeMap::<String, Vec<ModInstanceId>>::new();
    let mut ordinal_by_identity = BTreeMap::<(ArtifactId, String, DescriptorKind), u16>::new();
    for fact in store.by_kind(kind::MOD).chain(store.by_kind(kind::PLUGIN)) {
        let locator = fact.attr("file").unwrap_or(&fact.source.locator);
        let artifact = artifact_for(locator, &mut artifact_by_locator, &mut graph);
        let descriptor_kind = DescriptorKind::from_token(fact.attr("loader").unwrap_or("unknown"));
        let key = (artifact.clone(), fact.subject.clone(), descriptor_kind);
        let ordinal = ordinal_by_identity.entry(key).or_default();
        let id = ModInstanceId {
            artifact: artifact.clone(),
            declared_id: fact.subject.clone(),
            descriptor_kind,
            ordinal: *ordinal,
        };
        *ordinal = ordinal.saturating_add(1);
        let active = fact.attr("identity_certainty") != Some("undecidable")
            && fact.attr_bool("active_for_instance") != Some(false);
        graph.mods.push(ModInstanceNode {
            id: id.clone(),
            version: fact.attr("version").map(str::to_owned),
            loader: fact.attr("loader").map(str::to_owned),
            active,
        });
        graph.entities.push(EntityRef::Mod(id.clone()));
        graph.links.push(link(
            EntityRef::Artifact(artifact),
            EvidenceRelation::Contains,
            EntityRef::Mod(id.clone()),
            EvidenceOrigin::StaticExact,
            EvidenceStrength::Exact,
            fact.id,
        ));
        mods_by_declared
            .entry(fact.subject.clone())
            .or_default()
            .push(id);
    }

    for fact in store.by_kind(kind::DEPENDENCY) {
        let candidates = mods_by_declared
            .get(&fact.subject)
            .cloned()
            .unwrap_or_default();
        let source_artifact = artifact_by_locator.get(&fact.source.locator);
        let mut sources = candidates
            .iter()
            .filter(|source| source_artifact.is_some_and(|artifact| source.artifact == *artifact))
            .cloned()
            .collect::<Vec<_>>();
        // Synthetic/custom facts may not have an archive checksum. A unique mod
        // identity is still safe; multiple same-id instances must remain
        // unresolved instead of acquiring one another's dependency edges.
        if sources.is_empty() && candidates.len() == 1 {
            sources = candidates;
        }
        if sources.is_empty() {
            graph
                .entities
                .push(EntityRef::Dependency(dependency_edge_id(
                    fact,
                    &fact.source.locator,
                )));
        }
        for source in sources {
            let dependency = EntityRef::Dependency(dependency_edge_id(fact, &source.to_string()));
            graph.entities.push(dependency.clone());
            graph.links.push(link(
                EntityRef::Mod(source),
                EvidenceRelation::Declares,
                dependency.clone(),
                EvidenceOrigin::StaticExact,
                EvidenceStrength::Exact,
                fact.id,
            ));
        }
    }

    for fact in store.by_kind(kind::NESTED_JAR) {
        let nested_name = fact.attr("nested").unwrap_or("unknown");
        let parents = mods_by_declared
            .get(&fact.subject)
            .cloned()
            .unwrap_or_default();
        for parent in &parents {
            let locator = format!("{}!/{}", parent.artifact, nested_name);
            let nested = ArtifactId::unresolved(&locator);
            graph.artifacts.push(ArtifactNode {
                id: nested.clone(),
                locators: vec![locator.clone()],
                embedded_artifacts: Vec::new(),
            });
            graph.links.push(link(
                EntityRef::Artifact(parent.artifact.clone()),
                EvidenceRelation::Embeds,
                EntityRef::Artifact(nested.clone()),
                EvidenceOrigin::StaticExact,
                EvidenceStrength::Exact,
                fact.id,
            ));
            graph.entities.push(EntityRef::Artifact(nested));
            let nested_mod = ModInstanceId {
                artifact: ArtifactId::unresolved(&locator),
                declared_id: nested_name.to_string(),
                descriptor_kind: DescriptorKind::JarJar,
                ordinal: 0,
            };
            graph.mods.push(ModInstanceNode {
                id: nested_mod.clone(),
                version: fact.attr("version").map(str::to_string),
                loader: None,
                active: true,
            });
            graph.entities.push(EntityRef::Mod(nested_mod.clone()));
            graph.links.push(link(
                EntityRef::Artifact(nested_mod.artifact.clone()),
                EvidenceRelation::Contains,
                EntityRef::Mod(nested_mod.clone()),
                EvidenceOrigin::StaticExact,
                EvidenceStrength::Exact,
                fact.id,
            ));
            mods_by_declared
                .entry(nested_name.to_string())
                .or_default()
                .push(nested_mod);
        }
    }

    add_code_and_resource_entities(store, &mods_by_declared, &mut graph);
    add_runtime_entities(store, &mods_by_declared, &mut graph);
    add_security_provenance_links(store, &artifact_by_locator, &mods_by_declared, &mut graph);
    add_bridges(store, &artifact_by_locator, &mods_by_declared, &mut graph);
    graph.normalize();
    graph
}

fn dependency_edge_id(fact: &Fact, consumer_identity: &str) -> intermed_evidence::DependencyEdgeId {
    let mut digest = Sha256::new();
    digest.update(b"intermed-dependency-edge-v1\0");
    hash_tagged(&mut digest, "consumer", consumer_identity);
    hash_tagged(&mut digest, "declared-id", &fact.subject);
    for key in [
        "dep",
        "range",
        "mandatory",
        "relation",
        "version_dialect",
        "feature",
        "environment",
        "side",
    ] {
        if let Some(value) = fact.attributes.get(key) {
            hash_tagged(&mut digest, key, &format!("{value:?}"));
        }
    }
    intermed_evidence::DependencyEdgeId::new(format!("dependency:{:x}", digest.finalize()))
}

fn add_code_and_resource_entities(
    store: &FactStore,
    mods: &BTreeMap<String, Vec<ModInstanceId>>,
    graph: &mut EvidenceGraph,
) {
    let package_owners = store
        .by_kind(kind::PACKAGE_OWNER)
        .filter_map(|fact| Some((fact.attr("package")?.to_string(), fact.subject.clone())))
        .collect::<Vec<_>>();
    for fact in store.by_kind(kind::ENTRYPOINT) {
        let Some(class) = fact.attr("class") else {
            continue;
        };
        let class = class_entity(class, fact.attr("namespace"));
        graph.entities.push(class.clone());
        for owner in mods.get(&fact.subject).into_iter().flatten() {
            graph.links.push(link(
                EntityRef::Mod(owner.clone()),
                EvidenceRelation::Owns,
                class.clone(),
                EvidenceOrigin::StaticExact,
                EvidenceStrength::Exact,
                fact.id,
            ));
        }
    }
    let resource_fact_count = store.by_kind(kind::RESOURCE_WRITER).count()
        + store.by_kind(kind::RESOURCE_REFERENCE).count();
    let mut resource_links = 0usize;
    for fact in store
        .by_kind(kind::RESOURCE_WRITER)
        .take(MAX_RESOURCE_GRAPH_LINKS)
    {
        let Some(path) = fact.attr("path") else {
            continue;
        };
        let resource = EntityRef::Resource(ResourceKey::new(path));
        graph.entities.push(resource.clone());
        for owner in mods.get(&fact.subject).into_iter().flatten() {
            if resource_links >= MAX_RESOURCE_GRAPH_LINKS {
                break;
            }
            graph.links.push(link(
                EntityRef::Mod(owner.clone()),
                EvidenceRelation::Ships,
                resource.clone(),
                EvidenceOrigin::StaticExact,
                EvidenceStrength::Exact,
                fact.id,
            ));
            resource_links += 1;
        }
    }
    for fact in store
        .by_kind(kind::RESOURCE_REFERENCE)
        .take(MAX_RESOURCE_GRAPH_LINKS.saturating_sub(resource_links))
    {
        let Some(target) = fact.attr("to") else {
            continue;
        };
        let from = EntityRef::Resource(ResourceKey::new(&fact.subject));
        let to = EntityRef::Resource(ResourceKey::new(target));
        graph.entities.extend([from.clone(), to.clone()]);
        graph.links.push(link(
            from,
            EvidenceRelation::References,
            to,
            EvidenceOrigin::StaticInferred,
            if fact.confidence >= 0.99 {
                EvidenceStrength::Exact
            } else {
                EvidenceStrength::Corroborating
            },
            fact.id,
        ));
        resource_links += 1;
    }
    graph.resource_graph_coverage = if resource_fact_count > resource_links {
        intermed_evidence::CoverageState::Partial {
            gaps: vec![intermed_evidence::CoverageGap::new(
                "resource-graph-budget",
                format!(
                    "retained {resource_links} of {resource_fact_count} resource relationships"
                ),
            )],
        }
    } else {
        intermed_evidence::CoverageState::Complete
    };
    for fact in store.by_kind(kind::MIXIN_APPLICATION_SITE) {
        let site = EntityRef::MixinSite(MixinSiteId::new(
            fact.attr("site_occurrence_id").unwrap_or(&fact.subject),
        ));
        let target_class = fact.attr("target_class").unwrap_or("");
        let target_method = fact.attr("target_method").unwrap_or("");
        let class = class_entity(target_class, fact.attr("namespace"));
        graph.entities.extend([site.clone(), class.clone()]);
        let target = if target_method.is_empty() {
            class
        } else {
            let (name, descriptor) = target_method
                .split_once('(')
                .map_or((target_method, ""), |(n, _)| (n, &target_method[n.len()..]));
            EntityRef::Method(MethodSymbol {
                owner: match class {
                    EntityRef::Class(symbol) => symbol,
                    _ => unreachable!(),
                },
                name: name.to_string(),
                descriptor: MethodDescriptor::new(descriptor)
                    .unwrap_or_else(MethodDescriptor::unknown),
            })
        };
        graph.entities.push(target.clone());
        graph.links.push(link(
            site,
            EvidenceRelation::AppliesTo,
            target,
            EvidenceOrigin::StaticExact,
            EvidenceStrength::Exact,
            fact.id,
        ));
    }
    let (selected_call_edges, call_slice_coverage) = targeted_call_slice(store);
    graph.call_slice_coverage = call_slice_coverage;
    graph
        .coverage_evidence
        .extend(store.by_kind(kind::CALL_SLICE_COVERAGE).map(|fact| fact.id));
    // These facts are consumed again while constructing the final report.
    // Preserve them across post-rule evidence compaction even when no finding
    // happens to cite the selected environment directly.
    graph.coverage_evidence.extend(
        store
            .by_kind(kind::ENVIRONMENT)
            .chain(store.by_kind(kind::JAVA_RUNTIME))
            .map(|fact| fact.id),
    );
    for fact in store
        .by_kind(kind::BYTECODE_CALL_EDGE)
        .filter(|fact| selected_call_edges.contains(&fact.id))
    {
        let (Some(caller_class), Some(caller_method), Some(target_class), Some(target_method)) = (
            fact.attr("caller_class"),
            fact.attr("caller_method"),
            fact.attr("target_class"),
            fact.attr("target_method"),
        ) else {
            continue;
        };
        let caller = EntityRef::Method(MethodSymbol {
            owner: ClassSymbol::new(
                caller_class,
                MappingNamespace::Unknown,
                MappingGraphId::new(UNMAPPED_GRAPH),
            ),
            name: caller_method.to_string(),
            descriptor: fact
                .attr("caller_descriptor")
                .and_then(MethodDescriptor::new)
                .unwrap_or_else(MethodDescriptor::unknown),
        });
        let target = EntityRef::Method(MethodSymbol {
            owner: ClassSymbol::new(
                target_class,
                MappingNamespace::Unknown,
                MappingGraphId::new(UNMAPPED_GRAPH),
            ),
            name: target_method.to_string(),
            descriptor: fact
                .attr("target_descriptor")
                .and_then(MethodDescriptor::new)
                .unwrap_or_else(MethodDescriptor::unknown),
        });
        graph.entities.extend([caller.clone(), target.clone()]);
        graph.links.push(link(
            caller.clone(),
            EvidenceRelation::Calls,
            target,
            EvidenceOrigin::StaticExact,
            if fact.attr("dispatch") == Some("exact") {
                EvidenceStrength::Exact
            } else {
                EvidenceStrength::Corroborating
            },
            fact.id,
        ));
        for owner in mods.get(&fact.subject).into_iter().flatten() {
            graph.links.push(link(
                EntityRef::Mod(owner.clone()),
                EvidenceRelation::Owns,
                caller.clone(),
                EvidenceOrigin::StaticExact,
                EvidenceStrength::Exact,
                fact.id,
            ));
        }
        if let Some((_, target_mod)) = package_owners
            .iter()
            .filter(|(package, _)| class_under_package(target_class, package))
            .max_by_key(|(package, _)| package.len())
            && let Some(owner) = mods.get(target_mod).and_then(|instances| instances.first())
        {
            graph.links.push(link(
                EntityRef::Mod(owner.clone()),
                EvidenceRelation::Owns,
                class_entity(target_class, Some("unknown")),
                EvidenceOrigin::StaticExact,
                EvidenceStrength::Exact,
                fact.id,
            ));
        }
    }
}

fn targeted_call_slice(store: &FactStore) -> (BTreeSet<FactId>, intermed_evidence::CoverageState) {
    let edges = store.by_kind(kind::BYTECODE_CALL_EDGE).collect::<Vec<_>>();
    let has_coverage = store.by_kind(kind::CALL_SLICE_COVERAGE).next().is_some();
    if !has_coverage {
        return (
            BTreeSet::new(),
            intermed_evidence::CoverageState::Unavailable {
                reasons: vec![intermed_evidence::CoverageGap::new(
                    "call-slice-unavailable",
                    "metadata full bytecode scan did not run",
                )],
            },
        );
    }
    let mut by_caller = BTreeMap::<(String, String), Vec<&Fact>>::new();
    for edge in &edges {
        let (Some(class), Some(method)) = (edge.attr("caller_class"), edge.attr("caller_method"))
        else {
            continue;
        };
        by_caller
            .entry((normalize_class(class), method.to_string()))
            .or_default()
            .push(edge);
    }
    let mut frontier = BTreeSet::<(String, String)>::new();
    for frame in store.by_kind(kind::STACK_FRAME) {
        if let (Some(class), Some(method)) = (frame.attr("class"), frame.attr("method")) {
            frontier.insert((normalize_class(class), method.to_string()));
        }
    }
    for entrypoint in store.by_kind(kind::ENTRYPOINT) {
        if let Some(class) = entrypoint.attr("class") {
            frontier.insert((normalize_class(class), String::new()));
        }
    }
    for site in store.by_kind(kind::MIXIN_APPLICATION_SITE) {
        if let (Some(class), Some(method)) = (site.attr("mixin"), site.attr("handler_method")) {
            frontier.insert((normalize_class(class), method.to_string()));
        }
    }
    let mut selected = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut hit_budget = false;
    for _ in 0..MAX_CALL_SLICE_DEPTH {
        let mut next = BTreeSet::new();
        for (class, method) in frontier {
            if !visited.insert((class.clone(), method.clone())) {
                continue;
            }
            if visited.len() > MAX_CALL_SLICE_NODES {
                hit_budget = true;
                break;
            }
            let candidates = if method.is_empty() {
                by_caller
                    .iter()
                    .filter(|((candidate, _), _)| candidate == &class)
                    .flat_map(|(_, edges)| edges.iter().copied())
                    .collect::<Vec<_>>()
            } else {
                by_caller
                    .get(&(class, method))
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect()
            };
            for edge in candidates {
                selected.insert(edge.id);
                if selected.len() >= MAX_CALL_SLICE_EDGES {
                    hit_budget = true;
                    break;
                }
                if let (Some(class), Some(method)) =
                    (edge.attr("target_class"), edge.attr("target_method"))
                {
                    next.insert((normalize_class(class), method.to_string()));
                }
            }
            if hit_budget {
                break;
            }
        }
        if hit_budget || next.is_empty() {
            break;
        }
        frontier = next;
    }
    let collector_partial = store
        .by_kind(kind::CALL_SLICE_COVERAGE)
        .any(|coverage| coverage.attr_bool("truncated") == Some(true));
    let coverage = if hit_budget || collector_partial {
        intermed_evidence::CoverageState::Partial {
            gaps: vec![intermed_evidence::CoverageGap::new(
                "call-slice-truncated",
                if hit_budget {
                    "targeted call-slice graph budget exhausted"
                } else {
                    "collector call-edge input was truncated"
                },
            )],
        }
    } else {
        intermed_evidence::CoverageState::Complete
    };
    (selected, coverage)
}

fn normalize_class(class: &str) -> String {
    class.replace('/', ".")
}

fn add_runtime_entities(
    store: &FactStore,
    mods: &BTreeMap<String, Vec<ModInstanceId>>,
    graph: &mut EvidenceGraph,
) {
    for fact in store.by_kind(kind::RUNTIME_EVENT) {
        graph
            .entities
            .push(EntityRef::RuntimeEvent(RuntimeOccurrenceId::new(
                &fact.subject,
            )));
    }
    for fact in store.by_kind(kind::THROWABLE_NODE) {
        let index = fact.attr_int("index").unwrap_or_default().to_string();
        let throwable = EntityRef::Throwable(ThrowableId::new(format!("{}:{index}", fact.subject)));
        let event = EntityRef::RuntimeEvent(RuntimeOccurrenceId::new(&fact.subject));
        graph.entities.push(throwable.clone());
        graph.links.push(link(
            throwable,
            EvidenceRelation::ObservedIn,
            event,
            EvidenceOrigin::ObservedRuntime,
            EvidenceStrength::Exact,
            fact.id,
        ));
    }
    for fact in store.by_kind(kind::STACK_FRAME) {
        let Some(class_name) = fact.attr("class") else {
            continue;
        };
        let class = match class_entity(class_name, Some("unknown")) {
            EntityRef::Class(class) => class,
            _ => unreachable!(),
        };
        let method = EntityRef::Method(MethodSymbol {
            owner: class,
            name: fact.attr("method").unwrap_or("").to_string(),
            descriptor: MethodDescriptor::unknown(),
        });
        let event = EntityRef::RuntimeEvent(RuntimeOccurrenceId::new(&fact.subject));
        graph.entities.push(method.clone());
        graph.links.push(link(
            method.clone(),
            EvidenceRelation::ObservedIn,
            event,
            EvidenceOrigin::ObservedRuntime,
            EvidenceStrength::Exact,
            fact.id,
        ));
        if let Some(mod_id) = fact.attr("mod_id").filter(|id| !id.is_empty()) {
            for owner in mods.get(mod_id).into_iter().flatten() {
                graph.links.push(link(
                    EntityRef::Mod(owner.clone()),
                    EvidenceRelation::Owns,
                    method.clone(),
                    EvidenceOrigin::ObservedRuntime,
                    EvidenceStrength::Exact,
                    fact.id,
                ));
            }
        }
    }
}

fn add_security_provenance_links(
    store: &FactStore,
    artifacts: &BTreeMap<String, ArtifactId>,
    mods: &BTreeMap<String, Vec<ModInstanceId>>,
    graph: &mut EvidenceGraph,
) {
    for fact in store
        .all()
        .iter()
        .filter(|fact| fact.extractor == "security-scanner")
    {
        let locator = fact.attr("archive").unwrap_or(&fact.subject);
        let Some(artifact) = artifacts.get(locator) else {
            continue;
        };
        for node in mods
            .values()
            .flatten()
            .filter(|node| &node.artifact == artifact)
        {
            graph.links.push(link(
                EntityRef::Artifact(artifact.clone()),
                EvidenceRelation::Corroborates,
                EntityRef::Mod(node.clone()),
                EvidenceOrigin::StaticExact,
                EvidenceStrength::Corroborating,
                fact.id,
            ));
        }
    }
}

fn add_bridges(
    store: &FactStore,
    artifacts: &BTreeMap<String, ArtifactId>,
    mods: &BTreeMap<String, Vec<ModInstanceId>>,
    graph: &mut EvidenceGraph,
) {
    for fact in store.by_kind(kind::COMPATIBILITY_BRIDGE) {
        let artifact = mods
            .get(&fact.subject)
            .and_then(|instances| instances.first())
            .map(|instance| instance.artifact.clone())
            .or_else(|| artifacts.get(&fact.source.locator).cloned())
            .unwrap_or_else(|| ArtifactId::unresolved(&fact.source.locator));
        let capabilities = fact
            .attr("capabilities")
            .map(parse_bridge_capabilities)
            .unwrap_or_else(|| legacy_bridge_capabilities(fact.attr("scope")));
        let complete = fact.attr("coverage") == Some("complete");
        graph.bridges.push(CompatibilityBridge {
            artifact,
            source_family: fact.attr("from_loader").unwrap_or("unknown").to_string(),
            target_family: fact.attr("to_loader").unwrap_or("unknown").to_string(),
            capabilities,
            evidence: vec![fact.id],
            coverage: if complete {
                intermed_evidence::CoverageState::Complete
            } else {
                intermed_evidence::CoverageState::Partial {
                    gaps: vec![intermed_evidence::CoverageGap {
                        code: "bridge-runtime-unverified".to_string(),
                        scope: Some("compatibility-bridge".to_string()),
                        detail: "bridge capabilities do not prove runtime compatibility"
                            .to_string(),
                    }],
                }
            },
        });
    }
}

fn parse_bridge_capabilities(value: &str) -> BTreeSet<BridgeCapability> {
    value
        .split(',')
        .filter_map(|token| match token.trim() {
            "api-surface" => Some(BridgeCapability::ApiSurface),
            "metadata" => Some(BridgeCapability::MetadataCompatibility),
            "classloading" => Some(BridgeCapability::ClassloadingCompatibility),
            "runtime" => Some(BridgeCapability::RuntimeCompatibility),
            "resources" => Some(BridgeCapability::ResourceCompatibility),
            _ => None,
        })
        .collect()
}

fn legacy_bridge_capabilities(scope: Option<&str>) -> BTreeSet<BridgeCapability> {
    match scope {
        Some("api-surface") => [BridgeCapability::ApiSurface].into_iter().collect(),
        Some("mod-runtime") => [
            BridgeCapability::MetadataCompatibility,
            BridgeCapability::ClassloadingCompatibility,
        ]
        .into_iter()
        .collect(),
        _ => BTreeSet::new(),
    }
}

/// Reconcile conclusions against exact evidence from other layers. Decisions
/// use typed semantics; finding ids remain presentation identifiers only.
pub fn reconcile_findings(store: &FactStore, graph: &mut EvidenceGraph, findings: &mut [Finding]) {
    complete_evidence_graph(store, graph, findings);
    let runtime_classes: BTreeMap<String, Vec<FactId>> = store
        .by_kind(kind::STACK_FRAME)
        .filter_map(|fact| {
            Some((
                intermed_evidence::identity::normalize_class_name(fact.attr("class")?),
                fact.id,
            ))
        })
        .fold(BTreeMap::new(), |mut out, (class, id)| {
            out.entry(class).or_default().push(id);
            out
        });
    let runtime_event_mods = runtime_mods(store);
    let known_mods = graph
        .mods
        .iter()
        .filter(|node| node.active)
        .map(|node| (node.id.declared_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let package_owners = store
        .by_kind(kind::PACKAGE_OWNER)
        .filter_map(|fact| Some((fact.attr("package")?.to_string(), fact.subject.clone())))
        .collect::<Vec<_>>();
    let authoritative_environment = strongest_environment_fact(store);

    for finding in findings {
        let contradiction = match finding.conclusion_kind {
            ConclusionKind::ClassAbsent | ConclusionKind::MethodAbsent => finding
                .evidence
                .iter()
                .filter_map(|edge| store.get(edge.fact))
                .filter_map(|fact| fact.attr("target").or_else(|| fact.attr("target_class")))
                .find_map(|target| {
                    runtime_classes
                        .get(&intermed_evidence::identity::normalize_class_name(target))
                        .cloned()
                }),
            ConclusionKind::DependencyUnused => {
                let [from, to, ..] = finding.affected_components.as_slice() else {
                    continue;
                };
                runtime_event_mods
                    .values()
                    .find(|mods| mods.contains(from) && mods.contains(to))
                    .map(|mods| {
                        store
                            .by_kind(kind::STACK_FRAME)
                            .filter(|frame| {
                                frame.attr("mod_id").is_some_and(|id| mods.contains(id))
                            })
                            .map(|frame| frame.id)
                            .collect()
                    })
                    .or_else(|| {
                        let ids = store
                            .by_kind(kind::BYTECODE_CALL_EDGE)
                            .filter(|edge| edge.subject == *from)
                            .filter(|edge| {
                                edge.attr("target_class").is_some_and(|class| {
                                    package_owners.iter().any(|(package, owner)| {
                                        owner == to && class_under_package(class, package)
                                    })
                                })
                            })
                            .map(|edge| edge.id)
                            .collect::<Vec<_>>();
                        (!ids.is_empty()).then_some(ids)
                    })
            }
            ConclusionKind::MissingDependency => {
                let provider = finding.affected_components.get(1).map(String::as_str);
                provider
                    .and_then(|provider| known_mods.get(provider))
                    .map(|node| {
                        graph
                            .links
                            .iter()
                            .filter(|link| link.to == EntityRef::Mod(node.id.clone()))
                            .map(|link| link.source_fact)
                            .collect()
                    })
            }
            ConclusionKind::LoaderMismatch => authoritative_environment.and_then(|authoritative| {
                let cited_environment = finding
                    .evidence
                    .iter()
                    .filter_map(|edge| store.get(edge.fact))
                    .find(|fact| fact.kind == kind::ENVIRONMENT);
                cited_environment
                    .filter(|cited| cited.id != authoritative.id)
                    .map(|_| vec![authoritative.id])
            }),
            _ => None,
        };
        if let Some(mut evidence) = contradiction {
            evidence.sort_unstable();
            evidence.dedup();
            invalidate(finding, evidence);
            if finding.conclusion_kind == ConclusionKind::LoaderMismatch {
                let authoritative = authoritative_environment.expect("loader contradiction source");
                finding.id.push_str(":superseded:");
                finding
                    .id
                    .push_str(authoritative.attr("loader").unwrap_or("unknown"));
                finding.id.push(':');
                finding.id.push_str(
                    authoritative
                        .attr("loader_source")
                        .unwrap_or("environment-evidence"),
                );
            }
        }
        let mut evidence_path = graph
            .links
            .iter()
            .filter(|link| {
                finding
                    .evidence
                    .iter()
                    .any(|edge| edge.fact == link.source_fact)
            })
            .cloned()
            .collect::<Vec<_>>();
        // `EvidenceGraph::normalize` already provides a deterministic,
        // duplicate-free order; filtering preserves that order.
        if evidence_path.len() > MAX_FINDING_EVIDENCE_PATH {
            let total = evidence_path.len();
            evidence_path.truncate(MAX_FINDING_EVIDENCE_PATH);
            finding.assessment.adjustments.push(ConclusionAdjustment {
                code: "evidence-path-truncated".to_string(),
                detail: format!(
                    "the report retains {MAX_FINDING_EVIDENCE_PATH} of {total} matching graph links; the canonical evidence graph retains the complete normalized link set"
                ),
                original_disposition: None,
                final_disposition: None,
                from_severity: None,
                to_severity: None,
                contradicting_evidence: Vec::new(),
            });
        }
        finding.evidence_path = evidence_path;
    }
    graph.normalize();
}

fn strongest_environment_fact(store: &FactStore) -> Option<&Fact> {
    fn priority(source: Option<&str>) -> u8 {
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
    let facts = store
        .by_kind(kind::ENVIRONMENT)
        .filter(|fact| fact.attr("loader").is_some())
        .collect::<Vec<_>>();
    let best = facts
        .iter()
        .map(|fact| priority(fact.attr("loader_source")))
        .max()?;
    let mut candidates = facts
        .into_iter()
        .filter(|fact| priority(fact.attr("loader_source")) == best)
        .collect::<Vec<_>>();
    let loaders = candidates
        .iter()
        .filter_map(|fact| fact.attr("loader"))
        .collect::<BTreeSet<_>>();
    if loaders.len() != 1 {
        return None;
    }
    candidates.sort_by_key(|fact| fact.id);
    candidates.into_iter().next()
}

pub fn complete_evidence_graph(store: &FactStore, graph: &mut EvidenceGraph, findings: &[Finding]) {
    let linked = graph
        .links
        .iter()
        .map(|link| link.source_fact)
        .collect::<BTreeSet<_>>();
    for fact_id in findings
        .iter()
        .flat_map(|finding| finding.evidence.iter().map(|edge| edge.fact))
    {
        if linked.contains(&fact_id) {
            continue;
        }
        let Some(fact) = store.get(fact_id) else {
            continue;
        };
        let entity = if matches!(
            fact.kind.as_str(),
            kind::RUNTIME_EVENT | kind::CRASH_ANCHOR | kind::STACK_FRAME | kind::THROWABLE_NODE
        ) {
            EntityRef::RuntimeEvent(RuntimeOccurrenceId::new(&fact.subject))
        } else if let Some(path) = fact.attr("path").or_else(|| {
            fact.kind
                .contains("resource")
                .then_some(fact.subject.as_str())
        }) {
            EntityRef::Resource(ResourceKey::new(path))
        } else {
            unresolved_mod_entity(&fact.subject)
        };
        graph.entities.push(entity.clone());
        graph.links.push(link(
            entity.clone(),
            EvidenceRelation::Corroborates,
            entity,
            if fact.extractor == "log-analyzer" {
                EvidenceOrigin::ObservedRuntime
            } else {
                EvidenceOrigin::StaticExact
            },
            EvidenceStrength::Exact,
            fact.id,
        ));
    }
}

/// Assign stable semantic and physical occurrence identities from canonical
/// entities and input provenance. Presentation `id` remains backward compatible.
pub fn stabilize_finding_identities(
    store: &FactStore,
    graph: &EvidenceGraph,
    findings: &mut [Finding],
) {
    let mut input_identity = Sha256::new();
    input_identity.update(b"intermed-input-manifest-v1\0");
    let mut checksums = store
        .by_kind(kind::CHECKSUM)
        .filter_map(|fact| Some((fact.subject.as_str(), fact.attr("hex")?)))
        .collect::<Vec<_>>();
    checksums.sort_unstable();
    for (locator, hash) in checksums {
        hash_tagged(&mut input_identity, "locator", locator);
        hash_tagged(&mut input_identity, "sha256", hash);
    }
    let input_identity = format!("{:x}", input_identity.finalize());
    for finding in findings {
        let mut semantic = Sha256::new();
        semantic.update(b"intermed-semantic-finding-v1\0");
        hash_tagged(
            &mut semantic,
            "kind",
            &format!("{:?}", finding.conclusion_kind),
        );
        // Typed conditions are identified by `ConclusionKind`, canonical
        // entities and semantic evidence below. Their presentation ID is not
        // part of identity. Generic findings have no typed condition, so retain
        // their stable rule family to avoid merging unrelated generic rules.
        if finding.conclusion_kind == ConclusionKind::Generic {
            hash_tagged(&mut semantic, "condition-family", &finding.rule_id);
        }
        let mut semantic_entities = BTreeSet::new();
        for component in &finding.affected_components {
            let mut instances = graph
                .mods
                .iter()
                .filter(|node| node.id.declared_id == *component)
                .map(|node| node.id.to_string())
                .collect::<Vec<_>>();
            instances.sort_unstable();
            instances.dedup();
            if instances.is_empty() {
                semantic_entities.insert(("component", component.clone()));
            } else {
                for instance in instances {
                    semantic_entities.insert(("entity", instance));
                }
            }
        }
        for (tag, value) in semantic_entities {
            hash_tagged(&mut semantic, tag, &value);
        }
        if finding.conclusion_kind != ConclusionKind::Generic
            || finding.affected_components.is_empty()
        {
            let mut semantic_evidence = BTreeSet::new();
            for edge in &finding.evidence {
                if let Some(fact) = store.get(edge.fact) {
                    semantic_evidence.insert((
                        fact.kind.clone(),
                        fact.subject.clone(),
                        String::new(),
                        String::new(),
                    ));
                    for key in [
                        "target",
                        "target_class",
                        "member",
                        "descriptor",
                        "path",
                        "dep",
                    ] {
                        if let Some(value) = fact.attr(key) {
                            semantic_evidence.insert((
                                fact.kind.clone(),
                                fact.subject.clone(),
                                key.to_string(),
                                value.to_string(),
                            ));
                        }
                    }
                }
            }
            for (kind, subject, key, value) in semantic_evidence {
                hash_tagged(&mut semantic, "fact-kind", &kind);
                hash_tagged(&mut semantic, "fact-subject", &subject);
                if !key.is_empty() {
                    hash_tagged(&mut semantic, &key, &value);
                }
            }
        }
        let digest = format!("{:x}", semantic.finalize());
        finding.semantic_id = format!(
            "finding:{}:{}",
            format!("{:?}", finding.conclusion_kind).to_ascii_lowercase(),
            &digest[..24],
        );
        let mut occurrence = Sha256::new();
        occurrence.update(b"intermed-finding-occurrence-v1\0");
        hash_tagged(&mut occurrence, "semantic", &finding.semantic_id);
        hash_tagged(&mut occurrence, "input", &input_identity);
        let mut sources = finding
            .evidence
            .iter()
            .filter_map(|edge| store.get(edge.fact))
            .map(|fact| {
                (
                    fact.source.locator.as_str(),
                    fact.source.line.unwrap_or_default(),
                    fact.source.inner.as_deref().unwrap_or(""),
                )
            })
            .collect::<Vec<_>>();
        sources.sort_unstable();
        sources.dedup();
        for (locator, line, inner) in sources {
            hash_tagged(&mut occurrence, "source", locator);
            hash_tagged(&mut occurrence, "line", &line.to_string());
            hash_tagged(&mut occurrence, "inner", inner);
        }
        finding.occurrence_id = Some(format!("finding-occurrence:{:x}", occurrence.finalize()));
    }
}

fn hash_tagged(digest: &mut Sha256, tag: &str, value: &str) {
    digest.update((tag.len() as u32).to_be_bytes());
    digest.update(tag.as_bytes());
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

/// Synthesize terminal runtime occurrences into causal incidents. Strict
/// fingerprints preserve exact identity while fuzzy fingerprints group rebuilds
/// without merging their physical evidence.
#[must_use]
pub fn synthesize_incidents(store: &FactStore, graph: &EvidenceGraph) -> Vec<Incident> {
    let mut groups = BTreeMap::<String, Vec<&Fact>>::new();
    for anchor in store.by_kind(kind::CRASH_ANCHOR) {
        let key = anchor
            .attr("fuzzy_fingerprint")
            .or_else(|| anchor.attr("semantic_fingerprint"))
            .unwrap_or(&anchor.subject)
            .to_string();
        groups.entry(key).or_default().push(anchor);
    }
    let background_events = store
        .by_kind(kind::RUNTIME_EVENT)
        .filter(|event| {
            !matches!(
                event.attr("terminality"),
                Some(
                    "process-fatal"
                        | "loader-abort"
                        | "crash-report-root"
                        | "watchdog-termination"
                        | "server-stopped"
                )
            )
        })
        .map(|event| RuntimeOccurrenceId::new(&event.subject))
        .collect::<Vec<_>>();
    let mut incidents = Vec::new();
    for (fuzzy, anchors) in groups {
        let first = anchors[0];
        let strict = first.attr("semantic_fingerprint").unwrap_or("").to_string();
        let occurrences = anchors
            .iter()
            .map(|anchor| RuntimeOccurrenceId::new(&anchor.subject))
            .collect::<Vec<_>>();
        let primary_fact = store
            .by_kind(kind::THROWABLE_NODE)
            .filter(|node| anchors.iter().any(|anchor| anchor.subject == node.subject))
            .filter(|node| node.attr_bool("deepest") == Some(true))
            .min_by_key(|node| node.id);
        let primary_cause = primary_fact.map(|node| CausalNode {
            throwable_type: node.attr("type").unwrap_or("unknown").to_string(),
            message: node
                .attr("message")
                .filter(|message| !message.is_empty())
                .map(str::to_string),
            entity: EntityRef::Throwable(ThrowableId::new(format!(
                "{}:{}",
                node.subject,
                node.attr_int("index").unwrap_or_default()
            ))),
        });
        let frames = store
            .by_kind(kind::STACK_FRAME)
            .filter(|frame| frame.subject == first.subject)
            .collect::<Vec<_>>();
        let owned = frames
            .iter()
            .filter(|frame| frame.attr("mod_id").is_some_and(|id| !id.is_empty()))
            .collect::<Vec<_>>();
        // Java stack traces list the currently executing callee before its
        // callers. Therefore the deepest listed owned frame is the caller and
        // the first owned frame is the callee it reached.
        let caller_transition = owned
            .last()
            .and_then(|caller| {
                let callee = owned.first()?;
                let caller_entity = method_entity_from_frame(caller);
                let callee_entity = method_entity_from_frame(callee);
                Some(CausalTransition {
                    caller: (caller.id != callee.id).then_some(caller_entity),
                    callee: callee_entity,
                    rationale: "ordered runtime stack ownership transition".to_string(),
                    ambiguous: false,
                })
            })
            .or_else(|| {
                frames
                    .iter()
                    .find(|frame| frame.attr("ownership") == Some("ambiguous"))
                    .map(|frame| CausalTransition {
                        caller: None,
                        callee: method_entity_from_frame(frame),
                        rationale: format!(
                            "runtime frame ownership is shared by {}",
                            frame
                                .attr("owner_candidates")
                                .unwrap_or("multiple artifacts")
                        ),
                        ambiguous: true,
                    })
            });
        let mut contributor_facts = BTreeMap::<String, Vec<FactId>>::new();
        for frame in &owned {
            if let Some(mod_id) = frame.attr("mod_id") {
                contributor_facts
                    .entry(mod_id.to_string())
                    .or_default()
                    .push(frame.id);
            }
        }
        let contributors = contributor_facts
            .into_iter()
            .map(|(mod_id, evidence)| Contributor {
                entity: unresolved_mod_entity(&mod_id),
                role: "runtime-stack-owner".to_string(),
                evidence,
            })
            .collect::<Vec<_>>();
        let mut affected_entities = contributors
            .iter()
            .map(|c| c.entity.clone())
            .collect::<Vec<_>>();
        if let Some(cause) = &primary_cause {
            affected_entities.push(cause.entity.clone());
        }
        affected_entities.sort();
        affected_entities.dedup();
        let evidence_ids = anchors
            .iter()
            .map(|anchor| anchor.id)
            .chain(primary_fact.into_iter().map(|fact| fact.id))
            .chain(frames.iter().map(|frame| frame.id))
            .collect::<BTreeSet<_>>();
        let evidence_path = graph
            .links
            .iter()
            .filter(|link| evidence_ids.contains(&link.source_fact))
            .cloned()
            .collect();
        let mut assessment = FindingAssessment {
            disposition: AssessmentDisposition::Asserted,
            impact: Impact::RuntimeFailure,
            certainty: CertaintyTier::Confirmed,
            proof_kind: ProofKind::Observation,
            ..FindingAssessment::default()
        };
        assessment
            .provenance
            .insert(EvidenceOrigin::ObservedRuntime);
        incidents.push(Incident {
            semantic_id: format!("incident:fuzzy:{fuzzy}"),
            strict_fingerprint: strict,
            fuzzy_fingerprint: fuzzy,
            occurrences,
            primary_cause,
            caller_transition,
            contributors,
            background_events: background_events.clone(),
            affected_entities,
            evidence_path,
            recommendations: Vec::new(),
            assessment,
        });
    }
    incidents.sort_by(|a, b| a.semantic_id.cmp(&b.semantic_id));
    incidents
}

fn method_entity_from_frame(frame: &Fact) -> EntityRef {
    EntityRef::Method(MethodSymbol {
        owner: ClassSymbol::new(
            frame.attr("class").unwrap_or("unknown"),
            MappingNamespace::Unknown,
            MappingGraphId::new(UNMAPPED_GRAPH),
        ),
        name: frame.attr("method").unwrap_or("unknown").to_string(),
        descriptor: MethodDescriptor::unknown(),
    })
}

fn unresolved_mod_entity(mod_id: &str) -> EntityRef {
    EntityRef::Mod(ModInstanceId {
        artifact: ArtifactId::unresolved(&format!("runtime-owner:{mod_id}")),
        declared_id: mod_id.to_string(),
        descriptor_kind: DescriptorKind::Unknown,
        ordinal: 0,
    })
}

fn invalidate(finding: &mut Finding, evidence: Vec<FactId>) {
    let prior_disposition = finding.assessment.disposition;
    let prior_severity = finding.severity;
    finding.severity = if finding.conclusion_kind == ConclusionKind::DependencyUnused {
        Severity::Info
    } else {
        Severity::Note
    };
    finding.visibility = FindingVisibility::ExplainOnly;
    finding.confidence = finding.confidence.min(0.2);
    finding.assessment.disposition = AssessmentDisposition::Abstained;
    finding.assessment.certainty = CertaintyTier::Undecidable;
    if !finding
        .machine_tags
        .iter()
        .any(|tag| tag == "runtime-contradicted")
    {
        finding
            .machine_tags
            .push("runtime-contradicted".to_string());
    }
    finding.explanation.push_str(
        " Exact evidence from another analysis layer contradicts this static hypothesis; the conclusion is retained only for explanation.",
    );
    finding.assessment.adjustments.push(ConclusionAdjustment {
        code: "cross-layer-contradiction".to_string(),
        detail: "exact evidence from another layer contradicts the proposed conclusion".to_string(),
        original_disposition: Some(prior_disposition),
        final_disposition: Some(AssessmentDisposition::Abstained),
        from_severity: Some(prior_severity),
        to_severity: Some(finding.severity),
        contradicting_evidence: evidence,
    });
}

fn runtime_mods(store: &FactStore) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for frame in store.by_kind(kind::STACK_FRAME) {
        if let Some(mod_id) = frame.attr("mod_id").filter(|id| !id.is_empty()) {
            out.entry(frame.subject.clone())
                .or_insert_with(BTreeSet::new)
                .insert(mod_id.to_string());
        }
    }
    out
}

fn class_under_package(class: &str, package: &str) -> bool {
    let class = class.replace('/', ".");
    class == package
        || class
            .strip_prefix(package)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn artifact_for(
    locator: &str,
    by_locator: &mut BTreeMap<String, ArtifactId>,
    graph: &mut EvidenceGraph,
) -> ArtifactId {
    if let Some(id) = by_locator.get(locator) {
        return id.clone();
    }
    let id = ArtifactId::unresolved(locator);
    by_locator.insert(locator.to_string(), id.clone());
    graph.artifacts.push(ArtifactNode {
        id: id.clone(),
        locators: vec![locator.to_string()],
        embedded_artifacts: Vec::new(),
    });
    graph.entities.push(EntityRef::Artifact(id.clone()));
    id
}

fn class_entity(name: &str, namespace: Option<&str>) -> EntityRef {
    EntityRef::Class(ClassSymbol::new(
        name,
        namespace
            .map(MappingNamespace::from_token)
            .unwrap_or(MappingNamespace::Unknown),
        MappingGraphId::new(UNMAPPED_GRAPH),
    ))
}

fn link(
    from: EntityRef,
    relation: EvidenceRelation,
    to: EntityRef,
    origin: EvidenceOrigin,
    strength: EvidenceStrength,
    source_fact: FactId,
) -> EvidenceLink {
    EvidenceLink {
        from,
        relation,
        to,
        origin,
        strength,
        source_fact,
    }
}

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
}
