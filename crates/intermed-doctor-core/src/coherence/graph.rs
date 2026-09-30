use super::*;

/// Build one canonical graph from facts emitted by every collector. Physical
/// paths are locators; content hashes, when present, are artifact identities.
#[must_use]
pub fn build_evidence_graph(store: &FactStore) -> EvidenceGraph {
    let mut graph = EvidenceGraph::default();
    let mut artifact_by_locator = BTreeMap::<String, ArtifactId>::new();
    let schema = intermed_facts::schema_contract::contract();

    for fact in store
        .by_kind(kind::ENVIRONMENT)
        .chain(store.by_kind(kind::ANALYSIS_ENVIRONMENT))
        .chain(store.by_kind(kind::JAVA_RUNTIME))
    {
        let Some(entity) = fact_subject_entity(fact, schema) else {
            continue;
        };
        graph.entities.push(entity.clone());
        graph.links.push(link(
            entity.clone(),
            EvidenceRelation::Corroborates,
            entity,
            if fact.kind == kind::ANALYSIS_ENVIRONMENT {
                EvidenceOrigin::HostObservation
            } else if fact.extractor == "log-analyzer" {
                EvidenceOrigin::ObservedRuntime
            } else {
                EvidenceOrigin::StaticExact
            },
            EvidenceStrength::Exact,
            fact.id,
        ));
    }

    for fact in store
        .by_kind(kind::CHECKSUM)
        .filter(|f| f.attr("algorithm") == Some("sha256"))
    {
        if let Some(id) = fact.attr("hex").and_then(ArtifactId::from_sha256) {
            let mut locators = BTreeSet::new();
            if let Some(locator) = fact.attr("source_locator") {
                locators.insert(locator.replace('\\', "/"));
            }
            if !fact.subject.starts_with("sha256:") {
                locators.insert(fact.subject.to_string());
            }
            if fact.source.locator != fact.subject {
                locators.insert(fact.source.locator.replace('\\', "/"));
            }
            for locator in &locators {
                artifact_by_locator.insert(locator.clone(), id.clone());
            }
            graph.artifacts.push(ArtifactNode {
                id: id.clone(),
                locators: locators.into_iter().collect(),
                embedded_artifacts: Vec::new(),
            });
            graph.entities.push(EntityRef::Artifact(id));
        }
    }
    for fact in store.by_kind(kind::SBOM) {
        let id = fact
            .attr("artifact_id")
            .or_else(|| Some(fact.subject.as_str()))
            .and_then(parse_artifact_id)
            .or_else(|| fact.attr("sha256").and_then(ArtifactId::from_sha256))
            .unwrap_or_else(|| ArtifactId::unresolved(&fact.subject));
        let mut locators = BTreeSet::new();
        if let Some(locator) = fact.attr("source_locator") {
            locators.insert(locator.replace('\\', "/"));
        }
        if !fact.subject.starts_with("sha256:") {
            locators.insert(fact.subject.to_string());
        }
        for locator in &locators {
            artifact_by_locator
                .entry(locator.clone())
                .or_insert_with(|| id.clone());
        }
        graph.artifacts.push(ArtifactNode {
            id: id.clone(),
            locators: locators.into_iter().collect(),
            embedded_artifacts: Vec::new(),
        });
        graph.entities.push(EntityRef::Artifact(id));
    }

    let mut role_artifacts = BTreeMap::<(String, String), BTreeSet<ArtifactId>>::new();
    for role in store.by_kind(kind::ARTIFACT_ROLE) {
        if role.attr("identity_certainty") != Some("confirmed")
            || !matches!(
                role.attr("activation"),
                Some("active" | "self-loader-bootstrap")
            )
        {
            continue;
        }
        let Some(declared_id) = role.attr("declared_id") else {
            continue;
        };
        let locator = role.subject.replace('\\', "/");
        let Some(artifact) = artifact_by_locator.get(&locator).cloned() else {
            continue;
        };
        let basename = std::path::Path::new(&locator)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&locator)
            .to_string();
        role_artifacts
            .entry((declared_id.to_string(), basename))
            .or_default()
            .insert(artifact);
    }

    let mut mods_by_declared = BTreeMap::<String, Vec<ModInstanceId>>::new();
    let mut ordinal_by_identity = BTreeMap::<(ArtifactId, String, DescriptorKind), u16>::new();
    for fact in store.by_kind(kind::MOD).chain(store.by_kind(kind::PLUGIN)) {
        let locator = fact.attr("file").unwrap_or(&fact.source.locator);
        let normalized_locator = locator.replace('\\', "/");
        let basename = std::path::Path::new(&normalized_locator)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&normalized_locator);
        let role_artifact = role_artifacts
            .get(&(fact.subject.to_string(), basename.to_string()))
            .and_then(|candidates| {
                (candidates.len() == 1)
                    .then(|| candidates.first().cloned())
                    .flatten()
            });
        let artifact = artifact_by_locator
            .get(&normalized_locator)
            .cloned()
            .or(role_artifact)
            .unwrap_or_else(|| artifact_for(locator, &mut artifact_by_locator, &mut graph));
        let descriptor_kind = DescriptorKind::from_token(fact.attr("loader").unwrap_or("unknown"));
        let key = (artifact.clone(), fact.subject.to_string(), descriptor_kind);
        let ordinal = ordinal_by_identity.entry(key).or_default();
        let id = ModInstanceId {
            artifact: artifact.clone(),
            declared_id: fact.subject.to_string(),
            descriptor_kind,
            ordinal: *ordinal,
        };
        *ordinal = ordinal.saturating_add(1);
        let active = fact
            .attr("identity_certainty")
            .is_none_or(|certainty| certainty == "confirmed")
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
            .entry(fact.subject.to_string())
            .or_default()
            .push(id);
    }

    for fact in store.by_kind(kind::DEPENDENCY) {
        let candidates = mods_by_declared
            .get(fact.subject.as_str())
            .cloned()
            .unwrap_or_default();
        let source_artifact = artifact_by_locator.get(fact.source.locator.as_str());
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
            .get(fact.subject.as_str())
            .cloned()
            .unwrap_or_default();
        let mut parent_artifacts = parents
            .iter()
            .map(|parent| parent.artifact.clone())
            .collect::<Vec<_>>();
        if parent_artifacts.is_empty()
            && let Some(container) = fact.attr("container")
        {
            parent_artifacts.push(artifact_for(
                container,
                &mut artifact_by_locator,
                &mut graph,
            ));
        }
        for parent in parent_artifacts {
            let nested_path = fact.attr("nested_path").unwrap_or(nested_name);
            let locator = format!("{parent}!/{nested_path}");
            let nested = ArtifactId::unresolved(&locator);
            graph.artifacts.push(ArtifactNode {
                id: nested.clone(),
                locators: vec![locator.clone()],
                embedded_artifacts: Vec::new(),
            });
            graph.links.push(link(
                EntityRef::Artifact(parent),
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
        .filter_map(|fact| Some((fact.attr("package")?.to_string(), fact.subject.to_string())))
        .collect::<Vec<_>>();
    for fact in store.by_kind(kind::ENTRYPOINT) {
        let Some(class) = fact.attr("class") else {
            continue;
        };
        let class = class_entity(class, fact.attr("namespace"));
        graph.entities.push(class.clone());
        for owner in mods.get(fact.subject.as_str()).into_iter().flatten() {
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
        for owner in mods.get(fact.subject.as_str()).into_iter().flatten() {
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
    // Conflict edges are themselves method/site observations. Model their
    // target class explicitly instead of letting the generic fallback invent a
    // pseudo-mod named after the edge id. Besides producing honest explain
    // paths, this lets Layer K match a runtime MixinApplyError attributed to the
    // target class against the static conflict that named that class.
    for fact in store.by_kind(kind::MIXIN_CONFLICT_EDGE) {
        let Some(target_class) = fact.attr("target_class") else {
            continue;
        };
        let site =
            EntityRef::MixinSite(MixinSiteId::new(format!("mixin-conflict:{}", fact.subject)));
        let target = class_entity(target_class, fact.attr("namespace"));
        graph.entities.extend([site.clone(), target.clone()]);
        graph.links.push(link(
            site,
            EvidenceRelation::ConflictsWith,
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
        for owner in mods.get(fact.subject.as_str()).into_iter().flatten() {
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
            && let Some(owner) = mods
                .get(target_mod.as_str())
                .and_then(|instances| instances.first())
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
        let artifact = fact
            .attr("artifact_id")
            .and_then(parse_artifact_id)
            .or_else(|| {
                fact.attr("source_locator")
                    .and_then(|locator| artifacts.get(&locator.replace('\\', "/")).cloned())
            })
            .or_else(|| {
                let locator = fact.attr("archive").unwrap_or(&fact.subject);
                artifacts.get(locator).cloned()
            });
        let Some(artifact) = artifact else {
            continue;
        };
        for node in mods
            .values()
            .flatten()
            .filter(|node| node.artifact == artifact)
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
            .get(fact.subject.as_str())
            .and_then(|instances| instances.first())
            .map(|instance| instance.artifact.clone())
            .or_else(|| artifacts.get(fact.source.locator.as_str()).cloned())
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
