use super::*;

pub(super) fn hash_tagged(digest: &mut Sha256, tag: &str, value: &str) {
    digest.update((tag.len() as u32).to_be_bytes());
    digest.update(tag.as_bytes());
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

pub(super) fn class_under_package(class: &str, package: &str) -> bool {
    let class = class.replace('/', ".");
    class == package
        || class
            .strip_prefix(package)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

pub(super) fn unresolved_mod_entity(mod_id: &str) -> EntityRef {
    EntityRef::Mod(ModInstanceId {
        artifact: ArtifactId::unresolved(&format!("runtime-owner:{mod_id}")),
        declared_id: mod_id.to_string(),
        descriptor_kind: DescriptorKind::Unknown,
        ordinal: 0,
    })
}

pub(super) fn fact_subject_entity(
    fact: &Fact,
    schema: &intermed_facts::schema_contract::FactSchema,
) -> Option<EntityRef> {
    use intermed_facts::schema_contract::SubjectEntity;

    let subject_entity = schema.kind(&fact.kind)?.subject_entity;
    Some(match subject_entity {
        SubjectEntity::Artifact => EntityRef::Artifact(
            fact.attr("artifact_id")
                .or_else(|| {
                    fact.subject
                        .starts_with("sha256:")
                        .then_some(fact.subject.as_str())
                })
                .and_then(parse_artifact_id)
                .or_else(|| fact.attr("sha256").and_then(ArtifactId::from_sha256))
                .or_else(|| {
                    (fact.attr("algorithm") == Some("sha256"))
                        .then(|| fact.attr("hex"))
                        .flatten()
                        .and_then(ArtifactId::from_sha256)
                })
                .unwrap_or_else(|| ArtifactId::unresolved(&fact.subject)),
        ),
        SubjectEntity::ModInstance => unresolved_mod_entity(&fact.subject),
        SubjectEntity::Dependency => EntityRef::Dependency(DependencyEdgeId::new(format!(
            "fact:{}:{}",
            fact.id.0, fact.subject
        ))),
        SubjectEntity::Resource => {
            EntityRef::Resource(ResourceKey::new(fact.attr("path").unwrap_or(&fact.subject)))
        }
        SubjectEntity::RuntimeEvent => {
            EntityRef::RuntimeEvent(RuntimeOccurrenceId::new(&fact.subject))
        }
        SubjectEntity::Throwable => EntityRef::Throwable(ThrowableId::new(
            fact.attr("throwable_id").unwrap_or(&fact.subject),
        )),
        SubjectEntity::Environment => EntityRef::Environment(EnvironmentId::new(
            if fact.kind == kind::ANALYSIS_ENVIRONMENT {
                "analysis-environment"
            } else {
                "target-environment"
            },
        )),
        SubjectEntity::JavaRuntime => EntityRef::JavaRuntime(JavaRuntimeId::new(
            fact.attr("version").unwrap_or("target-java-runtime"),
        )),
        SubjectEntity::Unknown => return None,
    })
}

pub(super) fn parse_artifact_id(value: &str) -> Option<ArtifactId> {
    value
        .strip_prefix("sha256:")
        .and_then(ArtifactId::from_sha256)
        .or_else(|| ArtifactId::from_sha256(value))
}
pub(super) fn artifact_for(
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

pub(super) fn class_entity(name: &str, namespace: Option<&str>) -> EntityRef {
    EntityRef::Class(ClassSymbol::new(
        name,
        namespace
            .map(MappingNamespace::from_token)
            .unwrap_or(MappingNamespace::Unknown),
        MappingGraphId::new(UNMAPPED_GRAPH),
    ))
}

pub(super) fn link(
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
