//! The resource reference graph: definitions, references, and namespace owners
//! aggregated across every writer in the pack.
//!
//! The graph is pure data derived from the per-resource [`CachedResourceAst`]s. It
//! holds no opinions — rules (Layer M / Layer C) read it to decide implicit
//! dependencies, and `explain` reads it for unresolved references. This keeps to
//! the layer's contract: **the AST never emits findings**.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{CachedResourceAst, ParseStatus, RefRelation};
use crate::semantic::namespace::{is_platform_namespace, path_namespace};

/// One parsed resource attributed to the jar that shipped it.
#[derive(Debug, Clone)]
pub struct ResourceAstRecord {
    /// Jar file name (e.g. `create-1.20.1.jar`).
    pub archive: String,
    /// Resolved writer/mod id (e.g. `create`).
    pub writer: String,
    pub ast: CachedResourceAst,
}

impl ResourceAstRecord {
    /// The namespace this resource is *defined* in, from its path.
    #[must_use]
    pub fn definition_namespace(&self) -> String {
        path_namespace(&self.ast.resource_path).unwrap_or_else(|| "minecraft".to_string())
    }
}

/// An outgoing reference edge in the graph (source resource → referenced id).
#[derive(Debug, Clone)]
pub struct RefEdge {
    pub from_path: String,
    pub relation: RefRelation,
    pub target: String,
    pub namespace: String,
    pub required: bool,
    pub conditioned: bool,
    pub is_tag: bool,
}

/// The aggregated reference graph for a whole pack.
#[derive(Debug, Default)]
pub struct ResourceGraph {
    /// `resource_path → set of writers that define it`.
    pub definitions: BTreeMap<String, BTreeSet<String>>,
    /// All outgoing reference edges.
    pub references: Vec<RefEdge>,
    /// `namespace → set of writers that ship resources under it`.
    pub namespace_owners: BTreeMap<String, BTreeSet<String>>,
}

impl ResourceGraph {
    /// Build the graph from every parsed record. Only successfully-parsed records
    /// contribute references (an `Invalid` parse has none to trust).
    #[must_use]
    pub fn build(records: &[ResourceAstRecord]) -> Self {
        let mut graph = ResourceGraph::default();
        for rec in records {
            let path = rec.ast.resource_path.clone();
            graph
                .definitions
                .entry(path.clone())
                .or_default()
                .insert(rec.writer.clone());
            graph
                .namespace_owners
                .entry(rec.definition_namespace())
                .or_default()
                .insert(rec.writer.clone());

            if matches!(rec.ast.parse_status, ParseStatus::Invalid) {
                continue;
            }
            for r in &rec.ast.references {
                graph.references.push(RefEdge {
                    from_path: path.clone(),
                    relation: r.relation,
                    target: r.target.clone(),
                    namespace: r.namespace.clone(),
                    required: r.required,
                    conditioned: r.conditioned,
                    is_tag: r.is_tag,
                });
            }
        }
        graph
    }

    /// Record that `writer` ships resources under `namespace` (used to seed
    /// ownership from binary-only namespaces a jar provides no parsed AST for).
    pub fn add_owner(&mut self, namespace: String, writer: String) {
        self.namespace_owners.entry(namespace).or_default().insert(writer);
    }

    /// Whether any writer owns (ships resources under) `namespace`.
    #[must_use]
    pub fn namespace_is_owned(&self, namespace: &str) -> bool {
        self.namespace_owners.contains_key(namespace)
    }

    /// References to a namespace that no installed jar owns and that is not a
    /// platform namespace — the candidates for an implicit dependency. Conditioned
    /// references are included (flagged) so Layer C can treat them as gated.
    #[must_use]
    pub fn implicit_dependency_candidates(&self) -> Vec<&RefEdge> {
        self.references
            .iter()
            .filter(|e| {
                !is_platform_namespace(&e.namespace) && !self.namespace_is_owned(&e.namespace)
            })
            .collect()
    }

    /// Model/blockstate references whose target model *file* is not shipped by any
    /// jar, restricted to installed (owned), non-platform namespaces.
    ///
    /// This is **informational only** — it is NOT a list of bugs. Mods frequently
    /// reference models that have no JSON file: runtime-generated/baked models
    /// (AE2 formed multiblocks), custom model loaders, or models supplied by a
    /// resource pack. The `vfs explain --ast` view surfaces these as "unresolved
    /// within the pack (may be runtime-generated)". We never raise a finding from
    /// it, because absence of a file is not proof of a broken reference — flagging
    /// it caused confirmed false positives on real packs.
    ///
    /// Vanilla/platform parents and uninstalled namespaces are excluded (the
    /// former live in the MC jar; the latter are a missing-dependency concern).
    #[must_use]
    pub fn unresolved_model_references(&self) -> Vec<UnresolvedRef<'_>> {
        let mut out = Vec::new();
        for e in &self.references {
            if !matches!(e.relation, RefRelation::ParentModel | RefRelation::UsesModel) {
                continue;
            }
            if is_platform_namespace(&e.namespace) || !self.namespace_is_owned(&e.namespace) {
                continue;
            }
            let expected = model_resource_path(&e.target);
            if !self.definitions.contains_key(&expected) {
                out.push(UnresolvedRef {
                    from_path: &e.from_path,
                    relation: e.relation,
                    target: &e.target,
                    expected_path: expected,
                });
            }
        }
        out
    }
}

/// A reference whose resolved target file is absent from the pack. Informational:
/// the target may legitimately be generated at runtime or shipped by a resource
/// pack — see [`ResourceGraph::unresolved_model_references`].
#[derive(Debug, Clone)]
pub struct UnresolvedRef<'a> {
    pub from_path: &'a str,
    pub relation: RefRelation,
    pub target: &'a str,
    /// The resource path the target id resolves to (`assets/<ns>/models/<p>.json`).
    pub expected_path: String,
}

/// Resolve a model id (`ns:path`, default `minecraft`) to its resource path.
fn model_resource_path(id: &str) -> String {
    let id = id.trim_start_matches('#');
    let (ns, path) = match id.split_once(':') {
        Some((ns, p)) if !ns.is_empty() => (ns, p),
        _ => ("minecraft", id),
    };
    format!("assets/{ns}/models/{path}.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ResourceDomain, ResourceReference, ResourceSummary};

    fn record(archive: &str, writer: &str, path: &str, refs: Vec<ResourceReference>) -> ResourceAstRecord {
        ResourceAstRecord {
            archive: archive.into(),
            writer: writer.into(),
            ast: CachedResourceAst {
                schema: "s".into(),
                parser_version: "v".into(),
                resource_path: path.into(),
                domain: ResourceDomain::Recipe,
                parse_status: ParseStatus::Parsed,
                semantic_hash: "h".into(),
                summary: ResourceSummary::Generic,
                references: refs,
                diagnostics: vec![],
            },
        }
    }

    fn rref(ns: &str, target: &str) -> ResourceReference {
        ResourceReference {
            relation: RefRelation::UsesRecipeType,
            target: target.into(),
            namespace: ns.into(),
            required: true,
            conditioned: false,
            is_tag: false,
        }
    }

    #[test]
    fn owners_and_implicit_candidates() {
        let records = vec![
            record(
                "create.jar",
                "create",
                "data/create/recipe/x.json",
                vec![rref("thermal", "thermal:smelting")],
            ),
            record("create.jar", "create", "data/create/recipe/y.json", vec![]),
        ];
        let graph = ResourceGraph::build(&records);
        assert!(graph.namespace_is_owned("create"));
        assert!(!graph.namespace_is_owned("thermal"));
        let candidates = graph.implicit_dependency_candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].namespace, "thermal");
    }

    fn model_record(writer: &str, path: &str, parent: &str) -> ResourceAstRecord {
        ResourceAstRecord {
            archive: format!("{writer}.jar"),
            writer: writer.into(),
            ast: CachedResourceAst {
                schema: "s".into(),
                parser_version: "v".into(),
                resource_path: path.into(),
                domain: ResourceDomain::Model,
                parse_status: ParseStatus::Parsed,
                semantic_hash: "h".into(),
                summary: ResourceSummary::Generic,
                references: vec![ResourceReference {
                    relation: RefRelation::ParentModel,
                    target: parent.into(),
                    namespace: crate::semantic::namespace::namespace_of(parent),
                    required: true,
                    conditioned: false,
                    is_tag: false,
                }],
                diagnostics: vec![],
            },
        }
    }

    #[test]
    fn unresolved_excludes_vanilla_and_uninstalled_but_finds_real_gap() {
        let records = vec![
            // installed mod whose model extends a missing model in its own namespace
            model_record("modb", "assets/modb/models/item/a.json", "modb:item/missing"),
            // a real model that DOES exist in modb
            ResourceAstRecord {
                archive: "modb.jar".into(),
                writer: "modb".into(),
                ast: CachedResourceAst {
                    schema: "s".into(),
                    parser_version: "v".into(),
                    resource_path: "assets/modb/models/item/present.json".into(),
                    domain: ResourceDomain::Model,
                    parse_status: ParseStatus::Parsed,
                    semantic_hash: "h".into(),
                    summary: ResourceSummary::Generic,
                    references: vec![],
                    diagnostics: vec![],
                },
            },
            // vanilla parent — must NOT be flagged (lives in the MC jar)
            model_record("modb", "assets/modb/models/item/b.json", "minecraft:item/generated"),
            // parent in an uninstalled namespace — implicit dep, not dangling
            model_record("modb", "assets/modb/models/item/c.json", "ghostmod:item/x"),
        ];
        let graph = ResourceGraph::build(&records);
        let unresolved = graph.unresolved_model_references();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].target, "modb:item/missing");
        assert_eq!(unresolved[0].expected_path, "assets/modb/models/item/missing.json");
    }

    #[test]
    fn present_parent_is_not_dangling() {
        let records = vec![
            model_record("modb", "assets/modb/models/item/a.json", "modb:item/present"),
            ResourceAstRecord {
                archive: "modb.jar".into(),
                writer: "modb".into(),
                ast: CachedResourceAst {
                    schema: "s".into(),
                    parser_version: "v".into(),
                    resource_path: "assets/modb/models/item/present.json".into(),
                    domain: ResourceDomain::Model,
                    parse_status: ParseStatus::Parsed,
                    semantic_hash: "h".into(),
                    summary: ResourceSummary::Generic,
                    references: vec![],
                    diagnostics: vec![],
                },
            },
        ];
        let graph = ResourceGraph::build(&records);
        assert!(graph.unresolved_model_references().is_empty());
    }

    #[test]
    fn platform_namespace_is_not_a_candidate() {
        let records = vec![record(
            "x.jar",
            "x",
            "data/x/recipe/a.json",
            vec![rref("minecraft", "minecraft:stick"), rref("forge", "forge:conditional")],
        )];
        let graph = ResourceGraph::build(&records);
        assert!(graph.implicit_dependency_candidates().is_empty());
    }
}
