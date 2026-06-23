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
    /// The mod/jar id that shipped the source resource (the *consumer* of the
    /// referenced namespace). Lets Layer C attribute an implicit dependency to a
    /// concrete mod (`{mod}->{dep}`) rather than only a namespace.
    pub writer: String,
    pub relation: RefRelation,
    pub target: String,
    pub namespace: String,
    pub required: bool,
    pub conditions: Vec<crate::model::ResourceCondition>,
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
    /// Definition paths with registry folders normalized to their singular form
    /// (MC 1.21 renamed `advancements`→`advancement`, `loot_tables`→`loot_table`,
    /// …). Reference resolution checks against this so a 1.21 singular layout is
    /// not falsely reported as dangling against a plural-form expected path.
    canonical_definitions: BTreeSet<String>,
    /// Canonical resource paths supplied by an external **vanilla index** (the
    /// Minecraft jar, `--minecraft-jar`), if loaded. Lets `minecraft:` references
    /// resolve against real vanilla resources instead of being blanket-satisfied.
    external_definitions: BTreeSet<String>,
    /// `tag resource_path → entry ids` for every tag (pack + vanilla), the basis
    /// for effective tag-membership expansion.
    tag_entries: BTreeMap<String, Vec<String>>,
}

/// MC 1.21 registry-folder renames (plural ≤1.20 ↔ singular 1.21+).
const REGISTRY_FOLDER_RENAMES: &[(&str, &str)] = &[
    ("advancements", "advancement"),
    ("loot_tables", "loot_table"),
    ("recipes", "recipe"),
    ("predicates", "predicate"),
    ("item_modifiers", "item_modifier"),
    ("structures", "structure"),
    ("functions", "function"),
];

/// Normalize a resource path's registry folder to its singular (1.21) form so the
/// same logical resource compares equal regardless of MC version's folder naming.
fn canonical_registry_path(path: &str) -> String {
    let mut p = path.to_string();
    for (plural, singular) in REGISTRY_FOLDER_RENAMES {
        let from = format!("/{plural}/");
        if p.contains(&from) {
            p = p.replace(&from, &format!("/{singular}/"));
        }
    }
    p
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
                .canonical_definitions
                .insert(canonical_registry_path(&path));
            graph
                .namespace_owners
                .entry(rec.definition_namespace())
                .or_default()
                .insert(rec.writer.clone());

            if let crate::model::ResourceSummary::Tag(t) = &rec.ast.summary {
                graph.tag_entries.insert(path.clone(), t.entries.clone());
            }

            if matches!(rec.ast.parse_status, ParseStatus::Invalid) {
                continue;
            }
            for r in &rec.ast.references {
                graph.references.push(RefEdge {
                    from_path: path.clone(),
                    writer: rec.writer.clone(),
                    relation: r.relation,
                    target: r.target.clone(),
                    namespace: r.namespace.clone(),
                    required: r.required,
                    conditions: r.conditions.clone(),
                    is_tag: r.is_tag,
                });
            }
        }
        graph
    }

    /// Record that `writer` ships resources under `namespace` (used to seed
    /// ownership from binary-only namespaces a jar provides no parsed AST for).
    pub fn add_owner(&mut self, namespace: String, writer: String) {
        self.namespace_owners
            .entry(namespace)
            .or_default()
            .insert(writer);
    }

    /// Fold a vanilla resource index (from the Minecraft jar) into the graph:
    /// register every vanilla path as an external definition, mark `minecraft` as
    /// owned (so `minecraft:` references resolve instead of being blanket-skipped),
    /// and index vanilla tags for membership expansion. The records themselves are
    /// **not** added as writers — vanilla is the baseline, not a competing writer,
    /// so it never produces collision/override diffs or per-resource facts.
    pub fn add_vanilla_index(&mut self, records: &[ResourceAstRecord]) {
        if records.is_empty() {
            return;
        }
        self.add_owner("minecraft".to_string(), "minecraft".to_string());
        for rec in records {
            let path = &rec.ast.resource_path;
            self.external_definitions
                .insert(canonical_registry_path(path));
            if let crate::model::ResourceSummary::Tag(t) = &rec.ast.summary {
                self.tag_entries
                    .entry(path.clone())
                    .or_insert_with(|| t.entries.clone());
            }
        }
    }

    /// Whether a vanilla index has been loaded (`--minecraft-jar`).
    #[must_use]
    pub fn has_vanilla_index(&self) -> bool {
        !self.external_definitions.is_empty()
    }

    /// Whether the index has *any* definition in the same directory as `path` — i.e.
    /// we have ground-truth coverage of that area, so a missing sibling is a real
    /// dangling rather than a gap in an incomplete index.
    ///
    /// This is the key `minecraft:`-namespace FP-gate: the 1.20.1 *client* jar ships
    /// only the datagen-generated vanilla data (block loot tables, recipes) and NOT
    /// the hand-authored datapack (`tags/`, `loot_tables/chests/`, `loot_tables/archaeology/`,
    /// advancements, …). Without this gate, every real vanilla tag / chest / archaeology
    /// loot table a mod references would false-positive as dangling. Range queries keep
    /// it O(log n) per check.
    #[must_use]
    pub fn has_indexed_dir(&self, path: &str) -> bool {
        let Some(slash) = path.rfind('/') else {
            return false;
        };
        let dir = path[..=slash].to_string(); // includes trailing '/'
        // Only the *vanilla* index counts: a `minecraft:` resource's authoritative set
        // is vanilla, and mods routinely ADD files under `data/minecraft/...` (extending
        // a vanilla tag), which would otherwise make the directory look "covered" while
        // the vanilla set is absent — re-introducing the false positives.
        self.external_definitions
            .range(dir.clone()..)
            .next()
            .is_some_and(|k| k.starts_with(&dir))
    }

    /// All known tags' entries (pack + vanilla), keyed by resource path.
    #[must_use]
    pub fn tag_entries(&self) -> &BTreeMap<String, Vec<String>> {
        &self.tag_entries
    }

    /// Whether the pack (or the vanilla index) defines a resource at `path`,
    /// tolerant of the MC 1.21 registry-folder rename (a plural-form expected path
    /// matches a singular-form definition and vice-versa).
    #[must_use]
    pub fn has_definition(&self, path: &str) -> bool {
        let canon = canonical_registry_path(path);
        self.definitions.contains_key(path)
            || self.canonical_definitions.contains(&canon)
            || self.external_definitions.contains(&canon)
    }

    /// Whether any writer owns (ships resources under) `namespace`.
    #[must_use]
    pub fn namespace_is_owned(&self, namespace: &str) -> bool {
        self.namespace_owners.contains_key(namespace)
    }

    /// Whether references into `namespace` can be resolved to specific files for
    /// dangling/missing-tag checks. A real mod namespace (owned, non-platform) is
    /// resolvable. `minecraft` is resolvable **only when a vanilla index is loaded**
    /// — *not* merely when owned, because mods own `minecraft` by overriding vanilla
    /// resources, which gives an incomplete set (resolving against it manufactured
    /// thousands of false danglings). Convention/loader namespaces (`c`, `forge`, …)
    /// are never resolved: a partially-populated `#c:ingots/tin` is the normal
    /// state, not a broken reference.
    #[must_use]
    fn is_resolvable_namespace(&self, namespace: &str) -> bool {
        if is_platform_namespace(namespace) {
            return namespace == "minecraft" && self.has_vanilla_index();
        }
        self.namespace_is_owned(namespace)
    }

    /// References to a namespace that no installed jar owns and that is not a
    /// platform namespace — the candidates for an implicit dependency. Conditioned
    /// references are included (flagged) so Layer C can treat them as gated.
    #[must_use]
    pub fn implicit_dependency_candidates(&self) -> Vec<&RefEdge> {
        self.references
            .iter()
            .filter(|e| {
                e.relation.implies_dependency()
                    && !is_platform_namespace(&e.namespace)
                    && !self.namespace_is_owned(&e.namespace)
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
            if !matches!(
                e.relation,
                RefRelation::ParentModel | RefRelation::UsesModel
            ) {
                continue;
            }
            if is_platform_namespace(&e.namespace) || !self.namespace_is_owned(&e.namespace) {
                continue;
            }
            let expected = model_resource_path(&e.target);
            if !self.has_definition(&expected) {
                out.push(UnresolvedRef {
                    from_path: &e.from_path,
                    relation: e.relation,
                    target: &e.target,
                    namespace: &e.namespace,
                    expected_path: expected,
                });
            }
        }
        out
    }

    /// Tag entries that reference another **tag** which is not defined in the pack
    /// or the vanilla index — a broken tag reference (effective-tag-membership
    /// resolution). Gated on ownership exactly like [`Self::dangling_references`]:
    /// a `#minecraft:foo` reference is only checked once a vanilla index is loaded
    /// (so `#minecraft:logs` resolves to the real vanilla tag), and a reference
    /// into an uninstalled mod's namespace is left to missing-dependency analysis.
    /// Returns `(from_tag_path, missing_tag_id, expected_path)`.
    #[must_use]
    pub fn missing_tag_references(&self) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for e in &self.references {
            // A tag→tag reference is a required `UsesTag` edge whose entry was
            // `#`-prefixed; optional (`required: false`) tag entries are fine absent.
            if e.relation != RefRelation::UsesTag || !e.is_tag || !e.required {
                continue;
            }
            // Tags are *open sets*: an undefined tag is empty (not a load error),
            // and mods routinely reference tags filled at runtime / by datagen, so a
            // missing mod tag is too false-positive-prone to flag. Only `minecraft`
            // tags are flagged.
            if e.namespace != "minecraft" {
                continue;
            }
            if !e.conditions.is_empty() {
                continue;
            }
            // The referenced tag shares the *source* tag's registry (items/blocks/…).
            let Some(registry) = tag_registry_of(&e.from_path) else {
                continue;
            };
            let expected = tag_ref_path(&e.namespace, registry, &e.target);
            // FP-gate: only flag when the vanilla tag *directory* is actually indexed
            // (the client jar ships no `data/minecraft/tags/`, so otherwise every real
            // vanilla tag false-positives).
            if self.has_indexed_dir(&expected) && !self.has_definition(&expected) {
                out.push((e.from_path.clone(), format!("#{}", e.target), expected));
            }
        }
        out
    }

    /// References that point to an expected resource file that does not exist in
    /// the pack (or the vanilla index). Excludes conditioned/optional references and
    /// domains that cannot be resolved to a specific file (e.g. items).
    ///
    /// Resolution is by **ownership**: a reference into a namespace whose resources
    /// are indexed (a pack mod, or `minecraft` once `--minecraft-jar` is loaded) is
    /// checked; a reference into an un-indexed namespace is skipped (its absence is
    /// a missing-dependency concern, not a dangling file). So `minecraft:` refs are
    /// skipped *until* a vanilla index makes `minecraft` owned — then they resolve
    /// against real vanilla resources.
    #[must_use]
    pub fn dangling_references(&self) -> Vec<UnresolvedRef<'_>> {
        let mut out = Vec::new();
        for e in &self.references {
            if !e.required || !e.conditions.is_empty() {
                continue;
            }
            if !self.is_resolvable_namespace(&e.namespace) {
                continue;
            }

            let expected = match e.relation {
                RefRelation::ParentModel | RefRelation::UsesModel => {
                    Some(model_resource_path(&e.target))
                }
                RefRelation::UsesTexture => Some(texture_resource_path(&e.target)),
                RefRelation::LootEntry => Some(loot_table_resource_path(&e.target)),
                RefRelation::AdvancementCriterion => Some(advancement_resource_path(&e.target)),
                _ => None,
            };

            if let Some(expected_path) = expected {
                // For `minecraft:` targets the index may be partial (the client jar
                // ships only block loot tables, not chests/archaeology/etc.), so only
                // flag when the target's directory is actually indexed — ground truth.
                let indexed_area =
                    e.namespace != "minecraft" || self.has_indexed_dir(&expected_path);
                if indexed_area && !self.has_definition(&expected_path) {
                    out.push(UnresolvedRef {
                        from_path: &e.from_path,
                        relation: e.relation,
                        target: &e.target,
                        namespace: &e.namespace,
                        expected_path,
                    });
                }
            }
        }
        out
    }

    /// Mods that own (ship resources under) `namespace`, sorted. Empty for an
    /// unowned namespace. Lets a dangling finding name *whose* resource is missing.
    pub fn owners_of(&self, namespace: &str) -> Vec<String> {
        self.namespace_owners
            .get(namespace)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
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
    /// The namespace the missing target id lives in (its owning-mod domain).
    pub namespace: &'a str,
    /// The resource path the target id resolves to (`assets/<ns>/models/<p>.json`).
    pub expected_path: String,
}

fn split_id(id: &str) -> (&str, &str) {
    let id = id.trim_start_matches('#');
    match id.split_once(':') {
        Some((ns, p)) if !ns.is_empty() => (ns, p),
        _ => ("minecraft", id),
    }
}

pub(crate) fn model_resource_path(id: &str) -> String {
    let (ns, path) = split_id(id);
    format!("assets/{ns}/models/{path}.json")
}

pub(crate) fn texture_resource_path(id: &str) -> String {
    let (ns, path) = split_id(id);
    format!("assets/{ns}/textures/{path}.png")
}

pub(crate) fn loot_table_resource_path(id: &str) -> String {
    let (ns, path) = split_id(id);
    format!("data/{ns}/loot_tables/{path}.json")
}

pub(crate) fn advancement_resource_path(id: &str) -> String {
    let (ns, path) = split_id(id);
    format!("data/{ns}/advancements/{path}.json")
}

/// The registry of a tag path (`data/<ns>/tags/<registry…>/<file>.json`) — the
/// segment(s) between `/tags/` and the final file name.
fn tag_registry_of(path: &str) -> Option<&str> {
    let after = path.split_once("/tags/")?.1;
    after.rsplit_once('/').map(|(registry, _file)| registry)
}

/// Expected file path of a `#ns:path` tag reference within `registry`.
fn tag_ref_path(ns: &str, registry: &str, tag_id: &str) -> String {
    let (_, path) = split_id(tag_id);
    format!("data/{ns}/tags/{registry}/{path}.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ResourceDomain, ResourceReference, ResourceSummary};

    fn record(
        archive: &str,
        writer: &str,
        path: &str,
        refs: Vec<ResourceReference>,
    ) -> ResourceAstRecord {
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
            conditions: Vec::new(),
            is_tag: false,
        }
    }

    fn tag_record(writer: &str, path: &str, entries: &[&str]) -> ResourceAstRecord {
        // Mirror the tag parser: `#`-prefixed entries become `UsesTag` edges
        // (is_tag), bare entries become `UsesItem`; summary entries drop the `#`.
        let refs = entries
            .iter()
            .map(|e| {
                let is_tag = e.starts_with('#');
                let target = e.trim_start_matches('#').to_string();
                ResourceReference {
                    relation: if is_tag {
                        RefRelation::UsesTag
                    } else {
                        RefRelation::UsesItem
                    },
                    namespace: crate::semantic::namespace::namespace_of(&target),
                    target,
                    required: true,
                    conditions: vec![],
                    is_tag,
                }
            })
            .collect();
        let mut r = record(&format!("{writer}.jar"), writer, path, refs);
        r.ast.domain = ResourceDomain::Tag;
        r.ast.summary = ResourceSummary::Tag(crate::domain::tag::TagSummary {
            registry: "items".into(),
            replace: false,
            entry_count: entries.len(),
            has_required_flag: false,
            entries: entries
                .iter()
                .map(|s| s.trim_start_matches('#').to_string())
                .collect(),
        });
        r
    }

    #[test]
    fn vanilla_index_resolves_minecraft_refs_and_tags() {
        // A pack tag references a vanilla tag (#minecraft:logs) and a missing one.
        let pack = vec![tag_record(
            "create",
            "data/create/tags/items/woods.json",
            &[
                "#minecraft:logs",
                "#minecraft:nonexistent_tag",
                "create:gear",
            ],
        )];
        let mut graph = ResourceGraph::build(&pack);
        // Without a vanilla index, minecraft is not owned → no tag checks fire.
        assert!(graph.missing_tag_references().is_empty());
        assert!(!graph.has_vanilla_index());

        // Load a vanilla index that defines minecraft:logs but not the other.
        let vanilla = vec![tag_record(
            "minecraft",
            "data/minecraft/tags/items/logs.json",
            &[],
        )];
        graph.add_vanilla_index(&vanilla);
        assert!(graph.has_vanilla_index());
        assert!(graph.has_definition("data/minecraft/tags/items/logs.json"));

        let missing = graph.missing_tag_references();
        // Only the genuinely-absent vanilla tag is flagged; #minecraft:logs resolves.
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].1, "#minecraft:nonexistent_tag");
    }

    #[test]
    fn vanilla_index_without_tags_does_not_false_positive_on_minecraft_tags() {
        // Regression: the 1.20.1 *client* jar ships loot tables/recipes but NO
        // `data/minecraft/tags/`. A vanilla index built from it must NOT flag every
        // referenced vanilla tag as dangling.
        let pack = vec![tag_record(
            "create",
            "data/create/tags/items/woods.json",
            &["#minecraft:logs", "#minecraft:planks"],
        )];
        let mut graph = ResourceGraph::build(&pack);
        // Vanilla index has a loot table (a covered dir) but ZERO tags.
        let vanilla = vec![record(
            "client.jar",
            "minecraft",
            "data/minecraft/loot_tables/blocks/stone.json",
            vec![],
        )];
        graph.add_vanilla_index(&vanilla);
        assert!(graph.has_vanilla_index());
        // No `data/minecraft/tags/...` in the index → tag directory not covered →
        // no minecraft tag is flagged (would otherwise be a flood of false positives).
        assert!(
            graph.missing_tag_references().is_empty(),
            "vanilla index without tags must not flag minecraft tags"
        );
    }

    #[test]
    fn has_definition_tolerates_registry_folder_rename() {
        // A 1.21 pack ships advancements under the *singular* folder.
        let records = vec![record(
            "create.jar",
            "create",
            "data/create/advancement/root.json",
            vec![],
        )];
        let graph = ResourceGraph::build(&records);
        // A plural-form expected path (older resolver convention) still resolves.
        assert!(graph.has_definition("data/create/advancements/root.json"));
        assert!(graph.has_definition("data/create/advancement/root.json"));
        assert!(!graph.has_definition("data/create/advancement/missing.json"));
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
                    conditions: Vec::new(),
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
            model_record(
                "modb",
                "assets/modb/models/item/a.json",
                "modb:item/missing",
            ),
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
            model_record(
                "modb",
                "assets/modb/models/item/b.json",
                "minecraft:item/generated",
            ),
            // parent in an uninstalled namespace — implicit dep, not dangling
            model_record("modb", "assets/modb/models/item/c.json", "ghostmod:item/x"),
        ];
        let graph = ResourceGraph::build(&records);
        let unresolved = graph.unresolved_model_references();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].target, "modb:item/missing");
        assert_eq!(
            unresolved[0].expected_path,
            "assets/modb/models/item/missing.json"
        );
    }

    #[test]
    fn present_parent_is_not_dangling() {
        let records = vec![
            model_record(
                "modb",
                "assets/modb/models/item/a.json",
                "modb:item/present",
            ),
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
            vec![
                rref("minecraft", "minecraft:stick"),
                rref("forge", "forge:conditional"),
            ],
        )];
        let graph = ResourceGraph::build(&records);
        assert!(graph.implicit_dependency_candidates().is_empty());
    }
}
