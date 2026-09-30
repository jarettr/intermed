//! The resource reference graph: definitions, references, and namespace owners
//! aggregated across every writer in the pack.
//!
//! The graph is pure data derived from the per-resource [`CachedResourceAst`]s. It
//! holds no opinions — rules (Layer M / Layer C) read it to decide implicit
//! dependencies, and `explain` reads it for unresolved references. This keeps to
//! the layer's contract: **the AST never emits findings**.

use std::collections::{BTreeMap, BTreeSet};

use crate::domain::tag::TagEntrySummary;
use crate::model::{CachedResourceAst, ParseStatus, RefRelation};
use crate::semantic::namespace::{is_platform_namespace, path_namespace};

/// One parsed resource attributed to the jar that shipped it.
#[derive(Debug, Clone)]
pub struct ResourceAstRecord {
    /// Root-qualified artifact locator (e.g. `mods/create.jar`).
    pub archive: String,
    /// Stable content identity when known, otherwise an explicit unresolved id.
    pub artifact_id: String,
    /// Resolved writer/mod id (e.g. `create`).
    pub writer: String,
    pub ast: CachedResourceAst,
}

/// A physical resource path observed in the ZIP central directory, even when its
/// body was too large or otherwise unavailable to the AST parser.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourcePresence {
    pub archive: String,
    pub artifact_id: String,
    pub writer: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DefinitionState {
    ValidDefinition,
    InvalidDefinition,
    PresentUnparsed,
}

/// Resolution of a resource path after separating physical presence from parse
/// validity. Multiple competing states remain explicit instead of being treated
/// as a normal valid definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionResolution {
    ValidDefinition,
    InvalidDefinition,
    PresentUnparsed,
    Absent,
    Ambiguous(BTreeSet<DefinitionState>),
}

impl DefinitionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ValidDefinition => "valid-definition",
            Self::InvalidDefinition => "invalid-definition",
            Self::PresentUnparsed => "present-unparsed",
        }
    }
}

/// One writer's contribution to a tag. Contributions stay separate until a
/// resource-priority order is known; `replace:true` must never be guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagContribution {
    pub writer: String,
    pub artifact_id: String,
    pub replace: bool,
    pub entries: Vec<TagEntrySummary>,
}

/// Effective tag membership result. Append-only contributions are order
/// independent; `replace:true` requires an authoritative low-to-high resource
/// priority and otherwise remains explicitly unresolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveTagMembership {
    Resolved(BTreeSet<TagEntrySummary>),
    OrderDependent { writers: Vec<String> },
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
    pub certainty: crate::model::ReferenceCertainty,
}

/// The aggregated reference graph for a whole pack.
#[derive(Debug, Default)]
pub struct ResourceGraph {
    /// `resource_path → set of writers that define it`.
    pub definitions: BTreeMap<String, BTreeSet<String>>,
    definition_states: BTreeMap<String, BTreeSet<DefinitionState>>,
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
    external_definition_states: BTreeMap<String, BTreeSet<DefinitionState>>,
    /// True only when the external vanilla artifact was scanned without a
    /// relevant gap. Partial records may satisfy observed references, but may
    /// never justify an absence conclusion.
    vanilla_coverage: BTreeMap<String, intermed_evidence::CoverageState>,
    /// Pack and vanilla contributions are kept apart so reloading a baseline can
    /// never erase a pack override under `data/minecraft/tags/...`.
    pack_tags: BTreeMap<String, Vec<TagContribution>>,
    vanilla_tags: BTreeMap<String, Vec<TagContribution>>,
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
///
/// Only the **registry-folder segment** (the third slash-delimited component of a
/// MC path: `data/<ns>/<registry>/…` or `assets/<ns>/<registry>/…`) is touched.
/// A whole-string `replace` would also mangle namespace names or sub-directory names
/// that happen to share a word with a registry folder (e.g. a namespace called
/// `advancements_mod`, or a nested path `loot_tables/loot_tables/foo.json`).
fn canonical_registry_path(path: &str) -> String {
    // Split off the first two components (`data` or `assets`, then the namespace).
    // The registry folder is the third component; everything after is kept verbatim.
    let mut components = path.splitn(4, '/');
    let root = components.next().unwrap_or("");
    let ns = components.next().unwrap_or("");
    let registry = components.next().unwrap_or("");
    let rest = components.next().unwrap_or("");

    // Map the registry folder to its canonical (singular) form if it matches.
    let canonical_registry = REGISTRY_FOLDER_RENAMES
        .iter()
        .find_map(|(plural, singular)| {
            if *plural == registry {
                Some(*singular)
            } else {
                None
            }
        })
        .unwrap_or(registry);

    if rest.is_empty() {
        // Path has ≤ 3 components — nothing to normalise (no registry folder present).
        path.to_string()
    } else {
        format!("{root}/{ns}/{canonical_registry}/{rest}")
    }
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
                .definition_states
                .entry(canonical_registry_path(&path))
                .or_default()
                .insert(match rec.ast.parse_status {
                    ParseStatus::Invalid => DefinitionState::InvalidDefinition,
                    ParseStatus::Skipped => DefinitionState::PresentUnparsed,
                    ParseStatus::Parsed | ParseStatus::PartiallyParsed => {
                        DefinitionState::ValidDefinition
                    }
                });

            // Regression: only record namespace ownership when the writer *actually*
            // provides that namespace (not when a mod drops a file under
            // `data/minecraft/…` to override vanilla). A pack writer that puts a
            // file under a `minecraft` namespace does NOT make `minecraft` an
            // installed/owned namespace — that would skip the vanilla-index gate and
            // re-introduce dangling false-positives for every other minecraft ref.
            let ns = rec.definition_namespace();
            if ns != "minecraft" || rec.writer == "minecraft" {
                graph
                    .namespace_owners
                    .entry(ns)
                    .or_default()
                    .insert(rec.writer.clone());
            }

            // Invalid summaries are untrusted and cannot contribute membership.
            if matches!(rec.ast.parse_status, ParseStatus::Invalid) {
                continue;
            }

            if let crate::model::ResourceSummary::Tag(t) = &rec.ast.summary {
                graph
                    .pack_tags
                    .entry(path.clone())
                    .or_default()
                    .push(TagContribution {
                        writer: rec.writer.clone(),
                        artifact_id: rec.artifact_id.clone(),
                        replace: t.replace,
                        entries: t.entries.clone(),
                    });
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
                    certainty: r.certainty,
                });
            }
        }
        graph
    }

    /// Add central-directory presence records. Parsed records replace the weaker
    /// `present-unparsed` state; paths without ASTs still resolve as physically
    /// present and therefore cannot become false dangling references.
    pub fn add_presences(&mut self, presences: &[ResourcePresence]) {
        for presence in presences {
            self.definitions
                .entry(presence.path.clone())
                .or_default()
                .insert(presence.writer.clone());
            let canonical = canonical_registry_path(&presence.path);
            self.canonical_definitions.insert(canonical.clone());
            self.definition_states
                .entry(canonical)
                .or_insert_with(|| BTreeSet::from([DefinitionState::PresentUnparsed]));
        }
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
    ///
    /// Calling this more than once replaces the previous vanilla index entirely —
    /// the external definitions and any vanilla tag entries are cleared first so
    /// that stale data from a prior load (different MC version, different jar) does
    /// not bleed into the new index.
    pub fn add_vanilla_index(
        &mut self,
        records: &[ResourceAstRecord],
        presences: &[ResourcePresence],
        coverage: BTreeMap<String, intermed_evidence::CoverageState>,
    ) {
        self.external_definitions.clear();
        self.external_definition_states.clear();
        self.vanilla_tags.clear();

        self.vanilla_coverage = coverage;
        if !records.is_empty() {
            self.add_owner("minecraft".to_string(), "minecraft".to_string());
        }
        for rec in records {
            let path = &rec.ast.resource_path;
            let canonical = canonical_registry_path(path);
            self.external_definitions.insert(canonical.clone());
            self.external_definition_states
                .entry(canonical)
                .or_default()
                .insert(match rec.ast.parse_status {
                    ParseStatus::Invalid => DefinitionState::InvalidDefinition,
                    ParseStatus::Skipped => DefinitionState::PresentUnparsed,
                    ParseStatus::Parsed | ParseStatus::PartiallyParsed => {
                        DefinitionState::ValidDefinition
                    }
                });
            if let crate::model::ResourceSummary::Tag(t) = &rec.ast.summary {
                self.vanilla_tags
                    .entry(path.clone())
                    .or_default()
                    .push(TagContribution {
                        writer: "minecraft".to_string(),
                        artifact_id: rec.artifact_id.clone(),
                        replace: t.replace,
                        entries: t.entries.clone(),
                    });
            }
        }
        for presence in presences {
            let canonical = canonical_registry_path(&presence.path);
            self.external_definitions.insert(canonical.clone());
            self.external_definition_states
                .entry(canonical)
                .or_insert_with(|| BTreeSet::from([DefinitionState::PresentUnparsed]));
        }
    }

    /// Whether a vanilla index has been loaded (`--minecraft-jar`).
    #[must_use]
    pub fn has_vanilla_index(&self) -> bool {
        !self.external_definitions.is_empty()
    }

    #[must_use]
    pub fn vanilla_coverage(
        &self,
        domain: crate::model::ResourceDomain,
    ) -> Option<&intermed_evidence::CoverageState> {
        self.vanilla_coverage.get(domain.as_str())
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
        // Regression: external_definitions stores *canonical* paths (registry folder
        // already normalised to its singular 1.21 form). The incoming `path` may
        // still use the plural form (e.g. `data/minecraft/loot_tables/blocks/foo`).
        // We must canonicalize the directory prefix before the range scan, otherwise
        // the BTreeMap range misses all entries and the FP gate is never triggered.
        let raw_dir = &path[..=slash]; // includes trailing '/'
        let canonical_dir = {
            let canon = canonical_registry_path(path);
            let end = canon.rfind('/').map_or(canon.len(), |i| i + 1);
            canon[..end].to_string()
        };
        // Only the *vanilla* index counts: a `minecraft:` resource's authoritative set
        // is vanilla, and mods routinely ADD files under `data/minecraft/...` (extending
        // a vanilla tag), which would otherwise make the directory look "covered" while
        // the vanilla set is absent — re-introducing the false positives.
        let _ = raw_dir; // kept for documentation; canonical_dir is used below
        self.external_definitions
            .range(canonical_dir.clone()..)
            .next()
            .is_some_and(|k| k.starts_with(&canonical_dir))
    }

    /// All known tags' entries (pack + vanilla), keyed by resource path.
    #[must_use]
    pub fn pack_tag_contributions(&self) -> &BTreeMap<String, Vec<TagContribution>> {
        &self.pack_tags
    }

    #[must_use]
    pub fn vanilla_tag_contributions(&self) -> &BTreeMap<String, Vec<TagContribution>> {
        &self.vanilla_tags
    }

    /// Resolve one tag using an optional authoritative low-to-high artifact
    /// priority. Vanilla is always the baseline. Without priority, append-only
    /// tags safely union; a replacing pack contribution is order-dependent.
    #[must_use]
    pub fn effective_tag_membership(
        &self,
        path: &str,
        artifact_priority: Option<&[String]>,
    ) -> EffectiveTagMembership {
        let vanilla = self.vanilla_tags.get(path).cloned().unwrap_or_default();
        let mut pack = self.pack_tags.get(path).cloned().unwrap_or_default();

        if pack.iter().any(|contribution| contribution.replace) {
            let Some(priority) = artifact_priority else {
                let mut writers: Vec<_> = pack
                    .iter()
                    .map(|contribution| contribution.writer.clone())
                    .collect();
                writers.sort();
                writers.dedup();
                return EffectiveTagMembership::OrderDependent { writers };
            };
            let ranks: BTreeMap<_, _> = priority
                .iter()
                .enumerate()
                .map(|(rank, artifact)| (artifact.as_str(), rank))
                .collect();
            if pack
                .iter()
                .any(|contribution| !ranks.contains_key(contribution.artifact_id.as_str()))
            {
                let mut writers: Vec<_> = pack
                    .iter()
                    .map(|contribution| contribution.writer.clone())
                    .collect();
                writers.sort();
                writers.dedup();
                return EffectiveTagMembership::OrderDependent { writers };
            }
            pack.sort_by_key(|contribution| ranks[contribution.artifact_id.as_str()]);
        }

        let mut entries = BTreeSet::new();
        for contribution in vanilla.into_iter().chain(pack) {
            if contribution.replace {
                entries.clear();
            }
            entries.extend(contribution.entries);
        }
        EffectiveTagMembership::Resolved(entries)
    }

    /// Definition state for an expected path. Presence is distinct from validity.
    #[must_use]
    pub fn definition_states(&self, path: &str) -> BTreeSet<DefinitionState> {
        let canonical = canonical_registry_path(path);
        let mut states = self
            .definition_states
            .get(&canonical)
            .cloned()
            .unwrap_or_default();
        if let Some(external) = self.external_definition_states.get(&canonical) {
            states.extend(external.iter().copied());
        }
        states
    }

    #[must_use]
    pub fn resolve_definition(&self, path: &str) -> DefinitionResolution {
        let states = self.definition_states(path);
        if states.len() > 1 {
            return DefinitionResolution::Ambiguous(states);
        }
        match states.iter().next().copied() {
            Some(DefinitionState::ValidDefinition) => DefinitionResolution::ValidDefinition,
            Some(DefinitionState::InvalidDefinition) => DefinitionResolution::InvalidDefinition,
            Some(DefinitionState::PresentUnparsed) => DefinitionResolution::PresentUnparsed,
            None => DefinitionResolution::Absent,
        }
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
    ///
    /// **Model references (`ParentModel`, `UsesModel`) are intentionally excluded.**
    /// Absence of a model JSON file is not proof of a broken reference — mods
    /// frequently use runtime-generated/baked models, custom model loaders, or rely
    /// on a resource pack. Those are surfaced separately by
    /// [`Self::unresolved_model_references`] as informational only, and raising them
    /// as findings here produced confirmed false positives on real packs.
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

            // Regression: ParentModel / UsesModel were included here even though the
            // doc comment of unresolved_model_references says "informational only —
            // NOT a list of bugs" and warns of confirmed FPs. Remove them so that
            // dangling_references never returns the same FP class.
            let expected = match e.relation {
                RefRelation::UsesTexture => Some(texture_resource_path(&e.target)),
                RefRelation::LootEntry => Some(loot_table_resource_path(&e.target)),
                RefRelation::ParentAdvancement => Some(advancement_resource_path(&e.target)),
                #[allow(deprecated)]
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
            artifact_id: format!("unresolved:{archive}"),
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
                references_complete: true,
                reference_gap: None,
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
            certainty: crate::model::ReferenceCertainty::ExactSchemaReference,
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
                    certainty: crate::model::ReferenceCertainty::ExactSchemaReference,
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
                .map(|s| crate::domain::tag::TagEntrySummary {
                    id: s.trim_start_matches('#').to_string(),
                    is_tag: s.starts_with('#'),
                    required: true,
                })
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
        graph.add_vanilla_index(&vanilla, &[], BTreeMap::new());
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
        graph.add_vanilla_index(&vanilla, &[], BTreeMap::new());
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
            artifact_id: format!("unresolved:{writer}.jar"),
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
                    certainty: crate::model::ReferenceCertainty::ExactSchemaReference,
                }],
                references_complete: true,
                reference_gap: None,
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
                artifact_id: "unresolved:modb.jar".into(),
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
                    references_complete: true,
                    reference_gap: None,
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
                artifact_id: "unresolved:modb.jar".into(),
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
                    references_complete: true,
                    reference_gap: None,
                    diagnostics: vec![],
                },
            },
        ];
        let graph = ResourceGraph::build(&records);
        assert!(graph.unresolved_model_references().is_empty());
    }

    #[test]
    fn physically_present_unparsed_resource_is_not_dangling() {
        let mut source_ref = rref("modb", "modb:item/huge");
        source_ref.relation = RefRelation::UsesTexture;
        let source = record(
            "mods/modb.jar",
            "modb",
            "assets/modb/models/item/source.json",
            vec![source_ref],
        );
        let target_path = "assets/modb/textures/item/huge.png";
        let mut graph = ResourceGraph::build(&[source]);
        graph.add_presences(&[ResourcePresence {
            archive: "mods/modb.jar".into(),
            artifact_id: "sha256:large".into(),
            writer: "modb".into(),
            path: target_path.into(),
        }]);

        assert!(graph.dangling_references().is_empty());
        assert_eq!(
            graph.definition_states(target_path),
            BTreeSet::from([DefinitionState::PresentUnparsed])
        );
        assert_eq!(
            graph.resolve_definition(target_path),
            DefinitionResolution::PresentUnparsed
        );
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

    // ── Regression tests for resource-graph invariants ─────────────────

    /// Every tag writer remains a separate contribution until priority is known.
    #[test]
    fn tag_contributions_preserve_every_writer_and_entry_metadata() {
        let path = "data/minecraft/tags/items/logs.json";
        let first = tag_record("modA", path, &["minecraft:oak_log"]);
        let second = tag_record("modB", path, &["minecraft:birch_log"]);
        let graph = ResourceGraph::build(&[first, second]);
        let entries = graph
            .pack_tag_contributions()
            .get(path)
            .cloned()
            .unwrap_or_default();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entries[0].id, "minecraft:oak_log");
        assert_eq!(entries[1].entries[0].id, "minecraft:birch_log");
        assert!(entries.iter().all(|entry| entry.entries[0].required));
    }

    #[test]
    fn append_only_tags_union_but_replace_requires_priority() {
        let path = "data/minecraft/tags/items/logs.json";
        let first = tag_record("modA", path, &["minecraft:oak_log"]);
        let mut second = tag_record("modB", path, &["minecraft:birch_log"]);
        if let ResourceSummary::Tag(tag) = &mut second.ast.summary {
            tag.replace = true;
        }
        let graph = ResourceGraph::build(&[first.clone(), second.clone()]);
        assert!(matches!(
            graph.effective_tag_membership(path, None),
            EffectiveTagMembership::OrderDependent { .. }
        ));

        let priority = vec![first.artifact_id.clone(), second.artifact_id.clone()];
        let EffectiveTagMembership::Resolved(entries) =
            graph.effective_tag_membership(path, Some(&priority))
        else {
            panic!("authoritative priority must resolve replacing tags");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries.iter().next().unwrap().id, "minecraft:birch_log");
    }

    #[test]
    fn replacing_vanilla_index_preserves_pack_minecraft_tag() {
        let path = "data/minecraft/tags/items/logs.json";
        let pack = tag_record("create", path, &["create:rubber_log"]);
        let mut graph = ResourceGraph::build(&[pack]);
        let vanilla = tag_record("minecraft", path, &["minecraft:oak_log"]);
        graph.add_vanilla_index(&[vanilla], &[], BTreeMap::new());

        assert_eq!(graph.pack_tag_contributions()[path].len(), 1);
        let EffectiveTagMembership::Resolved(entries) = graph.effective_tag_membership(path, None)
        else {
            panic!("append-only pack and vanilla tags are order independent");
        };
        assert!(entries.iter().any(|entry| entry.id == "minecraft:oak_log"));
        assert!(entries.iter().any(|entry| entry.id == "create:rubber_log"));
    }

    /// Regression: partial vanilla index (has external_definitions covering the dir
    /// but NOT the specific tag) must still fire missing_tag_references.
    /// Previously the FP-gate was correct, but this test pins the behaviour.
    #[test]
    fn missing_tag_references_fires_when_dir_is_covered_but_tag_absent() {
        let pack = vec![tag_record(
            "create",
            "data/create/tags/items/woods.json",
            &["#minecraft:absent_tag"],
        )];
        let mut graph = ResourceGraph::build(&pack);
        // Vanilla index covers the tag directory but NOT the specific tag.
        let vanilla = vec![tag_record(
            "minecraft",
            "data/minecraft/tags/items/logs.json",
            &[],
        )];
        graph.add_vanilla_index(&vanilla, &[], BTreeMap::new());
        let missing = graph.missing_tag_references();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].1, "#minecraft:absent_tag");
    }

    /// Regression: canonical_registry_path must only normalise the registry-folder
    /// segment, not any occurrence elsewhere in the path.
    #[test]
    fn canonical_registry_path_only_touches_registry_segment() {
        // Namespace `advancements_ns` must survive unmodified.
        assert_eq!(
            canonical_registry_path("data/advancements_ns/advancements/root.json"),
            "data/advancements_ns/advancement/root.json",
        );
        // Nested sub-directory that happens to share the plural word must not be
        // touched (only the third component is the registry folder).
        assert_eq!(
            canonical_registry_path("data/ns/loot_tables/loot_tables/chest.json"),
            "data/ns/loot_table/loot_tables/chest.json",
        );
        // A path with fewer than 4 components is returned verbatim.
        assert_eq!(
            canonical_registry_path("data/ns/advancements"),
            "data/ns/advancements",
        );
        // Normal case: singular form already — no change.
        assert_eq!(
            canonical_registry_path("data/ns/advancement/root.json"),
            "data/ns/advancement/root.json",
        );
    }

    /// Regression: has_indexed_dir must canonicalise the query path before searching
    /// the (already-canonical) external_definitions BTreeMap.
    #[test]
    fn has_indexed_dir_plural_path_matches_canonical_external_defs() {
        let mut graph = ResourceGraph::default();
        // Vanilla index stores canonical (singular) paths.
        let vanilla = vec![record(
            "client.jar",
            "minecraft",
            "data/minecraft/loot_table/blocks/stone.json", // singular
            vec![],
        )];
        graph.add_vanilla_index(&vanilla, &[], BTreeMap::new());
        // Query with plural form must still find the directory.
        assert!(
            graph.has_indexed_dir("data/minecraft/loot_tables/blocks/missing.json"),
            "plural query path must match canonical directory"
        );
        // Unrelated directory must not match.
        assert!(
            !graph.has_indexed_dir("data/minecraft/loot_tables/archaeology/missing.json"),
            "uncovered directory must return false"
        );
    }

    /// Regression: dangling_references must NOT return ParentModel / UsesModel edges;
    /// those are FP-prone and covered by unresolved_model_references only.
    #[test]
    fn dangling_references_excludes_model_relations() {
        let records = vec![model_record(
            "modb",
            "assets/modb/models/item/a.json",
            "modb:item/definitely_missing",
        )];
        let graph = ResourceGraph::build(&records);
        // unresolved_model_references sees it (informational).
        assert!(!graph.unresolved_model_references().is_empty());
        // dangling_references must NOT include it.
        assert!(
            graph.dangling_references().is_empty(),
            "dangling_references must not surface ParentModel/UsesModel FP class"
        );
    }

    /// Regression: a mod writing files under `data/minecraft/…` must NOT cause
    /// `minecraft` to appear as an owned namespace (which would bypass the
    /// vanilla-index gate and re-introduce dangling FPs for minecraft refs).
    #[test]
    fn minecraft_namespace_not_owned_by_overriding_mod() {
        let records = vec![
            // A mod overrides a vanilla tag — drops a file under data/minecraft.
            tag_record(
                "create",
                "data/minecraft/tags/items/logs.json",
                &["minecraft:oak_log", "create:oak_log"],
            ),
            // The mod also ships its own tag in its own namespace.
            tag_record(
                "create",
                "data/create/tags/items/gears.json",
                &["create:brass_gear"],
            ),
        ];
        let graph = ResourceGraph::build(&records);
        // `minecraft` must NOT appear as owned (no vanilla index loaded), even
        // though `create` placed a file under data/minecraft/.
        assert!(
            !graph.namespace_is_owned("minecraft"),
            "minecraft must not be owned merely because a mod overrides a vanilla file"
        );
        // create IS owned (it ships pack files under data/create/).
        assert!(
            graph.namespace_is_owned("create"),
            "create must be owned via its own-namespace file"
        );
    }

    /// Regression: an Invalid-status tag record must not pollute tag_entries.
    #[test]
    fn invalid_tag_not_added_to_tag_entries() {
        let path = "data/create/tags/items/woods.json";
        let mut rec = tag_record("create", path, &["create:oak_plank"]);
        rec.ast.parse_status = ParseStatus::Invalid;
        let graph = ResourceGraph::build(&[rec]);
        assert!(
            !graph.pack_tag_contributions().contains_key(path),
            "Invalid-status tag must not appear in tag_entries"
        );
    }

    #[test]
    fn malformed_definition_is_present_but_not_valid() {
        let mut invalid = tag_record("broken", "data/broken/tags/items/x.json", &[]);
        invalid.ast.parse_status = ParseStatus::Invalid;
        invalid.ast.summary = ResourceSummary::Generic;
        let graph = ResourceGraph::build(&[invalid]);
        let path = "data/broken/tags/items/x.json";
        assert!(graph.has_definition(path));
        assert_eq!(
            graph.definition_states(path),
            BTreeSet::from([DefinitionState::InvalidDefinition])
        );
        assert_eq!(
            graph.resolve_definition(path),
            DefinitionResolution::InvalidDefinition
        );
        assert!(!graph.pack_tag_contributions().contains_key(path));
    }

    /// Regression: repeated calls to add_vanilla_index must replace the previous
    /// index entirely, not accumulate stale external definitions.
    #[test]
    fn add_vanilla_index_is_idempotent_and_replaces_previous() {
        let pack = vec![];
        let mut graph = ResourceGraph::build(&pack);

        // First load: a 1.20 client jar with stone loot table.
        let v1 = vec![record(
            "client-1.20.jar",
            "minecraft",
            "data/minecraft/loot_table/blocks/stone.json",
            vec![],
        )];
        graph.add_vanilla_index(&v1, &[], BTreeMap::new());
        assert!(graph.has_definition("data/minecraft/loot_table/blocks/stone.json"));

        // Second load (1.21 jar): stone loot table gone, only cobblestone present.
        let v2 = vec![record(
            "client-1.21.jar",
            "minecraft",
            "data/minecraft/loot_table/blocks/cobblestone.json",
            vec![],
        )];
        graph.add_vanilla_index(&v2, &[], BTreeMap::new());
        // Stale entry from the first load must be gone.
        assert!(
            !graph.has_definition("data/minecraft/loot_table/blocks/stone.json"),
            "stale entry from previous vanilla index must be cleared"
        );
        // New entry must be present.
        assert!(graph.has_definition("data/minecraft/loot_table/blocks/cobblestone.json"));
    }
}
