//! Typed resource-AST model: the data carried from parse → semantic summary →
//! cache → facts.
//!
//! Pipeline (the layer's guiding philosophy — the AST never emits findings):
//!
//! ```text
//! resource bytes → syntax AST → typed domain AST → semantic summary → facts → rules → findings
//! ```
//!
//! These types are the *compact* output: the full syntax AST is transient (parsed,
//! summarised, dropped). Only [`CachedResourceAst`] — a small, serialisable
//! summary + references + diagnostics — is cached and lowered into facts.

use serde::{Deserialize, Serialize};

/// Analysis depth for Layer M, mirroring `--resource-level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceLevel {
    /// Layer M disabled — only the Layer-E VFS raw layer runs.
    #[default]
    Basic,
    /// Tags, recipes, lang, pack.mcmeta, namespace/reference graph.
    Semantic,
    /// Adds models, blockstates, loot tables, atlases, advancements.
    Full,
}

impl ResourceLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceLevel::Basic => "basic",
            ResourceLevel::Semantic => "semantic",
            ResourceLevel::Full => "full",
        }
    }

    /// Parse from a config / CLI string; unknown values fall back to `basic`.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "semantic" => ResourceLevel::Semantic,
            "full" => ResourceLevel::Full,
            _ => ResourceLevel::Basic,
        }
    }

    /// Whether Layer M runs at all (`semantic` or `full`).
    pub fn is_enabled(self) -> bool {
        !matches!(self, ResourceLevel::Basic)
    }

    /// Whether the heavier "full"-only domains (model/blockstate/loot/atlas) parse.
    pub fn includes_full_domains(self) -> bool {
        matches!(self, ResourceLevel::Full)
    }
}

impl From<intermed_doctor_core::ResourceAstLevel> for ResourceLevel {
    fn from(level: intermed_doctor_core::ResourceAstLevel) -> Self {
        use intermed_doctor_core::ResourceAstLevel as L;
        match level {
            L::Basic => ResourceLevel::Basic,
            L::Semantic => ResourceLevel::Semantic,
            L::Full => ResourceLevel::Full,
        }
    }
}

// The Minecraft data/asset domain of a resource — *what kind of file* this is —
// is the canonical [`intermed_resource_identity::ResourceDomain`]. Re-exported so
// existing `crate::model::ResourceDomain` references (and serde shapes) are
// unchanged, while classification has a single source of truth.
pub use intermed_resource_identity::ResourceDomain;

/// Which domains parse at a given Layer-M level. This lives in Layer M (not the
/// identity crate) because [`ResourceLevel`] is an analysis-depth concept, not a
/// property of the resource itself. `Semantic` covers the MVP domains; `Full`
/// adds the reference-heavy asset domains.
pub trait DomainParseExt {
    fn parsed_at(self, level: ResourceLevel) -> bool;
}

impl DomainParseExt for ResourceDomain {
    fn parsed_at(self, level: ResourceLevel) -> bool {
        match self {
            ResourceDomain::Tag
            | ResourceDomain::Recipe
            | ResourceDomain::Lang
            | ResourceDomain::PackMcmeta => level.is_enabled(),
            ResourceDomain::Model
            | ResourceDomain::Blockstate
            | ResourceDomain::LootTable
            | ResourceDomain::Atlas
            | ResourceDomain::Advancement
            | ResourceDomain::Predicate
            | ResourceDomain::ItemModifier => level.includes_full_domains(),
            // Structure (`.nbt` binary / `.snbt` stringified-NBT) is *not* JSON and
            // has no parser — it is classified for namespace ownership but never
            // parsed (parsing it produced false "invalid JSON" diagnostics).
            ResourceDomain::Structure => false,
            // Generic JSON is parsed at `full` only — it stores a canonical-JSON
            // fingerprint so the generic-registry-object override (unmodelled
            // datapack registries: damage types, trim materials, …) can compare
            // writers. Heavier, hence gated to the opt-in full level.
            ResourceDomain::GenericJson => level.includes_full_domains(),
            // Binary / properties / mcfunction are classified but carry no domain
            // summary; they still contribute namespace ownership.
            _ => false,
        }
    }
}

/// A specific load condition gating a resource or reference (Forge/Fabric/NeoForge).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum ResourceCondition {
    /// E.g. `forge:mod_loaded` or `fabric:all_mods_loaded`
    ModLoaded { modid: String },
    /// E.g. `forge:not`
    Not { condition: Box<ResourceCondition> },
    /// E.g. `forge:and`
    And { conditions: Vec<ResourceCondition> },
    /// E.g. `forge:or`
    Or { conditions: Vec<ResourceCondition> },
    /// E.g. `forge:tag_empty`
    TagEmpty { tag: String },
    /// E.g. `forge:false`
    False,
    /// Any other condition we don't deeply model
    Other { condition_type: String },
}

/// How fully Layer M understands a resource's *meaning* (as opposed to whether it
/// parsed as JSON). A vanilla recipe is fully understood; a custom serializer's
/// payload may be opaque, so diffs over it must not claim a precise semantic change
/// they cannot actually see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticOpacity {
    /// Fully interpreted (vanilla schema).
    #[default]
    Transparent,
    /// A modded schema we partially understand (extracted some structure).
    PartiallyKnown,
    /// A custom serializer whose payload we cannot interpret — compare by content
    /// hash only, and never claim a precise semantic diff (output/ingredient).
    OpaqueCustomSerializer,
}

impl SemanticOpacity {
    pub fn as_str(self) -> &'static str {
        match self {
            SemanticOpacity::Transparent => "transparent",
            SemanticOpacity::PartiallyKnown => "partially-known",
            SemanticOpacity::OpaqueCustomSerializer => "opaque-custom-serializer",
        }
    }
    /// Whether the extracted semantic fields (outputs/ingredients) are reliable.
    pub fn is_reliable(self) -> bool {
        !matches!(self, SemanticOpacity::OpaqueCustomSerializer)
    }
}

/// Outcome of attempting to parse a resource into its typed AST.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParseStatus {
    /// Fully parsed into a typed domain AST.
    Parsed,
    /// Parsed as syntax but some domain fields were unrecognised.
    PartiallyParsed,
    /// Could not be parsed (malformed syntax for its domain).
    Invalid,
    /// Recognised but not parsed at the active level (or binary).
    Skipped,
}

impl ParseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ParseStatus::Parsed => "parsed",
            ParseStatus::PartiallyParsed => "partially-parsed",
            ParseStatus::Invalid => "invalid",
            ParseStatus::Skipped => "skipped",
        }
    }
}

/// The relation a [`ResourceReference`] edge expresses (recipe→item, model→parent…).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefRelation {
    UsesItem,
    UsesTag,
    UsesRecipeType,
    ProducesItem,
    ParentModel,
    UsesModel,
    UsesTexture,
    LootEntry,
    AtlasSource,
    AdvancementCriterion,
    /// A reference extracted from an unmodelled datapack registry object by a
    /// data-driven JSON-pointer spec (damage type → sound, trim material → asset…).
    RegistryRef,
}

impl RefRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            RefRelation::UsesItem => "uses_item",
            RefRelation::UsesTag => "uses_tag",
            RefRelation::UsesRecipeType => "uses_recipe_type",
            RefRelation::ProducesItem => "produces_item",
            RefRelation::ParentModel => "parent_model",
            RefRelation::UsesModel => "uses_model",
            RefRelation::UsesTexture => "uses_texture",
            RefRelation::RegistryRef => "registry_ref",
            RefRelation::LootEntry => "loot_entry",
            RefRelation::AtlasSource => "atlas_source",
            RefRelation::AdvancementCriterion => "advancement_criterion",
        }
    }

    /// Whether a *cross-namespace* reference of this kind is evidence of a
    /// load-time dependency on another mod.
    ///
    /// Client-asset references — model parents, model/texture uses, atlas sources —
    /// are excluded: those targets are frequently runtime-generated, baked, or
    /// supplied by a resource pack, so a target in an uninstalled namespace is not
    /// proof of a missing mod (the same FP class the model-file resolver already
    /// refuses to raise findings from). Data references (recipe type/items, loot,
    /// tags, advancements, datapack registry refs) do imply a dependency.
    #[must_use]
    pub fn implies_dependency(self) -> bool {
        !matches!(
            self,
            RefRelation::ParentModel
                | RefRelation::UsesModel
                | RefRelation::UsesTexture
                | RefRelation::AtlasSource
        )
    }
}

/// One outgoing reference from a resource to a referenced id (item, tag, model…).
/// The semantic edge that builds the resource reference graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceReference {
    pub relation: RefRelation,
    /// The referenced id (e.g. `create:crushing`, `#minecraft:logs`, `minecraft:stone`).
    pub target: String,
    /// The namespace component of `target` (`create`, `minecraft`, …).
    pub namespace: String,
    /// Whether absence of the target would break the resource (vs. optional).
    pub required: bool,
    /// Whether this reference is gated behind load conditions (forge/fabric
    /// `conditions`), so a missing target may be intentional.
    pub conditions: Vec<ResourceCondition>,
    /// Whether `target` is a tag reference (`#namespace:path`).
    pub is_tag: bool,
}

impl ResourceReference {
    /// Returns true if this reference is gated by any load conditions.
    pub fn is_conditioned(&self) -> bool {
        !self.conditions.is_empty()
    }
}

/// Severity of a parse-time diagnostic on a single resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

impl DiagnosticSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticSeverity::Info => "info",
            DiagnosticSeverity::Warning => "warning",
            DiagnosticSeverity::Error => "error",
        }
    }
}

/// A diagnostic produced while parsing one resource (malformed field, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceParseDiagnostic {
    pub severity: DiagnosticSeverity,
    pub message: String,
}

/// Compact, serialisable AST summary for one resource — the cache payload and the
/// source of all Layer-M facts. The full syntax tree is never stored here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedResourceAst {
    pub schema: String,
    pub parser_version: String,
    pub resource_path: String,
    pub domain: ResourceDomain,
    pub parse_status: ParseStatus,
    /// Order-independent content hash of the *semantic* summary, so two writers
    /// that differ only in key order hash identically (used for safe-merge / diff).
    pub semantic_hash: String,
    pub summary: ResourceSummary,
    pub references: Vec<ResourceReference>,
    pub diagnostics: Vec<ResourceParseDiagnostic>,
}

/// Domain-specific compact summary. Only the modelled domains carry a typed
/// summary; everything else is [`ResourceSummary::Generic`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ResourceSummary {
    Tag(crate::domain::tag::TagSummary),
    Recipe(crate::domain::recipe::RecipeSummary),
    Lang(crate::domain::lang::LangSummary),
    PackMcmeta(crate::domain::pack_mcmeta::PackMcmetaSummary),
    Model(crate::domain::model::ModelSummary),
    Blockstate(crate::domain::blockstate::BlockstateSummary),
    LootTable(crate::domain::loot_table::LootTableSummary),
    Atlas(crate::domain::atlas::AtlasSummary),
    Advancement(crate::domain::advancement::AdvancementSummary),
    Predicate(crate::domain::predicate::PredicateSummary),
    ItemModifier(crate::domain::item_modifier::ItemModifierSummary),
    /// Generic JSON: a content fingerprint (SHA-256 of canonical JSON) for the
    /// generic-registry override diff. A *struct* variant, not a newtype — an
    /// internally-tagged enum (`tag = "kind"`) cannot serialize a newtype holding
    /// a primitive, which silently broke hashing when generic JSON was parsed.
    GenericJson {
        fingerprint: String,
    },
    /// No typed summary (binary/skipped).
    Generic,
}

#[cfg(test)]
mod relation_tests {
    use super::RefRelation;

    #[test]
    fn client_asset_refs_do_not_imply_dependency() {
        for r in [
            RefRelation::ParentModel,
            RefRelation::UsesModel,
            RefRelation::UsesTexture,
            RefRelation::AtlasSource,
        ] {
            assert!(!r.implies_dependency(), "{r:?} must not imply a dependency");
        }
    }

    #[test]
    fn data_refs_imply_dependency() {
        for r in [
            RefRelation::UsesRecipeType,
            RefRelation::UsesItem,
            RefRelation::UsesTag,
            RefRelation::LootEntry,
            RefRelation::AdvancementCriterion,
            RefRelation::RegistryRef,
        ] {
            assert!(r.implies_dependency(), "{r:?} must imply a dependency");
        }
    }
}
