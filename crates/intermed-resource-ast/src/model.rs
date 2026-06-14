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

/// The Minecraft data/asset domain of a resource — *what kind of file* this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceDomain {
    Tag,
    Recipe,
    Lang,
    PackMcmeta,
    Model,
    Blockstate,
    LootTable,
    Atlas,
    Advancement,
    /// Valid JSON in a domain we don't model in detail.
    GenericJson,
    /// `.lang` properties / other `key=value` files.
    Properties,
    /// `.mcfunction` script.
    McFunction,
    /// Non-text / unmodelled asset (textures, sounds, …).
    BinaryAsset,
}

impl ResourceDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceDomain::Tag => "tag",
            ResourceDomain::Recipe => "recipe",
            ResourceDomain::Lang => "lang",
            ResourceDomain::PackMcmeta => "pack-mcmeta",
            ResourceDomain::Model => "model",
            ResourceDomain::Blockstate => "blockstate",
            ResourceDomain::LootTable => "loot-table",
            ResourceDomain::Atlas => "atlas",
            ResourceDomain::Advancement => "advancement",
            ResourceDomain::GenericJson => "generic-json",
            ResourceDomain::Properties => "properties",
            ResourceDomain::McFunction => "mcfunction",
            ResourceDomain::BinaryAsset => "binary-asset",
        }
    }

    /// Whether this domain is parsed at the given level. `Semantic` covers the
    /// MVP domains; `Full` adds the reference-heavy asset domains.
    pub fn parsed_at(self, level: ResourceLevel) -> bool {
        match self {
            ResourceDomain::Tag
            | ResourceDomain::Recipe
            | ResourceDomain::Lang
            | ResourceDomain::PackMcmeta => level.is_enabled(),
            ResourceDomain::Model
            | ResourceDomain::Blockstate
            | ResourceDomain::LootTable
            | ResourceDomain::Atlas
            | ResourceDomain::Advancement => level.includes_full_domains(),
            // Generic / binary / properties / mcfunction are classified but carry
            // no domain summary; they still contribute namespace ownership.
            _ => false,
        }
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
            RefRelation::LootEntry => "loot_entry",
            RefRelation::AtlasSource => "atlas_source",
            RefRelation::AdvancementCriterion => "advancement_criterion",
        }
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
    /// Whether this reference is gated behind a load condition (forge/fabric
    /// `conditions`), so a missing target may be intentional.
    pub conditioned: bool,
    /// Whether `target` is a tag reference (`#namespace:path`).
    pub is_tag: bool,
}

/// Severity of a parse-time diagnostic on a single resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
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
    /// No typed summary (generic/binary/skipped).
    Generic,
}
