//! The Minecraft data/asset domain of a resource — *what kind of file* this is —
//! plus the canonical, purely path-based classifier.
//!
//! This is the single source of truth for domain classification. Layer E (VFS)
//! and Layer M (resource AST) both go through [`classify`] so a path is never
//! parsed two different ways.

use serde::{Deserialize, Serialize};

/// The Minecraft data/asset domain of a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    Predicate,
    ItemModifier,
    Structure,
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
    /// Stable kebab-case identifier (matches the serde representation).
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
            ResourceDomain::Predicate => "predicate",
            ResourceDomain::ItemModifier => "item-modifier",
            ResourceDomain::Structure => "structure",
            ResourceDomain::GenericJson => "generic-json",
            ResourceDomain::Properties => "properties",
            ResourceDomain::McFunction => "mcfunction",
            ResourceDomain::BinaryAsset => "binary-asset",
        }
    }

    /// Whether this domain is a single-document file the runtime keeps exactly one
    /// of by load order (an *override* on collision), as opposed to a mergeable
    /// document (tags / lang). Used by Layer E to classify collisions.
    pub fn is_single_document(self) -> bool {
        !matches!(
            self,
            ResourceDomain::Tag | ResourceDomain::Lang | ResourceDomain::Properties
        )
    }
}

/// Classify a normalized (`/`-separated) resource path into its [`ResourceDomain`].
///
/// Purely path-based (no I/O).
#[must_use]
pub fn classify(path: &str) -> ResourceDomain {
    if path == "pack.mcmeta" || path.ends_with("/pack.mcmeta") {
        return ResourceDomain::PackMcmeta;
    }
    if path.ends_with(".mcfunction") {
        return ResourceDomain::McFunction;
    }
    if path.contains("/lang/") && (path.ends_with(".json") || path.ends_with(".lang")) {
        return ResourceDomain::Lang;
    }
    if path.ends_with(".lang") {
        return ResourceDomain::Properties;
    }
    if path.ends_with(".nbt") || path.ends_with(".snbt") {
        if path.starts_with("data/")
            && (path.contains("/structures/") || path.contains("/structure/"))
        {
            return ResourceDomain::Structure;
        }
        return ResourceDomain::BinaryAsset;
    }
    if !path.ends_with(".json") {
        return ResourceDomain::BinaryAsset;
    }
    // JSON domains, keyed on the **registry directory** — the path segment
    // directly after `data|assets/<namespace>/` — not on a substring anywhere in
    // the path. Substring matching mis-routed the vanilla recipe-unlock
    // advancements under `data/<ns>/advancements/recipes/…` to `Recipe` (because
    // the path contains `/recipes/` and the recipe check ran first), which then
    // read them as output-less recipes and reported them as "disabling" vanilla.
    // Keying on the segment also keeps this classifier consistent with the
    // canonical registry derived in `ResourceKey::from_path`.
    let registry = registry_dir(path);
    if path.starts_with("data/") {
        match registry {
            "tags" => return ResourceDomain::Tag,
            "recipe" | "recipes" => return ResourceDomain::Recipe,
            "loot_table" | "loot_tables" => return ResourceDomain::LootTable,
            "advancement" | "advancements" => return ResourceDomain::Advancement,
            "predicate" | "predicates" => return ResourceDomain::Predicate,
            "item_modifier" | "item_modifiers" => return ResourceDomain::ItemModifier,
            _ => {}
        }
    } else if path.starts_with("assets/") {
        match registry {
            "blockstate" | "blockstates" => return ResourceDomain::Blockstate,
            "model" | "models" => return ResourceDomain::Model,
            "atlas" | "atlases" => return ResourceDomain::Atlas,
            _ => {}
        }
    }
    ResourceDomain::GenericJson
}

/// The registry directory — the third path segment, i.e. the directory directly
/// after `data|assets/<namespace>/`. Returns `""` when the path is too shallow.
/// (`data/<ns>/advancements/recipes/x.json` → `"advancements"`.)
fn registry_dir(path: &str) -> &str {
    path.split('/').nth(2).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_core_domains() {
        assert_eq!(classify("pack.mcmeta"), ResourceDomain::PackMcmeta);
        assert_eq!(classify("data/c/tags/items/x.json"), ResourceDomain::Tag);
        assert_eq!(classify("data/c/recipes/x.json"), ResourceDomain::Recipe);
        assert_eq!(
            classify("data/c/loot_tables/x.json"),
            ResourceDomain::LootTable
        );
        assert_eq!(
            classify("data/c/advancements/x.json"),
            ResourceDomain::Advancement
        );
        assert_eq!(classify("assets/c/lang/en_us.json"), ResourceDomain::Lang);
        assert_eq!(classify("assets/c/lang/en_us.lang"), ResourceDomain::Lang);
        assert_eq!(
            classify("assets/c/models/item/x.json"),
            ResourceDomain::Model
        );
        assert_eq!(
            classify("assets/c/blockstates/x.json"),
            ResourceDomain::Blockstate
        );
        assert_eq!(
            classify("assets/c/atlases/blocks.json"),
            ResourceDomain::Atlas
        );
        assert_eq!(
            classify("assets/c/textures/x.png"),
            ResourceDomain::BinaryAsset
        );
        assert_eq!(classify("data/c/foo/x.json"), ResourceDomain::GenericJson);
    }

    #[test]
    fn recipe_unlock_advancements_are_advancements_not_recipes() {
        // The vanilla recipe-book unlock advancements live under
        // `advancements/recipes/…`; the registry directory is `advancements`, so
        // they must classify as Advancement even though the path contains
        // `/recipes/`. (Regression: these were mis-read as output-less recipes.)
        assert_eq!(
            classify("data/minecraft/advancements/recipes/redstone/dispenser.json"),
            ResourceDomain::Advancement
        );
        // 1.21 singular registry folders.
        assert_eq!(
            classify("data/minecraft/advancement/recipes/misc/orange_dye.json"),
            ResourceDomain::Advancement
        );
        assert_eq!(
            classify("data/minecraft/recipe/orange_dye.json"),
            ResourceDomain::Recipe
        );
        // Nested recipe sub-folders (Create-style) stay recipes.
        assert_eq!(
            classify("data/create/recipes/crushing/tuff.json"),
            ResourceDomain::Recipe
        );
        // A folder literally named `recipes` deeper in a non-registry tree must
        // not be mistaken for a recipe.
        assert_eq!(
            classify("data/mymod/custom/recipes/x.json"),
            ResourceDomain::GenericJson
        );
    }

    #[test]
    fn single_document_classification() {
        assert!(!ResourceDomain::Tag.is_single_document());
        assert!(!ResourceDomain::Lang.is_single_document());
        assert!(ResourceDomain::Recipe.is_single_document());
        assert!(ResourceDomain::Model.is_single_document());
    }
}
