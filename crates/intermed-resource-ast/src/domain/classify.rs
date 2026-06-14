//! Classify a resource path into its [`ResourceDomain`].
//!
//! Purely path-based (no I/O); the same vocabulary the Layer-E VFS uses, lifted
//! to the richer Layer-M domain set.

use crate::model::ResourceDomain;

/// Classify a normalized (`/`-separated) resource path.
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
    if !path.ends_with(".json") {
        return ResourceDomain::BinaryAsset;
    }
    // JSON domains, by directory.
    if path.starts_with("data/") {
        if path.contains("/tags/") {
            return ResourceDomain::Tag;
        }
        if path.contains("/recipe/") || path.contains("/recipes/") {
            return ResourceDomain::Recipe;
        }
        if path.contains("/loot_table/") || path.contains("/loot_tables/") {
            return ResourceDomain::LootTable;
        }
        if path.contains("/advancement/") || path.contains("/advancements/") {
            return ResourceDomain::Advancement;
        }
    }
    if path.starts_with("assets/") {
        if path.contains("/blockstates/") {
            return ResourceDomain::Blockstate;
        }
        if path.contains("/models/") {
            return ResourceDomain::Model;
        }
        if path.contains("/atlases/") {
            return ResourceDomain::Atlas;
        }
    }
    ResourceDomain::GenericJson
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_core_domains() {
        assert_eq!(classify("pack.mcmeta"), ResourceDomain::PackMcmeta);
        assert_eq!(classify("data/c/tags/items/x.json"), ResourceDomain::Tag);
        assert_eq!(classify("data/c/recipes/x.json"), ResourceDomain::Recipe);
        assert_eq!(classify("data/c/loot_tables/x.json"), ResourceDomain::LootTable);
        assert_eq!(classify("assets/c/lang/en_us.json"), ResourceDomain::Lang);
        assert_eq!(classify("assets/c/lang/en_us.lang"), ResourceDomain::Lang);
        assert_eq!(classify("assets/c/models/item/x.json"), ResourceDomain::Model);
        assert_eq!(classify("assets/c/blockstates/x.json"), ResourceDomain::Blockstate);
        assert_eq!(classify("assets/c/atlases/blocks.json"), ResourceDomain::Atlas);
        assert_eq!(classify("assets/c/textures/x.png"), ResourceDomain::BinaryAsset);
        assert_eq!(classify("data/c/foo/x.json"), ResourceDomain::GenericJson);
    }
}
