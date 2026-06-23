//! The canonical [`ResourceKey`]: one parsed identity for a resource path that
//! every layer (VFS, resource AST, implicit deps, overlay, report) shares instead
//! of re-deriving namespace / object id / registry from the raw path each time.

use serde::{Deserialize, Serialize};

use crate::domain::{ResourceDomain, classify};
use crate::namespace::path_namespace;

/// A fully-qualified Minecraft resource id, `namespace:path`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceId {
    pub namespace: String,
    /// The id path, registry-relative and without file extension
    /// (`crushing/tuff`, `ingots/copper`, `blocks`).
    pub path: String,
}

impl ResourceId {
    pub fn new(namespace: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            path: path.into(),
        }
    }
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.path)
    }
}

/// Which logical side a resource applies to. Best-effort from the path root:
/// `assets/` is client-only, `data/` (data packs) is applied server-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Client,
    Server,
    Both,
}

/// The canonical parsed identity of one resource path.
///
/// Build it once with [`ResourceKey::from_path`]; downstream layers read the
/// fields rather than re-splitting the raw path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceKey {
    /// The original normalized (`/`-separated) path, verbatim.
    pub raw_path: String,
    pub domain: ResourceDomain,
    /// `assets`/`data` namespace, when the path is rooted there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// The Minecraft registry the object belongs to, derived from the directory
    /// after the namespace (`recipes` → `recipe`, `tags/items` → `items`,
    /// `atlases` → `atlas`). `None` for `pack.mcmeta` / unrooted paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// The fully-qualified object id, when one can be derived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<ResourceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<Side>,
}

impl ResourceKey {
    /// Parse a normalized (`/`-separated) resource path into its canonical key.
    #[must_use]
    pub fn from_path(path: &str) -> Self {
        let domain = classify(path);
        let namespace = path_namespace(path);
        let side = match path.split('/').next() {
            Some("assets") => Some(Side::Client),
            Some("data") => Some(Side::Server),
            _ => None,
        };
        let (registry, object_id) = derive_registry_and_id(path, domain, namespace.as_deref());
        ResourceKey {
            raw_path: path.to_string(),
            domain,
            namespace,
            registry,
            object_id,
            side,
        }
    }
}

/// Strip a single known resource extension from the final segment.
fn strip_ext(path: &str) -> &str {
    for ext in [".json", ".mcfunction", ".lang", ".nbt", ".snbt", ".mcmeta"] {
        if let Some(stripped) = path.strip_suffix(ext) {
            return stripped;
        }
    }
    path
}

/// Derive the `(registry, object_id)` pair from the directory layout.
///
/// `data/<ns>/<registry>/<object…>` and `assets/<ns>/<registry>/<object…>`, with
/// tags carrying a two-level registry (`tags/<tagged-registry>/<object…>`).
fn derive_registry_and_id(
    path: &str,
    domain: ResourceDomain,
    namespace: Option<&str>,
) -> (Option<String>, Option<ResourceId>) {
    let Some(ns) = namespace else {
        return (None, None);
    };
    let segments: Vec<&str> = path.split('/').collect();
    // segments[0] = assets|data, segments[1] = namespace, rest = registry + object.
    let rest = &segments[2..];
    if rest.is_empty() {
        return (None, None);
    }

    // Tags use `tags/<registry>/<object…>`: the registry the *tag* applies to is
    // the directory after `tags` (items / blocks / fluids / …).
    if domain == ResourceDomain::Tag {
        if let Some(tags_pos) = rest.iter().position(|s| *s == "tags") {
            let after = &rest[tags_pos + 1..];
            if after.len() >= 2 {
                let registry = after[0].to_string();
                let object = after[1..].join("/");
                let object = strip_ext(&object);
                return (Some(registry), Some(ResourceId::new(ns, object)));
            }
        }
        return (Some("tag".to_string()), None);
    }

    // Everything else: registry is the first directory, object is the remainder.
    let registry_dir = rest[0];
    let object = rest[1..].join("/");
    let object = strip_ext(&object);
    let registry = registry_to_singular(registry_dir).to_string();
    let object_id = if object.is_empty() {
        None
    } else {
        Some(ResourceId::new(ns, object))
    };
    (Some(registry), object_id)
}

/// Map a directory name to the registry it represents. Minecraft pluralises
/// registry directories (`recipes`, `loot_tables`); the registry id is singular.
fn registry_to_singular(dir: &str) -> &str {
    match dir {
        "recipes" | "recipe" => "recipe",
        "loot_tables" | "loot_table" => "loot_table",
        "advancements" | "advancement" => "advancement",
        "predicates" | "predicate" => "predicate",
        "item_modifiers" | "item_modifier" => "item_modifier",
        "structures" | "structure" => "structure",
        "atlases" | "atlas" => "atlas",
        "blockstates" | "blockstate" => "blockstate",
        "models" | "model" => "model",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipe_key() {
        let k = ResourceKey::from_path("data/create/recipes/crushing/tuff.json");
        assert_eq!(k.domain, ResourceDomain::Recipe);
        assert_eq!(k.namespace.as_deref(), Some("create"));
        assert_eq!(k.registry.as_deref(), Some("recipe"));
        assert_eq!(
            k.object_id,
            Some(ResourceId::new("create", "crushing/tuff"))
        );
        assert_eq!(k.object_id.unwrap().to_string(), "create:crushing/tuff");
        assert_eq!(k.side, Some(Side::Server));
    }

    #[test]
    fn tag_key_uses_tagged_registry() {
        let k = ResourceKey::from_path("data/c/tags/items/ingots/copper.json");
        assert_eq!(k.domain, ResourceDomain::Tag);
        assert_eq!(k.namespace.as_deref(), Some("c"));
        assert_eq!(k.registry.as_deref(), Some("items"));
        assert_eq!(k.object_id, Some(ResourceId::new("c", "ingots/copper")));
    }

    #[test]
    fn atlas_key() {
        let k = ResourceKey::from_path("assets/minecraft/atlases/blocks.json");
        assert_eq!(k.domain, ResourceDomain::Atlas);
        assert_eq!(k.namespace.as_deref(), Some("minecraft"));
        assert_eq!(k.registry.as_deref(), Some("atlas"));
        assert_eq!(k.object_id, Some(ResourceId::new("minecraft", "blocks")));
        assert_eq!(k.side, Some(Side::Client));
    }

    #[test]
    fn pack_mcmeta_has_no_object() {
        let k = ResourceKey::from_path("pack.mcmeta");
        assert_eq!(k.domain, ResourceDomain::PackMcmeta);
        assert_eq!(k.namespace, None);
        assert_eq!(k.object_id, None);
        assert_eq!(k.registry, None);
        assert_eq!(k.side, None);
    }

    #[test]
    fn nested_tag_block_registry() {
        let k = ResourceKey::from_path("data/minecraft/tags/blocks/mineable/pickaxe.json");
        assert_eq!(k.registry.as_deref(), Some("blocks"));
        assert_eq!(
            k.object_id,
            Some(ResourceId::new("minecraft", "mineable/pickaxe"))
        );
    }
}
