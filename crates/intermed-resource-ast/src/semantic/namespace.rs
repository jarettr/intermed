//! Namespace extraction and ownership.
//!
//! A Minecraft resource id is `namespace:path` (defaulting to `minecraft` when no
//! colon is present). Resource and asset paths are `assets/<ns>/...` /
//! `data/<ns>/...`. The owner of a namespace is the mod(s) whose jar defines
//! resources under it — used to resolve implicit dependencies (a recipe that
//! references `create:*` implies the pack needs Create).

/// The namespace component of a resource id (`create:crushing` → `create`).
/// A bare path defaults to the vanilla `minecraft` namespace.
#[must_use]
pub fn namespace_of(id: &str) -> String {
    let id = id.trim_start_matches('#');
    match id.split_once(':') {
        Some((ns, _)) if !ns.is_empty() => ns.to_string(),
        _ => "minecraft".to_string(),
    }
}

/// The namespace a resource *path* lives in (`assets/<ns>/...` / `data/<ns>/...`).
#[must_use]
pub fn path_namespace(path: &str) -> Option<String> {
    let mut parts = path.split('/');
    match parts.next() {
        Some("assets" | "data") => parts.next().map(str::to_string).filter(|s| !s.is_empty()),
        _ => None,
    }
}

/// Namespaces that are part of the platform, never a mod a user must install.
const PLATFORM_NAMESPACES: &[&str] = &["minecraft", "c", "forge", "neoforge", "fabric", "common"];

/// Whether a namespace names the platform/convention rather than an installable mod.
#[must_use]
pub fn is_platform_namespace(ns: &str) -> bool {
    PLATFORM_NAMESPACES.contains(&ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_extraction() {
        assert_eq!(namespace_of("create:crushing"), "create");
        assert_eq!(namespace_of("#minecraft:logs"), "minecraft");
        assert_eq!(namespace_of("stone"), "minecraft");
    }

    #[test]
    fn path_namespace_extraction() {
        assert_eq!(path_namespace("data/create/recipes/x.json").as_deref(), Some("create"));
        assert_eq!(path_namespace("assets/sodium/lang/en_us.json").as_deref(), Some("sodium"));
        assert_eq!(path_namespace("pack.mcmeta"), None);
    }

    #[test]
    fn platform_namespaces_recognised() {
        assert!(is_platform_namespace("minecraft"));
        assert!(is_platform_namespace("c"));
        assert!(!is_platform_namespace("create"));
    }
}
