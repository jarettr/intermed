//! Namespace extraction and ownership.
//!
//! These are canonical helpers from `intermed-resource-identity`, re-exported
//! under the historical `crate::semantic::namespace::*` paths so Layer E and
//! Layer M share one definition of "what namespace owns this path" and which
//! namespaces are platform-provided rather than installable mods.

pub use intermed_resource_identity::{is_platform_namespace, namespace_of, path_namespace};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegates_to_identity_crate() {
        assert_eq!(namespace_of("create:crushing"), "create");
        assert_eq!(
            path_namespace("data/create/recipes/x.json").as_deref(),
            Some("create")
        );
        assert!(is_platform_namespace("minecraft"));
        assert!(!is_platform_namespace("create"));
    }
}
