//! Classify a resource path into its [`ResourceDomain`].
//!
//! Classification is canonical and lives in `intermed-resource-identity` so the
//! byte-level Layer-E VFS and the typed Layer-M AST never disagree about what a
//! path is. This module re-exports it under the historical
//! `crate::domain::classify::classify` path.

pub use intermed_resource_identity::classify;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ResourceDomain;

    #[test]
    fn delegates_to_identity_crate() {
        assert_eq!(classify("pack.mcmeta"), ResourceDomain::PackMcmeta);
        assert_eq!(classify("data/c/recipes/x.json"), ResourceDomain::Recipe);
        assert_eq!(classify("data/c/foo/x.json"), ResourceDomain::GenericJson);
    }
}
