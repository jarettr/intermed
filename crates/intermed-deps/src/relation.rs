//! Canonical dependency-relation semantics shared by every Layer-C surface.
//!
//! Facts retain their stable string representation at the wire boundary.  They
//! are parsed once into this type before any policy decision is made, avoiding
//! subtly different allow-lists in pairwise, PubGrub, explain and impact paths.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyRelation {
    Requires,
    Recommends,
    Suggests,
    Conflicts,
    Breaks,
    Discouraged,
    Includes,
    LoadBefore,
    LoadAfter,
    Unknown(String),
}

impl DependencyRelation {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "depends" | "requires" | "required" => Self::Requires,
            "recommends" | "recommended" | "softdepend" => Self::Recommends,
            "suggests" | "suggested" | "optional" => Self::Suggests,
            "conflicts" | "conflict" => Self::Conflicts,
            "breaks" | "incompatible" => Self::Breaks,
            "discouraged" => Self::Discouraged,
            "embedded" | "include" | "included" | "includes" => Self::Includes,
            "loadbefore" | "load_before" | "before" => Self::LoadBefore,
            "loadafter" | "load_after" | "after" => Self::LoadAfter,
            other => Self::Unknown(other.to_string()),
        }
    }

    #[must_use]
    pub const fn canonical_token(&self) -> &str {
        match self {
            Self::Requires => "depends",
            Self::Recommends => "recommends",
            Self::Suggests => "suggests",
            Self::Conflicts => "conflicts",
            Self::Breaks => "breaks",
            Self::Discouraged => "discouraged",
            Self::Includes => "includes",
            Self::LoadBefore => "loadbefore",
            Self::LoadAfter => "loadafter",
            Self::Unknown(value) => value.as_str(),
        }
    }

    #[must_use]
    pub const fn requires_presence(&self) -> bool {
        matches!(self, Self::Requires | Self::Includes)
    }

    #[must_use]
    pub const fn is_positive(&self) -> bool {
        matches!(
            self,
            Self::Requires | Self::Recommends | Self::Suggests | Self::Includes
        )
    }

    #[must_use]
    pub const fn is_negative(&self) -> bool {
        matches!(self, Self::Conflicts | Self::Breaks | Self::Discouraged)
    }

    #[must_use]
    pub const fn is_soft(&self) -> bool {
        matches!(
            self,
            Self::Recommends | Self::Suggests | Self::Conflicts | Self::Discouraged
        )
    }

    #[must_use]
    pub const fn contributes_to_solver(&self) -> bool {
        matches!(self, Self::Requires | Self::Includes)
    }

    #[must_use]
    pub const fn is_ordering(&self) -> bool {
        matches!(self, Self::LoadBefore | Self::LoadAfter)
    }

    /// Normalize both ordering spellings to a single `before -> after` edge.
    #[must_use]
    pub fn ordering_edge<'a>(&self, from: &'a str, to: &'a str) -> Option<(&'a str, &'a str)> {
        match self {
            Self::LoadBefore => Some((from, to)),
            Self::LoadAfter => Some((to, from)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_polarity_is_canonical() {
        assert!(DependencyRelation::parse("depends").requires_presence());
        assert!(!DependencyRelation::parse("breaks").requires_presence());
        assert!(DependencyRelation::parse("conflicts").is_negative());
        assert_eq!(
            DependencyRelation::parse("loadafter").ordering_edge("a", "b"),
            Some(("b", "a"))
        );
    }
}
