//! Unified name resolution (plan Phase 3).
//!
//! Different layers used to compare names in whatever form they happened to be in
//! — named, intermediary, refmap, raw bytecode — which risks false "method not
//! found" results and missed conflicts. [`ResolvedName`] is the single shape every
//! resolved class/method/field reference is normalized to before comparison: it
//! records the *original* token, the *canonical* (cross-mod-stable) form, the
//! namespace of each, where the mapping came from, and a confidence with an
//! auditable reason when resolution is partial.

use serde::{Deserialize, Serialize};

use crate::refmap::{Namespace, is_intermediary_name};

/// Where a name's canonical form came from — the provenance of the mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NameSource {
    /// Resolved through the config's `.refmap.json` (obf↔intermediary↔named).
    Refmap,
    /// Resolved through the jar's bundled Tiny mappings.
    TinyMappings,
    /// Already an intermediary token (`method_NNNN`) — cross-mod-stable as-is.
    IntermediaryDirect,
    /// A bare named/yarn token with no bridge to intermediary in this jar — usable
    /// for display but *not* reliably comparable across mods.
    NamedUnbridged,
    /// Could not be resolved to any canonical form.
    Unresolved,
}

impl NameSource {
    pub fn as_str(self) -> &'static str {
        match self {
            NameSource::Refmap => "refmap",
            NameSource::TinyMappings => "tiny-mappings",
            NameSource::IntermediaryDirect => "intermediary-direct",
            NameSource::NamedUnbridged => "named-unbridged",
            NameSource::Unresolved => "unresolved",
        }
    }

    /// `true` when the canonical form is cross-mod-stable (safe to compare across
    /// mods). Named-unbridged and unresolved names are *not*.
    pub fn is_cross_mod_stable(self) -> bool {
        matches!(
            self,
            NameSource::Refmap | NameSource::TinyMappings | NameSource::IntermediaryDirect
        )
    }
}

/// One class/method/field reference normalized to the project-wide canonical form,
/// carrying its full resolution provenance (plan Phase 3 / Phase 15).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedName {
    /// The token exactly as it appeared at the source (annotation / bytecode).
    pub original: String,
    /// The canonical, preferably cross-mod-stable form used for comparison.
    pub canonical: String,
    /// Namespace `original` is expressed in.
    pub namespace_original: Namespace,
    /// Namespace `canonical` is expressed in (intermediary when fully resolved).
    pub namespace_canonical: Namespace,
    /// Where the mapping to `canonical` came from.
    pub source: NameSource,
    /// 0–100 confidence the canonical form is correct *and comparable*.
    pub confidence: u8,
    /// Why confidence is below 100 (empty when fully resolved).
    pub reason: String,
}

impl ResolvedName {
    /// Classify the namespace of a raw token by shape: an intermediary token is
    /// recognizable syntactically; an empty token is unknown; anything else is a
    /// named/yarn form.
    fn classify(token: &str) -> Namespace {
        if token.is_empty() {
            Namespace::Unknown
        } else if is_intermediary_name(strip_descriptor(token)) {
            Namespace::Intermediary
        } else {
            Namespace::Named
        }
    }

    /// Build a [`ResolvedName`] from the resolution facts an injection point already
    /// carries: the `original` token, the `canonical` comparison key, the resolved
    /// namespace, and whether a refmap performed the resolution.
    pub fn resolve(
        original: &str,
        canonical: &str,
        namespace_canonical: Namespace,
        resolved_via_refmap: bool,
    ) -> Self {
        let namespace_original = Self::classify(original);
        let canonical = if canonical.is_empty() {
            original.to_string()
        } else {
            canonical.to_string()
        };

        // Determine provenance and confidence from the evidence.
        let (source, confidence, reason) = if resolved_via_refmap {
            (NameSource::Refmap, 100, String::new())
        } else if namespace_canonical == Namespace::Intermediary {
            // Either already intermediary, or bridged to it via Tiny mappings.
            if namespace_original == Namespace::Intermediary {
                (NameSource::IntermediaryDirect, 100, String::new())
            } else {
                (NameSource::TinyMappings, 95, String::new())
            }
        } else if namespace_canonical == Namespace::Named {
            (
                NameSource::NamedUnbridged,
                65,
                "named token with no bridge to intermediary — not cross-mod-stable".to_string(),
            )
        } else {
            (
                NameSource::Unresolved,
                45,
                "no mapping/refmap context to resolve this reference".to_string(),
            )
        };

        ResolvedName {
            original: original.to_string(),
            canonical,
            namespace_original,
            namespace_canonical,
            source,
            confidence,
            reason,
        }
    }

    /// Two resolved names refer to the same member with confidence only when both
    /// are cross-mod-stable and their canonical forms match. Returns `None` when the
    /// comparison cannot be made reliably (a namespace mismatch that must not be
    /// silently treated as "different").
    pub fn same_member(&self, other: &ResolvedName) -> Option<bool> {
        if self.source.is_cross_mod_stable() && other.source.is_cross_mod_stable() {
            Some(self.canonical == other.canonical)
        } else if self.namespace_canonical == other.namespace_canonical {
            // Same (possibly weak) namespace — comparable, but lower trust.
            Some(self.canonical == other.canonical)
        } else {
            None
        }
    }
}

/// Drop a trailing JVM descriptor (`name(…)…` / `name:…`) to get the bare member
/// name for namespace classification.
fn strip_descriptor(token: &str) -> &str {
    if let Some(idx) = token.find('(') {
        &token[..idx]
    } else if let Some(idx) = token.find(':') {
        &token[..idx]
    } else {
        token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refmap_resolution_is_full_confidence() {
        let n = ResolvedName::resolve("tick", "method_3748()V", Namespace::Intermediary, true);
        assert_eq!(n.source, NameSource::Refmap);
        assert_eq!(n.confidence, 100);
        assert!(n.source.is_cross_mod_stable());
    }

    #[test]
    fn direct_intermediary_needs_no_mapping() {
        let n = ResolvedName::resolve(
            "method_3748()V",
            "method_3748()V",
            Namespace::Intermediary,
            false,
        );
        assert_eq!(n.source, NameSource::IntermediaryDirect);
        assert_eq!(n.namespace_original, Namespace::Intermediary);
        assert_eq!(n.confidence, 100);
    }

    #[test]
    fn named_unbridged_is_not_cross_mod_stable() {
        let n = ResolvedName::resolve("tick", "tick", Namespace::Named, false);
        assert_eq!(n.source, NameSource::NamedUnbridged);
        assert!(!n.source.is_cross_mod_stable());
        assert!(n.confidence < 100);
        assert!(!n.reason.is_empty());
    }

    #[test]
    fn cross_namespace_comparison_is_inconclusive_not_false() {
        let intermediary =
            ResolvedName::resolve("method_3748", "method_3748", Namespace::Intermediary, false);
        let named = ResolvedName::resolve("tick", "tick", Namespace::Named, false);
        // One side unbridged-named, other intermediary: cannot conclude they differ.
        assert_eq!(intermediary.same_member(&named), None);
    }

    #[test]
    fn same_canonical_intermediary_matches() {
        let a = ResolvedName::resolve("a", "method_1()V", Namespace::Intermediary, true);
        let b = ResolvedName::resolve("b", "method_1()V", Namespace::Intermediary, true);
        assert_eq!(a.same_member(&b), Some(true));
    }
}
