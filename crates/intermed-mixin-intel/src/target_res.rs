//! Descriptor-aware target resolution status (plan Phase 5).
//!
//! Name-only "method exists" checks are not enough: Minecraft and mod bytecode are
//! full of overloads, so a handler can bind the *wrong* method — or fail to bind —
//! even when a method of that name exists. [`TargetResolution`] records the precise
//! outcome of matching a site's target member against the indexed class, so a
//! "method not found" can be told apart from a descriptor/overload/mapping problem.

use serde::{Deserialize, Serialize};

/// Outcome of resolving a site's target method/field against the class index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TargetResolution {
    /// Name *and* descriptor matched a member on the target class.
    ExactMatch,
    /// The name matched but no descriptor was available to verify the overload.
    NameOnlyMatch,
    /// The name exists but no member has the requested descriptor (and there is a
    /// single same-named member — a genuine signature/mapping mismatch).
    DescriptorMismatch,
    /// The name exists with several overloads, none matching the requested
    /// descriptor — which exact overload binds is ambiguous.
    AmbiguousOverload,
    /// The member resolves on a different owner (super/interface) than declared.
    OwnerMismatch,
    /// The class is indexed but has no member of that name.
    MissingMethod,
    /// The target class itself is absent under conclusive coverage.
    MissingClass,
    /// Not checked — the target class was not indexed (coverage gap), so absence
    /// proves nothing (plan Phase 4/15).
    #[default]
    Unchecked,
}

impl TargetResolution {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetResolution::ExactMatch => "exact-match",
            TargetResolution::NameOnlyMatch => "name-only-match",
            TargetResolution::DescriptorMismatch => "descriptor-mismatch",
            TargetResolution::AmbiguousOverload => "ambiguous-overload",
            TargetResolution::OwnerMismatch => "owner-mismatch",
            TargetResolution::MissingMethod => "missing-method",
            TargetResolution::MissingClass => "missing-class",
            TargetResolution::Unchecked => "unchecked",
        }
    }

    /// `true` when the resolution is positive evidence the site binds correctly.
    pub fn is_resolved(self) -> bool {
        matches!(
            self,
            TargetResolution::ExactMatch | TargetResolution::NameOnlyMatch
        )
    }

    /// `true` when the resolution is conclusive evidence the site will *not* bind.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            TargetResolution::MissingMethod
                | TargetResolution::MissingClass
                | TargetResolution::DescriptorMismatch
        )
    }
}

/// Split a resolved member reference (`tick()V`, `method_3748:Lfoo;`, or bare
/// `tick`) into `(name, Option<descriptor>)`.
pub fn split_member_ref(reference: &str) -> (&str, Option<&str>) {
    if let Some(idx) = reference.find('(') {
        (&reference[..idx], Some(&reference[idx..]))
    } else if let Some(idx) = reference.find(':') {
        (&reference[..idx], Some(&reference[idx + 1..]))
    } else {
        (reference, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_method_descriptor() {
        assert_eq!(split_member_ref("tick()V"), ("tick", Some("()V")));
        assert_eq!(split_member_ref("tick"), ("tick", None));
        assert_eq!(
            split_member_ref("field:Lnet/Foo;"),
            ("field", Some("Lnet/Foo;"))
        );
    }

    #[test]
    fn classification_predicates() {
        assert!(TargetResolution::ExactMatch.is_resolved());
        assert!(!TargetResolution::ExactMatch.is_failure());
        assert!(TargetResolution::MissingMethod.is_failure());
        assert!(TargetResolution::DescriptorMismatch.is_failure());
        assert!(!TargetResolution::Unchecked.is_failure());
        assert!(!TargetResolution::Unchecked.is_resolved());
    }
}
