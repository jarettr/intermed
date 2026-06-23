//! Injection selector verification (plan Phase 6).
//!
//! A target method existing is not enough: many real Mixin failures are an `@At`
//! that no longer *matches an instruction* — an `INVOKE` whose call site was
//! removed, an `ordinal` past the last match, an empty slice. [`SelectorVerification`]
//! records whether the `@At` actually finds its instruction(s) in the target body,
//! to the extent the indexed bytecode allows.
//!
//! `HEAD`/`RETURN`/`TAIL` match by construction on any existing method; `INVOKE`
//! and `FIELD` selectors are verified against the per-method call-site histogram the
//! [`crate::apply_failure::TargetClassIndex`] records; richer selectors
//! (`CONSTANT`, `NEW`, `JUMP`, locals) are reported `Unsupported` rather than guessed.

use serde::{Deserialize, Serialize};

/// Outcome of verifying a site's `@At` selector against the target method body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SelectorVerification {
    /// The selector matched at least one instruction in the target body.
    Matched,
    /// `HEAD`/`RETURN`/`TAIL` — always present on an existing method.
    MatchesByConstruction,
    /// The selector found zero matching instructions — the injector won't apply.
    NoMatch,
    /// `@At(ordinal = N)` exceeds the number of matching instructions.
    OrdinalOutOfRange,
    /// The target method itself is absent (nothing to match against).
    TargetMethodMissing,
    /// A selector kind we do not verify (`CONSTANT`, `NEW`, `JUMP`, locals, …).
    Unsupported,
    /// Not checked — bytecode/coverage for the target method was unavailable.
    #[default]
    Unchecked,
}

impl SelectorVerification {
    pub fn as_str(self) -> &'static str {
        match self {
            SelectorVerification::Matched => "matched",
            SelectorVerification::MatchesByConstruction => "matches-by-construction",
            SelectorVerification::NoMatch => "no-match",
            SelectorVerification::OrdinalOutOfRange => "ordinal-out-of-range",
            SelectorVerification::TargetMethodMissing => "target-method-missing",
            SelectorVerification::Unsupported => "unsupported",
            SelectorVerification::Unchecked => "unchecked",
        }
    }

    /// `true` when the selector is conclusively shown not to apply.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            SelectorVerification::NoMatch
                | SelectorVerification::OrdinalOutOfRange
                | SelectorVerification::TargetMethodMissing
        )
    }

    /// `true` when the selector is positively shown to match.
    pub fn is_matched(self) -> bool {
        matches!(
            self,
            SelectorVerification::Matched | SelectorVerification::MatchesByConstruction
        )
    }
}

/// Classify an `@At` target keyword into how it should be verified.
pub enum SelectorKind {
    /// Matches the method boundary — always present (`HEAD`/`RETURN`/`TAIL`).
    Boundary,
    /// Matches an invoke/field instruction by member name (`INVOKE`/`FIELD`).
    MemberRef,
    /// A selector kind we do not statically verify.
    Other,
}

/// Map an `@At` target keyword to its [`SelectorKind`].
pub fn classify_selector(at_target: &str) -> SelectorKind {
    match at_target.trim().to_ascii_uppercase().as_str() {
        "HEAD" | "RETURN" | "TAIL" => SelectorKind::Boundary,
        "INVOKE" | "INVOKE_ASSIGN" | "INVOKE_STRING" | "FIELD" => SelectorKind::MemberRef,
        _ => SelectorKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_selectors_recognized() {
        assert!(matches!(classify_selector("HEAD"), SelectorKind::Boundary));
        assert!(matches!(
            classify_selector("return"),
            SelectorKind::Boundary
        ));
        assert!(matches!(
            classify_selector("INVOKE"),
            SelectorKind::MemberRef
        ));
        assert!(matches!(classify_selector("CONSTANT"), SelectorKind::Other));
    }

    #[test]
    fn failure_and_match_predicates() {
        assert!(SelectorVerification::NoMatch.is_failure());
        assert!(SelectorVerification::OrdinalOutOfRange.is_failure());
        assert!(!SelectorVerification::Unsupported.is_failure());
        assert!(SelectorVerification::Matched.is_matched());
        assert!(SelectorVerification::MatchesByConstruction.is_matched());
        assert!(!SelectorVerification::Unchecked.is_matched());
    }
}
