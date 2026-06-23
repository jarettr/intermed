//! Unified confidence & severity model (plan Phase 14).
//!
//! Different layers used to sound equally certain regardless of how strong their
//! evidence was. [`ConfirmationLevel`] is the single ladder describing *how* a claim
//! is backed — from a runtime log all the way down to a mod-level heuristic — and
//! [`recommended_severity`] turns that, plus impact and coverage, into a severity
//! that never over-states the evidence (a missing method under full classpath is an
//! `Error`; the same claim on an unresolved mapping is at most a `Warn`).

use serde::{Deserialize, Serialize};

use intermed_doctor_core::evidence::Severity;

/// How a claim is backed, strongest first (plan Phase 14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ConfirmationLevel {
    /// A runtime log confirmed the same mixin/site failed.
    RuntimeConfirmed,
    /// Proven against exact bytecode (target present, selector/locals checked).
    StaticExact,
    /// Backed by descriptor-aware resolution (overload/signature reasoning).
    StaticDescriptorAware,
    /// Backed only by name-level resolution (descriptor unknown).
    StaticNameOnly,
    /// Site-level heuristic (no bytecode confirmation).
    HeuristicSite,
    /// Class-level heuristic.
    HeuristicClass,
    /// Mod-level heuristic (the coarsest signal).
    HeuristicMod,
    /// Nothing was actually checked.
    #[default]
    Unchecked,
}

impl ConfirmationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfirmationLevel::RuntimeConfirmed => "runtime-confirmed",
            ConfirmationLevel::StaticExact => "static-exact",
            ConfirmationLevel::StaticDescriptorAware => "static-descriptor-aware",
            ConfirmationLevel::StaticNameOnly => "static-name-only",
            ConfirmationLevel::HeuristicSite => "heuristic-site",
            ConfirmationLevel::HeuristicClass => "heuristic-class",
            ConfirmationLevel::HeuristicMod => "heuristic-mod",
            ConfirmationLevel::Unchecked => "unchecked",
        }
    }

    /// `true` when the claim is backed by exact bytecode or a runtime log — the only
    /// levels strong enough to justify an `Error` for an apply failure.
    pub fn is_exact_or_confirmed(self) -> bool {
        matches!(
            self,
            ConfirmationLevel::RuntimeConfirmed | ConfirmationLevel::StaticExact
        )
    }
}

/// Inputs to the severity decision (plan Phase 14): all the axes that should move it.
pub struct SeverityInputs {
    pub confirmation: ConfirmationLevel,
    /// The claim is about a *failure* (vs. a mere risk/observation).
    pub is_failure: bool,
    /// The classpath was complete enough for an absence to be conclusive.
    pub coverage_conclusive: bool,
    /// How destructive the underlying semantics are, 0–100.
    pub impact: u8,
    /// How clear the fix is, 0–100 (reported, mildly nudges severity).
    pub actionability: u8,
}

/// Recommend a [`Severity`] from the unified evidence model (plan Phase 14).
///
/// The rule of thumb: a *failure* backed by exact/runtime evidence under conclusive
/// coverage is an `Error`; weaker confirmation or partial coverage caps it at `Warn`
/// or `Note`; a non-failure is graded by impact alone.
pub fn recommended_severity(inputs: &SeverityInputs) -> Severity {
    if inputs.is_failure {
        return match inputs.confirmation {
            ConfirmationLevel::RuntimeConfirmed => Severity::Error,
            ConfirmationLevel::StaticExact => {
                if inputs.coverage_conclusive {
                    Severity::Error
                } else {
                    // Exact reasoning but we may have missed a library-provided class.
                    Severity::Warn
                }
            }
            ConfirmationLevel::StaticDescriptorAware => Severity::Warn,
            ConfirmationLevel::StaticNameOnly => Severity::Warn,
            ConfirmationLevel::HeuristicSite | ConfirmationLevel::HeuristicClass => Severity::Note,
            ConfirmationLevel::HeuristicMod | ConfirmationLevel::Unchecked => Severity::Info,
        };
    }
    // Not a failure: grade by impact, never above Warn.
    match inputs.impact {
        80..=100 => Severity::Warn,
        40..=79 => Severity::Note,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(confirmation: ConfirmationLevel, coverage: bool) -> SeverityInputs {
        SeverityInputs {
            confirmation,
            is_failure: true,
            coverage_conclusive: coverage,
            impact: 50,
            actionability: 80,
        }
    }

    #[test]
    fn exact_failure_under_full_coverage_is_error() {
        assert_eq!(
            recommended_severity(&inputs(ConfirmationLevel::StaticExact, true)),
            Severity::Error
        );
    }

    #[test]
    fn exact_failure_under_partial_coverage_is_only_warn() {
        assert_eq!(
            recommended_severity(&inputs(ConfirmationLevel::StaticExact, false)),
            Severity::Warn
        );
    }

    #[test]
    fn name_only_failure_is_warn_not_error() {
        assert_eq!(
            recommended_severity(&inputs(ConfirmationLevel::StaticNameOnly, true)),
            Severity::Warn
        );
    }

    #[test]
    fn runtime_confirmed_is_always_error() {
        assert_eq!(
            recommended_severity(&inputs(ConfirmationLevel::RuntimeConfirmed, false)),
            Severity::Error
        );
    }

    #[test]
    fn non_failure_graded_by_impact() {
        let mut i = inputs(ConfirmationLevel::HeuristicMod, true);
        i.is_failure = false;
        i.impact = 90;
        assert_eq!(recommended_severity(&i), Severity::Warn);
        i.impact = 10;
        assert_eq!(recommended_severity(&i), Severity::Info);
    }
}
