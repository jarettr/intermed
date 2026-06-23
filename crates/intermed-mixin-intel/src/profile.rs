//! Precision profiles & selective escalation (plan Phases 18–19).
//!
//! Not every site deserves the heaviest checks. A [`PrecisionProfile`] sets the
//! baseline depth (a quick `Fast` scan vs. a `Forensic` deep dive), and
//! [`should_escalate`] re-raises *individual* sites that are worth a deeper look
//! even under a light profile — a hot, destructive, `require`d, or `CAPTURE_FAILHARD`
//! site is always verified, so depth is spent where it pays off.

use serde::{Deserialize, Serialize};

use crate::model::ResolvedInjectionPoint;
use crate::perf_match::is_destructive_operation;

/// Analysis depth mode (plan Phase 18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PrecisionProfile {
    /// Configs, annotations, basic targets, rough overlaps only.
    Fast,
    /// Activation, name resolution, descriptor-aware target checks, basic
    /// interaction analysis. The default.
    #[default]
    Standard,
    /// Adds selector verification, signature + local-capture checks, composition.
    Deep,
    /// Everything, plus detailed traces / runtime-log joins / debug output.
    Forensic,
}

impl PrecisionProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            PrecisionProfile::Fast => "fast",
            PrecisionProfile::Standard => "standard",
            PrecisionProfile::Deep => "deep",
            PrecisionProfile::Forensic => "forensic",
        }
    }

    /// Descriptor-aware target resolution runs from `Standard` up.
    pub fn resolves_targets(self) -> bool {
        self >= PrecisionProfile::Standard
    }
    /// Handler-signature checks (cheap, descriptor-only) run from `Standard` up.
    pub fn checks_signatures(self) -> bool {
        self >= PrecisionProfile::Standard
    }
    /// `@At` selector verification runs from `Deep` up.
    pub fn verifies_selectors(self) -> bool {
        self >= PrecisionProfile::Deep
    }
    /// Local-capture/frame verification runs from `Deep` up.
    pub fn checks_locals(self) -> bool {
        self >= PrecisionProfile::Deep
    }
}

/// Should this specific site be escalated to deep checks regardless of the baseline
/// profile (plan Phase 19)? Returns the criteria matched (empty ⇒ no escalation).
///
/// `hot` is whether the owning mixin class sits on a hot path.
pub fn escalation_reasons(inj: &ResolvedInjectionPoint, hot: bool) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if hot {
        reasons.push("hot-path");
    }
    if is_destructive_operation(&inj.injection_type) {
        reasons.push("destructive-operation");
    }
    if inj.meta.require.unwrap_or(0) >= 1 {
        reasons.push("require>=1");
    }
    if inj.local_capture.eq_ignore_ascii_case("CAPTURE_FAILHARD") {
        reasons.push("capture-failhard");
    }
    if inj.namespace == crate::refmap::Namespace::Unknown {
        reasons.push("unresolved-target");
    }
    reasons
}

/// The effective profile for one site: the baseline, raised to [`PrecisionProfile::Deep`]
/// when escalation criteria are met (plan Phase 19).
pub fn effective_profile(
    baseline: PrecisionProfile,
    inj: &ResolvedInjectionPoint,
    hot: bool,
) -> PrecisionProfile {
    if baseline < PrecisionProfile::Deep && !escalation_reasons(inj, hot).is_empty() {
        PrecisionProfile::Deep
    } else {
        baseline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InjectorMeta;
    use crate::refmap::Namespace;

    fn inj(op: &str, require: Option<i32>, capture: &str) -> ResolvedInjectionPoint {
        ResolvedInjectionPoint {
            target: "net.minecraft.Foo".into(),
            original: "m".into(),
            resolved: "m".into(),
            canonical: "m()V".into(),
            site_key: "m()V@HEAD".into(),
            namespace: Namespace::Intermediary,
            injection_type: op.into(),
            resolved_via_refmap: true,
            handler_method: "h".into(),
            handler_descriptor: String::new(),
            mutates_target_local: false,
            at_target: "HEAD".into(),
            at_detail: "HEAD".into(),
            impact: String::new(),
            local_index: None,
            local_capture: capture.into(),
            meta: InjectorMeta {
                require,
                ..Default::default()
            },
            at_ordinal: None,
            at_target_member: String::new(),
        }
    }

    #[test]
    fn profile_gates() {
        assert!(!PrecisionProfile::Fast.resolves_targets());
        assert!(PrecisionProfile::Standard.resolves_targets());
        assert!(!PrecisionProfile::Standard.verifies_selectors());
        assert!(PrecisionProfile::Deep.verifies_selectors());
        assert!(PrecisionProfile::Forensic.checks_locals());
    }

    #[test]
    fn destructive_site_escalates_under_standard() {
        let site = inj("redirect", None, "");
        assert!(!escalation_reasons(&site, false).is_empty());
        assert_eq!(
            effective_profile(PrecisionProfile::Standard, &site, false),
            PrecisionProfile::Deep
        );
    }

    #[test]
    fn benign_site_keeps_baseline() {
        let site = inj("inject", None, "");
        assert!(escalation_reasons(&site, false).is_empty());
        assert_eq!(
            effective_profile(PrecisionProfile::Standard, &site, false),
            PrecisionProfile::Standard
        );
    }

    #[test]
    fn require_and_failhard_escalate() {
        assert!(escalation_reasons(&inj("inject", Some(1), ""), false).contains(&"require>=1"));
        assert!(
            escalation_reasons(&inj("inject", None, "CAPTURE_FAILHARD"), false)
                .contains(&"capture-failhard")
        );
        assert!(escalation_reasons(&inj("inject", None, ""), true).contains(&"hot-path"));
    }
}
