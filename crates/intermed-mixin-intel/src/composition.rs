//! Application order + composition engine (plan Phases 9–10).
//!
//! Pairwise "two mixins touch the same site" is not enough: what matters is the
//! *order* they apply in and *how their roles compose*. Two `@Redirect`s on one call
//! are a near-certain conflict; two `@WrapOperation`s that each call the original
//! once are a legal chain; an unconditional cancel suppresses everything downstream.
//!
//! This module groups [`ApplicationSite`]s by their exact injection point, orders
//! the participants by effective priority (Phase 9), assigns each a [`HandlerRole`],
//! and classifies the group's interaction into a [`CompositionClass`] (Phase 10).

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

use crate::site::ApplicationSite;

/// The semantic role a handler plays at a site (plan Phase 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandlerRole {
    /// Reads/observes without changing behaviour (a plain `@Inject` with no cancel).
    Observer,
    /// Transforms a value passing through (`@ModifyArg(s)`/`@ModifyVariable`/
    /// `@ModifyReturnValue`/`@ModifyExpressionValue`/`@ModifyConstant`).
    Transformer,
    /// Wraps the original operation, delegating to it (`@WrapOperation`).
    Wrapper,
    /// Conditionally gates a call (`@WrapWithCondition`).
    Guard,
    /// Replaces an operation outright (`@Redirect`, `@Overwrite`).
    Replacement,
    /// Can suppress downstream behaviour entirely (a cancelling `@Inject`,
    /// `@WrapWithCondition` that drops the call).
    Suppressor,
    /// Runs the original more than once (duplicating side effects).
    Multiplier,
    Unknown,
}

impl HandlerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            HandlerRole::Observer => "observer",
            HandlerRole::Transformer => "transformer",
            HandlerRole::Wrapper => "wrapper",
            HandlerRole::Guard => "guard",
            HandlerRole::Replacement => "replacement",
            HandlerRole::Suppressor => "suppressor",
            HandlerRole::Multiplier => "multiplier",
            HandlerRole::Unknown => "unknown",
        }
    }
}

/// Infer a handler's role from its operation kind (the role data available on a
/// site). Cancel/`Operation.call`-count refinements are layered by effect analysis.
pub fn role_for_operation(operation: &str) -> HandlerRole {
    match operation {
        "inject" => HandlerRole::Observer,
        "redirect" | "overwrite" => HandlerRole::Replacement,
        "wrap-operation" => HandlerRole::Wrapper,
        "wrap-with-condition" => HandlerRole::Guard,
        "modify-arg"
        | "modify-args"
        | "modify-variable"
        | "modify-return-value"
        | "modify-expression-value"
        | "modify-constant"
        | "modify-receiver" => HandlerRole::Transformer,
        _ => HandlerRole::Unknown,
    }
}

/// How a group of co-located handlers compose (plan Phase 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompositionClass {
    /// A genuine conflict — at most one participant can win (two replacements).
    HighConflict,
    /// Behaviour depends on application order (wrappers, same-index transformers).
    OrderSensitiveChain,
    /// The participants compose safely (observers, disjoint transformers).
    SafeComposition,
    /// Risk only under a condition (a guard/suppressor may drop the others).
    ConditionalRisk,
    /// The participants can never co-apply (disjoint strict sides).
    ImpossibleIntersection,
    /// Order/interaction could not be determined.
    Unknown,
}

impl CompositionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            CompositionClass::HighConflict => "high-conflict",
            CompositionClass::OrderSensitiveChain => "order-sensitive-chain",
            CompositionClass::SafeComposition => "safe-composition",
            CompositionClass::ConditionalRisk => "conditional-risk",
            CompositionClass::ImpossibleIntersection => "impossible-intersection",
            CompositionClass::Unknown => "unknown",
        }
    }
}

/// One participant in a site composition group, in application order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionParticipant {
    pub site_id: String,
    pub mod_id: String,
    pub operation: String,
    pub role: HandlerRole,
    pub priority: i64,
    /// `true` when this is an `@Inject` with `cancellable = true`: the handler
    /// may call `CallbackInfo.cancel()` to suppress the rest of the target method,
    /// making its effective role `Suppressor` rather than `Observer`.
    pub cancellable: bool,
}

/// A set of handlers applied at one exact injection point, ordered and classified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteComposition {
    pub target_class: String,
    pub site_key: String,
    pub classification: CompositionClass,
    /// `true` when more than one distinct mod participates (a real cross-mod case).
    pub cross_mod: bool,
    /// Participants in effective-priority order (higher priority first).
    pub participants: Vec<CompositionParticipant>,
    pub detail: String,
}

/// Key identifying one exact injection point across mods.
fn group_key(site: &ApplicationSite) -> (String, String) {
    let point = if site.site_key.is_empty() {
        format!("{}@{}", site.target_method, site.at_target)
    } else {
        site.site_key.clone()
    };
    (site.target_class.clone(), point)
}

/// Classify a group of co-located participants (already side-compatible filtered by
/// the caller's grouping). Pure function of the participants' roles + sides.
fn classify(
    participants: &[CompositionParticipant],
    all_compatible: bool,
) -> (CompositionClass, String) {
    if !all_compatible {
        return (
            CompositionClass::ImpossibleIntersection,
            "participants are on disjoint strict sides and can never co-apply".to_string(),
        );
    }
    let replacements = participants
        .iter()
        .filter(|p| p.role == HandlerRole::Replacement)
        .count();
    let wrappers = participants
        .iter()
        .filter(|p| p.role == HandlerRole::Wrapper)
        .count();
    let guards = participants
        .iter()
        .any(|p| matches!(p.role, HandlerRole::Guard | HandlerRole::Suppressor));
    let non_observer = participants.iter().any(|p| p.role != HandlerRole::Observer);

    if replacements >= 2 {
        return (
            CompositionClass::HighConflict,
            format!(
                "{replacements} replacements (@Redirect/@Overwrite) seize the same point — only one can win"
            ),
        );
    }
    if replacements == 1 && non_observer {
        return (
            CompositionClass::HighConflict,
            "a replacement co-located with other behavioural handlers — it drops the others"
                .to_string(),
        );
    }
    if wrappers >= 2 {
        return (
            CompositionClass::OrderSensitiveChain,
            format!("{wrappers} @WrapOperation handlers chain — order changes the result"),
        );
    }
    if guards {
        return (
            CompositionClass::ConditionalRisk,
            "a guard/suppressor may drop the co-located handlers under its condition".to_string(),
        );
    }
    // Same-kind transformers on the same point are order-sensitive; otherwise the
    // group is observers and/or disjoint transformers — safe.
    let mut by_op: BTreeMap<&str, usize> = BTreeMap::new();
    for p in participants {
        if p.role == HandlerRole::Transformer {
            *by_op.entry(p.operation.as_str()).or_default() += 1;
        }
    }
    if by_op.values().any(|&c| c >= 2) {
        return (
            CompositionClass::OrderSensitiveChain,
            "multiple transformers of the same kind on one point — order-sensitive".to_string(),
        );
    }
    (
        CompositionClass::SafeComposition,
        "observers and/or disjoint transformers compose without conflict".to_string(),
    )
}

/// Build composition groups for every shared injection point (≥2 participants).
pub fn analyze_compositions(sites: &[ApplicationSite]) -> Vec<SiteComposition> {
    let mut groups: BTreeMap<(String, String), Vec<&ApplicationSite>> = BTreeMap::new();
    for site in sites {
        groups.entry(group_key(site)).or_default().push(site);
    }

    let mut out = Vec::new();
    for ((target_class, site_key), group) in groups {
        if group.len() < 2 {
            continue;
        }
        // Order by effective priority (higher first), then by stable id.
        let mut participants: Vec<CompositionParticipant> = group
            .iter()
            .map(|s| {
                // `@Inject(cancellable = true)` can call `CallbackInfo.cancel()`,
                // suppressing everything downstream in the target method. The
                // initial role from the operation name alone misses this: inject
                // maps to Observer, but a cancellable inject is a Suppressor.
                let base_role = role_for_operation(&s.operation);
                let role = if base_role == HandlerRole::Observer && s.cancellable {
                    HandlerRole::Suppressor
                } else {
                    base_role
                };
                CompositionParticipant {
                    site_id: s.site_id.clone(),
                    mod_id: s.mod_id.clone(),
                    operation: s.operation.clone(),
                    role,
                    priority: s.priority,
                    cancellable: s.cancellable,
                }
            })
            .collect();
        participants.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.site_id.cmp(&b.site_id))
        });

        let cross_mod = group
            .iter()
            .map(|s| s.mod_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1;

        // All sides pairwise compatible? (Side-suppression already drops conflicts,
        // but composition runs on raw sites, so re-check here.)
        let all_compatible = group.iter().enumerate().all(|(i, a)| {
            group
                .iter()
                .skip(i + 1)
                .all(|b| a.side.compatible_with(b.side))
        });

        let (classification, detail) = classify(&participants, all_compatible);
        out.push(SiteComposition {
            target_class,
            site_key,
            classification,
            cross_mod,
            participants,
            detail,
        });
    }
    out.sort_by(|a, b| {
        (a.target_class.as_str(), a.site_key.as_str())
            .cmp(&(b.target_class.as_str(), b.site_key.as_str()))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locals::LocalCaptureStatus;
    use crate::model::{ActivationStatus, Side};
    use crate::naming::{NameSource, ResolvedName};
    use crate::refmap::Namespace;
    use crate::selector::SelectorVerification;
    use crate::signature::SignatureCheck;
    use crate::target_res::TargetResolution;

    fn site(mod_id: &str, operation: &str, priority: i64, side: Side) -> ApplicationSite {
        ApplicationSite {
            site_id: format!("{mod_id}::M::h->T#tick()V@HEAD"),
            mod_id: mod_id.into(),
            archive: format!("{mod_id}.jar"),
            config_path: "m.json".into(),
            mixin_class: format!("{mod_id}.M"),
            handler_method: "h".into(),
            handler_descriptor: String::new(),
            operation: operation.into(),
            target_class: "net.minecraft.Foo".into(),
            target_method: "tick()V".into(),
            at_target: "HEAD".into(),
            at_detail: "HEAD".into(),
            site_key: "tick()V@HEAD".into(),
            namespace: Namespace::Intermediary,
            target_name: ResolvedName {
                original: "tick".into(),
                canonical: "tick()V".into(),
                namespace_original: Namespace::Intermediary,
                namespace_canonical: Namespace::Intermediary,
                source: NameSource::IntermediaryDirect,
                confidence: 100,
                reason: String::new(),
            },
            target_resolution: TargetResolution::Unchecked,
            selector_verification: SelectorVerification::Unchecked,
            signature_check: SignatureCheck::Unchecked,
            local_capture_status: LocalCaptureStatus::NoLocalCapture,
            side,
            activation: ActivationStatus::ActiveAssumed,
            priority,
            require: None,
            expect: None,
            allow: None,
            cancellable: false,
            confidence: 100,
            imprecision_reasons: Vec::new(),
        }
    }

    fn cancellable_site(mod_id: &str, priority: i64) -> ApplicationSite {
        let mut s = site(mod_id, "inject", priority, Side::Both);
        s.cancellable = true;
        s
    }

    #[test]
    fn two_redirects_are_high_conflict() {
        let sites = vec![
            site("a", "redirect", 1000, Side::Both),
            site("b", "redirect", 1000, Side::Both),
        ];
        let comps = analyze_compositions(&sites);
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].classification, CompositionClass::HighConflict);
        assert!(comps[0].cross_mod);
    }

    #[test]
    fn two_wrap_operations_are_an_order_sensitive_chain() {
        let sites = vec![
            site("a", "wrap-operation", 1100, Side::Both),
            site("b", "wrap-operation", 1000, Side::Both),
        ];
        let comps = analyze_compositions(&sites);
        assert_eq!(
            comps[0].classification,
            CompositionClass::OrderSensitiveChain
        );
        // Higher priority orders first.
        assert_eq!(comps[0].participants[0].mod_id, "a");
    }

    #[test]
    fn two_observers_compose_safely() {
        let sites = vec![
            site("a", "inject", 1000, Side::Both),
            site("b", "inject", 1000, Side::Both),
        ];
        let comps = analyze_compositions(&sites);
        assert_eq!(comps[0].classification, CompositionClass::SafeComposition);
    }

    #[test]
    fn disjoint_sides_are_impossible_intersection() {
        let sites = vec![
            site("a", "redirect", 1000, Side::Client),
            site("b", "redirect", 1000, Side::Server),
        ];
        let comps = analyze_compositions(&sites);
        assert_eq!(
            comps[0].classification,
            CompositionClass::ImpossibleIntersection
        );
    }

    #[test]
    fn lone_site_is_not_a_group() {
        let sites = vec![site("a", "inject", 1000, Side::Both)];
        assert!(analyze_compositions(&sites).is_empty());
    }

    #[test]
    fn cancellable_inject_is_a_suppressor_causing_conditional_risk() {
        // A plain `@Inject` is Observer (safe). An `@Inject(cancellable = true)`
        // can call `cancel()` and suppress downstream handlers, so it must be
        // classified as Suppressor and drive a ConditionalRisk classification.
        let sites = vec![
            cancellable_site("a", 1000),
            site("b", "inject", 1000, Side::Both),
        ];
        let comps = analyze_compositions(&sites);
        assert_eq!(comps.len(), 1);
        // At least one participant must be a Suppressor.
        assert!(
            comps[0]
                .participants
                .iter()
                .any(|p| p.role == HandlerRole::Suppressor)
        );
        assert_eq!(comps[0].classification, CompositionClass::ConditionalRisk);
    }
}
