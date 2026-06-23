//! Risk clusters (plan Phase 13).
//!
//! A modpack produces thousands of site-level facts; a user does not want the
//! firehose, they want the few *diagnoses*: what is actually broken, what might
//! break, what affects performance, what is just forensic detail. A [`RiskCluster`]
//! rolls the per-site evidence for one target into a single actionable verdict.

use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet};

use intermed_doctor_core::evidence::Severity;

use crate::apply_failure::ApplyFailure;
use crate::composition::{CompositionClass, SiteComposition};
use crate::severity::{ConfirmationLevel, SeverityInputs, recommended_severity};
use crate::site::ApplicationSite;

/// The dominant character of a cluster, which drives its headline and action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClusterKind {
    /// One or more sites are confirmed/likely not to apply (missing target,
    /// bad selector, bad signature, failed local capture).
    ApplyFailure,
    /// Multiple handlers genuinely conflict at a shared point.
    Composition,
    /// Handlers chain in an order-sensitive way (works, but order matters).
    OrderSensitive,
    /// Many mods touch one target without a concrete failure — forensic detail.
    Crowded,
}

impl ClusterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ClusterKind::ApplyFailure => "apply-failure",
            ClusterKind::Composition => "composition",
            ClusterKind::OrderSensitive => "order-sensitive",
            ClusterKind::Crowded => "crowded",
        }
    }
}

/// A grouped, actionable diagnosis for one target class (plan Phase 13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskCluster {
    pub id: String,
    pub kind: ClusterKind,
    /// The target class this cluster is about.
    pub target_class: String,
    pub participants: Vec<String>,
    pub site_count: usize,
    pub apply_failures: usize,
    pub selector_failures: usize,
    pub signature_failures: usize,
    pub local_failures: usize,
    /// The most severe composition class observed at any site on this target.
    pub worst_composition: Option<CompositionClass>,
    /// Aggregate confidence (the minimum site confidence — the weakest link).
    pub confidence: u8,
    /// How this cluster's verdict is backed (plan Phase 14).
    pub confirmation_level: ConfirmationLevel,
    /// Recommended severity under the unified model (plan Phase 14).
    pub severity: Severity,
    /// 0–100 how clear the fix is.
    pub actionability: u8,
    pub headline: String,
    pub recommended_action: String,
}

/// Strongest confirmation level backing this target's failures (plan Phase 14).
fn cluster_confirmation(group: &[&ApplicationSite], any_failure: bool) -> ConfirmationLevel {
    if !any_failure {
        return ConfirmationLevel::HeuristicSite;
    }
    // Bytecode-backed failure (selector / local capture / resolved-against-index).
    let bytecode_backed = group.iter().any(|s| {
        s.selector_verification.is_failure()
            || s.local_capture_status.is_failure()
            || matches!(
                s.target_resolution,
                crate::target_res::TargetResolution::MissingMethod
                    | crate::target_res::TargetResolution::MissingClass
            )
    });
    if bytecode_backed {
        return ConfirmationLevel::StaticExact;
    }
    let descriptor_backed = group.iter().any(|s| {
        s.signature_check.is_failure()
            || matches!(
                s.target_resolution,
                crate::target_res::TargetResolution::DescriptorMismatch
                    | crate::target_res::TargetResolution::AmbiguousOverload
            )
    });
    if descriptor_backed {
        return ConfirmationLevel::StaticDescriptorAware;
    }
    ConfirmationLevel::StaticNameOnly
}

/// Severity ordering for composition classes (higher = worse).
fn composition_rank(c: CompositionClass) -> u8 {
    match c {
        CompositionClass::HighConflict => 5,
        CompositionClass::OrderSensitiveChain => 4,
        CompositionClass::ConditionalRisk => 3,
        CompositionClass::Unknown => 2,
        CompositionClass::SafeComposition => 1,
        CompositionClass::ImpossibleIntersection => 0,
    }
}

/// Build risk clusters from the per-site evidence. Trivial single-mod, all-safe
/// targets are dropped — a cluster is only emitted when it carries a real signal.
pub fn build_clusters(
    sites: &[ApplicationSite],
    apply_failures: &[ApplyFailure],
    compositions: &[SiteComposition],
    coverage_conclusive: bool,
) -> Vec<RiskCluster> {
    // Index sites + compositions by target class.
    let mut by_target: BTreeMap<&str, Vec<&ApplicationSite>> = BTreeMap::new();
    for s in sites {
        by_target
            .entry(s.target_class.as_str())
            .or_default()
            .push(s);
    }
    let mut comps_by_target: BTreeMap<&str, Vec<&SiteComposition>> = BTreeMap::new();
    for c in compositions {
        comps_by_target
            .entry(c.target_class.as_str())
            .or_default()
            .push(c);
    }
    let mut failures_by_target: BTreeMap<&str, usize> = BTreeMap::new();
    for f in apply_failures {
        *failures_by_target.entry(f.target.as_str()).or_default() += 1;
    }

    let mut out = Vec::new();
    for (target, group) in by_target {
        let participants: BTreeSet<&str> = group.iter().map(|s| s.mod_id.as_str()).collect();
        let selector_failures = group
            .iter()
            .filter(|s| s.selector_verification.is_failure())
            .count();
        let signature_failures = group
            .iter()
            .filter(|s| s.signature_check.is_failure())
            .count();
        let local_failures = group
            .iter()
            .filter(|s| s.local_capture_status.is_failure())
            .count();
        let resolution_failures = group
            .iter()
            .filter(|s| s.target_resolution.is_failure())
            .count();
        let apply_failures_n =
            failures_by_target.get(target).copied().unwrap_or(0) + resolution_failures;

        let worst_composition = comps_by_target.get(target).and_then(|cs| {
            cs.iter()
                .map(|c| c.classification)
                .max_by_key(|c| composition_rank(*c))
        });
        let high_conflict = matches!(worst_composition, Some(CompositionClass::HighConflict));
        let order_sensitive = matches!(
            worst_composition,
            Some(CompositionClass::OrderSensitiveChain)
        );

        let any_failure =
            apply_failures_n + selector_failures + signature_failures + local_failures > 0;

        // Decide whether this target is worth a cluster, and of what kind.
        let kind = if any_failure {
            ClusterKind::ApplyFailure
        } else if high_conflict {
            ClusterKind::Composition
        } else if order_sensitive {
            ClusterKind::OrderSensitive
        } else if participants.len() >= 3 {
            ClusterKind::Crowded
        } else {
            // Single-or-two-mod, no failure, safe composition: not a diagnosis.
            continue;
        };

        let confidence = group.iter().map(|s| s.confidence).min().unwrap_or(0);
        let confirmation_level = cluster_confirmation(&group, any_failure);
        // Impact proxy: a real apply/conflict failure is high-impact, a crowded
        // target is low. (Phase 12 perf impact can refine this later.)
        let impact: u8 = if any_failure || high_conflict { 80 } else { 30 };
        let (actionability, headline, recommended_action) = describe(
            kind,
            target,
            &participants,
            apply_failures_n,
            selector_failures,
            signature_failures,
            local_failures,
        );
        let severity = recommended_severity(&SeverityInputs {
            confirmation: confirmation_level,
            is_failure: any_failure || high_conflict,
            coverage_conclusive,
            impact,
            actionability,
        });

        out.push(RiskCluster {
            id: format!("cluster-{target}"),
            kind,
            target_class: target.to_string(),
            participants: participants.iter().map(|s| s.to_string()).collect(),
            site_count: group.len(),
            apply_failures: apply_failures_n,
            selector_failures,
            signature_failures,
            local_failures,
            worst_composition,
            confidence,
            confirmation_level,
            severity,
            actionability,
            headline,
            recommended_action,
        });
    }
    // Most actionable / most severe first.
    out.sort_by(|a, b| {
        b.actionability
            .cmp(&a.actionability)
            .then_with(|| b.apply_failures.cmp(&a.apply_failures))
            .then_with(|| a.target_class.cmp(&b.target_class))
    });
    out
}

#[allow(clippy::too_many_arguments)]
fn describe(
    kind: ClusterKind,
    target: &str,
    participants: &BTreeSet<&str>,
    apply_failures: usize,
    selector_failures: usize,
    signature_failures: usize,
    local_failures: usize,
) -> (u8, String, String) {
    let mods = participants.iter().copied().collect::<Vec<_>>().join(", ");
    match kind {
        ClusterKind::ApplyFailure => (
            90,
            format!(
                "{apply_failures} apply / {selector_failures} selector / {signature_failures} signature / {local_failures} local-capture issue(s) on `{target}` ({mods})"
            ),
            "Inspect the failing sites — verify the target still has the method/injection point under the current mappings, and the handler signature/locals match.".to_string(),
        ),
        ClusterKind::Composition => (
            70,
            format!("Conflicting handlers on `{target}` ({mods}) seize the same point"),
            "Only one replacement (@Redirect/@Overwrite) can own a call site — switch the others to @WrapOperation or coordinate priorities.".to_string(),
        ),
        ClusterKind::OrderSensitive => (
            55,
            format!("Order-sensitive handler chain on `{target}` ({mods})"),
            "Behaviour depends on application order — set explicit injector priorities so the chain is deterministic.".to_string(),
        ),
        ClusterKind::Crowded => (
            25,
            format!(
                "{} mods weave `{target}` — no concrete failure, forensic detail",
                participants.len()
            ),
            "No action needed; monitor if this target later shows apply failures.".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composition::{CompositionParticipant, HandlerRole};
    use crate::naming::{NameSource, ResolvedName};
    use crate::refmap::Namespace;

    fn site(mod_id: &str, target: &str, selector_fail: bool) -> ApplicationSite {
        ApplicationSite {
            site_id: format!("{mod_id}::M::h->{target}#tick()V@HEAD"),
            mod_id: mod_id.into(),
            archive: format!("{mod_id}.jar"),
            config_path: "m.json".into(),
            mixin_class: format!("{mod_id}.M"),
            handler_method: "h".into(),
            handler_descriptor: String::new(),
            operation: "inject".into(),
            target_class: target.into(),
            target_method: "tick()V".into(),
            at_target: "INVOKE".into(),
            at_detail: "INVOKE".into(),
            site_key: "tick()V@INVOKE".into(),
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
            target_resolution: crate::target_res::TargetResolution::ExactMatch,
            selector_verification: if selector_fail {
                crate::selector::SelectorVerification::NoMatch
            } else {
                crate::selector::SelectorVerification::Matched
            },
            signature_check: crate::signature::SignatureCheck::Valid,
            local_capture_status: crate::locals::LocalCaptureStatus::NoLocalCapture,
            side: crate::model::Side::Both,
            activation: crate::model::ActivationStatus::ActiveAssumed,
            priority: 1000,
            require: None,
            expect: None,
            allow: None,
            cancellable: false,
            confidence: 90,
            imprecision_reasons: Vec::new(),
        }
    }

    #[test]
    fn selector_failure_makes_an_apply_failure_cluster() {
        let sites = vec![site("a", "net.minecraft.Foo", true)];
        let clusters = build_clusters(&sites, &[], &[], true);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].kind, ClusterKind::ApplyFailure);
        assert_eq!(clusters[0].selector_failures, 1);
        assert!(clusters[0].actionability >= 80);
    }

    #[test]
    fn safe_single_mod_target_is_not_a_cluster() {
        let sites = vec![site("a", "net.minecraft.Bar", false)];
        assert!(build_clusters(&sites, &[], &[], true).is_empty());
    }

    #[test]
    fn high_conflict_composition_makes_a_composition_cluster() {
        let sites = vec![
            site("a", "net.minecraft.Baz", false),
            site("b", "net.minecraft.Baz", false),
        ];
        let comp = SiteComposition {
            target_class: "net.minecraft.Baz".into(),
            site_key: "tick()V@INVOKE".into(),
            classification: CompositionClass::HighConflict,
            cross_mod: true,
            participants: vec![CompositionParticipant {
                site_id: "x".into(),
                mod_id: "a".into(),
                operation: "redirect".into(),
                role: HandlerRole::Replacement,
                priority: 1000,
                cancellable: false,
            }],
            detail: String::new(),
        };
        let clusters = build_clusters(&sites, &[], &[comp], true);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].kind, ClusterKind::Composition);
    }
}
