//! Application-site identity (plan Phase 2).
//!
//! The central entity of deep mixin analysis is not the *mixin class* but the
//! *application site*: one `handler → target-method → injection-point` tuple. A
//! single mixin class can host dozens of sites, and real failures live at the site
//! level ("this handler, on this target method, at this injection point"), not at
//! the class or mod level.
//!
//! [`ApplicationSite`] flattens the scan's per-class [`ResolvedInjectionPoint`]s
//! into stable, individually-addressable records carrying everything later phases
//! key on: side, activation, priority, `require`/`expect`/`allow`, and a first-pass
//! resolution [`confidence`](ApplicationSite::confidence) with auditable reasons.

use serde::{Deserialize, Serialize};

use crate::apply_failure::TargetClassIndex;
use crate::locals::{CaptureSite, LocalCaptureStatus, verify_local_capture};
use crate::model::{ActivationStatus, MixinClassRecord, ResolvedInjectionPoint, Side};
use crate::naming::ResolvedName;
use crate::profile::{PrecisionProfile, effective_profile};
use crate::refmap::{Namespace, TinyMappings};
use crate::selector::SelectorVerification;
use crate::signature::{SignatureCheck, check_handler_signature};
use crate::target_res::{TargetResolution, split_member_ref};

/// One stable mixin application site (plan Phase 2). Its [`site_id`] is a
/// deterministic, scan-order-independent identity used as the *subject* of
/// site-level facts (mod id becomes an attribute, per plan Phase 16).
///
/// [`site_id`]: ApplicationSite::site_id
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationSite {
    /// Stable, human-readable, scan-order-independent identity for this site.
    pub site_id: String,
    pub mod_id: String,
    pub archive: String,
    pub config_path: String,
    pub mixin_class: String,
    pub handler_method: String,
    pub handler_descriptor: String,
    /// Operation kind at this site (`inject`, `redirect`, `overwrite`, …).
    pub operation: String,
    pub target_class: String,
    /// Resolved (preferably canonical) target method name+descriptor.
    pub target_method: String,
    /// `@At` target (`HEAD`, `RETURN`, `INVOKE`, …).
    pub at_target: String,
    /// Fine-grained injection-point detail (opcode / ordinal / member).
    pub at_detail: String,
    /// Cross-mod-stable collision key for this exact point.
    pub site_key: String,
    /// Namespace `target_method` / `site_key` are expressed in.
    pub namespace: Namespace,
    /// Unified resolution of the target method name (plan Phase 3) — original form,
    /// canonical form, provenance, and per-name confidence.
    pub target_name: ResolvedName,
    /// Descriptor-aware resolution of the target method against the class index
    /// (plan Phase 5): exact / name-only / descriptor-mismatch / missing / unchecked.
    pub target_resolution: TargetResolution,
    /// Whether the `@At` selector actually matches an instruction in the target
    /// body (plan Phase 6): matched / no-match / ordinal-out-of-range / unsupported.
    pub selector_verification: SelectorVerification,
    /// Whether the handler's signature is valid for its operation (plan Phase 7):
    /// valid / missing-callback-info / wrong-return-type / missing-operation-param.
    pub signature_check: SignatureCheck,
    /// Whether a captured target-method local is recoverable & matches (plan Phase 8):
    /// no-local-capture / exact-locals-match / local-missing / frame-(un)available.
    pub local_capture_status: LocalCaptureStatus,
    pub side: Side,
    pub activation: ActivationStatus,
    /// Effective priority (injector `priority` overrides the class priority).
    pub priority: i64,
    /// `require = N` on this injector, if set.
    pub require: Option<i32>,
    /// `expect = N` on this injector, if set.
    pub expect: Option<i32>,
    /// `allow = N` on this injector, if set.
    pub allow: Option<i32>,
    /// `cancellable = true` on this `@Inject` handler: the handler may call
    /// `CallbackInfo.cancel()` to suppress the rest of the target method.
    /// Elevates the role from `Observer` to `Suppressor` in composition analysis.
    pub cancellable: bool,
    /// 0–100 confidence that this site is correctly *identified and resolved* (not
    /// that it is risk-free). Phases 3–8 refine it; this is the resolution baseline.
    pub confidence: u8,
    /// Auditable reasons the confidence is below 100 (plan Phase 15 precision trace).
    pub imprecision_reasons: Vec<String>,
}

/// Build the stable site id. Deterministic in its inputs and independent of scan
/// order, so the same physical site always gets the same id across runs.
fn make_site_id(
    mod_id: &str,
    mixin_class: &str,
    handler: &str,
    handler_desc: &str,
    target_class: &str,
    target_method: &str,
    at: &str,
) -> String {
    format!("{mod_id}::{mixin_class}::{handler}{handler_desc}->{target_class}#{target_method}@{at}")
}

/// First-pass resolution confidence for a site, with the reasons it is not 100.
///
/// The name-resolution component now flows from the unified [`ResolvedName`] (plan
/// Phase 3), so the site and every other layer agree on how trustworthy a name is.
/// On top of that we fold in injection-point under-resolution and activation gating
/// (we cannot be fully sure of a site we cannot confirm applies).
fn site_confidence(
    inj: &ResolvedInjectionPoint,
    target_name: &ResolvedName,
    activation: ActivationStatus,
) -> (u8, Vec<String>) {
    let mut confidence: i32 = i32::from(target_name.confidence);
    let mut reasons = Vec::new();
    if !target_name.reason.is_empty() {
        reasons.push(target_name.reason.clone());
    }

    if inj.site_key.is_empty() {
        confidence -= 10;
        reasons.push("no fine-grained site key (injection point under-resolved)".to_string());
    }

    match activation {
        ActivationStatus::ConditionalByPlugin => {
            confidence -= 15;
            reasons.push("plugin-gated: cannot confirm the mixin applies".to_string());
        }
        ActivationStatus::ConditionalByConstraint => {
            confidence -= 15;
            reasons.push("constraint-gated: application is environment-conditional".to_string());
        }
        _ => {}
    }

    (confidence.clamp(0, 100) as u8, reasons)
}

/// Flatten one class's injection points into [`ApplicationSite`]s. `index`/`mappings`
/// drive descriptor-aware target resolution (plan Phase 5); when absent, sites are
/// marked `Unchecked`.
fn sites_for_class(
    class: &MixinClassRecord,
    index: Option<&TargetClassIndex>,
    mappings: Option<&TinyMappings>,
    profile: PrecisionProfile,
) -> Vec<ApplicationSite> {
    let hot = !class.hot_paths.is_empty();
    class
        .injected_methods
        .iter()
        .map(|inj| {
            // Phases 18–19: baseline depth for this site, escalated when the site is
            // hot/destructive/required/fail-hard/unresolved.
            let depth = effective_profile(profile, inj, hot);
            let target_method = if inj.canonical.is_empty() {
                inj.resolved.clone()
            } else {
                inj.canonical.clone()
            };
            let at = if inj.at_detail.is_empty() {
                inj.at_target.clone()
            } else {
                inj.at_detail.clone()
            };
            let target_name = ResolvedName::resolve(
                &inj.original,
                &target_method,
                inj.namespace,
                inj.resolved_via_refmap,
            );
            // Phase 5: resolve the target method (descriptor-aware) against the index.
            // Use the canonical reference (carries the descriptor) when present.
            let reference = if inj.canonical.is_empty() {
                inj.resolved.as_str()
            } else {
                inj.canonical.as_str()
            };
            let (name, descriptor) = split_member_ref(reference);
            let target_resolution = match index {
                Some(idx) if depth.resolves_targets() => {
                    idx.resolve_method(&inj.target, name, descriptor, mappings)
                }
                _ => TargetResolution::Unchecked,
            };
            // Phase 6: verify the @At selector actually matches an instruction.
            let selector_verification = match index {
                Some(idx) if depth.verifies_selectors() => idx.verify_selector(
                    &inj.target,
                    name,
                    &inj.at_target,
                    &inj.at_target_member,
                    inj.at_ordinal,
                    mappings,
                ),
                _ => SelectorVerification::Unchecked,
            };
            // Phase 7: check the handler's signature against its operation contract.
            let (signature_check, _sig_detail) = if depth.checks_signatures() {
                check_handler_signature(&inj.injection_type, &inj.handler_descriptor)
            } else {
                (SignatureCheck::Unchecked, String::new())
            };
            // Phase 8: verify local capture against the target method frame.
            let capture_site = CaptureSite {
                operation: &inj.injection_type,
                local_capture: &inj.local_capture,
                mutates_target_local: inj.mutates_target_local,
                local_index: inj.local_index,
                handler_descriptor: &inj.handler_descriptor,
            };
            let local_capture_status = if !capture_site.captures_locals() {
                LocalCaptureStatus::NoLocalCapture
            } else if depth.checks_locals() {
                let frame = index.and_then(|idx| idx.method_frame_for(&inj.target, name, mappings));
                verify_local_capture(&capture_site, frame)
            } else {
                LocalCaptureStatus::Unchecked
            };
            let (confidence, mut imprecision_reasons) =
                site_confidence(inj, &target_name, class.activation);
            // A CAPTURE_FAILHARD injector with no recoverable frame hard-fails at
            // load time rather than degrading — surface it in the precision trace.
            if local_capture_status == LocalCaptureStatus::FrameUnavailable
                && capture_site.is_fail_hard()
            {
                imprecision_reasons.push(
                    "CAPTURE_FAILHARD with no recoverable target frame — capture will hard-fail"
                        .to_string(),
                );
            }
            ApplicationSite {
                site_id: make_site_id(
                    &class.mod_id,
                    &class.class_name,
                    &inj.handler_method,
                    &inj.handler_descriptor,
                    &inj.target,
                    &target_method,
                    &at,
                ),
                mod_id: class.mod_id.clone(),
                archive: class.archive.clone(),
                config_path: class.config.clone(),
                mixin_class: class.class_name.clone(),
                handler_method: inj.handler_method.clone(),
                handler_descriptor: inj.handler_descriptor.clone(),
                operation: inj.injection_type.clone(),
                target_class: inj.target.clone(),
                target_method,
                at_target: inj.at_target.clone(),
                at_detail: inj.at_detail.clone(),
                site_key: inj.site_key.clone(),
                namespace: inj.namespace,
                target_name,
                target_resolution,
                selector_verification,
                signature_check,
                local_capture_status,
                side: class.side,
                activation: class.activation,
                priority: inj.meta.priority.map(i64::from).unwrap_or(class.priority),
                require: inj.meta.require,
                expect: inj.meta.expect,
                allow: inj.meta.allow,
                cancellable: inj.meta.cancellable,
                confidence,
                imprecision_reasons,
            }
        })
        .collect()
}

/// Build every application site in a scan, sorted by stable id for determinism.
/// `index`/`mappings` enable descriptor-aware target resolution (plan Phase 5).
pub fn build_application_sites(
    classes: &[MixinClassRecord],
    index: Option<&TargetClassIndex>,
    mappings: Option<&TinyMappings>,
    profile: PrecisionProfile,
) -> Vec<ApplicationSite> {
    let mut sites: Vec<ApplicationSite> = classes
        .iter()
        .flat_map(|c| sites_for_class(c, index, mappings, profile))
        .collect();
    sites.sort_by(|a, b| a.site_id.cmp(&b.site_id));
    sites
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{InjectorMeta, MixinOperation};

    fn class_with_injection(inj: ResolvedInjectionPoint) -> MixinClassRecord {
        MixinClassRecord {
            archive: "alpha.jar".into(),
            mod_id: "alpha".into(),
            config: "alpha.mixins.json".into(),
            class_name: "alpha.FooMixin".into(),
            class_path: "alpha/FooMixin.class".into(),
            targets: vec![inj.target.clone()],
            target_namespace: Default::default(),
            runtime_namespace: Default::default(),
            operations: vec![MixinOperation::Inject],
            injected_methods: vec![inj],
            shadows: Vec::new(),
            added_members: Vec::new(),
            calls: Vec::new(),
            handler_bodies: Vec::new(),
            target_hierarchy: Vec::new(),
            priority: 1000,
            refmap: None,
            hot_paths: Vec::new(),
            effects: Vec::new(),
            plugin_gated: false,
            side: Side::Both,
            activation: ActivationStatus::ActiveAssumed,
            activation_reason: String::new(),
        }
    }

    fn injection() -> ResolvedInjectionPoint {
        ResolvedInjectionPoint {
            target: "net.minecraft.server.MinecraftServer".into(),
            original: "method_3748".into(),
            resolved: "tick".into(),
            canonical: "method_3748()V".into(),
            site_key: "method_3748()V@HEAD".into(),
            namespace: Namespace::Intermediary,
            injection_type: "inject".into(),
            resolved_via_refmap: true,
            handler_method: "onTick".into(),
            handler_descriptor: "(Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfo;)V"
                .into(),
            mutates_target_local: false,
            at_target: "HEAD".into(),
            at_detail: "HEAD".into(),
            impact: "entry-hook".into(),
            local_index: None,
            local_capture: String::new(),
            meta: InjectorMeta {
                require: Some(1),
                ..Default::default()
            },
            at_ordinal: None,
            at_target_member: String::new(),
        }
    }

    #[test]
    fn builds_a_stable_addressable_site() {
        let class = class_with_injection(injection());
        let sites = build_application_sites(
            std::slice::from_ref(&class),
            None,
            None,
            PrecisionProfile::Deep,
        );
        assert_eq!(sites.len(), 1);
        let s = &sites[0];
        assert_eq!(s.mod_id, "alpha");
        assert_eq!(s.handler_method, "onTick");
        assert_eq!(s.operation, "inject");
        assert_eq!(s.require, Some(1));
        assert_eq!(s.side, Side::Both);
        // Intermediary + refmap-resolved ⇒ full resolution confidence.
        assert_eq!(s.confidence, 100);
        // Site id is deterministic.
        let again = build_application_sites(
            std::slice::from_ref(&class),
            None,
            None,
            PrecisionProfile::Deep,
        );
        assert_eq!(s.site_id, again[0].site_id);
    }

    #[test]
    fn injector_priority_overrides_class_priority() {
        let mut inj = injection();
        inj.meta.priority = Some(1500);
        let class = class_with_injection(inj);
        let sites = build_application_sites(&[class], None, None, PrecisionProfile::Deep);
        assert_eq!(sites[0].priority, 1500);
    }

    #[test]
    fn unmapped_named_target_lowers_confidence_with_reason() {
        let mut inj = injection();
        inj.namespace = Namespace::Named;
        inj.resolved_via_refmap = false;
        let class = class_with_injection(inj);
        let sites = build_application_sites(&[class], None, None, PrecisionProfile::Deep);
        assert!(sites[0].confidence < 100);
        assert_eq!(
            sites[0].target_name.source,
            crate::naming::NameSource::NamedUnbridged
        );
        assert!(
            sites[0]
                .imprecision_reasons
                .iter()
                .any(|r| r.contains("cross-mod-stable"))
        );
    }

    #[test]
    fn handler_signature_is_checked_per_operation() {
        // The default injection has a CallbackInfo param + void return ⇒ valid.
        let class = class_with_injection(injection());
        let sites = build_application_sites(&[class], None, None, PrecisionProfile::Deep);
        assert_eq!(sites[0].signature_check, SignatureCheck::Valid);

        // Strip the CallbackInfo param ⇒ an invalid @Inject handler.
        let mut inj = injection();
        inj.handler_descriptor = "(I)V".into();
        let class = class_with_injection(inj);
        let sites = build_application_sites(&[class], None, None, PrecisionProfile::Deep);
        assert_eq!(
            sites[0].signature_check,
            SignatureCheck::MissingCallbackInfo
        );
    }

    #[test]
    fn plugin_gating_subtracts_confidence() {
        let mut class = class_with_injection(injection());
        class.activation = ActivationStatus::ConditionalByPlugin;
        let sites = build_application_sites(&[class], None, None, PrecisionProfile::Deep);
        assert!(
            sites[0]
                .imprecision_reasons
                .iter()
                .any(|r| r.contains("plugin-gated"))
        );
        assert_eq!(sites[0].confidence, 85);
    }
}
