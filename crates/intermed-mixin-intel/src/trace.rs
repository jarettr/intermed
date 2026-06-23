//! Coverage & precision trace (plan Phase 15).
//!
//! Every verdict should be able to explain *what was actually checked* and *what
//! was not* — the difference between "confidence 0.55 because we couldn't see the
//! target bytecode" and "confidence 0.95, fully verified". This turns an
//! [`ApplicationSite`]'s per-layer statuses into two lists for `--explain`.

use crate::locals::LocalCaptureStatus;
use crate::naming::NameSource;
use crate::selector::SelectorVerification;
use crate::signature::SignatureCheck;
use crate::site::ApplicationSite;
use crate::target_res::TargetResolution;

/// What was and wasn't verified for one site (plan Phase 15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecisionTrace {
    /// Layers that were actually checked (with positive or negative result).
    pub checked: Vec<&'static str>,
    /// Layers that could not be checked, with the reason.
    pub not_checked: Vec<&'static str>,
}

/// Derive the precision trace for one application site.
pub fn site_trace(site: &ApplicationSite) -> PrecisionTrace {
    let mut checked = Vec::new();
    let mut not_checked = Vec::new();

    // Activation/side are always resolved during scanning.
    checked.push("activation");

    // Name mapping (Phase 3).
    match site.target_name.source {
        NameSource::Unresolved => not_checked.push("name-mapping (missing mappings/refmap)"),
        _ => checked.push("name-mapping"),
    }

    // Descriptor-aware target resolution (Phase 5).
    match site.target_resolution {
        TargetResolution::Unchecked => {
            not_checked.push("target-descriptor (target bytecode unavailable)")
        }
        _ => checked.push("target-descriptor"),
    }

    // Selector verification (Phase 6).
    match site.selector_verification {
        SelectorVerification::Unchecked => {
            not_checked.push("selector (target bytecode unavailable)")
        }
        SelectorVerification::Unsupported => not_checked.push("selector (unsupported @At kind)"),
        _ => checked.push("selector"),
    }

    // Handler signature (Phase 7).
    match site.signature_check {
        SignatureCheck::Unchecked => not_checked.push("handler-signature (no descriptor)"),
        SignatureCheck::Unsupported => {
            not_checked.push("handler-signature (operation not signature-checked)")
        }
        _ => checked.push("handler-signature"),
    }

    // Local capture (Phase 8).
    match site.local_capture_status {
        LocalCaptureStatus::NoLocalCapture => {} // not applicable — neither checked nor a gap
        LocalCaptureStatus::Unchecked => not_checked.push("local-capture (frame unavailable)"),
        LocalCaptureStatus::FrameUnavailable => {
            not_checked.push("local-capture (no LVT/StackMapTable)")
        }
        _ => checked.push("local-capture"),
    }

    // Runtime-log join and performance match are scan-external (Phase 11/12) — not
    // performed in a pure jar scan, so they are honestly reported as not-checked.
    not_checked.push("runtime-logs (no log input)");
    not_checked.push("performance-match (no Spark input)");

    PrecisionTrace {
        checked,
        not_checked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::ResolvedName;
    use crate::refmap::Namespace;

    fn site() -> ApplicationSite {
        ApplicationSite {
            site_id: "s".into(),
            mod_id: "m".into(),
            archive: "m.jar".into(),
            config_path: "m.json".into(),
            mixin_class: "m.M".into(),
            handler_method: "h".into(),
            handler_descriptor: String::new(),
            operation: "inject".into(),
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
            target_resolution: TargetResolution::ExactMatch,
            selector_verification: SelectorVerification::MatchesByConstruction,
            signature_check: SignatureCheck::Valid,
            local_capture_status: LocalCaptureStatus::NoLocalCapture,
            side: crate::model::Side::Both,
            activation: crate::model::ActivationStatus::ActiveAssumed,
            priority: 1000,
            require: None,
            expect: None,
            allow: None,
            cancellable: false,
            confidence: 100,
            imprecision_reasons: Vec::new(),
        }
    }

    #[test]
    fn fully_resolved_site_checks_the_static_layers() {
        let t = site_trace(&site());
        assert!(t.checked.contains(&"name-mapping"));
        assert!(t.checked.contains(&"target-descriptor"));
        assert!(t.checked.contains(&"selector"));
        assert!(t.checked.contains(&"handler-signature"));
        // Runtime/perf are always external in a jar scan.
        assert!(t.not_checked.iter().any(|s| s.starts_with("runtime-logs")));
    }

    #[test]
    fn unresolved_site_reports_the_gaps() {
        let mut s = site();
        s.target_resolution = TargetResolution::Unchecked;
        s.selector_verification = SelectorVerification::Unchecked;
        s.target_name.source = NameSource::Unresolved;
        let t = site_trace(&s);
        assert!(
            t.not_checked
                .iter()
                .any(|x| x.starts_with("target-descriptor"))
        );
        assert!(t.not_checked.iter().any(|x| x.starts_with("selector")));
        assert!(t.not_checked.iter().any(|x| x.starts_with("name-mapping")));
    }
}
