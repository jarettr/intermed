//! Local capture & frame model (plan Phase 8).
//!
//! Injectors that capture target-method locals (`@Inject(locals = …)`,
//! `@ModifyVariable`, MixinExtras `@Local`/`LocalRef`) are among the most
//! version-fragile mixins: a local that moved, changed type, or lost its
//! `LocalVariableTable` between versions makes the capture fail — and a
//! `CAPTURE_FAILHARD` injector hard-crashes rather than degrading.
//!
//! This layer asks, for a *capturing* site, whether the target method's frame is
//! even recoverable (LVT / StackMapTable present) and whether the captured type is
//! actually declared. It is deliberately conservative: it never claims an exact
//! match it cannot prove, and it flags `FrameUnavailable` (the real hazard) rather
//! than guessing.

use serde::{Deserialize, Serialize};

use crate::apply_failure::MethodFrame;
use crate::signature::parse_descriptor;

/// Outcome of verifying a site's local capture against the target method frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LocalCaptureStatus {
    /// The site does not capture any target-method locals.
    NoLocalCapture,
    /// The captured local type is present in the target method's frame.
    ExactLocalsMatch,
    /// The captured local type is not declared in the target method's frame.
    LocalMissing,
    /// The target frame is available but the captured type could not be pinned to a
    /// single local (kept neutral rather than asserting a match).
    FrameAvailable,
    /// The target method has neither an LVT nor a StackMapTable — locals cannot be
    /// recovered, and a `CAPTURE_FAILHARD` injector would hard-fail.
    FrameUnavailable,
    /// Not checked — the target class/method was not indexed.
    #[default]
    Unchecked,
}

impl LocalCaptureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            LocalCaptureStatus::NoLocalCapture => "no-local-capture",
            LocalCaptureStatus::ExactLocalsMatch => "exact-locals-match",
            LocalCaptureStatus::LocalMissing => "local-missing",
            LocalCaptureStatus::FrameAvailable => "frame-available",
            LocalCaptureStatus::FrameUnavailable => "frame-unavailable",
            LocalCaptureStatus::Unchecked => "unchecked",
        }
    }

    /// `true` when the capture is conclusively shown to be broken/fragile-failing.
    pub fn is_failure(self) -> bool {
        matches!(self, LocalCaptureStatus::LocalMissing)
    }
}

/// Inputs describing a site's local capture intent.
pub struct CaptureSite<'a> {
    /// The operation kind (`modify-variable`, `inject`, …).
    pub operation: &'a str,
    /// Sponge `locals = LocalCapture.X` mode (empty when none).
    pub local_capture: &'a str,
    /// The injector mutates a target local (writable `LocalRef`/`@ModifyVariable`).
    pub mutates_target_local: bool,
    /// A captured local index was recorded.
    pub local_index: Option<i32>,
    /// The handler descriptor (its return type is the modified local type for
    /// `@ModifyVariable`).
    pub handler_descriptor: &'a str,
}

impl CaptureSite<'_> {
    /// Whether this site captures any target-method locals at all.
    pub fn captures_locals(&self) -> bool {
        self.operation == "modify-variable"
            || !self.local_capture.is_empty()
            || self.mutates_target_local
            || self.local_index.is_some()
    }

    /// Whether the injector hard-fails on a frame mismatch (`CAPTURE_FAILHARD`).
    pub fn is_fail_hard(&self) -> bool {
        self.local_capture.eq_ignore_ascii_case("CAPTURE_FAILHARD")
    }

    /// The concrete captured local type, when statically known (the `@ModifyVariable`
    /// handler's return type). `None` for multi-local `@Inject` captures we don't pin.
    fn captured_type(&self) -> Option<String> {
        if self.operation == "modify-variable" {
            parse_descriptor(self.handler_descriptor).map(|(_, ret)| ret)
        } else {
            None
        }
    }
}

/// Verify a capture site against the target method frame.
pub fn verify_local_capture(
    site: &CaptureSite<'_>,
    frame: Option<&MethodFrame>,
) -> LocalCaptureStatus {
    if !site.captures_locals() {
        return LocalCaptureStatus::NoLocalCapture;
    }
    let Some(frame) = frame else {
        return LocalCaptureStatus::Unchecked;
    };
    if !frame.has_lvt && !frame.has_stackmap {
        return LocalCaptureStatus::FrameUnavailable;
    }
    match site.captured_type() {
        Some(ty) if !ty.is_empty() && ty != "V" => {
            // We need the LVT (not just a StackMapTable) to match a concrete type.
            if !frame.has_lvt {
                LocalCaptureStatus::FrameAvailable
            } else if !frame.local_descriptors.contains(&ty) {
                LocalCaptureStatus::LocalMissing
            } else if let Some(idx) = site.local_index {
                // The type exists, but we must also confirm the *slot index* is
                // actually present in the LVT. Three int locals don't make slot 4
                // valid — without index validation we produce a false-positive
                // ExactLocalsMatch that masks a runtime InvalidInjectionException.
                let slot = u16::try_from(idx).unwrap_or(u16::MAX);
                if frame.local_slots.contains(&slot) {
                    LocalCaptureStatus::ExactLocalsMatch
                } else {
                    LocalCaptureStatus::LocalMissing
                }
            } else {
                LocalCaptureStatus::ExactLocalsMatch
            }
        }
        // Frame exists but we can't pin a concrete captured type — stay neutral.
        _ => LocalCaptureStatus::FrameAvailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(has_lvt: bool, has_stackmap: bool, locals: &[&str]) -> MethodFrame {
        // Slots 0..n are assigned automatically to match the LVT entries, which
        // is the normal bytecode convention (each variable occupies one slot,
        // category-2 types like long/double skipping the next).
        let local_slots = (0u16..locals.len() as u16).collect();
        MethodFrame {
            has_lvt,
            has_stackmap,
            local_descriptors: locals.iter().map(|s| s.to_string()).collect(),
            local_slots,
        }
    }

    fn modify_var(handler_descriptor: &str, fail_hard: bool) -> CaptureSite<'static> {
        CaptureSite {
            operation: "modify-variable",
            local_capture: if fail_hard { "CAPTURE_FAILHARD" } else { "" },
            mutates_target_local: true,
            local_index: Some(2),
            handler_descriptor: Box::leak(handler_descriptor.to_string().into_boxed_str()),
        }
    }

    #[test]
    fn non_capturing_site_is_no_capture() {
        let site = CaptureSite {
            operation: "inject",
            local_capture: "",
            mutates_target_local: false,
            local_index: None,
            handler_descriptor: "(Lx;)V",
        };
        assert_eq!(
            verify_local_capture(&site, None),
            LocalCaptureStatus::NoLocalCapture
        );
    }

    #[test]
    fn no_frame_data_is_fragile() {
        let site = modify_var("(I)I", true);
        let f = frame(false, false, &[]);
        assert_eq!(
            verify_local_capture(&site, Some(&f)),
            LocalCaptureStatus::FrameUnavailable
        );
        assert!(site.is_fail_hard());
    }

    #[test]
    fn matching_local_type_is_exact() {
        // modify_var captures local_index: Some(2), so the frame must contain slot 2.
        // frame() assigns slots 0..n, so three locals give slots {0, 1, 2}.
        let site = modify_var("(I)I", false);
        let f = frame(true, true, &["Lfoo/Bar;", "Lfoo/Bar;", "I"]);
        assert_eq!(
            verify_local_capture(&site, Some(&f)),
            LocalCaptureStatus::ExactLocalsMatch
        );
    }

    #[test]
    fn matching_type_but_wrong_slot_index_is_a_failure() {
        // The method has three `int` locals (slots 0, 1, 2) and the mixin tries
        // to capture slot 4 — the type exists in the LVT but the index does not.
        // This must return LocalMissing, not ExactLocalsMatch.
        let f = frame(true, true, &["I", "I", "I"]);
        // Manually insert slots 1 and 2 (slot 0 is always `this`).
        let mut frame_with_slots = f;
        frame_with_slots.local_slots = [0u16, 1, 2].iter().copied().collect();
        let site = CaptureSite {
            operation: "modify-variable",
            local_capture: "",
            mutates_target_local: true,
            local_index: Some(4), // slot 4 does not exist
            handler_descriptor: Box::leak("(I)I".to_string().into_boxed_str()),
        };
        let status = verify_local_capture(&site, Some(&frame_with_slots));
        assert_eq!(status, LocalCaptureStatus::LocalMissing);
        assert!(status.is_failure());
    }

    #[test]
    fn missing_local_type_is_a_failure() {
        let site = modify_var("(Lfoo/Bar;)Lfoo/Bar;", false);
        let f = frame(true, true, &["I", "J"]);
        let status = verify_local_capture(&site, Some(&f));
        assert_eq!(status, LocalCaptureStatus::LocalMissing);
        assert!(status.is_failure());
    }

    #[test]
    fn stackmap_only_stays_neutral() {
        let site = modify_var("(I)I", false);
        let f = frame(false, true, &[]);
        assert_eq!(
            verify_local_capture(&site, Some(&f)),
            LocalCaptureStatus::FrameAvailable
        );
    }
}
