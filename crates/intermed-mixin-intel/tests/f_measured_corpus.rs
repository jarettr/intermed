//! Small sanitized Layer-F measurement gate. Each family contains positive and
//! negative labels; the test reports precision/recall and fails on regression.

use intermed_mixin_intel::{
    ActivationStatus, ApplicationSite, CompositionClass, PrecisionProfile, RuntimeFailureReason,
    RuntimeMixinFailure, Side, SignatureCheck, SitePrecision, TargetClassIndex, TargetResolution,
    analyze_compositions, check_handler_signature_with_target, confirm_sites,
};

#[derive(Default)]
struct Counts {
    tp: u32,
    fp: u32,
    fn_: u32,
    tn: u32,
}

impl Counts {
    fn observe(&mut self, expected: bool, predicted: bool) {
        match (expected, predicted) {
            (true, true) => self.tp += 1,
            (false, true) => self.fp += 1,
            (true, false) => self.fn_ += 1,
            (false, false) => self.tn += 1,
        }
    }
    fn precision(&self) -> f64 {
        self.tp as f64 / (self.tp + self.fp).max(1) as f64
    }
    fn recall(&self) -> f64 {
        self.tp as f64 / (self.tp + self.fn_).max(1) as f64
    }
    fn assert_perfect(&self, family: &str) {
        assert_eq!(
            self.fp,
            0,
            "{family}: false positives; precision={}",
            self.precision()
        );
        assert_eq!(
            self.fn_,
            0,
            "{family}: false negatives; recall={}",
            self.recall()
        );
        assert!(
            self.tp > 0 && self.tn > 0,
            "{family}: corpus needs positive and negative support"
        );
    }
}

fn site(id: &str, operation: &str) -> ApplicationSite {
    ApplicationSite {
        site_id: id.into(),
        mod_id: id.into(),
        artifact_id: format!("sha256:{id}"),
        identity_certainty: "confirmed".into(),
        archive: format!("{id}.jar"),
        config_path: "test.mixins.json".into(),
        mixin_class: format!("test.{id}Mixin"),
        handler_method: "handler".into(),
        handler_descriptor: "()V".into(),
        operation: operation.into(),
        target_class: "net.minecraft.Server".into(),
        target_method: "tick()V".into(),
        at_target: "HEAD".into(),
        at_detail: "HEAD".into(),
        site_key: "tick()V@HEAD".into(),
        namespace: intermed_mixin_intel::Namespace::Intermediary,
        target_name: intermed_mixin_intel::ResolvedName {
            original: "tick".into(),
            canonical: "tick()V".into(),
            namespace_original: intermed_mixin_intel::Namespace::Intermediary,
            namespace_canonical: intermed_mixin_intel::Namespace::Intermediary,
            source: intermed_mixin_intel::NameSource::IntermediaryDirect,
            confidence: 100,
            reason: String::new(),
        },
        target_resolution: TargetResolution::ExactMatch,
        selector_verification: intermed_mixin_intel::SelectorVerification::MatchesByConstruction,
        selector_offsets: vec![0],
        signature_check: SignatureCheck::CompatibleShape,
        local_capture_status: intermed_mixin_intel::LocalCaptureStatus::NoLocalCapture,
        side: Side::Both,
        activation: ActivationStatus::ActiveConfirmed,
        priority: 1000,
        require: None,
        expect: None,
        allow: None,
        cancellable: false,
        handler_effect: None,
        confidence: 100,
        imprecision_reasons: Vec::new(),
        precision: SitePrecision {
            identity: 100,
            activation: 100,
            verification: 100,
            effect: 100,
        },
    }
}

#[test]
fn measured_layer_f_corpus_has_no_known_false_positive_or_negative() {
    let mut target = Counts::default();
    let mut index = TargetClassIndex::new();
    index.ingest_class(
        &intermed_mixin_intel::fixtures::mixin_class_with_handler_bytecode(
            "mod/Target",
            "net/minecraft/Foo",
        ),
    );
    target.observe(
        true,
        matches!(
            index.resolve_method(
                "mod.Target",
                "handler",
                Some("(Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfo;)V"),
                None
            ),
            TargetResolution::ExactMatch
        ),
    );
    target.observe(
        false,
        matches!(
            index.resolve_method("mod.Target", "missing", Some("()V"), None),
            TargetResolution::ExactMatch
        ),
    );
    target.assert_perfect("target-resolution");

    let mut selector = Counts::default();
    let target_method = "handler(Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfo;)V";
    selector.observe(
        true,
        index
            .verify_selector(
                "mod.Target",
                target_method,
                "INVOKE",
                "Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfo;cancel()V",
                None,
                None,
            )
            .is_matched(),
    );
    selector.observe(
        false,
        index
            .verify_selector(
                "mod.Target",
                target_method,
                "INVOKE",
                "Lwrong/Owner;cancel()V",
                None,
                None,
            )
            .is_matched(),
    );
    selector.assert_perfect("selector");

    let mut signature = Counts::default();
    signature.observe(
        true,
        !check_handler_signature_with_target(
            "inject",
            "(Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfo;)V",
            Some("()V"),
            None,
        )
        .0
        .is_failure(),
    );
    signature.observe(
        false,
        !check_handler_signature_with_target("inject", "(I)V", Some("()V"), None)
            .0
            .is_failure(),
    );
    signature.assert_perfect("signature");

    let mut runtime = Counts::default();
    let s = site("runtime", "inject");
    let exact = RuntimeMixinFailure {
        exception_type: "InvalidInjectionException".into(),
        config: s.config_path.clone(),
        mixin_class: s.mixin_class.clone(),
        target_class: s.target_class.clone(),
        handler_method: s.handler_method.clone(),
        injection_point: s.target_method.clone(),
        reason: RuntimeFailureReason::InjectionPointNotFound,
        excerpt: "sanitized".into(),
    };
    runtime.observe(
        true,
        confirm_sites(&[exact], std::slice::from_ref(&s))[0].confirmed,
    );
    let weak = RuntimeMixinFailure {
        mixin_class: "runtimeMixin".into(),
        injection_point: String::new(),
        config: s.config_path.clone(),
        exception_type: String::new(),
        target_class: String::new(),
        handler_method: String::new(),
        reason: RuntimeFailureReason::Unknown,
        excerpt: String::new(),
    };
    runtime.observe(
        false,
        confirm_sites(&[weak], std::slice::from_ref(&s))[0].confirmed,
    );
    runtime.assert_perfect("runtime-confirmation");

    let mut composition = Counts::default();
    let redirects = analyze_compositions(&[site("a", "redirect"), site("b", "redirect")]);
    composition.observe(
        true,
        redirects[0].classification == CompositionClass::HighConflict,
    );
    let observers = analyze_compositions(&[site("c", "inject"), site("d", "inject")]);
    composition.observe(
        false,
        observers[0].classification == CompositionClass::HighConflict,
    );
    composition.assert_perfect("composition");

    let _ = PrecisionProfile::Forensic; // corpus is the full-depth policy gate.
}
