use intermed_doctor_core::facts::{kind, FactStore};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};
use intermed_security_audit::rule;

fn dummy_target() -> Target {
    Target {
        path: ".".into(),
        kind: TargetKind::ModsDir,
        mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
        spark_report: None,
    }
}

#[test]
fn grouped_finding_emits_one_entry_per_mod_with_warn_for_process_spawn() {
    let mut store = FactStore::new();
    store
        .fact("security-scanner", kind::USES_PROCESS_SPAWN)
        .subject("risky")
        .attr("archive", "risky.jar")
        .emit();

    let target = dummy_target();
    let ctx = RuleCtx::for_test(&store, &target);
    let findings = rule().evaluate(&ctx);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "security-api-risk:risky");
    assert_eq!(
        findings[0].severity,
        intermed_doctor_core::evidence::Severity::Warn
    );
    assert!(findings[0].title.contains("1 security API signal"));
    assert!(findings[0].confidence > 0.5);
}

#[test]
fn single_note_signal_does_not_emit_finding() {
    let mut store = FactStore::new();
    store
        .fact("security-scanner", kind::USES_SOCKET)
        .subject("netty")
        .attr("archive", "netty.jar")
        .emit();

    let target = dummy_target();
    let ctx = RuleCtx::for_test(&store, &target);
    let findings = rule().evaluate(&ctx);

    assert!(findings.is_empty());
}

#[test]
fn two_note_signals_emit_grouped_note_finding() {
    let mut store = FactStore::new();
    store
        .fact("security-scanner", kind::USES_SOCKET)
        .subject("netty")
        .attr("archive", "netty.jar")
        .emit();
    store
        .fact("security-scanner", kind::USES_NATIVE_LIBRARY)
        .subject("netty")
        .attr("archive", "netty.jar")
        .emit();

    let target = dummy_target();
    let ctx = RuleCtx::for_test(&store, &target);
    let findings = rule().evaluate(&ctx);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "security-api-risk:netty");
    assert_eq!(
        findings[0].severity,
        intermed_doctor_core::evidence::Severity::Note
    );
}

#[test]
fn corroborated_process_spawn_surfaces_as_warn_and_is_marked_inferred() {
    let mut store = FactStore::new();
    // Structural reflection machinery.
    store
        .fact("security-scanner", kind::USES_REFLECTION_SET_ACCESSIBLE)
        .subject("sneaky")
        .attr("archive", "sneaky.jar")
        .attr("provenance", "structural")
        .emit();
    // Process spawn established only by string corroboration (low confidence).
    store
        .fact("security-scanner", kind::USES_PROCESS_SPAWN)
        .subject("sneaky")
        .attr("archive", "sneaky.jar")
        .attr("provenance", "reflection-corroborated")
        .confidence(0.4)
        .emit();

    let target = dummy_target();
    let ctx = RuleCtx::for_test(&store, &target);
    let findings = rule().evaluate(&ctx);

    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    // The corroborated high-risk capability drives Warn severity.
    assert_eq!(
        finding.severity,
        intermed_doctor_core::evidence::Severity::Warn
    );
    // …but it is transparently labelled as inferred, not asserted as fact.
    assert!(finding.explanation.contains("low confidence"));
    assert!(finding
        .machine_tags
        .iter()
        .any(|t| t == "reflection-corroborated"));
}
