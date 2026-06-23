use std::io::Write;

use intermed_doctor_core::facts::{FactStore, SourceRef, kind};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};
use intermed_rules::{SouffleRulePack, escape_souffle_symbol, escape_tsv_field};

#[test]
fn escape_tsv_adversarial_inputs() {
    assert_eq!(escape_tsv_field(""), "\"\"");
    assert_eq!(escape_tsv_field("mod\tid"), "\"mod\tid\"");
    assert_eq!(escape_tsv_field("line\nbreak"), "\"line\nbreak\"");
    assert_eq!(escape_tsv_field("quote\"field"), "\"quote\"\"field\"");
    assert_eq!(escape_tsv_field(r"back\slash"), r#""back\slash""#);
    assert_eq!(escape_tsv_field("unicode:🎮"), "unicode:🎮");
}

#[test]
fn escape_souffle_has_no_raw_tabs_or_newlines() {
    for input in [
        "mod\tid",
        "line\nbreak",
        "a\r\nb",
        "back\\slash",
        " spaced ",
    ] {
        let escaped = escape_souffle_symbol(input);
        assert!(!escaped.contains('\t'));
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
    }
}

#[test]
fn souffle_facts_golden_mod_decl_line() {
    let adversarial_id = "mod\twith\nnewline";
    let adversarial_file = r#"path"with\quote"#;

    let mut store = FactStore::new();
    store
        .fact("test", kind::MOD)
        .subject(adversarial_id)
        .attr("file", adversarial_file)
        .source(SourceRef::file(adversarial_file))
        .emit();

    let target = Target {
        path: ".".into(),
        kind: TargetKind::ModsDir,
        mods_dir: None,
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let ctx = RuleCtx::for_test(&store, &target);

    let mut buf = Vec::new();
    for fact in ctx.store.by_kind(kind::MOD) {
        let file = fact.attr("file").unwrap_or(&fact.source.locator);
        writeln!(
            buf,
            "{}\t{}\t{}",
            escape_souffle_symbol(&fact.subject),
            escape_souffle_symbol(file),
            fact.id
        )
        .unwrap();
    }

    let actual = String::from_utf8(buf).unwrap();
    assert!(actual.contains(r"mod\twith\nnewline"));
    assert!(actual.contains(r#"path"with\\quote"#));
}

#[test]
fn souffle_rule_pack_accepts_adversarial_subjects_when_available() {
    if !intermed_rules::souffle_available() {
        return;
    }
    let mut store = FactStore::new();
    store
        .fact("test", kind::MOD)
        .subject("dup\tid")
        .attr("file", "a.jar")
        .source(SourceRef::file("a.jar"))
        .emit();
    store
        .fact("test", kind::MOD)
        .subject("dup\tid")
        .attr("file", "b.jar")
        .source(SourceRef::file("b.jar"))
        .emit();

    let target = Target {
        path: ".".into(),
        kind: TargetKind::ModsDir,
        mods_dir: None,
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let ctx = RuleCtx::for_test(&store, &target);
    let findings = SouffleRulePack::default().evaluate(&ctx);
    assert!(findings.iter().any(|f| f.id.contains("duplicate-id")));
}
