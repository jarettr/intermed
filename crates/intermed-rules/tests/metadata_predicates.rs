use intermed_doctor_core::facts::{FactStore, kind};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};
use intermed_rules::{DeclarativeRulePack, default_core_pack_v2, parse_rule_pack};

fn test_target() -> Target {
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

/// The embedded core `corrupt-jar` rule must fire on a genuinely unreadable
/// archive (`failure_class = corrupt`) but stay silent for a benign library jar
/// without a manifest (`failure_class = no-manifest`).
#[test]
fn corrupt_jar_rule_fires_only_on_corruption() {
    let pack = default_core_pack_v2();

    let mut corrupt = FactStore::new();
    corrupt
        .fact("metadata-scanner", kind::UNPARSEABLE_ARCHIVE)
        .subject("broken.jar")
        .attr("reason", "zip: invalid Zip archive")
        .attr("failure_class", "corrupt")
        .emit();
    let target = test_target();
    let ctx = RuleCtx::for_test(&corrupt, &target);
    let findings = DeclarativeRulePack::new(pack.clone())
        .expect("declarative pack")
        .evaluate(&ctx);
    assert!(
        findings.iter().any(|f| f.id == "corrupt-jar:broken.jar"),
        "corrupt jar should be flagged, got: {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );

    let mut benign = FactStore::new();
    benign
        .fact("metadata-scanner", kind::UNPARSEABLE_ARCHIVE)
        .subject("lib.jar")
        .attr("reason", "no recognised manifest")
        .attr("failure_class", "no-manifest")
        .emit();
    let ctx = RuleCtx::for_test(&benign, &target);
    let findings = DeclarativeRulePack::new(pack)
        .expect("declarative pack")
        .evaluate(&ctx);
    assert!(
        !findings.iter().any(|f| f.id.starts_with("corrupt-jar:")),
        "library jar without manifest must not be flagged as corrupt"
    );
}

#[test]
fn rule_packs_can_consume_metadata_intelligence_predicates() {
    let pack = parse_rule_pack(
        r#"{
          "schema":"intermed-rule-pack-v2",
          "id":"metadata-intel-test",
          "version":"1.0.0",
          "rules":[{
            "id":"tick-hook",
            "kind":"fact-finding",
            "input_kinds":["mod_capability"],
            "where_all":{"attr:capability":"hooks_game_tick"},
            "finding":{
              "id":"tick-hook:{subject}",
              "severity":"note",
              "category":"metadata",
              "title":"{subject} hooks the game tick",
              "explanation":"Capability evidence: {attr:reason}",
              "tags":["metadata","capability"]
            }
          }]
        }"#,
        "metadata-intel-test.json",
    )
    .expect("valid rule pack");
    let mut store = FactStore::new();
    store
        .fact("metadata-scanner", kind::MOD_CAPABILITY)
        .subject("example")
        .attr("capability", "hooks_game_tick")
        .attr("reason", "entrypoint subscribes to tick events")
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
    let findings = DeclarativeRulePack::new(pack)
        .expect("valid declarative pack")
        .evaluate(&ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "tick-hook:example");
}

/// A `join` whose `on` is a disjunction must still find pairs that match only
/// the *second* branch. The optimizer previously extracted an equijoin key from
/// inside the `OR` and used it as a mandatory hash-index lookup, so such pairs
/// were never even considered. The match here exists only via `a.attr:provides
/// = b.subject`, never via `a.subject = b.subject`.
#[test]
fn join_with_or_finds_second_branch_match() {
    let pack = parse_rule_pack(
        r#"{
          "schema":"intermed-rule-pack-v2",
          "id":"or-join-test",
          "version":"1.0.0",
          "rules":[{
            "id":"alias-provider",
            "kind":"join",
            "left":{"kind":"mod","alias":"a","select":["subject","attr:provides"]},
            "right":{"kind":"mod","alias":"b","select":["subject"]},
            "on":"a.subject = b.subject OR a.attr:provides = b.subject",
            "where":"a.subject != b.subject",
            "finding":{
              "id":"alias-provider:{a.subject}->{b.subject}",
              "severity":"note",
              "category":"metadata",
              "title":"{a.subject} provides {b.subject}",
              "explanation":"matched via provides alias",
              "tags":["metadata"]
            }
          }]
        }"#,
        "or-join-test.json",
    )
    .expect("valid rule pack");

    let mut store = FactStore::new();
    // `alpha` provides the id `target`; the join must connect them even though
    // their subjects differ (so only the OR's second branch matches).
    store
        .fact("metadata-scanner", kind::MOD)
        .subject("alpha")
        .attr("provides", "target")
        .emit();
    store
        .fact("metadata-scanner", kind::MOD)
        .subject("target")
        .emit();

    let target = test_target();
    let findings = DeclarativeRulePack::new(pack)
        .expect("valid declarative pack")
        .evaluate(&RuleCtx::for_test(&store, &target));

    assert_eq!(
        findings.len(),
        1,
        "expected the alias-only match, got: {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    assert_eq!(findings[0].id, "alias-provider:alpha->target");
}
