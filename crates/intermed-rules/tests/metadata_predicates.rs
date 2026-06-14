use intermed_doctor_core::facts::{kind, FactStore};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};
use intermed_rules::{parse_rule_pack, DeclarativeRulePack};

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
