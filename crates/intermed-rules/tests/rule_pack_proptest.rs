//! Property tests for declarative rule-pack validation invariants.

use intermed_rules::{default_core_pack, validate_rule_pack, RuleKind, RulePack, RuleSpec};
use proptest::prelude::*;

fn valid_core_pack() -> RulePack {
    default_core_pack()
}

proptest! {
    #[test]
    fn default_core_pack_always_valid(_seed in any::<u64>()) {
        let pack = valid_core_pack();
        prop_assert!(validate_rule_pack(&pack).is_ok());
    }

    #[test]
    fn empty_input_kinds_is_rejected(_seed in any::<u64>()) {
        let mut pack = valid_core_pack();
        pack.rules[0].input_kinds.clear();
        prop_assert!(validate_rule_pack(&pack).is_err());
    }

    #[test]
    fn group_distinct_requires_min_count_at_least_two(min_count in 0usize..2) {
        let mut pack = valid_core_pack();
        if let Some(rule) = pack.rules.iter_mut().find(|r| matches!(r.kind, RuleKind::GroupDistinct)) {
            rule.min_count = min_count;
            prop_assert!(validate_rule_pack(&pack).is_err());
        }
    }

    #[test]
    fn duplicate_rule_ids_are_rejected(suffix in "[a-z]{1,6}") {
        let mut pack = valid_core_pack();
        let clone = pack.rules[0].clone();
        pack.rules.push(RuleSpec {
            id: clone.id.clone(),
            ..clone
        });
        prop_assert!(validate_rule_pack(&pack).is_err());
        let _ = suffix;
    }

    #[test]
    fn invalid_severity_is_rejected(severity in "[0-9]{1,4}") {
        let mut pack = valid_core_pack();
        pack.rules[0].finding.severity = severity;
        prop_assert!(validate_rule_pack(&pack).is_err());
    }

    #[test]
    fn malformed_where_expression_is_rejected(garbage in "[a-z]{1,6}") {
        // A clause that doesn't parse silently evaluates to `false` at runtime,
        // so it must be caught at load time instead of matching nothing.
        let mut pack = valid_core_pack();
        pack.rules[0].r#where = Some(format!("{garbage} = "));
        prop_assert!(validate_rule_pack(&pack).is_err());
    }

    #[test]
    fn wrong_schema_is_rejected(schema in "[a-z-]{3,20}") {
        prop_assume!(schema != intermed_rules::RULE_PACK_SCHEMA);
        let mut pack = valid_core_pack();
        pack.schema = schema;
        prop_assert!(validate_rule_pack(&pack).is_err());
    }
}
