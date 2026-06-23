//! Rule-pack merging for doctor runs.
//!
//! Community packs overlay the embedded core: rules with the same `id` replace
//! the base rule; new ids append. Pack metadata (`id`, `version`, `publisher`)
//! stays from the base so reports remain anchored to the InterMed core pack.

use crate::RulePackError;
use crate::model::RulePack;
use crate::validate::validate_rule_pack;

/// Overlay one or more packs onto `base`. Later overlays win on duplicate rule ids.
///
/// Each overlay is validated before merge. The merged result is validated again so
/// structural invariants (unique ids, valid severities) hold on the final pack.
pub fn merge_rule_packs(
    mut base: RulePack,
    overlays: impl IntoIterator<Item = RulePack>,
) -> Result<RulePack, RulePackError> {
    for overlay in overlays {
        validate_rule_pack(&overlay)?;
        for rule in overlay.rules {
            if let Some(pos) = base.rules.iter().position(|r| r.id == rule.id) {
                base.rules[pos] = rule;
            } else {
                base.rules.push(rule);
            }
        }
    }
    validate_rule_pack(&base)?;
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_core_pack_v2;
    use crate::model::{FindingTemplate, RuleKind, RuleSpec};
    use std::collections::BTreeMap;

    fn overlay_with_id(rule_id: &str) -> RulePack {
        let mut pack = default_core_pack_v2();
        pack.id = "community-overlay".to_string();
        pack.rules = vec![RuleSpec {
            id: rule_id.to_string(),
            alias: None,
            kind: RuleKind::FactFinding,
            input_kinds: vec!["mod".to_string()],
            where_all: BTreeMap::new(),
            where_not: BTreeMap::new(),
            group_by: None,
            group_by_fields: Vec::new(),
            distinct: None,
            min_count: 1,
            left: None,
            right: None,
            on: None,
            r#where: None,
            having: None,
            input: None,
            anchor: None,
            related_kinds: Vec::new(),
            match_on: None,
            settings_refs: BTreeMap::new(),
            evidence: None,
            finding: FindingTemplate {
                id: "overlay:{subject}".to_string(),
                rule_id: None,
                severity: "warn".to_string(),
                category: "metadata".to_string(),
                title: "overlay".to_string(),
                explanation: "overlay".to_string(),
                fix: None,
                tags: vec!["overlay".to_string()],
                affects: Vec::new(),
            },
        }];
        pack
    }

    #[test]
    fn replaces_existing_rule_by_id() {
        let base = default_core_pack_v2();
        let before = base.rules.len();
        let overlay = overlay_with_id("loader-mismatch");
        let merged = merge_rule_packs(base, [overlay]).expect("merge");
        assert_eq!(merged.rules.len(), before);
        let rule = merged
            .rules
            .iter()
            .find(|r| r.id == "loader-mismatch")
            .expect("rule");
        assert_eq!(rule.finding.title, "overlay");
    }

    #[test]
    fn appends_new_rule_ids() {
        let base = default_core_pack_v2();
        let before = base.rules.len();
        let overlay = overlay_with_id("community-custom-rule");
        let merged = merge_rule_packs(base, [overlay]).expect("merge");
        assert_eq!(merged.rules.len(), before + 1);
        assert!(merged.rules.iter().any(|r| r.id == "community-custom-rule"));
    }
}
