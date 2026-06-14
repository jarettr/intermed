//! Soufflé Datalog generation from declarative [`RulePack`] rules.

use crate::model::{RuleKind, RulePack, RuleSpec};

/// Generated `.dl` fragment for one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedDatalogRule {
    pub id: String,
    pub datalog: String,
}

/// Generate Soufflé relations and rules for `pack`.
pub fn generate_pack_datalog(pack: &RulePack) -> String {
    let mut out = String::from(header());
    for rule in &pack.rules {
        if let Some(fragment) = rule_to_datalog(rule) {
            out.push_str(&fragment);
            out.push('\n');
        }
    }
    out
}

/// List per-rule Datalog fragments (for CLI `rules generate --backend datalog`).
pub fn generate_pack_datalog_rules(pack: &RulePack) -> Vec<GeneratedDatalogRule> {
    pack.rules
        .iter()
        .filter_map(|rule| {
            rule_to_datalog(rule).map(|datalog| GeneratedDatalogRule {
                id: rule.id.clone(),
                datalog,
            })
        })
        .collect()
}

fn header() -> &'static str {
    r"# Generated from intermed-rule-pack-v2 — do not edit by hand.
.decl mod_decl(id:symbol, file:symbol, fact:symbol)
.input mod_decl
"
}

fn rule_to_datalog(rule: &RuleSpec) -> Option<String> {
    match rule.kind {
        RuleKind::GroupDistinct if rule.id.contains("duplicate") => Some(
            r".decl duplicate_id(id:symbol)
.output duplicate_id
duplicate_id(id) :- mod_decl(id, f1, _), mod_decl(id, f2, _), f1 != f2.
"
            .to_string(),
        ),
        RuleKind::FactFinding if rule.input_kinds.iter().any(|k| k == "mixin_overlap") => {
            Some(mixin_overlap_dl())
        }
        RuleKind::FactFinding if rule.input_kinds.iter().any(|k| k == "high_risk_overwrite") => {
            Some(mixin_overwrite_dl())
        }
        // Join / Aggregate / Correlation and any future kinds have no Datalog
        // lowering yet.
        _ => None,
    }
}

fn mixin_overlap_dl() -> String {
    r".decl mixin_overlap_input(target:symbol, mods:symbol, operations:symbol, hot:symbol, fact:symbol)
.input mixin_overlap_input
.decl mixin_overlap_out(target:symbol, mods:symbol, operations:symbol, hot:symbol, fact:symbol)
.output mixin_overlap_out
mixin_overlap_out(t, m, o, h, f) :- mixin_overlap_input(t, m, o, h, f).
"
    .to_string()
}

fn mixin_overwrite_dl() -> String {
    r".decl mixin_overwrite_input(mod:symbol, target:symbol, hot:symbol, fact:symbol)
.input mixin_overwrite_input
.decl mixin_overwrite_out(mod:symbol, target:symbol, hot:symbol, fact:symbol)
.output mixin_overwrite_out
mixin_overwrite_out(m, t, h, f) :- mixin_overwrite_input(m, t, h, f).
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::default_core_pack_v2;

    #[test]
    fn generates_duplicate_id_relation() {
        let dl = generate_pack_datalog(&default_core_pack_v2());
        assert!(dl.contains(".decl duplicate_id"));
    }
}