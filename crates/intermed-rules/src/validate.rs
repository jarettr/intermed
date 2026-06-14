//! Rule-pack structural validation.

use std::collections::BTreeSet;

use crate::model::{RuleKind, RulePack, RULE_PACK_SCHEMA, RULE_PACK_SCHEMA_V2};
use crate::template::{parse_category, parse_severity};
use crate::RulePackError;

/// Validate pack schema, rule ids, and per-kind required fields.
pub fn validate_rule_pack(pack: &RulePack) -> Result<(), RulePackError> {
    if pack.schema != RULE_PACK_SCHEMA && pack.schema != RULE_PACK_SCHEMA_V2 {
        return Err(RulePackError(format!(
            "unsupported rule-pack schema: {}",
            pack.schema
        )));
    }
    if pack.id.trim().is_empty() {
        return Err(RulePackError("rule pack id is empty".into()));
    }
    if pack.rules.is_empty() {
        return Err(RulePackError("rule pack has no rules".into()));
    }

    let mut ids = BTreeSet::new();
    for rule in &pack.rules {
        if !ids.insert(rule.id.as_str()) {
            return Err(RulePackError(format!("duplicate rule id: {}", rule.id)));
        }
        if parse_severity(&rule.finding.severity).is_none() {
            return Err(RulePackError(format!(
                "{}: invalid severity {}",
                rule.id, rule.finding.severity
            )));
        }
        if parse_category(&rule.finding.category).is_none() {
            return Err(RulePackError(format!(
                "{}: invalid category {}",
                rule.id, rule.finding.category
            )));
        }
        validate_rule_shape(rule)?;
        validate_rule_expressions(rule)?;
    }
    Ok(())
}

/// Parse-check every boolean-expression field on a rule.
///
/// A clause that does not parse silently evaluates to `false` for every row at
/// runtime (the interpreter swallows parse errors), so a typo in an `on` /
/// `where` / `having` / `match_on` clause would otherwise make a rule match
/// nothing with no diagnostic. Rejecting it at load time turns that into a clear
/// authoring error.
fn validate_rule_expressions(rule: &crate::model::RuleSpec) -> Result<(), RulePackError> {
    let known = known_aliases(rule);
    for (field, expr) in [
        ("on", rule.on.as_deref()),
        ("where", rule.r#where.as_deref()),
        ("having", rule.having.as_deref()),
        ("match_on", rule.match_on.as_deref()),
    ] {
        if let Some(expr) = expr.map(str::trim).filter(|s| !s.is_empty()) {
            crate::expr::check_expr(expr).map_err(|msg| {
                RulePackError(format!("{}: invalid `{field}` expression: {msg}", rule.id))
            })?;
            // Catch a misspelled alias (`m.loder`) that parses but never resolves.
            for alias in crate::expr::referenced_aliases(expr) {
                if !known.contains(alias.as_str()) {
                    return Err(RulePackError(format!(
                        "{}: `{field}` references unknown alias `{alias}` (known: {})",
                        rule.id,
                        known.iter().cloned().collect::<Vec<_>>().join(", ")
                    )));
                }
            }
        }
    }
    Ok(())
}

/// The set of aliases an expression on `rule` may legitimately reference.
fn known_aliases(rule: &crate::model::RuleSpec) -> std::collections::BTreeSet<String> {
    let mut set = std::collections::BTreeSet::new();
    if let Some(l) = &rule.left {
        set.insert(l.alias.clone());
    }
    if let Some(r) = &rule.right {
        set.insert(r.alias.clone());
    }
    if let Some(i) = &rule.input {
        set.insert(i.alias.clone());
    }
    if let Some(a) = &rule.anchor {
        set.insert(a.alias.clone());
    }
    // Correlation/evidence joins use the conventional `primary`/`related` aliases;
    // fact-finding binds its single fact under `alias` (default `f`).
    set.insert("primary".to_string());
    set.insert("related".to_string());
    set.insert(rule.alias.clone().unwrap_or_else(|| "f".to_string()));
    set
}

fn validate_rule_shape(rule: &crate::model::RuleSpec) -> Result<(), RulePackError> {
    match rule.kind {
        RuleKind::GroupDistinct => {
            if rule.input_kinds.is_empty() {
                return Err(RulePackError(format!(
                    "{}: input_kinds must not be empty",
                    rule.id
                )));
            }
            if rule.group_by.is_none() || rule.distinct.is_none() || rule.min_count < 2 {
                return Err(RulePackError(format!(
                    "{}: group-distinct requires group_by, distinct, min_count >= 2",
                    rule.id
                )));
            }
        }
        RuleKind::FactFinding => {
            if rule.input_kinds.is_empty() {
                return Err(RulePackError(format!(
                    "{}: input_kinds must not be empty",
                    rule.id
                )));
            }
        }
        RuleKind::Join => {
            let (Some(left), Some(right)) = (&rule.left, &rule.right) else {
                return Err(RulePackError(format!(
                    "{}: join requires left and right fact sources",
                    rule.id
                )));
            };
            validate_fact_source(rule.id.as_str(), left)?;
            validate_fact_source(rule.id.as_str(), right)?;
            if rule.on.as_ref().is_none_or(|s| s.trim().is_empty()) {
                return Err(RulePackError(format!(
                    "{}: join requires non-empty on expression",
                    rule.id
                )));
            }
        }
        RuleKind::Aggregate => {
            let Some(input) = &rule.input else {
                return Err(RulePackError(format!(
                    "{}: aggregate requires input fact source",
                    rule.id
                )));
            };
            validate_fact_source(rule.id.as_str(), input)?;
            if rule.group_by_fields.is_empty() && rule.group_by.is_none() {
                return Err(RulePackError(format!(
                    "{}: aggregate requires group_by or group_by_fields",
                    rule.id
                )));
            }
        }
        RuleKind::Correlation => {
            let Some(anchor) = &rule.anchor else {
                return Err(RulePackError(format!(
                    "{}: correlation requires anchor fact source",
                    rule.id
                )));
            };
            validate_fact_source(rule.id.as_str(), anchor)?;
            if rule.related_kinds.is_empty() {
                return Err(RulePackError(format!(
                    "{}: correlation requires related_kinds",
                    rule.id
                )));
            }
            if rule.match_on.as_ref().is_none_or(|s| s.trim().is_empty()) {
                return Err(RulePackError(format!(
                    "{}: correlation requires match_on expression",
                    rule.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_fact_source(rule_id: &str, source: &crate::model::FactSource) -> Result<(), RulePackError> {
    if source.kind.trim().is_empty() {
        return Err(RulePackError(format!("{rule_id}: fact source kind is empty")));
    }
    if source.alias.trim().is_empty() {
        return Err(RulePackError(format!("{rule_id}: fact source alias is empty")));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use crate::pack::parse_rule_pack;

    const PACK: &str = r#"{
      "schema": "intermed-rule-pack-v2", "id": "t", "version": "1", "publisher": "t",
      "rules": [{
        "id": "typo", "kind": "join",
        "left": {"kind": "mod", "alias": "m", "select": ["subject"]},
        "right": {"kind": "environment", "alias": "e", "select": ["attr:loader"]},
        "on": "TRUE", "where": "ALIAS.loader = 'fabric'",
        "finding": {"id": "x:{m.subject}", "severity": "warn", "category": "loader",
          "title": "t", "explanation": "e"}
      }]
    }"#;

    #[test]
    fn unknown_alias_in_where_is_rejected() {
        let bad = PACK.replace("ALIAS", "zzz");
        let err = parse_rule_pack(&bad, "t.json").unwrap_err();
        assert!(err.0.contains("unknown alias `zzz`"), "got: {}", err.0);
    }

    #[test]
    fn known_alias_in_where_is_accepted() {
        let good = PACK.replace("ALIAS", "m");
        assert!(parse_rule_pack(&good, "t.json").is_ok());
    }
}
