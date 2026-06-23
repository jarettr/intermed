//! Advancement domain (`data/<ns>/advancement[s]/<path>.json`).
//!
//! Parses advancements to extract rewards (loot tables, recipes, experience) and
//! criteria triggers (e.g., inventory_changed items).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{DomainParse, parse_conditions};
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

pub const ADVANCEMENT_AST_VERSION: &str = "advancement-r2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvancementSummary {
    pub parent: Option<String>,
    pub criteria_count: usize,
    pub has_rewards: bool,
    pub has_conditions: bool,
}

pub fn parse(value: &Value) -> DomainParse {
    let Some(obj) = value.as_object() else {
        return DomainParse::invalid(vec![diag("advancement root is not a JSON object")]);
    };

    let conditions = parse_conditions(obj);
    let mut references = Vec::new();

    let parent = obj.get("parent").and_then(Value::as_str).map(String::from);
    if let Some(ref p) = parent {
        let p = p.trim_start_matches('#').to_string();
        references.push(ResourceReference {
            relation: RefRelation::AdvancementCriterion, // Not entirely correct relation, but acceptable for generic deps. Or add ParentAdvancement. Let's reuse.
            namespace: namespace_of(&p),
            target: p,
            required: conditions.is_empty(),
            conditions: conditions.clone(),
            is_tag: false,
        });
    }

    let mut criteria_count = 0;
    if let Some(criteria) = obj.get("criteria").and_then(Value::as_object) {
        criteria_count = criteria.len();
        for (_, crit) in criteria {
            collect_trigger_refs(crit, &conditions, &mut references);
        }
    }

    let has_rewards = obj.contains_key("rewards");
    if let Some(rewards) = obj.get("rewards").and_then(Value::as_object) {
        if let Some(loot) = rewards.get("loot").and_then(Value::as_array) {
            for l in loot {
                if let Some(s) = l.as_str() {
                    let t = s.to_string();
                    references.push(ResourceReference {
                        relation: RefRelation::LootEntry,
                        namespace: namespace_of(&t),
                        target: t,
                        required: conditions.is_empty(),
                        conditions: conditions.clone(),
                        is_tag: false,
                    });
                }
            }
        }
        if let Some(recipes) = rewards.get("recipes").and_then(Value::as_array) {
            for r in recipes {
                if let Some(s) = r.as_str() {
                    let t = s.to_string();
                    references.push(ResourceReference {
                        // technically rewards a recipe, but ProducesItem or similar. UsesItem is generic enough for dependencies.
                        relation: RefRelation::UsesItem,
                        namespace: namespace_of(&t),
                        target: t,
                        required: conditions.is_empty(),
                        conditions: conditions.clone(),
                        is_tag: false,
                    });
                }
            }
        }
    }

    DomainParse {
        summary: ResourceSummary::Advancement(AdvancementSummary {
            parent,
            criteria_count,
            has_rewards,
            has_conditions: !conditions.is_empty(),
        }),
        references,
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
    }
}

fn collect_trigger_refs(
    value: &Value,
    conditions: &[crate::model::ResourceCondition],
    refs: &mut Vec<ResourceReference>,
) {
    match value {
        Value::Object(map) => {
            if let Some(item) = map.get("item").and_then(Value::as_str) {
                push_ref(item, RefRelation::UsesItem, false, conditions, refs);
            }
            if let Some(tag) = map.get("tag").and_then(Value::as_str) {
                push_ref(tag, RefRelation::UsesTag, true, conditions, refs);
            }
            for v in map.values() {
                collect_trigger_refs(v, conditions, refs);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_trigger_refs(v, conditions, refs);
            }
        }
        _ => {}
    }
}

fn push_ref(
    id: &str,
    relation: RefRelation,
    is_tag: bool,
    conditions: &[crate::model::ResourceCondition],
    refs: &mut Vec<ResourceReference>,
) {
    let target = id.trim_start_matches('#').to_string();
    refs.push(ResourceReference {
        relation,
        namespace: namespace_of(&target),
        target,
        required: conditions.is_empty(),
        conditions: conditions.to_vec(),
        is_tag,
    });
}

fn diag(message: &str) -> crate::model::ResourceParseDiagnostic {
    crate::model::ResourceParseDiagnostic {
        severity: crate::model::DiagnosticSeverity::Error,
        message: message.to_string(),
    }
}
