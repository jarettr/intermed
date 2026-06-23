//! Predicate domain (`data/<ns>/predicate[s]/<path>.json`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{DomainParse, parse_conditions};
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

pub const PREDICATE_AST_VERSION: &str = "predicate-r2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateSummary {
    pub has_conditions: bool,
}

pub fn parse(value: &Value) -> DomainParse {
    // Predicates can be an object or an array of objects
    let conditions = if let Some(obj) = value.as_object() {
        parse_conditions(obj)
    } else {
        Vec::new()
    };

    let mut references = Vec::new();
    collect_refs(value, &conditions, &mut references);

    DomainParse {
        summary: ResourceSummary::Predicate(PredicateSummary {
            has_conditions: !conditions.is_empty(),
        }),
        references,
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
    }
}

fn collect_refs(
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
            if let Some(lt) = map.get("loot_table").and_then(Value::as_str) {
                push_ref(lt, RefRelation::LootEntry, false, conditions, refs);
            }
            for v in map.values() {
                collect_refs(v, conditions, refs);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_refs(v, conditions, refs);
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
