//! Loot table domain (`data/<ns>/loot_table[s]/<path>.json`): references the
//! items / tags its entries can drop.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::DomainParse;
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

pub const LOOT_TABLE_AST_VERSION: &str = "loot-table-r1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LootTableSummary {
    pub pool_count: usize,
    pub entry_count: usize,
    /// Sorted dropped item/tag ids.
    pub drops: Vec<String>,
}

/// Parse a loot table resource.
pub fn parse(value: &Value) -> DomainParse {
    let Some(obj) = value.as_object() else {
        return DomainParse::invalid(vec![diag("loot table root is not a JSON object")]);
    };
    let mut references = Vec::new();
    let mut drops = Vec::new();
    let mut entry_count = 0;

    let pools = obj.get("pools").and_then(Value::as_array);
    let pool_count = pools.map_or(0, Vec::len);
    if let Some(pools) = pools {
        for pool in pools {
            if let Some(entries) = pool.get("entries").and_then(Value::as_array) {
                for entry in entries {
                    entry_count += 1;
                    collect_entry(entry, &mut references, &mut drops);
                }
            }
        }
    }
    drops.sort();
    drops.dedup();

    DomainParse {
        summary: ResourceSummary::LootTable(LootTableSummary {
            pool_count,
            entry_count,
            drops,
        }),
        references,
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
    }
}

/// A loot entry of `type` `item`/`tag` names the resource in its `name` field.
fn collect_entry(entry: &Value, refs: &mut Vec<ResourceReference>, drops: &mut Vec<String>) {
    let Some(obj) = entry.as_object() else { return };
    let entry_type = obj.get("type").and_then(Value::as_str).unwrap_or("");
    if let Some(name) = obj.get("name").and_then(Value::as_str) {
        let is_tag = entry_type.ends_with("tag");
        drops.push(name.to_string());
        refs.push(ResourceReference {
            relation: RefRelation::LootEntry,
            namespace: namespace_of(name),
            target: name.to_string(),
            required: true,
            conditioned: false,
            is_tag,
        });
    }
    // Nested children (`type: alternatives`/`group`/`sequence`).
    if let Some(children) = obj.get("children").and_then(Value::as_array) {
        for child in children {
            collect_entry(child, refs, drops);
        }
    }
}

fn diag(message: &str) -> crate::model::ResourceParseDiagnostic {
    crate::model::ResourceParseDiagnostic {
        severity: crate::model::DiagnosticSeverity::Error,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loot_table_drops() {
        let v = serde_json::from_str(
            r#"{"pools":[{"entries":[{"type":"minecraft:item","name":"create:zinc_ingot"}]}]}"#,
        )
        .unwrap();
        let p = parse(&v);
        let ResourceSummary::LootTable(s) = &p.summary else { panic!() };
        assert_eq!(s.pool_count, 1);
        assert!(s.drops.contains(&"create:zinc_ingot".to_string()));
    }
}
