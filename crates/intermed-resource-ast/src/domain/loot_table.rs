//! Loot table domain (`data/<ns>/loot_table[s]/<path>.json`): references the
//! items / tags its entries can drop.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::DomainParse;
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

pub const LOOT_TABLE_AST_VERSION: &str = "loot-table-r2";

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

/// A loot entry names a resource in its `name` field; the *kind* of resource
/// depends on the entry `type`:
/// * `minecraft:loot_table` → a reference to **another loot-table file**
///   (`LootEntry`) — the only kind resolvable to a file (dangling-checkable).
/// * `minecraft:tag` → an item tag (`UsesTag`).
/// * everything else (`minecraft:item`, …) → a dropped **item id**, which is
///   code-registered, *not* a file — so it must NOT be treated as a loot-table
///   reference (doing so produced thousands of false "dangling reference" notes).
fn collect_entry(entry: &Value, refs: &mut Vec<ResourceReference>, drops: &mut Vec<String>) {
    let Some(obj) = entry.as_object() else { return };
    let entry_type = obj.get("type").and_then(Value::as_str).unwrap_or("");
    if let Some(name) = obj.get("name").and_then(Value::as_str) {
        drops.push(name.to_string());
        let (relation, is_tag) = if entry_type.ends_with("loot_table") {
            (RefRelation::LootEntry, false)
        } else if entry_type.ends_with("tag") {
            (RefRelation::UsesTag, true)
        } else {
            (RefRelation::UsesItem, false)
        };
        refs.push(ResourceReference {
            relation,
            namespace: namespace_of(name),
            target: name.to_string(),
            required: true,
            conditions: Vec::new(),
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
        let ResourceSummary::LootTable(s) = &p.summary else {
            panic!()
        };
        assert_eq!(s.pool_count, 1);
        assert!(s.drops.contains(&"create:zinc_ingot".to_string()));
        // An item drop is NOT a loot-table file reference (must not be dangling-checked).
        assert!(
            p.references
                .iter()
                .all(|r| r.relation != RefRelation::LootEntry)
        );
        assert!(
            p.references
                .iter()
                .any(|r| r.relation == RefRelation::UsesItem)
        );
    }

    #[test]
    fn sub_table_reference_is_loot_entry() {
        let v = serde_json::from_str(
            r#"{"pools":[{"entries":[{"type":"minecraft:loot_table","name":"ad_astra:chests/lunar"}]}]}"#,
        )
        .unwrap();
        let p = parse(&v);
        // Only a `minecraft:loot_table` entry is a file reference (dangling-checkable).
        assert!(
            p.references.iter().any(
                |r| r.relation == RefRelation::LootEntry && r.target == "ad_astra:chests/lunar"
            )
        );
    }

    #[test]
    fn tag_entry_is_uses_tag() {
        let v = serde_json::from_str(
            r#"{"pools":[{"entries":[{"type":"minecraft:tag","name":"c:ingots"}]}]}"#,
        )
        .unwrap();
        let p = parse(&v);
        assert!(
            p.references
                .iter()
                .any(|r| r.relation == RefRelation::UsesTag && r.is_tag)
        );
    }
}
