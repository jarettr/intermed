//! Recipe domain (`data/<ns>/recipe[s]/<path>.json`).
//!
//! Modded recipe schemas are open-ended, so this parser favours **generic
//! traversal** over a per-type schema: it reads `type`, walks output subtrees
//! (`result`/`output`/`outputs`/`results`) for produced items, treats every other
//! `item`/`tag` reference as an ingredient, and detects load `conditions`. That
//! is enough to drive same-id-different-output diffs and implicit-dependency
//! detection (a recipe `type` namespace that isn't installed).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::DomainParse;
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

/// Parser version — bump when recipe lowering changes (cache-invalidating).
pub const RECIPE_AST_VERSION: &str = "recipe-r1";

const OUTPUT_KEYS: &[&str] = &["result", "results", "output", "outputs"];

/// Compact recipe summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeSummary {
    pub recipe_type: String,
    pub ingredient_count: usize,
    pub output_count: usize,
    pub has_conditions: bool,
    /// Sorted output ids (the discriminator for same-id-different-output).
    pub outputs: Vec<String>,
    /// Sorted ingredient ids.
    pub ingredients: Vec<String>,
}

/// Parse a recipe resource.
pub fn parse(value: &Value) -> DomainParse {
    let Some(obj) = value.as_object() else {
        return DomainParse::invalid(vec![diag("recipe root is not a JSON object")]);
    };

    let recipe_type = obj
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let conditioned = has_conditions(obj);

    let mut references = Vec::new();

    // The recipe serializer type is itself a dependency (`create:crushing` ⇒ Create).
    if !recipe_type.is_empty() {
        references.push(ResourceReference {
            relation: RefRelation::UsesRecipeType,
            namespace: namespace_of(&recipe_type),
            target: recipe_type.clone(),
            required: true,
            conditioned,
            is_tag: false,
        });
    }

    // Outputs from the result subtrees.
    let mut outputs = Vec::new();
    for key in OUTPUT_KEYS {
        if let Some(v) = obj.get(*key) {
            collect_refs(v, RefRelation::ProducesItem, conditioned, &mut references, &mut outputs);
        }
    }

    // Ingredients = every other item/tag reference (the whole object except the
    // output subtrees and the type field).
    let mut ingredients = Vec::new();
    for (k, v) in obj {
        if OUTPUT_KEYS.contains(&k.as_str()) || k == "type" || k == "conditions" {
            continue;
        }
        collect_refs(v, RefRelation::UsesItem, conditioned, &mut references, &mut ingredients);
    }

    outputs.sort();
    outputs.dedup();
    ingredients.sort();
    ingredients.dedup();

    let summary = RecipeSummary {
        recipe_type,
        ingredient_count: ingredients.len(),
        output_count: outputs.len(),
        has_conditions: conditioned,
        outputs,
        ingredients,
    };

    DomainParse {
        summary: ResourceSummary::Recipe(summary),
        references,
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
    }
}

/// True when the recipe is gated by a forge/fabric load condition (so a missing
/// referenced namespace may be intentional).
fn has_conditions(obj: &serde_json::Map<String, Value>) -> bool {
    obj.get("conditions").is_some_and(|v| v.is_array() && !v.as_array().unwrap().is_empty())
        || obj.contains_key("fabric:load_conditions")
        || obj.contains_key("neoforge:conditions")
}

/// Recursively collect `item`/`tag` references from a value subtree. An object
/// with `"item": "ns:id"` is an item ref; `"tag": "ns:path"` is a tag ref. The
/// `default_relation` is `ProducesItem` for output subtrees, `UsesItem` otherwise
/// (tag refs always use `UsesTag`).
fn collect_refs(
    value: &Value,
    default_relation: RefRelation,
    conditioned: bool,
    refs: &mut Vec<ResourceReference>,
    ids: &mut Vec<String>,
) {
    match value {
        Value::Object(map) => {
            if let Some(item) = map.get("item").and_then(Value::as_str) {
                push_ref(item, default_relation, false, conditioned, refs, ids);
            }
            if let Some(tag) = map.get("tag").and_then(Value::as_str) {
                push_ref(tag, RefRelation::UsesTag, true, conditioned, refs, ids);
            }
            // A bare `"id"` is used by some result schemas.
            if !map.contains_key("item") && !map.contains_key("tag") {
                if let Some(id) = map.get("id").and_then(Value::as_str) {
                    if looks_like_resource_id(id) {
                        push_ref(id, default_relation, false, conditioned, refs, ids);
                    }
                }
            }
            for v in map.values() {
                collect_refs(v, default_relation, conditioned, refs, ids);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_refs(v, default_relation, conditioned, refs, ids);
            }
        }
        _ => {}
    }
}

fn push_ref(
    id: &str,
    relation: RefRelation,
    is_tag: bool,
    conditioned: bool,
    refs: &mut Vec<ResourceReference>,
    ids: &mut Vec<String>,
) {
    let target = id.trim_start_matches('#').to_string();
    ids.push(target.clone());
    refs.push(ResourceReference {
        relation,
        namespace: namespace_of(&target),
        target,
        required: !conditioned,
        conditioned,
        is_tag,
    });
}

fn looks_like_resource_id(s: &str) -> bool {
    s.contains(':') && !s.contains(' ')
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

    fn json(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    fn summary(p: &DomainParse) -> &RecipeSummary {
        match &p.summary {
            ResourceSummary::Recipe(s) => s,
            _ => panic!("not a recipe summary"),
        }
    }

    #[test]
    fn recipe_parse_shaped() {
        let p = parse(&json(
            r###"{"type":"minecraft:crafting_shaped","pattern":["##"],
                "key":{"#":{"item":"minecraft:stick"}},
                "result":{"item":"minecraft:ladder","count":3}}"###,
        ));
        let s = summary(&p);
        assert_eq!(s.recipe_type, "minecraft:crafting_shaped");
        assert!(s.ingredients.contains(&"minecraft:stick".to_string()));
        assert!(s.outputs.contains(&"minecraft:ladder".to_string()));
    }

    #[test]
    fn recipe_parse_shapeless_with_tag() {
        let p = parse(&json(
            r#"{"type":"minecraft:crafting_shapeless",
                "ingredients":[{"tag":"minecraft:planks"}],
                "result":{"item":"minecraft:stick"}}"#,
        ));
        assert!(p.references.iter().any(|r| r.is_tag && r.target == "minecraft:planks"));
    }

    #[test]
    fn recipe_parse_modded_generic() {
        // An unknown modded type with non-standard fields still yields type + refs.
        let p = parse(&json(
            r#"{"type":"create:crushing",
                "ingredients":[{"item":"minecraft:tuff"}],
                "results":[{"item":"create:tuff_powder"}]}"#,
        ));
        let s = summary(&p);
        assert_eq!(s.recipe_type, "create:crushing");
        assert!(p.references.iter().any(|r| r.relation == RefRelation::UsesRecipeType
            && r.namespace == "create"));
        assert!(s.outputs.contains(&"create:tuff_powder".to_string()));
    }

    #[test]
    fn recipe_conditions_mark_refs_optional() {
        let p = parse(&json(
            r#"{"type":"create:crushing","conditions":[{"type":"forge:mod_loaded","modid":"create"}],
                "ingredients":[{"item":"minecraft:tuff"}],"results":[{"item":"create:x"}]}"#,
        ));
        assert!(summary(&p).has_conditions);
        assert!(p.references.iter().all(|r| r.conditioned));
    }

    #[test]
    fn malformed_recipe_is_invalid() {
        assert_eq!(parse(&json("[]")).status, ParseStatus::Invalid);
    }
}
