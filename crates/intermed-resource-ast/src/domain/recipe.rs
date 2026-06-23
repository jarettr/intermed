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
use sha2::{Digest, Sha256};

use crate::domain::DomainParse;
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary, SemanticOpacity};
use crate::semantic::namespace::{is_platform_namespace, namespace_of};

/// Parser version — bump when recipe lowering changes (cache-invalidating).
pub const RECIPE_AST_VERSION: &str = "recipe-r3";

const OUTPUT_KEYS: &[&str] = &["result", "results", "output", "outputs"];

/// Compact recipe summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeSummary {
    pub recipe_type: String,
    /// Namespace of the recipe `type` (the serializer's owning mod).
    #[serde(default)]
    pub serializer_namespace: String,
    pub ingredient_count: usize,
    pub output_count: usize,
    pub has_conditions: bool,
    /// Recipe `group` (recipe-book grouping), when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// How fully the serializer is understood — gates whether `outputs` /
    /// `ingredients` can be trusted for a precise diff.
    #[serde(default)]
    pub opacity: SemanticOpacity,
    /// Sorted output ids (the discriminator for same-id-different-output).
    pub outputs: Vec<String>,
    /// Sorted ingredient ids.
    pub ingredients: Vec<String>,
    /// Content fingerprint of the whole recipe, set **only** for opaque custom
    /// serializers so two opaque writers that differ are still detectable (their
    /// summaries would otherwise collapse to the same empty outputs/ingredients).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_payload_hash: Option<String>,
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
    let conditions = crate::domain::parse_conditions(obj);
    let has_conditions = !conditions.is_empty();

    let mut references = Vec::new();

    // The recipe serializer type is itself a dependency (`create:crushing` ⇒ Create).
    if !recipe_type.is_empty() {
        references.push(ResourceReference {
            relation: RefRelation::UsesRecipeType,
            namespace: namespace_of(&recipe_type),
            target: recipe_type.clone(),
            required: !has_conditions,
            conditions: conditions.clone(),
            is_tag: false,
        });
    }

    // Outputs from the result subtrees. The result shape varies by recipe type:
    //   crafting:     "result": {"item": "ns:x", "count": n}
    //   1.21 form:    "result": {"id": "ns:x", "count": n}
    //   cooking /     "result": "ns:x"   (bare string — smelting, blasting,
    //   stonecutting                       smoking, campfire, stonecutting)
    //   multi-output: "results": ["ns:x", {"id": "ns:y"}, …]
    // The bare-string form is why outputs need their own collector: the generic
    // `collect_refs` only reads `item`/`tag`/`id` *object* fields, so a string
    // result produced `output_count == 0`, which the diff layer then reported as
    // an empty recipe "disabling" the vanilla one.
    let mut outputs = Vec::new();
    for key in OUTPUT_KEYS {
        if let Some(v) = obj.get(*key) {
            collect_output(v, &conditions, &mut references, &mut outputs);
        }
    }

    // Ingredients = every other item/tag reference (the whole object except the
    // output subtrees and the type field).
    let mut ingredients = Vec::new();
    for (k, v) in obj {
        if OUTPUT_KEYS.contains(&k.as_str())
            || k == "type"
            || k == "conditions"
            || k == "fabric:load_conditions"
            || k == "neoforge:conditions"
        {
            continue;
        }
        collect_refs(
            v,
            RefRelation::UsesItem,
            &conditions,
            &mut references,
            &mut ingredients,
        );
    }

    outputs.sort();
    outputs.dedup();
    ingredients.sort();
    ingredients.dedup();

    let serializer_namespace = if recipe_type.is_empty() {
        String::new()
    } else {
        namespace_of(&recipe_type)
    };
    // Opacity: vanilla/platform serializers are transparent; a modded serializer we
    // still pulled an output from is partially known; a modded serializer that
    // yielded no output is an opaque custom payload we must not over-interpret.
    let opacity = if recipe_type.is_empty() || is_platform_namespace(&serializer_namespace) {
        SemanticOpacity::Transparent
    } else if !outputs.is_empty() {
        SemanticOpacity::PartiallyKnown
    } else {
        SemanticOpacity::OpaqueCustomSerializer
    };
    // For opaque recipes the structured fields are unreliable, so fingerprint the
    // raw payload (sorted-key JSON) — this is what a diff compares instead.
    let custom_payload_hash = if opacity == SemanticOpacity::OpaqueCustomSerializer {
        serde_json::to_vec(value)
            .ok()
            .map(|b| format!("{:x}", Sha256::digest(&b)))
    } else {
        None
    };

    let summary = RecipeSummary {
        recipe_type,
        serializer_namespace,
        ingredient_count: ingredients.len(),
        output_count: outputs.len(),
        has_conditions,
        group: obj.get("group").and_then(Value::as_str).map(str::to_string),
        opacity,
        outputs,
        ingredients,
        custom_payload_hash,
    };

    DomainParse {
        summary: ResourceSummary::Recipe(summary),
        references,
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
    }
}

/// Recursively collect `item`/`tag` references from a value subtree. An object
/// with `"item": "ns:id"` is an item ref; `"tag": "ns:path"` is a tag ref. The
/// `default_relation` is `ProducesItem` for output subtrees, `UsesItem` otherwise
/// (tag refs always use `UsesTag`).
/// Collect produced-item ids from a `result`/`results` subtree, accepting the
/// bare-string result form (`"result": "ns:x"`) and arrays of them in addition
/// to the `{item}` / `{id}` object forms handled by [`collect_refs`].
fn collect_output(
    value: &Value,
    conditions: &[crate::model::ResourceCondition],
    refs: &mut Vec<ResourceReference>,
    ids: &mut Vec<String>,
) {
    match value {
        Value::String(s) if looks_like_resource_id(s) => {
            push_ref(s, RefRelation::ProducesItem, false, conditions, refs, ids);
        }
        Value::Array(arr) => {
            for v in arr {
                collect_output(v, conditions, refs, ids);
            }
        }
        // Object forms ({item}/{id}/{tag}, possibly nested) reuse the generic walk.
        Value::Object(_) => {
            collect_refs(value, RefRelation::ProducesItem, conditions, refs, ids);
        }
        _ => {}
    }
}

fn collect_refs(
    value: &Value,
    default_relation: RefRelation,
    conditions: &[crate::model::ResourceCondition],
    refs: &mut Vec<ResourceReference>,
    ids: &mut Vec<String>,
) {
    match value {
        Value::Object(map) => {
            if let Some(item) = map.get("item").and_then(Value::as_str) {
                push_ref(item, default_relation, false, conditions, refs, ids);
            }
            if let Some(tag) = map.get("tag").and_then(Value::as_str) {
                push_ref(tag, RefRelation::UsesTag, true, conditions, refs, ids);
            }
            // A bare `"id"` is used by some result schemas.
            if !map.contains_key("item") && !map.contains_key("tag") {
                if let Some(id) = map.get("id").and_then(Value::as_str) {
                    if looks_like_resource_id(id) {
                        push_ref(id, default_relation, false, conditions, refs, ids);
                    }
                }
            }
            for v in map.values() {
                collect_refs(v, default_relation, conditions, refs, ids);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_refs(v, default_relation, conditions, refs, ids);
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
    ids: &mut Vec<String>,
) {
    let target = id.trim_start_matches('#').to_string();
    ids.push(target.clone());
    refs.push(ResourceReference {
        relation,
        namespace: namespace_of(&target),
        target,
        required: conditions.is_empty(),
        conditions: conditions.to_vec(),
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
    fn recipe_parse_string_result_cooking() {
        // 1.20.x smelting/blasting/smoking/campfire/stonecutting use a bare-string
        // result. This must be counted as an output (regression: it yielded
        // output_count == 0 and was misread as a vanilla-disabling empty recipe).
        for ty in [
            "minecraft:smelting",
            "minecraft:blasting",
            "minecraft:smoking",
            "minecraft:campfire_cooking",
            "minecraft:stonecutting",
        ] {
            let p = parse(&json(&format!(
                r#"{{"type":"{ty}","ingredient":{{"item":"deeperdarker:gloomy_cactus"}},
                    "result":"minecraft:orange_dye"}}"#
            )));
            let s = summary(&p);
            assert_eq!(s.output_count, 1, "{ty} should have one output");
            assert!(
                s.outputs.contains(&"minecraft:orange_dye".to_string()),
                "{ty} output id missing"
            );
            assert!(
                s.ingredients
                    .contains(&"deeperdarker:gloomy_cactus".to_string())
            );
        }
    }

    #[test]
    fn recipe_with_no_result_is_output_less() {
        // The genuine "disable a vanilla recipe" pattern: a recipe file with no
        // result subtree at all. This must still report zero outputs so the diff
        // layer can flag it — the string-result fix must not mask it.
        let p = parse(&json(
            r#"{"type":"minecraft:crafting_shapeless",
                "ingredients":[{"item":"minecraft:stick"}]}"#,
        ));
        assert_eq!(summary(&p).output_count, 0);
    }

    #[test]
    fn recipe_parse_string_results_array() {
        let p = parse(&json(
            r#"{"type":"mymod:multi","ingredient":{"item":"minecraft:stone"},
                "results":["minecraft:gravel",{"id":"minecraft:sand"}]}"#,
        ));
        let s = summary(&p);
        assert_eq!(s.output_count, 2);
        assert!(s.outputs.contains(&"minecraft:gravel".to_string()));
        assert!(s.outputs.contains(&"minecraft:sand".to_string()));
    }

    #[test]
    fn recipe_parse_id_result_121() {
        // 1.21 crafting result uses `id` instead of `item`.
        let p = parse(&json(
            r#"{"type":"minecraft:crafting_shapeless",
                "ingredients":[{"item":"minecraft:diamond"}],
                "result":{"id":"minecraft:diamond_block","count":1}}"#,
        ));
        let s = summary(&p);
        assert_eq!(s.output_count, 1);
        assert!(s.outputs.contains(&"minecraft:diamond_block".to_string()));
    }

    #[test]
    fn recipe_parse_shapeless_with_tag() {
        let p = parse(&json(
            r#"{"type":"minecraft:crafting_shapeless",
                "ingredients":[{"tag":"minecraft:planks"}],
                "result":{"item":"minecraft:stick"}}"#,
        ));
        assert!(
            p.references
                .iter()
                .any(|r| r.is_tag && r.target == "minecraft:planks")
        );
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
        assert!(
            p.references
                .iter()
                .any(|r| r.relation == RefRelation::UsesRecipeType && r.namespace == "create")
        );
        assert!(s.outputs.contains(&"create:tuff_powder".to_string()));
    }

    #[test]
    fn recipe_conditions_mark_refs_optional() {
        let p = parse(&json(
            r#"{"type":"create:crushing","conditions":[{"type":"forge:mod_loaded","modid":"create"}],
                "ingredients":[{"item":"minecraft:tuff"}],"results":[{"item":"create:x"}]}"#,
        ));
        assert!(summary(&p).has_conditions);
        assert!(p.references.iter().all(|r| r.is_conditioned()));
    }

    #[test]
    fn malformed_recipe_is_invalid() {
        assert_eq!(parse(&json("[]")).status, ParseStatus::Invalid);
    }
}
