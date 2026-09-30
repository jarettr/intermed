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
pub const RECIPE_AST_VERSION: &str = "recipe-r5";

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
    /// Canonical fingerprint of the load conditions tree (sorted, deterministic).
    /// `None` when there are no conditions. Used for precise condition comparison
    /// so two recipes that both have conditions but with different mod gates
    /// (`modloaded:create` vs `modloaded:thermal`) are not missed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_fingerprint: Option<String>,
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
    /// Canonical whole-recipe structure, preserving shaped layout, counts,
    /// multiplicity, and serializer-specific fields.
    #[serde(default)]
    pub structure_fingerprint: String,
    /// Canonical output subtree, including item counts and output ordering.
    #[serde(default)]
    pub output_fingerprint: String,
    /// Canonical non-output payload, preserving ingredient multiplicity/layout.
    #[serde(default)]
    pub input_fingerprint: String,
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
            certainty: crate::model::ReferenceCertainty::ExactSchemaReference,
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
    // Condition fingerprint: a canonical hash of the sorted conditions tree so
    // two conditioned recipes with *different* mod gates are not missed by the
    // diff (has_conditions: bool alone cannot distinguish them).
    let condition_fingerprint = if has_conditions {
        // Serialize each condition to a canonical string, sort, then hash.
        let mut parts: Vec<String> = conditions.iter().map(|c| format!("{c:?}")).collect();
        parts.sort();
        let digest = Sha256::digest(parts.join("|").as_bytes());
        Some(format!("{digest:x}"))
    } else {
        None
    };

    let canonical_structure = canonical_recipe_structure(value, &recipe_type);
    let structure_fingerprint = hash_value(&canonical_structure);
    let canonical_obj = canonical_structure.as_object().cloned().unwrap_or_default();
    let mut output_view = serde_json::Map::new();
    for key in OUTPUT_KEYS {
        if let Some(value) = canonical_obj.get(*key) {
            output_view.insert((*key).to_string(), value.clone());
        }
    }
    let output_fingerprint = hash_value(&Value::Object(output_view));
    let mut input_view = canonical_obj;
    for key in OUTPUT_KEYS {
        input_view.remove(*key);
    }
    for key in [
        "type",
        "conditions",
        "fabric:load_conditions",
        "neoforge:conditions",
        "group",
    ] {
        input_view.remove(key);
    }
    let input_fingerprint = hash_value(&Value::Object(input_view));

    let summary = RecipeSummary {
        recipe_type,
        serializer_namespace,
        ingredient_count: ingredients.len(),
        output_count: outputs.len(),
        has_conditions,
        condition_fingerprint,
        group: obj.get("group").and_then(Value::as_str).map(str::to_string),
        opacity,
        outputs,
        ingredients,
        custom_payload_hash,
        structure_fingerprint,
        output_fingerprint,
        input_fingerprint,
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
            // A bare `"id"` is exact only inside a known output subtree. In an
            // arbitrary custom payload its registry role is unknown and must not
            // masquerade as an item dependency.
            if !map.contains_key("item")
                && !map.contains_key("tag")
                && let Some(id) = map.get("id").and_then(Value::as_str)
                && looks_like_resource_id(id)
            {
                if default_relation == RefRelation::ProducesItem {
                    push_ref(id, default_relation, false, conditions, refs, ids);
                } else {
                    let target = id.trim_start_matches('#').to_string();
                    refs.push(ResourceReference {
                        relation: RefRelation::UnknownRegistryRef,
                        namespace: namespace_of(&target),
                        target,
                        required: false,
                        conditions: conditions.to_vec(),
                        is_tag: id.starts_with('#'),
                        certainty: crate::model::ReferenceCertainty::OpaqueCustomReference,
                    });
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
        certainty: crate::model::ReferenceCertainty::ExactSchemaReference,
    });
}

fn hash_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

/// Canonicalize only arrays whose order is non-semantic while retaining every
/// element. Shaped patterns, custom serializer payloads, counts, and duplicate
/// ingredients remain intact.
fn canonical_recipe_structure(value: &Value, recipe_type: &str) -> Value {
    let mut canonical = value.clone();
    let Some(object) = canonical.as_object_mut() else {
        return canonical;
    };
    for key in ["results", "outputs"] {
        if let Some(Value::Array(values)) = object.get_mut(key) {
            sort_json_values(values);
        }
    }
    if recipe_type == "minecraft:crafting_shapeless"
        && let Some(Value::Array(values)) = object.get_mut("ingredients")
    {
        sort_json_values(values);
    }
    canonical
}

fn sort_json_values(values: &mut [Value]) {
    values.sort_by_cached_key(|value| serde_json::to_vec(value).unwrap_or_default());
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

    #[test]
    fn fingerprints_preserve_output_count_and_shaped_layout() {
        let count_one = parse(&json(
            r###"{"type":"minecraft:crafting_shaped","pattern":["AA"," B"],
                "key":{"A":{"item":"minecraft:stick"},"B":{"item":"minecraft:stone"}},
                "result":{"id":"minecraft:diamond","count":1}}"###,
        ));
        let count_sixty_four = parse(&json(
            r###"{"type":"minecraft:crafting_shaped","pattern":["AA"," B"],
                "key":{"A":{"item":"minecraft:stick"},"B":{"item":"minecraft:stone"}},
                "result":{"id":"minecraft:diamond","count":64}}"###,
        ));
        let different_layout = parse(&json(
            r###"{"type":"minecraft:crafting_shaped","pattern":["A ","AB"],
                "key":{"A":{"item":"minecraft:stick"},"B":{"item":"minecraft:stone"}},
                "result":{"id":"minecraft:diamond","count":1}}"###,
        ));
        assert_ne!(
            summary(&count_one).output_fingerprint,
            summary(&count_sixty_four).output_fingerprint
        );
        assert_ne!(
            summary(&count_one).input_fingerprint,
            summary(&different_layout).input_fingerprint
        );
    }

    #[test]
    fn arbitrary_custom_id_is_not_treated_as_an_item_dependency() {
        let parsed = parse(&json(
            r#"{"type":"custom:machine","machine":{"id":"custom:fast_mode"}}"#,
        ));
        let reference = parsed
            .references
            .iter()
            .find(|reference| reference.target == "custom:fast_mode")
            .expect("opaque id remains explainable");
        assert_eq!(reference.relation, RefRelation::UnknownRegistryRef);
        assert!(!reference.required);
        assert_eq!(
            reference.certainty,
            crate::model::ReferenceCertainty::OpaqueCustomReference
        );
        assert!(
            !summary(&parsed)
                .ingredients
                .contains(&"custom:fast_mode".into())
        );
    }
}
