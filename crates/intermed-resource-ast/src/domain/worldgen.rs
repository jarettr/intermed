//! Deep worldgen reference extraction (Layer M → Layer C).
//!
//! The worldgen registries (`biome`, `configured_feature`, `placed_feature`,
//! `dimension`, `noise_settings`, `density_function`, `structure`, `structure_set`,
//! …) form a reference graph: a biome lists placed features, a placed feature names
//! a configured feature, a dimension names its type / noise settings / biomes, and
//! so on. [`registry_spec`](super::registry_spec) only walks the *shallow* top level
//! of two of these because naive deep pointer extraction is false-positive-prone
//! (much of the graph is inline objects and runtime-mutated). This module walks the
//! graph **carefully**: it only follows the well-known *id-bearing* fields, only
//! emits namespaced ids, and marks every edge `required: false`.
//!
//! Why `required: false`: a worldgen id often resolves to an *inline* sibling, a
//! datapack-merged entry, or a runtime registration, so its absence is not a load
//! error. Soft edges still feed Layer C's cross-mod implicit-dependency model (a
//! mod's biome that references another mod's placed feature *does* depend on it) but
//! never the dangling-file check — exactly the "deep but quiet" goal.

use serde_json::Value;

use crate::model::{RefRelation, ResourceReference};
use crate::semantic::namespace::namespace_of;

/// The worldgen sub-registry of a `data/<ns>/worldgen/<sub>/...` path (e.g. `biome`,
/// `placed_feature`), or `None` for a non-worldgen path.
#[must_use]
pub fn worldgen_subtype(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("data/")?;
    let mut segs = rest.split('/');
    let _ns = segs.next()?;
    if segs.next()? != "worldgen" {
        return None;
    }
    segs.next()
}

/// `true` for any `data/<ns>/worldgen/...` resource.
#[must_use]
pub fn is_worldgen_path(path: &str) -> bool {
    worldgen_subtype(path).is_some()
}

/// Push a soft `RegistryRef` for a namespaced worldgen id; bare strings and inline
/// objects carry no resolution signal and are skipped.
fn push_id(id: &str, out: &mut Vec<ResourceReference>) {
    let id = id.trim_start_matches('#');
    if !id.contains(':') {
        return;
    }
    let target = id.to_string();
    out.push(ResourceReference {
        relation: RefRelation::RegistryRef,
        namespace: namespace_of(&target),
        target,
        required: false,
        conditions: Vec::new(),
        is_tag: false,
    });
}

/// Push the id at a JSON pointer if it is a string.
fn push_at(value: &Value, pointer: &str, out: &mut Vec<ResourceReference>) {
    if let Some(Value::String(s)) = value.pointer(pointer) {
        push_id(s, out);
    }
}

/// Extract every worldgen reference from `value` for the registry at `path`. Only the
/// id-bearing structural fields per sub-type are followed.
#[must_use]
pub fn extract_references(path: &str, value: &Value) -> Vec<ResourceReference> {
    let Some(sub) = worldgen_subtype(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match sub {
        // A placed feature places exactly one configured feature.
        "placed_feature" => push_at(value, "/feature", &mut out),

        // A configured feature can embed *other* configured features by id in the
        // selector families (`random_selector`, `simple_random_selector`). We follow
        // only those two well-known shapes; everything else is inline config.
        "configured_feature" => collect_configured_feature(value, &mut out),

        // A biome lists its placed features (a list of generation-step lists) and its
        // carvers (a single id or a list).
        "biome" => collect_biome(value, &mut out),

        // A dimension names its type, noise settings, and biome set.
        "dimension" => collect_dimension(value, &mut out),

        // A structure's spawn biomes (a tag or list); a structure set's members.
        "structure" => push_at(value, "/biomes", &mut out),
        "structure_set" => {
            if let Some(Value::Array(arr)) = value.pointer("/structures") {
                for s in arr {
                    push_at(s, "/structure", &mut out);
                }
            }
        }

        _ => {}
    }
    out
}

fn collect_configured_feature(value: &Value, out: &mut Vec<ResourceReference>) {
    // `random_selector`: { config: { features: [ { feature: "ns:id" | {...} } ], default: "ns:id" } }
    if let Some(Value::Array(arr)) = value.pointer("/config/features") {
        for entry in arr {
            // entry may be a bare id string or an object with a `feature` id.
            match entry {
                Value::String(s) => push_id(s, out),
                Value::Object(_) => push_at(entry, "/feature", out),
                _ => {}
            }
        }
    }
    // `default` placement target and `simple_random_selector` features list.
    push_at(value, "/config/default", out);
}

fn collect_biome(value: &Value, out: &mut Vec<ResourceReference>) {
    // /features: [[ "ns:placed_feature" | {inline} , ... ], ...]
    if let Some(Value::Array(steps)) = value.pointer("/features") {
        for step in steps {
            if let Value::Array(list) = step {
                for f in list {
                    if let Value::String(s) = f {
                        push_id(s, out);
                    }
                }
            }
        }
    }
    // /carvers: "ns:carver" | ["ns:carver", ...] | { air: ... } (object form is inline)
    match value.pointer("/carvers") {
        Some(Value::String(s)) => push_id(s, out),
        Some(Value::Array(arr)) => {
            for c in arr {
                if let Value::String(s) = c {
                    push_id(s, out);
                }
            }
        }
        _ => {}
    }
}

fn collect_dimension(value: &Value, out: &mut Vec<ResourceReference>) {
    push_at(value, "/type", out);
    push_at(value, "/generator/settings", out);
    // biome_source: fixed (`/biome`) or multi_noise (`/biomes[].biome`).
    push_at(value, "/generator/biome_source/biome", out);
    if let Some(Value::Array(arr)) = value.pointer("/generator/biome_source/biomes") {
        for b in arr {
            // entry: { biome: "ns:id", parameters: {...} } or a bare id.
            match b {
                Value::String(s) => push_id(s, out),
                Value::Object(_) => push_at(b, "/biome", out),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn targets(refs: &[ResourceReference]) -> Vec<&str> {
        let mut t: Vec<&str> = refs.iter().map(|r| r.target.as_str()).collect();
        t.sort_unstable();
        t
    }

    #[test]
    fn subtype_detection() {
        assert_eq!(
            worldgen_subtype("data/c/worldgen/biome/x.json"),
            Some("biome")
        );
        assert_eq!(worldgen_subtype("data/c/recipes/x.json"), None);
        assert!(is_worldgen_path("data/c/worldgen/placed_feature/y.json"));
    }

    #[test]
    fn placed_feature_follows_configured_feature() {
        let v = json!({ "feature": "create:my_ore", "placement": [] });
        let r = extract_references("data/create/worldgen/placed_feature/p.json", &v);
        assert_eq!(targets(&r), vec!["create:my_ore"]);
        assert_eq!(r[0].relation, RefRelation::RegistryRef);
        assert!(!r[0].required, "worldgen edges are soft (no dangling FP)");
    }

    #[test]
    fn biome_collects_placed_features_skips_inline() {
        let v = json!({
            "features": [
                [],
                ["create:placed_ore", { "feature": "inline", "placement": [] }],
                ["minecraft:trees"]
            ],
            "carvers": "create:my_carver"
        });
        let r = extract_references("data/create/worldgen/biome/b.json", &v);
        // The inline object (no namespaced id) is skipped.
        assert_eq!(
            targets(&r),
            vec!["create:my_carver", "create:placed_ore", "minecraft:trees"]
        );
    }

    #[test]
    fn dimension_collects_type_settings_and_biomes() {
        let v = json!({
            "type": "create:my_dim_type",
            "generator": {
                "settings": "create:my_noise",
                "biome_source": { "biomes": [ { "biome": "create:my_biome" } ] }
            }
        });
        let r = extract_references("data/create/worldgen/dimension/d.json", &v);
        assert_eq!(
            targets(&r),
            vec!["create:my_biome", "create:my_dim_type", "create:my_noise"]
        );
    }

    #[test]
    fn non_worldgen_path_yields_nothing() {
        let v = json!({ "feature": "create:x" });
        assert!(extract_references("data/create/recipes/r.json", &v).is_empty());
    }

    #[test]
    fn end_to_end_parse_resource_extracts_worldgen_refs() {
        // Real shape (botania placed feature) through the full domain dispatch:
        // proves the `parse_resource` → GenericJson → worldgen wiring, not just the
        // module in isolation.
        let bytes = br#"{ "feature": "botania:mystical_flowers",
            "placement": [ { "type": "minecraft:count", "count": 2 } ] }"#;
        let parsed = crate::domain::parse_resource(
            "data/botania/worldgen/placed_feature/mystical_flowers.json",
            bytes,
            crate::model::ResourceLevel::Full,
        );
        assert!(
            parsed
                .references
                .iter()
                .any(|r| r.target == "botania:mystical_flowers"
                    && r.relation == RefRelation::RegistryRef
                    && !r.required),
            "parse_resource should surface the soft worldgen feature ref"
        );
    }
}
