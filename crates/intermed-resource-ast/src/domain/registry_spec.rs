//! Data-driven reference extraction for unmodelled datapack registries (§16).
//!
//! Minecraft 1.19+ adds many small datapack registries (damage types, trim
//! materials/patterns, banner patterns, …). Writing a parser per registry does not
//! scale, so instead of code we use a **declarative spec table**: for a registry
//! path, a set of JSON pointers naming the fields that hold references, plus the
//! reference's requiredness. The generic-JSON parser applies the matching spec to
//! pull `RegistryRef` edges — giving namespace resolution / implicit-dependency
//! coverage for these registries without a bespoke parser each.

use serde_json::Value;

use crate::model::{RefRelation, ResourceReference};
use crate::semantic::namespace::namespace_of;

/// One reference field within a registry object, addressed by JSON pointer.
pub struct RefSpec {
    /// RFC-6901 JSON pointer to the field (`/effects`, `/asset_name`). A pointer
    /// to a string yields one ref; to an array of strings, one ref per element.
    pub pointer: &'static str,
    /// Whether absence of the target would break the object.
    pub required: bool,
}

/// A registry and the reference fields its objects carry.
pub struct RegistrySpec {
    /// The registry directory under `data/<ns>/` (`damage_type`, `trim_material`).
    pub registry: &'static str,
    pub refs: &'static [RefSpec],
}

/// The declarative spec table. Extend by adding a row — no new parser.
const SPECS: &[RegistrySpec] = &[
    RegistrySpec {
        registry: "damage_type",
        // The hurt sound a damage type plays references a sound event.
        refs: &[RefSpec {
            pointer: "/effects",
            required: false,
        }],
    },
    RegistrySpec {
        registry: "trim_material",
        refs: &[
            RefSpec {
                pointer: "/asset_name",
                required: true,
            },
            RefSpec {
                pointer: "/ingredient",
                required: true,
            },
        ],
    },
    RegistrySpec {
        registry: "trim_pattern",
        refs: &[
            RefSpec {
                pointer: "/template_item",
                required: true,
            },
            RefSpec {
                pointer: "/asset_id",
                required: true,
            },
        ],
    },
    RegistrySpec {
        registry: "banner_pattern",
        refs: &[RefSpec {
            pointer: "/asset_id",
            required: false,
        }],
    },
    // ── Worldgen (§17) — only *shallow, top-level* references are extracted. The
    // deeply-nested worldgen graph is intentionally NOT walked: it is frequently
    // runtime-mutated and pointer extraction there is fragile, so we stay
    // conservative (a missing nested feature would be a false positive). The
    // generic-registry override already notes worldgen object changes at `Note`.
    RegistrySpec {
        // A placed feature names the configured feature it places.
        registry: "worldgen/placed_feature",
        refs: &[RefSpec {
            pointer: "/feature",
            required: false,
        }],
    },
    RegistrySpec {
        // A dimension names its dimension type.
        registry: "worldgen/dimension",
        refs: &[RefSpec {
            pointer: "/type",
            required: false,
        }],
    },
];

/// The registry of a `data/<ns>/<registry>/...` path. Worldgen registries are
/// two-level (`worldgen/<sub>`), so the worldgen sub-registry is appended.
fn registry_of(path: &str) -> Option<String> {
    let rest = path.strip_prefix("data/")?;
    let mut segs = rest.split('/');
    let _ns = segs.next()?;
    let first = segs.next()?;
    if first == "worldgen" {
        if let Some(sub) = segs.next() {
            return Some(format!("worldgen/{sub}"));
        }
    }
    Some(first.to_string())
}

/// Extract `RegistryRef` references from a generic registry object, using the
/// matching spec. Returns an empty vec when no spec matches the path.
#[must_use]
pub fn extract_registry_refs(path: &str, value: &Value) -> Vec<ResourceReference> {
    let Some(registry) = registry_of(path) else {
        return Vec::new();
    };
    let Some(spec) = SPECS.iter().find(|s| s.registry == registry.as_str()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for r in spec.refs {
        let Some(found) = value.pointer(r.pointer) else {
            continue;
        };
        match found {
            Value::String(s) => push_ref(s, r.required, &mut out),
            Value::Array(arr) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        push_ref(s, r.required, &mut out);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn push_ref(id: &str, required: bool, out: &mut Vec<ResourceReference>) {
    // Only namespaced ids carry resolution signal; skip bare strings.
    if !id.contains(':') {
        return;
    }
    let target = id.trim_start_matches('#').to_string();
    out.push(ResourceReference {
        relation: RefRelation::RegistryRef,
        namespace: namespace_of(&target),
        target,
        required,
        conditions: Vec::new(),
        is_tag: false,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_of_extracts_directory() {
        assert_eq!(
            registry_of("data/c/damage_type/sharp.json").as_deref(),
            Some("damage_type")
        );
        assert_eq!(
            registry_of("data/c/trim_material/x.json").as_deref(),
            Some("trim_material")
        );
        // Worldgen is two-level.
        assert_eq!(
            registry_of("data/c/worldgen/placed_feature/ore.json").as_deref(),
            Some("worldgen/placed_feature")
        );
        assert_eq!(registry_of("assets/c/foo.json"), None);
    }

    #[test]
    fn extracts_placed_feature_ref() {
        let v: Value =
            serde_json::from_str(r#"{"feature":"mymod:ore_feature","placement":[]}"#).unwrap();
        let refs = extract_registry_refs("data/c/worldgen/placed_feature/ore.json", &v);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].target, "mymod:ore_feature");
    }

    #[test]
    fn extracts_trim_material_refs() {
        let v: Value = serde_json::from_str(
            r#"{"asset_name":"mymod:silver","ingredient":"mymod:silver_ingot","description":{"translate":"x"}}"#,
        )
        .unwrap();
        let refs = extract_registry_refs("data/c/trim_material/silver.json", &v);
        assert_eq!(refs.len(), 2);
        assert!(
            refs.iter()
                .any(|r| r.target == "mymod:silver_ingot" && r.namespace == "mymod")
        );
        assert!(refs.iter().all(|r| r.relation == RefRelation::RegistryRef));
    }

    #[test]
    fn no_spec_no_refs() {
        let v: Value = serde_json::from_str(r#"{"foo":"bar:baz"}"#).unwrap();
        assert!(extract_registry_refs("data/c/unknown_registry/x.json", &v).is_empty());
    }

    #[test]
    fn bare_string_is_not_a_ref() {
        // `asset_name` is often a bare name, not a namespaced id — no resolution signal.
        let v: Value = serde_json::from_str(r#"{"asset_name":"silver"}"#).unwrap();
        assert!(extract_registry_refs("data/c/trim_material/x.json", &v).is_empty());
    }
}
