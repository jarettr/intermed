//! Domain layer: classify a resource path, then lower its syntax tree into a
//! typed domain AST + compact [`ResourceSummary`].
//!
//! Each domain parser returns a [`DomainParse`]; [`parse_resource`] is the single
//! entry point that classifies, parses at the active [`ResourceLevel`], computes
//! the order-independent semantic hash, and assembles the [`CachedResourceAst`].

pub mod advancement;
pub mod atlas;
pub mod blockstate;
pub mod classify;
pub mod item_modifier;
pub mod lang;
pub mod loot_table;
pub mod model;
pub mod pack_mcmeta;
pub mod predicate;
pub mod recipe;
pub mod registry_spec;
pub mod tag;
pub mod worldgen;

use sha2::{Digest, Sha256};

use crate::model::{
    CachedResourceAst, DomainParseExt, ParseStatus, ResourceDomain, ResourceLevel,
    ResourceParseDiagnostic, ResourceReference, ResourceSummary,
};

/// Schema tag for the cached resource-AST payload (cache-invalidating).
pub const RESOURCE_AST_CACHE_SCHEMA: &str = "intermed-resource-ast-cache-v3";

/// Uniform output of a single domain parser.
pub struct DomainParse {
    pub summary: ResourceSummary,
    pub references: Vec<ResourceReference>,
    pub diagnostics: Vec<ResourceParseDiagnostic>,
    pub status: ParseStatus,
}

impl DomainParse {
    /// An empty, generic, skipped parse (domain not parsed at this level).
    pub fn skipped() -> Self {
        Self {
            summary: ResourceSummary::Generic,
            references: Vec::new(),
            diagnostics: Vec::new(),
            status: ParseStatus::Skipped,
        }
    }

    /// A parse that failed (malformed for its domain).
    pub fn invalid(diagnostics: Vec<ResourceParseDiagnostic>) -> Self {
        Self {
            summary: ResourceSummary::Generic,
            references: Vec::new(),
            diagnostics,
            status: ParseStatus::Invalid,
        }
    }
}

/// Combined parser version string for the active level — every domain's version
/// folded together so a change to any parser invalidates the cache.
#[must_use]
pub fn parser_version() -> String {
    format!(
        // Trailing literal covers cross-cutting hashing behaviour (generic-json
        // fingerprinting, content-hash for coarse registry domains).
        "{}+{}+{}+{}+{}+{}+{}+{}+{}+{}+{}+genjson-r3",
        tag::TAG_AST_VERSION,
        recipe::RECIPE_AST_VERSION,
        lang::LANG_AST_VERSION,
        pack_mcmeta::PACK_MCMETA_AST_VERSION,
        model::MODEL_AST_VERSION,
        blockstate::BLOCKSTATE_AST_VERSION,
        loot_table::LOOT_TABLE_AST_VERSION,
        atlas::ATLAS_AST_VERSION,
        advancement::ADVANCEMENT_AST_VERSION,
        predicate::PREDICATE_AST_VERSION,
        item_modifier::ITEM_MODIFIER_AST_VERSION,
    )
}

/// Parse one resource into its cached AST summary. Never panics on bad input —
/// malformed resources become `ParseStatus::Invalid` with a diagnostic.
#[must_use]
pub fn parse_resource(path: &str, bytes: &[u8], level: ResourceLevel) -> CachedResourceAst {
    let domain = classify::classify(path);
    let parse = if domain.parsed_at(level) {
        parse_domain(domain, path, bytes)
    } else {
        DomainParse::skipped()
    };

    let mut references = parse.references;
    references.sort();
    references.dedup();

    // The advancement / predicate / item-modifier summaries are intentionally
    // coarse (counts + flags), so two *different* definitions can summarise
    // identically. For these single-document registry files, an override is a
    // content change, so hash the canonical JSON content instead — otherwise the
    // diff pass would miss a genuine override. Other domains hash their (lossless
    // enough) summary; GenericJson already stores the canonical string.
    let semantic_hash = if matches!(
        domain,
        ResourceDomain::Advancement | ResourceDomain::Predicate | ResourceDomain::ItemModifier
    ) && parse.status == ParseStatus::Parsed
    {
        content_fingerprint(bytes).unwrap_or_else(|| hash_summary(&parse.summary))
    } else {
        hash_summary(&parse.summary)
    };
    CachedResourceAst {
        schema: RESOURCE_AST_CACHE_SCHEMA.to_string(),
        parser_version: parser_version(),
        resource_path: path.to_string(),
        domain,
        parse_status: parse.status,
        semantic_hash,
        summary: parse.summary,
        references,
        diagnostics: parse.diagnostics,
    }
}

fn parse_domain(domain: ResourceDomain, path: &str, bytes: &[u8]) -> DomainParse {
    // Lang has a non-JSON `.lang` variant; everything else is JSON-rooted.
    if domain == ResourceDomain::Lang && path.ends_with(".lang") {
        return lang::parse_properties(bytes);
    }
    let value = match crate::syntax::json::parse(bytes) {
        Ok(v) => v,
        Err(e) => {
            return DomainParse::invalid(vec![ResourceParseDiagnostic {
                severity: crate::model::DiagnosticSeverity::Error,
                message: format!("invalid JSON: {e}"),
            }]);
        }
    };
    match domain {
        ResourceDomain::Tag => tag::parse(path, &value),
        ResourceDomain::Recipe => recipe::parse(&value),
        ResourceDomain::Lang => lang::parse_json(&value),
        ResourceDomain::PackMcmeta => pack_mcmeta::parse(&value),
        ResourceDomain::Model => model::parse(&value),
        ResourceDomain::Blockstate => blockstate::parse(&value),
        ResourceDomain::LootTable => loot_table::parse(&value),
        ResourceDomain::Atlas => atlas::parse(&value),
        ResourceDomain::Advancement => advancement::parse(&value),
        ResourceDomain::Predicate => predicate::parse(&value),
        ResourceDomain::ItemModifier => item_modifier::parse(&value),
        ResourceDomain::GenericJson => {
            let mut v = value.clone();
            canonicalize_json(&mut v);
            let canonical = serde_json::to_vec(&v).unwrap_or_default();
            let fingerprint = format!("{:x}", Sha256::digest(&canonical));
            // Data-driven references for known unmodelled datapack registries
            // (damage types, trim materials, …) — coverage without a parser each.
            let mut references = registry_spec::extract_registry_refs(path, &value);
            // Deep worldgen graph (biome → placed feature → configured feature,
            // dimension → type/settings/biomes). Soft edges that feed Layer C's
            // implicit-dependency model without the dangling-file check (no FP).
            if worldgen::is_worldgen_path(path) {
                references.extend(worldgen::extract_references(path, &value));
            }
            DomainParse {
                status: ParseStatus::Parsed,
                summary: ResourceSummary::GenericJson { fingerprint },
                references,
                diagnostics: Vec::new(),
            }
        }
        _ => DomainParse::skipped(),
    }
}

/// Recursively canonicalizes JSON by sorting arrays of primitives (strings/numbers)
/// so that set-like structures yield a consistent hash. `serde_json::Value` already
/// uses BTreeMap for objects, so object keys are sorted automatically.
fn canonicalize_json(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                canonicalize_json(v);
            }
            // If all elements are strings, sort them as a set.
            if arr.iter().all(|v| v.is_string()) {
                arr.sort_by(|a, b| a.as_str().unwrap().cmp(b.as_str().unwrap()));
            } else if arr.iter().all(|v| v.is_number()) {
                arr.sort_by(|a, b| {
                    let f_a = a.as_f64().unwrap_or(0.0);
                    let f_b = b.as_f64().unwrap_or(0.0);
                    f_a.partial_cmp(&f_b).unwrap_or(std::cmp::Ordering::Equal)
                });
            }
        }
        serde_json::Value::Object(obj) => {
            for v in obj.values_mut() {
                canonicalize_json(v);
            }
        }
        _ => {}
    }
}

/// Order-independent content hash of a summary: serialise to canonical JSON (maps
/// are sorted by serde_json) and SHA-256. Two writers that differ only in key
/// order produce the same hash — the basis for safe-merge equality and diffs.
fn hash_summary(summary: &ResourceSummary) -> String {
    let json = serde_json::to_vec(summary).unwrap_or_default();
    let digest = Sha256::digest(&json);
    format!("{digest:x}")
}

/// SHA-256 of the canonical JSON content. Used to give coarse-summary domains a
/// content-sensitive hash so an override (same path, different definition) is
/// detected. Returns `None` if the bytes are not valid JSON.
fn content_fingerprint(bytes: &[u8]) -> Option<String> {
    let mut value = crate::syntax::json::parse(bytes).ok()?;
    canonicalize_json(&mut value);
    let canonical = serde_json::to_vec(&value).ok()?;
    Some(format!("{:x}", Sha256::digest(&canonical)))
}

/// Extract Forge/Fabric/NeoForge load conditions from a resource object.
pub fn parse_conditions(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Vec<crate::model::ResourceCondition> {
    let mut out = Vec::new();

    // Fabric / NeoForge single conditions object or array
    if let Some(conds) = obj
        .get("conditions")
        .or_else(|| obj.get("fabric:load_conditions"))
        .or_else(|| obj.get("neoforge:conditions"))
    {
        if let Some(arr) = conds.as_array() {
            for v in arr {
                if let Some(c) = parse_condition(v) {
                    out.push(c);
                }
            }
        } else if let Some(c) = parse_condition(conds) {
            out.push(c);
        }
    }

    out
}

fn parse_condition(v: &serde_json::Value) -> Option<crate::model::ResourceCondition> {
    use crate::model::ResourceCondition;
    let obj = v.as_object()?;
    // Forge/NeoForge name the discriminator `type`; Fabric's `fabric:load_conditions`
    // names it `condition`. Reading only `type` dropped every Fabric load-gate, so
    // mod-gated compat recipes (`fabric:all_mods_loaded: [betterend]`) looked
    // unconditioned and their references were reported as required-missing.
    let ctype = obj
        .get("type")
        .or_else(|| obj.get("condition"))
        .and_then(|t| t.as_str())?;

    match ctype {
        "forge:mod_loaded" | "neoforge:mod_loaded" => {
            let modid = obj
                .get("modid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some(ResourceCondition::ModLoaded { modid })
        }
        // Fabric mod-list gates carry a `values` array of mod ids (`all` ⇒ And,
        // `any` ⇒ Or); they also tolerate a Forge-style single `modid`.
        "fabric:all_mods_loaded" | "fabric:any_mod_loaded" => {
            let mods = fabric_mod_loaded_list(obj);
            match (mods.len(), ctype == "fabric:any_mod_loaded") {
                (0, _) => Some(ResourceCondition::Other {
                    condition_type: ctype.to_string(),
                }),
                (1, _) => mods.into_iter().next(),
                (_, true) => Some(ResourceCondition::Or { conditions: mods }),
                (_, false) => Some(ResourceCondition::And { conditions: mods }),
            }
        }
        "forge:not" | "neoforge:not" => {
            let inner = obj.get("value")?;
            parse_condition(inner).map(|c| ResourceCondition::Not {
                condition: Box::new(c),
            })
        }
        "forge:and" | "neoforge:and" => {
            let arr = obj.get("values")?.as_array()?;
            let conds: Vec<_> = arr.iter().filter_map(parse_condition).collect();
            Some(ResourceCondition::And { conditions: conds })
        }
        "forge:or" | "neoforge:or" => {
            let arr = obj.get("values")?.as_array()?;
            let conds: Vec<_> = arr.iter().filter_map(parse_condition).collect();
            Some(ResourceCondition::Or { conditions: conds })
        }
        "forge:tag_empty" | "neoforge:tag_empty" => {
            let tag = obj
                .get("tag")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some(ResourceCondition::TagEmpty { tag })
        }
        "forge:false" | "neoforge:false" => Some(ResourceCondition::False),
        _ => Some(ResourceCondition::Other {
            condition_type: ctype.to_string(),
        }),
    }
}

/// The mod ids of a Fabric `all_mods_loaded` / `any_mod_loaded` gate, as
/// `ModLoaded` conditions — from the `values` array, or a single `modid`.
fn fabric_mod_loaded_list(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Vec<crate::model::ResourceCondition> {
    use crate::model::ResourceCondition;
    if let Some(arr) = obj.get("values").and_then(|v| v.as_array()) {
        return arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(|m| ResourceCondition::ModLoaded {
                modid: m.to_string(),
            })
            .collect();
    }
    obj.get("modid")
        .and_then(|v| v.as_str())
        .map(|m| {
            vec![ResourceCondition::ModLoaded {
                modid: m.to_string(),
            }]
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod condition_tests {
    use super::parse_conditions;
    use crate::model::ResourceCondition;
    use serde_json::json;

    fn conds(v: serde_json::Value) -> Vec<ResourceCondition> {
        parse_conditions(v.as_object().unwrap())
    }

    #[test]
    fn fabric_load_conditions_all_mods_loaded_is_parsed() {
        // Fabric uses `condition` (not `type`) and a `values` array (not `modid`).
        let got = conds(json!({
            "fabric:load_conditions": [
                {"condition": "fabric:all_mods_loaded", "values": ["betterend"]}
            ]
        }));
        assert_eq!(
            got,
            vec![ResourceCondition::ModLoaded {
                modid: "betterend".into()
            }],
            "single-mod fabric gate must yield one ModLoaded"
        );
    }

    #[test]
    fn fabric_multi_mod_gate_combines() {
        let all = conds(json!({
            "fabric:load_conditions": [
                {"condition": "fabric:all_mods_loaded", "values": ["a", "b"]}
            ]
        }));
        assert!(matches!(all.as_slice(), [ResourceCondition::And { .. }]));
        let any = conds(json!({
            "fabric:load_conditions": [
                {"condition": "fabric:any_mod_loaded", "values": ["a", "b"]}
            ]
        }));
        assert!(matches!(any.as_slice(), [ResourceCondition::Or { .. }]));
    }

    #[test]
    fn neoforge_and_forge_mod_loaded_still_parsed() {
        let neo = conds(json!({
            "neoforge:conditions": [{"type": "neoforge:mod_loaded", "modid": "create"}]
        }));
        assert_eq!(
            neo,
            vec![ResourceCondition::ModLoaded {
                modid: "create".into()
            }]
        );
    }

    #[test]
    fn unconditioned_resource_has_no_conditions() {
        assert!(conds(json!({"type": "minecraft:crafting_shaped"})).is_empty());
    }
}
