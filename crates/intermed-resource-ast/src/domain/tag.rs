//! Tag domain (`data/<ns>/tags/<registry>/<path>.json`).
//!
//! Minecraft tag JSON merges as a set union of `values` across writers — but only
//! when no writer sets `"replace": true` (which wipes earlier writers, making the
//! result order-dependent). Object entries may carry `"required": false`. This
//! parser lifts those into a typed [`TagAst`] and a compact [`TagSummary`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::DomainParse;
use crate::model::{
    DiagnosticSeverity, ParseStatus, RefRelation, ResourceParseDiagnostic, ResourceReference,
    ResourceSummary,
};
use crate::semantic::namespace::namespace_of;

/// Parser version — bump when tag lowering changes (cache-invalidating).
pub const TAG_AST_VERSION: &str = "tag-r1";

/// Typed tag AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagAst {
    /// `replace: true` wipes accumulated values before adding this writer's.
    pub replace: bool,
    pub values: Vec<TagValue>,
}

/// One tag entry: a plain id, a tag reference (`#ns:path`), or an object with a
/// `required` flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagValue {
    pub id: String,
    pub is_tag_ref: bool,
    pub required: Option<bool>,
}

/// Compact tag summary stored in the cache / lowered to facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagSummary {
    /// The tag registry (`items`, `blocks`, `fluids`, …) derived from the path.
    pub registry: String,
    pub replace: bool,
    pub entry_count: usize,
    /// Whether any entry carries an explicit `required` flag.
    pub has_required_flag: bool,
    /// Sorted, de-duplicated entry ids (for diff / safe-merge equality).
    pub entries: Vec<String>,
}

/// Derive the tag registry from a `data/<ns>/tags/<registry...>/<path>.json` path.
pub fn tag_registry(path: &str) -> String {
    // Everything between `/tags/` and the final `/<file>.json` is the registry
    // (registries can be nested, e.g. `worldgen/biome`).
    let after = match path.split_once("/tags/") {
        Some((_, rest)) => rest,
        None => return String::new(),
    };
    match after.rsplit_once('/') {
        Some((registry, _file)) => registry.to_string(),
        None => String::new(),
    }
}

/// Parse a tag resource into its summary + tag-entry references.
pub fn parse(path: &str, value: &Value) -> DomainParse {
    let mut diagnostics = Vec::new();
    let registry = tag_registry(path);

    let Some(obj) = value.as_object() else {
        diagnostics.push(invalid("tag root is not a JSON object"));
        return DomainParse::invalid(diagnostics);
    };
    let replace = obj.get("replace").and_then(Value::as_bool).unwrap_or(false);

    let mut ast = TagAst {
        replace,
        values: Vec::new(),
    };
    let mut status = ParseStatus::Parsed;
    match obj.get("values").and_then(Value::as_array) {
        Some(values) => {
            for v in values {
                match parse_value(v) {
                    Some(tv) => ast.values.push(tv),
                    None => {
                        status = ParseStatus::PartiallyParsed;
                        diagnostics.push(invalid("tag entry is neither a string nor an object with `id`"));
                    }
                }
            }
        }
        None if obj.contains_key("values") => {
            status = ParseStatus::PartiallyParsed;
            diagnostics.push(invalid("`values` is not an array"));
        }
        None => {} // a `replace`-only tag with no values is valid (clears the tag).
    }

    let mut entries: Vec<String> = ast.values.iter().map(|v| v.id.clone()).collect();
    entries.sort();
    entries.dedup();

    let references = ast
        .values
        .iter()
        .map(|v| ResourceReference {
            relation: RefRelation::UsesTag, // refined to UsesItem below for non-tag entries
            target: v.id.clone(),
            namespace: namespace_of(&v.id),
            // A `required: false` entry is explicitly optional; default is required.
            required: v.required.unwrap_or(true),
            conditioned: false,
            is_tag: v.is_tag_ref,
        })
        .map(|mut r| {
            if !r.is_tag {
                r.relation = RefRelation::UsesItem;
            }
            r
        })
        .collect();

    let summary = TagSummary {
        registry,
        replace: ast.replace,
        // Canonical (de-duplicated) count: a tag is a set, so duplicate `values`
        // are redundant. Counting unique entries keeps the summary — and thus the
        // semantic hash — order- and duplicate-independent.
        entry_count: entries.len(),
        has_required_flag: ast.values.iter().any(|v| v.required.is_some()),
        entries,
    };

    DomainParse {
        summary: ResourceSummary::Tag(summary),
        references,
        diagnostics,
        status,
    }
}

fn parse_value(v: &Value) -> Option<TagValue> {
    if let Some(s) = v.as_str() {
        return Some(tag_value_from_id(s));
    }
    let obj = v.as_object()?;
    let id = obj.get("id").and_then(Value::as_str)?;
    let mut tv = tag_value_from_id(id);
    tv.required = obj.get("required").and_then(Value::as_bool);
    Some(tv)
}

fn tag_value_from_id(id: &str) -> TagValue {
    let is_tag_ref = id.starts_with('#');
    TagValue {
        id: id.trim_start_matches('#').to_string(),
        is_tag_ref,
        required: None,
    }
}

fn invalid(message: &str) -> ResourceParseDiagnostic {
    ResourceParseDiagnostic {
        severity: DiagnosticSeverity::Error,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn tag_parse_basic() {
        let p = parse(
            "data/c/tags/items/ingots.json",
            &json(r##"{"values":["minecraft:iron_ingot","#c:tags/copper"]}"##),
        );
        let ResourceSummary::Tag(s) = &p.summary else { panic!() };
        assert_eq!(s.registry, "items");
        assert!(!s.replace);
        assert_eq!(s.entry_count, 2);
        // One item ref, one tag ref.
        assert!(p.references.iter().any(|r| r.relation == RefRelation::UsesItem));
        assert!(p.references.iter().any(|r| r.is_tag));
    }

    #[test]
    fn tag_parse_replace_true() {
        let p = parse(
            "data/c/tags/items/x.json",
            &json(r#"{"replace":true,"values":["a:b"]}"#),
        );
        let ResourceSummary::Tag(s) = &p.summary else { panic!() };
        assert!(s.replace);
    }

    #[test]
    fn tag_parse_required_object() {
        let p = parse(
            "data/c/tags/items/x.json",
            &json(r#"{"values":[{"id":"a:b","required":false}]}"#),
        );
        let ResourceSummary::Tag(s) = &p.summary else { panic!() };
        assert!(s.has_required_flag);
        assert!(!p.references[0].required);
    }

    #[test]
    fn tag_registry_handles_nested() {
        assert_eq!(tag_registry("data/c/tags/worldgen/biome/x.json"), "worldgen/biome");
        assert_eq!(tag_registry("data/c/tags/items/x.json"), "items");
    }

    #[test]
    fn malformed_tag_is_invalid() {
        let p = parse("data/c/tags/items/x.json", &json("[]"));
        assert_eq!(p.status, ParseStatus::Invalid);
    }
}
