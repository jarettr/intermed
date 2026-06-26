//! Machine-checkable fact-schema **contract** (static), complementary to the
//! runtime value-type checker in [`crate::schema`].
//!
//! * [`crate::schema`] answers *"does an emitted fact's attribute **value** have
//!   the right type?"* (e.g. a count stored as `Str` instead of `Int`).
//! * This module answers *"is every fact **kind** registered, and does the
//!   declared attribute surface match what rules read?"* — the static contract
//!   that prevents schema drift between collectors, rules, and backends.
//!
//! The contract lives in `schema.toml`. Each fact kind is declared with its
//! subject meaning and, when `complete = true`, the full typed set of attributes
//! it carries. The schema gate (`tests/schema_gate.rs`) enforces that every kind
//! in [`crate::kind::all_kinds`] is declared exactly once, that no entry names a
//! non-existent kind, and that the declared types are well-formed. `complete`
//! kinds are the audited surface a future per-attribute rule gate can rely on;
//! `complete = false` is the explicit opt-out until a kind is pinned down.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The embedded contract source.
pub const SCHEMA_TOML: &str = include_str!("../schema.toml");

/// Declared scalar type of an attribute, mirroring [`crate::AttrValue`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrType {
    String,
    Int,
    Float,
    Bool,
    /// A string attribute constrained to a closed set of values.
    Enum(Vec<String>),
}

impl AttrType {
    fn parse(value: &RawAttr) -> Result<AttrType, String> {
        let (ty, values) = match value {
            RawAttr::Scalar(s) => (s.as_str(), None),
            RawAttr::Typed { r#type, values } => (r#type.as_str(), values.clone()),
        };
        match ty {
            "string" => Ok(AttrType::String),
            "int" => Ok(AttrType::Int),
            "float" => Ok(AttrType::Float),
            "bool" => Ok(AttrType::Bool),
            "enum" => {
                let values = values.unwrap_or_default();
                if values.is_empty() {
                    Err("enum attr declares no values".to_string())
                } else {
                    Ok(AttrType::Enum(values))
                }
            }
            other => Err(format!("unknown attr type `{other}`")),
        }
    }
}

/// The schema for a single fact kind.
#[derive(Debug, Clone)]
pub struct KindSchema {
    /// Human description of what the fact's `subject` identifies.
    pub subject: String,
    /// Whether the attribute set is exhaustive (and thus enforceable).
    pub complete: bool,
    /// Declared attributes by name.
    pub attrs: BTreeMap<String, AttrType>,
}

/// The parsed fact-schema contract.
#[derive(Debug, Clone)]
pub struct FactSchema {
    pub schema_version: String,
    pub kinds: BTreeMap<String, KindSchema>,
}

impl FactSchema {
    /// Look up a kind's schema.
    #[must_use]
    pub fn kind(&self, name: &str) -> Option<&KindSchema> {
        self.kinds.get(name)
    }
}

/// Parse and validate the embedded schema contract. Panics on a malformed
/// contract — it is compiled into the binary and a parse failure is a build bug.
#[must_use]
pub fn contract() -> FactSchema {
    parse_schema(SCHEMA_TOML).expect("embedded fact schema is valid")
}

/// Parse a schema document into a structured [`FactSchema`] or an error.
pub fn parse_schema(toml_src: &str) -> Result<FactSchema, String> {
    let raw: RawSchema = toml::from_str(toml_src).map_err(|e| e.to_string())?;
    let mut kinds = BTreeMap::new();
    for (name, raw_kind) in raw.kind {
        let mut attrs = BTreeMap::new();
        for (attr_name, raw_attr) in raw_kind.attrs {
            let ty = AttrType::parse(&raw_attr)
                .map_err(|e| format!("kind `{name}` attr `{attr_name}`: {e}"))?;
            attrs.insert(attr_name, ty);
        }
        kinds.insert(
            name,
            KindSchema {
                subject: raw_kind.subject,
                complete: raw_kind.complete,
                attrs,
            },
        );
    }
    Ok(FactSchema {
        schema_version: raw.schema_version,
        kinds,
    })
}

#[derive(Deserialize)]
struct RawSchema {
    schema_version: String,
    #[serde(default)]
    kind: BTreeMap<String, RawKind>,
}

#[derive(Deserialize)]
struct RawKind {
    subject: String,
    #[serde(default)]
    complete: bool,
    #[serde(default)]
    attrs: BTreeMap<String, RawAttr>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawAttr {
    Scalar(String),
    Typed {
        r#type: String,
        #[serde(default)]
        values: Option<Vec<String>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_contract_parses() {
        let s = contract();
        assert_eq!(s.schema_version, "intermed-fact-schema-v1");
        let mod_kind = s.kind("mod").expect("mod kind");
        assert!(mod_kind.complete);
        assert_eq!(mod_kind.attrs.get("version"), Some(&AttrType::String));
    }

    #[test]
    fn enum_attr_parses() {
        let s = parse_schema(
            r#"
            schema_version = "t"
            [kind.x]
            subject = "x"
            complete = true
            attrs.relation = { type = "enum", values = ["a", "b"] }
            "#,
        )
        .expect("parse");
        assert_eq!(
            s.kind("x").unwrap().attrs.get("relation"),
            Some(&AttrType::Enum(vec!["a".to_string(), "b".to_string()]))
        );
    }
}
