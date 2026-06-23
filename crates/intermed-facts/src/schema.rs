//! Typed schema for core fact kinds.
//!
//! The fact model is intentionally flexible (free-form string-keyed attributes),
//! which is great for collector velocity but lets a typed attribute drift to the
//! wrong representation — the classic bug being a numeric count written as a
//! `Str` instead of an `Int`, which then reads as `NULL` in the DuckDB backend.
//!
//! This module is a *thin* typed layer over the flexible facts: a curated table
//! of `(kind, attr) → expected type` for the attributes where the type actually
//! matters (counts, scores, flags). [`schema_violations`] checks a fact against
//! it; collectors are not forced through it, but the schema test suite scans the
//! emitted facts so drift is caught in CI rather than in production analytics.

use crate::{AttrValue, Fact};

/// The representation a typed attribute must use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrType {
    Int,
    Float,
    Bool,
}

impl AttrType {
    fn matches(self, value: &AttrValue) -> bool {
        matches!(
            (self, value),
            (AttrType::Int, AttrValue::Int(_))
                | (AttrType::Float, AttrValue::Float(_) | AttrValue::Int(_))
                | (AttrType::Bool, AttrValue::Bool(_))
        )
    }

    fn label(self) -> &'static str {
        match self {
            AttrType::Int => "int",
            AttrType::Float => "float",
            AttrType::Bool => "bool",
        }
    }
}

/// Curated `(kind, attr, type)` rows for attributes whose representation matters
/// (numeric aggregation in SQL, typed risk math, boolean filters). Only typed
/// attributes are listed; every other attribute is free-form `Str` by design.
const SCHEMA: &[(&str, &str, AttrType)] = &[
    // Security signals — counts MUST be Int (DuckDB `val_int` aggregation).
    ("uses_process_spawn", "dangerous_classes", AttrType::Int),
    ("uses_process_spawn", "classes_scanned", AttrType::Int),
    ("uses_process_spawn", "affected_classes", AttrType::Int),
    // Mixin risk — score and axes are integers 0..=100.
    ("mixin_risk_score", "score", AttrType::Int),
    ("mixin_risk_score", "certainty", AttrType::Int),
    ("mixin_risk_score", "apply_failure", AttrType::Int),
    ("mixin_risk_score", "semantic_conflict", AttrType::Int),
    ("mixin_risk_score", "blast_radius", AttrType::Int),
    ("mixin_risk_score", "fragility", AttrType::Int),
    ("mixin_risk_score", "actionability", AttrType::Int),
    ("mixin_risk_score", "hot_path", AttrType::Bool),
    // Resource writers / collisions.
    ("resource_writer", "size", AttrType::Int),
    ("resource_writer", "json", AttrType::Bool),
    ("resource_collision", "safe_merge", AttrType::Bool),
    // Dependency facts.
    ("dependency", "mandatory", AttrType::Bool),
    // Modpack manifest completeness.
    ("modpack_manifest", "referenced_mods", AttrType::Int),
    ("modpack_incomplete", "referenced_mods", AttrType::Int),
    ("modpack_incomplete", "materialized_jars", AttrType::Int),
    ("modpack_incomplete", "completeness_pct", AttrType::Int),
];

/// The expected type for a `(kind, attr)` pair, if the schema constrains it.
#[must_use]
pub fn expected_type(kind: &str, attr: &str) -> Option<AttrType> {
    SCHEMA
        .iter()
        .find(|(k, a, _)| *k == kind && *a == attr)
        .map(|(_, _, t)| *t)
}

/// Schema violations on a single fact: an attribute present but with a type the
/// schema does not allow (e.g. a count stored as `Str`). Empty = conformant.
#[must_use]
pub fn schema_violations(fact: &Fact) -> Vec<String> {
    let mut out = Vec::new();
    for (attr, value) in &fact.attributes {
        if let Some(expected) = expected_type(&fact.kind, attr) {
            if !expected.matches(value) {
                out.push(format!(
                    "{}.{attr}: expected {}, got {value:?}",
                    fact.kind,
                    expected.label()
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FactStore;

    #[test]
    fn int_attr_as_string_is_a_violation() {
        let mut store = FactStore::new();
        store
            .fact("t", "mixin_risk_score")
            .subject("net.minecraft.Foo")
            .attr("score", "87") // WRONG: string, schema wants Int
            .emit();
        let v = schema_violations(&store.all()[0]);
        assert!(
            v.iter().any(|m| m.contains("mixin_risk_score.score")),
            "{v:?}"
        );
    }

    #[test]
    fn correctly_typed_attrs_pass() {
        let mut store = FactStore::new();
        store
            .fact("t", "mixin_risk_score")
            .subject("net.minecraft.Foo")
            .attr("score", 87i64)
            .attr("hot_path", true)
            .emit();
        assert!(schema_violations(&store.all()[0]).is_empty());
    }

    #[test]
    fn float_attr_accepts_int() {
        // Int is an acceptable representation where Float is expected.
        assert!(AttrType::Float.matches(&AttrValue::Int(3)));
        assert!(!AttrType::Int.matches(&AttrValue::Str("3".into())));
    }
}
