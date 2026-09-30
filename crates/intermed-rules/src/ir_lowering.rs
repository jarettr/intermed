//! Lower declarative [`RuleSpec`]s to the columnar query IR ([`RelExpr`]).
//!
//! This is the migration frontend: a rule compiles to one IR plan, which the
//! columnar backends ([`to_sql`](intermed_columnar::to_sql) /
//! [`to_datalog`](intermed_columnar::to_datalog)) execute — replacing the bespoke
//! per-backend codegen. Currently covers `FactFinding` rules whose matching is the
//! v1 `where_all`/`where_not` maps over a single `input_kind`, with literal,
//! non-aliased terms and no `where`-expression — the subset proven row-equivalent to
//! the interpreter on real packs. Everything else returns [`Lowering::Unsupported`]
//! so the caller keeps using the interpreter (no silent divergence).

use intermed_columnar::ir::{CmpOp, Condition, Predicate, RelExpr, ScalarValue};
use intermed_doctor_core::facts::schema_contract::{AttrType, contract};

use crate::expr::parse_to_condition;
use crate::model::{RuleKind, RuleSpec};

/// The outcome of trying to lower a rule to IR.
#[derive(Debug, Clone, PartialEq)]
pub enum Lowering {
    /// The rule was lowered; the IR backends can run it.
    Ir(RelExpr),
    /// The rule uses a feature not yet faithfully lowered (keep the interpreter).
    Unsupported(String),
}

/// Attribute terms whose interpreter lookup falls back to *alias* keys
/// (`archive`→`file`/`jar`/…); the IR has no alias fallback, so such rules are left
/// to the interpreter to avoid a silent divergence.
const ALIASED_TERMS: &[&str] = &["archive", "path", "trust_score", "mod_id"];
const BASE_COLUMNS: &[&str] = &[
    "fact_id",
    "kind",
    "subject",
    "confidence",
    "extractor",
    "source_locator",
    "source_line",
    "source_inner",
];

fn looks_like_settings_ref(v: &str) -> bool {
    v.contains("settings.") || v.contains('{')
}

/// Combine an `on` and a `where` condition (dropping trivially-`True` arms).
fn and_conditions(a: Condition, b: Condition) -> Condition {
    match (a, b) {
        (Condition::True, c) | (c, Condition::True) => c,
        (a, b) => Condition::And(Box::new(a), Box::new(b)),
    }
}

/// Lower a [`RuleSpec`] to the relational IR, faithfully or not at all.
pub fn rule_to_ir(spec: &RuleSpec) -> Lowering {
    match &spec.kind {
        RuleKind::FactFinding => lower_fact_finding(spec),
        RuleKind::Join => lower_join(spec),
        RuleKind::GroupDistinct => lower_group_distinct(spec),
        // Aggregate has no rules in the core pack; Correlation uses a settings
        // interpolation the IR can't resolve — both stay on the interpreter.
        other => Lowering::Unsupported(format!("rule kind {other:?} not yet lowered")),
    }
}

/// `Join` rule → cross-scan + `on`/`where` condition.
fn lower_join(spec: &RuleSpec) -> Lowering {
    let (Some(left), Some(right)) = (spec.left.as_ref(), spec.right.as_ref()) else {
        return Lowering::Unsupported("join rule missing left/right source".into());
    };
    let Some(on) = parse_to_condition(spec.on.as_deref().unwrap_or("TRUE")) else {
        return Lowering::Unsupported("join `on` not lowerable to IR".into());
    };
    let Some(where_c) = parse_to_condition(spec.r#where.as_deref().unwrap_or("TRUE")) else {
        return Lowering::Unsupported("join `where` not lowerable to IR".into());
    };
    if !condition_is_faithful(&on) || !condition_is_faithful(&where_c) {
        return Lowering::Unsupported(
            "join condition requires interpreter-only term semantics".into(),
        );
    }
    Lowering::Ir(RelExpr::JoinFilter {
        left_kind: left.kind.clone(),
        left_alias: left.alias.clone(),
        right_kind: right.kind.clone(),
        right_alias: right.alias.clone(),
        condition: and_conditions(on, where_c),
    })
}

fn condition_is_faithful(condition: &Condition) -> bool {
    let faithful_column = |term: &str| {
        let Some((alias, qualified_field)) = term.split_once('.') else {
            return false;
        };
        if alias.is_empty() {
            return false;
        }
        let field = qualified_field
            .strip_prefix("attr:")
            .unwrap_or(qualified_field);
        matches!(field, "subject" | "kind")
            || (!field.is_empty()
                && !ALIASED_TERMS.contains(&field)
                && !BASE_COLUMNS.contains(&field))
    };
    match condition {
        Condition::True => true,
        Condition::Cmp { column, .. }
        | Condition::In { column, .. }
        | Condition::NotNull { column }
        | Condition::IsNull { column } => faithful_column(column),
        Condition::ColCmp { left, right, .. } => faithful_column(left) && faithful_column(right),
        Condition::And(left, right) | Condition::Or(left, right) => {
            condition_is_faithful(left) && condition_is_faithful(right)
        }
        Condition::Not(inner) => condition_is_faithful(inner),
    }
}

/// `GroupDistinct` rule → group-by + count-distinct over the input kinds.
fn lower_group_distinct(spec: &RuleSpec) -> Lowering {
    if spec.input_kinds.is_empty() {
        return Lowering::Unsupported("group-distinct rule has no input_kinds".into());
    }
    let Some(group_term) = spec.group_by.as_deref() else {
        return Lowering::Unsupported("group-distinct rule has no group_by term".into());
    };
    let Some(distinct_term) = spec.distinct.as_deref() else {
        return Lowering::Unsupported("group-distinct rule has no distinct term".into());
    };
    // v1 `where_not` treats a missing term as a match, while SQL/columnar `<>`
    // treats NULL as unknown. Until the IR has an explicit "distinct-or-missing"
    // predicate, keep this shape on the reference interpreter.
    if !spec.where_not.is_empty() {
        return Lowering::Unsupported(
            "group-distinct where_not requires missing-aware inequality".into(),
        );
    }
    let Some(group_col) = lower_single_fact_term(group_term) else {
        return Lowering::Unsupported(format!(
            "group_by term `{group_term}` is not faithfully lowerable"
        ));
    };
    let Some(distinct_attr) = lower_single_fact_term(distinct_term) else {
        return Lowering::Unsupported(format!(
            "distinct term `{distinct_term}` is not faithfully lowerable"
        ));
    };

    let mut filters = Vec::with_capacity(spec.where_all.len());
    for (term, expected) in &spec.where_all {
        let Some(column) = lower_single_fact_term(term) else {
            return Lowering::Unsupported(format!(
                "filter term `{term}` is not faithfully lowerable"
            ));
        };
        if looks_like_settings_ref(expected) {
            return Lowering::Unsupported(format!("value `{expected}` is a settings reference"));
        }
        filters.push(Predicate {
            column,
            op: CmpOp::Eq,
            value: ScalarValue::Str(expected.clone()),
        });
    }
    Lowering::Ir(RelExpr::GroupCountDistinct {
        kinds: spec.input_kinds.clone(),
        group_col,
        distinct_attr,
        filters,
        min_count: spec.min_count,
    })
}

/// Map a v1 single-fact term to a physical column without inventing semantics.
/// Alias-backed legacy terms remain on the interpreter because the columnar store
/// deliberately has no fallback lookup order.
fn lower_single_fact_term(term: &str) -> Option<String> {
    if matches!(term, "subject" | "kind") {
        return Some(term.to_string());
    }
    let column = term.strip_prefix("attr:").unwrap_or(term);
    if column.is_empty()
        || ALIASED_TERMS.contains(&column)
        || BASE_COLUMNS.contains(&column)
        || term.contains('.')
    {
        return None;
    }
    Some(column.to_string())
}

fn lower_fact_finding(spec: &RuleSpec) -> Lowering {
    if spec.r#where.is_some() {
        return Lowering::Unsupported("where-expression refinement not yet lowered".into());
    }
    if spec.input_kinds.len() != 1 {
        return Lowering::Unsupported(format!(
            "expected exactly one input_kind, got {}",
            spec.input_kinds.len()
        ));
    }
    if !spec.where_not.is_empty() {
        return Lowering::Unsupported(
            "where_not requires missing-aware inequality not represented by Predicate".into(),
        );
    }

    let mut expr = RelExpr::scan(&spec.input_kinds[0]);
    for (term, expected) in &spec.where_all {
        let Some(column) = lower_single_fact_term(term) else {
            return Lowering::Unsupported(format!("term `{term}` is not faithfully lowerable"));
        };
        if looks_like_settings_ref(expected) {
            return Lowering::Unsupported(format!("value `{expected}` is a settings reference"));
        }
        let Some(value) = lower_schema_literal(&spec.input_kinds[0], &column, expected) else {
            return Lowering::Unsupported(format!(
                "value `{expected}` is not valid for `{}`.`{column}`",
                spec.input_kinds[0]
            ));
        };
        expr = expr.filter(Predicate {
            column,
            op: CmpOp::Eq,
            value,
        });
    }
    Lowering::Ir(expr)
}

/// Lower a declarative string literal to the physical type promised by the fact
/// schema.  The reference rule format stores `where_all` values as strings, but
/// the relational scan deliberately preserves typed attributes; leaving the
/// literal as `Str` would make SQL backends rely on implicit casts and diverge
/// from the in-process engine.
fn lower_schema_literal(kind: &str, column: &str, value: &str) -> Option<ScalarValue> {
    if matches!(column, "subject" | "kind") {
        return Some(ScalarValue::Str(value.to_owned()));
    }
    let Some(attr_type) = contract()
        .kind(kind)
        .and_then(|schema| schema.attrs.get(column))
    else {
        // An incomplete schema permits undeclared, legacy string attributes.
        return Some(ScalarValue::Str(value.to_owned()));
    };
    match attr_type {
        AttrType::String | AttrType::Enum(_) => Some(ScalarValue::Str(value.to_owned())),
        AttrType::Int => value.parse().ok().map(ScalarValue::Int),
        AttrType::Float => value
            .parse::<f64>()
            .ok()
            .filter(|number| number.is_finite())
            .map(ScalarValue::Float),
        AttrType::Bool => value.parse().ok().map(ScalarValue::Bool),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_literals_preserve_declared_physical_types() {
        assert_eq!(
            lower_schema_literal("invalid_metadata", "active_for_instance", "true"),
            Some(ScalarValue::Bool(true))
        );
        assert_eq!(
            lower_schema_literal("invalid_metadata", "active_for_instance", "not-a-bool"),
            None
        );
        assert_eq!(
            lower_schema_literal("invalid_metadata", "reason", "broken"),
            Some(ScalarValue::Str("broken".into()))
        );
    }
}
