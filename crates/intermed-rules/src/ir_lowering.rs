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

fn looks_like_settings_ref(v: &str) -> bool {
    v.contains("settings.") || v.contains('{')
}

fn term_to_column(term: &str) -> &str {
    term.strip_prefix("attr:").unwrap_or(term)
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
    Lowering::Ir(RelExpr::JoinFilter {
        left_kind: left.kind.clone(),
        left_alias: left.alias.clone(),
        right_kind: right.kind.clone(),
        right_alias: right.alias.clone(),
        condition: and_conditions(on, where_c),
    })
}

/// `GroupDistinct` rule → group-by + count-distinct over the input kinds.
fn lower_group_distinct(spec: &RuleSpec) -> Lowering {
    if spec.input_kinds.is_empty() {
        return Lowering::Unsupported("group-distinct rule has no input_kinds".into());
    }
    let group_col = spec
        .group_by
        .clone()
        .unwrap_or_else(|| "subject".to_string());
    let distinct_attr = spec
        .distinct
        .as_deref()
        .and_then(|d| d.strip_prefix("attr:"))
        .unwrap_or("file")
        .to_string();
    Lowering::Ir(RelExpr::GroupCountDistinct {
        kinds: spec.input_kinds.clone(),
        group_col,
        distinct_attr,
        min_count: spec.min_count,
    })
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

    let mut expr = RelExpr::scan(&spec.input_kinds[0]);
    for (term, expected) in spec.where_all.iter().chain(spec.where_not.iter()) {
        if ALIASED_TERMS.contains(&term_to_column(term)) {
            return Lowering::Unsupported(format!("term `{term}` uses interpreter alias fallback"));
        }
        if looks_like_settings_ref(expected) {
            return Lowering::Unsupported(format!("value `{expected}` is a settings reference"));
        }
    }
    for (term, expected) in &spec.where_all {
        expr = expr.filter(Predicate {
            column: term_to_column(term).to_string(),
            op: CmpOp::Eq,
            value: ScalarValue::Str(expected.clone()),
        });
    }
    for (term, rejected) in &spec.where_not {
        expr = expr.filter(Predicate {
            column: term_to_column(term).to_string(),
            op: CmpOp::Ne,
            value: ScalarValue::Str(rejected.clone()),
        });
    }
    Lowering::Ir(expr)
}
