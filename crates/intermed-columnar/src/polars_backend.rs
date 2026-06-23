//! Polars query backend (plan Phase 4.2), behind the `polars-backend` feature.
//!
//! Translates the single-scan relational fragment (`Scan` / `Filter` / `Project` /
//! `Aggregate`) to a Polars `LazyFrame` and runs it. Facts of the scanned kind are
//! materialized into a DataFrame with **string** columns (matching the engine's
//! stringly `Eq`/`Ne` semantics); numeric comparisons and aggregates cast to `f64`.
//! Polars carries its own arrow fork, so this backend is isolated behind the feature
//! and never linked into the default build. (For an arrow-58-native SQL backend, use
//! `datafusion-backend`.)

use intermed_facts::{AttrValue, Fact};
use polars::prelude::*;
use std::collections::BTreeSet;

use crate::backend::QueryBackend;
use crate::ir::{AggFunc, CmpOp, RelExpr, ScalarValue};
use crate::value::{Relation, Row, Value};

/// Runs the single-scan relational fragment on Polars.
pub struct PolarsBackend;

fn err(e: impl std::fmt::Display) -> crate::error::ColumnarError {
    crate::error::ColumnarError::Schema(format!("polars: {e}"))
}

const BASE_COLS: [&str; 5] = ["fact_id", "kind", "subject", "extractor", "confidence"];

impl QueryBackend for PolarsBackend {
    fn name(&self) -> &str {
        "polars"
    }

    fn supports(&self, plan: &RelExpr) -> bool {
        single_scan_relational(plan)
    }

    fn run(&self, plan: &RelExpr, facts: &[Fact]) -> Result<Relation, crate::error::ColumnarError> {
        let lf = build(plan, facts)?;
        let df = lf.collect().map_err(err)?;
        dataframe_to_relation(&df)
    }
}

/// Whether `plan` is a single-scan pipeline of Filter/Project/Aggregate only.
fn single_scan_relational(plan: &RelExpr) -> bool {
    match plan {
        RelExpr::Scan { .. } => true,
        RelExpr::Filter { input, .. }
        | RelExpr::Project { input, .. }
        | RelExpr::Aggregate { input, .. } => single_scan_relational(input),
        _ => false,
    }
}

fn build(expr: &RelExpr, facts: &[Fact]) -> Result<LazyFrame, crate::error::ColumnarError> {
    match expr {
        RelExpr::Scan { kind } => Ok(scan_dataframe(kind, facts)?.lazy()),
        RelExpr::Filter { input, predicate } => {
            Ok(build(input, facts)?.filter(predicate_expr(predicate)))
        }
        RelExpr::Project { input, columns } => {
            let exprs: Vec<Expr> = columns.iter().map(|c| col(c.as_str())).collect();
            Ok(build(input, facts)?.select(exprs))
        }
        RelExpr::Aggregate {
            input,
            group_by,
            aggregates,
        } => {
            let lf = build(input, facts)?;
            let keys: Vec<Expr> = group_by.iter().map(|c| col(c.as_str())).collect();
            let aggs: Vec<Expr> = aggregates.iter().map(aggregate_expr).collect();
            Ok(lf.group_by(keys).agg(aggs))
        }
        other => Err(err(format!("unsupported in polars backend: {other:?}"))),
    }
}

fn scalar_string(v: &ScalarValue) -> String {
    match v {
        ScalarValue::Str(s) => s.clone(),
        ScalarValue::Int(i) => i.to_string(),
        ScalarValue::Float(f) => f.to_string(),
        ScalarValue::Bool(b) => b.to_string(),
    }
}

fn scalar_f64(v: &ScalarValue) -> f64 {
    match v {
        ScalarValue::Int(i) => *i as f64,
        ScalarValue::Float(f) => *f,
        ScalarValue::Bool(b) => *b as i64 as f64,
        ScalarValue::Str(s) => s.parse().unwrap_or(f64::NAN),
    }
}

fn predicate_expr(p: &crate::ir::Predicate) -> Expr {
    let c = col(p.column.as_str());
    match p.op {
        // String semantics (columns are Utf8) match the engine's value_eq.
        CmpOp::Eq => c.eq(lit(scalar_string(&p.value))),
        CmpOp::Ne => c.neq(lit(scalar_string(&p.value))),
        // Numeric comparisons cast the column to f64.
        CmpOp::Lt => c.cast(DataType::Float64).lt(lit(scalar_f64(&p.value))),
        CmpOp::Le => c.cast(DataType::Float64).lt_eq(lit(scalar_f64(&p.value))),
        CmpOp::Gt => c.cast(DataType::Float64).gt(lit(scalar_f64(&p.value))),
        CmpOp::Ge => c.cast(DataType::Float64).gt_eq(lit(scalar_f64(&p.value))),
    }
}

fn aggregate_expr(a: &crate::ir::Aggregate) -> Expr {
    let alias = a.alias.as_str();
    match a.func {
        AggFunc::Count => len().alias(alias),
        AggFunc::Sum => col(a.column.as_str())
            .cast(DataType::Float64)
            .sum()
            .alias(alias),
        AggFunc::Avg => col(a.column.as_str())
            .cast(DataType::Float64)
            .mean()
            .alias(alias),
        AggFunc::Min => col(a.column.as_str())
            .cast(DataType::Float64)
            .min()
            .alias(alias),
        AggFunc::Max => col(a.column.as_str())
            .cast(DataType::Float64)
            .max()
            .alias(alias),
    }
}

/// Build a string-typed DataFrame of all facts of `kind` (base columns + attributes).
fn scan_dataframe(kind: &str, facts: &[Fact]) -> Result<DataFrame, crate::error::ColumnarError> {
    let rows: Vec<&Fact> = facts.iter().filter(|f| f.kind == kind).collect();

    // Column set: base columns + the union of attribute keys.
    let mut attr_keys: BTreeSet<String> = BTreeSet::new();
    for f in &rows {
        for k in f.attributes.keys() {
            if !BASE_COLS.contains(&k.as_str()) {
                attr_keys.insert(k.clone());
            }
        }
    }

    let mut columns: Vec<Column> = Vec::new();
    // Base columns (string form).
    for base in BASE_COLS {
        let values: Vec<Option<String>> = rows.iter().map(|f| Some(base_value(f, base))).collect();
        columns.push(Series::new(base.into(), values).into_column());
    }
    // Attribute columns.
    for key in &attr_keys {
        let values: Vec<Option<String>> = rows
            .iter()
            .map(|f| {
                f.attributes
                    .iter()
                    .find(|(k, _)| k.as_str() == key.as_str())
                    .map(|(_, v)| attr_string(v))
            })
            .collect();
        columns.push(Series::new(key.as_str().into(), values).into_column());
    }

    DataFrame::new(rows.len(), columns).map_err(err)
}

fn base_value(f: &Fact, base: &str) -> String {
    match base {
        "fact_id" => f.id.0.to_string(),
        "kind" => f.kind.clone(),
        "subject" => f.subject.clone(),
        "extractor" => f.extractor.clone(),
        "confidence" => f.confidence.to_string(),
        _ => String::new(),
    }
}

fn attr_string(v: &AttrValue) -> String {
    match v {
        AttrValue::Str(s) => s.clone(),
        AttrValue::Int(i) => i.to_string(),
        AttrValue::Float(f) => f.to_string(),
        AttrValue::Bool(b) => b.to_string(),
    }
}

fn any_to_value(av: &AnyValue) -> Value {
    match av {
        AnyValue::Null => Value::Null,
        AnyValue::Boolean(b) => Value::Bool(*b),
        AnyValue::String(s) => Value::Str(s.to_string()),
        AnyValue::StringOwned(s) => Value::Str(s.to_string()),
        AnyValue::Int64(i) => Value::Int(*i),
        AnyValue::Int32(i) => Value::Int(*i as i64),
        AnyValue::UInt32(i) => Value::Int(*i as i64),
        AnyValue::UInt64(i) => Value::Int(*i as i64),
        AnyValue::Float64(f) => Value::Float(*f),
        AnyValue::Float32(f) => Value::Float(*f as f64),
        other => Value::Str(other.to_string()),
    }
}

fn dataframe_to_relation(df: &DataFrame) -> Result<Relation, crate::error::ColumnarError> {
    let columns = df.columns();
    let mut rows = Vec::with_capacity(df.height());
    for r in 0..df.height() {
        let mut row = Row::new();
        for c in columns {
            let av = c.get(r).map_err(err)?;
            row.insert(c.name().to_string(), any_to_value(&av));
        }
        rows.push(row);
    }
    Ok(Relation::new(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_facts::FactStore;

    fn facts() -> Vec<Fact> {
        let mut s = FactStore::new();
        for (m, op) in [
            ("owo", "redirect"),
            ("poly", "redirect"),
            ("sodium", "inject"),
        ] {
            s.fact("c", "mixin_application_site")
                .subject(m)
                .attr("operation", op)
                .emit();
        }
        s.all().to_vec()
    }

    #[test]
    fn polars_scan_filter_project() {
        let plan = RelExpr::scan("mixin_application_site")
            .filter(crate::ir::Predicate {
                column: "operation".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Str("redirect".into()),
            })
            .project(vec!["subject".into()]);
        let rel = PolarsBackend.run(&plan, &facts()).unwrap();
        let subs: BTreeSet<String> = rel
            .rows
            .iter()
            .filter_map(|r| r.get("subject").and_then(Value::as_str).map(str::to_string))
            .collect();
        assert_eq!(
            subs,
            ["owo", "poly"].iter().map(|s| s.to_string()).collect()
        );
    }

    #[test]
    fn polars_group_count() {
        let plan = RelExpr::scan("mixin_application_site").aggregate(
            vec!["operation".into()],
            vec![crate::ir::Aggregate {
                func: AggFunc::Count,
                column: String::new(),
                alias: "n".into(),
            }],
        );
        let rel = PolarsBackend.run(&plan, &facts()).unwrap();
        // redirect → 2, inject → 1.
        let redirect = rel
            .rows
            .iter()
            .find(|r| r.get("operation").and_then(Value::as_str) == Some("redirect"))
            .unwrap();
        assert_eq!(redirect.get("n").and_then(Value::as_f64), Some(2.0));
    }
}
