//! IR → DuckDB SQL translator (plan Phase 2 / Phase 3 DuckDB route).
//!
//! Lowers a [`RelExpr`] into SQL that runs over the DuckDB `facts` / `fact_attributes`
//! relational tables (the same flat FK layout the columnar projection produces). A
//! `Scan` becomes a CTE that pivots the referenced attributes into columns via
//! conditional aggregation, so downstream `WHERE` / `GROUP BY` can address attributes
//! as if they were native columns. This replaces ad-hoc JSON→SQL string-building with
//! a single typed lowering.
//!
//! The generated SQL is what the DuckDB adapter would execute against Arrow-scanned
//! tables; here it is produced and shape-tested without requiring the DuckDB engine
//! to be built.

use std::collections::BTreeSet;

use crate::ir::{AggFunc, Aggregate, CmpOp, Condition, Predicate, RelExpr, ScalarValue};

/// Base columns that live directly on the `facts` table (everything else is a
/// pivoted attribute).
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

fn is_base_column(col: &str) -> bool {
    BASE_COLUMNS.contains(&col)
}

/// Translate a plan rooted at a single `Scan` (with filters/projection/aggregation)
/// into a DuckDB SQL string. Returns `None` for shapes that are not single-scan SQL
/// (e.g. a top-level `TransitiveClosure`, which the router sends to Souffle, or a
/// `CallExternal`, which goes to WASM).
pub fn to_sql(expr: &RelExpr) -> Option<String> {
    // The declarative join / group-distinct shapes have their own SQL.
    match expr {
        RelExpr::JoinFilter {
            left_kind,
            left_alias,
            right_kind,
            right_alias,
            condition,
        } => {
            return Some(join_filter_sql(
                left_kind,
                left_alias,
                right_kind,
                right_alias,
                condition,
            ));
        }
        RelExpr::GroupCountDistinct {
            kinds,
            group_col,
            distinct_attr,
            min_count,
        } => {
            return Some(group_count_distinct_sql(
                kinds,
                group_col,
                distinct_attr,
                *min_count,
            ));
        }
        _ => {}
    }

    // Collect every column referenced anywhere so the scan CTE can pivot them.
    let mut referenced = BTreeSet::new();
    collect_columns(expr, &mut referenced);

    let scan_kind = base_scan_kind(expr)?;
    let attrs: Vec<&str> = referenced
        .iter()
        .map(String::as_str)
        .filter(|c| !is_base_column(c))
        .collect();

    let cte = scan_cte(scan_kind, &attrs);
    let (select, from_filters_group) = lower(expr)?;
    Some(format!(
        "WITH scan AS (\n{cte}\n)\n{select} FROM scan{from_filters_group}"
    ))
}

/// The kind scanned at the base of the plan (the single `Scan` leaf), if the plan is
/// a linear single-scan pipeline.
fn base_scan_kind(expr: &RelExpr) -> Option<&str> {
    match expr {
        RelExpr::Scan { kind } => Some(kind),
        RelExpr::Filter { input, .. }
        | RelExpr::Project { input, .. }
        | RelExpr::Aggregate { input, .. } => base_scan_kind(input),
        // Joins / recursion / external calls are not single-scan SQL here.
        _ => None,
    }
}

/// Build the scan CTE: base columns + one pivoted column per referenced attribute.
fn scan_cte(kind: &str, attrs: &[&str]) -> String {
    let mut cols = vec![
        "f.fact_id".to_string(),
        "f.kind".to_string(),
        "f.subject".to_string(),
        "f.confidence".to_string(),
        "f.extractor".to_string(),
        "f.source_locator".to_string(),
        "f.source_line".to_string(),
        "f.source_inner".to_string(),
    ];
    for a in attrs {
        // COALESCE across typed value columns; cast non-string for predicates.
        cols.push(format!(
            "MAX(CASE WHEN a.key = '{a}' THEN COALESCE(a.val_str, CAST(a.val_int AS VARCHAR), \
             CAST(a.val_float AS VARCHAR), CAST(a.val_bool AS VARCHAR)) END) AS \"{a}\""
        ));
    }
    format!(
        "  SELECT {}\n  FROM facts f LEFT JOIN fact_attributes a USING (run_id, fact_id)\n  \
         WHERE f.kind = '{}'\n  GROUP BY f.fact_id, f.kind, f.subject, f.confidence, f.extractor, \
         f.source_locator, f.source_line, f.source_inner",
        cols.join(", "),
        escape(kind)
    )
}

/// Lower the pipeline above the scan into the SELECT + trailing clauses.
fn lower(expr: &RelExpr) -> Option<(String, String)> {
    match expr {
        RelExpr::Scan { .. } => Some(("SELECT *".to_string(), String::new())),
        RelExpr::Filter { input, predicate } => {
            let (select, rest) = lower(input)?;
            // A filter on an aggregate alias is HAVING; otherwise WHERE.
            let clause = predicate_sql(predicate);
            if rest.contains("GROUP BY") {
                Some((select, format!("{rest} HAVING {clause}")))
            } else {
                Some((select, push_where(&rest, &clause)))
            }
        }
        RelExpr::Project { input, columns } => {
            let (_, rest) = lower(input)?;
            let cols = columns
                .iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(", ");
            Some((format!("SELECT {cols}"), rest))
        }
        RelExpr::Aggregate {
            input,
            group_by,
            aggregates,
        } => {
            let (_, rest) = lower(input)?;
            let mut select_cols: Vec<String> =
                group_by.iter().map(|c| format!("\"{c}\"")).collect();
            for a in aggregates {
                select_cols.push(agg_sql(a));
            }
            let group = if group_by.is_empty() {
                String::new()
            } else {
                format!(
                    " GROUP BY {}",
                    group_by
                        .iter()
                        .map(|c| format!("\"{c}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            Some((
                format!("SELECT {}", select_cols.join(", ")),
                format!("{rest}{group}"),
            ))
        }
        _ => None,
    }
}

fn push_where(rest: &str, clause: &str) -> String {
    if rest.trim_start().starts_with("WHERE") {
        format!("{rest} AND {clause}")
    } else {
        format!(" WHERE {clause}{rest}")
    }
}

fn agg_sql(a: &Aggregate) -> String {
    let inner = match a.func {
        AggFunc::Count => "COUNT(*)".to_string(),
        AggFunc::Sum => format!("SUM(CAST(\"{}\" AS DOUBLE))", a.column),
        AggFunc::Avg => format!("AVG(CAST(\"{}\" AS DOUBLE))", a.column),
        AggFunc::Min => format!("MIN(CAST(\"{}\" AS DOUBLE))", a.column),
        AggFunc::Max => format!("MAX(CAST(\"{}\" AS DOUBLE))", a.column),
    };
    format!("{inner} AS \"{}\"", a.alias)
}

fn predicate_sql(p: &Predicate) -> String {
    let op = match p.op {
        CmpOp::Eq => "=",
        CmpOp::Ne => "<>",
        CmpOp::Lt => "<",
        CmpOp::Le => "<=",
        CmpOp::Gt => ">",
        CmpOp::Ge => ">=",
    };
    format!("\"{}\" {op} {}", p.column, scalar_sql(&p.value))
}

fn scalar_sql(v: &ScalarValue) -> String {
    match v {
        ScalarValue::Str(s) => format!("'{}'", escape(s)),
        ScalarValue::Int(i) => i.to_string(),
        ScalarValue::Float(f) => f.to_string(),
        ScalarValue::Bool(b) => b.to_string(),
    }
}

fn escape(s: &str) -> String {
    s.replace('\'', "''")
}

fn cmp_sql(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "=",
        CmpOp::Ne => "<>",
        CmpOp::Lt => "<",
        CmpOp::Le => "<=",
        CmpOp::Gt => ">",
        CmpOp::Ge => ">=",
    }
}

/// Render an alias-qualified column reference (`m.loader`, `s.attr:trust_score`,
/// `m.subject`) into SQL over the aliased scan CTE: base columns stay bare, attribute
/// fields address the pivoted `"attr"` column.
fn col_ref(qualified: &str) -> String {
    let (alias, rest) = match qualified.split_once('.') {
        Some((a, r)) => (a, r),
        None => return format!("\"{qualified}\""),
    };
    let field = rest.strip_prefix("attr:").unwrap_or(rest);
    if is_base_column(field) {
        format!("{alias}.{field}")
    } else {
        format!("{alias}.\"{field}\"")
    }
}

/// Render a [`Condition`] to SQL.
fn condition_sql(c: &Condition) -> String {
    match c {
        Condition::True => "TRUE".to_string(),
        Condition::Cmp { column, op, value } => {
            format!("{} {} {}", col_ref(column), cmp_sql(*op), scalar_sql(value))
        }
        Condition::ColCmp { left, op, right } => {
            format!("{} {} {}", col_ref(left), cmp_sql(*op), col_ref(right))
        }
        Condition::In { column, values } => {
            let list = values
                .iter()
                .map(|v| format!("'{}'", escape(v)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} IN ({list})", col_ref(column))
        }
        Condition::NotNull { column } => format!("{} IS NOT NULL", col_ref(column)),
        Condition::IsNull { column } => format!("{} IS NULL", col_ref(column)),
        Condition::And(a, b) => format!("({}) AND ({})", condition_sql(a), condition_sql(b)),
        Condition::Or(a, b) => format!("({}) OR ({})", condition_sql(a), condition_sql(b)),
        Condition::Not(a) => format!("NOT ({})", condition_sql(a)),
    }
}

/// Attribute fields (`alias` → non-base field) referenced by a condition, so each
/// side's scan CTE pivots exactly the columns it needs.
fn collect_condition_attrs(c: &Condition, out: &mut BTreeSet<(String, String)>) {
    let mut add = |q: &str| {
        if let Some((alias, rest)) = q.split_once('.') {
            let field = rest.strip_prefix("attr:").unwrap_or(rest);
            if !is_base_column(field) {
                out.insert((alias.to_string(), field.to_string()));
            }
        }
    };
    match c {
        Condition::True => {}
        Condition::Cmp { column, .. }
        | Condition::In { column, .. }
        | Condition::NotNull { column }
        | Condition::IsNull { column } => add(column),
        Condition::ColCmp { left, right, .. } => {
            add(left);
            add(right);
        }
        Condition::And(a, b) | Condition::Or(a, b) => {
            collect_condition_attrs(a, out);
            collect_condition_attrs(b, out);
        }
        Condition::Not(a) => collect_condition_attrs(a, out),
    }
}

/// SQL for a declarative join: two aliased scan CTEs cross-joined under the condition.
fn join_filter_sql(
    left_kind: &str,
    left_alias: &str,
    right_kind: &str,
    right_alias: &str,
    condition: &Condition,
) -> String {
    let mut attrs = BTreeSet::new();
    collect_condition_attrs(condition, &mut attrs);
    let side_attrs = |alias: &str| -> Vec<&str> {
        attrs
            .iter()
            .filter(|(a, _)| a == alias)
            .map(|(_, f)| f.as_str())
            .collect()
    };
    let left_cte = scan_cte(left_kind, &side_attrs(left_alias));
    let right_cte = scan_cte(right_kind, &side_attrs(right_alias));
    format!(
        "WITH {la} AS (\n{left_cte}\n),\n{ra} AS (\n{right_cte}\n)\nSELECT \
         {la}.fact_id AS left_fact_id, {la}.subject AS left_subject, \
         {ra}.fact_id AS right_fact_id, {ra}.subject AS right_subject\n\
         FROM {la} CROSS JOIN {ra}\nWHERE {cond}",
        la = left_alias,
        ra = right_alias,
        cond = condition_sql(condition),
    )
}

/// SQL for a GroupDistinct rule (group by subject, keep groups with ≥ min_count
/// distinct values of `distinct_attr`).
fn group_count_distinct_sql(
    kinds: &[String],
    group_col: &str,
    distinct_attr: &str,
    min_count: usize,
) -> String {
    let kind_list = kinds
        .iter()
        .map(|k| format!("'{}'", escape(k)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "SELECT f.subject AS \"{group_col}\"\n  FROM facts f JOIN fact_attributes a \
         USING (run_id, fact_id)\n  WHERE f.kind IN ({kind_list}) AND a.key = '{}'\n  \
         GROUP BY f.subject\n  HAVING COUNT(DISTINCT a.val_str) >= {min_count}",
        escape(distinct_attr),
    )
}

fn collect_columns(expr: &RelExpr, out: &mut BTreeSet<String>) {
    match expr {
        RelExpr::Scan { .. } => {}
        RelExpr::Filter { input, predicate } => {
            out.insert(predicate.column.clone());
            collect_columns(input, out);
        }
        RelExpr::Project { input, columns } => {
            out.extend(columns.iter().cloned());
            collect_columns(input, out);
        }
        RelExpr::Aggregate {
            input,
            group_by,
            aggregates,
        } => {
            out.extend(group_by.iter().cloned());
            for a in aggregates {
                if !a.column.is_empty() {
                    out.insert(a.column.clone());
                }
            }
            collect_columns(input, out);
        }
        RelExpr::Join { left, right, on } => {
            for (l, r) in on {
                out.insert(l.clone());
                out.insert(r.clone());
            }
            collect_columns(left, out);
            collect_columns(right, out);
        }
        RelExpr::Window {
            input,
            partition_by,
            order_by,
            functions,
        } => {
            out.extend(partition_by.iter().cloned());
            out.extend(order_by.iter().cloned());
            for f in functions {
                if !f.column.is_empty() {
                    out.insert(f.column.clone());
                }
            }
            collect_columns(input, out);
        }
        RelExpr::TransitiveClosure { input, from, to } => {
            out.insert(from.clone());
            out.insert(to.clone());
            collect_columns(input, out);
        }
        RelExpr::CallExternal { input, .. } => collect_columns(input, out),
        // These have their own SQL (handled before collect_columns) — no scan-CTE
        // attribute collection needed here.
        RelExpr::JoinFilter { .. } | RelExpr::GroupCountDistinct { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eq(col: &str, v: &str) -> Predicate {
        Predicate {
            column: col.into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str(v.into()),
        }
    }

    #[test]
    fn scan_filter_project_to_sql() {
        let plan = RelExpr::scan("mixin_application_site")
            .filter(eq("operation", "redirect"))
            .project(vec!["mod".into(), "target_class".into()]);
        let sql = to_sql(&plan).unwrap();
        // Pivots the referenced attributes and filters on them.
        assert!(sql.contains("WHERE f.kind = 'mixin_application_site'"));
        assert!(sql.contains("THEN COALESCE(a.val_str"));
        assert!(sql.contains("\"operation\""));
        assert!(sql.contains("\"operation\" = 'redirect'"));
        assert!(sql.contains("SELECT \"mod\", \"target_class\""));
    }

    #[test]
    fn aggregate_with_having_to_sql() {
        let plan = RelExpr::scan("hot_method")
            .aggregate(
                vec!["class".into()],
                vec![Aggregate {
                    func: AggFunc::Sum,
                    column: "percent".into(),
                    alias: "total".into(),
                }],
            )
            .filter(Predicate {
                column: "total".into(),
                op: CmpOp::Gt,
                value: ScalarValue::Int(50),
            });
        let sql = to_sql(&plan).unwrap();
        assert!(sql.contains("GROUP BY \"class\""));
        assert!(sql.contains("SUM(CAST(\"percent\" AS DOUBLE)) AS \"total\""));
        assert!(sql.contains("HAVING \"total\" > 50"));
    }

    #[test]
    fn non_single_scan_shapes_return_none() {
        // A top-level transitive closure is Souffle's job, not SQL.
        let plan = RelExpr::scan("dependency").transitive_closure("mod", "requires");
        assert!(to_sql(&plan).is_none());
    }

    #[test]
    fn sql_escapes_quotes() {
        let plan = RelExpr::scan("mod").filter(eq("name", "O'Hare"));
        let sql = to_sql(&plan).unwrap();
        assert!(sql.contains("'O''Hare'"));
    }
}
