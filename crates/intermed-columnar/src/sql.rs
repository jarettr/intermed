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

use intermed_facts::schema_contract::{AttrType, contract};

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
            filters,
            min_count,
        } => {
            return group_count_distinct_sql(kinds, group_col, distinct_attr, filters, *min_count);
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
    let kind_schema = contract().kind(kind);
    for a in attrs {
        let value = match kind_schema.and_then(|kind| kind.attrs.get(*a)) {
            Some(AttrType::String | AttrType::Enum(_)) => "a.val_str".to_string(),
            Some(AttrType::Int) => "a.val_int".to_string(),
            Some(AttrType::Float) => "a.val_float".to_string(),
            Some(AttrType::Bool) => "a.val_bool".to_string(),
            // Legacy or intentionally incomplete fact schemas cannot provide a
            // stable physical type. Preserve display compatibility only there.
            None => display_value_sql("a"),
        };
        cols.push(format!(
            "MAX(CASE WHEN a.key = {} THEN {value} END) AS {}",
            quote_literal(a),
            quote_identifier(a),
        ));
    }
    format!(
        "  SELECT {}\n  FROM facts f LEFT JOIN fact_attributes a USING (run_id, fact_id)\n  \
         WHERE f.kind = {}\n  GROUP BY f.fact_id, f.kind, f.subject, f.confidence, f.extractor, \
         f.source_locator, f.source_line, f.source_inner",
        cols.join(", "),
        quote_literal(kind)
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
                .map(|c| quote_identifier(c))
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
                group_by.iter().map(|c| quote_identifier(c)).collect();
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
                        .map(|c| quote_identifier(c))
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
    let column = quote_identifier(&a.column);
    let inner = match a.func {
        AggFunc::Count => "COUNT(*)".to_string(),
        AggFunc::Sum => format!("SUM(CAST({column} AS DOUBLE))"),
        AggFunc::Avg => format!("AVG(CAST({column} AS DOUBLE))"),
        AggFunc::Min => format!("MIN(CAST({column} AS DOUBLE))"),
        AggFunc::Max => format!("MAX(CAST({column} AS DOUBLE))"),
    };
    format!("{inner} AS {}", quote_identifier(&a.alias))
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
    format!(
        "{} {op} {}",
        quote_identifier(&p.column),
        scalar_sql(&p.value)
    )
}

fn scalar_sql(v: &ScalarValue) -> String {
    match v {
        ScalarValue::Str(s) => quote_literal(s),
        ScalarValue::Int(i) => i.to_string(),
        ScalarValue::Float(f) => f.to_string(),
        ScalarValue::Bool(b) => b.to_string(),
    }
}

fn quote_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn quote_identifier(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Canonical display projection for a dynamically typed attribute. This is only
/// used by legacy/incomplete schemas and GroupDistinct's deliberately display-based
/// equality contract.
fn display_value_sql(alias: &str) -> String {
    let alias = quote_identifier(alias);
    format!(
        "COALESCE({alias}.val_str, CAST({alias}.val_int AS VARCHAR), \
         CAST({alias}.val_float AS VARCHAR), CAST({alias}.val_bool AS VARCHAR))"
    )
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
        None => return quote_identifier(qualified),
    };
    let field = rest.strip_prefix("attr:").unwrap_or(rest);
    format!("{}.{}", quote_identifier(alias), quote_identifier(field))
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
                .map(|v| quote_literal(v))
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
        la = quote_identifier(left_alias),
        ra = quote_identifier(right_alias),
        cond = condition_sql(condition),
    )
}

/// SQL for a GroupDistinct rule. The specialised relation deliberately uses the
/// interpreter's display equality for grouped/distinct terms while retaining
/// NULL-as-missing semantics.
fn group_count_distinct_sql(
    kinds: &[String],
    group_col: &str,
    distinct_attr: &str,
    filters: &[Predicate],
    min_count: usize,
) -> Option<String> {
    if kinds.is_empty() || group_col.is_empty() || distinct_attr.is_empty() {
        return None;
    }
    let mut attrs = BTreeSet::new();
    if !is_base_column(group_col) {
        attrs.insert(group_col);
    }
    if !is_base_column(distinct_attr) {
        attrs.insert(distinct_attr);
    }
    for filter in filters {
        if !is_base_column(&filter.column) {
            attrs.insert(filter.column.as_str());
        }
    }
    let attrs: Vec<&str> = attrs.into_iter().collect();

    let scans = kinds
        .iter()
        .enumerate()
        .map(|(index, kind)| {
            let name = quote_identifier(&format!("group_input_{index}"));
            format!("{name} AS (\n{}\n)", display_scan_cte(kind, &attrs))
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let union = (0..kinds.len())
        .map(|index| {
            format!(
                "SELECT * FROM {}",
                quote_identifier(&format!("group_input_{index}"))
            )
        })
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let group = quote_identifier(group_col);
    let distinct = quote_identifier(distinct_attr);
    let mut clauses = vec![
        format!("{group} IS NOT NULL"),
        format!("{distinct} IS NOT NULL"),
    ];
    clauses.extend(filters.iter().map(predicate_sql));
    Some(format!(
        "WITH {scans},\n{source} AS ({union})\nSELECT {group} AS {group}\n  FROM {source}\n  \
         WHERE {where_clause}\n  GROUP BY {group}\n  \
         HAVING COUNT(DISTINCT {distinct}) >= {min_count}",
        source = quote_identifier("group_source"),
        where_clause = clauses.join(" AND "),
    ))
}

fn display_scan_cte(kind: &str, attrs: &[&str]) -> String {
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
    for attr in attrs {
        cols.push(format!(
            "MAX(CASE WHEN a.key = {} THEN {} END) AS {}",
            quote_literal(attr),
            display_value_sql("a"),
            quote_identifier(attr),
        ));
    }
    format!(
        "  SELECT {}\n  FROM facts f LEFT JOIN fact_attributes a USING (run_id, fact_id)\n  \
         WHERE f.kind = {}\n  GROUP BY f.fact_id, f.kind, f.subject, f.confidence, f.extractor, \
         f.source_locator, f.source_line, f.source_inner",
        cols.join(", "),
        quote_literal(kind),
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
        assert!(sql.contains("THEN COALESCE(\"a\".val_str"));
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
    fn schema_typed_attributes_remain_typed_in_scan_cte() {
        let plan = RelExpr::scan("artifact_role").filter(Predicate {
            column: "ordinal".into(),
            op: CmpOp::Ge,
            value: ScalarValue::Int(2),
        });
        let sql = to_sql(&plan).unwrap();
        assert!(sql.contains("THEN a.val_int END) AS \"ordinal\""), "{sql}");
        assert!(sql.contains("\"ordinal\" >= 2"));
        assert!(!sql.contains("CAST(a.val_int AS VARCHAR)"));
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

    #[test]
    fn identifiers_are_quoted_independently_from_literals() {
        let plan = RelExpr::scan("mod").project(vec!["odd\"column".into()]);
        let sql = to_sql(&plan).unwrap();
        assert!(sql.contains("\"odd\"\"column\""));

        let join = RelExpr::JoinFilter {
            left_kind: "mod".into(),
            left_alias: "left\"alias".into(),
            right_kind: "plugin".into(),
            right_alias: "right".into(),
            condition: Condition::True,
        };
        let sql = to_sql(&join).unwrap();
        assert!(sql.contains("\"left\"\"alias\" AS"));
        assert!(!sql.contains("WITH left\"alias AS"));
    }

    #[test]
    fn group_distinct_uses_requested_group_typed_values_and_filters() {
        let plan = RelExpr::GroupCountDistinct {
            kinds: vec!["mod".into(), "plugin".into()],
            group_col: "loader".into(),
            distinct_attr: "numeric_id".into(),
            filters: vec![eq("side", "client")],
            min_count: 2,
        };
        let sql = to_sql(&plan).unwrap();
        assert!(sql.contains("SELECT \"loader\" AS \"loader\""));
        assert!(sql.contains("GROUP BY \"loader\""));
        assert!(sql.contains("COUNT(DISTINCT \"numeric_id\")"));
        assert!(sql.contains("CAST(\"a\".val_int AS VARCHAR)"));
        assert!(sql.contains("\"side\" = 'client'"));
        assert!(!sql.contains("GROUP BY f.subject"));
    }
}
