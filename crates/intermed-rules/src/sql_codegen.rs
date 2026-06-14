//! DuckDB SQL generation from declarative [`RuleSpec`] entries.
//!
//! Generated queries pivot `fact_attributes` into row shapes consumed by
//! [`intermed_duckdb::rules`] row mappers. `{run_id}` and settings placeholders
//! are preserved for bind-time substitution.

use crate::model::{RuleKind, RulePack, RuleSpec};

/// Pivot expression for boolean `hot_path` attributes (bool column or legacy str).
pub const HOT_PATH_EXPR: &str = r"
    MAX(CASE
        WHEN a.key = 'hot_path' AND a.val_bool IS NOT NULL THEN
            CASE WHEN a.val_bool THEN 'true' ELSE 'false' END
        WHEN a.key = 'hot_path' THEN a.val_str
    END)
";

/// One generated SQL program with stable id for tests and CLI output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedSqlRule {
    pub id: String,
    pub sql: String,
}

/// Generate SQL for every rule in `pack`.
pub fn generate_pack_sql(pack: &RulePack) -> Vec<GeneratedSqlRule> {
    pack.rules
        .iter()
        .filter_map(|rule| {
            let sql = rule_to_sql(rule)?;
            Some(GeneratedSqlRule {
                id: rule.id.clone(),
                sql,
            })
        })
        .collect()
}

/// Map a declarative rule to DuckDB SQL when the kind is supported.
pub fn rule_to_sql(rule: &RuleSpec) -> Option<String> {
    match rule.kind {
        RuleKind::GroupDistinct => Some(sql_group_distinct(rule)),
        RuleKind::FactFinding => Some(sql_fact_finding(rule)),
        RuleKind::Join => sql_join(rule),
        RuleKind::Aggregate => sql_aggregate(rule),
        RuleKind::Correlation => sql_correlation(rule),
    }
}

fn sql_group_distinct(rule: &RuleSpec) -> String {
    let kinds: Vec<String> = rule
        .input_kinds
        .iter()
        .map(|k| format!("'{k}'"))
        .collect();
    let group = rule.group_by.as_deref().unwrap_or("subject");
    let distinct = rule
        .distinct
        .as_deref()
        .and_then(|d| d.strip_prefix("attr:"))
        .unwrap_or("file");
    format!(
        r"
    SELECT f.subject AS {group}
    FROM facts f
    JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id AND a.key = '{distinct}'
    WHERE f.run_id = '{{run_id}}'
      AND f.kind IN ({kinds})
    GROUP BY f.run_id, f.subject
    HAVING COUNT(DISTINCT a.val_str) >= {min_count}
",
        group = group,
        distinct = distinct,
        kinds = kinds.join(", "),
        min_count = rule.min_count,
    )
}

fn sql_fact_finding(rule: &RuleSpec) -> String {
    let kind = rule.input_kinds.first().map(String::as_str).unwrap_or("?");
    let mut filters = Vec::new();
    for (term, expected) in &rule.where_all {
        if let Some(attr) = term.strip_prefix("attr:") {
            filters.push(format!(
                "MAX(CASE WHEN a.key = '{attr}' THEN COALESCE(a.val_str, CAST(a.val_bool AS VARCHAR), CAST(a.val_int AS VARCHAR)) END) = '{expected}'"
            ));
        } else if term == "subject" {
            filters.push(format!("f.subject = '{expected}'"));
        }
    }
    let having = if filters.is_empty() {
        String::new()
    } else {
        format!("\n    HAVING {}", filters.join(" AND "))
    };
    let hot_select = if rule.where_all.contains_key("attr:hot_path") {
        format!(",\n        {HOT_PATH_EXPR} AS hot_path")
    } else {
        String::new()
    };
    format!(
        r"
    SELECT
        f.subject,
        f.fact_id{hot_select}
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.run_id = '{{run_id}}' AND f.kind = '{kind}'
    GROUP BY f.run_id, f.fact_id, f.subject{having}
",
        kind = kind,
        hot_select = hot_select,
        having = having,
    )
}

fn sql_join(rule: &RuleSpec) -> Option<String> {
    let left = rule.left.as_ref()?;
    let right = rule.right.as_ref()?;
    let left_cte = fact_cte(left);
    let right_cte = fact_cte(right);
    let on = rule.on.as_deref().unwrap_or("TRUE");
    let filter = rule.r#where.as_deref().unwrap_or("TRUE");
    let on_sql = expr_to_sql(on);
    let where_sql = expr_to_sql(filter);
    Some(format!(
        r"
    WITH {left_cte},
    {right_cte}
    SELECT
        {left_alias}.fact_id AS left_fact_id,
        {left_alias}.subject AS left_subject,
        {right_alias}.fact_id AS right_fact_id
    FROM {left_alias}
    CROSS JOIN {right_alias}
    WHERE {on_sql} AND {where_sql}
",
        left_cte = left_cte,
        right_cte = right_cte,
        left_alias = left.alias,
        right_alias = right.alias,
        on_sql = on_sql,
        where_sql = where_sql,
    ))
}

fn sql_aggregate(rule: &RuleSpec) -> Option<String> {
    let input = rule.input.as_ref()?;
    let cte = fact_cte(input);
    let having = rule
        .having
        .as_deref()
        .map(expr_to_sql)
        .unwrap_or_else(|| "TRUE".to_string());
    Some(format!(
        r"
    WITH {cte}
    SELECT {alias}.fact_id, {alias}.subject
    FROM {alias}
    WHERE {having}
",
        cte = cte,
        alias = input.alias,
        having = having,
    ))
}

fn sql_correlation(rule: &RuleSpec) -> Option<String> {
    let anchor = rule.anchor.as_ref()?;
    let filter = rule
        .r#where
        .as_deref()
        .map(expr_to_sql)
        .unwrap_or_else(|| "TRUE".to_string());
    let kinds: Vec<String> = rule
        .related_kinds
        .iter()
        .map(|k| format!("'{k}'"))
        .collect();
    Some(format!(
        r"
    WITH anchor AS (
        SELECT f.fact_id, f.subject,
               MAX(CASE WHEN a.key = 'trust_score' THEN a.val_int END) AS trust_score
        FROM facts f
        LEFT JOIN fact_attributes a
          ON f.run_id = a.run_id AND f.fact_id = a.fact_id
        WHERE f.run_id = '{{run_id}}' AND f.kind = '{anchor_kind}'
        GROUP BY f.fact_id, f.subject
    ),
    related AS (
        SELECT
            per_fact.archive AS archive,
            per_fact.capability_kind AS capability_kind,
            MIN(per_fact.fact_id) AS fact_id
        FROM (
            SELECT
                f.fact_id AS fact_id,
                f.kind AS capability_kind,
                MAX(CASE WHEN a.key = 'archive' THEN a.val_str END) AS archive
            FROM facts f
            LEFT JOIN fact_attributes a
              ON f.run_id = a.run_id AND f.fact_id = a.fact_id
            WHERE f.run_id = '{{run_id}}' AND f.kind IN ({kinds})
            GROUP BY f.fact_id, f.kind
        ) per_fact
        WHERE per_fact.archive IS NOT NULL
        GROUP BY per_fact.archive, per_fact.capability_kind
    )
    SELECT a.subject AS archive, r.capability_kind, r.fact_id, COALESCE(a.trust_score, 0) AS trust_score
    FROM anchor a
    JOIN related r ON a.subject = r.archive
    WHERE {filter}
",
        anchor_kind = anchor.kind,
        kinds = kinds.join(", "),
        filter = filter
            .replace("s.attr:trust_score", "a.trust_score")
            .replace("s.subject", "a.subject")
            .replace(
                "{settings.sbom.well_identified_trust}",
                "{well_identified_trust}",
            ),
    ))
}

fn fact_cte(source: &crate::model::FactSource) -> String {
    // Pivot exactly the attributes the rule selects (`attr:X` → column `X`), so any
    // join can reference `alias.X` in its `on`/`where`. `loader`/`side`/`file` are
    // always pivoted for backward compatibility with the historical hardcoded set.
    let mut attrs: Vec<String> = vec!["loader".into(), "side".into(), "file".into()];
    for term in &source.select {
        if let Some(attr) = term.strip_prefix("attr:") {
            if !attrs.iter().any(|a| a == attr) {
                attrs.push(attr.to_string());
            }
        }
    }
    let pivots: String = attrs
        .iter()
        .map(|attr| {
            format!(
                ",\n            MAX(CASE WHEN a.key = '{attr}' THEN COALESCE(a.val_str, CAST(a.val_int AS VARCHAR), CAST(a.val_bool AS VARCHAR)) END) AS {attr}"
            )
        })
        .collect();
    format!(
        r#"{alias} AS (
        SELECT
            f.fact_id,
            f.subject{pivots}
        FROM facts f
        LEFT JOIN fact_attributes a
          ON f.run_id = a.run_id AND f.fact_id = a.fact_id
        WHERE f.run_id = '{{run_id}}' AND f.kind = '{kind}'
        GROUP BY f.fact_id, f.subject
    )"#,
        alias = source.alias,
        kind = source.kind,
        pivots = pivots,
    )
}

fn expr_to_sql(expr: &str) -> String {
    // `alias.attr` references already match the pivoted column names produced by
    // `fact_cte`, so only genuine dialect/semantic translations are applied here.
    expr.replace("!=", "<>")
        .replace("TRUE", "1=1")
        .replace("m.mod_side", "m.side")
        .replace("e.mod_side", "e.side")
}

/// Substitute `{run_id}` and hot-path pivot for evaluation-time binding.
#[must_use]
pub fn prepare_sql(sql: &str, run_id: &str) -> String {
    sql.replace("{run_id}", run_id)
        .replace("__HOT_PATH__", HOT_PATH_EXPR)
}

/// DuckDB `CREATE OR REPLACE VIEW` programs for analytics over materialized facts.
///
/// These complement rule-generated SQL (`generate_pack_sql`) with cross-run rollups
/// operators can query via `intermed db query` without hand-writing pivots.
pub const ANALYTICS_VIEW_DDL: &str = r"
CREATE OR REPLACE VIEW rule_fact_inputs AS
SELECT DISTINCT kind AS fact_kind
FROM facts
WHERE kind IS NOT NULL;

CREATE OR REPLACE VIEW security_low_trust_capabilities AS
WITH trust AS (
    SELECT
        f.run_id,
        f.subject AS archive,
        MAX(CASE WHEN a.key = 'trust_score' THEN a.val_int END) AS trust_score
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.kind = 'sbom'
    GROUP BY f.run_id, f.subject
),
risky AS (
    SELECT
        f.run_id,
        COALESCE(MAX(CASE WHEN a.key = 'archive' THEN a.val_str END), f.subject) AS archive,
        f.kind AS capability
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.kind LIKE 'uses_%'
    GROUP BY f.run_id, f.fact_id, f.subject, f.kind
)
SELECT
    r.run_id,
    r.archive,
    r.capability,
    COALESCE(t.trust_score, 0) AS trust_score
FROM risky r
LEFT JOIN trust t ON r.run_id = t.run_id AND r.archive = t.archive
WHERE COALESCE(t.trust_score, 0) < {well_identified_trust};

CREATE OR REPLACE VIEW mixin_overlap_hotpaths AS
SELECT
    f.run_id,
    f.subject AS target,
    MAX(CASE WHEN a.key = 'mods' THEN a.val_str END) AS mods,
    MAX(CASE WHEN a.key = 'operations' THEN a.val_str END) AS operations,
    MAX(CASE
        WHEN a.key = 'hot_path' AND a.val_bool IS NOT NULL THEN
            CASE WHEN a.val_bool THEN 'true' ELSE 'false' END
        WHEN a.key = 'hot_path' THEN a.val_str
    END) AS hot_path
FROM facts f
LEFT JOIN fact_attributes a
  ON f.run_id = a.run_id AND f.fact_id = a.fact_id
WHERE f.kind = 'mixin_overlap'
GROUP BY f.run_id, f.fact_id, f.subject
HAVING COALESCE(hot_path, 'false') IN ('true', '1');

CREATE OR REPLACE VIEW log_signal_hot_methods AS
SELECT
    f.run_id,
    f.subject AS signal,
    MAX(CASE WHEN a.key = 'excerpt' THEN a.val_str END) AS excerpt,
    MAX(CASE WHEN a.key = 'line' THEN a.val_int END) AS line_no
FROM facts f
LEFT JOIN fact_attributes a
  ON f.run_id = a.run_id AND f.fact_id = a.fact_id
WHERE f.kind = 'log_signal'
  AND f.subject IN ('tick-overrun', 'mspt-spike', 'server-overloaded')
GROUP BY f.run_id, f.fact_id, f.subject;
";

/// Bind analytics view placeholders for one evaluation context.
#[must_use]
pub fn prepare_analytics_views(sql: &str, well_identified_trust: i64) -> String {
    sql.replace(
        "{well_identified_trust}",
        &well_identified_trust.to_string(),
    )
}

/// Emit analytics view DDL plus one generated SELECT per declarative rule (for docs/CLI).
#[must_use]
pub fn generate_analytics_bundle(pack: &RulePack, well_identified_trust: i64) -> String {
    let mut out = prepare_analytics_views(ANALYTICS_VIEW_DDL, well_identified_trust);
    out.push_str("\n-- ── Rule pack queries (per-run; bind {run_id}) ──\n");
    for entry in generate_pack_sql(pack) {
        out.push_str(&format!("\n-- rule: {}\n", entry.id));
        out.push_str(&entry.sql);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::default_core_pack_v2;

    #[test]
    fn analytics_bundle_includes_views_and_rules() {
        let pack = default_core_pack_v2();
        let bundle = generate_analytics_bundle(&pack, 60);
        assert!(bundle.contains("CREATE OR REPLACE VIEW security_low_trust_capabilities"));
        assert!(bundle.contains("loader-mismatch"));
        assert!(bundle.contains("60"));
    }

    #[test]
    fn core_pack_generates_sql_for_join_rules() {
        let pack = default_core_pack_v2();
        let generated = generate_pack_sql(&pack);
        let loader = generated
            .iter()
            .find(|r| r.id == "loader-mismatch")
            .expect("loader-mismatch sql");
        assert!(loader.sql.contains("CROSS JOIN"));
        assert!(loader.sql.contains("loader"));
    }
}