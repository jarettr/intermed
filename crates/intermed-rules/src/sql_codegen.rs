//! DuckDB SQL generation from declarative [`RuleSpec`] entries.
//!
//! Generated queries pivot `fact_attributes` into row shapes consumed by
//! [`intermed_duckdb::rules`] row mappers. `{run_id}` and settings placeholders
//! are preserved for bind-time substitution.

use crate::model::RulePack;

/// Pivot expression for boolean `hot_path` attributes (bool column or legacy str).
pub const HOT_PATH_EXPR: &str = r"
    MAX(CASE
        WHEN a.key = 'hot_path' AND a.val_bool IS NOT NULL THEN
            CASE WHEN a.val_bool THEN 'true' ELSE 'false' END
        WHEN a.key = 'hot_path' THEN a.val_str
    END)
";

/// Substitute `{run_id}` and hot-path pivot for evaluation-time binding.
#[must_use]
pub fn prepare_sql(sql: &str, run_id: &str) -> String {
    let run_id_esc = escape_sql_literal(run_id);
    sql.replace("{run_id}", &run_id_esc)
        .replace("__HOT_PATH__", HOT_PATH_EXPR)
}

fn escape_sql_literal(val: &str) -> String {
    val.replace('\'', "''")
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
    // Per-rule SQL now comes from the unified IR backend (single source of truth).
    out.push_str(&crate::generate::generate_rules(
        pack,
        crate::generate::GenerateBackend::Sql,
    ));
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
        // The Join rule SQL now comes from the unified IR backend.
        let pack = default_core_pack_v2();
        let sql = crate::generate::generate_rules(&pack, crate::generate::GenerateBackend::Sql);
        assert!(sql.contains("loader-mismatch"));
        assert!(sql.contains("CROSS JOIN"));
        assert!(sql.contains("loader"));
    }
}
