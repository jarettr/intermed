//! Core SQL rule programs for the DuckDB backend.
//!
//! Declarative rules are generated from [`intermed_rules::default_core_pack_v2`] via
//! [`intermed_rules::sql_codegen`]. Legacy constants below remain for security-signal
//! aggregation and analytics until those rules move fully into the pack.

/// Pivot expression for boolean `hot_path` attributes (bool column or legacy str).
pub const HOT_PATH_EXPR: &str = r"
    MAX(CASE
        WHEN a.key = 'hot_path' AND a.val_bool IS NOT NULL THEN
            CASE WHEN a.val_bool THEN 'true' ELSE 'false' END
        WHEN a.key = 'hot_path' THEN a.val_str
    END)
";

pub const DUPLICATE_ID: &str = r"
    SELECT DISTINCT f1.subject AS id
    FROM facts f1
    JOIN fact_attributes a1
      ON f1.run_id = a1.run_id AND f1.fact_id = a1.fact_id AND a1.key = 'file'
    JOIN facts f2
      ON f1.run_id = f2.run_id AND f1.subject = f2.subject AND f1.fact_id < f2.fact_id
    JOIN fact_attributes a2
      ON f2.run_id = a2.run_id AND f2.fact_id = a2.fact_id AND a2.key = 'file'
    WHERE f1.run_id = '{run_id}'
      AND f1.kind IN ('mod', 'plugin')
      AND f2.kind IN ('mod', 'plugin')
      AND COALESCE(a1.val_str, '') != ''
      AND COALESCE(a2.val_str, '') != ''
      AND a1.val_str != a2.val_str
";

pub const MIXIN_OVERLAP: &str = r"
    SELECT
        f.subject AS target,
        MAX(CASE WHEN a.key = 'mods' THEN a.val_str END) AS mods,
        MAX(CASE WHEN a.key = 'operations' THEN a.val_str END) AS operations,
        __HOT_PATH__ AS hot_path,
        f.fact_id
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.run_id = '{run_id}' AND f.kind = 'mixin_overlap'
    GROUP BY f.run_id, f.fact_id, f.subject
";

pub const MIXIN_OVERWRITE: &str = r"
    SELECT
        f.subject AS mod_id,
        MAX(CASE WHEN a.key = 'target' THEN a.val_str END) AS target,
        __HOT_PATH__ AS hot_path,
        f.fact_id
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.run_id = '{run_id}' AND f.kind = 'high_risk_overwrite'
    GROUP BY f.run_id, f.fact_id, f.subject
";

pub const LOADER_MISMATCH: &str = r"
    WITH env AS (
        SELECT MAX(CASE WHEN a.key = 'loader' THEN a.val_str END) AS loader
        FROM facts f
        LEFT JOIN fact_attributes a
          ON f.run_id = a.run_id AND f.fact_id = a.fact_id
        WHERE f.run_id = '{run_id}' AND f.kind = 'environment'
    ),
    mods AS (
        SELECT
            f.fact_id,
            f.subject,
            MAX(CASE WHEN a.key = 'loader' THEN a.val_str END) AS loader
        FROM facts f
        LEFT JOIN fact_attributes a
          ON f.run_id = a.run_id AND f.fact_id = a.fact_id
        WHERE f.run_id = '{run_id}' AND f.kind = 'mod'
        GROUP BY f.fact_id, f.subject
    )
    SELECT m.fact_id, m.subject, m.loader, e.loader AS env_loader
    FROM mods m
    CROSS JOIN env e
    WHERE e.loader IN ('fabric', 'quilt', 'forge', 'neoforge')
      AND m.loader IN ('fabric', 'quilt', 'forge', 'neoforge')
      AND m.loader != e.loader
";

pub const SIDE_MISMATCH: &str = r"
    WITH env AS (
        SELECT MAX(CASE WHEN a.key = 'side' THEN a.val_str END) AS side
        FROM facts f
        LEFT JOIN fact_attributes a
          ON f.run_id = a.run_id AND f.fact_id = a.fact_id
        WHERE f.run_id = '{run_id}' AND f.kind = 'environment'
    ),
    mod_sides AS (
        SELECT
            f.fact_id,
            f.subject,
            MAX(CASE WHEN a.key = 'side' THEN a.val_str END) AS mod_side
        FROM facts f
        LEFT JOIN fact_attributes a
          ON f.run_id = a.run_id AND f.fact_id = a.fact_id
        WHERE f.run_id = '{run_id}' AND f.kind = 'mod_side'
        GROUP BY f.fact_id, f.subject
    )
    SELECT ms.fact_id, ms.subject, ms.mod_side, e.side AS env_side
    FROM mod_sides ms
    CROSS JOIN env e
    WHERE ms.mod_side IS NOT NULL
      AND ms.mod_side != 'both'
      AND e.side IS NOT NULL
      AND ms.mod_side != e.side
";

pub const RESOURCE_CONFLICT: &str = r"
    SELECT
        f.subject AS path,
        f.fact_id,
        MAX(CASE WHEN a.key = 'class' THEN a.val_str END) AS class,
        MAX(CASE WHEN a.key = 'writers' THEN a.val_str END) AS writers,
        MAX(CASE WHEN a.key = 'reason' THEN a.val_str END) AS reason
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.run_id = '{run_id}' AND f.kind = 'resource_collision'
    GROUP BY f.run_id, f.fact_id, f.subject
    HAVING COALESCE(class, '') != '' AND class != 'identical'
";

pub const LOG_SIGNAL: &str = r"
    SELECT
        f.subject AS signal,
        f.fact_id,
        MAX(CASE WHEN a.key = 'line' THEN a.val_int END) AS line_no,
        MAX(CASE WHEN a.key = 'excerpt' THEN a.val_str END) AS excerpt
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.run_id = '{run_id}' AND f.kind = 'log_signal'
    GROUP BY f.run_id, f.fact_id, f.subject
";

pub const UNKNOWN_SOURCE: &str = r"
    SELECT f.subject AS archive, f.fact_id
    FROM facts f
    WHERE f.run_id = '{run_id}' AND f.kind = 'unknown_source'
";

pub const UNSIGNED_JAR: &str = r"
    SELECT f.subject AS archive, f.fact_id
    FROM facts f
    JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
     AND a.key = 'status' AND a.val_str = 'unsigned'
    WHERE f.run_id = '{run_id}' AND f.kind = 'signature_status'
";

/// Per-mod security signal rows for Rust-side thresholding and severity.
pub const SECURITY_SIGNALS: &str = r"
    SELECT
        f.subject AS mod_id,
        f.kind AS signal_kind,
        f.fact_id,
        MAX(CASE WHEN a.key = 'archive' THEN a.val_str END) AS archive,
        MAX(CASE WHEN a.key = 'provenance' THEN a.val_str END) AS provenance,
        MAX(CASE WHEN a.key = 'evidence_strength' THEN a.val_str END) AS evidence_strength,
        MAX(CASE WHEN a.key = 'dangerous_classes' THEN a.val_int END) AS dangerous_classes,
        MAX(CASE WHEN a.key = 'classes_scanned' THEN a.val_int END) AS classes_scanned,
        MAX(CASE WHEN a.key = 'affected_classes' THEN a.val_int END) AS affected_classes
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.run_id = '{run_id}'
      AND f.kind IN (
        'uses_process_spawn', 'uses_socket', 'uses_reflection_set_accessible',
        'uses_unsafe', 'uses_native_library', 'uses_dynamic_class_definition',
        'uses_reflective_invocation', 'uses_script_engine', 'uses_deserialization',
        'uses_system_exit'
      )
    GROUP BY f.run_id, f.fact_id, f.subject, f.kind
";

/// Low-trust archives with at least one high-risk capability fact.
pub const SBOM_SECURITY_CORRELATION: &str = r"
    WITH trust AS (
        SELECT
            f.subject AS archive,
            MAX(CASE WHEN a.key = 'trust_score' THEN a.val_int END) AS trust_score
        FROM facts f
        LEFT JOIN fact_attributes a
          ON f.run_id = a.run_id AND f.fact_id = a.fact_id
        WHERE f.run_id = '{run_id}' AND f.kind = 'sbom'
        GROUP BY f.subject
    ),
    risky AS (
        -- Resolve each capability fact's archive attribute first (one row per
        -- fact), then collapse to one representative fact per (archive, kind).
        -- Grouping on the resolved column avoids DuckDB rejecting an aggregate
        -- alias in GROUP BY.
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
            WHERE f.run_id = '{run_id}'
              AND f.kind IN (
                'uses_process_spawn', 'uses_unsafe',
                'uses_dynamic_class_definition', 'uses_script_engine'
              )
            GROUP BY f.fact_id, f.kind
        ) per_fact
        WHERE per_fact.archive IS NOT NULL
        GROUP BY per_fact.archive, per_fact.capability_kind
    )
    SELECT
        r.archive,
        r.capability_kind,
        r.fact_id,
        COALESCE(t.trust_score, 0) AS trust_score
    FROM risky r
    LEFT JOIN trust t ON r.archive = t.archive
    WHERE COALESCE(t.trust_score, 0) < {well_identified_trust}
";

/// SQL programs shipped by the DuckDB rule pack (for docs/tests).
pub const CORE_RULES: &[&str] = &[
    "duplicate_id",
    "mixin_overlap",
    "mixin_overwrite",
    "loader_mismatch",
    "side_mismatch",
    "resource_conflict",
    "log_signal",
    "unknown_source",
    "unsigned_jar",
    "security_signals",
    "sbom_security_correlation",
];

/// Rule ids with generated SQL from the embedded v2 pack (SSOT).
pub fn generated_rule_ids() -> Vec<String> {
    intermed_rules::default_core_pack_v2()
        .rules
        .iter()
        .filter(|r| {
            matches!(
                intermed_rules::rule_to_ir(r),
                intermed_rules::Lowering::Ir(_)
            )
        })
        .map(|r| r.id.clone())
        .collect()
}

#[must_use]
pub fn bind_run(sql: &str, run_id: &str) -> String {
    sql.replace("{run_id}", run_id)
}

#[must_use]
pub fn prepare(sql: &str, run_id: &str) -> String {
    bind_run(&sql.replace("__HOT_PATH__", HOT_PATH_EXPR), run_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_run_substitutes_run_id() {
        let sql = bind_run("SELECT 1 WHERE run_id = '{run_id}'", "abc");
        assert!(sql.contains("abc"));
        assert!(!sql.contains("{run_id}"));
    }

    #[test]
    fn core_rules_catalog_has_eleven_entries() {
        assert_eq!(CORE_RULES.len(), 11);
    }

    #[test]
    fn generated_pack_exposes_join_rules() {
        let ids = generated_rule_ids();
        assert!(ids.iter().any(|id| id == "loader-mismatch"));
    }
}
