//! DuckDB execution of the columnar query IR (the accelerated backend route).
//!
//! This is the live half of the columnar migration's DuckDB path: it ingests the
//! Arrow projection of the facts directly via the appender (zero-copy — duckdb-rs
//! and `intermed-columnar` share the same `arrow` 58 crate), then executes a
//! relational plan by lowering it through [`intermed_columnar::to_sql`] and reading
//! the result back as Arrow. The in-process executor remains the correctness
//! reference; a dual-path test asserts the two agree, so routing a rule to DuckDB
//! is provably equivalent — the prerequisite for cutting the old codegen over.

use duckdb::Connection;

use intermed_columnar::ir::RelExpr;
use intermed_columnar::{Row, Value, facts_to_batches, record_batch_to_rows, to_sql};
use intermed_facts::Fact;

/// Errors running an IR plan through DuckDB.
#[derive(Debug, thiserror::Error)]
pub enum IrEngineError {
    #[error("duckdb: {0}")]
    Duck(#[from] duckdb::Error),
    #[error("columnar: {0}")]
    Columnar(#[from] intermed_columnar::ColumnarError),
    /// The plan shape is not single-scan SQL (a top-level recursion / external call),
    /// so it belongs on another engine, not DuckDB.
    #[error("plan not lowerable to DuckDB SQL")]
    NotSql,
}

/// DDL for the in-memory tables, matching the Arrow projection schema exactly so the
/// appender can ingest the record batches by column.
const DDL: &str = "\
CREATE TABLE facts (
    run_id VARCHAR, fact_id UBIGINT, kind VARCHAR, subject VARCHAR, confidence FLOAT,
    extractor VARCHAR, source_locator VARCHAR, source_line INTEGER, source_inner VARCHAR
);
CREATE TABLE fact_attributes (
    run_id VARCHAR, fact_id UBIGINT, key VARCHAR, val_type VARCHAR,
    val_str VARCHAR, val_int BIGINT, val_float DOUBLE, val_bool BOOLEAN
);";

/// An in-memory DuckDB instance loaded with the columnar facts, ready to run IR.
pub struct DuckIrEngine {
    conn: Connection,
}

impl DuckIrEngine {
    /// Build an engine from facts: project to Arrow once, append both batches.
    pub fn from_facts(facts: &[Fact]) -> Result<Self, IrEngineError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(DDL)?;
        let batches = facts_to_batches(facts, "run")?;
        {
            let mut app = conn.appender("facts")?;
            app.append_record_batch(batches.facts)?;
        }
        {
            let mut app = conn.appender("fact_attributes")?;
            app.append_record_batch(batches.attributes)?;
        }
        Ok(Self { conn })
    }

    /// Execute a relational plan by lowering it to SQL and reading the Arrow result.
    pub fn run(&self, ir: &RelExpr) -> Result<Vec<Row>, IrEngineError> {
        let sql = to_sql(ir).ok_or(IrEngineError::NotSql)?;
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = Vec::new();
        for batch in stmt.query_arrow([])? {
            rows.extend(record_batch_to_rows(&batch));
        }
        Ok(rows)
    }

    /// The SQL a plan lowers to (for inspection / `--explain`).
    pub fn explain(ir: &RelExpr) -> Option<String> {
        to_sql(ir)
    }
}

/// Compare two result sets on a chosen set of output columns, by *display* value
/// (DuckDB returns the attribute pivot as strings; the in-process engine keeps types
/// — so equivalence is checked on rendered values). Returns the symmetric difference
/// as `(only_a, only_b)` multisets; empty ⇒ the engines agree.
pub fn result_divergence(a: &[Row], b: &[Row], columns: &[&str]) -> (Vec<String>, Vec<String>) {
    fn key(rows: &[Row], columns: &[&str]) -> Vec<String> {
        let mut keys: Vec<String> = rows
            .iter()
            .map(|row| {
                columns
                    .iter()
                    .map(|c| row.get(*c).map(Value::to_display).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join("\u{1}")
            })
            .collect();
        keys.sort();
        keys
    }
    let ka = key(a, columns);
    let kb = key(b, columns);
    let sb: std::collections::BTreeMap<&String, usize> =
        kb.iter().fold(Default::default(), |mut m, k| {
            *m.entry(k).or_default() += 1;
            m
        });
    let sa: std::collections::BTreeMap<&String, usize> =
        ka.iter().fold(Default::default(), |mut m, k| {
            *m.entry(k).or_default() += 1;
            m
        });
    let only_a = ka
        .iter()
        .filter(|k| sa.get(*k).copied().unwrap_or(0) > sb.get(*k).copied().unwrap_or(0))
        .cloned()
        .collect();
    let only_b = kb
        .iter()
        .filter(|k| sb.get(*k).copied().unwrap_or(0) > sa.get(*k).copied().unwrap_or(0))
        .cloned()
        .collect();
    (only_a, only_b)
}

// Reading an Arrow result batch into rows is shared with the DataFusion backend; the
// single implementation lives in `intermed_columnar::arrow_rows` (re-exported as
// `record_batch_to_rows`) so the conversion can't drift between backends.

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_columnar::ir::{AggFunc, Aggregate, CmpOp, Predicate, RelExpr, ScalarValue};
    use intermed_facts::FactStore;

    fn facts() -> Vec<Fact> {
        let mut s = FactStore::new();
        for (m, op, tc) in [
            ("owo", "redirect", "RecipeManager"),
            ("polymorph", "redirect", "RecipeManager"),
            ("sodium", "inject", "WorldRenderer"),
            ("create", "overwrite", "RecipeManager"),
        ] {
            s.fact("c", "mixin_application_site")
                .subject(m)
                .attr("mod", m)
                .attr("operation", op)
                .attr("target_class", tc)
                .emit();
        }
        s.all().to_vec()
    }

    #[test]
    fn duckdb_runs_scan_filter_project() {
        let engine = DuckIrEngine::from_facts(&facts()).unwrap();
        let ir = RelExpr::scan("mixin_application_site")
            .filter(Predicate {
                column: "operation".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Str("redirect".into()),
            })
            .project(vec!["mod".into()]);
        let rows = engine.run(&ir).unwrap();
        let mods: std::collections::BTreeSet<String> = rows
            .iter()
            .filter_map(|r| r.get("mod").and_then(Value::as_str).map(str::to_string))
            .collect();
        assert_eq!(
            mods,
            ["owo", "polymorph"].iter().map(|s| s.to_string()).collect()
        );
    }

    #[test]
    fn duckdb_runs_aggregate_with_having() {
        let engine = DuckIrEngine::from_facts(&facts()).unwrap();
        let ir = RelExpr::scan("mixin_application_site")
            .aggregate(
                vec!["target_class".into()],
                vec![Aggregate {
                    func: AggFunc::Count,
                    column: String::new(),
                    alias: "n".into(),
                }],
            )
            .filter(Predicate {
                column: "n".into(),
                op: CmpOp::Ge,
                value: ScalarValue::Int(2),
            });
        let rows = engine.run(&ir).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("target_class").and_then(Value::as_str),
            Some("RecipeManager")
        );
        // COUNT(*) of RecipeManager redirects/overwrite = 3.
        assert_eq!(rows[0].get("n").and_then(Value::as_f64), Some(3.0));
    }

    /// Dual-path: the same plan through the in-process executor and through DuckDB
    /// must produce the same answer. This is the equivalence that lets a rule be
    /// routed to DuckDB safely.
    #[test]
    fn in_process_and_duckdb_agree() {
        use intermed_columnar::{ColumnarStore, execute, facts_to_batches};

        let facts = facts();
        let batches = facts_to_batches(&facts, "run").unwrap();
        let store = ColumnarStore::from_batches(&batches).unwrap();
        let engine = DuckIrEngine::from_facts(&facts).unwrap();

        // (1) filtered scan, projecting fact_id so both engines emit it.
        let scan = RelExpr::scan("mixin_application_site")
            .filter(Predicate {
                column: "operation".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Str("redirect".into()),
            })
            .project(vec!["fact_id".into(), "mod".into()]);
        let inproc = execute(&scan, &store).unwrap();
        let duck = engine.run(&scan).unwrap();
        let (a, b) = result_divergence(&inproc.rows, &duck, &["fact_id", "mod"]);
        assert!(a.is_empty() && b.is_empty(), "scan diverged: {a:?} / {b:?}");

        // (2) group-by aggregate with HAVING.
        let agg = RelExpr::scan("mixin_application_site")
            .aggregate(
                vec!["target_class".into()],
                vec![Aggregate {
                    func: AggFunc::Count,
                    column: String::new(),
                    alias: "n".into(),
                }],
            )
            .filter(Predicate {
                column: "n".into(),
                op: CmpOp::Ge,
                value: ScalarValue::Int(2),
            });
        let inproc = execute(&agg, &store).unwrap();
        let duck = engine.run(&agg).unwrap();
        let (a, b) = result_divergence(&inproc.rows, &duck, &["target_class", "n"]);
        assert!(
            a.is_empty() && b.is_empty(),
            "aggregate diverged: {a:?} / {b:?}"
        );
    }
}
