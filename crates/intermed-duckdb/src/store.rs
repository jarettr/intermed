//! DuckDB persistence (`DuckStore`) — analytics history with idempotent upsert per `run_id`.
//!
//! Re-persisting the same diagnosis run deletes prior rows for that `run_id`, then
//! inserts fresh data. Row writes use `INSERT OR REPLACE` so a partial retry or
//! duplicate `(run_id, fact_id)` tuple in one batch cannot trip PRIMARY KEY errors
//! (common when large `mixin_effect` fact sets are written twice into one DB).

use std::path::Path;

use duckdb::{AccessMode, Config, Connection, params};
use intermed_doctor_core::report::DoctorReport;
use intermed_facts::Fact;
use thiserror::Error;

use crate::schema::{
    FactAttributeRow, FactRow, FindingAffectsRow, FindingEvidenceRow, FindingRow, FindingTagRow,
    MaterializedRun, RunRow, SCHEMA_DDL, delete_run_statements, materialize_facts_only,
    materialize_run,
};

/// Query result for `intermed db query`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Debug, Error)]
pub enum DuckError {
    #[error("duckdb: {0}")]
    Duck(String),
}

impl From<duckdb::Error> for DuckError {
    fn from(value: duckdb::Error) -> Self {
        Self::Duck(value.to_string())
    }
}

/// Columnar fact / finding store backed by embedded DuckDB.
pub struct DuckStore {
    conn: Connection,
}

impl DuckStore {
    /// Open (or create) a file-backed store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DuckError> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an existing store **read-only** at the engine level.
    ///
    /// Used by `intermed db query`: DuckDB rejects every DDL/DML statement
    /// (`DROP`, `DELETE`, `UPDATE`, `INSERT`, `CREATE`) on a read-only
    /// connection, so an ad-hoc "query" can never mutate the analytics history.
    /// `init_schema` is intentionally skipped — creating tables is itself a write
    /// that a read-only connection forbids; the store must already exist.
    pub fn open_readonly(path: impl AsRef<Path>) -> Result<Self, DuckError> {
        let config = Config::default().access_mode(AccessMode::ReadOnly)?;
        let conn = Connection::open_with_flags(path, config)?;
        Ok(Self { conn })
    }

    /// In-memory store (rule evaluation and tests).
    pub fn open_in_memory() -> Result<Self, DuckError> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Idempotent `CREATE TABLE IF NOT EXISTS` for all relations.
    pub fn init_schema(&self) -> Result<(), DuckError> {
        self.conn.execute_batch(SCHEMA_DDL)?;
        Ok(())
    }

    /// Persist a full diagnosis run (idempotent per `run_id`).
    pub fn persist_run(&self, report: &DoctorReport, facts: &[Fact]) -> Result<String, DuckError> {
        let bundle = materialize_run(report, facts);
        let run_id = bundle.run.run_id.clone();
        self.write_run_bundle(&bundle)?;
        Ok(run_id)
    }

    /// Materialize facts only (in-memory rule evaluation).
    pub fn materialize_facts(&self, run_id: &str, facts: &[Fact]) -> Result<(), DuckError> {
        let (fact_rows, attr_rows) = materialize_facts_only(run_id, facts);
        let tx = self.conn.unchecked_transaction()?;
        for stmt in delete_run_statements(run_id) {
            tx.execute(&stmt, [])?;
        }
        upsert_facts(&tx, &fact_rows)?;
        upsert_fact_attributes(&tx, &attr_rows)?;
        tx.commit()?;
        Ok(())
    }

    /// Remove all persisted rows for one `run_id` (child tables first).
    pub fn clear_run(&self, run_id: &str) -> Result<(), DuckError> {
        let tx = self.conn.unchecked_transaction()?;
        for stmt in delete_run_statements(run_id) {
            tx.execute(&stmt, [])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Execute one or more SQL statements (mutating analytics maintenance).
    pub fn execute_batch(&self, sql: &str) -> Result<(), DuckError> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    /// Run a read-only SQL query and return stringified rows.
    pub fn query(&self, sql: &str) -> Result<QueryResult, DuckError> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut iter = stmt.query([])?;
        let columns = iter
            .as_ref()
            .map(|stmt| stmt.column_names())
            .unwrap_or_default();
        let mut rows = Vec::new();
        while let Some(row) = iter.next()? {
            let mut vals = Vec::with_capacity(columns.len());
            for i in 0..columns.len() {
                vals.push(cell_to_string(row, i));
            }
            rows.push(vals);
        }
        Ok(QueryResult { columns, rows })
    }

    fn write_run_bundle(&self, bundle: &MaterializedRun) -> Result<(), DuckError> {
        let tx = self.conn.unchecked_transaction()?;
        for stmt in delete_run_statements(&bundle.run.run_id) {
            tx.execute(&stmt, [])?;
        }
        upsert_run(&tx, &bundle.run)?;
        upsert_facts(&tx, &bundle.facts)?;
        upsert_fact_attributes(&tx, &bundle.fact_attributes)?;
        upsert_findings(&tx, &bundle.findings)?;
        upsert_finding_tags(&tx, &bundle.finding_tags)?;
        upsert_finding_affects(&tx, &bundle.finding_affects)?;
        upsert_finding_evidence(&tx, &bundle.finding_evidence)?;
        tx.commit()?;
        Ok(())
    }
}

fn upsert_run(conn: &Connection, run: &RunRow) -> Result<(), DuckError> {
    conn.execute(
        "INSERT OR REPLACE INTO runs (
            run_id, generated_at, tool_version, target_path, target_kind,
            loader, launcher, host_launcher, mc_version, side, instance_type, layout,
            total, error_count, warn_count, note_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            run.run_id,
            run.generated_at,
            run.tool_version,
            run.target_path,
            run.target_kind,
            run.loader,
            run.launcher,
            run.host_launcher,
            run.mc_version,
            run.side,
            run.instance_type,
            run.layout,
            run.total,
            run.error_count,
            run.warn_count,
            run.note_count,
        ],
    )?;
    Ok(())
}

fn upsert_facts(conn: &Connection, rows: &[FactRow]) -> Result<(), DuckError> {
    for row in rows {
        conn.execute(
            "INSERT OR REPLACE INTO facts (
                run_id, fact_id, kind, subject, confidence, extractor,
                source_locator, source_line, source_inner
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                row.run_id,
                row.fact_id,
                row.kind,
                row.subject,
                row.confidence,
                row.extractor,
                row.source_locator,
                row.source_line,
                row.source_inner,
            ],
        )?;
    }
    Ok(())
}

fn upsert_fact_attributes(conn: &Connection, rows: &[FactAttributeRow]) -> Result<(), DuckError> {
    for row in rows {
        conn.execute(
            "INSERT OR REPLACE INTO fact_attributes (
                run_id, fact_id, key, val_type, val_str, val_int, val_float, val_bool
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                row.run_id,
                row.fact_id,
                row.key,
                row.val_type,
                row.val_str,
                row.val_int,
                row.val_float,
                row.val_bool,
            ],
        )?;
    }
    Ok(())
}

fn upsert_findings(conn: &Connection, rows: &[FindingRow]) -> Result<(), DuckError> {
    for row in rows {
        conn.execute(
            "INSERT OR REPLACE INTO findings (
                run_id, finding_id, rule_id, severity, category, title, explanation, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                row.run_id,
                row.finding_id,
                row.rule_id,
                row.severity,
                row.category,
                row.title,
                row.explanation,
                row.confidence,
            ],
        )?;
    }
    Ok(())
}

fn upsert_finding_tags(conn: &Connection, rows: &[FindingTagRow]) -> Result<(), DuckError> {
    for row in rows {
        conn.execute(
            "INSERT OR REPLACE INTO finding_tags (run_id, finding_id, tag)
             VALUES (?, ?, ?)",
            params![row.run_id, row.finding_id, row.tag],
        )?;
    }
    Ok(())
}

fn upsert_finding_affects(conn: &Connection, rows: &[FindingAffectsRow]) -> Result<(), DuckError> {
    for row in rows {
        conn.execute(
            "INSERT OR REPLACE INTO finding_affects (run_id, finding_id, component)
             VALUES (?, ?, ?)",
            params![row.run_id, row.finding_id, row.component],
        )?;
    }
    Ok(())
}

fn upsert_finding_evidence(
    conn: &Connection,
    rows: &[FindingEvidenceRow],
) -> Result<(), DuckError> {
    for row in rows {
        conn.execute(
            "INSERT OR REPLACE INTO finding_evidence (
                run_id, finding_id, fact_id, relation, weight
            ) VALUES (?, ?, ?, ?, ?)",
            params![
                row.run_id,
                row.finding_id,
                row.fact_id,
                row.relation,
                row.weight,
            ],
        )?;
    }
    Ok(())
}

fn cell_to_string(row: &duckdb::Row<'_>, index: usize) -> String {
    use duckdb::types::ValueRef;
    match row.get_ref(index) {
        Ok(ValueRef::Null) => String::new(),
        Ok(ValueRef::Boolean(v)) => v.to_string(),
        Ok(ValueRef::TinyInt(v)) => v.to_string(),
        Ok(ValueRef::SmallInt(v)) => v.to_string(),
        Ok(ValueRef::Int(v)) => v.to_string(),
        Ok(ValueRef::BigInt(v)) => v.to_string(),
        Ok(ValueRef::HugeInt(v)) => v.to_string(),
        Ok(ValueRef::UTinyInt(v)) => v.to_string(),
        Ok(ValueRef::USmallInt(v)) => v.to_string(),
        Ok(ValueRef::UInt(v)) => v.to_string(),
        Ok(ValueRef::UBigInt(v)) => v.to_string(),
        Ok(ValueRef::Float(v)) => v.to_string(),
        Ok(ValueRef::Double(v)) => v.to_string(),
        Ok(ValueRef::Text(v)) => String::from_utf8_lossy(v).into_owned(),
        Ok(ValueRef::Blob(v)) => format!("<blob {} bytes>", v.len()),
        Ok(other) => format!("{other:?}"),
        Err(_) => String::new(),
    }
}
