//! Apache DataFusion query backend (plan Phase 4.2), behind the `datafusion-backend`
//! feature.
//!
//! DataFusion 54 uses the **same arrow 58** as this crate, so the fact projection is
//! registered into a DataFusion `SessionContext` with no copy or version duplication.
//! A plan is lowered to SQL with the shared [`to_sql`](crate::to_sql) and executed by
//! DataFusion — the same SQL the DuckDB backend runs, now on a pure-Rust engine.
//!
//! DataFusion's API is async; this wraps it in a small current-thread Tokio runtime so
//! the [`QueryBackend`] stays synchronous like the others.

use datafusion::prelude::SessionContext;
use intermed_facts::Fact;

use crate::arrow_rows::record_batch_to_rows;
use crate::backend::QueryBackend;
use crate::convert::facts_to_batches;
use crate::error::ColumnarError;
use crate::ir::RelExpr;
use crate::sql::to_sql;
use crate::value::Relation;

/// Runs IR plans (those lowerable to SQL) on Apache DataFusion.
pub struct DataFusionBackend;

fn err(e: impl std::fmt::Display) -> ColumnarError {
    ColumnarError::Schema(format!("datafusion: {e}"))
}

impl QueryBackend for DataFusionBackend {
    fn name(&self) -> &str {
        "datafusion"
    }

    fn supports(&self, plan: &RelExpr) -> bool {
        to_sql(plan).is_some()
    }

    fn run(&self, plan: &RelExpr, facts: &[Fact]) -> Result<Relation, ColumnarError> {
        let sql = to_sql(plan).ok_or_else(|| err("plan is not lowerable to SQL"))?;
        let batches = facts_to_batches(facts, "datafusion")?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(err)?;
        rt.block_on(async move {
            let ctx = SessionContext::new();
            ctx.register_batch("facts", batches.facts).map_err(err)?;
            ctx.register_batch("fact_attributes", batches.attributes)
                .map_err(err)?;
            let df = ctx.sql(&sql).await.map_err(err)?;
            let result = df.collect().await.map_err(err)?;
            let mut rows = Vec::new();
            for batch in &result {
                rows.extend(record_batch_to_rows(batch));
            }
            Ok(Relation::new(rows))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CmpOp, Predicate, ScalarValue};
    use crate::value::Value;
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
                .attr("mod", m)
                .attr("operation", op)
                .emit();
        }
        s.all().to_vec()
    }

    #[test]
    fn datafusion_runs_scan_filter_project() {
        let plan = RelExpr::scan("mixin_application_site")
            .filter(Predicate {
                column: "operation".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Str("redirect".into()),
            })
            .project(vec!["mod".into()]);
        let rel = DataFusionBackend.run(&plan, &facts()).unwrap();
        let mods: std::collections::BTreeSet<String> = rel
            .rows
            .iter()
            .filter_map(|r| r.get("mod").and_then(Value::as_str).map(str::to_string))
            .collect();
        assert_eq!(
            mods,
            ["owo", "poly"].iter().map(|s| s.to_string()).collect()
        );
    }

    #[test]
    fn datafusion_agrees_with_in_process() {
        use crate::executor::{ColumnarStore, execute};
        let facts = facts();
        let plan = RelExpr::scan("mixin_application_site")
            .filter(Predicate {
                column: "operation".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Str("redirect".into()),
            })
            .project(vec!["fact_id".into()]);
        let df = DataFusionBackend.run(&plan, &facts).unwrap();

        let batches = facts_to_batches(&facts, "x").unwrap();
        let store = ColumnarStore::from_batches(&batches).unwrap();
        let inproc = execute(&plan, &store).unwrap();
        assert_eq!(df.len(), inproc.len());
    }
}
