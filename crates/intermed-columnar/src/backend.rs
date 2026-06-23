//! Pluggable query backends (plan Phase 4.2).
//!
//! The router ([`router`](crate::router)) splits a plan into single-engine stages; a
//! [`QueryBackend`] is what actually *runs* a stage. Formalizing the seam lets new
//! engines slot in without touching the planner: a backend declares which plans it
//! [`supports`](QueryBackend::supports) and how to [`run`](QueryBackend::run) one over a
//! set of facts.
//!
//! Implemented here: [`InProcessBackend`] (the optimizing columnar engine — pure Rust,
//! always available). Implemented elsewhere against this same contract:
//!
//! - **DuckDB** — `intermed-duckdb`'s `DuckIrEngine` (`to_sql` + Arrow appender);
//!   feature-gated.
//! - **Soufflé** — `to_datalog` + the external `souffle` binary (`intermed-rules`).
//!
//! Future engines (Rust Datalog `ascent`, `DataFusion`, `Polars`) plug in by
//! implementing [`QueryBackend`] in their own crate/feature — they are *additive* and
//! carry their own (heavy) dependencies, so they are not linked into the default build.

use intermed_facts::Fact;

use crate::convert::facts_to_batches;
use crate::error::ColumnarError;
use crate::executor::{ColumnarStore, execute};
use crate::ir::RelExpr;
use crate::value::Relation;

/// A backend that can execute (some) relational plans over a fact set.
pub trait QueryBackend {
    /// A stable identifier (matches the router's engine label where applicable).
    fn name(&self) -> &str;

    /// Whether this backend can execute `plan`.
    fn supports(&self, plan: &RelExpr) -> bool;

    /// Execute `plan` over `facts`, returning the result relation.
    fn run(&self, plan: &RelExpr, facts: &[Fact]) -> Result<Relation, ColumnarError>;
}

/// The in-process columnar engine as a [`QueryBackend`]. Supports every construct the
/// executor runs (i.e. everything except the SQL-only `JoinFilter`/`GroupCountDistinct`
/// shapes, which belong to the DuckDB backend).
pub struct InProcessBackend;

impl QueryBackend for InProcessBackend {
    fn name(&self) -> &str {
        "in-process"
    }

    fn supports(&self, _plan: &RelExpr) -> bool {
        // The in-process engine is relationally complete — it runs every `RelExpr`
        // node (including JoinFilter / GroupCountDistinct), so it supports any plan.
        true
    }

    fn run(&self, plan: &RelExpr, facts: &[Fact]) -> Result<Relation, ColumnarError> {
        let batches = facts_to_batches(facts, "backend")?;
        let store = ColumnarStore::from_batches(&batches)?;
        execute(plan, &store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CmpOp, Predicate, ScalarValue};
    use intermed_facts::FactStore;

    #[test]
    fn in_process_backend_supports_every_plan() {
        let b = InProcessBackend;
        let scan_filter = RelExpr::scan("k").filter(Predicate {
            column: "a".into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str("v".into()),
        });
        assert!(b.supports(&scan_filter));
        // Previously SQL-only shapes now run in-process too.
        let group_distinct = RelExpr::GroupCountDistinct {
            kinds: vec!["mod".into()],
            group_col: "subject".into(),
            distinct_attr: "file".into(),
            min_count: 2,
        };
        assert!(b.supports(&group_distinct));
    }

    #[test]
    fn in_process_backend_runs_over_facts() {
        let mut s = FactStore::new();
        s.fact("c", "mod")
            .subject("a")
            .attr("loader", "fabric")
            .emit();
        s.fact("c", "mod")
            .subject("b")
            .attr("loader", "forge")
            .emit();
        let plan = RelExpr::scan("mod").filter(Predicate {
            column: "loader".into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str("fabric".into()),
        });
        let rel = InProcessBackend.run(&plan, s.all()).unwrap();
        assert_eq!(rel.len(), 1);
    }
}
