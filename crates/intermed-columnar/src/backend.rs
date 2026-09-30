//! Pluggable query backends.
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
//! Feature-gated implementations in this crate provide DataFusion, Polars, and
//! Ascent-backed execution. They are additive and carry their own heavier dependencies,
//! so they are not linked into the default build.

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

    /// Experimental backends are parity/research surfaces, not selectable
    /// production defaults. Production status requires the semantic conformance
    /// gate, not merely a working adapter.
    fn is_experimental(&self) -> bool {
        true
    }

    /// Whether this backend can execute `plan`.
    fn supports(&self, plan: &RelExpr) -> bool;

    /// Execute `plan` over `facts`, returning the result relation.
    fn run(&self, plan: &RelExpr, facts: &[Fact]) -> Result<Relation, ColumnarError>;
}

/// The in-process columnar engine as a [`QueryBackend`]. It executes every relational
/// node, including `JoinFilter` and `GroupCountDistinct`. `CallExternal` requires an
/// explicitly provisioned function registry and is therefore not advertised by this
/// zero-configuration backend.
pub struct InProcessBackend;

impl QueryBackend for InProcessBackend {
    fn name(&self) -> &str {
        "in-process"
    }

    fn is_experimental(&self) -> bool {
        false
    }

    fn supports(&self, plan: &RelExpr) -> bool {
        !contains_external_call(plan)
    }

    fn run(&self, plan: &RelExpr, facts: &[Fact]) -> Result<Relation, ColumnarError> {
        let batches = facts_to_batches(facts, "backend")?;
        let store = ColumnarStore::from_batches(&batches)?;
        execute(plan, &store)
    }
}

fn contains_external_call(plan: &RelExpr) -> bool {
    match plan {
        RelExpr::CallExternal { .. } => true,
        RelExpr::Filter { input, .. }
        | RelExpr::Project { input, .. }
        | RelExpr::Aggregate { input, .. }
        | RelExpr::Window { input, .. }
        | RelExpr::TransitiveClosure { input, .. } => contains_external_call(input),
        RelExpr::Join { left, right, .. } => {
            contains_external_call(left) || contains_external_call(right)
        }
        RelExpr::Scan { .. } | RelExpr::JoinFilter { .. } | RelExpr::GroupCountDistinct { .. } => {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CmpOp, Predicate, ScalarValue};
    use intermed_facts::FactStore;

    #[test]
    fn in_process_backend_supports_the_relational_surface_only() {
        let b = InProcessBackend;
        assert!(!b.is_experimental());
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
            filters: vec![],
            min_count: 2,
        };
        assert!(b.supports(&group_distinct));
        assert!(!b.supports(&RelExpr::scan("mod").call_external("missing")));
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
