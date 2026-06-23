//! Incremental maintenance over fact deltas (plan Phase 4.3).
//!
//! Re-running a query over the whole [`ColumnarStore`](crate::executor::ColumnarStore)
//! after every fact change is wasteful. For the **row-local** (monotonic) fragment of
//! the IR — `Scan` / `Filter` / `Project` — each output row depends on exactly one
//! input fact, so for a query `q`:
//!
//! ```text
//! q(base ∪ delta)  ≡  q(base) ∪ q(delta)
//! ```
//!
//! i.e. the *new* result rows of appending `delta` facts are exactly `q(delta)` — no
//! need to touch the base. [`execute_incremental`] runs a maintainable plan against a
//! store built from just the delta facts; the caller unions the rows with the prior
//! result.
//!
//! Joins are monotonic too but need both sides (Δl⋈r ∪ l⋈Δr ∪ Δl⋈Δr), and
//! aggregation / transitive closure are not row-additive, so they are reported as not
//! incrementally maintainable here (the caller falls back to a full re-run). This is
//! the "at least Filter and Project" slice the plan calls for, kept sound.

use crate::error::ColumnarError;
use crate::executor::{ColumnarStore, execute};
use crate::ir::RelExpr;
use crate::value::Relation;

/// Whether a plan can be incrementally maintained by re-running it on a delta store
/// (true iff it is composed only of the row-local operators `Scan`/`Filter`/`Project`).
pub fn is_incrementally_maintainable(plan: &RelExpr) -> bool {
    match plan {
        RelExpr::Scan { .. } => true,
        RelExpr::Filter { input, .. } | RelExpr::Project { input, .. } => {
            is_incrementally_maintainable(input)
        }
        // Joins need both sides; aggregation / window / closure / external calls are
        // not row-additive over a delta alone.
        RelExpr::Join { .. }
        | RelExpr::Aggregate { .. }
        | RelExpr::Window { .. }
        | RelExpr::TransitiveClosure { .. }
        | RelExpr::CallExternal { .. }
        | RelExpr::JoinFilter { .. }
        | RelExpr::GroupCountDistinct { .. } => false,
    }
}

/// Compute the incremental result of appending the facts in `delta` (a store built from
/// only the new facts): the rows to *add* to the previous result.
///
/// Errors with [`ColumnarError::Schema`] if the plan is not row-local — callers should
/// check [`is_incrementally_maintainable`] first (or treat the error as "re-run fully").
pub fn execute_incremental(
    plan: &RelExpr,
    delta: &ColumnarStore,
) -> Result<Relation, ColumnarError> {
    if !is_incrementally_maintainable(plan) {
        return Err(ColumnarError::Schema(
            "plan is not incrementally maintainable (contains a join/aggregate/closure/external call)"
                .into(),
        ));
    }
    execute(plan, delta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::facts_to_batches;
    use crate::ir::{CmpOp, Predicate, ScalarValue};
    use crate::value::Value;
    use intermed_facts::{Fact, FactStore};
    use std::collections::BTreeSet;

    fn store_of(facts: &[Fact]) -> ColumnarStore {
        let batches = facts_to_batches(facts, "r").unwrap();
        ColumnarStore::from_batches(&batches).unwrap()
    }

    fn redirect_plan() -> RelExpr {
        RelExpr::scan("mixin_application_site")
            .filter(Predicate {
                column: "operation".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Str("redirect".into()),
            })
            .project(vec!["fact_id".into(), "subject".into()])
    }

    fn ids(rel: &Relation) -> BTreeSet<i64> {
        rel.rows
            .iter()
            .filter_map(|r| match r.get("fact_id") {
                Some(Value::Int(n)) => Some(*n),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn delta_result_unions_to_full_result() {
        // Base facts.
        let mut base = FactStore::new();
        for (i, op) in ["redirect", "inject", "redirect"].iter().enumerate() {
            base.fact("c", "mixin_application_site")
                .subject(format!("b{i}"))
                .attr("operation", *op)
                .emit();
        }
        // Delta facts (appended later).
        let mut delta = FactStore::new();
        for (i, op) in ["redirect", "overwrite"].iter().enumerate() {
            delta
                .fact("c", "mixin_application_site")
                .subject(format!("d{i}"))
                .attr("operation", *op)
                .emit();
        }
        let combined: Vec<Fact> = base.all().iter().chain(delta.all()).cloned().collect();

        let plan = redirect_plan();
        assert!(is_incrementally_maintainable(&plan));

        let base_res = execute(&plan, &store_of(base.all())).unwrap();
        let delta_res = execute_incremental(&plan, &store_of(delta.all())).unwrap();
        let full_res = execute(&plan, &store_of(&combined)).unwrap();

        // q(base) ∪ q(delta) == q(base ∪ delta).
        let mut union = ids(&base_res);
        union.extend(ids(&delta_res));
        assert_eq!(union, ids(&full_res));
        // The delta contributed exactly the one new redirect.
        assert_eq!(delta_res.len(), 1);
    }

    #[test]
    fn aggregate_plan_is_not_maintainable() {
        let plan =
            RelExpr::scan("mixin_application_site").aggregate(vec!["operation".into()], vec![]);
        assert!(!is_incrementally_maintainable(&plan));
        let delta = FactStore::new();
        assert!(execute_incremental(&plan, &store_of(delta.all())).is_err());
    }
}
