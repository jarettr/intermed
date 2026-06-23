//! The **FastRow** execution strategy (plan Phase 2).
//!
//! A specialized, low-overhead path for the linear `Scan → Filter* → Project` pipeline
//! that dominates real rule packs (a `FactFinding` rule is almost always "scan a kind,
//! keep rows matching a conjunction of equalities, project `fact_id`"). The Vectorized
//! engine runs this shape too, but pays for generality: a boxed `dyn Iterator` per
//! stage, a cloned [`Tuple`](crate::executor) for every scanned row, and another for
//! every projected row.
//!
//! FastRow instead:
//! - flattens the plan to `(kind, filters, projection)` once,
//! - reads the [`ColumnarStore`](crate::executor::ColumnarStore) batch directly,
//! - pre-resolves every filter and projection **column position** against the batch
//!   schema a single time (not per row),
//! - streams the batch rows by reference, evaluating the conjunctive filter in place
//!   (short-circuiting), and materializes **only** the projected columns of surviving
//!   rows straight into the public [`Relation`].
//!
//! Correctness is by construction: it reuses the executor's
//! [`eval_cmp`](crate::executor::eval_cmp) and
//! [`scalar_to_value`](crate::executor::scalar_to_value), so its filter semantics —
//! including the stringly `Eq`/`Ne` comparison the legacy interpreter uses — are
//! identical to the Vectorized path, and it emits the same columns in the same row
//! order. The shadow/regression tests assert this on real packs.

use crate::executor::{ColumnarStore, eval_cmp, scalar_to_value};
use crate::ir::{CmpOp, Predicate};
use crate::physical::PhysicalPlan;
use crate::value::{Relation, Row, Value};

/// A flattened linear pipeline: one source `kind`, a conjunction of `filters`, and an
/// optional `project` column list. Extracted from a `Project?(Filter*(Scan))` plan.
struct LinearPipeline<'a> {
    kind: &'a str,
    /// Filters in plan order (top filter first); evaluated as a conjunction.
    filters: Vec<&'a Predicate>,
    /// Output columns, or `None` to emit the full row (all base + attribute columns).
    project: Option<&'a [String]>,
}

/// Flatten a FastRow-eligible physical plan, or `None` if it is not the linear shape.
///
/// Mirrors [`is_fast_row_eligible`](crate::strategy::is_fast_row_eligible): the
/// outermost `Project` (if any) fixes the output columns; below it, intermediate
/// `Project` nodes are the optimizer's column-pruning pushdown and are skipped
/// (FastRow reads the full batch, so pruning is a no-op for correctness). Intermediate
/// projects are only accepted when an outer projection bounds the output.
fn flatten(plan: &PhysicalPlan) -> Option<LinearPipeline<'_>> {
    let (project, mut node, allow_inner_project) = match plan {
        PhysicalPlan::Project { input, columns } => {
            (Some(columns.as_slice()), input.as_ref(), true)
        }
        other => (None, other, false),
    };
    let mut filters = Vec::new();
    loop {
        match node {
            PhysicalPlan::Filter { input, predicate } => {
                filters.push(predicate);
                node = input.as_ref();
            }
            PhysicalPlan::Project { input, .. } if allow_inner_project => {
                node = input.as_ref();
            }
            PhysicalPlan::Scan { kind } => {
                return Some(LinearPipeline {
                    kind,
                    filters,
                    project,
                });
            }
            _ => return None,
        }
    }
}

/// Execute a FastRow-eligible plan directly over the store. Returns `None` when the
/// plan is not a linear pipeline, so the caller falls back to the Vectorized engine.
pub(crate) fn execute_fast_row(plan: &PhysicalPlan, store: &ColumnarStore) -> Option<Relation> {
    let pipe = flatten(plan)?;
    let Some(batch) = store.batch(pipe.kind) else {
        // No facts of this kind ⇒ empty result (same as a Vectorized scan miss).
        return Some(Relation::new(Vec::new()));
    };

    // Pre-resolve filter column positions and right-hand literals once.
    let filters: Vec<(Option<usize>, CmpOp, Value)> = pipe
        .filters
        .iter()
        .map(|p| (batch.pos(&p.column), p.op, scalar_to_value(&p.value)))
        .collect();

    // Pre-resolve the output columns (name, position). No projection ⇒ all columns.
    let out_cols: Vec<(String, Option<usize>)> = match pipe.project {
        Some(cols) => cols.iter().map(|c| (c.clone(), batch.pos(c))).collect(),
        None => batch
            .names()
            .iter()
            .map(|n| (n.clone(), batch.pos(n)))
            .collect(),
    };

    let mut rows: Vec<Row> = Vec::new();
    for tuple in batch.rows() {
        let pass = filters.iter().all(|(pos, op, rhs)| {
            let lhs = pos.and_then(|i| tuple.get(i)).unwrap_or(&Value::Null);
            eval_cmp(lhs, *op, rhs)
        });
        if !pass {
            continue;
        }
        let mut row = Row::new();
        for (name, pos) in &out_cols {
            let v = pos
                .and_then(|i| tuple.get(i).cloned())
                .unwrap_or(Value::Null);
            row.insert(name.clone(), v);
        }
        rows.push(row);
    }
    Some(Relation::new(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{ColumnarStore, execute};
    use crate::ir::RelExpr;
    use crate::physical::PhysicalPlan;
    use crate::{facts_to_batches, optimize};
    use intermed_facts::FactStore;

    fn store() -> ColumnarStore {
        let mut s = FactStore::new();
        for (m, loader, side) in [
            ("sodium", "fabric", "client"),
            ("create", "forge", "both"),
            ("iris", "fabric", "client"),
            ("rei", "fabric", "both"),
        ] {
            s.fact("meta", "mod")
                .subject(m)
                .attr("loader", loader)
                .attr("side", side)
                .emit();
        }
        let batches = facts_to_batches(s.all(), "t").unwrap();
        ColumnarStore::from_batches(&batches).unwrap()
    }

    /// FastRow must produce exactly what the Vectorized engine does, for the same plan.
    fn assert_parity(expr: &RelExpr) {
        let st = store();
        let stats = st.statistics();
        let phys = crate::physical::plan(&optimize(expr, &stats), &stats);
        let fast = execute_fast_row(&phys, &st).expect("eligible");
        let vectorized = execute(expr, &st).unwrap();
        assert_eq!(
            fast.rows, vectorized.rows,
            "FastRow != Vectorized for {expr:?}"
        );
    }

    #[test]
    fn scan_filter_project_parity() {
        assert_parity(
            &RelExpr::scan("mod")
                .filter(crate::ir::Predicate {
                    column: "loader".into(),
                    op: CmpOp::Eq,
                    value: crate::ir::ScalarValue::Str("fabric".into()),
                })
                .project(vec!["subject".into()]),
        );
    }

    #[test]
    fn multi_filter_parity() {
        assert_parity(
            &RelExpr::scan("mod")
                .filter(crate::ir::Predicate {
                    column: "loader".into(),
                    op: CmpOp::Eq,
                    value: crate::ir::ScalarValue::Str("fabric".into()),
                })
                .filter(crate::ir::Predicate {
                    column: "side".into(),
                    op: CmpOp::Eq,
                    value: crate::ir::ScalarValue::Str("both".into()),
                })
                .project(vec!["subject".into(), "loader".into()]),
        );
    }

    #[test]
    fn bare_scan_parity() {
        assert_parity(&RelExpr::scan("mod"));
    }

    #[test]
    fn missing_kind_is_empty() {
        let st = store();
        let phys = PhysicalPlan::Scan {
            kind: "nonexistent".into(),
        };
        let rel = execute_fast_row(&phys, &st).expect("eligible");
        assert!(rel.is_empty());
    }

    #[test]
    fn non_linear_plan_returns_none() {
        let st = store();
        let join = PhysicalPlan::NestedLoopJoin {
            left: Box::new(PhysicalPlan::Scan { kind: "mod".into() }),
            right: Box::new(PhysicalPlan::Scan { kind: "mod".into() }),
        };
        assert!(execute_fast_row(&join, &st).is_none());
    }
}
