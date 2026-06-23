//! Execution-strategy selection for the unified physical engine (plan Phases 1 & 3).
//!
//! The crate keeps **one** [`RelExpr`](crate::ir::RelExpr) and **one**
//! [`PhysicalPlan`](crate::physical::PhysicalPlan). What this module adds is a choice
//! of *how* a (sub)plan runs:
//!
//! - [`ExecutionStrategy::Vectorized`] — the full Arrow/columnar streaming engine
//!   (hash join / aggregate / window / transitive closure / external calls). It is
//!   relationally complete and is the correctness reference.
//! - [`ExecutionStrategy::FastRow`] — a specialized, low-overhead row path
//!   ([`crate::fast_row`]) for the overwhelmingly common linear `Scan → Filter* →
//!   Project` shape (the typical `FactFinding` rule). It reads the [`ColumnarStore`]
//!   batch directly by positional index, pre-resolves filter/projection columns once,
//!   and builds only the output rows — no per-stage boxed iterator, no intermediate
//!   `Tuple` clone.
//!
//! The planner ([`select_strategy`]) chooses per top-level plan; an explicit strategy
//! can be forced (debugging / experiments) via [`ExecutionStrategy::resolve`]. The
//! decision is a *selection pass* over the existing `PhysicalPlan`, deliberately **not**
//! a field threaded through all eleven operator variants: the logical/physical split
//! stays clean and every existing match site is untouched. Both strategies are proven
//! to produce identical results (the FastRow path reuses the executor's `eval_cmp` /
//! `scalar_to_value`, so its stringly comparison semantics match exactly).
//!
//! [`ColumnarStore`]: crate::executor::ColumnarStore

use crate::physical::PhysicalPlan;

/// How a physical (sub)plan is executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStrategy {
    /// The full streaming columnar engine — relationally complete, the reference path.
    Vectorized,
    /// The specialized linear `Scan → Filter* → Project` fast path.
    FastRow,
    /// Let the planner decide (resolves to FastRow when eligible, else Vectorized).
    Auto,
}

impl ExecutionStrategy {
    /// Stable lower-case label for `EXPLAIN` / diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionStrategy::Vectorized => "vectorized",
            ExecutionStrategy::FastRow => "fast-row",
            ExecutionStrategy::Auto => "auto",
        }
    }

    /// Resolve this strategy against a concrete plan. `Auto` defers to
    /// [`select_strategy`]; an explicit `FastRow` is honored only when the plan is
    /// actually eligible (otherwise it safely degrades to `Vectorized`, which can run
    /// anything). `Vectorized` always passes through.
    pub fn resolve(self, plan: &PhysicalPlan) -> ExecutionStrategy {
        match self {
            ExecutionStrategy::Auto => select_strategy(plan),
            ExecutionStrategy::FastRow if is_fast_row_eligible(plan) => ExecutionStrategy::FastRow,
            ExecutionStrategy::FastRow | ExecutionStrategy::Vectorized => {
                ExecutionStrategy::Vectorized
            }
        }
    }
}

/// The planner's heuristic: a linear `Scan → Filter* → Project` pipeline runs on
/// FastRow; anything richer (join / aggregate / window / transitive closure / external
/// call / declarative join-filter / group-count-distinct) needs the Vectorized engine.
pub fn select_strategy(plan: &PhysicalPlan) -> ExecutionStrategy {
    if is_fast_row_eligible(plan) {
        ExecutionStrategy::FastRow
    } else {
        ExecutionStrategy::Vectorized
    }
}

/// Whether `plan` is the FastRow shape `Project?(Filter|Project)*(Scan)`.
///
/// The output schema is fixed by the outermost projection (or, with none, the full
/// row). Intermediate `Project` nodes are only the optimizer's column-*pruning*
/// pushdown — FastRow reads the full batch, so they are transparent and safe to skip,
/// **but only when an outer projection bounds the output**. Without an outer
/// projection the chain must therefore be filters-only (`Filter*(Scan)`), so emitting
/// every column stays correct; a bare scan and a pure filter chain both qualify.
pub fn is_fast_row_eligible(plan: &PhysicalPlan) -> bool {
    match plan {
        PhysicalPlan::Project { input, .. } => chain_over_scan(input, true),
        other => chain_over_scan(other, false),
    }
}

/// A chain of `Filter` (always) and `Project` (only when `allow_project`) nodes
/// terminating in a single `Scan`.
fn chain_over_scan(p: &PhysicalPlan, allow_project: bool) -> bool {
    match p {
        PhysicalPlan::Scan { .. } => true,
        PhysicalPlan::Filter { input, .. } => chain_over_scan(input, allow_project),
        PhysicalPlan::Project { input, .. } if allow_project => {
            chain_over_scan(input, allow_project)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CmpOp, Predicate, ScalarValue};
    use crate::physical::PhysicalPlan;

    fn scan() -> PhysicalPlan {
        PhysicalPlan::Scan { kind: "mod".into() }
    }
    fn filter(inner: PhysicalPlan) -> PhysicalPlan {
        PhysicalPlan::Filter {
            input: Box::new(inner),
            predicate: Predicate {
                column: "loader".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Str("fabric".into()),
            },
        }
    }
    fn project(inner: PhysicalPlan) -> PhysicalPlan {
        PhysicalPlan::Project {
            input: Box::new(inner),
            columns: vec!["subject".into()],
        }
    }

    #[test]
    fn linear_shapes_are_fast_row() {
        assert!(is_fast_row_eligible(&scan()));
        assert!(is_fast_row_eligible(&filter(scan())));
        assert!(is_fast_row_eligible(&project(filter(scan()))));
        assert!(is_fast_row_eligible(&project(filter(filter(scan())))));
        assert_eq!(
            select_strategy(&project(filter(scan()))),
            ExecutionStrategy::FastRow
        );
    }

    #[test]
    fn projection_below_filter_is_not_eligible() {
        // Project nested under a Filter is not the FastRow shape.
        let plan = filter(project(scan()));
        assert!(!is_fast_row_eligible(&plan));
        assert_eq!(select_strategy(&plan), ExecutionStrategy::Vectorized);
    }

    #[test]
    fn join_is_vectorized() {
        let plan = PhysicalPlan::HashJoin {
            left: Box::new(scan()),
            right: Box::new(scan()),
            on: vec![("k".into(), "k".into())],
            build_side: crate::physical::BuildSide::Right,
        };
        assert!(!is_fast_row_eligible(&plan));
        assert_eq!(select_strategy(&plan), ExecutionStrategy::Vectorized);
    }

    #[test]
    fn forced_fast_row_degrades_when_ineligible() {
        let join = PhysicalPlan::NestedLoopJoin {
            left: Box::new(scan()),
            right: Box::new(scan()),
        };
        assert_eq!(
            ExecutionStrategy::FastRow.resolve(&join),
            ExecutionStrategy::Vectorized
        );
        assert_eq!(
            ExecutionStrategy::FastRow.resolve(&scan()),
            ExecutionStrategy::FastRow
        );
        assert_eq!(
            ExecutionStrategy::Auto.resolve(&scan()),
            ExecutionStrategy::FastRow
        );
    }
}
