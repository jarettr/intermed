//! Cardinality + cost estimation for the optimizer (plan Phase 2.2).
//!
//! A minimal **cost-based** layer: the optimizer and physical planner need to compare
//! plan alternatives (which join input to build, whether a rewrite helps), and even a
//! coarse heuristic model — driven by per-kind fact counts — captures the decisions
//! that matter (filter before join, build the smaller side). The model estimates an
//! operator's output [`Cost`] (cardinality + CPU + peak memory) bottom-up.

use std::collections::{BTreeSet, HashMap};

use crate::ir::{AggFunc, CmpOp, RelExpr};

/// Catalog statistics the optimizer reasons over: per-kind row counts and the column
/// set of each kind (base columns + the attributes seen on that kind). Built from the
/// live [`ColumnarStore`](crate::executor::ColumnarStore); an [`empty`] instance makes
/// the optimizer a conservative no-op (no pushdown across joins, heuristic build side).
///
/// [`empty`]: Statistics::empty
#[derive(Debug, Clone, Default)]
pub struct Statistics {
    kind_rows: HashMap<String, f64>,
    kind_cols: HashMap<String, BTreeSet<String>>,
}

impl Statistics {
    pub fn new(
        kind_rows: HashMap<String, f64>,
        kind_cols: HashMap<String, BTreeSet<String>>,
    ) -> Self {
        Statistics {
            kind_rows,
            kind_cols,
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    /// Estimated number of facts of `kind` (0 if unknown).
    pub fn rows_of(&self, kind: &str) -> f64 {
        self.kind_rows.get(kind).copied().unwrap_or(0.0)
    }

    /// The known columns of `kind` (the full row schema), or `None` if the kind is not
    /// in the catalog — in which case the optimizer must not assume a column's origin.
    pub fn columns_of(&self, kind: &str) -> Option<&BTreeSet<String>> {
        self.kind_cols.get(kind)
    }
}

/// The estimated cost of producing an operator's output.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cost {
    /// Work performed (rows touched across the subtree) — the field plans are ranked on.
    pub cpu: f64,
    /// Peak working-set rows held in memory (largest hash table / materialization).
    pub memory: f64,
    /// Estimated output cardinality (rows produced).
    pub rows: f64,
}

/// Selectivity (surviving fraction) of a comparison — a coarse default since the
/// catalog has no per-column histograms yet. Equality is the most selective.
fn selectivity(op: CmpOp) -> f64 {
    match op {
        CmpOp::Eq => 0.1,
        CmpOp::Ne => 0.9,
        CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge => 0.33,
    }
}

/// A cost model maps a logical plan to an estimated [`Cost`] under given statistics.
pub trait CostModel {
    fn cost(&self, plan: &RelExpr, stats: &Statistics) -> Cost;
}

/// The default heuristic cost model: cardinalities flow from `Scan` counts through
/// selectivity factors, joins are estimated by the textbook
/// `|l|·|r| / max(|l|,|r|)` (≈ the smaller side for a key join), and CPU accumulates
/// the rows each operator touches (hash join/aggregate are linear, not quadratic).
pub struct HeuristicCostModel;

impl CostModel for HeuristicCostModel {
    fn cost(&self, plan: &RelExpr, stats: &Statistics) -> Cost {
        match plan {
            RelExpr::Scan { kind } => {
                let r = stats.rows_of(kind).max(1.0);
                Cost {
                    cpu: r,
                    memory: 0.0,
                    rows: r,
                }
            }
            RelExpr::Filter { input, predicate } => {
                let c = self.cost(input, stats);
                Cost {
                    cpu: c.cpu + c.rows,
                    memory: c.memory,
                    rows: (c.rows * selectivity(predicate.op)).max(1.0),
                }
            }
            RelExpr::Project { input, .. } => {
                let c = self.cost(input, stats);
                Cost {
                    cpu: c.cpu + c.rows,
                    ..c
                }
            }
            RelExpr::Join { left, right, on } => {
                let l = self.cost(left, stats);
                let r = self.cost(right, stats);
                let out = if on.is_empty() {
                    l.rows * r.rows
                } else {
                    (l.rows * r.rows) / l.rows.max(r.rows).max(1.0)
                };
                Cost {
                    // build + probe (linear) + emit.
                    cpu: l.cpu + r.cpu + l.rows + r.rows + out,
                    memory: l.memory.max(r.memory).max(l.rows.min(r.rows)),
                    rows: out.max(1.0),
                }
            }
            RelExpr::Aggregate {
                input, group_by, ..
            } => {
                let c = self.cost(input, stats);
                let groups = if group_by.is_empty() {
                    1.0
                } else {
                    (c.rows * 0.5).max(1.0)
                };
                Cost {
                    cpu: c.cpu + c.rows,
                    memory: c.memory.max(c.rows),
                    rows: groups,
                }
            }
            RelExpr::Window { input, .. } => {
                let c = self.cost(input, stats);
                Cost {
                    // Partition + sort, then one pass; row count is unchanged.
                    cpu: c.cpu + c.rows + c.rows.max(1.0) * c.rows.max(1.0).log2().max(1.0),
                    memory: c.memory.max(c.rows),
                    rows: c.rows,
                }
            }
            RelExpr::TransitiveClosure { input, .. } => {
                let c = self.cost(input, stats);
                Cost {
                    // Fixpoint is super-linear; charge ~rows² as a deterrent.
                    cpu: c.cpu + c.rows * c.rows,
                    memory: c.memory.max(c.rows),
                    rows: c.rows,
                }
            }
            RelExpr::CallExternal { input, .. } => self.cost(input, stats),
            RelExpr::JoinFilter {
                left_kind,
                right_kind,
                ..
            } => {
                let l = stats.rows_of(left_kind).max(1.0);
                let r = stats.rows_of(right_kind).max(1.0);
                Cost {
                    cpu: l * r,
                    memory: l.min(r),
                    rows: l.max(r),
                }
            }
            RelExpr::GroupCountDistinct { kinds, .. } => {
                let total: f64 = kinds.iter().map(|k| stats.rows_of(k)).sum::<f64>().max(1.0);
                Cost {
                    cpu: total,
                    memory: total,
                    rows: total,
                }
            }
        }
    }
}

/// Estimated output cardinality of a plan under the heuristic model — the common
/// query the optimizer asks (e.g. which join side is smaller).
pub fn cardinality(plan: &RelExpr, stats: &Statistics) -> f64 {
    HeuristicCostModel.cost(plan, stats).rows
}

/// Whether an aggregate function reads its argument column (so projection pushdown
/// must keep it). `Count` ignores its column.
pub(crate) fn agg_reads_column(func: AggFunc) -> bool {
    !matches!(func, AggFunc::Count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CmpOp, Predicate, ScalarValue};

    fn stats() -> Statistics {
        let mut rows = HashMap::new();
        rows.insert("big".to_string(), 100_000.0);
        rows.insert("small".to_string(), 100.0);
        Statistics::new(rows, HashMap::new())
    }

    #[test]
    fn filter_reduces_estimated_cardinality() {
        let s = stats();
        let scan = RelExpr::scan("big");
        let filtered = RelExpr::scan("big").filter(Predicate {
            column: "x".into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str("v".into()),
        });
        assert!(cardinality(&filtered, &s) < cardinality(&scan, &s));
    }

    #[test]
    fn key_join_estimated_as_smaller_side() {
        let s = stats();
        let join =
            RelExpr::scan("big").join(RelExpr::scan("small"), vec![("k".into(), "k".into())]);
        // |big|·|small| / max = |small| order of magnitude, not the product.
        let rows = cardinality(&join, &s);
        assert!(
            rows <= 100.0 + 1.0,
            "join estimate {rows} should track the smaller side"
        );
    }
}
