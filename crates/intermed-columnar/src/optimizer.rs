//! Rule-based logical optimizer (plan Phase 2.1).
//!
//! [`optimize`] rewrites a logical [`RelExpr`] into an equivalent but cheaper plan
//! before it is lowered to physical operators. It is *logical* — it never commits to
//! an operator (that is the physical planner's job, which then uses the [`cost`] model
//! to pick a hash-join build side). The rewrites are equivalence-preserving for the
//! inner-join / inner-filter semantics the engine uses:
//!
//! - **Predicate pushdown** — a `Filter` is pushed below a `Join` to the input that
//!   provides its column (so the join processes fewer rows), and below a `Project`
//!   when the column survives the projection. Soundness for an inner equi-join: a row
//!   removed by a non-key filter could only have produced output rows that the
//!   post-join filter would have removed anyway; key columns are pushed to the side
//!   that owns the (possibly `right.`-prefixed) name.
//! - **Projection pushdown** — a `Project`/`Aggregate`/`TransitiveClosure` tells its
//!   input which columns it actually needs, so a `Scan` is pruned to those columns
//!   (narrower tuples flow through the pipeline). Pruning never crosses a join (the
//!   merge's collision-prefixing makes it unsound to drop a join input's columns), so
//!   join inputs keep their full width.
//!
//! Column origin and join-side decisions use the catalog [`Statistics`]; with empty
//! statistics the rewrites that need provenance are skipped (a safe no-op), so the
//! optimizer never changes results, only — at most — does less.

use std::collections::BTreeSet;

use crate::cost::{Statistics, agg_reads_column, cardinality};
use crate::ir::{Predicate, RelExpr};

/// Optimize a logical plan under the given catalog statistics.
///
/// Passes, in order: predicate pushdown (shrink relations before joins), join
/// reordering (cheapest multi-way join order), projection pushdown (narrow scans).
pub fn optimize(expr: &RelExpr, stats: &Statistics) -> RelExpr {
    let pushed = push_filters(expr.clone(), stats);
    let reordered = reorder_joins(pushed, stats);
    prune_columns(reordered, None, stats)
}

// ---------------------------------------------------------------------------
// Predicate pushdown
// ---------------------------------------------------------------------------

/// Recursively push every `Filter` toward the leaves.
fn push_filters(expr: RelExpr, stats: &Statistics) -> RelExpr {
    match expr {
        RelExpr::Filter { input, predicate } => {
            let input = push_filters(*input, stats);
            push_one(input, predicate, stats)
        }
        RelExpr::Project { input, columns } => RelExpr::Project {
            input: Box::new(push_filters(*input, stats)),
            columns,
        },
        RelExpr::Join { left, right, on } => RelExpr::Join {
            left: Box::new(push_filters(*left, stats)),
            right: Box::new(push_filters(*right, stats)),
            on,
        },
        RelExpr::Aggregate {
            input,
            group_by,
            aggregates,
        } => RelExpr::Aggregate {
            input: Box::new(push_filters(*input, stats)),
            group_by,
            aggregates,
        },
        RelExpr::TransitiveClosure { input, from, to } => RelExpr::TransitiveClosure {
            input: Box::new(push_filters(*input, stats)),
            from,
            to,
        },
        RelExpr::CallExternal { input, module } => RelExpr::CallExternal {
            input: Box::new(push_filters(*input, stats)),
            module,
        },
        leaf => leaf,
    }
}

/// Place `pred` as low as possible over `input` (already filter-pushed).
fn push_one(input: RelExpr, pred: Predicate, stats: &Statistics) -> RelExpr {
    match input {
        RelExpr::Join { left, right, on } => {
            // A `right.`-prefixed name addresses the right input's column.
            if let Some(stripped) = pred.column.strip_prefix("right.") {
                if output_cols(&right, stats).is_some_and(|c| c.contains(stripped)) {
                    let inner = Predicate {
                        column: stripped.to_string(),
                        ..pred
                    };
                    return RelExpr::Join {
                        left,
                        right: Box::new(push_one(*right, inner, stats)),
                        on,
                    };
                }
            } else {
                let in_left = output_cols(&left, stats).is_some_and(|c| c.contains(&pred.column));
                if in_left {
                    // Unprefixed name resolves to the left input (merge semantics).
                    return RelExpr::Join {
                        left: Box::new(push_one(*left, pred, stats)),
                        right,
                        on,
                    };
                }
                let in_right = output_cols(&right, stats).is_some_and(|c| c.contains(&pred.column));
                if in_right {
                    return RelExpr::Join {
                        left,
                        right: Box::new(push_one(*right, pred, stats)),
                        on,
                    };
                }
            }
            // Origin unknown — keep the filter above the join.
            RelExpr::Filter {
                input: Box::new(RelExpr::Join { left, right, on }),
                predicate: pred,
            }
        }
        RelExpr::Project { input, columns } => {
            if columns.contains(&pred.column) {
                // The column survives the projection unchanged ⇒ filter below it.
                RelExpr::Project {
                    input: Box::new(push_one(*input, pred, stats)),
                    columns,
                }
            } else {
                RelExpr::Filter {
                    input: Box::new(RelExpr::Project { input, columns }),
                    predicate: pred,
                }
            }
        }
        other => RelExpr::Filter {
            input: Box::new(other),
            predicate: pred,
        },
    }
}

// ---------------------------------------------------------------------------
// Projection pushdown
// ---------------------------------------------------------------------------

/// Push the set of needed columns toward the leaves, pruning scans. `needed = None`
/// means "all columns" (the root, and anything below a join / external call where
/// pruning is unsafe).
fn prune_columns(expr: RelExpr, needed: Option<BTreeSet<String>>, stats: &Statistics) -> RelExpr {
    match expr {
        RelExpr::Scan { kind } => match (needed, stats.columns_of(&kind)) {
            (Some(req), Some(cols)) => {
                let keep: Vec<String> = cols.iter().filter(|c| req.contains(*c)).cloned().collect();
                // Only prune if it actually narrows the row and keeps ≥1 column.
                if !keep.is_empty() && keep.len() < cols.len() {
                    RelExpr::Scan { kind }.project(keep)
                } else {
                    RelExpr::Scan { kind }
                }
            }
            _ => RelExpr::Scan { kind },
        },
        RelExpr::Filter { input, predicate } => {
            let child = needed.map(|mut n| {
                n.insert(predicate.column.clone());
                n
            });
            RelExpr::Filter {
                input: Box::new(prune_columns(*input, child, stats)),
                predicate,
            }
        }
        RelExpr::Project { input, columns } => {
            // The project defines its output; its input needs exactly `columns`.
            let child: BTreeSet<String> = columns.iter().cloned().collect();
            RelExpr::Project {
                input: Box::new(prune_columns(*input, Some(child), stats)),
                columns,
            }
        }
        RelExpr::Aggregate {
            input,
            group_by,
            aggregates,
        } => {
            let mut child: BTreeSet<String> = group_by.iter().cloned().collect();
            for a in &aggregates {
                if agg_reads_column(a.func) {
                    child.insert(a.column.clone());
                }
            }
            RelExpr::Aggregate {
                input: Box::new(prune_columns(*input, Some(child), stats)),
                group_by,
                aggregates,
            }
        }
        RelExpr::TransitiveClosure { input, from, to } => {
            let child: BTreeSet<String> = [from.clone(), to.clone()].into_iter().collect();
            RelExpr::TransitiveClosure {
                input: Box::new(prune_columns(*input, Some(child), stats)),
                from,
                to,
            }
        }
        RelExpr::Window {
            input,
            partition_by,
            order_by,
            functions,
        } => {
            // The input needs the partition/order columns, each function's argument,
            // and any required columns that are not window-produced aliases.
            let child = needed.map(|mut n| {
                for f in &functions {
                    n.remove(&f.alias);
                    n.insert(f.column.clone());
                }
                n.extend(partition_by.iter().cloned());
                n.extend(order_by.iter().cloned());
                n
            });
            RelExpr::Window {
                input: Box::new(prune_columns(*input, child, stats)),
                partition_by,
                order_by,
                functions,
            }
        }
        // Pruning across a join is unsound (collision-prefixing depends on the full
        // column sets); leave both inputs at full width.
        RelExpr::Join { left, right, on } => RelExpr::Join {
            left: Box::new(prune_columns(*left, None, stats)),
            right: Box::new(prune_columns(*right, None, stats)),
            on,
        },
        RelExpr::CallExternal { input, module } => RelExpr::CallExternal {
            input: Box::new(prune_columns(*input, None, stats)),
            module,
        },
        leaf => leaf,
    }
}

// ---------------------------------------------------------------------------
// Join reordering (multi-way)
// ---------------------------------------------------------------------------

/// Reorder multi-way inner-join clusters into a cheaper left-deep order. Inner
/// equi-joins are associative + commutative, so a contiguous tree of `Join` nodes can
/// be re-associated freely; this picks a greedy order that keeps each intermediate
/// result small (start with the smallest relation, always add the connected relation
/// that yields the smallest join). Two-way joins and clusters whose column origins are
/// not all known are left as-is (build-side selection in the physical planner already
/// handles the binary case). Conservative: if the leaves cannot all be connected by the
/// collected predicates, the original expression is returned unchanged.
fn reorder_joins(expr: RelExpr, stats: &Statistics) -> RelExpr {
    match expr {
        RelExpr::Join { .. } => {
            // Flatten the contiguous inner-join cluster (recursing reorders subtrees).
            let mut leaves = Vec::new();
            let mut preds: Vec<(String, String)> = Vec::new();
            flatten_join(expr, stats, &mut leaves, &mut preds);
            // Reorder only a ≥3-way cluster whose inputs have *disjoint non-key
            // columns*: otherwise the row-merge's `right.` collision-prefixing is not
            // order-independent (and not lossless past one join), so changing the order
            // could change a column's name/value. Fact relations share base columns, so
            // rule joins keep source order — where per-join build-side selection (the
            // physical planner) already optimizes the binary case. A lossless reorder of
            // shared-schema multi-way joins would need source-qualified column naming;
            // deferred, as no rule emits 3-way joins.
            if leaves.len() >= 3 && safe_to_reorder(&leaves, &preds, stats) {
                greedy_order(leaves, preds, stats)
            } else {
                rebuild_left_deep(leaves, preds, stats)
            }
        }
        RelExpr::Filter { input, predicate } => RelExpr::Filter {
            input: Box::new(reorder_joins(*input, stats)),
            predicate,
        },
        RelExpr::Project { input, columns } => RelExpr::Project {
            input: Box::new(reorder_joins(*input, stats)),
            columns,
        },
        RelExpr::Aggregate {
            input,
            group_by,
            aggregates,
        } => RelExpr::Aggregate {
            input: Box::new(reorder_joins(*input, stats)),
            group_by,
            aggregates,
        },
        RelExpr::TransitiveClosure { input, from, to } => RelExpr::TransitiveClosure {
            input: Box::new(reorder_joins(*input, stats)),
            from,
            to,
        },
        RelExpr::CallExternal { input, module } => RelExpr::CallExternal {
            input: Box::new(reorder_joins(*input, stats)),
            module,
        },
        leaf => leaf,
    }
}

/// Collect the leaf inputs and `on`-pairs of a contiguous inner-join cluster. A child
/// that is itself a join is descended into (its joins join the same cluster); any other
/// child is a leaf, with its own subtrees reordered first.
fn flatten_join(
    expr: RelExpr,
    stats: &Statistics,
    leaves: &mut Vec<RelExpr>,
    preds: &mut Vec<(String, String)>,
) {
    match expr {
        RelExpr::Join { left, right, on } => {
            preds.extend(on);
            flatten_join(*left, stats, leaves, preds);
            flatten_join(*right, stats, leaves, preds);
        }
        other => leaves.push(reorder_joins(other, stats)),
    }
}

/// Whether reordering `leaves` is provably result-preserving: every pair of leaves
/// shares columns only among the join keys (so no non-key collision is renamed/lost by
/// the merge regardless of order). Unknown column sets ⇒ not safe.
fn safe_to_reorder(leaves: &[RelExpr], preds: &[(String, String)], stats: &Statistics) -> bool {
    let cols: Vec<BTreeSet<String>> = match leaves
        .iter()
        .map(|l| output_cols(l, stats))
        .collect::<Option<Vec<_>>>()
    {
        Some(c) => c,
        None => return false,
    };
    let keys: BTreeSet<&String> = preds.iter().flat_map(|(a, b)| [a, b]).collect();
    for i in 0..cols.len() {
        for j in (i + 1)..cols.len() {
            if cols[i].intersection(&cols[j]).any(|c| !keys.contains(c)) {
                return false;
            }
        }
    }
    true
}

/// Orient an unordered `on`-pair so its first column belongs to `left_cols`: returns
/// `(left_col, right_col)` if the pair connects `left_cols` to `right_cols`.
fn orient(
    pair: &(String, String),
    left_cols: &BTreeSet<String>,
    right_cols: &BTreeSet<String>,
) -> Option<(String, String)> {
    let (a, b) = pair;
    if left_cols.contains(a) && right_cols.contains(b) {
        Some((a.clone(), b.clone()))
    } else if left_cols.contains(b) && right_cols.contains(a) {
        Some((b.clone(), a.clone()))
    } else {
        None
    }
}

/// The chosen next leaf in the greedy join order.
struct NextLeaf {
    index: usize,
    on: Vec<(String, String)>,
    estimate: f64,
}

/// Greedy left-deep ordering of `leaves` connected by `preds`, smallest-first. Falls
/// back to the source-order left-deep build if column sets are unknown or the cluster
/// is not fully connected (avoids accidentally introducing a cross join).
fn greedy_order(leaves: Vec<RelExpr>, preds: Vec<(String, String)>, stats: &Statistics) -> RelExpr {
    let cols: Vec<BTreeSet<String>> = match leaves
        .iter()
        .map(|l| output_cols(l, stats))
        .collect::<Option<Vec<_>>>()
    {
        Some(c) => c,
        None => return rebuild_left_deep(leaves, preds, stats),
    };

    let n = leaves.len();
    let mut used = vec![false; n];
    // Start with the smallest leaf.
    let start = (0..n)
        .min_by(|&a, &b| {
            cardinality(&leaves[a], stats)
                .partial_cmp(&cardinality(&leaves[b], stats))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .expect("non-empty");
    used[start] = true;
    let mut acc = leaves[start].clone();
    let mut acc_cols = cols[start].clone();

    for _ in 1..n {
        // Among unused leaves connected to the accumulated set, pick the smallest join.
        let mut best: Option<NextLeaf> = None;
        for (i, leaf) in leaves.iter().enumerate() {
            if used[i] {
                continue;
            }
            let on: Vec<(String, String)> = preds
                .iter()
                .filter_map(|p| orient(p, &acc_cols, &cols[i]))
                .collect();
            if on.is_empty() {
                continue; // not connected yet
            }
            let candidate = RelExpr::Join {
                left: Box::new(acc.clone()),
                right: Box::new(leaf.clone()),
                on: on.clone(),
            };
            let estimate = cardinality(&candidate, stats);
            if best.as_ref().is_none_or(|b| estimate < b.estimate) {
                best = Some(NextLeaf {
                    index: i,
                    on,
                    estimate,
                });
            }
        }
        match best {
            Some(next) => {
                acc = RelExpr::Join {
                    left: Box::new(acc),
                    right: Box::new(leaves[next.index].clone()),
                    on: next.on,
                };
                // Connectivity tracking only needs plain-name membership; the physical
                // executor applies `right.` collision-prefixing at run time.
                acc_cols.extend(cols[next.index].iter().cloned());
                used[next.index] = true;
            }
            // A disconnected leaf remains ⇒ would be a cross join; don't risk it.
            None => return rebuild_left_deep(leaves, preds, stats),
        }
    }
    acc
}

/// Rebuild a left-deep join over `leaves` in source order, attaching each `on`-pair to
/// the join where both its columns first become available. A single leaf is returned
/// as-is (no join to build).
fn rebuild_left_deep(
    leaves: Vec<RelExpr>,
    preds: Vec<(String, String)>,
    stats: &Statistics,
) -> RelExpr {
    let mut iter = leaves.into_iter();
    let mut acc = iter.next().expect("≥1 leaf");
    let mut acc_cols = output_cols(&acc, stats).unwrap_or_default();
    for leaf in iter {
        let leaf_cols = output_cols(&leaf, stats).unwrap_or_default();
        let on: Vec<(String, String)> = preds
            .iter()
            .filter_map(|p| orient(p, &acc_cols, &leaf_cols))
            .collect();
        acc_cols.extend(leaf_cols);
        acc = RelExpr::Join {
            left: Box::new(acc),
            right: Box::new(leaf),
            on,
        };
    }
    acc
}

// ---------------------------------------------------------------------------
// Column provenance
// ---------------------------------------------------------------------------

/// The set of columns a subtree outputs, or `None` if unknown (an unscanned kind, or
/// a SQL-only node). Used to decide which join input owns a filter's column.
fn output_cols(expr: &RelExpr, stats: &Statistics) -> Option<BTreeSet<String>> {
    match expr {
        RelExpr::Scan { kind } => stats.columns_of(kind).cloned(),
        RelExpr::Filter { input, .. } | RelExpr::CallExternal { input, .. } => {
            output_cols(input, stats)
        }
        RelExpr::Project { columns, .. } => Some(columns.iter().cloned().collect()),
        RelExpr::Join { left, right, .. } => {
            let l = output_cols(left, stats)?;
            let r = output_cols(right, stats)?;
            let mut out = l.clone();
            for rn in &r {
                if l.contains(rn) {
                    out.insert(format!("right.{rn}"));
                } else {
                    out.insert(rn.clone());
                }
            }
            Some(out)
        }
        RelExpr::Aggregate {
            group_by,
            aggregates,
            ..
        } => {
            let mut out: BTreeSet<String> = group_by.iter().cloned().collect();
            out.extend(aggregates.iter().map(|a| a.alias.clone()));
            Some(out)
        }
        RelExpr::Window {
            input, functions, ..
        } => {
            // Window keeps the input columns and adds one per function alias.
            let mut out = output_cols(input, stats)?;
            out.extend(functions.iter().map(|f| f.alias.clone()));
            Some(out)
        }
        RelExpr::TransitiveClosure { from, to, .. } => {
            Some([from.clone(), to.clone()].into_iter().collect())
        }
        RelExpr::JoinFilter { .. } | RelExpr::GroupCountDistinct { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CmpOp, Predicate, ScalarValue};
    use std::collections::HashMap;

    fn pred(col: &str, v: &str) -> Predicate {
        Predicate {
            column: col.into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str(v.into()),
        }
    }

    fn stats() -> Statistics {
        let mut rows = HashMap::new();
        let mut cols = HashMap::new();
        rows.insert("left_rel".into(), 1000.0);
        rows.insert("right_rel".into(), 1000.0);
        cols.insert(
            "left_rel".to_string(),
            ["key", "tier", "subject", "fact_id"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        cols.insert(
            "right_rel".to_string(),
            ["key", "subject", "fact_id"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        Statistics::new(rows, cols)
    }

    #[test]
    fn filter_pushed_below_join_to_owning_side() {
        // Filter on `tier` (a left-only column) sits above the join; it should sink
        // into the left input.
        let plan = RelExpr::scan("left_rel")
            .join(
                RelExpr::scan("right_rel"),
                vec![("key".into(), "key".into())],
            )
            .filter(pred("tier", "hot"));
        let opt = optimize(&plan, &stats());
        // Expect Join(Filter(Scan left), Scan right) — the filter is now under the join.
        match &opt {
            RelExpr::Join { left, .. } => {
                assert!(
                    matches!(&**left, RelExpr::Filter { .. })
                        // possibly wrapped by a projection-pushdown Project
                        || matches!(&**left, RelExpr::Project { .. }),
                    "left input should carry the pushed filter, got {left:?}"
                );
                fn has_filter(e: &RelExpr) -> bool {
                    match e {
                        RelExpr::Filter { .. } => true,
                        RelExpr::Project { input, .. } => has_filter(input),
                        _ => false,
                    }
                }
                assert!(has_filter(left));
            }
            other => panic!("expected top-level Join, got {other:?}"),
        }
    }

    #[test]
    fn filter_not_pushed_when_origin_unknown() {
        // With empty stats the optimizer cannot prove the column's side ⇒ no pushdown.
        let plan = RelExpr::scan("left_rel")
            .join(
                RelExpr::scan("right_rel"),
                vec![("key".into(), "key".into())],
            )
            .filter(pred("tier", "hot"));
        let opt = optimize(&plan, &Statistics::empty());
        assert!(
            matches!(opt, RelExpr::Filter { .. }),
            "should stay a top Filter"
        );
    }

    /// Stats for three relations connected on `k` with otherwise *disjoint* columns
    /// (the reorder-safe shape).
    fn three_disjoint(big: f64, mid: f64, small: f64) -> Statistics {
        let mut rows = HashMap::new();
        let mut cols = HashMap::new();
        for (kind, n, extra) in [("big", big, "a"), ("mid", mid, "b"), ("small", small, "c")] {
            rows.insert(kind.to_string(), n);
            cols.insert(
                kind.to_string(),
                ["k", extra].iter().map(|s| s.to_string()).collect(),
            );
        }
        Statistics::new(rows, cols)
    }

    fn deepest_scan(e: &RelExpr) -> Option<&str> {
        match e {
            RelExpr::Scan { kind } => Some(kind),
            RelExpr::Join { left, .. } => deepest_scan(left),
            RelExpr::Filter { input, .. } | RelExpr::Project { input, .. } => deepest_scan(input),
            _ => None,
        }
    }

    #[test]
    fn three_way_join_reorders_smallest_first() {
        // Disjoint non-key columns ⇒ reordering is safe; smallest relation anchors.
        let stats = three_disjoint(100_000.0, 1000.0, 10.0);
        let plan = RelExpr::scan("big")
            .join(RelExpr::scan("small"), vec![("k".into(), "k".into())])
            .join(RelExpr::scan("mid"), vec![("k".into(), "k".into())]);
        let opt = optimize(&plan, &stats);
        assert_eq!(deepest_scan(&opt), Some("small"));
    }

    #[test]
    fn shared_schema_multiway_join_is_not_reordered() {
        // Fact relations share base columns (`subject` here) ⇒ reordering is unsafe and
        // must be skipped, leaving the source order intact (no silent corruption).
        let mut rows = HashMap::new();
        let mut cols = HashMap::new();
        for (kind, n) in [("big", 100_000.0), ("mid", 1000.0), ("small", 10.0)] {
            rows.insert(kind.to_string(), n);
            cols.insert(
                kind.to_string(),
                ["k", "subject"].iter().map(|s| s.to_string()).collect(),
            );
        }
        let stats = Statistics::new(rows, cols);
        let plan = RelExpr::scan("big")
            .join(RelExpr::scan("small"), vec![("k".into(), "k".into())])
            .join(RelExpr::scan("mid"), vec![("k".into(), "k".into())]);
        let opt = optimize(&plan, &stats);
        // Source order preserved: the original deepest leaf is `big`.
        assert_eq!(deepest_scan(&opt), Some("big"));
    }

    #[test]
    fn scan_pruned_to_referenced_columns() {
        let plan = RelExpr::scan("left_rel")
            .filter(pred("tier", "hot"))
            .project(vec!["subject".into()]);
        let opt = optimize(&plan, &stats());
        // The scan should now be wrapped in a Project keeping only {subject, tier}.
        fn find_scan_project(e: &RelExpr) -> Option<&Vec<String>> {
            match e {
                RelExpr::Project { input, columns } => {
                    if matches!(&**input, RelExpr::Scan { .. }) {
                        Some(columns)
                    } else {
                        find_scan_project(input)
                    }
                }
                RelExpr::Filter { input, .. } => find_scan_project(input),
                _ => None,
            }
        }
        let pruned = find_scan_project(&opt).expect("scan should be pruned by a Project");
        let set: BTreeSet<&String> = pruned.iter().collect();
        assert!(set.contains(&"subject".to_string()));
        assert!(set.contains(&"tier".to_string()));
        assert!(
            !set.contains(&"key".to_string()),
            "unused column should be pruned"
        );
    }
}
