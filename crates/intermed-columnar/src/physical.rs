//! Physical query plan + planner (plan Phase 1.1).
//!
//! [`RelExpr`](crate::ir::RelExpr) is the *logical* plan — what the rule means,
//! independent of how it runs. A physical plan is *how* the in-process engine
//! evaluates it: it commits to concrete operators (a [`HashJoin`] rather than a bare
//! "join", a [`HashAggregate`] rather than a bare "aggregate") and to operator
//! options (which side of a join to build the hash table from).
//!
//! Keeping the two separate is the precondition for everything downstream: the
//! optimizer (Phase 2) rewrites the *logical* plan, the physical planner ([`plan`])
//! lowers the optimized logical plan to operators, and the executor
//! ([`crate::executor`]) runs the operators. The logical [`RelExpr`] stays the stable,
//! widely-consumed IR (SQL/Datalog lowering, the rule bridge); the physical plan is
//! private to the in-process engine.
//!
//! [`HashJoin`]: PhysicalPlan::HashJoin
//! [`HashAggregate`]: PhysicalPlan::HashAggregate

use crate::cost::{Statistics, cardinality};
use crate::ir::{Aggregate, Condition, Predicate, RelExpr, WindowFunction};

/// Which input of a join the hash table is built from. The build side is fully
/// materialized into the hash table; the *probe* side is streamed. Choosing the
/// smaller relation as the build side minimizes memory — the cost-based optimizer
/// (Phase 2) sets this from cardinality estimates; until then [`plan`] uses a
/// heuristic (build the right input, which for the declarative rules is usually the
/// smaller dimension relation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildSide {
    Left,
    Right,
}

/// A node in the physical plan: a concrete operator tree the executor runs.
#[derive(Debug, Clone, PartialEq)]
pub enum PhysicalPlan {
    /// Read all facts of a kind (base relation). Streams rows from the store.
    Scan { kind: String },
    /// Streaming selection: keep rows matching `predicate` (no materialization).
    Filter {
        input: Box<PhysicalPlan>,
        predicate: Predicate,
    },
    /// Streaming projection: keep only the named columns (no materialization).
    Project {
        input: Box<PhysicalPlan>,
        columns: Vec<String>,
    },
    /// Hash equi-join: build a hash table from `build_side`, stream the other side
    /// and probe. Replaces the old nested-loop join.
    HashJoin {
        left: Box<PhysicalPlan>,
        right: Box<PhysicalPlan>,
        on: Vec<(String, String)>,
        build_side: BuildSide,
    },
    /// Nested-loop join — the fallback for a join with no equi-keys (a cross join /
    /// cartesian product). Kept for completeness; equi-joins use [`HashJoin`].
    NestedLoopJoin {
        left: Box<PhysicalPlan>,
        right: Box<PhysicalPlan>,
    },
    /// Hash aggregation: group rows in a hash table keyed by the group columns,
    /// accumulating aggregates per group. First-seen group order is preserved.
    HashAggregate {
        input: Box<PhysicalPlan>,
        group_by: Vec<String>,
        aggregates: Vec<Aggregate>,
    },
    /// Window functions over partitions (does not collapse rows).
    Window {
        input: Box<PhysicalPlan>,
        partition_by: Vec<String>,
        order_by: Vec<String>,
        functions: Vec<WindowFunction>,
    },
    /// Recursive reachability over a `(from, to)` edge relation (in-process fixpoint).
    TransitiveClosure {
        input: Box<PhysicalPlan>,
        from: String,
        to: String,
    },
    /// Pass-through for an external (WASM) call — the in-process engine yields its
    /// input unchanged; the router dispatches the real call to the WASM backend.
    CallExternal {
        input: Box<PhysicalPlan>,
        module: String,
    },
    /// Declarative-rule join: cross two scanned kinds (aliased) and keep rows
    /// satisfying `condition`. Output columns: `left_fact_id`/`left_subject`/
    /// `right_fact_id`/`right_subject` (matching the SQL form).
    JoinFilter {
        left_kind: String,
        left_alias: String,
        right_kind: String,
        right_alias: String,
        condition: Condition,
    },
    /// Group facts of any of `kinds` by subject and keep groups whose distinct count of
    /// `distinct_attr` is at least `min_count`. Output column: `group_col` (= subject).
    GroupCountDistinct {
        kinds: Vec<String>,
        group_col: String,
        distinct_attr: String,
        min_count: usize,
    },
}

impl PhysicalPlan {
    /// The child operators feeding this one (for tree traversal / `EXPLAIN ANALYZE`).
    pub fn children(&self) -> Vec<&PhysicalPlan> {
        match self {
            PhysicalPlan::Scan { .. }
            | PhysicalPlan::JoinFilter { .. }
            | PhysicalPlan::GroupCountDistinct { .. } => Vec::new(),
            PhysicalPlan::Filter { input, .. }
            | PhysicalPlan::Project { input, .. }
            | PhysicalPlan::HashAggregate { input, .. }
            | PhysicalPlan::Window { input, .. }
            | PhysicalPlan::TransitiveClosure { input, .. }
            | PhysicalPlan::CallExternal { input, .. } => vec![input.as_ref()],
            PhysicalPlan::HashJoin { left, right, .. }
            | PhysicalPlan::NestedLoopJoin { left, right } => vec![left.as_ref(), right.as_ref()],
        }
    }

    /// A one-line description of this operator (label + key options) for `EXPLAIN`.
    pub fn describe(&self) -> String {
        match self {
            PhysicalPlan::Scan { kind } => format!("Scan {kind}"),
            PhysicalPlan::Filter { predicate, .. } => {
                format!("Filter {}", describe_predicate(predicate))
            }
            PhysicalPlan::Project { columns, .. } => format!("Project [{}]", columns.join(", ")),
            PhysicalPlan::HashJoin { on, build_side, .. } => {
                let keys = on
                    .iter()
                    .map(|(l, r)| format!("{l}={r}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("HashJoin on [{keys}] build={build_side:?}")
            }
            PhysicalPlan::NestedLoopJoin { .. } => "NestedLoopJoin".to_string(),
            PhysicalPlan::HashAggregate {
                group_by,
                aggregates,
                ..
            } => format!(
                "HashAggregate group=[{}] aggs=[{}]",
                group_by.join(", "),
                aggregates
                    .iter()
                    .map(|a| a.alias.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            PhysicalPlan::Window {
                partition_by,
                order_by,
                functions,
                ..
            } => format!(
                "Window partition=[{}] order=[{}] fns=[{}]",
                partition_by.join(", "),
                order_by.join(", "),
                functions
                    .iter()
                    .map(|f| f.alias.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            PhysicalPlan::TransitiveClosure { from, to, .. } => {
                format!("TransitiveClosure {from}->{to}")
            }
            PhysicalPlan::CallExternal { module, .. } => format!("CallExternal {module}"),
            PhysicalPlan::JoinFilter {
                left_kind,
                left_alias,
                right_kind,
                right_alias,
                ..
            } => format!("JoinFilter {left_alias}:{left_kind} × {right_alias}:{right_kind}"),
            PhysicalPlan::GroupCountDistinct {
                kinds,
                distinct_attr,
                min_count,
                ..
            } => format!(
                "GroupCountDistinct kinds=[{}] distinct({distinct_attr})>={min_count}",
                kinds.join(", ")
            ),
        }
    }

    /// A short operator label for `EXPLAIN`-style output and diagnostics.
    pub fn op_label(&self) -> &'static str {
        match self {
            PhysicalPlan::Scan { .. } => "Scan",
            PhysicalPlan::Filter { .. } => "Filter",
            PhysicalPlan::Project { .. } => "Project",
            PhysicalPlan::HashJoin { .. } => "HashJoin",
            PhysicalPlan::NestedLoopJoin { .. } => "NestedLoopJoin",
            PhysicalPlan::HashAggregate { .. } => "HashAggregate",
            PhysicalPlan::Window { .. } => "Window",
            PhysicalPlan::TransitiveClosure { .. } => "TransitiveClosure",
            PhysicalPlan::CallExternal { .. } => "CallExternal",
            PhysicalPlan::JoinFilter { .. } => "JoinFilter",
            PhysicalPlan::GroupCountDistinct { .. } => "GroupCountDistinct",
        }
    }
}

/// Choose which side to build the hash table from: the input with the smaller
/// estimated cardinality, so the hash table (the materialized side) is as small as
/// possible. With empty statistics the estimates tie and this falls back to building
/// the right input.
fn choose_build_side(left: &RelExpr, right: &RelExpr, stats: &Statistics) -> BuildSide {
    if cardinality(left, stats) < cardinality(right, stats) {
        BuildSide::Left
    } else {
        BuildSide::Right
    }
}

/// Lower an (optimized) logical [`RelExpr`] to a physical operator tree, using the
/// catalog `stats` to choose operator options (the hash-join build side).
pub fn plan(expr: &RelExpr, stats: &Statistics) -> PhysicalPlan {
    match expr {
        RelExpr::Scan { kind } => PhysicalPlan::Scan { kind: kind.clone() },
        RelExpr::Filter { input, predicate } => PhysicalPlan::Filter {
            input: Box::new(plan(input, stats)),
            predicate: predicate.clone(),
        },
        RelExpr::Project { input, columns } => PhysicalPlan::Project {
            input: Box::new(plan(input, stats)),
            columns: columns.clone(),
        },
        RelExpr::Join { left, right, on } => {
            if on.is_empty() {
                PhysicalPlan::NestedLoopJoin {
                    left: Box::new(plan(left, stats)),
                    right: Box::new(plan(right, stats)),
                }
            } else {
                PhysicalPlan::HashJoin {
                    left: Box::new(plan(left, stats)),
                    right: Box::new(plan(right, stats)),
                    on: on.clone(),
                    build_side: choose_build_side(left, right, stats),
                }
            }
        }
        RelExpr::Aggregate {
            input,
            group_by,
            aggregates,
        } => PhysicalPlan::HashAggregate {
            input: Box::new(plan(input, stats)),
            group_by: group_by.clone(),
            aggregates: aggregates.clone(),
        },
        RelExpr::Window {
            input,
            partition_by,
            order_by,
            functions,
        } => PhysicalPlan::Window {
            input: Box::new(plan(input, stats)),
            partition_by: partition_by.clone(),
            order_by: order_by.clone(),
            functions: functions.clone(),
        },
        RelExpr::TransitiveClosure { input, from, to } => PhysicalPlan::TransitiveClosure {
            input: Box::new(plan(input, stats)),
            from: from.clone(),
            to: to.clone(),
        },
        RelExpr::CallExternal { input, module } => PhysicalPlan::CallExternal {
            input: Box::new(plan(input, stats)),
            module: module.clone(),
        },
        RelExpr::JoinFilter {
            left_kind,
            left_alias,
            right_kind,
            right_alias,
            condition,
        } => PhysicalPlan::JoinFilter {
            left_kind: left_kind.clone(),
            left_alias: left_alias.clone(),
            right_kind: right_kind.clone(),
            right_alias: right_alias.clone(),
            condition: condition.clone(),
        },
        RelExpr::GroupCountDistinct {
            kinds,
            group_col,
            distinct_attr,
            min_count,
        } => PhysicalPlan::GroupCountDistinct {
            kinds: kinds.clone(),
            group_col: group_col.clone(),
            distinct_attr: distinct_attr.clone(),
            min_count: *min_count,
        },
    }
}

/// Render a physical plan as an indented tree (the body of `EXPLAIN`). Phase 3 wires
/// the richer `EXPLAIN ANALYZE`; this is the structural view.
pub fn explain(plan: &PhysicalPlan) -> String {
    let mut out = String::new();
    fmt_node(plan, 0, &mut out);
    out
}

/// Render one operator and recurse into its children (each operator's one-line form is
/// [`PhysicalPlan::describe`], so the tree printer and the `EXPLAIN ANALYZE` annotator
/// share a single description per operator).
fn fmt_node(plan: &PhysicalPlan, depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("  ");
    }
    out.push_str(&plan.describe());
    out.push('\n');
    for child in plan.children() {
        fmt_node(child, depth + 1, out);
    }
}

fn describe_predicate(p: &Predicate) -> String {
    format!("{} {:?} {:?}", p.column, p.op, p.value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{AggFunc, Aggregate, CmpOp, Predicate, ScalarValue};

    fn eq(col: &str, v: &str) -> Predicate {
        Predicate {
            column: col.into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str(v.into()),
        }
    }

    #[test]
    fn equi_join_lowers_to_hash_join() {
        let logical = RelExpr::scan("a").join(RelExpr::scan("b"), vec![("k".into(), "k".into())]);
        let phys = plan(&logical, &Statistics::empty());
        // Empty stats ⇒ the build side ties and falls back to the right input.
        assert!(matches!(
            phys,
            PhysicalPlan::HashJoin {
                build_side: BuildSide::Right,
                ..
            }
        ));
    }

    #[test]
    fn build_side_picks_smaller_input() {
        use std::collections::HashMap;
        let mut rows = HashMap::new();
        rows.insert("big".to_string(), 100_000.0);
        rows.insert("small".to_string(), 10.0);
        let stats = Statistics::new(rows, HashMap::new());
        // left = big, right = small ⇒ build the right (smaller) side.
        let r = RelExpr::scan("big").join(RelExpr::scan("small"), vec![("k".into(), "k".into())]);
        assert!(matches!(
            plan(&r, &stats),
            PhysicalPlan::HashJoin {
                build_side: BuildSide::Right,
                ..
            }
        ));
        // left = small, right = big ⇒ build the left (smaller) side.
        let l = RelExpr::scan("small").join(RelExpr::scan("big"), vec![("k".into(), "k".into())]);
        assert!(matches!(
            plan(&l, &stats),
            PhysicalPlan::HashJoin {
                build_side: BuildSide::Left,
                ..
            }
        ));
    }

    #[test]
    fn keyless_join_lowers_to_nested_loop() {
        let logical = RelExpr::scan("a").join(RelExpr::scan("b"), Vec::new());
        assert!(matches!(
            plan(&logical, &Statistics::empty()),
            PhysicalPlan::NestedLoopJoin { .. }
        ));
    }

    #[test]
    fn aggregate_lowers_to_hash_aggregate() {
        let logical = RelExpr::scan("a").aggregate(
            vec!["g".into()],
            vec![Aggregate {
                func: AggFunc::Count,
                column: String::new(),
                alias: "n".into(),
            }],
        );
        assert!(matches!(
            plan(&logical, &Statistics::empty()),
            PhysicalPlan::HashAggregate { .. }
        ));
    }

    #[test]
    fn explain_renders_indented_tree() {
        let logical = RelExpr::scan("mixin")
            .filter(eq("op", "redirect"))
            .project(vec!["mod".into()]);
        let text = explain(&plan(&logical, &Statistics::empty()));
        assert!(text.contains("Project"));
        assert!(text.contains("Filter"));
        assert!(text.contains("Scan mixin"));
        // Indentation increases down the tree.
        let scan_line = text.lines().find(|l| l.contains("Scan")).unwrap();
        assert!(scan_line.starts_with("    "));
    }
}
