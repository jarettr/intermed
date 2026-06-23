//! Query router / planner (plan Phase 2).
//!
//! The capability analyzer says *which* engines a plan needs; the router decides
//! *how to split it across them*. It partitions a [`RelExpr`] into maximal
//! single-engine **stages** connected by a dependency DAG: a stage's output (an
//! Arrow batch) feeds the stages above it. This realizes the plan's example —
//! filter base facts in-process, aggregate in DuckDB, recurse in Souffle, finish in
//! WASM — as an explicit, inspectable execution plan.

use crate::ir::{Engine, RelExpr};

/// The engine an individual operator runs on (its *own* requirement, before union).
fn op_engine(expr: &RelExpr) -> Engine {
    match expr {
        RelExpr::Scan { .. }
        | RelExpr::Filter { .. }
        | RelExpr::Project { .. }
        | RelExpr::Join { .. } => Engine::InProcessDatalog,
        // Aggregation / join-filter / group-distinct run in-process too, but the router
        // prefers DuckDB for them at scale.
        RelExpr::Aggregate { .. }
        | RelExpr::GroupCountDistinct { .. }
        | RelExpr::JoinFilter { .. } => Engine::DuckDb,
        RelExpr::Window { .. } => Engine::InProcessDatalog,
        RelExpr::TransitiveClosure { .. } => Engine::Souffle,
        RelExpr::CallExternal { .. } => Engine::Wasm,
    }
}

fn op_label(expr: &RelExpr) -> &'static str {
    match expr {
        RelExpr::Scan { .. } => "scan",
        RelExpr::Filter { .. } => "filter",
        RelExpr::Project { .. } => "project",
        RelExpr::Join { .. } => "join",
        RelExpr::Aggregate { .. } => "aggregate",
        RelExpr::Window { .. } => "window",
        RelExpr::TransitiveClosure { .. } => "transitive-closure",
        RelExpr::CallExternal { .. } => "call-external",
        RelExpr::JoinFilter { .. } => "join-filter",
        RelExpr::GroupCountDistinct { .. } => "group-count-distinct",
    }
}

/// One single-engine partition of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub id: usize,
    pub engine: Engine,
    /// The operator at the root of this stage (for diagnostics).
    pub root_op: String,
    /// Stages whose output this stage consumes (cross-engine boundaries).
    pub depends_on: Vec<usize>,
}

/// A partitioned plan: stages plus the id of the final (output) stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub stages: Vec<Stage>,
    pub output: usize,
}

impl ExecutionPlan {
    /// Stage ids in a valid execution order (every stage after the stages it
    /// depends on). Leaves first, output last.
    pub fn execution_order(&self) -> Vec<usize> {
        let mut visited = vec![false; self.stages.len()];
        let mut order = Vec::new();
        self.visit(self.output, &mut visited, &mut order);
        order
    }

    fn visit(&self, id: usize, visited: &mut [bool], order: &mut Vec<usize>) {
        if visited[id] {
            return;
        }
        visited[id] = true;
        for &dep in &self.stages[id].depends_on {
            self.visit(dep, visited, order);
        }
        order.push(id);
    }

    /// Number of distinct engines the plan touches.
    pub fn engine_count(&self) -> usize {
        let mut e: Vec<Engine> = self.stages.iter().map(|s| s.engine).collect();
        e.sort();
        e.dedup();
        e.len()
    }
}

struct Builder {
    stages: Vec<Stage>,
}

impl Builder {
    fn new_stage(&mut self, engine: Engine, root_op: &str) -> usize {
        let id = self.stages.len();
        self.stages.push(Stage {
            id,
            engine,
            root_op: root_op.to_string(),
            depends_on: Vec::new(),
        });
        id
    }

    /// Walk `expr`, which belongs to `stage` running on `engine`. Same-engine
    /// children stay in `stage`; a different-engine child opens a new stage that
    /// `stage` depends on.
    fn walk(&mut self, expr: &RelExpr, engine: Engine, stage: usize) {
        for child in children(expr) {
            let ce = op_engine(child);
            if ce == engine {
                self.walk(child, engine, stage);
            } else {
                let child_stage = self.new_stage(ce, op_label(child));
                if !self.stages[stage].depends_on.contains(&child_stage) {
                    self.stages[stage].depends_on.push(child_stage);
                }
                self.walk(child, ce, child_stage);
            }
        }
    }
}

fn children(expr: &RelExpr) -> Vec<&RelExpr> {
    match expr {
        RelExpr::Scan { .. } | RelExpr::JoinFilter { .. } | RelExpr::GroupCountDistinct { .. } => {
            Vec::new()
        }
        RelExpr::Filter { input, .. }
        | RelExpr::Project { input, .. }
        | RelExpr::Aggregate { input, .. }
        | RelExpr::Window { input, .. }
        | RelExpr::TransitiveClosure { input, .. }
        | RelExpr::CallExternal { input, .. } => vec![input.as_ref()],
        RelExpr::Join { left, right, .. } => vec![left.as_ref(), right.as_ref()],
    }
}

/// Partition a plan into single-engine stages.
pub fn plan(expr: &RelExpr) -> ExecutionPlan {
    let mut b = Builder { stages: Vec::new() };
    let root_engine = op_engine(expr);
    let output = b.new_stage(root_engine, op_label(expr));
    b.walk(expr, root_engine, output);
    ExecutionPlan {
        stages: b.stages,
        output,
    }
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
    fn single_engine_plan_is_one_stage() {
        let p = plan(
            &RelExpr::scan("mixin_application_site")
                .filter(eq("operation", "redirect"))
                .project(vec!["mod".into()]),
        );
        assert_eq!(p.stages.len(), 1);
        assert_eq!(p.stages[0].engine, Engine::InProcessDatalog);
        assert_eq!(p.engine_count(), 1);
    }

    #[test]
    fn engine_boundaries_split_stages_in_dependency_order() {
        // scan+filter (datalog) → transitive-closure (souffle) → aggregate (duckdb)
        // → call-external (wasm): four stages, linear dependency chain.
        let p = plan(
            &RelExpr::scan("dependency")
                .filter(eq("side", "server"))
                .transitive_closure("mod", "requires")
                .aggregate(
                    vec!["mod".into()],
                    vec![Aggregate {
                        func: AggFunc::Count,
                        column: String::new(),
                        alias: "n".into(),
                    }],
                )
                .call_external("semver"),
        );
        assert_eq!(p.engine_count(), 4);
        let order = p.execution_order();
        // Leaves (datalog) first, output (wasm) last.
        assert_eq!(p.stages[order[0]].engine, Engine::InProcessDatalog);
        assert_eq!(p.stages[*order.last().unwrap()].engine, Engine::Wasm);
        assert_eq!(p.stages[p.output].engine, Engine::Wasm);
        // Every dependency appears before its dependent in the order.
        for (pos, &sid) in order.iter().enumerate() {
            for &dep in &p.stages[sid].depends_on {
                let dep_pos = order.iter().position(|&x| x == dep).unwrap();
                assert!(dep_pos < pos, "dep {dep} must precede {sid}");
            }
        }
    }

    #[test]
    fn adjacent_same_engine_ops_share_a_stage() {
        // Two filters + a project are all in-process ⇒ a single stage.
        let p = plan(
            &RelExpr::scan("mod")
                .filter(eq("loader", "fabric"))
                .filter(eq("side", "client"))
                .project(vec!["id".into()]),
        );
        assert_eq!(p.stages.len(), 1);
    }
}
