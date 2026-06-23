//! Relational query IR + capability analyzer (plan Phase 2).
//!
//! Instead of translating a declarative rule directly to SQL or Datalog, a rule
//! compiles to this small relational algebra ([`RelExpr`]). The [`analyze`] pass
//! then tags the graph with which execution engine each construct *requires*, which
//! a later router uses to partition the plan across the in-process Datalog engine,
//! DuckDB, Souffle, and the WASM sandbox.
//!
//! This module is intentionally pure data + analysis: it builds and inspects plans
//! but does not execute them, so it is dependency-free.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Which execution engine a construct is routed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Engine {
    /// Compiled in-process Datalog (scan/filter/project/join of base predicates).
    InProcessDatalog,
    /// DuckDB (aggregation, window/time-series analytics).
    DuckDb,
    /// Souffle (recursive fixpoint / transitive closure over graphs).
    Souffle,
    /// WASM sandbox (imperative host logic — semver, heuristics).
    Wasm,
}

impl Engine {
    pub fn as_str(self) -> &'static str {
        match self {
            Engine::InProcessDatalog => "in-process-datalog",
            Engine::DuckDb => "duckdb",
            Engine::Souffle => "souffle",
            Engine::Wasm => "wasm",
        }
    }
}

/// A comparison predicate on a column.
#[derive(Debug, Clone, PartialEq)]
pub struct Predicate {
    pub column: String,
    pub op: CmpOp,
    pub value: ScalarValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// A literal. Deserializes directly from a JSON scalar (`"x"`, `5`, `5.0`, `true`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScalarValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

/// An aggregate to compute per group.
#[derive(Debug, Clone, PartialEq)]
pub struct Aggregate {
    pub func: AggFunc,
    pub column: String,
    pub alias: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AggFunc {
    Count,
    Sum,
    Min,
    Max,
    Avg,
}

/// A window function computed per row over a partition (it does not collapse rows,
/// unlike [`Aggregate`]). Ranking functions (`RowNumber`/`Rank`/`DenseRank`) use the
/// `order_by`; the aggregate windows compute over the whole partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowFn {
    RowNumber,
    Rank,
    DenseRank,
    Count,
    Sum,
    Min,
    Max,
    Avg,
}

/// One window function to compute, written into `alias`. `column` is the argument for
/// the aggregate windows (ignored by the ranking functions).
#[derive(Debug, Clone, PartialEq)]
pub struct WindowFunction {
    pub func: WindowFn,
    pub column: String,
    pub alias: String,
}

/// A richer boolean condition over (possibly two) relations — needed for join
/// `on`/`where` and aggregate `having`, where the declarative rules compare two
/// columns, test `IN` lists and `IS NOT NULL`, not just `column op literal`. Columns
/// are alias-qualified (`m.loader`) in a join context.
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    /// Always true (`TRUE`).
    True,
    /// `column op literal`.
    Cmp {
        column: String,
        op: CmpOp,
        value: ScalarValue,
    },
    /// `left_column op right_column` (a column-to-column comparison).
    ColCmp {
        left: String,
        op: CmpOp,
        right: String,
    },
    /// `column IN (literals…)`.
    In {
        column: String,
        values: Vec<String>,
    },
    /// `column IS NOT NULL`.
    NotNull {
        column: String,
    },
    /// `column IS NULL`.
    IsNull {
        column: String,
    },
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    Not(Box<Condition>),
}

/// A node in the relational IR.
#[derive(Debug, Clone, PartialEq)]
pub enum RelExpr {
    /// Read all facts of a predicate kind (base relation).
    Scan { kind: String },
    /// Keep rows matching `predicate`.
    Filter {
        input: Box<RelExpr>,
        predicate: Predicate,
    },
    /// Keep only the named columns.
    Project {
        input: Box<RelExpr>,
        columns: Vec<String>,
    },
    /// Equi-join two inputs on `on` column pairs.
    Join {
        left: Box<RelExpr>,
        right: Box<RelExpr>,
        on: Vec<(String, String)>,
    },
    /// Group-by aggregation.
    Aggregate {
        input: Box<RelExpr>,
        group_by: Vec<String>,
        aggregates: Vec<Aggregate>,
    },
    /// Window functions: compute per-row values over partitions without collapsing
    /// rows. Output = input columns + one column per [`WindowFunction`] alias.
    Window {
        input: Box<RelExpr>,
        partition_by: Vec<String>,
        order_by: Vec<String>,
        functions: Vec<WindowFunction>,
    },
    /// Recursive reachability over a `(from, to)` edge relation — the construct that
    /// forces a fixpoint engine (Souffle).
    TransitiveClosure {
        input: Box<RelExpr>,
        from: String,
        to: String,
    },
    /// Call an external (WASM) module over the input rows.
    CallExternal { input: Box<RelExpr>, module: String },
    /// A declarative-rule join: cross two scanned kinds (with aliases) and keep rows
    /// satisfying `condition`. Mirrors the `Join` rule shape (`left`/`right`/`on`/
    /// `where`), where `condition` is alias-qualified.
    JoinFilter {
        left_kind: String,
        left_alias: String,
        right_kind: String,
        right_alias: String,
        condition: Condition,
    },
    /// `GroupDistinct`: group facts of any of `kinds` by `group_col` and keep groups
    /// whose distinct count of `distinct_attr` is at least `min_count`.
    GroupCountDistinct {
        kinds: Vec<String>,
        group_col: String,
        distinct_attr: String,
        min_count: usize,
    },
}

impl RelExpr {
    /// Convenience constructors keep plan-building readable.
    pub fn scan(kind: impl Into<String>) -> Self {
        RelExpr::Scan { kind: kind.into() }
    }
    pub fn filter(self, predicate: Predicate) -> Self {
        RelExpr::Filter {
            input: Box::new(self),
            predicate,
        }
    }
    pub fn project(self, columns: Vec<String>) -> Self {
        RelExpr::Project {
            input: Box::new(self),
            columns,
        }
    }
    pub fn aggregate(self, group_by: Vec<String>, aggregates: Vec<Aggregate>) -> Self {
        RelExpr::Aggregate {
            input: Box::new(self),
            group_by,
            aggregates,
        }
    }
    pub fn window(
        self,
        partition_by: Vec<String>,
        order_by: Vec<String>,
        functions: Vec<WindowFunction>,
    ) -> Self {
        RelExpr::Window {
            input: Box::new(self),
            partition_by,
            order_by,
            functions,
        }
    }
    pub fn transitive_closure(self, from: impl Into<String>, to: impl Into<String>) -> Self {
        RelExpr::TransitiveClosure {
            input: Box::new(self),
            from: from.into(),
            to: to.into(),
        }
    }
    pub fn call_external(self, module: impl Into<String>) -> Self {
        RelExpr::CallExternal {
            input: Box::new(self),
            module: module.into(),
        }
    }
    pub fn join(self, right: RelExpr, on: Vec<(String, String)>) -> Self {
        RelExpr::Join {
            left: Box::new(self),
            right: Box::new(right),
            on,
        }
    }

    /// Every base-relation kind this plan reads (from `Scan`, `JoinFilter`, and
    /// `GroupCountDistinct`). The in-process store only needs to materialize these
    /// kinds (plan Phase 2: demand-driven build) — a kind no plan scans is never
    /// queried, so building it is wasted work.
    pub fn collect_scanned_kinds(&self, out: &mut BTreeSet<String>) {
        match self {
            RelExpr::Scan { kind } => {
                out.insert(kind.clone());
            }
            RelExpr::JoinFilter {
                left_kind,
                right_kind,
                ..
            } => {
                out.insert(left_kind.clone());
                out.insert(right_kind.clone());
            }
            RelExpr::GroupCountDistinct { kinds, .. } => {
                out.extend(kinds.iter().cloned());
            }
            RelExpr::Filter { input, .. }
            | RelExpr::Project { input, .. }
            | RelExpr::Aggregate { input, .. }
            | RelExpr::Window { input, .. }
            | RelExpr::TransitiveClosure { input, .. }
            | RelExpr::CallExternal { input, .. } => input.collect_scanned_kinds(out),
            RelExpr::Join { left, right, .. } => {
                left.collect_scanned_kinds(out);
                right.collect_scanned_kinds(out);
            }
        }
    }
}

/// The capability profile of a plan: which engines its constructs require.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub engines: BTreeSet<Engine>,
}

impl Capabilities {
    /// The single engine that can run the whole plan in-process, if any — i.e. the
    /// plan needs nothing beyond the compiled Datalog engine. When more than one
    /// engine is required the router must partition the plan.
    pub fn is_single_engine(&self) -> bool {
        self.engines.len() <= 1
    }

    /// Does the plan require a fixpoint (Souffle) engine?
    pub fn needs_souffle(&self) -> bool {
        self.engines.contains(&Engine::Souffle)
    }

    /// Does the plan require DuckDB analytics?
    pub fn needs_duckdb(&self) -> bool {
        self.engines.contains(&Engine::DuckDb)
    }

    /// Does the plan call into the WASM sandbox?
    pub fn needs_wasm(&self) -> bool {
        self.engines.contains(&Engine::Wasm)
    }
}

/// Compute the engine requirements of a plan. The base relational constructs
/// (scan/filter/project/join) run in the compiled Datalog engine; recursion routes
/// to Souffle, aggregation to DuckDB, and external calls to WASM. The requirement of
/// a node is the union of its own engine and its children's.
pub fn analyze(expr: &RelExpr) -> Capabilities {
    let mut engines = BTreeSet::new();
    walk(expr, &mut engines);
    Capabilities { engines }
}

fn walk(expr: &RelExpr, out: &mut BTreeSet<Engine>) {
    match expr {
        RelExpr::Scan { .. } => {
            out.insert(Engine::InProcessDatalog);
        }
        RelExpr::Filter { input, .. } | RelExpr::Project { input, .. } => {
            out.insert(Engine::InProcessDatalog);
            walk(input, out);
        }
        RelExpr::Join { left, right, .. } => {
            out.insert(Engine::InProcessDatalog);
            walk(left, out);
            walk(right, out);
        }
        RelExpr::Aggregate { input, .. } => {
            out.insert(Engine::DuckDb);
            walk(input, out);
        }
        RelExpr::Window { input, .. } => {
            // Implemented by the in-process engine.
            out.insert(Engine::InProcessDatalog);
            walk(input, out);
        }
        RelExpr::TransitiveClosure { input, .. } => {
            out.insert(Engine::Souffle);
            walk(input, out);
        }
        RelExpr::CallExternal { input, .. } => {
            out.insert(Engine::Wasm);
            walk(input, out);
        }
        // The declarative join / group-distinct shapes run on the in-process engine
        // (the physical plan is the reference impl), but the router *prefers* DuckDB
        // for them at scale — same policy as `Aggregate`.
        RelExpr::JoinFilter { .. } | RelExpr::GroupCountDistinct { .. } => {
            out.insert(Engine::DuckDb);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pred(col: &str, op: CmpOp, v: ScalarValue) -> Predicate {
        Predicate {
            column: col.into(),
            op,
            value: v,
        }
    }

    #[test]
    fn base_relational_plan_runs_in_process() {
        let plan = RelExpr::scan("mixin_application_site")
            .filter(pred(
                "operation",
                CmpOp::Eq,
                ScalarValue::Str("redirect".into()),
            ))
            .project(vec!["mod".into(), "target_class".into()]);
        let caps = analyze(&plan);
        assert!(caps.is_single_engine());
        assert!(!caps.needs_souffle() && !caps.needs_duckdb() && !caps.needs_wasm());
        assert_eq!(
            caps.engines.into_iter().collect::<Vec<_>>(),
            vec![Engine::InProcessDatalog]
        );
    }

    #[test]
    fn recursion_requires_souffle() {
        // Deep dependency-conflict reachability (Layer C) ⇒ fixpoint engine.
        let plan = RelExpr::scan("dependency").transitive_closure("mod", "requires");
        let caps = analyze(&plan);
        assert!(caps.needs_souffle());
        assert!(!caps.is_single_engine() || caps.engines.len() == 2); // souffle + base scan
    }

    #[test]
    fn aggregation_requires_duckdb() {
        let plan = RelExpr::scan("hot_method").aggregate(
            vec!["class".into()],
            vec![Aggregate {
                func: AggFunc::Sum,
                column: "percent".into(),
                alias: "total".into(),
            }],
        );
        assert!(analyze(&plan).needs_duckdb());
    }

    #[test]
    fn mixed_plan_requires_multiple_engines_and_must_be_partitioned() {
        // Scan+filter (datalog) → recursion (souffle) → aggregate (duckdb) → wasm.
        let plan = RelExpr::scan("dependency")
            .filter(pred("side", CmpOp::Eq, ScalarValue::Str("server".into())))
            .transitive_closure("mod", "requires")
            .aggregate(vec!["mod".into()], Vec::new())
            .call_external("semver-check");
        let caps = analyze(&plan);
        assert!(!caps.is_single_engine());
        assert!(caps.needs_souffle() && caps.needs_duckdb() && caps.needs_wasm());
        assert_eq!(caps.engines.len(), 4);
    }
}
