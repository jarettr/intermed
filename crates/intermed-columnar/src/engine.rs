//! The unified query-engine facade.
//!
//! The crate's pieces — Arrow projection, catalog statistics, the rule-based
//! optimizer, the physical planner, the streaming executor, `EXPLAIN`, and external
//! functions — compose into one obvious entry point so callers don't have to wire them
//! by hand. The whole model in one object:
//!
//! ```
//! use intermed_columnar::{QueryEngine, QuerySpec};
//! # use intermed_facts::FactStore;
//! # let mut s = FactStore::new();
//! # s.fact("c", "mod").subject("sodium").attr("loader", "fabric").emit();
//! let engine = QueryEngine::from_facts(s.all()).unwrap();
//! let spec = QuerySpec::from_json(r#"{"scan":"mod","project":["subject"]}"#).unwrap();
//! let rows = engine.run_query(&spec).unwrap();          // compile → optimize → execute
//! let plan_text = engine.explain(&spec.compile());      // inspect the chosen plan
//! # let _ = (rows, plan_text);
//! ```
//!
//! `from_facts` builds the columnar store + statistics once; every `run`/`explain`
//! reuses them. External (WASM) functions are registered on the engine and become
//! available to any `CallExternal` in a plan.

use intermed_facts::Fact;

use crate::error::ColumnarError;
use crate::executor::{ColumnarStore, execute_strategy_with_stats, execute_with_stats};
use crate::external::{ExternalFunction, FunctionRegistry};
use crate::frontend::QuerySpec;
use crate::ir::RelExpr;
use crate::optimizer::optimize;
use crate::value::Relation;
use crate::{cost::Statistics, explain as explain_mod};

/// A ready-to-query view over a fact set: the store, its statistics, and the registered
/// external functions, with the optimizer/executor/`EXPLAIN` exposed as methods.
pub struct QueryEngine {
    store: ColumnarStore,
    stats: Statistics,
    registry: FunctionRegistry,
}

impl QueryEngine {
    /// Build the columnar store from `facts` and compute catalog statistics once.
    ///
    /// Uses the **direct** `ColumnarStore::from_facts` (plan Phase 1): the in-process
    /// engine reads facts straight into the queryable view, skipping the
    /// `Fact → Arrow RecordBatch → rows` round-trip that only the DuckDB / DataFusion
    /// backends actually need. Infallible, so the `Result` is kept solely for API
    /// stability with the previous Arrow-backed signature.
    pub fn from_facts(facts: &[Fact]) -> Result<Self, ColumnarError> {
        let store = ColumnarStore::from_facts(facts);
        let stats = store.statistics();
        Ok(QueryEngine {
            store,
            stats,
            registry: FunctionRegistry::new(),
        })
    }

    /// Build a store containing **only** the kinds in `kinds` (plan Phase 2:
    /// demand-driven build). A caller that knows every kind its plans will scan
    /// (`RelExpr::collect_scanned_kinds`) passes that set, so the engine never
    /// materializes high-volume kinds nothing queries — the dominant build-cost win.
    /// Plans that scan a kind outside the set see it as empty, so the set **must** be
    /// the complete scanned-kind set for the plans that will run.
    pub fn from_facts_for_kinds(
        facts: &[Fact],
        kinds: &std::collections::BTreeSet<String>,
    ) -> Result<Self, ColumnarError> {
        let store = ColumnarStore::from_facts_for_kinds(facts, Some(kinds));
        let stats = store.statistics();
        Ok(QueryEngine {
            store,
            stats,
            registry: FunctionRegistry::new(),
        })
    }

    /// Register an external function, available to `CallExternal` in subsequent runs.
    pub fn register_function(&mut self, function: Box<dyn ExternalFunction>) -> &mut Self {
        self.registry.register(function);
        self
    }

    /// The catalog statistics the optimizer uses (per-kind row counts + column sets).
    pub fn statistics(&self) -> &Statistics {
        &self.stats
    }

    /// The optimized logical plan for `plan` under this engine's statistics.
    pub fn optimize(&self, plan: &RelExpr) -> RelExpr {
        optimize(plan, &self.stats)
    }

    /// Optimize and execute a logical plan, returning the materialized result.
    pub fn run(&self, plan: &RelExpr) -> Result<Relation, ColumnarError> {
        execute_with_stats(plan, &self.store, &self.stats, &self.registry)
    }

    /// Optimize and execute under an explicit [`ExecutionStrategy`] (debugging /
    /// benchmarking / forcing a path). The result is identical to [`run`](Self::run);
    /// only the execution path differs.
    pub fn run_with_strategy(
        &self,
        plan: &RelExpr,
        strategy: crate::strategy::ExecutionStrategy,
    ) -> Result<Relation, ColumnarError> {
        execute_strategy_with_stats(plan, &self.store, &self.stats, &self.registry, strategy)
    }

    /// Compile a declarative [`QuerySpec`], then optimize and execute it.
    pub fn run_query(&self, spec: &QuerySpec) -> Result<Relation, ColumnarError> {
        self.run(&spec.compile())
    }

    /// A static `EXPLAIN` (logical → optimized → physical plan + engines + estimate).
    pub fn explain(&self, plan: &RelExpr) -> String {
        explain_mod::explain(plan, &self.stats)
    }

    /// `EXPLAIN ANALYZE`: run the plan and report actual per-operator rows and time.
    pub fn explain_analyze(&self, plan: &RelExpr) -> Result<String, ColumnarError> {
        explain_mod::explain_analyze(plan, &self.store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external::ExternalFunction;
    use crate::value::{Relation, Value};
    use intermed_facts::FactStore;

    fn engine() -> QueryEngine {
        let mut s = FactStore::new();
        for (m, loader) in [
            ("sodium", "fabric"),
            ("create", "forge"),
            ("iris", "fabric"),
        ] {
            s.fact("meta", "mod")
                .subject(m)
                .attr("loader", loader)
                .emit();
        }
        QueryEngine::from_facts(s.all()).unwrap()
    }

    #[test]
    fn run_query_compiles_optimizes_and_executes() {
        let eng = engine();
        let spec = QuerySpec::from_json(
            r#"{"scan":"mod","filters":[{"column":"loader","op":"eq","value":"fabric"}],"project":["subject"]}"#,
        )
        .unwrap();
        let rows = eng.run_query(&spec).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn explain_and_analyze_are_reachable() {
        let eng = engine();
        let plan = QuerySpec::from_json(r#"{"scan":"mod","project":["subject"]}"#)
            .unwrap()
            .compile();
        assert!(eng.explain(&plan).contains("Physical plan"));
        assert!(eng.explain_analyze(&plan).unwrap().contains("actual rows="));
    }

    #[test]
    fn registered_function_is_used() {
        struct Drop;
        impl ExternalFunction for Drop {
            fn name(&self) -> &str {
                "drop-all"
            }
            fn call(&self, _: &Relation) -> Result<Relation, ColumnarError> {
                Ok(Relation::new(Vec::new()))
            }
        }
        let mut eng = engine();
        eng.register_function(Box::new(Drop));
        let plan = RelExpr::scan("mod").call_external("drop-all");
        assert_eq!(eng.run(&plan).unwrap().len(), 0);
        // A plain run without the external call returns all rows.
        assert_eq!(eng.run(&RelExpr::scan("mod")).unwrap().len(), 3);
        let _ = Value::Null;
    }
}
