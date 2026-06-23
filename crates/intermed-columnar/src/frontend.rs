//! Declarative query frontend (plan Phase 2).
//!
//! Parses a JSON/YAML-friendly [`QuerySpec`] into the typed relational IR
//! ([`RelExpr`]). This is the compiler frontend: a rule pack ships declarative query
//! specs, the frontend lowers them to one IR, and the capability analyzer + router
//! decide how to execute. The pipeline order is fixed and predictable:
//!
//! `scan → [join] → filters → [transitive-closure] → [aggregate + having] →
//!  [call-external] → [project]`.

use serde::{Deserialize, Serialize};

use crate::ir::{
    AggFunc, Aggregate, CmpOp, Predicate, RelExpr, ScalarValue, WindowFn, WindowFunction,
};

/// A comparison in a declarative spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterSpec {
    pub column: String,
    pub op: CmpOp,
    pub value: ScalarValue,
}

impl FilterSpec {
    fn to_predicate(&self) -> Predicate {
        Predicate {
            column: self.column.clone(),
            op: self.op,
            value: self.value.clone(),
        }
    }
}

/// A join arm: scan another kind and equi-join on column pairs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JoinSpec {
    pub scan: String,
    /// `[[left_col, right_col], …]`.
    pub on: Vec<(String, String)>,
}

/// One aggregate to compute.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AggSpec {
    pub func: AggFunc,
    #[serde(default)]
    pub column: String,
    pub alias: String,
}

/// A transitive-closure (recursive reachability) spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransitiveClosureSpec {
    pub from: String,
    pub to: String,
}

/// One window function to compute (ROW_NUMBER/RANK/… or a whole-partition aggregate).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowFuncSpec {
    pub func: WindowFn,
    #[serde(default)]
    pub column: String,
    pub alias: String,
}

/// A window step: per-row functions over partitions, ordered within each partition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowSpec {
    #[serde(default)]
    pub partition_by: Vec<String>,
    #[serde(default)]
    pub order_by: Vec<String>,
    pub functions: Vec<WindowFuncSpec>,
}

/// A named common table expression (CTE): a query referenced by name from a `scan`
/// or `join.scan` of this spec (or a later CTE). CTEs compile by inlining.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamedQuery {
    pub name: String,
    pub query: QuerySpec,
}

/// A declarative query that lowers to a relational IR plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuerySpec {
    /// Named CTEs, compiled in order; a later one (or this spec) may reference an
    /// earlier name in its `scan`/`join.scan`.
    #[serde(default)]
    pub with: Vec<NamedQuery>,
    /// Base relation: a fact kind, or the name of a CTE in `with`.
    pub scan: String,
    #[serde(default)]
    pub join: Option<JoinSpec>,
    #[serde(default)]
    pub filters: Vec<FilterSpec>,
    #[serde(default)]
    pub transitive_closure: Option<TransitiveClosureSpec>,
    #[serde(default)]
    pub group_by: Vec<String>,
    #[serde(default)]
    pub aggregates: Vec<AggSpec>,
    /// Filters applied *after* aggregation (HAVING).
    #[serde(default)]
    pub having: Vec<FilterSpec>,
    /// Window functions, applied after aggregation/having.
    #[serde(default)]
    pub window: Option<WindowSpec>,
    #[serde(default)]
    pub call_external: Option<String>,
    #[serde(default)]
    pub project: Vec<String>,
}

impl QuerySpec {
    /// Lower the declarative spec into the typed relational IR. CTEs in `with` are
    /// compiled first (in order) and inlined where referenced by name.
    pub fn compile(&self) -> RelExpr {
        let mut ctes: Vec<(String, RelExpr)> = Vec::new();
        for nq in &self.with {
            let compiled = nq.query.compile_with(&ctes);
            ctes.push((nq.name.clone(), compiled));
        }
        self.compile_with(&ctes)
    }

    /// Resolve a relation name to a CTE plan (inlined) or a base `Scan`.
    fn resolve(name: &str, ctes: &[(String, RelExpr)]) -> RelExpr {
        match ctes.iter().find(|(n, _)| n == name) {
            Some((_, expr)) => expr.clone(),
            None => RelExpr::scan(name),
        }
    }

    fn compile_with(&self, ctes: &[(String, RelExpr)]) -> RelExpr {
        let mut expr = Self::resolve(&self.scan, ctes);

        if let Some(j) = &self.join {
            expr = expr.join(Self::resolve(&j.scan, ctes), j.on.clone());
        }
        for f in &self.filters {
            expr = expr.filter(f.to_predicate());
        }
        if let Some(tc) = &self.transitive_closure {
            expr = expr.transitive_closure(&tc.from, &tc.to);
        }
        if !self.group_by.is_empty() || !self.aggregates.is_empty() {
            let aggs = self
                .aggregates
                .iter()
                .map(|a| Aggregate {
                    func: a.func,
                    column: a.column.clone(),
                    alias: a.alias.clone(),
                })
                .collect();
            expr = expr.aggregate(self.group_by.clone(), aggs);
        }
        for h in &self.having {
            expr = expr.filter(h.to_predicate());
        }
        if let Some(w) = &self.window {
            let functions = w
                .functions
                .iter()
                .map(|f| WindowFunction {
                    func: f.func,
                    column: f.column.clone(),
                    alias: f.alias.clone(),
                })
                .collect();
            expr = expr.window(w.partition_by.clone(), w.order_by.clone(), functions);
        }
        if let Some(module) = &self.call_external {
            expr = expr.call_external(module);
        }
        if !self.project.is_empty() {
            expr = expr.project(self.project.clone());
        }
        expr
    }

    /// Parse a spec from JSON.
    pub fn from_json(json: &str) -> Result<QuerySpec, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::analyze;

    #[test]
    fn lowers_scan_filter_project() {
        let spec = QuerySpec {
            with: Vec::new(),
            scan: "mixin_application_site".into(),
            join: None,
            filters: vec![FilterSpec {
                column: "operation".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Str("redirect".into()),
            }],
            transitive_closure: None,
            group_by: Vec::new(),
            aggregates: Vec::new(),
            having: Vec::new(),
            window: None,
            call_external: None,
            project: vec!["mod".into()],
        };
        let plan = spec.compile();
        // scan → filter → project.
        assert!(matches!(plan, RelExpr::Project { .. }));
        assert!(analyze(&plan).is_single_engine());
    }

    #[test]
    fn cte_is_inlined_when_referenced() {
        // A CTE `redirects` filters the scan; the outer query scans the CTE by name.
        let json = r#"{
            "with": [{
                "name": "redirects",
                "query": {
                    "scan": "mixin_application_site",
                    "filters": [{"column": "operation", "op": "eq", "value": "redirect"}]
                }
            }],
            "scan": "redirects",
            "project": ["subject"]
        }"#;
        let spec = QuerySpec::from_json(json).unwrap();
        let plan = spec.compile();
        // The CTE body (Filter over Scan) is inlined beneath the outer Project.
        match &plan {
            RelExpr::Project { input, .. } => assert!(matches!(&**input, RelExpr::Filter { .. })),
            other => panic!("expected Project over inlined CTE, got {other:?}"),
        }
    }

    #[test]
    fn window_spec_lowers_to_window_node() {
        let json = r#"{
            "scan": "hot_method",
            "window": {
                "partition_by": ["class"],
                "order_by": ["percent"],
                "functions": [{"func": "row-number", "alias": "rn"}]
            }
        }"#;
        let spec = QuerySpec::from_json(json).unwrap();
        assert!(matches!(spec.compile(), RelExpr::Window { .. }));
    }

    #[test]
    fn parses_json_with_typed_scalars() {
        let json = r#"{
            "scan": "hot_method",
            "filters": [{"column": "percent", "op": "ge", "value": 5.0}],
            "group_by": ["class"],
            "aggregates": [{"func": "sum", "column": "percent", "alias": "total"}],
            "having": [{"column": "total", "op": "gt", "value": 50}]
        }"#;
        let spec = QuerySpec::from_json(json).unwrap();
        assert_eq!(spec.filters[0].value, ScalarValue::Float(5.0));
        assert_eq!(spec.having[0].value, ScalarValue::Int(50));
        // Aggregation ⇒ the analyzer routes it to DuckDB.
        assert!(analyze(&spec.compile()).needs_duckdb());
    }

    #[test]
    fn deep_dependency_query_routes_to_souffle() {
        let json = r#"{
            "scan": "dependency",
            "transitive_closure": {"from": "mod", "to": "requires"}
        }"#;
        let spec = QuerySpec::from_json(json).unwrap();
        assert!(analyze(&spec.compile()).needs_souffle());
    }
}
