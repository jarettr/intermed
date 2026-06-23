//! Ascent (Rust Datalog) backend for the recursive fragment (plan Phase 4.2), behind
//! the `ascent-backend` feature.
//!
//! `ascent` is a **compile-time** Datalog: rules are fixed in the `ascent!` macro, so a
//! single generic "run any RelExpr" backend does not fit it. Instead this uses ascent
//! for what it is actually good at — **fixpoint recursion** — exposing a backend that
//! supports the [`TransitiveClosure`](crate::ir::RelExpr::TransitiveClosure) construct.
//! The non-recursive input (a scan/filter producing `(from, to)` edges) is prepared by
//! the columnar engine; ascent computes the reachability closure with a real
//! semi-naïve Datalog evaluator. (The dynamic, general Datalog backend role is filled
//! by Soufflé via [`to_datalog`](crate::to_datalog).)

use ascent::ascent;
use intermed_facts::Fact;

use crate::backend::QueryBackend;
use crate::convert::facts_to_batches;
use crate::error::ColumnarError;
use crate::executor::{ColumnarStore, execute};
use crate::ir::RelExpr;
use crate::value::{Relation, Row, Value};

ascent! {
    /// Input edges `(from, to)`.
    relation edge(String, String);
    /// Reachability closure.
    relation path(String, String);

    path(x, y) <-- edge(x, y);
    path(x, z) <-- edge(x, y), path(y, z);
}

/// Computes transitive-closure plans on an `ascent` Datalog program.
pub struct AscentClosureBackend;

impl QueryBackend for AscentClosureBackend {
    fn name(&self) -> &str {
        "ascent"
    }

    fn supports(&self, plan: &RelExpr) -> bool {
        matches!(plan, RelExpr::TransitiveClosure { .. })
    }

    fn run(&self, plan: &RelExpr, facts: &[Fact]) -> Result<Relation, ColumnarError> {
        let RelExpr::TransitiveClosure { input, from, to } = plan else {
            return Err(ColumnarError::Schema(
                "ascent backend only runs TransitiveClosure plans".into(),
            ));
        };

        // Prepare the edge relation by running the (non-recursive) input.
        let batches = facts_to_batches(facts, "ascent")?;
        let store = ColumnarStore::from_batches(&batches)?;
        let edges = execute(input, &store)?;

        let edge = edges
            .rows
            .iter()
            .filter_map(|r| {
                let a = r.get(from).map(Value::to_display)?;
                let b = r.get(to).map(Value::to_display)?;
                Some((a, b))
            })
            .collect();
        let mut prog = AscentProgram {
            edge,
            ..Default::default()
        };
        prog.run();

        let mut pairs = prog.path;
        pairs.sort();
        let rows = pairs
            .into_iter()
            .map(|(a, b)| {
                let mut row = Row::new();
                row.insert(from.clone(), Value::Str(a));
                row.insert(to.clone(), Value::Str(b));
                row
            })
            .collect();
        Ok(Relation::new(rows))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_facts::FactStore;
    use std::collections::BTreeSet;

    #[test]
    fn ascent_computes_reachability() {
        let mut s = FactStore::new();
        for (m, dep) in [("a", "b"), ("b", "c"), ("c", "d")] {
            s.fact("deps", "dependency")
                .subject(m)
                .attr("mod", m)
                .attr("requires", dep)
                .emit();
        }
        let plan = RelExpr::scan("dependency").transitive_closure("mod", "requires");
        let rel = AscentClosureBackend.run(&plan, s.all()).unwrap();
        // a reaches b, c, d.
        let from_a: BTreeSet<&str> = rel
            .rows
            .iter()
            .filter(|r| r.get("mod").and_then(Value::as_str) == Some("a"))
            .filter_map(|r| r.get("requires").and_then(Value::as_str))
            .collect();
        assert_eq!(from_a, ["b", "c", "d"].into_iter().collect());
    }

    #[test]
    fn ascent_rejects_non_closure_plans() {
        let plan = RelExpr::scan("dependency");
        assert!(!AscentClosureBackend.supports(&plan));
        assert!(AscentClosureBackend.run(&plan, &[]).is_err());
    }
}
