//! `EXPLAIN` and `EXPLAIN ANALYZE` for the query engine (plan Phase 3.3).
//!
//! [`explain`] is static: it shows the logical plan, the optimized logical plan, the
//! chosen physical plan, and the engines the plan's constructs require (so a reader
//! can see *why* a rule routes where it does). [`explain_analyze`] additionally
//! *runs* the plan and annotates each physical operator with its actual output
//! cardinality and wall-clock time — the tool for trusting and debugging the engine.

use std::time::Instant;

use crate::cost::{Statistics, cardinality};
use crate::error::ColumnarError;
use crate::executor::{ColumnarStore, count_physical};
use crate::ir::{RelExpr, analyze};
use crate::optimizer::optimize;
use crate::physical::{self, PhysicalPlan};

/// A static `EXPLAIN`: logical plan → optimized logical plan → physical plan →
/// required engines + estimated output cardinality, given catalog `stats`.
pub fn explain(expr: &RelExpr, stats: &Statistics) -> String {
    let optimized = optimize(expr, stats);
    let phys = physical::plan(&optimized, stats);
    let caps = analyze(&optimized);
    let engines = caps
        .engines
        .iter()
        .map(|e| e.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = String::new();
    out.push_str("== Logical plan ==\n");
    fmt_logical(expr, 0, &mut out);
    out.push_str("\n== Optimized logical plan ==\n");
    fmt_logical(&optimized, 0, &mut out);
    out.push_str("\n== Physical plan ==\n");
    out.push_str(&physical::explain(&phys));
    out.push_str(&format!(
        "\n== Strategy ==\n{}\n",
        crate::strategy::select_strategy(&phys).as_str()
    ));
    out.push_str(&format!("== Engines ==\n{engines}\n"));
    out.push_str(&format!(
        "== Estimated rows ==\n{:.0}\n",
        cardinality(&optimized, stats)
    ));
    out
}

/// An `EXPLAIN ANALYZE`: runs the optimized physical plan and annotates every operator
/// with its **actual** output rows and **actual** (inclusive of its subtree) time.
pub fn explain_analyze(expr: &RelExpr, store: &ColumnarStore) -> Result<String, ColumnarError> {
    let stats = store.statistics();
    let optimized = optimize(expr, &stats);
    let phys = physical::plan(&optimized, &stats);

    let mut out = String::from("== EXPLAIN ANALYZE (physical) ==\n");
    out.push_str(&format!(
        "strategy: {}\n",
        crate::strategy::select_strategy(&phys).as_str()
    ));
    analyze_node(&phys, store, 0, &mut out)?;
    Ok(out)
}

fn analyze_node(
    plan: &PhysicalPlan,
    store: &ColumnarStore,
    depth: usize,
    out: &mut String,
) -> Result<(), ColumnarError> {
    let start = Instant::now();
    let rows = count_physical(plan, store)?;
    let millis = start.elapsed().as_secs_f64() * 1000.0;
    for _ in 0..depth {
        out.push_str("  ");
    }
    out.push_str(&format!(
        "{} (actual rows={rows} time={millis:.3}ms)\n",
        plan.describe()
    ));
    for child in plan.children() {
        analyze_node(child, store, depth + 1, out)?;
    }
    Ok(())
}

fn fmt_logical(expr: &RelExpr, depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("  ");
    }
    let (label, children): (String, Vec<&RelExpr>) = match expr {
        RelExpr::Scan { kind } => (format!("Scan {kind}"), vec![]),
        RelExpr::Filter { input, predicate } => (
            format!(
                "Filter {} {:?} {:?}",
                predicate.column, predicate.op, predicate.value
            ),
            vec![input.as_ref()],
        ),
        RelExpr::Project { input, columns } => (
            format!("Project [{}]", columns.join(", ")),
            vec![input.as_ref()],
        ),
        RelExpr::Join { left, right, on } => {
            let keys = on
                .iter()
                .map(|(l, r)| format!("{l}={r}"))
                .collect::<Vec<_>>()
                .join(", ");
            (
                format!("Join on [{keys}]"),
                vec![left.as_ref(), right.as_ref()],
            )
        }
        RelExpr::Aggregate {
            input,
            group_by,
            aggregates,
        } => (
            format!(
                "Aggregate group=[{}] aggs=[{}]",
                group_by.join(", "),
                aggregates
                    .iter()
                    .map(|a| a.alias.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            vec![input.as_ref()],
        ),
        RelExpr::Window {
            input,
            partition_by,
            order_by,
            functions,
        } => (
            format!(
                "Window partition=[{}] order=[{}] fns=[{}]",
                partition_by.join(", "),
                order_by.join(", "),
                functions
                    .iter()
                    .map(|f| f.alias.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            vec![input.as_ref()],
        ),
        RelExpr::TransitiveClosure { input, from, to } => (
            format!("TransitiveClosure {from}->{to}"),
            vec![input.as_ref()],
        ),
        RelExpr::CallExternal { input, module } => {
            (format!("CallExternal {module}"), vec![input.as_ref()])
        }
        RelExpr::JoinFilter {
            left_kind,
            right_kind,
            ..
        } => (format!("JoinFilter {left_kind} × {right_kind}"), vec![]),
        RelExpr::GroupCountDistinct {
            kinds,
            distinct_attr,
            min_count,
            ..
        } => (
            format!(
                "GroupCountDistinct kinds=[{}] distinct={distinct_attr} >= {min_count}",
                kinds.join(", ")
            ),
            vec![],
        ),
    };
    out.push_str(&label);
    out.push('\n');
    for c in children {
        fmt_logical(c, depth + 1, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::facts_to_batches;
    use crate::ir::{CmpOp, Predicate, ScalarValue};
    use intermed_facts::FactStore;

    fn store_and_stats() -> (ColumnarStore, Statistics) {
        let mut s = FactStore::new();
        for i in 0..50 {
            s.fact("c", "mixin_application_site")
                .subject(format!("m{i}"))
                .attr("operation", if i % 5 == 0 { "redirect" } else { "inject" })
                .attr("target_class", "net/minecraft/Foo")
                .emit();
        }
        let batches = facts_to_batches(s.all(), "r").unwrap();
        let store = ColumnarStore::from_batches(&batches).unwrap();
        let stats = store.statistics();
        (store, stats)
    }

    fn redirect_plan() -> RelExpr {
        RelExpr::scan("mixin_application_site")
            .filter(Predicate {
                column: "operation".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Str("redirect".into()),
            })
            .project(vec!["subject".into()])
    }

    #[test]
    fn explain_shows_all_sections() {
        let (_, stats) = store_and_stats();
        let text = explain(&redirect_plan(), &stats);
        for section in [
            "Logical plan",
            "Optimized logical plan",
            "Physical plan",
            "Engines",
            "Estimated rows",
        ] {
            assert!(
                text.contains(section),
                "missing section `{section}` in:\n{text}"
            );
        }
        // The optimizer prunes the scan to the referenced columns (projection pushdown).
        assert!(text.contains("Project"));
    }

    #[test]
    fn explain_analyze_reports_actual_cardinalities() {
        let (store, _) = store_and_stats();
        let text = explain_analyze(&redirect_plan(), &store).unwrap();
        assert!(text.contains("actual rows="));
        assert!(text.contains("time="));
        // 10 of 50 facts are redirects.
        assert!(
            text.contains("actual rows=10"),
            "expected 10 redirect rows in:\n{text}"
        );
    }

    #[test]
    fn explain_includes_stats_when_present() {
        // With statistics the cost model produces a non-trivial estimate.
        let (_, stats) = store_and_stats();
        let cardinality_unstated = explain(&redirect_plan(), &Statistics::empty());
        assert!(cardinality_unstated.contains("Estimated rows"));
        let stated = explain(&redirect_plan(), &stats);
        assert!(stated.contains("Estimated rows"));
    }
}
