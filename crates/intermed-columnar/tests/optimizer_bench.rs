//! Measures the optimizer's real effect (plan Phase 2).
//!
//! A frontend emits the natural plan `Filter(Join(left, right), tier = hot)` — the
//! selective filter sits *above* the join, so the unoptimized engine joins both full
//! relations and only then discards 98% of the rows. The optimizer pushes the filter
//! into the left input, so the join sees a fraction of the rows. This test runs both
//! plans on identical data, asserts they agree, and prints the speedup.
//!
//! ```text
//! cargo test -p intermed-columnar --test optimizer_bench --release -- --ignored --nocapture
//! ```

use std::time::Instant;

use intermed_columnar::{
    ColumnarStore, RelExpr, Statistics, execute, execute_physical, facts_to_batches, optimize,
    plan_physical,
};
use intermed_facts::FactStore;

#[test]
#[ignore = "perf benchmark; run with --ignored --release"]
fn predicate_pushdown_speedup() {
    let n: usize = 50_000;
    let keys: usize = 5_000; // fan-out ~10 per key on each side
    let hot_every: usize = 50; // ~2% of left rows are "hot"

    let mut s = FactStore::new();
    for i in 0..n {
        let key = format!("k{}", i % keys);
        let tier = if i % hot_every == 0 { "hot" } else { "cold" };
        s.fact("bench", "left_rel")
            .subject(format!("l{i}"))
            .attr("key", key.clone())
            .attr("tier", tier)
            .emit();
        s.fact("bench", "right_rel")
            .subject(format!("r{i}"))
            .attr("key", key)
            .emit();
    }
    let batches = facts_to_batches(s.all(), "r").unwrap();
    let store = ColumnarStore::from_batches(&batches).unwrap();
    let stats = store.statistics();

    // The natural (unoptimized) plan: filter above the join.
    let raw = RelExpr::scan("left_rel")
        .join(
            RelExpr::scan("right_rel"),
            vec![("key".into(), "key".into())],
        )
        .filter(intermed_columnar::ir::Predicate {
            column: "tier".into(),
            op: intermed_columnar::ir::CmpOp::Eq,
            value: intermed_columnar::ir::ScalarValue::Str("hot".into()),
        });

    // Unoptimized: lower the raw plan directly (no optimizer, no stats).
    let phys_raw = plan_physical(&raw, &Statistics::empty());
    let t0 = Instant::now();
    let unopt = execute_physical(&phys_raw, &store).unwrap();
    let unopt_time = t0.elapsed();

    // Optimized: `execute` runs the optimizer (predicate pushdown) + cost-based plan.
    let t1 = Instant::now();
    let opt = execute(&raw, &store).unwrap();
    let opt_time = t1.elapsed();

    assert_eq!(
        unopt.len(),
        opt.len(),
        "optimizer changed the result cardinality"
    );

    // Show that the filter really moved below the join.
    let optimized_plan = optimize(&raw, &stats);
    let pushed = matches!(optimized_plan, RelExpr::Join { .. });

    let ratio = unopt_time.as_secs_f64() / opt_time.as_secs_f64();
    println!("--- predicate pushdown ---");
    println!("rows: {} left × {} right, {} result rows", n, n, opt.len());
    println!("filter pushed below join: {pushed}");
    println!("unoptimized: {unopt_time:?}");
    println!("optimized:   {opt_time:?}");
    println!("speedup:     {ratio:.1}x");

    assert!(pushed, "filter should have been pushed below the join");
}
