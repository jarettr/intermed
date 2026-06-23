//! Measures the **FastRow** strategy against the **Vectorized** engine on the linear
//! `Scan → Filter* → Project` shape that dominates real rule packs (plan Phase 0/2).
//!
//! Both strategies run the same plan on identical data; the test asserts they return
//! identical results and prints the speedup. FastRow reads the batch directly by
//! position and builds only the projected output rows, so it should beat the
//! general streaming engine on this shape (the plan's core success criterion).
//!
//! ```text
//! cargo test -p intermed-columnar --test strategy_bench --release -- --ignored --nocapture
//! ```

use std::time::Instant;

use intermed_columnar::ir::{CmpOp, Predicate, ScalarValue};
use intermed_columnar::{
    ColumnarStore, ExecutionStrategy, RelExpr, execute_strategy, facts_to_batches,
};
use intermed_facts::FactStore;

fn eq(col: &str, v: &str) -> Predicate {
    Predicate {
        column: col.into(),
        op: CmpOp::Eq,
        value: ScalarValue::Str(v.into()),
    }
}

#[test]
#[ignore = "perf benchmark; run with --ignored --release"]
fn fast_row_beats_vectorized_on_linear_pipeline() {
    let n: usize = 300_000;
    let mut s = FactStore::new();
    for i in 0..n {
        let op = match i % 4 {
            0 => "inject",
            1 => "redirect",
            2 => "overwrite",
            _ => "modify",
        };
        s.fact("bench", "mixin_application_site")
            .subject(format!("mod{}", i % 200))
            .attr("operation", op)
            .attr("target_class", format!("net/minecraft/Class{}", i % 1000))
            .attr("priority", (i % 5) as i64)
            .emit();
    }
    let batches = facts_to_batches(s.all(), "bench").unwrap();
    let store = ColumnarStore::from_batches(&batches).unwrap();

    // The canonical FactFinding shape: scan a kind, keep an equality match, project ids.
    let plan = RelExpr::scan("mixin_application_site")
        .filter(eq("operation", "overwrite"))
        .project(vec!["fact_id".into(), "subject".into()]);

    // Warm both paths once (build any lazy state, fair timing).
    let warm_v = execute_strategy(&plan, &store, ExecutionStrategy::Vectorized).unwrap();
    let warm_f = execute_strategy(&plan, &store, ExecutionStrategy::FastRow).unwrap();
    assert_eq!(warm_v.rows, warm_f.rows, "FastRow must equal Vectorized");

    let reps = 20;
    let t0 = Instant::now();
    for _ in 0..reps {
        let _ = execute_strategy(&plan, &store, ExecutionStrategy::Vectorized).unwrap();
    }
    let vec_ms = t0.elapsed().as_secs_f64() * 1000.0 / reps as f64;

    let t1 = Instant::now();
    for _ in 0..reps {
        let _ = execute_strategy(&plan, &store, ExecutionStrategy::FastRow).unwrap();
    }
    let fast_ms = t1.elapsed().as_secs_f64() * 1000.0 / reps as f64;

    println!(
        "linear pipeline over {n} rows ({} matched): Vectorized {vec_ms:.3}ms, FastRow {fast_ms:.3}ms, speedup {:.2}×",
        warm_v.rows.len(),
        vec_ms / fast_ms,
    );
    // FastRow should not be materially slower on its target shape. (Equality + the
    // printed speedup is the real signal; the bound guards against a regression.)
    assert!(
        fast_ms <= vec_ms * 1.10,
        "FastRow ({fast_ms:.3}ms) should be ≤ Vectorized ({vec_ms:.3}ms) on a linear pipeline"
    );
}
