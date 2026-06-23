//! Phase 0 measurement harness: breaks the columnar cost into **store-build** vs
//! **per-rule eval**, and times the direct (`from_facts`, Phase 1) store build against
//! the Arrow round-trip (`facts_to_batches` → `from_batches`).
//!
//! The whole engine plan rests on one claim: store-build dominates the columnar
//! overhead (the interpreter pays none of it), so killing the Arrow round-trip and
//! materializing less is what lets the engine beat the interpreter. This bench is the
//! evidence.
//!
//! ```text
//! cargo test -p intermed-columnar --test engine_breakdown --release -- --ignored --nocapture
//! # against a real dump (doctor --dump-facts):
//! INTERMED_FACT_DUMP=/tmp/facts.json cargo test -p intermed-columnar --test engine_breakdown --release -- --ignored --nocapture
//! ```

use std::time::Instant;

use intermed_columnar::ir::{CmpOp, Predicate, ScalarValue};
use intermed_columnar::{
    ColumnarStore, ExecutionStrategy, RelExpr, execute_strategy, facts_to_batches,
};
use intermed_facts::{Fact, FactStore};

fn synthetic_facts(n: usize) -> FactStore {
    let mut s = FactStore::new();
    for i in 0..n {
        let op = ["inject", "redirect", "overwrite", "modify"][i % 4];
        s.fact("bench", "mixin_application_site")
            .subject(format!("mod{}", i % 200))
            .attr("operation", op)
            .attr("target_class", format!("net/minecraft/Class{}", i % 1000))
            .attr("priority", (i % 5) as i64)
            .emit();
        // A second, high-volume kind no rule scans — exercises wasted materialization.
        s.fact("bench", "resource_reference")
            .subject(format!("data/mod{}/recipe/{i}.json", i % 200))
            .attr("namespace", format!("ns{}", i % 50))
            .attr("relation", "uses_item")
            .emit();
    }
    s
}

fn load_facts() -> FactStore {
    match std::env::var_os("INTERMED_FACT_DUMP") {
        Some(p) => {
            let json = std::fs::read_to_string(p).expect("read dump");
            let facts: Vec<Fact> = serde_json::from_str(&json)
                .or_else(|_| {
                    serde_json::from_str::<serde_json::Value>(&json)
                        .and_then(|v| serde_json::from_value(v["facts"].clone()))
                })
                .expect("parse dump");
            let mut s = FactStore::new();
            for f in &facts {
                let mut b = s
                    .fact(&f.extractor, &f.kind)
                    .subject(f.subject.clone())
                    .confidence(f.confidence)
                    .source(f.source.clone());
                for (k, v) in &f.attributes {
                    b = b.attr(k, v.clone());
                }
                b.emit();
            }
            s
        }
        None => synthetic_facts(50_000),
    }
}

fn median_ms(mut samples: Vec<f64>) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

#[test]
#[ignore = "measurement harness; run with --ignored --release"]
fn store_build_dominates_and_direct_path_wins() {
    let store = load_facts();
    let facts = store.all();
    let reps = 9;

    // Old path: Fact → Arrow → rows.
    let arrow_ms = median_ms(
        (0..reps)
            .map(|_| {
                let t = Instant::now();
                let batches = facts_to_batches(facts, "bench").unwrap();
                let _ = ColumnarStore::from_batches(&batches).unwrap();
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect(),
    );

    // New path (Phase 1): Fact → rows, directly.
    let direct_ms = median_ms(
        (0..reps)
            .map(|_| {
                let t = Instant::now();
                let _ = ColumnarStore::from_facts(facts);
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect(),
    );

    // Per-rule eval cost (FastRow) on the built store, for the build-vs-eval ratio.
    let built = ColumnarStore::from_facts(facts);
    let plan = RelExpr::scan("mixin_application_site")
        .filter(Predicate {
            column: "operation".into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str("overwrite".into()),
        })
        .project(vec!["fact_id".into()]);
    let eval_ms = median_ms(
        (0..reps)
            .map(|_| {
                let t = Instant::now();
                let _ = execute_strategy(&plan, &built, ExecutionStrategy::FastRow).unwrap();
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect(),
    );

    println!(
        "facts={} | build: Arrow {arrow_ms:.2}ms → direct {direct_ms:.2}ms ({:.2}× faster) | one-rule eval {eval_ms:.3}ms (build is {:.0}× a single rule)",
        facts.len(),
        arrow_ms / direct_ms,
        direct_ms / eval_ms.max(0.0001),
    );
    assert!(
        direct_ms <= arrow_ms,
        "direct build ({direct_ms:.2}ms) should be ≤ Arrow round-trip ({arrow_ms:.2}ms)"
    );
}
