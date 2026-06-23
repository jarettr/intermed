//! Performance smoke test for the hash join (plan Phase 1.2).
//!
//! The old executor used a nested-loop join: O(n·m). A self-join of N rows on a
//! low-cardinality key is therefore ~N² comparisons — pathological at scale. The
//! hash join is ~O(n+m) on the build/probe sides. This test builds a join that would
//! be tens of millions of comparisons under nested-loop and asserts it both produces
//! the correct cardinality and finishes well under a generous bound.
//!
//! Run explicitly (it is `#[ignore]`d so it does not slow the normal suite):
//!
//! ```text
//! cargo test -p intermed-columnar --test join_bench --release -- --ignored --nocapture
//! ```

use std::time::Instant;

use intermed_columnar::{ColumnarStore, RelExpr, execute, facts_to_batches};
use intermed_facts::FactStore;

#[test]
#[ignore = "perf benchmark; run with --ignored --release"]
fn hash_join_scales_to_a_large_equi_join() {
    // N rows in each of two relations, sharing `groups` distinct join keys. The join
    // produces ~N²/groups rows; with groups close to N the result is modest but the
    // *probe* still has to find each key among N build rows — under nested-loop that
    // is N² = 2.5 billion comparisons, the case it handles worst. The hash join is
    // O(n+m), so this isolates the join algorithm from row materialization (1.3).
    let n: usize = 50_000;
    let groups: usize = 50_000;

    let mut s = FactStore::new();
    for i in 0..n {
        let key = format!("k{}", i % groups);
        s.fact("bench", "left_rel")
            .subject(format!("l{i}"))
            .attr("key", key.clone())
            .emit();
        s.fact("bench", "right_rel")
            .subject(format!("r{i}"))
            .attr("key", key)
            .emit();
    }
    let batches = facts_to_batches(s.all(), "r").unwrap();
    let store = ColumnarStore::from_batches(&batches).unwrap();

    let plan = RelExpr::scan("left_rel").join(
        RelExpr::scan("right_rel"),
        vec![("key".into(), "key".into())],
    );

    let start = Instant::now();
    let result = execute(&plan, &store).unwrap();
    let elapsed = start.elapsed();

    // Each of `groups` keys has N/groups rows on each side ⇒ (N/groups)² matches.
    let per_group = n / groups;
    let expected = groups * per_group * per_group;
    assert_eq!(result.len(), expected, "join cardinality");

    println!(
        "hash join: {n} x {n} rows, {groups} keys -> {} result rows in {:?} ({:.1} Mrows/s)",
        result.len(),
        elapsed,
        result.len() as f64 / elapsed.as_secs_f64() / 1e6,
    );

    // Nested-loop here would be N² = 2.5B comparisons; the hash join must be far
    // faster. A very loose ceiling that still fails on an accidental O(n²) regression.
    assert!(
        elapsed.as_secs() < 10,
        "hash join took {elapsed:?}, suspiciously slow"
    );
}

/// Output-heavy fan-out join — 20k × 20k over 200 keys produces 2M merged rows. This
/// measures *end-to-end* time including reconstructing the public `Row = BTreeMap`
/// `Relation` for every output row. The internal join runs on positional tuples
/// (1.3), but a query returning millions of wide rows is bounded by that final
/// `BTreeMap` materialization (inherent to the stable public API). Realistic rules
/// return small result sets (filter/aggregate), where the per-stage tuple model — no
/// `BTreeMap` allocation at intermediate stages — is the win.
#[test]
#[ignore = "perf benchmark; run with --ignored --release"]
fn hash_join_fan_out_materialization() {
    let n: usize = 20_000;
    let groups: usize = 200;

    let mut s = FactStore::new();
    for i in 0..n {
        let key = format!("k{}", i % groups);
        s.fact("bench", "left_rel")
            .subject(format!("l{i}"))
            .attr("key", key.clone())
            .emit();
        s.fact("bench", "right_rel")
            .subject(format!("r{i}"))
            .attr("key", key)
            .emit();
    }
    let batches = facts_to_batches(s.all(), "r").unwrap();
    let store = ColumnarStore::from_batches(&batches).unwrap();
    let plan = RelExpr::scan("left_rel").join(
        RelExpr::scan("right_rel"),
        vec![("key".into(), "key".into())],
    );

    let start = Instant::now();
    let result = execute(&plan, &store).unwrap();
    let elapsed = start.elapsed();

    let per_group = n / groups;
    assert_eq!(result.len(), groups * per_group * per_group);
    println!(
        "fan-out join: {} result rows in {:?} ({:.1} Mrows/s)",
        result.len(),
        elapsed,
        result.len() as f64 / elapsed.as_secs_f64() / 1e6,
    );
}
