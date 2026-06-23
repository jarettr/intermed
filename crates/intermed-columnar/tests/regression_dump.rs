//! Regression harness against a real fact dump (plan Phase 4).
//!
//! Run against a real `--dump-facts` snapshot to prove the columnar projection is
//! lossless on production-shaped data:
//!
//! ```sh
//! intermed doctor --mixin-risk --mixin-level full ./fabric_mega --dump-facts /tmp/facts.json
//! INTERMED_FACT_DUMP=/tmp/facts.json cargo test -p intermed-columnar --test regression_dump
//! ```
//!
//! Skipped (passes vacuously) when the env var is unset, like the repo's other
//! real-data tests.

use intermed_columnar::assert_lossless;
use intermed_facts::Fact;

#[test]
fn columnar_round_trip_is_lossless_on_real_dump() {
    let Ok(path) = std::env::var("INTERMED_FACT_DUMP") else {
        eprintln!("INTERMED_FACT_DUMP not set — skipping real-dump regression");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read fact dump");
    // `--dump-facts` writes a JSON array of facts.
    let facts: Vec<Fact> = serde_json::from_str(&text).expect("parse fact dump as Vec<Fact>");
    eprintln!("regression: {} facts from {path}", facts.len());
    assert_lossless(&facts).expect("columnar round-trip diverged from source facts");
}
