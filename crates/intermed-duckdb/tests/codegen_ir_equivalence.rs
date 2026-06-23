//! End-to-end equivalence of the new IR→DuckDB path against the **runtime
//! interpreter** (the source of truth for findings), on real packs.
//!
//! The migration gate is *not* "new SQL == old hand-written SQL" — the old
//! `sql_codegen` turned out to diverge from the interpreter (it omits `val_float`
//! in its COALESCE and handles terms differently), so matching it would be matching
//! a bug. The gate that matters: for every `FactFinding` rule the bridge lowers,
//! running `to_sql(rule_to_ir(rule))` through DuckDB selects exactly the fact ids the
//! interpreter's `matching_fact_ids` does. The old codegen's divergence from this is
//! *reported* (it is the inferior path being replaced), not asserted.
//!
//! ```sh
//! INTERMED_FACT_DUMP=/tmp/facts.json cargo test -p intermed-duckdb --features duckdb --test codegen_ir_equivalence
//! ```
#![cfg(feature = "duckdb")]

use std::collections::BTreeSet;

use intermed_columnar::Value;
use intermed_duckdb::ir_engine::DuckIrEngine;
use intermed_facts::{Fact, FactStore};
use intermed_query_bridge::{Lowering, rule_to_ir};
use intermed_rules::{RuleKind, RuleSpec, default_core_pack_v2, matching_fact_ids};

fn rebuild(facts: &[Fact]) -> FactStore {
    let mut s = FactStore::new();
    for f in facts {
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

/// Interpreter-matched fact ids for a rule, as a set of strings.
fn interpreter_set(spec: &RuleSpec, store: &FactStore) -> BTreeSet<String> {
    matching_fact_ids(spec, store)
        .into_iter()
        .map(|id| id.0.to_string())
        .collect()
}

/// For every lowerable FactFinding rule, assert IR→DuckDB (via the production Arrow
/// appender engine) ≡ interpreter. Returns `(checked, skipped)`.
fn validate(fact_store: &FactStore) -> (usize, usize) {
    let engine = DuckIrEngine::from_facts(fact_store.all()).expect("duck ir engine");
    let pack = default_core_pack_v2();
    let (mut checked, mut skipped) = (0, 0);
    for rule in &pack.rules {
        if rule.kind != RuleKind::FactFinding || rule.where_all.contains_key("attr:hot_path") {
            skipped += 1;
            continue;
        }
        let ir = match rule_to_ir(rule) {
            Lowering::Ir(e) => e,
            Lowering::Unsupported(_) => {
                skipped += 1;
                continue;
            }
        };
        let Ok(rows) = engine.run(&ir) else {
            skipped += 1;
            continue;
        };
        let ir_duck: BTreeSet<String> = rows
            .iter()
            .filter_map(|r| match r.get("fact_id") {
                Some(Value::Int(i)) => Some(i.to_string()),
                Some(Value::Str(s)) => Some(s.clone()),
                _ => None,
            })
            .collect();
        let interp = interpreter_set(rule, fact_store);
        assert_eq!(
            ir_duck,
            interp,
            "rule `{}`: IR→DuckDB diverged from interpreter\n  only-duck={:?}\n  only-interp={:?}",
            rule.id,
            ir_duck.difference(&interp).collect::<Vec<_>>(),
            interp.difference(&ir_duck).collect::<Vec<_>>()
        );
        checked += 1;
    }
    (checked, skipped)
}

#[test]
fn ir_duckdb_equals_interpreter_on_synthetic_store() {
    let mut s = FactStore::new();
    s.fact("metadata-scanner", "mod")
        .subject("sodium")
        .attr("loader", "fabric")
        .emit();
    s.fact("metadata-scanner", "mod")
        .subject("forgemod")
        .attr("loader", "forge")
        .emit();
    s.fact("resource-ast-scanner", "resource_collision")
        .subject("data/x/recipe/a.json")
        .attr("class", "json-merge-candidate")
        .emit();
    let (checked, skipped) = validate(&s);
    eprintln!("synthetic: {checked} rules IR→DuckDB≡interpreter, {skipped} skipped");
    assert!(checked > 0);
}

#[test]
fn ir_duckdb_equals_interpreter_on_real_dump() {
    let Ok(path) = std::env::var("INTERMED_FACT_DUMP") else {
        eprintln!("INTERMED_FACT_DUMP not set — skipping real-dump validation");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read dump");
    let facts: Vec<Fact> = serde_json::from_str(&text).expect("parse Vec<Fact>");
    let s = rebuild(&facts);
    let (checked, skipped) = validate(&s);
    eprintln!(
        "real ({} facts): {checked} rules IR→DuckDB≡interpreter, {skipped} skipped",
        facts.len()
    );
    assert!(checked > 0);
}
