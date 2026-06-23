//! Fast diagnostic: where does `to_sql` (DuckDB) diverge from the in-process IR
//! executor on real facts? (In-process IR ≡ interpreter is already proven, so any
//! IR→DuckDB ≠ interpreter divergence is a `to_sql` bug.) Indexed for speed; prints
//! the first diverging rule with examples, then stops.
#![cfg(feature = "duckdb")]

use std::collections::BTreeSet;

use intermed_columnar::{ColumnarStore, Value, execute, facts_to_batches};
use intermed_duckdb::ir_engine::DuckIrEngine;
use intermed_facts::{Fact, FactStore};
use intermed_query_bridge::{Lowering, rule_to_ir};
use intermed_rules::{RuleKind, default_core_pack_v2};

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

#[test]
fn find_to_sql_divergence_on_real_dump() {
    let Ok(path) = std::env::var("INTERMED_FACT_DUMP") else {
        eprintln!("INTERMED_FACT_DUMP not set — skipping");
        return;
    };
    let facts: Vec<Fact> = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let fs = rebuild(&facts);
    // DuckDB side via the Arrow appender (fast, unlike row-by-row INSERT).
    let engine = DuckIrEngine::from_facts(fs.all()).unwrap();
    let batches = facts_to_batches(fs.all(), "run").unwrap();
    let columnar = ColumnarStore::from_batches(&batches).unwrap();

    let pack = default_core_pack_v2();
    let mut diverged = Vec::new();
    for rule in &pack.rules {
        if rule.kind != RuleKind::FactFinding || rule.where_all.contains_key("attr:hot_path") {
            continue;
        }
        let ir = match rule_to_ir(rule) {
            Lowering::Ir(e) => e,
            Lowering::Unsupported(_) => continue,
        };
        let Ok(duck_rows) = engine.run(&ir) else {
            continue;
        };

        let inproc: BTreeSet<i64> = execute(&ir, &columnar)
            .unwrap()
            .rows
            .iter()
            .filter_map(|r| match r.get("fact_id") {
                Some(Value::Int(i)) => Some(*i),
                _ => None,
            })
            .collect();
        let duck: BTreeSet<i64> = duck_rows
            .iter()
            .filter_map(|r| match r.get("fact_id") {
                Some(Value::Int(i)) => Some(*i),
                Some(Value::Str(s)) => s.parse().ok(),
                _ => None,
            })
            .collect();
        let sql = String::new();

        if inproc != duck {
            let only_in = inproc
                .difference(&duck)
                .take(3)
                .copied()
                .collect::<Vec<_>>();
            let only_du = duck
                .difference(&inproc)
                .take(3)
                .copied()
                .collect::<Vec<_>>();
            eprintln!(
                "DIVERGED rule `{}`: in-proc={} duck={} | only-inproc(ex)={:?} only-duck(ex)={:?}\n  where_all={:?}\n  SQL:\n{}",
                rule.id,
                inproc.len(),
                duck.len(),
                only_in,
                only_du,
                rule.where_all,
                sql
            );
            diverged.push(rule.id.clone());
        }
    }
    eprintln!("total diverged rules: {}", diverged.len());
    assert!(
        diverged.is_empty(),
        "to_sql diverges from in-process on: {diverged:?}"
    );
}
