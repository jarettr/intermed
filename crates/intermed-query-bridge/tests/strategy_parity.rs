//! Strategy equivalence: the **FastRow** path must select exactly what the
//! **Vectorized** engine does, for every rule the bridge lowers (plan Phase 0/2.4).
//!
//! This is the second leg of the migration gate. `real_pack_shadow` proves
//! Vectorized ≡ interpreter; this proves FastRow ≡ Vectorized. Transitively, FastRow ≡
//! interpreter — so routing the live `--logic columnar` path through the FastRow fast
//! path cannot change a single finding. It also asserts FastRow is *actually exercised*
//! (the selector picks it for the common FactFinding shape), so the fast path is not
//! silently bypassed.
//!
//! On a synthetic store always; on a real fact dump when `INTERMED_FACT_DUMP` is set:
//!
//! ```sh
//! INTERMED_FACT_DUMP=/tmp/facts.json cargo test -p intermed-query-bridge --test strategy_parity
//! ```

use std::path::PathBuf;

use intermed_columnar::{ExecutionStrategy, QueryEngine, optimize, plan_physical, select_strategy};
use intermed_facts::{Fact, FactStore};
use intermed_rules::{Lowering, default_core_pack, rule_to_ir};

fn rebuild_store(facts: &[Fact]) -> FactStore {
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

/// Run the whole default pack's lowerable rules through both strategies; assert every
/// one is byte-identical, and return `(rules_compared, fast_row_selected)`.
fn compare_strategies(store: &FactStore) -> (usize, usize) {
    let engine = QueryEngine::from_facts(store.all()).expect("engine");
    let stats = engine.statistics();
    let pack = default_core_pack();
    let (mut compared, mut fast_row) = (0, 0);
    for spec in &pack.rules {
        let Lowering::Ir(ir) = rule_to_ir(spec) else {
            continue;
        };
        // The strategy the planner would auto-select for this rule.
        let phys = plan_physical(&optimize(&ir, stats), stats);
        if select_strategy(&phys) == ExecutionStrategy::FastRow {
            fast_row += 1;
        }
        let fast = engine
            .run_with_strategy(&ir, ExecutionStrategy::FastRow)
            .expect("fast-row run");
        let vectorized = engine
            .run_with_strategy(&ir, ExecutionStrategy::Vectorized)
            .expect("vectorized run");
        assert_eq!(
            fast.rows, vectorized.rows,
            "rule `{}` diverged between FastRow and Vectorized",
            spec.id
        );
        compared += 1;
    }
    (compared, fast_row)
}

#[test]
fn fast_row_equals_vectorized_on_synthetic_store() {
    let mut s = FactStore::new();
    for (m, loader, side) in [
        ("sodium", "fabric", "client"),
        ("forgemod", "forge", "both"),
        ("iris", "fabric", "client"),
    ] {
        s.fact("metadata-scanner", "mod")
            .subject(m)
            .attr("loader", loader)
            .attr("side", side)
            .emit();
    }
    s.fact("mixin-analyzer", "mixin_application_site")
        .subject("owo")
        .attr("operation", "overwrite")
        .attr("target_class", "net/minecraft/Foo")
        .emit();
    s.fact("mixin-analyzer", "mixin_overlap")
        .subject("net.minecraft.Foo")
        .attr("method_conflict", true)
        .emit();

    let (compared, fast_row) = compare_strategies(&s);
    eprintln!("synthetic: {compared} rules compared, {fast_row} selected FastRow");
    assert!(compared > 0, "no lowerable rules compared");
    assert!(
        fast_row > 0,
        "FastRow was never selected — fast path not exercised"
    );
}

#[test]
fn fast_row_equals_vectorized_on_real_dump() {
    let Some(path) = std::env::var_os("INTERMED_FACT_DUMP") else {
        eprintln!("INTERMED_FACT_DUMP not set; skipping real-pack strategy parity");
        return;
    };
    let path = PathBuf::from(path);
    let json = std::fs::read_to_string(&path).expect("read fact dump");
    let facts: Vec<Fact> = serde_json::from_str(&json)
        .or_else(|_| {
            // Tolerate a `{ "facts": [...] }` envelope.
            serde_json::from_str::<serde_json::Value>(&json)
                .and_then(|v| serde_json::from_value(v["facts"].clone()))
        })
        .expect("parse fact dump");
    let store = rebuild_store(&facts);
    let (compared, fast_row) = compare_strategies(&store);
    eprintln!(
        "real dump ({} facts): {compared} rules compared, {fast_row} selected FastRow",
        facts.len()
    );
    assert!(compared > 0);
    assert!(fast_row > 0);
}
