//! Shadow equivalence of the new IR engine against the live interpreter, run over
//! the *real default rule pack* — on a synthetic store always, and on a real
//! `fabric_mega` fact dump when `INTERMED_FACT_DUMP` is set.
//!
//! The migration gate: for every rule the bridge lowers, the new engine must select
//! exactly the facts the interpreter does. Any divergence fails the test, so the old
//! matching code can only be deleted once this stays green on real packs.
//!
//! ```sh
//! INTERMED_FACT_DUMP=/tmp/facts.json cargo test -p intermed-query-bridge --test real_pack_shadow
//! ```

use intermed_facts::{Fact, FactStore};
use intermed_query_bridge::{ShadowResult, shadow_compare};
use intermed_rules::default_core_pack;

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

/// Run the whole default pack through the shadow comparator; assert no divergence,
/// return `(supported, skipped)` counts.
fn shadow_pack(store: &FactStore) -> (usize, usize) {
    let pack = default_core_pack();
    let (mut supported, mut skipped) = (0, 0);
    for spec in &pack.rules {
        match shadow_compare(spec, store) {
            ShadowResult::Match { .. } => supported += 1,
            ShadowResult::Skipped(_) => skipped += 1,
            ShadowResult::Diverged {
                only_interpreter,
                only_ir,
            } => panic!(
                "rule `{}` DIVERGED: interp-only={:?} ir-only={:?}",
                spec.id, only_interpreter, only_ir
            ),
        }
    }
    (supported, skipped)
}

#[test]
fn default_pack_shadow_matches_on_synthetic_store() {
    // A small, realistically-shaped store exercising several default-pack rules.
    let mut s = FactStore::new();
    s.fact("metadata-scanner", "mod")
        .subject("sodium")
        .attr("loader", "fabric")
        .attr("side", "client")
        .emit();
    s.fact("metadata-scanner", "mod")
        .subject("forgemod")
        .attr("loader", "forge")
        .emit();
    s.fact("mixin-analyzer", "mixin_overlap")
        .subject("net.minecraft.Foo")
        .attr("method_conflict", true)
        .emit();
    let (supported, skipped) = shadow_pack(&s);
    eprintln!("default pack on synthetic store: {supported} supported, {skipped} skipped");
    // The bridge must lower *some* of the real pack's rules (else it is vacuous).
    assert!(supported > 0, "bridge lowered no default-pack rules");
}

/// Demonstrate `EXPLAIN` / `EXPLAIN ANALYZE` (Phase 3.3) on real facts: lower the
/// first lowerable FactFinding rule and print its plan with actual cardinalities/time.
#[test]
fn explain_analyze_on_real_dump() {
    use intermed_columnar::ir::RelExpr;
    use intermed_columnar::{ColumnarStore, explain, explain_analyze, facts_to_batches};
    use intermed_query_bridge::{Lowering, rule_to_ir};

    let Ok(path) = std::env::var("INTERMED_FACT_DUMP") else {
        eprintln!("INTERMED_FACT_DUMP not set — skipping EXPLAIN ANALYZE demo");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read fact dump");
    let facts: Vec<Fact> = serde_json::from_str(&text).expect("parse Vec<Fact>");
    let store = rebuild_store(&facts);
    let batches = facts_to_batches(store.all(), "explain").unwrap();
    let columnar = ColumnarStore::from_batches(&batches).unwrap();
    let stats = columnar.statistics();

    let pack = default_core_pack();
    // Pick a rule the in-process engine actually runs (not a SQL-only
    // JoinFilter/GroupCountDistinct shape).
    let (rule, ir) = pack
        .rules
        .iter()
        .find_map(|r| match rule_to_ir(r) {
            Lowering::Ir(ir)
                if !matches!(
                    ir,
                    RelExpr::JoinFilter { .. } | RelExpr::GroupCountDistinct { .. }
                ) =>
            {
                Some((r, ir))
            }
            _ => None,
        })
        .expect("at least one in-process lowerable rule");

    eprintln!("=== rule: {} ===", rule.id);
    eprintln!("{}", explain(&ir, &stats));
    eprintln!("{}", explain_analyze(&ir, &columnar).unwrap());
}

#[test]
fn default_pack_shadow_matches_on_real_dump() {
    let Ok(path) = std::env::var("INTERMED_FACT_DUMP") else {
        eprintln!("INTERMED_FACT_DUMP not set — skipping real-dump shadow");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("read fact dump");
    let facts: Vec<Fact> = serde_json::from_str(&text).expect("parse Vec<Fact>");
    let store = rebuild_store(&facts);
    let (supported, skipped) = shadow_pack(&store);
    eprintln!(
        "default pack on {} real facts: {supported} rules matched the interpreter, {skipped} skipped",
        facts.len()
    );
    assert!(supported > 0);
}
