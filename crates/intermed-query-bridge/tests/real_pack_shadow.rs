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
use std::collections::BTreeSet;

const EXPECTED_CORE_RULE_IDS: &[&str] = &[
    "corrupt-jar",
    "duplicate-id",
    "forge-coremod-present",
    "invalid-active-metadata",
    "known-incompatible-mods",
    "loader-mismatch",
    "log-ClassNotFound",
    "log-DatapackValidationError",
    "log-JvmCrash",
    "log-MissingDependency",
    "log-MixinApplyError",
    "log-ModLoadingFailure",
    "log-NoClassDefFound",
    "log-OutOfMemory",
    "log-PortInUse",
    "log-RegistryFreezeError",
    "log-StackOverflow",
    "mixin-overlap",
    "mixin-overlap-hot",
    "mixin-overwrite",
    "mixin-overwrite-hot",
    "recipe-disabled-platform",
    "resource-conflict-binary-override-cosmetic",
    "resource-conflict-binary-override-font",
    "resource-conflict-binary-override-functional",
    "resource-conflict-classification-unavailable",
    "resource-conflict-json-merge",
    "resource-conflict-json-override",
    "resource-conflict-order-dependent-atlas",
    "resource-conflict-order-dependent-shader",
    "resource-conflict-order-dependent-sound-def",
    "resource-conflict-root-metadata",
    "resource-conflict-safe-crdt-merge",
    "resource-conflict-safe-json-object-merge",
    "resource-conflict-sound-event-merge",
    "resource-conflict-tag-invalid",
    "resource-conflict-tag-mixed-required",
    "resource-conflict-tag-remove",
    "resource-conflict-tag-replace",
    "resource-conflict-unsafe-replace",
    "sbom-security-correlation",
    "scan-incomplete",
    "side-mismatch-client-on-server",
    "side-mismatch-server-on-client",
    "tag-replace-platform",
    "unknown-source",
    "unsigned-jar",
];

const EXPECTED_UNSUPPORTED_RULE_IDS: &[&str] =
    &["known-incompatible-mods", "sbom-security-correlation"];

fn rebuild_store(facts: &[Fact]) -> FactStore {
    let mut s = FactStore::new();
    for f in facts {
        let mut b = s
            .fact(&f.extractor, &f.kind)
            .subject(f.subject.to_string())
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
fn shadow_pack(store: &FactStore) -> (BTreeSet<String>, BTreeSet<String>) {
    let pack = default_core_pack();
    let (mut supported, mut skipped) = (BTreeSet::new(), BTreeSet::new());
    for spec in &pack.rules {
        match shadow_compare(spec, store) {
            ShadowResult::Match { .. } => {
                supported.insert(spec.id.clone());
            }
            ShadowResult::Unsupported(_) => {
                skipped.insert(spec.id.clone());
            }
            ShadowResult::ExecutionFailed(error) => {
                panic!("rule `{}` backend execution failed: {error}", spec.id)
            }
            ShadowResult::Diverged {
                only_interpreter,
                only_ir,
            } => panic!(
                "rule `{}` DIVERGED: interp-only={:?} ir-only={:?}",
                spec.id, only_interpreter, only_ir
            ),
        }
    }
    let all = supported.union(&skipped).cloned().collect::<BTreeSet<_>>();
    let expected_all = EXPECTED_CORE_RULE_IDS
        .iter()
        .map(|id| (*id).to_string())
        .collect::<BTreeSet<_>>();
    let expected_skipped = EXPECTED_UNSUPPORTED_RULE_IDS
        .iter()
        .map(|id| (*id).to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(all, expected_all, "default rule-pack surface changed");
    assert_eq!(
        skipped, expected_skipped,
        "columnar shadow coverage changed; support loss/addition must be reviewed"
    );
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
    eprintln!(
        "default pack on synthetic store: {} supported, {} skipped",
        supported.len(),
        skipped.len()
    );
    assert_eq!(supported.len(), 45);
    assert_eq!(skipped.len(), 2);
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
        "default pack on {} real facts: {} rules matched the interpreter, {} skipped",
        facts.len(),
        supported.len(),
        skipped.len()
    );
    assert_eq!(supported.len(), 45);
    assert_eq!(skipped.len(), 2);
}
