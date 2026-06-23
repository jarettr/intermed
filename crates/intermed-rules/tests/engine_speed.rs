//! Engine-vs-engine speed: the **columnar** rule pack (FastRow + Vectorized, with
//! Phase-1 direct build + Phase-2 kind pruning) against the legacy **interpreter**
//! (`evaluate_pack`), on the same facts. End-to-end `doctor` time is dominated by
//! collectors (jar scanning, bytecode), so this isolates the slice the plan is about:
//! rule evaluation. It also asserts both produce the same finding set.
//!
//! ```text
//! INTERMED_FACT_DUMP=/tmp/facts.json cargo test -p intermed-rules --test engine_speed --release -- --ignored --nocapture
//! ```

use std::time::Instant;

use intermed_doctor_core::evidence::Finding;
use intermed_doctor_core::facts::{Fact, FactStore};
use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};
use intermed_rules::{ColumnarRulePack, RulePack, default_core_pack_v2, evaluate_pack};

/// Regression guard for the related-evidence quadratic: the candidate index is a
/// function of the rule, so it must be built **once per rule**, not once per finding.
/// The old code rebuilt a 20k-candidate index for each of 300 findings (6M ops) and
/// took seconds; the fix builds it once. This is a *non-ignored* test so the quadratic
/// can never silently come back.
#[test]
fn related_evidence_is_built_once_not_per_finding() {
    let mut s = FactStore::new();
    for i in 0..300 {
        s.fact("resource-ast", "resource_collision")
            .subject(format!("data/p{i}.json"))
            .attr("class", "safe-crdt-merge")
            .attr("reason", "tags merge cleanly")
            .emit();
    }
    // A large candidate pool the evidence join scans (one matching writer per path,
    // plus noise) — the cost the old per-finding rebuild multiplied by 300.
    for i in 0..20_000 {
        s.fact("resource-ast", "resource_writer")
            .subject(format!("w{i}"))
            .attr("path", format!("data/p{}.json", i % 300))
            .emit();
    }
    let pack = default_core_pack_v2();
    let rule = pack
        .rules
        .iter()
        .find(|r| r.id == "resource-conflict-safe-crdt-merge")
        .expect("rule present")
        .clone();
    let single = RulePack {
        rules: vec![rule],
        ..pack
    };
    let t = target();
    let ctx = RuleCtx::for_test(&s, &t);

    let start = std::time::Instant::now();
    let findings = evaluate_pack(&single, &ctx);
    let ms = start.elapsed().as_millis();

    assert_eq!(findings.len(), 300, "one finding per matching collision");
    // Evidence must still be attached (the join still works), ~67 writers per path.
    assert!(
        findings.iter().any(|f| !f.evidence.is_empty()),
        "evidence edges should be attached"
    );
    // The fix makes this ~O(candidates) once. A generous bound that the old
    // O(findings × candidates) rebuild (seconds) would blow.
    assert!(
        ms < 1500,
        "evidence join took {ms}ms — quadratic regression?"
    );
}

fn target() -> Target {
    Target {
        path: ".".into(),
        kind: TargetKind::ModsDir,
        mods_dir: None,
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    }
}

fn load_store() -> FactStore {
    let Some(p) = std::env::var_os("INTERMED_FACT_DUMP") else {
        // Synthetic fallback: many facts across a few scanned + unscanned kinds.
        let mut s = FactStore::new();
        for i in 0..40_000 {
            s.fact("c", "mixin_application_site")
                .subject(format!("mod{}", i % 300))
                .attr("operation", ["inject", "redirect", "overwrite"][i % 3])
                .attr("target_class", format!("net/minecraft/C{}", i % 800))
                .emit();
            s.fact("c", "resource_reference")
                .subject(format!("data/m{}/r{i}.json", i % 300))
                .attr("namespace", format!("ns{}", i % 40))
                .emit();
        }
        return s;
    };
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

fn median_ms(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn ids(mut fs: Vec<Finding>) -> Vec<String> {
    let mut v: Vec<String> = fs.drain(..).map(|f| f.id).collect();
    v.sort();
    v.dedup();
    v
}

#[test]
#[ignore = "speed comparison; run with --ignored --release"]
fn columnar_engine_vs_interpreter() {
    let store = load_store();
    let t = target();
    let reps = 7;

    let interp_ms = median_ms(
        (0..reps)
            .map(|_| {
                let ctx = RuleCtx::for_test(&store, &t);
                let start = Instant::now();
                let _ = evaluate_pack(&default_core_pack_v2(), &ctx);
                start.elapsed().as_secs_f64() * 1000.0
            })
            .collect(),
    );

    let columnar_ms = median_ms(
        (0..reps)
            .map(|_| {
                let ctx = RuleCtx::for_test(&store, &t);
                let start = Instant::now();
                let _ = ColumnarRulePack::default().evaluate(&ctx);
                start.elapsed().as_secs_f64() * 1000.0
            })
            .collect(),
    );

    // Equivalence: same findings either way.
    let ctx = RuleCtx::for_test(&store, &t);
    let interp_ids = ids(evaluate_pack(&default_core_pack_v2(), &ctx));
    let columnar_ids = ids(ColumnarRulePack::default().evaluate(&ctx));
    assert_eq!(
        interp_ids, columnar_ids,
        "columnar and interpreter findings differ"
    );

    println!(
        "rule-eval over {} facts: interpreter {interp_ms:.2}ms, columnar {columnar_ms:.2}ms ({:.2}× vs interpreter), {} findings",
        store.all().len(),
        interp_ms / columnar_ms,
        interp_ids.len(),
    );
}

#[test]
#[ignore = "per-rule timing probe"]
fn per_rule_timing() {
    let store = load_store();
    let t = target();
    let pack = default_core_pack_v2();
    let mut timings: Vec<(String, String, f64)> = Vec::new();
    for spec in &pack.rules {
        let single = intermed_rules::RulePack {
            rules: vec![spec.clone()],
            ..pack.clone()
        };
        let ctx = RuleCtx::for_test(&store, &t);
        let start = Instant::now();
        let _ = evaluate_pack(&single, &ctx);
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        timings.push((spec.id.clone(), format!("{:?}", spec.kind), ms));
    }
    timings.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    for (id, kind, ms) in timings.iter().take(12) {
        println!("{ms:8.2}ms  {kind:14}  {id}");
    }
}
