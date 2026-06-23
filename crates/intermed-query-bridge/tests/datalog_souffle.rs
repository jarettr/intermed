//! End-to-end: IR → `to_datalog` → **Soufflé** → matched fact ids ≡ interpreter, on
//! real packs. Proves the generic IR-driven Datalog backend reproduces the runtime
//! (and, unlike the old 3-rule `datalog_codegen`, covers every FactFinding rule).
//!
//! ```sh
//! PATH=/tmp/souffle_local/usr/bin:$PATH INTERMED_FACT_DUMP=/tmp/fm6.json \
//!   cargo test -p intermed-query-bridge --test datalog_souffle -- --nocapture
//! ```
//! Skips when souffle is absent or the dump env is unset.

use std::collections::BTreeSet;
use std::io::Write;
use std::process::Command;

use intermed_columnar::{FACT_SCHEMA, to_datalog};
use intermed_facts::{AttrValue, Fact, FactStore};
use intermed_query_bridge::{Lowering, rule_to_ir};
use intermed_rules::{RuleKind, default_core_pack_v2, matching_fact_ids};

fn souffle_bin() -> Option<String> {
    [
        std::env::var("SOUFFLE_BIN").ok(),
        Some("/tmp/souffle_local/usr/bin/souffle".to_string()),
        Some("souffle".to_string()),
    ]
    .into_iter()
    .flatten()
    .find(|cand| {
        Command::new(cand)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

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

/// Souffle reads plain TSV; keep symbols on one tab-free line.
fn sym(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

fn attr_str(v: &AttrValue) -> String {
    match v {
        AttrValue::Str(s) => s.clone(),
        AttrValue::Int(i) => i.to_string(),
        AttrValue::Float(f) => f.to_string(),
        AttrValue::Bool(b) => b.to_string(),
    }
}

/// Write the generic `fact` / `fact_attr` relations once.
fn write_facts(dir: &std::path::Path, store: &FactStore) {
    let mut fact = std::fs::File::create(dir.join("fact.facts")).unwrap();
    let mut attr = std::fs::File::create(dir.join("fact_attr.facts")).unwrap();
    for f in store.all() {
        writeln!(fact, "{}\t{}\t{}", f.id.0, sym(&f.kind), sym(&f.subject)).unwrap();
        for (k, v) in &f.attributes {
            writeln!(attr, "{}\t{}\t{}", f.id.0, sym(k), sym(&attr_str(v))).unwrap();
        }
    }
}

fn run_souffle(bin: &str, root: &std::path::Path, program: &str, rel: &str) -> BTreeSet<String> {
    std::fs::write(root.join("p.dl"), program).unwrap();
    let out = Command::new(bin)
        .arg("-F")
        .arg(root)
        .arg("-D")
        .arg(root)
        .arg(root.join("p.dl"))
        .output()
        .expect("run souffle");
    assert!(
        out.status.success(),
        "souffle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let csv = std::fs::read_to_string(root.join(format!("{rel}.csv"))).unwrap_or_default();
    csv.lines()
        .filter_map(|l| l.split('\t').next().map(str::to_string))
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
fn ir_datalog_souffle_equals_interpreter() {
    let Some(bin) = souffle_bin() else {
        eprintln!("souffle not available — skipping");
        return;
    };
    let store = match std::env::var("INTERMED_FACT_DUMP") {
        Ok(path) => {
            let facts: Vec<Fact> =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            rebuild(&facts)
        }
        Err(_) => {
            // Small built-in fixture so the test isn't vacuous without a dump.
            let mut s = FactStore::new();
            s.fact("c", "resource_collision")
                .subject("a")
                .attr("class", "json-merge-candidate")
                .emit();
            s.fact("c", "resource_collision")
                .subject("b")
                .attr("class", "unsafe-replace")
                .emit();
            s
        }
    };

    let root = std::env::temp_dir().join(format!("intermed-dl-test-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    write_facts(&root, &store);

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
        let Some(rule_dl) = to_datalog(&ir, "matched") else {
            skipped += 1;
            continue;
        };
        let program = format!("{FACT_SCHEMA}{rule_dl}");
        let souffle_ids = run_souffle(&bin, &root, &program, "matched");
        let interp: BTreeSet<String> = matching_fact_ids(rule, &store)
            .into_iter()
            .map(|id| id.0.to_string())
            .collect();
        assert_eq!(
            souffle_ids,
            interp,
            "rule `{}`: souffle ≠ interpreter\n  only-souffle={:?}\n  only-interp={:?}",
            rule.id,
            souffle_ids.difference(&interp).collect::<Vec<_>>(),
            interp.difference(&souffle_ids).collect::<Vec<_>>()
        );
        checked += 1;
    }
    let _ = std::fs::remove_dir_all(&root);
    eprintln!("IR→Datalog→souffle ≡ interpreter: {checked} rules checked, {skipped} skipped");
    assert!(checked > 0);
}
