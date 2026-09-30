//! Execute the IR-generated SQL for every lowerable rule against an in-memory
//! DuckDB store — verifies the unified IR→to_sql backend emits valid DuckDB SQL for
//! FactFinding / Join / GroupDistinct shapes.

use intermed_columnar::ir::{CmpOp, Predicate, RelExpr, ScalarValue};
use intermed_columnar::to_sql;
use intermed_doctor_core::facts::{FactStore, kind};
use intermed_duckdb::{DuckStore, EVAL_RUN_ID};
use intermed_rules::{Lowering, default_core_pack_v2, rule_to_ir};

#[test]
fn generated_core_pack_sql_executes() {
    let mut store = FactStore::new();
    store
        .fact("t", kind::MOD)
        .subject("alpha")
        .attr("file", "a.jar")
        .attr("loader", "forge")
        .emit();
    store
        .fact("env", kind::ENVIRONMENT)
        .subject("instance")
        .attr("loader", "fabric")
        .emit();
    store
        .fact("ast", "resource_collision")
        .subject("data/x/recipe/a.json")
        .attr("class", "json-merge-candidate")
        .emit();

    let duck = DuckStore::open_in_memory().expect("memory store");
    duck.materialize_facts(EVAL_RUN_ID, store.all())
        .expect("materialize");

    let pack = default_core_pack_v2();
    let mut executed = 0;
    for rule in &pack.rules {
        let Lowering::Ir(ir) = rule_to_ir(rule) else {
            continue;
        };
        let Some(sql) = to_sql(&ir) else { continue };
        let result = duck
            .query(&sql)
            .unwrap_or_else(|e| panic!("rule `{}` sql failed: {e}\n---\n{sql}", rule.id));
        executed += 1;

        // Correctness spot-check: the forge mod on a fabric env must surface as a
        // loader-mismatch pair (proves the Join IR→SQL semantics, not just validity).
        if rule.id == "loader-mismatch" {
            let li = result.columns.iter().position(|c| c == "left_subject");
            let ri = result.columns.iter().position(|c| c == "right_subject");
            let pairs: Vec<(String, String)> = match (li, ri) {
                (Some(li), Some(ri)) => result
                    .rows
                    .iter()
                    .map(|r| (r[li].clone(), r[ri].clone()))
                    .collect(),
                _ => Vec::new(),
            };
            assert!(
                pairs.contains(&("alpha".to_string(), "instance".to_string())),
                "loader-mismatch Join SQL should match (alpha forge × instance fabric); got {pairs:?}"
            );
        }
    }
    assert!(executed > 0, "no IR-generated SQL was executed");
}

#[test]
fn group_distinct_sql_honors_group_filter_and_typed_distinct_values() {
    let mut store = FactStore::new();
    for (subject, loader, number, side) in [
        ("a", "fabric", 1_i64, "client"),
        ("b", "fabric", 2_i64, "client"),
        ("c", "forge", 3_i64, "client"),
        ("ignored", "forge", 4_i64, "server"),
    ] {
        store
            .fact("t", kind::MOD)
            .subject(subject)
            .attr("loader", loader)
            .attr("number", number)
            .attr("side", side)
            .emit();
    }
    let duck = DuckStore::open_in_memory().expect("memory store");
    duck.materialize_facts(EVAL_RUN_ID, store.all())
        .expect("materialize");
    let plan = RelExpr::GroupCountDistinct {
        kinds: vec![kind::MOD.to_string()],
        group_col: "loader".into(),
        distinct_attr: "number".into(),
        filters: vec![Predicate {
            column: "side".into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str("client".into()),
        }],
        min_count: 2,
    };
    let sql = to_sql(&plan).expect("group SQL");
    let result = duck
        .query(&sql)
        .unwrap_or_else(|error| panic!("{error}\n{sql}"));
    assert_eq!(result.columns, vec!["loader"]);
    assert_eq!(result.rows, vec![vec!["fabric".to_string()]]);
}
