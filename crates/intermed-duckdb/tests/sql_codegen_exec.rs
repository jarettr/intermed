//! Execute generated SQL from the v2 pack against an in-memory DuckDB store.

use intermed_duckdb::{DuckStore, EVAL_RUN_ID};
use intermed_doctor_core::facts::{kind, FactStore};
use intermed_rules::{default_core_pack_v2, generate_pack_sql, prepare_sql};

#[test]
fn generated_core_pack_sql_executes() {
    let mut store = FactStore::new();
    store
        .fact("t", kind::MOD)
        .subject("alpha")
        .attr("file", "a.jar")
        .emit();
    store
        .fact("env", kind::ENVIRONMENT)
        .subject("instance")
        .attr("loader", "fabric")
        .emit();

    let duck = DuckStore::open_in_memory().expect("memory store");
    duck
        .materialize_facts(EVAL_RUN_ID, store.all())
        .expect("materialize");

    let pack = default_core_pack_v2();
    for entry in generate_pack_sql(&pack) {
        let sql = prepare_sql(&entry.sql, EVAL_RUN_ID)
            .replace("{well_identified_trust}", "60");
        duck.query(&sql).unwrap_or_else(|e| {
            panic!("rule `{}` sql failed: {e}\n---\n{sql}", entry.id);
        });
    }
}