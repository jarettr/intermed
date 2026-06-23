//! End-to-end query-compiler pipeline: declarative spec → IR → {analyze, route,
//! execute, SQL}, all over the columnar Arrow store. Proves the pieces compose.

use intermed_columnar::{
    ColumnarStore, QuerySpec, Value, analyze, execute, facts_to_batches, plan, to_sql,
};
use intermed_facts::FactStore;

fn store() -> ColumnarStore {
    let mut s = FactStore::new();
    for (mod_id, op, target) in [
        ("owo", "redirect", "net.minecraft.recipe.RecipeManager"),
        (
            "polymorph",
            "redirect",
            "net.minecraft.recipe.RecipeManager",
        ),
        (
            "sodium",
            "inject",
            "net.minecraft.client.render.WorldRenderer",
        ),
        ("create", "overwrite", "net.minecraft.recipe.RecipeManager"),
    ] {
        s.fact("mixin-analyzer", "mixin_application_site")
            .subject(mod_id)
            .attr("mod", mod_id)
            .attr("operation", op)
            .attr("target_class", target)
            .emit();
    }
    let batches = facts_to_batches(s.all(), "run").unwrap();
    ColumnarStore::from_batches(&batches).unwrap()
}

#[test]
fn declarative_query_executes_and_routes_consistently() {
    // "How many mods redirect each target class?" — group + count + having.
    let json = r#"{
        "scan": "mixin_application_site",
        "filters": [{"column": "operation", "op": "eq", "value": "redirect"}],
        "group_by": ["target_class"],
        "aggregates": [{"func": "count", "column": "", "alias": "n"}],
        "having": [{"column": "n", "op": "ge", "value": 2}]
    }"#;
    let spec = QuerySpec::from_json(json).unwrap();
    let ir = spec.compile();

    // The analyzer routes aggregation to DuckDB; the router keeps the base
    // scan/filter in-process and splits the aggregate into its own stage.
    let caps = analyze(&ir);
    assert!(caps.needs_duckdb());
    let execution = plan(&ir);
    assert_eq!(execution.engine_count(), 2); // datalog + duckdb

    // The in-process executor produces the answer directly (reference engine).
    let result = execute(&ir, &store()).unwrap();
    assert_eq!(result.len(), 1);
    let row = &result.rows[0];
    assert_eq!(
        row.get("target_class").and_then(Value::as_str),
        Some("net.minecraft.recipe.RecipeManager")
    );
    assert_eq!(row.get("n"), Some(&Value::Int(2))); // owo + polymorph

    // The same IR lowers to DuckDB SQL (the accelerated route for the same answer).
    let sql = to_sql(&ir).unwrap();
    assert!(sql.contains("GROUP BY \"target_class\""));
    assert!(sql.contains("HAVING \"n\" >= 2"));
}
