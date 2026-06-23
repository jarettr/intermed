//! Golden tests: each fixture resource lowers to a stable AST summary.
//!
//! The golden captures the *semantic* output (domain, parse status, summary,
//! references, diagnostics) — not the versioned envelope (schema / parser_version
//! / semantic_hash), so a fixture only drifts when parsing behaviour actually
//! changes. Regenerate after an intentional change with:
//!
//! ```sh
//! UPDATE_GOLDEN=1 cargo test -p intermed-resource-ast --test golden
//! ```

use std::path::PathBuf;

use intermed_resource_ast::{ResourceLevel, parse_resource};
use serde_json::json;

/// (fixture file, the resource path it represents in a jar).
const FIXTURES: &[(&str, &str)] = &[
    ("tag_basic.json", "data/c/tags/items/ingots.json"),
    ("recipe_shaped.json", "data/create/recipe/gadget.json"),
    ("lang.json", "assets/create/lang/en_us.json"),
    ("model.json", "assets/create/models/item/wrench.json"),
];

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/resource_ast")
}

#[test]
fn golden_ast_summaries_are_stable() {
    let dir = fixtures_dir();
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();

    for (file, path) in FIXTURES {
        let bytes = std::fs::read(dir.join(file)).expect("read fixture");
        let ast = parse_resource(path, &bytes, ResourceLevel::Full);

        // Stable, version-independent view of the parse result.
        let actual = json!({
            "resource_path": ast.resource_path,
            "domain": ast.domain.as_str(),
            "parse_status": ast.parse_status.as_str(),
            "summary": ast.summary,
            "references": ast.references,
            "diagnostics": ast.diagnostics,
        });
        let actual_pretty = serde_json::to_string_pretty(&actual).unwrap();

        let golden_path = dir.join(format!("{file}.golden"));
        if update {
            std::fs::write(&golden_path, &actual_pretty).expect("write golden");
            continue;
        }
        let expected = std::fs::read_to_string(&golden_path).unwrap_or_else(|_| {
            panic!("missing golden for {file}; run with UPDATE_GOLDEN=1 to create it")
        });
        assert_eq!(
            actual_pretty.trim(),
            expected.trim(),
            "AST summary for {file} drifted; re-run with UPDATE_GOLDEN=1 if intended"
        );
    }
}
