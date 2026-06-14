//! CLI-facing code generation entry points.

use crate::datalog_codegen::{generate_pack_datalog, generate_pack_datalog_rules};
use crate::model::RulePack;
use crate::sql_codegen::{generate_pack_sql, rule_to_sql};

/// Backend target for `intermed rules generate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateBackend {
    Sql,
    Rust,
    Datalog,
}

/// Generate artifacts for every rule in `pack`.
pub fn generate_rules(pack: &RulePack, backend: GenerateBackend) -> String {
    match backend {
        GenerateBackend::Sql => {
            let mut out = String::new();
            for entry in generate_pack_sql(pack) {
                out.push_str(&format!("-- rule: {}\n", entry.id));
                out.push_str(&entry.sql);
                out.push_str("\n\n");
            }
            out
        }
        GenerateBackend::Datalog => generate_pack_datalog(pack),
        GenerateBackend::Rust => generate_rust_stubs(pack),
    }
}

fn generate_rust_stubs(pack: &RulePack) -> String {
    let mut out = String::from(
        "// Generated declarative rule stubs — evaluate via DeclarativeRulePack interpreter.\n",
    );
    for rule in &pack.rules {
        out.push_str(&format!(
            "/// Rule `{}` (kind: {:?})\npub const {}: &str = {:?};\n\n",
            rule.id, rule.kind, rule.id.replace('-', "_").to_uppercase(), rule.id
        ));
    }
    out
}

/// Generate SQL for one rule id when present in `pack`.
pub fn generate_rule_sql(pack: &RulePack, rule_id: &str) -> Option<String> {
    pack.rules
        .iter()
        .find(|r| r.id == rule_id)
        .and_then(rule_to_sql)
}

/// Per-rule Datalog fragments.
pub fn generate_rule_datalog_list(pack: &RulePack) -> Vec<(String, String)> {
    generate_pack_datalog_rules(pack)
        .into_iter()
        .map(|r| (r.id, r.datalog))
        .collect()
}