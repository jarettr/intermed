//! CLI-facing code generation entry points — now IR-driven.
//!
//! Each rule lowers to the columnar query IR ([`rule_to_ir`](crate::rule_to_ir)) and
//! the IR is rendered by the shared backends ([`to_sql`](intermed_columnar::to_sql) /
//! [`to_datalog`](intermed_columnar::to_datalog)). This replaces the bespoke
//! `sql_codegen` / `datalog_codegen` translators with a single source of truth.

use intermed_columnar::{FACT_SCHEMA, QueryEngine, Statistics, explain, to_datalog, to_sql};
use intermed_doctor_core::facts::Fact;

use crate::model::RulePack;
use crate::{Lowering, rule_to_ir};

/// Backend target for `intermed rules generate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateBackend {
    Sql,
    Rust,
    Datalog,
    /// The columnar query engine's `EXPLAIN` (logical + optimized + physical plan +
    /// required engines) for each lowerable rule — for trust/debugging (Phase 3.3).
    Explain,
}

fn rel_name(i: usize) -> String {
    format!("r{i}")
}

/// IR for a rule, or `None` when it is not lowerable (then no artifact is emitted —
/// the interpreter remains the engine for that rule).
fn ir_of(rule: &crate::model::RuleSpec) -> Option<intermed_columnar::RelExpr> {
    match rule_to_ir(rule) {
        Lowering::Ir(e) => Some(e),
        Lowering::Unsupported(_) => None,
    }
}

/// Generate artifacts for every rule in `pack`.
pub fn generate_rules(pack: &RulePack, backend: GenerateBackend) -> String {
    match backend {
        GenerateBackend::Sql => {
            let mut out = String::new();
            for rule in &pack.rules {
                if let Some(sql) = ir_of(rule).and_then(|ir| to_sql(&ir)) {
                    out.push_str(&format!("-- rule: {}\n{sql}\n\n", rule.id));
                }
            }
            out
        }
        GenerateBackend::Datalog => {
            let mut out = String::from(FACT_SCHEMA);
            for (i, rule) in pack.rules.iter().enumerate() {
                if let Some(clause) = ir_of(rule).and_then(|ir| to_datalog(&ir, &rel_name(i))) {
                    out.push_str(&format!("// rule: {}\n{clause}", rule.id));
                }
            }
            out
        }
        // Static EXPLAIN per rule (no facts ⇒ empty statistics).
        GenerateBackend::Explain => explain_plans(pack, None, None),
        GenerateBackend::Rust => generate_rust_stubs(pack),
    }
}

/// Render the query-engine plan for each lowerable rule (optionally just `rule_id`).
///
/// Without `facts` this is a static `EXPLAIN` (logical → optimized → physical →
/// engines, empty statistics). With `facts`, it builds a [`QueryEngine`] over them and
/// additionally runs `EXPLAIN ANALYZE` — real per-operator cardinalities and timings —
/// for the plans the in-process engine executes (SQL-only shapes show the plan only).
pub fn explain_plans(pack: &RulePack, rule_id: Option<&str>, facts: Option<&[Fact]>) -> String {
    let engine = facts.and_then(|f| QueryEngine::from_facts(f).ok());
    let mut out = String::new();
    for rule in &pack.rules {
        if rule_id.is_some_and(|id| rule.id != id) {
            continue;
        }
        let Some(ir) = ir_of(rule) else {
            continue;
        };
        out.push_str(&format!("# rule: {}\n", rule.id));
        match &engine {
            Some(eng) => {
                out.push_str(&eng.explain(&ir));
                match eng.explain_analyze(&ir) {
                    Ok(analyze) => {
                        out.push('\n');
                        out.push_str(&analyze);
                    }
                    Err(e) => out.push_str(&format!("(EXPLAIN ANALYZE unavailable: {e})\n")),
                }
            }
            None => out.push_str(&explain(&ir, &Statistics::empty())),
        }
        out.push('\n');
    }
    out
}

fn generate_rust_stubs(pack: &RulePack) -> String {
    let mut out = String::from(
        "// Generated declarative rule stubs — evaluate via DeclarativeRulePack interpreter.\n",
    );
    for rule in &pack.rules {
        out.push_str(&format!(
            "/// Rule `{}` (kind: {:?})\npub const {}: &str = {:?};\n\n",
            rule.id,
            rule.kind,
            rule.id.replace('-', "_").to_uppercase(),
            rule.id
        ));
    }
    out
}

/// Generate SQL for one rule id when present and lowerable.
pub fn generate_rule_sql(pack: &RulePack, rule_id: &str) -> Option<String> {
    let rule = pack.rules.iter().find(|r| r.id == rule_id)?;
    to_sql(&ir_of(rule)?)
}

/// Per-rule Datalog clauses (id, clause) for lowerable rules.
pub fn generate_rule_datalog_list(pack: &RulePack) -> Vec<(String, String)> {
    pack.rules
        .iter()
        .enumerate()
        .filter_map(|(i, rule)| {
            ir_of(rule)
                .and_then(|ir| to_datalog(&ir, &rel_name(i)))
                .map(|dl| (rule.id.clone(), dl))
        })
        .collect()
}
