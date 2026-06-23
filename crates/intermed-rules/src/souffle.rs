//! External Soufflé backend — runs the declarative pack as Datalog.
//!
//! Generic, IR-driven (replaces the old 3-rule hand-coded `datalog_codegen`): facts
//! are written in the flat foreign-key shape (`fact` / `fact_attr`), every
//! `FactFinding` rule is lowered via [`rule_to_ir`](crate::rule_to_ir) →
//! [`to_datalog`](intermed_columnar::to_datalog) into one clause, Soufflé computes
//! the matching, and findings are emitted by the interpreter's
//! [`fact_finding_findings`](crate::fact_finding_findings) (so they are identical
//! across backends by construction). Rule kinds the IR doesn't lower yet
//! (Join/Aggregate/Correlation/GroupDistinct) fall back to the interpreter, so the
//! souffle backend is now *complete*, not a 3-rule proof of concept.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_columnar::{FACT_SCHEMA, to_datalog};
use intermed_doctor_core::evidence::Finding;
use intermed_doctor_core::facts::{AttrValue, Fact};
use intermed_doctor_core::{Rule, RuleCtx};

use crate::model::{RuleKind, RulePack};
use crate::pack::default_core_pack_v2;
use crate::tsv::escape_souffle_symbol;
use crate::{Lowering, RulePackError, evaluate_pack, fact_finding_findings, rule_to_ir};

/// Optional external Souffle backend. Holds the **resolved** rule pack (honoring
/// `--mixin-risk`'s without-mixin selection + installed overlays), like the other
/// backends — not a hardcoded default.
pub struct SouffleRulePack {
    pack: RulePack,
}

impl SouffleRulePack {
    pub fn new(pack: RulePack) -> Self {
        Self { pack }
    }
}

impl Default for SouffleRulePack {
    fn default() -> Self {
        Self::new(default_core_pack_v2())
    }
}

impl Rule for SouffleRulePack {
    fn id(&self) -> &'static str {
        "souffle-rule-pack"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        match run_souffle(&self.pack, ctx) {
            Ok(findings) => findings,
            Err(e) => vec![
                intermed_doctor_core::evidence::Finding::builder(
                    "souffle-rule-pack",
                    "souffle-backend-failed",
                )
                .severity(intermed_doctor_core::evidence::Severity::Fatal)
                .category(intermed_doctor_core::evidence::Category::Runtime)
                .title("Souffle backend failed")
                .explanation(e.to_string())
                .tag("logic")
                .tag("souffle")
                .build(),
            ],
        }
    }
}

pub fn souffle_available() -> bool {
    Command::new("souffle")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// The generated Soufflé program for the embedded core pack (schema + one clause per
/// IR-lowerable FactFinding rule). Exposed for `rules generate --backend datalog`.
pub fn souffle_program() -> String {
    let pack = default_core_pack_v2();
    let mut out = String::from(FACT_SCHEMA);
    for (i, rule) in pack.rules.iter().enumerate() {
        if let Lowering::Ir(ir) = rule_to_ir(rule) {
            if let Some(clause) = to_datalog(&ir, &rel_name(i)) {
                out.push_str(&clause);
            }
        }
    }
    out
}

fn rel_name(i: usize) -> String {
    format!("r{i}")
}

fn attr_str(v: &AttrValue) -> String {
    match v {
        AttrValue::Str(s) => s.clone(),
        AttrValue::Int(i) => i.to_string(),
        AttrValue::Float(f) => f.to_string(),
        AttrValue::Bool(b) => b.to_string(),
    }
}

/// Write the generic `fact` / `fact_attr` relations (one write covers every rule).
fn write_generic_facts(ctx: &RuleCtx<'_>, facts_dir: &Path) -> Result<(), RulePackError> {
    let mut fact = std::fs::File::create(facts_dir.join("fact.facts"))
        .map_err(|e| RulePackError(format!("write fact.facts: {e}")))?;
    let mut attr = std::fs::File::create(facts_dir.join("fact_attr.facts"))
        .map_err(|e| RulePackError(format!("write fact_attr.facts: {e}")))?;
    for f in ctx.store.all() {
        writeln!(
            fact,
            "{}\t{}\t{}",
            f.id.0,
            escape_souffle_symbol(&f.kind),
            escape_souffle_symbol(&f.subject)
        )
        .map_err(|e| RulePackError(format!("write fact.facts: {e}")))?;
        for (k, v) in &f.attributes {
            writeln!(
                attr,
                "{}\t{}\t{}",
                f.id.0,
                escape_souffle_symbol(k),
                escape_souffle_symbol(&attr_str(v))
            )
            .map_err(|e| RulePackError(format!("write fact_attr.facts: {e}")))?;
        }
    }
    Ok(())
}

fn run_souffle(pack: &RulePack, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, RulePackError> {
    let root = temp_souffle_dir();
    let facts_dir = root.join("facts");
    let out_dir = root.join("out");
    std::fs::create_dir_all(&facts_dir)
        .map_err(|e| RulePackError(format!("create {}: {e}", facts_dir.display())))?;
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| RulePackError(format!("create {}: {e}", out_dir.display())))?;

    let result = (|| {
        // Partition: IR-lowerable FactFinding rules run through Souffle; the rest fall
        // back to the interpreter (so coverage is complete).
        let mut souffle_rules: Vec<(usize, &crate::model::RuleSpec)> = Vec::new();
        let mut fallback = RulePack {
            rules: Vec::new(),
            ..pack.clone()
        };
        for (i, rule) in pack.rules.iter().enumerate() {
            match rule_to_ir(rule) {
                Lowering::Ir(_) if rule.kind == RuleKind::FactFinding => {
                    souffle_rules.push((i, rule));
                }
                _ => fallback.rules.push(rule.clone()),
            }
        }

        write_generic_facts(ctx, &facts_dir)?;

        // Build + run one program with a relation per Souffle rule.
        let mut program = String::from(FACT_SCHEMA);
        for (i, rule) in &souffle_rules {
            if let Lowering::Ir(ir) = rule_to_ir(rule) {
                if let Some(clause) = to_datalog(&ir, &rel_name(*i)) {
                    program.push_str(&clause);
                }
            }
        }
        let program_path = root.join("intermed_core.dl");
        std::fs::write(&program_path, &program)
            .map_err(|e| RulePackError(format!("write {}: {e}", program_path.display())))?;

        let output = Command::new("souffle")
            .arg(&program_path)
            .arg("-F")
            .arg(&facts_dir)
            .arg("-D")
            .arg(&out_dir)
            .output()
            .map_err(|e| RulePackError(format!("run souffle: {e}")))?;
        if !output.status.success() {
            return Err(RulePackError(format!(
                "souffle exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Souffle-matched FactFinding findings (emission reused from the interpreter).
        let evidence_cache = crate::EvidenceCache::new();
        let mut findings = Vec::new();
        for (i, rule) in &souffle_rules {
            let matched: Vec<&Fact> = read_relation(&out_dir, &rel_name(*i))
                .iter()
                .filter_map(|row| row.first())
                .filter_map(|id| id.parse::<u64>().ok())
                .filter_map(|n| ctx.store.get(intermed_doctor_core::facts::FactId(n)))
                .collect();
            findings.extend(fact_finding_findings(rule, &matched, ctx, &evidence_cache));
        }

        // Interpreter fallback for the rule kinds the IR does not lower yet.
        findings.extend(evaluate_pack(&fallback, ctx));

        for f in &mut findings {
            if !f.machine_tags.iter().any(|t| t == "souffle") {
                f.machine_tags.push("souffle".to_string());
            }
        }
        Ok(findings)
    })();

    let _ = std::fs::remove_dir_all(&root);
    result
}

fn read_relation(out_dir: &Path, relation: &str) -> Vec<Vec<String>> {
    let paths = [
        out_dir.join(format!("{relation}.csv")),
        out_dir.join(relation),
    ];
    let Some(path) = paths.iter().find(|path| path.is_file()) else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect()
}

fn temp_souffle_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("intermed-souffle-{}-{nanos}", std::process::id()))
}
