//! SQL rule backend — DuckDB materializes facts; findings come from the declarative pack interpreter.
//!
//! Generated SQL ([`intermed_rules::sql_codegen`]) is available for analytics queries and
//! `intermed rules generate --backend sql`; row-to-finding mapping uses the same
//! [`intermed_rules::evaluate_pack`] path as imperative and Datalog modes.

#[cfg(feature = "duckdb")]
use std::collections::BTreeMap;

use intermed_doctor_core::evidence::{Category, Finding, Severity};
#[cfg(feature = "duckdb")]
use intermed_doctor_core::facts::{Fact, FactId};
use intermed_doctor_core::{Rule, RuleCtx};

#[cfg(feature = "duckdb")]
use intermed_rules::{default_core_pack_v2, evaluate_pack};

/// Whether this build linked embedded DuckDB.
#[must_use]
pub fn duckdb_available() -> bool {
    cfg!(feature = "duckdb")
}

/// Layer-J SQL rule pack (feature-gated implementation).
pub struct DuckdbRulePack;

impl DuckdbRulePack {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DuckdbRulePack {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DuckdbRulePack {
    fn id(&self) -> &'static str {
        "duckdb-rule-pack"
    }

    #[allow(unused_variables)]
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        #[cfg(feature = "duckdb")]
        {
            match run_duckdb_rules(ctx) {
                Ok(findings) => findings,
                Err(e) => vec![backend_failed_finding(e)],
            }
        }
        #[cfg(not(feature = "duckdb"))]
        {
            vec![backend_failed_finding(
                "DuckDB backend is not compiled in; rebuild with --features duckdb".into(),
            )]
        }
    }
}

fn backend_failed_finding(message: String) -> Finding {
    Finding::builder("duckdb-rule-pack", "duckdb-backend-failed")
        .severity(Severity::Fatal)
        .category(Category::Runtime)
        .title("DuckDB backend failed")
        .explanation(message)
        .tag("logic")
        .tag("duckdb")
        .build()
}

#[cfg(feature = "duckdb")]
fn run_duckdb_rules(ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, String> {
    use crate::schema::EVAL_RUN_ID;
    use crate::store::DuckStore;

    let facts: Vec<Fact> = ctx.store.all().to_vec();
    let store = DuckStore::open_in_memory().map_err(|e| e.to_string())?;
    store
        .materialize_facts(EVAL_RUN_ID, &facts)
        .map_err(|e| e.to_string())?;

    // Materialize facts into DuckDB (enables SQL analytics); evaluate findings via SSOT pack.
    let pack = default_core_pack_v2();
    let mut findings = evaluate_pack(&pack, ctx);
    for finding in &mut findings {
        if !finding.machine_tags.iter().any(|t| t == "duckdb") {
            finding.machine_tags.push("duckdb".to_string());
        }
    }

    // Security API aggregation still uses SQL row scan + Rust thresholding.
    findings.extend(read_security_signal_findings(ctx, &store)?);

    Ok(findings)
}

#[cfg(feature = "duckdb")]
fn read_security_signal_findings(
    ctx: &RuleCtx<'_>,
    store: &crate::store::DuckStore,
) -> Result<Vec<Finding>, String> {
    use crate::schema::EVAL_RUN_ID;
    use crate::sql::{self, SECURITY_SIGNALS};
    use intermed_security_audit::{
        security_findings_from_drafts, signal_for_fact_kind, SecurityModDraft,
    };

    let sql = sql::bind_run(SECURITY_SIGNALS, EVAL_RUN_ID);
    let result = store.query(&sql).map_err(|e| e.to_string())?;
    let mut drafts: BTreeMap<String, SecurityModDraft> = BTreeMap::new();
    for row in result.rows {
        if row.len() < 9 {
            continue;
        }
        let mod_id = row[0].clone();
        let signal_kind = row[1].as_str();
        let Some(signal) = signal_for_fact_kind(signal_kind) else {
            continue;
        };
        let fact_id = row[2]
            .parse::<u64>()
            .ok()
            .map(FactId)
            .or_else(|| fact_by_id(ctx, &row[2]).map(|f| f.id))
            .unwrap_or(FactId(0));
        let archive = row[3].as_str();
        let provenance = row[4].as_str();
        let evidence_strength = row[5].as_str();
        let dangerous_classes = row[6].parse::<i64>().ok();
        let classes_scanned = row[7].parse::<i64>().ok();
        let affected_classes = row[8].parse::<i64>().ok();
        let draft = drafts.entry(mod_id).or_default();
        draft.record_signal(
            signal,
            fact_id,
            archive,
            if provenance.is_empty() {
                None
            } else {
                Some(provenance)
            },
            if evidence_strength.is_empty() {
                None
            } else {
                Some(evidence_strength)
            },
            dangerous_classes,
            classes_scanned,
            affected_classes,
        );
    }
    for draft in drafts.values_mut() {
        draft.finalize_corroboration();
    }
    let mut findings =
        security_findings_from_drafts(drafts, ctx.settings.security.min_note_signals);
    for finding in &mut findings {
        finding.rule_id = "duckdb-security-api-risk".to_string();
        if !finding.machine_tags.iter().any(|t| t == "duckdb") {
            finding.machine_tags.push("duckdb".to_string());
        }
    }
    Ok(findings)
}

#[cfg(feature = "duckdb")]
fn fact_by_id<'a>(ctx: &'a RuleCtx<'_>, raw: &str) -> Option<&'a Fact> {
    raw.parse::<u64>().ok().and_then(|n| ctx.store.get(FactId(n)))
}