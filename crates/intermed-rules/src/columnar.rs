//! In-process **columnar** backend — runs the declarative pack on the query engine.
//!
//! This is the default Layer-J backend (`--logic columnar`) and the only in-process
//! one; Soufflé and DuckDB are the external alternatives. Facts are projected once
//! into the Arrow [`ColumnarStore`]; every IR-lowerable rule (`FactFinding` / `Join`
//! / `GroupDistinct`) is lowered via [`rule_to_ir`](crate::rule_to_ir) and executed
//! by the optimizing columnar [`execute`](intermed_columnar::execute)
//! (predicate/projection pushdown, hash join/aggregate, streaming). Matched rows are
//! turned into findings by the shared finding builders
//! ([`fact_finding_findings`](crate::fact_finding_findings),
//! [`join_findings`](crate::join_findings),
//! [`group_distinct_findings`](crate::group_distinct_findings)), so findings are
//! identical across backends by construction. The relational IR cannot express
//! `Correlation` / `Aggregate`; those rules keep their matching on the residual
//! interpreter path ([`evaluate_pack`](crate::evaluate_pack)), so coverage stays
//! complete.
//!
//! Unlike Soufflé/DuckDB this backend needs no external tool and no extra build
//! feature — the engine is pure Rust — so it is always available.

use intermed_columnar::{QueryEngine, RelExpr, Value};
use intermed_doctor_core::evidence::{Category, Finding, Severity};
use intermed_doctor_core::facts::{Fact, FactId};
use intermed_doctor_core::{Rule, RuleCtx};

use crate::model::{RuleKind, RulePack};
use crate::pack::default_core_pack_v2;
use crate::{Lowering, RulePackError, evaluate_pack, fact_finding_findings, rule_to_ir};

/// In-process columnar Layer-J backend (`--logic columnar`).
///
/// Holds the **resolved** rule pack (the same one `DeclarativeRulePack` runs — honoring
/// `--mixin-risk`'s without-mixin selection and any installed overlays), so the columnar
/// backend evaluates exactly the rules the imperative path would, not a hardcoded pack.
pub struct ColumnarRulePack {
    pack: RulePack,
}

impl ColumnarRulePack {
    pub fn new(pack: RulePack) -> Self {
        Self { pack }
    }
}

impl Default for ColumnarRulePack {
    fn default() -> Self {
        Self::new(default_core_pack_v2())
    }
}

impl Rule for ColumnarRulePack {
    fn id(&self) -> &'static str {
        "columnar-rule-pack"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        match run_columnar(&self.pack, ctx) {
            Ok(findings) => findings,
            Err(e) => vec![
                Finding::builder("columnar-rule-pack", "columnar-backend-failed")
                    .severity(Severity::Fatal)
                    .category(Category::Runtime)
                    .title("Columnar backend failed")
                    .explanation(e.to_string())
                    .tag("logic")
                    .tag("columnar")
                    .build(),
            ],
        }
    }
}

fn run_columnar(pack: &RulePack, ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, RulePackError> {
    // Partition: every IR-lowerable rule (FactFinding / Join / GroupDistinct) runs on
    // the columnar engine; the rest (Correlation / Aggregate, which the IR does not
    // lower) fall back to the residual interpreter path.
    let mut engine_rules: Vec<&crate::model::RuleSpec> = Vec::new();
    let mut fallback = RulePack {
        rules: Vec::new(),
        ..pack.clone()
    };
    // Collect the kinds the engine plans actually scan, so the store materializes only
    // those (Phase 2: demand-driven build) — high-volume kinds nothing queries (e.g.
    // resource_reference) are skipped, the dominant build-cost win.
    let mut scanned_kinds: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for rule in &pack.rules {
        match rule_to_ir(rule) {
            Lowering::Ir(ir) => {
                ir.collect_scanned_kinds(&mut scanned_kinds);
                engine_rules.push(rule);
            }
            Lowering::Unsupported(_) => fallback.rules.push(rule.clone()),
        }
    }

    // The query engine projects the (pruned) facts + builds statistics once; all
    // engine rules run on it.
    let engine = QueryEngine::from_facts_for_kinds(ctx.store.all(), &scanned_kinds)
        .map_err(|e| RulePackError(format!("columnar engine init failed: {e}")))?;

    // One evidence cache shared across every emitted rule (so the rules that declare
    // the same related-evidence build the candidate index once for the whole pack).
    let evidence_cache = crate::EvidenceCache::new();
    let mut findings = Vec::new();
    for rule in &engine_rules {
        let Lowering::Ir(ir) = rule_to_ir(rule) else {
            continue;
        };
        let rel = engine.run(&ir).map_err(|e| {
            RulePackError(format!("columnar execution of `{}` failed: {e}", rule.id))
        })?;

        match rule.kind {
            RuleKind::Join => {
                let pairs: Vec<(u64, u64)> = rel
                    .rows
                    .iter()
                    .filter_map(
                        |row| match (row.get("left_fact_id"), row.get("right_fact_id")) {
                            (Some(Value::Int(l)), Some(Value::Int(r))) => {
                                Some((*l as u64, *r as u64))
                            }
                            _ => None,
                        },
                    )
                    .collect();
                findings.extend(crate::join_findings(rule, &pairs, ctx, &evidence_cache));
            }
            RuleKind::GroupDistinct => {
                let group_col = match &ir {
                    RelExpr::GroupCountDistinct { group_col, .. } => group_col.as_str(),
                    _ => "subject",
                };
                let groups: Vec<String> = rel
                    .rows
                    .iter()
                    .filter_map(|row| row.get(group_col).map(Value::to_display))
                    .collect();
                findings.extend(crate::group_distinct_findings(
                    rule,
                    &groups,
                    ctx,
                    &evidence_cache,
                ));
            }
            // FactFinding (and any other single-fact-id shape) emit from fact ids.
            _ => {
                let matched: Vec<&Fact> = rel
                    .rows
                    .iter()
                    .filter_map(|row| match row.get("fact_id") {
                        Some(Value::Int(n)) => Some(*n as u64),
                        _ => None,
                    })
                    .filter_map(|n| ctx.store.get(FactId(n)))
                    .collect();
                findings.extend(fact_finding_findings(rule, &matched, ctx, &evidence_cache));
            }
        }
    }

    // Residual interpreter path for the rule kinds the IR does not lower (Correlation).
    findings.extend(evaluate_pack(&fallback, ctx));

    for f in &mut findings {
        if !f.machine_tags.iter().any(|t| t == "columnar") {
            f.machine_tags.push("columnar".to_string());
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::FactStore;
    use intermed_doctor_core::{Target, TargetKind};

    fn test_target() -> Target {
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

    /// The columnar backend selects the same facts (and emits the same findings) as
    /// the interpreter for a simple FactFinding rule.
    #[test]
    fn columnar_backend_matches_interpreter_findings() {
        let mut store = FactStore::new();
        store
            .fact("c", "mixin_application_site")
            .subject("owo")
            .attr("operation", "overwrite")
            .attr("target_class", "net/minecraft/Foo")
            .emit();
        store
            .fact("c", "mixin_application_site")
            .subject("polymorph")
            .attr("operation", "inject")
            .attr("target_class", "net/minecraft/Bar")
            .emit();

        let target = test_target();
        let ctx = RuleCtx::for_test(&store, &target);

        let columnar = ColumnarRulePack::default().evaluate(&ctx);
        // Same pack via the interpreter.
        let interp = evaluate_pack(&default_core_pack_v2(), &ctx);

        let ids = |fs: &[Finding]| {
            let mut v: Vec<String> = fs.iter().map(|f| f.id.clone()).collect();
            v.sort();
            v
        };
        assert_eq!(ids(&columnar), ids(&interp));
        assert!(
            columnar
                .iter()
                .all(|f| f.machine_tags.iter().any(|t| t == "columnar"))
        );
    }
}
