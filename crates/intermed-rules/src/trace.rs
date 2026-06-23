//! Dry-run tracing for declarative rule evaluation (debugging rule packs).

use intermed_doctor_core::RuleCtx;

use crate::interpreter::evaluate_pack;
use crate::model::{RuleKind, RulePack};

/// Per-rule trace line from a dry-run evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTraceLine {
    pub rule_id: String,
    pub kind: String,
    pub input_facts: usize,
    pub findings: usize,
    pub note: String,
}

/// Evaluate `pack` over `ctx` and return human-readable trace lines.
///
/// Used by `intermed rules check --trace` to debug why a rule did or did not fire
/// without emitting a full doctor report.
pub fn trace_pack(pack: &RulePack, ctx: &RuleCtx<'_>) -> Vec<RuleTraceLine> {
    let mut lines = Vec::with_capacity(pack.rules.len());
    for spec in &pack.rules {
        let input_facts = count_input_facts(ctx, spec);
        let mini = RulePack {
            schema: pack.schema.clone(),
            id: pack.id.clone(),
            version: pack.version.clone(),
            publisher: pack.publisher.clone(),
            signature: None,
            rules: vec![spec.clone()],
        };
        let findings = evaluate_pack(&mini, ctx);
        let note = match spec.kind {
            RuleKind::Join => format!(
                "left={:?} right={:?} on={}",
                spec.left.as_ref().map(|l| l.kind.as_str()),
                spec.right.as_ref().map(|r| r.kind.as_str()),
                spec.on.as_deref().unwrap_or("TRUE")
            ),
            RuleKind::Correlation => format!(
                "anchor={:?} related={:?} match_on={}",
                spec.anchor.as_ref().map(|a| a.kind.as_str()),
                spec.related_kinds.join(","),
                spec.match_on.as_deref().unwrap_or("TRUE")
            ),
            _ => String::new(),
        };
        lines.push(RuleTraceLine {
            rule_id: spec.id.clone(),
            kind: format!("{:?}", spec.kind).to_ascii_lowercase(),
            input_facts,
            findings: findings.len(),
            note,
        });
    }
    lines
}

fn count_input_facts(ctx: &RuleCtx<'_>, spec: &crate::RuleSpec) -> usize {
    match spec.kind {
        RuleKind::Join => {
            let left = spec
                .left
                .as_ref()
                .map(|l| ctx.store.by_kind(&l.kind).count())
                .unwrap_or(0);
            let right = spec
                .right
                .as_ref()
                .map(|r| ctx.store.by_kind(&r.kind).count())
                .unwrap_or(0);
            left.saturating_add(right)
        }
        RuleKind::Correlation => {
            let anchor = spec
                .anchor
                .as_ref()
                .map(|a| ctx.store.by_kind(&a.kind).count())
                .unwrap_or(0);
            let related: usize = spec
                .related_kinds
                .iter()
                .map(|k| ctx.store.by_kind(k).count())
                .sum();
            anchor.saturating_add(related)
        }
        RuleKind::Aggregate => spec
            .input
            .as_ref()
            .map(|i| ctx.store.by_kind(&i.kind).count())
            .unwrap_or(0),
        _ => {
            if spec.input_kinds.is_empty() {
                ctx.store.len()
            } else {
                spec.input_kinds
                    .iter()
                    .map(|k| ctx.store.by_kind(k).count())
                    .sum()
            }
        }
    }
}

/// Render trace lines as plain text for CLI output.
pub fn format_trace(lines: &[RuleTraceLine]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(&format!(
            "{:<24} {:<18} inputs={:<6} findings={}{}\n",
            line.rule_id,
            line.kind,
            line.input_facts,
            line.findings,
            if line.note.is_empty() {
                String::new()
            } else {
                format!("  ({})", line.note)
            }
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::default_core_pack_v2;
    use intermed_doctor_core::facts::{FactStore, kind};
    use intermed_doctor_core::{Target, TargetKind};

    #[test]
    fn trace_runs_without_panic() {
        let mut store = FactStore::new();
        store.fact("t", kind::MOD).subject("a").emit();
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        let pack = default_core_pack_v2();
        let lines = trace_pack(&pack, &ctx);
        assert!(!lines.is_empty());
    }
}
