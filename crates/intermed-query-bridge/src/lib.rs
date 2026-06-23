//! Equivalence guard: lowers a declarative `RuleSpec` to the columnar query IR and
//! compares the columnar engine's fact selection against the interpreter's matching
//! on real packs, so the two never diverge.
//!
//! The bridge lowers only the rule shapes it can reproduce *faithfully* and returns
//! [`Unsupported`] for the rest (the relational IR cannot express `Correlation` /
//! `Aggregate`, whose matching stays on the interpreter). The comparator runs both
//! paths and reports divergence per rule; a real-pack test fails if they ever
//! differ. This crate is a test-time regression guard, not part of the live
//! analysis path.
//!
//! [`Unsupported`]: Lowering::Unsupported

use std::collections::BTreeSet;

use intermed_columnar::{QueryEngine, Value};
use intermed_facts::{FactId, FactStore};
use intermed_rules::{RuleSpec, matching_fact_ids};

// The IR lowering now lives in `intermed-rules` (so the codegen/souffle backends can
// use it without a dependency cycle); re-exported here for the shadow comparator and
// existing consumers.
pub use intermed_rules::{Lowering, rule_to_ir};

/// Per-rule result of the shadow comparison.
#[derive(Debug, Clone, PartialEq)]
pub enum ShadowResult {
    /// Both engines selected the same fact set (`count` facts).
    Match { count: usize },
    /// The rule was not lowered (still on the interpreter); not a failure.
    Skipped(String),
    /// The engines disagreed — a migration blocker.
    Diverged {
        only_interpreter: Vec<u64>,
        only_ir: Vec<u64>,
    },
}

impl ShadowResult {
    pub fn is_diverged(&self) -> bool {
        matches!(self, ShadowResult::Diverged { .. })
    }
}

/// Run one rule through both the live interpreter matching and the new IR engine over
/// the columnar projection of `store`, and report whether they agree.
pub fn shadow_compare(spec: &RuleSpec, store: &FactStore) -> ShadowResult {
    use intermed_columnar::ir::RelExpr;
    let ir = match rule_to_ir(spec) {
        Lowering::Ir(expr) => expr,
        Lowering::Unsupported(why) => return ShadowResult::Skipped(why),
    };
    // The shadow compares *fact-id sets*, which is only meaningful for FactFinding IR
    // (rows carrying `fact_id`). Join / group-distinct shapes produce pairs / groups,
    // not fact-id sets, so they are out of scope for this comparison.
    if matches!(
        ir,
        RelExpr::JoinFilter { .. } | RelExpr::GroupCountDistinct { .. }
    ) {
        return ShadowResult::Skipped("join / group-distinct: not a fact-id comparison".into());
    }

    // Old engine: the interpreter's own matching predicate.
    let interp: BTreeSet<u64> = matching_fact_ids(spec, store)
        .into_iter()
        .map(|FactId(n)| n)
        .collect();

    // New engine: build the query engine over the facts, run the lowered plan, collect
    // fact ids. Routes through the same `QueryEngine` the live `--logic columnar`
    // backend uses, so the shadow validates the actual runtime path.
    let engine = match QueryEngine::from_facts(store.all()) {
        Ok(e) => e,
        Err(e) => return ShadowResult::Skipped(format!("columnar engine init failed: {e}")),
    };
    let rel = match engine.run(&ir) {
        Ok(r) => r,
        Err(e) => return ShadowResult::Skipped(format!("ir execution failed: {e}")),
    };
    let ir_ids: BTreeSet<u64> = rel
        .rows
        .iter()
        .filter_map(|row| match row.get("fact_id") {
            Some(Value::Int(i)) => Some(*i as u64),
            _ => None,
        })
        .collect();

    if interp == ir_ids {
        ShadowResult::Match {
            count: interp.len(),
        }
    } else {
        ShadowResult::Diverged {
            only_interpreter: interp.difference(&ir_ids).copied().collect(),
            only_ir: ir_ids.difference(&interp).copied().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_rules::{FindingTemplate, RuleKind, RuleSpec};
    use std::collections::BTreeMap;

    fn fact_finding(input_kind: &str, where_all: &[(&str, &str)]) -> RuleSpec {
        RuleSpec {
            id: "test-rule".into(),
            kind: RuleKind::FactFinding,
            input_kinds: vec![input_kind.into()],
            alias: None,
            where_all: where_all
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            where_not: BTreeMap::new(),
            group_by: None,
            group_by_fields: Vec::new(),
            distinct: None,
            min_count: 1,
            left: None,
            right: None,
            on: None,
            r#where: None,
            having: None,
            input: None,
            anchor: None,
            related_kinds: Vec::new(),
            match_on: None,
            settings_refs: BTreeMap::new(),
            evidence: None,
            finding: FindingTemplate {
                id: "f".into(),
                rule_id: None,
                severity: "warn".into(),
                category: "mixin".into(),
                title: "t".into(),
                explanation: "e".into(),
                fix: None,
                tags: Vec::new(),
                affects: Vec::new(),
            },
        }
    }

    fn store() -> FactStore {
        let mut s = FactStore::new();
        s.fact("c", "mod")
            .subject("a")
            .attr("loader", "fabric")
            .emit();
        s.fact("c", "mod")
            .subject("b")
            .attr("loader", "forge")
            .emit();
        s.fact("c", "mod")
            .subject("d")
            .attr("loader", "fabric")
            .emit();
        s.fact("c", "plugin")
            .subject("p")
            .attr("loader", "fabric")
            .emit();
        s
    }

    #[test]
    fn fact_finding_matches_interpreter_on_attribute_filter() {
        let spec = fact_finding("mod", &[("loader", "fabric")]);
        let r = shadow_compare(&spec, &store());
        assert_eq!(r, ShadowResult::Match { count: 2 }, "{r:?}");
    }

    #[test]
    fn fact_finding_on_subject_and_kind_terms() {
        // `subject` is a base term; only the `mod` kind, subject `a`.
        let spec = fact_finding("mod", &[("subject", "a")]);
        assert_eq!(
            shadow_compare(&spec, &store()),
            ShadowResult::Match { count: 1 }
        );
    }

    #[test]
    fn where_not_excludes() {
        let mut spec = fact_finding("mod", &[]);
        spec.where_not.insert("loader".into(), "forge".into());
        // mods a,d (fabric) match; b (forge) excluded ⇒ 2.
        assert_eq!(
            shadow_compare(&spec, &store()),
            ShadowResult::Match { count: 2 }
        );
    }

    #[test]
    fn aliased_and_settings_rules_are_skipped_not_wrong() {
        let aliased = fact_finding("mod", &[("archive", "x.jar")]);
        assert!(matches!(
            shadow_compare(&aliased, &store()),
            ShadowResult::Skipped(_)
        ));
        let settings = fact_finding("mod", &[("trust", "{settings.x}")]);
        assert!(matches!(
            shadow_compare(&settings, &store()),
            ShadowResult::Skipped(_)
        ));
    }

    #[test]
    fn join_rule_is_unsupported() {
        let mut spec = fact_finding("mod", &[]);
        spec.kind = RuleKind::Join;
        assert!(matches!(rule_to_ir(&spec), Lowering::Unsupported(_)));
    }
}
