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

use std::collections::BTreeMap;

use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};
use intermed_facts::FactStore;
use intermed_rules::{ColumnarRulePack, RULE_PACK_SCHEMA_V3, RulePack, RuleSpec, evaluate_pack};

// The IR lowering now lives in `intermed-rules` (so the codegen/souffle backends can
// use it without a dependency cycle); re-exported here for the shadow comparator and
// existing consumers.
pub use intermed_rules::{Lowering, rule_to_ir};

/// Per-rule result of the shadow comparison.
#[derive(Debug, Clone, PartialEq)]
pub enum ShadowResult {
    /// Both engines selected the same fact set (`count` facts).
    Match { count: usize },
    /// The rule is outside the faithfully lowered IR subset; interpreter routing is
    /// expected and not a backend failure.
    Unsupported(String),
    /// A backend claimed the lowered shape but failed to initialize or execute it.
    ExecutionFailed(String),
    /// The engines disagreed — a migration blocker.
    Diverged {
        only_interpreter: Vec<String>,
        only_ir: Vec<String>,
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
    match rule_to_ir(spec) {
        Lowering::Ir(_) => {}
        Lowering::Unsupported(why) => return ShadowResult::Unsupported(why),
    };

    let pack = RulePack {
        schema: RULE_PACK_SCHEMA_V3.to_string(),
        id: "shadow-rule".to_string(),
        version: "0".to_string(),
        publisher: None,
        rules: vec![spec.clone()],
        signature: None,
    };
    let target = Target::with_kind(".", TargetKind::ModsDir);
    let ctx = RuleCtx::for_test(store, &target);
    let interp = finding_multiset(evaluate_pack(&pack, &ctx));
    let ir = match ColumnarRulePack::new(pack).evaluate(&ctx) {
        Ok(findings) => finding_multiset(findings),
        Err(error) => {
            return ShadowResult::ExecutionFailed(format!("columnar execution failed: {error}"));
        }
    };

    if interp == ir {
        ShadowResult::Match {
            count: interp.values().sum(),
        }
    } else {
        ShadowResult::Diverged {
            only_interpreter: multiset_difference(&interp, &ir),
            only_ir: multiset_difference(&ir, &interp),
        }
    }
}

fn finding_multiset(
    findings: Vec<intermed_doctor_core::evidence::Finding>,
) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for mut finding in findings {
        finding.machine_tags.retain(|tag| tag != "columnar");
        finding.machine_tags.sort();
        finding.evidence.sort_by_key(|edge| {
            (
                edge.fact.0,
                format!("{:?}", edge.relation),
                edge.weight.to_bits(),
            )
        });
        let key = serde_json::to_string(&finding).expect("Finding is serializable");
        *out.entry(key).or_default() += 1;
    }
    out
}

fn multiset_difference(
    left: &BTreeMap<String, usize>,
    right: &BTreeMap<String, usize>,
) -> Vec<String> {
    let mut difference = Vec::new();
    for (row, left_count) in left {
        let excess = left_count.saturating_sub(right.get(row).copied().unwrap_or(0));
        difference.extend(std::iter::repeat_n(row.clone(), excess));
    }
    difference
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_rules::{FactSource, FindingTemplate, RuleKind, RuleSpec};
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
            assessment: None,
            finding: FindingTemplate {
                id: "f".into(),
                rule_id: None,
                severity: "warn".into(),
                category: "mixin".into(),
                visibility: "default".into(),
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
    fn where_not_routes_to_reference_until_null_semantics_are_explicit() {
        let mut spec = fact_finding("mod", &[]);
        spec.where_not.insert("loader".into(), "forge".into());
        assert!(matches!(
            shadow_compare(&spec, &store()),
            ShadowResult::Unsupported(_)
        ));
    }

    #[test]
    fn aliased_and_settings_rules_are_skipped_not_wrong() {
        let aliased = fact_finding("mod", &[("archive", "x.jar")]);
        assert!(matches!(
            shadow_compare(&aliased, &store()),
            ShadowResult::Unsupported(_)
        ));
        let settings = fact_finding("mod", &[("trust", "{settings.x}")]);
        assert!(matches!(
            shadow_compare(&settings, &store()),
            ShadowResult::Unsupported(_)
        ));
    }

    #[test]
    fn join_rule_is_unsupported() {
        let mut spec = fact_finding("mod", &[]);
        spec.kind = RuleKind::Join;
        assert!(matches!(rule_to_ir(&spec), Lowering::Unsupported(_)));
    }

    #[test]
    fn join_and_group_distinct_are_part_of_the_shadow_gate() {
        let mut join = fact_finding("mod", &[]);
        join.kind = RuleKind::Join;
        join.input_kinds.clear();
        join.left = Some(FactSource {
            kind: "mod".into(),
            alias: "m".into(),
            select: vec![],
        });
        join.right = Some(FactSource {
            kind: "plugin".into(),
            alias: "p".into(),
            select: vec![],
        });
        join.on = Some("m.attr:loader = p.attr:loader".into());
        assert_eq!(
            shadow_compare(&join, &store()),
            ShadowResult::Match { count: 2 }
        );

        let mut grouped_store = FactStore::new();
        for (subject, loader, side) in [
            ("a", "fabric", "client"),
            ("c", "forge", "client"),
            ("d", "forge", "client"),
            ("ignored", "fabric", "server"),
        ] {
            grouped_store
                .fact("c", "mod")
                .subject(subject)
                .attr("loader", loader)
                .attr("side", side)
                .emit();
        }
        let mut group = fact_finding("mod", &[("attr:side", "client")]);
        group.kind = RuleKind::GroupDistinct;
        group.group_by = Some("attr:loader".into());
        group.distinct = Some("subject".into());
        group.min_count = 2;
        assert_eq!(
            shadow_compare(&group, &grouped_store),
            ShadowResult::Match { count: 1 }
        );
    }

    #[test]
    fn multiset_diagnostic_reports_only_excess_multiplicity() {
        let left = BTreeMap::from([("x".to_string(), 2)]);
        let right = BTreeMap::from([("x".to_string(), 1)]);
        assert_eq!(multiset_difference(&left, &right), vec!["x"]);
        assert!(multiset_difference(&right, &left).is_empty());
    }
}
