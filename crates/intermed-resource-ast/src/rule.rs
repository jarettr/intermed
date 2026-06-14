//! Layer-M rules: turn the compact semantic facts into findings.
//!
//! Rules are the *only* place Layer M draws conclusions. They read the facts the
//! collector emitted (`resource_semantic_diff`, …) and never re-parse resources.
//! The rule set is deliberately conservative — every finding here corresponds to a
//! behaviour-changing disagreement the byte-level Layer E cannot see, so it adds
//! signal without adding false positives.

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::{kind, Fact};
use intermed_doctor_core::{Rule, RuleCtx};

use crate::semantic::diff::DiffKind;

/// Number of example ids shown inline before truncating with "(+N more)".
const SAMPLE_LIMIT: usize = 6;

/// The Layer-M semantic-diff rule.
#[must_use]
pub fn rule() -> impl Rule {
    ResourceSemanticRule
}

pub struct ResourceSemanticRule;

impl Rule for ResourceSemanticRule {
    fn id(&self) -> &'static str {
        "resource-semantics"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let diffs: Vec<&Fact> = ctx.store.by_kind(kind::RESOURCE_SEMANTIC_DIFF).collect();
        let mut findings = Vec::new();
        findings.extend(recipe_output_findings(&diffs));
        if let Some(f) = lang_conflict_finding(&diffs) {
            findings.push(f);
        }
        findings
    }
}

// NOTE on dangling model references: we deliberately do *not* raise a finding for
// a model whose parent/model target has no file in the pack. Mods routinely
// generate models at runtime (AE2 formed multiblocks, custom model loaders, baked
// models) or pull them from resource packs, so an absent file is not proof of a
// broken reference. Flagging it produced confirmed false positives on real packs
// (e.g. `ae2:block/crafting/monitor_formed`). The reference graph still records
// these as *unresolved* (see `ResourceGraph::unresolved_model_references`) for the
// `vfs explain --ast` view, clearly labelled as "may be runtime-generated" — but
// that is information, not a conclusion.

/// One finding per recipe whose writers craft *different outputs* — a real change
/// to what a player obtains, decided silently by load order. These are rare and
/// individually actionable, so they are not grouped.
fn recipe_output_findings(diffs: &[&Fact]) -> Vec<Finding> {
    diffs
        .iter()
        .filter(|f| diff_kind(f) == Some(DiffKind::RecipeOutputOverride))
        .map(|f| {
            let path = f.subject.as_str();
            let writers = f.attr("writers").unwrap_or_default();
            let detail = f.attr("detail").unwrap_or_default();
            Finding::builder(
                "resource-semantics",
                format!("recipe-output-override:{path}"),
            )
            .severity(Severity::Warn)
            .category(Category::Resource)
            .title(format!("Recipe `{path}` resolves to different outputs depending on load order"))
            .explanation(format!(
                "Multiple mods ({writers}) define the recipe at `{path}` with different results \
                 ({detail}). A recipe file is a single document: the runtime keeps exactly one by \
                 load order, so which item you actually craft is decided non-deterministically by \
                 mod ordering — a silent gameplay change, not a mergeable conflict."
            ))
            .affects(path.to_string())
            .fix(FixCandidate::advice(
                "Decide which mod should own this recipe and remove or data-pack-override the \
                 other(s); do not rely on load order to pick the winner.",
            ))
            .tag("resource")
            .tag("recipe")
            .tag("override")
            .evidence(EvidenceEdge::subject(f.id))
            .confidence(0.9)
            .build()
        })
        .collect()
}

/// One grouped Note for locale keys that map to different translations across
/// writers. Cosmetic (the wrong tooltip text may show), so it is a single
/// low-severity finding listing the affected files rather than per-file noise.
fn lang_conflict_finding(diffs: &[&Fact]) -> Option<Finding> {
    let conflicts: Vec<&&Fact> = diffs
        .iter()
        .filter(|f| diff_kind(f) == Some(DiffKind::LangKeyConflict))
        .collect();
    if conflicts.is_empty() {
        return None;
    }

    let mut paths: Vec<&str> = conflicts.iter().map(|f| f.subject.as_str()).collect();
    paths.sort_unstable();
    paths.dedup();
    let shown: Vec<&str> = paths.iter().take(SAMPLE_LIMIT).copied().collect();
    let extra = paths.len().saturating_sub(shown.len());
    let suffix = if extra > 0 {
        format!(" (+{extra} more)")
    } else {
        String::new()
    };

    let mut builder = Finding::builder("resource-semantics", "lang-key-conflict")
        .severity(Severity::Note)
        .category(Category::Resource)
        .title(format!(
            "{} locale file(s) map shared keys to different text across mods",
            paths.len()
        ))
        .explanation(format!(
            "These locale files are written by more than one mod with the *same* translation key \
             bound to *different* text: {}{}. The displayed string is decided by load order, so a \
             tooltip or item name may silently change. This is cosmetic (no crash), but worth a \
             deliberate winner if the text matters.",
            shown.join(", "),
            suffix
        ))
        .fix(FixCandidate::advice(
            "If the differing text matters, override the key in a resource pack so it no longer \
             depends on mod load order.",
        ))
        .tag("resource")
        .tag("lang")
        .tag("override");
    for f in &conflicts {
        builder = builder.evidence(EvidenceEdge::subject(f.id));
    }
    for p in shown {
        builder = builder.affects(p.to_string());
    }
    Some(builder.confidence(0.8).build())
}

fn diff_kind(f: &Fact) -> Option<DiffKind> {
    match f.attr("diff_kind") {
        Some("recipe-output-override") => Some(DiffKind::RecipeOutputOverride),
        Some("lang-key-conflict") => Some(DiffKind::LangKeyConflict),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::FactStore;
    use intermed_doctor_core::{Target, TargetKind};

    fn test_target() -> Target {
        Target {
            path: "/tmp".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        }
    }

    fn diff_fact(store: &mut FactStore, path: &str, kind_str: &str, writers: &str, detail: &str) {
        store
            .fact("resource-ast-scanner", kind::RESOURCE_SEMANTIC_DIFF)
            .subject(path.to_string())
            .attr("diff_kind", kind_str)
            .attr("writers", writers)
            .attr("detail", detail)
            .emit();
    }

    #[test]
    fn recipe_override_warns_per_recipe() {
        let mut store = FactStore::new();
        diff_fact(
            &mut store,
            "data/create/recipe/x.json",
            "recipe-output-override",
            "create,createaddition",
            "conflicting outputs: a:x, b:y",
        );
        let target = test_target();
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = ResourceSemanticRule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].machine_tags.iter().any(|t| t == "recipe"));
    }

    #[test]
    fn lang_conflicts_group_into_one_note() {
        let mut store = FactStore::new();
        diff_fact(&mut store, "assets/c/lang/en_us.json", "lang-key-conflict", "a,b", "1 key");
        diff_fact(&mut store, "assets/d/lang/en_us.json", "lang-key-conflict", "a,b", "2 keys");
        let target = test_target();
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = ResourceSemanticRule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Note);
    }

    #[test]
    fn no_diffs_no_findings() {
        let store = FactStore::new();
        let target = test_target();
        let ctx = RuleCtx::for_test(&store, &target);
        assert!(ResourceSemanticRule.evaluate(&ctx).is_empty());
    }
}
