//! Layer-M rules: turn the compact semantic facts into findings.
//!
//! Rules are the *only* place Layer M draws conclusions. They read the facts the
//! collector emitted (`resource_semantic_diff`, …) and never re-parse resources.
//! The rule set is deliberately conservative — every finding here corresponds to a
//! behaviour-changing disagreement the byte-level Layer E cannot see, so it adds
//! signal without adding false positives.

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::{Fact, kind};
use intermed_doctor_core::{Rule, RuleCtx};

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
        // Per-path semantic overrides (recipe / loot / atlas / model / blockstate).
        for f in &diffs {
            if let Some(finding) = per_path_override_finding(f) {
                findings.push(finding);
            }
        }
        // Lang key conflicts are grouped into one low-severity note.
        if let Some(f) = lang_conflict_finding(&diffs) {
            findings.push(f);
        }
        // Parse/validation issues → one grouped, explain-only finding (auditable,
        // never per-file noise).
        if let Some(f) = parse_issue_finding(ctx) {
            findings.push(f);
        }
        // Dangling datapack references (loot/advancement/tag only) → internal (Warn)
        // and cross-mod (Note) groups, calibrated by who owns the missing target.
        findings.extend(dangling_reference_findings(ctx));
        findings
    }
}

/// Relations safe to flag as dangling: datapack-resource → datapack-resource,
/// where a missing target file is a genuine (if low-confidence) datapack error.
/// **Models / textures / blockstates are excluded** — they are routinely
/// runtime-generated or shipped by resource packs, so absence is not proof of a
/// bug (the documented false-positive trap).
const SAFE_DANGLING_RELATIONS: &[&str] = &["loot_entry", "advancement_criterion", "uses_tag"];

/// Findings for references to a datapack resource not present in the pack, split by
/// who owns the missing target. An **internal** dangling — a mod referencing its own
/// namespace's missing loot/tag/advancement — is a likely typo/forgotten file the mod
/// controls (`Warn`). A **cross-mod** dangling — into another present mod's namespace
/// — is more often a version mismatch and may be satisfied by a runtime script
/// (`Note`). Both restricted to loot/advancement/tag targets (the model/texture
/// false-positive trap stays excluded). A short sample with a `(+N more)` suffix.
fn dangling_reference_findings(ctx: &RuleCtx<'_>) -> Vec<Finding> {
    let dangling: Vec<&Fact> = ctx
        .store
        .by_kind(kind::RESOURCE_DANGLING_REFERENCE)
        .filter(|f| {
            f.attr("relation")
                .is_some_and(|r| SAFE_DANGLING_RELATIONS.contains(&r))
        })
        .collect();
    if dangling.is_empty() {
        return Vec::new();
    }
    let (internal, cross): (Vec<&Fact>, Vec<&Fact>) = dangling
        .into_iter()
        .partition(|f| f.attr_bool("internal") == Some(true));

    let mut out = Vec::new();
    if let Some(f) = internal_dangling_finding(&internal) {
        out.push(f);
    }
    if let Some(f) = cross_dangling_finding(&cross) {
        out.push(f);
    }
    out
}

/// Sorted, deduplicated, truncated sample of the missing target ids with a `(+N)` tail.
fn dangling_sample(facts: &[&Fact]) -> (String, usize) {
    let mut targets: Vec<&str> = facts.iter().filter_map(|f| f.attr("to")).collect();
    targets.sort_unstable();
    targets.dedup();
    let shown: Vec<&str> = targets.iter().take(SAMPLE_LIMIT).copied().collect();
    let extra = targets.len().saturating_sub(shown.len());
    let suffix = if extra > 0 {
        format!(" (+{extra} more)")
    } else {
        String::new()
    };
    (format!("{}{}", shown.join(", "), suffix), targets.len())
}

/// A mod references its *own* namespace's missing resource — a typo or a file it
/// forgot to ship. The mod controls the namespace, so absence is a real defect, not
/// a soft cross-mod mismatch: `Warn`, higher confidence.
fn internal_dangling_finding(facts: &[&Fact]) -> Option<Finding> {
    if facts.is_empty() {
        return None;
    }
    let (sample, count) = dangling_sample(facts);
    let mut b = Finding::builder("resource-semantics", "dangling-reference-internal")
        .severity(Severity::Warn)
        .category(Category::Resource)
        .title(format!(
            "{count} reference(s) point to a resource the *same* mod does not ship"
        ))
        .explanation(format!(
            "These loot table / advancement / tag references resolve to a resource in the \
             referencing mod's own namespace that the mod does not ship: {sample}. Since the mod \
             owns the namespace, this is most likely a typo or a file left out of the build — a \
             real datapack defect rather than a cross-mod version mismatch. (A data-pack script \
             could still add it at load time.)"
        ))
        .fix(FixCandidate::advice(
            "Check the referenced id against the mod's own resources for a typo or a missing file.",
        ))
        .tag("resource")
        .tag("dangling-reference")
        .tag("internal");
    for f in facts {
        b = b.evidence(EvidenceEdge::subject(f.id));
    }
    Some(b.confidence(0.7).build())
}

/// A reference into *another* present mod's namespace whose target is absent — more
/// often a version mismatch or an optional/scripted target: `Note`, low confidence.
fn cross_dangling_finding(facts: &[&Fact]) -> Option<Finding> {
    if facts.is_empty() {
        return None;
    }
    let (sample, count) = dangling_sample(facts);
    // Name the owning mods when the fact recorded them (single-line, deduped).
    let mut owners: Vec<&str> = facts
        .iter()
        .filter_map(|f| f.attr("owners"))
        .flat_map(|o| o.split(',').filter(|s| !s.is_empty()))
        .collect();
    owners.sort_unstable();
    owners.dedup();
    let owner_clause = if owners.is_empty() {
        String::new()
    } else {
        format!(" (owned by {})", owners.join(", "))
    };
    let mut b = Finding::builder("resource-semantics", "dangling-reference")
        .severity(Severity::Note)
        .category(Category::Resource)
        .title(format!(
            "{count} datapack reference(s) point to a resource not present in the pack"
        ))
        .explanation(format!(
            "These loot table / advancement / tag references resolve to a resource that no \
             installed jar (nor the indexed vanilla jar) ships: {sample}{owner_clause}. The owning \
             namespace is present, so this is likely a version mismatch — but a data-pack script \
             (KubeJS/CraftTweaker) may add the target at load time, so treat it as a review item, \
             not a confirmed break."
        ))
        .fix(FixCandidate::advice(
            "Verify the referenced id exists for your mod versions, or that a script provides it.",
        ))
        .tag("resource")
        .tag("dangling-reference");
    for f in facts {
        b = b.evidence(EvidenceEdge::subject(f.id));
    }
    Some(b.confidence(0.55).build())
}

/// One grouped, explain-only finding summarising resource parse/validation issues
/// (`resource_semantic_issue` facts). Explain-only so a malformed datapack file is
/// auditable in `--explain` / JSON without adding a per-file warning to the
/// default report.
fn parse_issue_finding(ctx: &RuleCtx<'_>) -> Option<Finding> {
    use intermed_doctor_core::evidence::FindingVisibility;
    let issues: Vec<&Fact> = ctx.store.by_kind(kind::RESOURCE_SEMANTIC_ISSUE).collect();
    if issues.is_empty() {
        return None;
    }
    let mut paths: Vec<&str> = issues.iter().map(|f| f.subject.as_str()).collect();
    paths.sort_unstable();
    paths.dedup();
    let shown: Vec<&str> = paths.iter().take(SAMPLE_LIMIT).copied().collect();
    let extra = paths.len().saturating_sub(shown.len());
    let suffix = if extra > 0 {
        format!(" (+{extra} more)")
    } else {
        String::new()
    };
    let mut builder = Finding::builder("resource-semantics", "resource-parse-issues")
        .severity(Severity::Info)
        .category(Category::Resource)
        .visibility(FindingVisibility::ExplainOnly)
        .title(format!(
            "{} resource(s) had parse/validation issues",
            paths.len()
        ))
        .explanation(format!(
            "These resources did not fully parse for their domain (malformed JSON / unexpected \
             shape): {}{}. The game may log a data error for them. Informational — inspect with \
             `vfs explain --ast`.",
            shown.join(", "),
            suffix
        ))
        .tag("resource")
        .tag("parse-issue");
    for f in &issues {
        builder = builder.evidence(EvidenceEdge::subject(f.id));
    }
    Some(builder.confidence(0.7).build())
}

/// How a per-path semantic-diff kind is *presented* (title, fix, domain tag).
/// Severity is **not** here — it is derived centrally from the diff's impact (the
/// `severity`/`impact` attrs on the fact), so it never drifts per rule.
struct DiffPresentation {
    /// `{path}` is substituted with the resource path.
    title: &'static str,
    fix: &'static str,
    domain_tag: &'static str,
}

fn presentation(diff_kind: &str) -> Option<DiffPresentation> {
    let p = |title, fix, domain_tag| {
        Some(DiffPresentation {
            title,
            fix,
            domain_tag,
        })
    };
    match diff_kind {
        "recipe-output-override" => p(
            "Recipe `{path}` resolves to different outputs depending on load order",
            "Decide which mod should own this recipe and remove or data-pack-override the other(s); \
             do not rely on load order to pick the winner.",
            "recipe",
        ),
        "recipe-type-override" => p(
            "Recipe `{path}` uses a different serializer type across mods",
            "The same output is produced by different recipe types; only one survives by load \
             order. Choose the intended serializer.",
            "recipe",
        ),
        "recipe-ingredient-override" => p(
            "Recipe `{path}` produces the same output from different ingredients",
            "Often an intentional compatibility recipe. Confirm the intended inputs if it matters.",
            "recipe",
        ),
        "recipe-condition-override" => p(
            "Recipe `{path}` is gated by load conditions in only some mods",
            "A conditioned variant may be intentional; verify the condition matches your modset.",
            "recipe",
        ),
        "recipe-opaque-override" => p(
            "Recipe `{path}` uses a custom serializer whose payload differs across mods",
            "InterMed cannot interpret this custom recipe type, so it cannot say what changed — \
             only that the definitions differ. Review manually if it matters.",
            "recipe",
        ),
        "loot-table-output-override" => p(
            "Loot table `{path}` drops different items depending on load order",
            "Two mods define this loot table with different drops; only one survives. Choose the \
             intended owner.",
            "loot-table",
        ),
        "atlas-source-override" => p(
            "Atlas `{path}` texture sources are order-dependent",
            "Merge the atlas source lists into one file, or make one writer authoritative — a later \
             writer drops the earlier's sources.",
            "atlas",
        ),
        "model-override" => p(
            "Model `{path}` declares a different parent across mods",
            "Verify which model definition should win; models may also be runtime-generated.",
            "model",
        ),
        "blockstate-override" => p(
            "Blockstate `{path}` maps to different models across mods",
            "Verify which blockstate definition should win.",
            "blockstate",
        ),
        "advancement-override" => p(
            "Advancement `{path}` is defined differently across mods",
            "Only one advancement definition survives by load order; confirm the intended one.",
            "advancement",
        ),
        "predicate-override" => p(
            "Predicate `{path}` is defined differently across mods",
            "Only one predicate definition survives by load order; confirm the intended one.",
            "predicate",
        ),
        "item-modifier-override" => p(
            "Item modifier `{path}` is defined differently across mods",
            "Only one item-modifier definition survives by load order; confirm the intended one.",
            "item-modifier",
        ),
        "registry-object-override" => p(
            "Registry object `{path}` is defined differently across mods",
            "A datapack registry object is kept by load order; confirm which mod should own it.",
            "registry-object",
        ),
        _ => None,
    }
}

/// Parse the central `severity` attr the collector derived from the diff's impact.
fn severity_from_attr(s: Option<&str>) -> Severity {
    match s {
        Some("fatal") => Severity::Fatal,
        Some("error") => Severity::Error,
        Some("warn") => Severity::Warn,
        Some("info") => Severity::Info,
        _ => Severity::Note,
    }
}

/// Build one finding for a per-path semantic override diff fact.
fn per_path_override_finding(f: &Fact) -> Option<Finding> {
    let diff_kind = f.attr("diff_kind")?;
    let pres = presentation(diff_kind)?;
    let path = f.subject.as_str();
    let writers = f.attr("writers").unwrap_or_default();
    let detail = f.attr("detail").unwrap_or_default();
    let severity = severity_from_attr(f.attr("severity"));
    let impact_label = f.attr("impact").unwrap_or("gameplay-behavior");
    let title = pres.title.replace("{path}", path);
    let order_note = if severity >= Severity::Warn {
        "Which one wins is order-dependent — decided by mod/resource-pack load order, a silent \
         change rather than a mergeable conflict."
    } else {
        "Resolved by load order."
    };
    Some(
        Finding::builder("resource-semantics", format!("{diff_kind}:{path}"))
            .severity(severity)
            .category(Category::Resource)
            .title(title)
            .explanation(format!(
                "Multiple mods ({writers}) define `{path}` differently ({detail}). {order_note} \
                 Impact: {impact_label}."
            ))
            .affects(path.to_string())
            .fix(FixCandidate::advice(pres.fix))
            .tag("resource")
            .tag(pres.domain_tag)
            .tag("override")
            .tag("semantic-override")
            .tag(impact_label)
            .evidence(EvidenceEdge::subject(f.id))
            .confidence(0.9)
            .build(),
    )
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

/// One grouped Note for locale keys that map to different translations across
/// writers. Cosmetic (the wrong tooltip text may show), so it is a single
/// low-severity finding listing the affected files rather than per-file noise.
fn lang_conflict_finding(diffs: &[&Fact]) -> Option<Finding> {
    let conflicts: Vec<&&Fact> = diffs
        .iter()
        .filter(|f| f.attr("diff_kind") == Some("lang-key-conflict"))
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
        // Mirror the real collector: derive the central severity/impact from the kind.
        let kind =
            crate::semantic::diff::DiffKind::from_kind_str(kind_str).expect("known diff kind");
        store
            .fact("resource-ast-scanner", kind::RESOURCE_SEMANTIC_DIFF)
            .subject(path.to_string())
            .attr("diff_kind", kind_str)
            .attr("writers", writers)
            .attr("detail", detail)
            .attr("impact", kind.impact().as_str())
            .attr("severity", kind.severity().as_str())
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
        diff_fact(
            &mut store,
            "assets/c/lang/en_us.json",
            "lang-key-conflict",
            "a,b",
            "1 key",
        );
        diff_fact(
            &mut store,
            "assets/d/lang/en_us.json",
            "lang-key-conflict",
            "a,b",
            "2 keys",
        );
        let target = test_target();
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = ResourceSemanticRule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Note);
    }

    #[test]
    fn loot_override_warns_per_table() {
        let mut store = FactStore::new();
        diff_fact(
            &mut store,
            "data/c/loot_tables/x.json",
            "loot-table-output-override",
            "a,b",
            "differing drops: a:gem, b:dust",
        );
        let target = test_target();
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = ResourceSemanticRule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].id.starts_with("loot-table-output-override:"));
        assert!(
            findings[0]
                .machine_tags
                .iter()
                .any(|t| t == "semantic-override")
        );
    }

    #[test]
    fn model_override_is_note() {
        let mut store = FactStore::new();
        diff_fact(
            &mut store,
            "assets/c/models/item/x.json",
            "model-override",
            "a,b",
            "different parent models: minecraft:item/generated, minecraft:item/handheld",
        );
        let target = test_target();
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = ResourceSemanticRule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Note);
        assert!(findings[0].id.starts_with("model-override:"));
    }

    fn dangling_fact(store: &mut FactStore, from: &str, relation: &str, to: &str) {
        store
            .fact("resource-ast-scanner", kind::RESOURCE_DANGLING_REFERENCE)
            .subject(from.to_string())
            .attr("relation", relation)
            .attr("to", to)
            .attr("expected_path", "x")
            .emit();
    }

    #[test]
    fn dangling_loot_ref_is_noted_but_model_is_not() {
        let mut store = FactStore::new();
        dangling_fact(
            &mut store,
            "data/c/loot_tables/a.json",
            "loot_entry",
            "c:missing_table",
        );
        // A dangling *model* ref must NOT produce a finding (runtime-generated trap).
        dangling_fact(
            &mut store,
            "assets/c/models/x.json",
            "uses_model",
            "c:missing_model",
        );
        let target = test_target();
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = ResourceSemanticRule.evaluate(&ctx);
        let dangling: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "dangling-reference")
            .collect();
        assert_eq!(dangling.len(), 1, "one grouped dangling finding");
        assert_eq!(dangling[0].severity, Severity::Note);
        // Only the loot target is referenced, not the model.
        assert!(dangling[0].explanation.contains("c:missing_table"));
        assert!(!dangling[0].explanation.contains("c:missing_model"));
    }

    #[test]
    fn internal_dangling_is_warn_cross_mod_is_note() {
        let mut store = FactStore::new();
        // mymod references its OWN missing loot table → internal, Warn.
        store
            .fact("resource-ast-scanner", kind::RESOURCE_DANGLING_REFERENCE)
            .subject("data/mymod/loot_tables/a.json")
            .attr("relation", "loot_entry")
            .attr("to", "mymod:missing_own")
            .attr("namespace", "mymod")
            .attr("from_namespace", "mymod")
            .attr("internal", true)
            .attr("expected_path", "x")
            .emit();
        // mymod references ANOTHER present mod's missing loot table → cross, Note.
        store
            .fact("resource-ast-scanner", kind::RESOURCE_DANGLING_REFERENCE)
            .subject("data/mymod/loot_tables/b.json")
            .attr("relation", "loot_entry")
            .attr("to", "othermod:missing_theirs")
            .attr("namespace", "othermod")
            .attr("from_namespace", "mymod")
            .attr("internal", false)
            .attr("owners", "othermod")
            .attr("expected_path", "y")
            .emit();
        let target = test_target();
        let findings = ResourceSemanticRule.evaluate(&RuleCtx::for_test(&store, &target));
        let internal = findings
            .iter()
            .find(|f| f.id == "dangling-reference-internal")
            .expect("internal dangling finding");
        assert_eq!(internal.severity, Severity::Warn);
        assert!(internal.explanation.contains("mymod:missing_own"));
        let cross = findings
            .iter()
            .find(|f| f.id == "dangling-reference")
            .expect("cross-mod dangling finding");
        assert_eq!(cross.severity, Severity::Note);
        assert!(cross.explanation.contains("othermod:missing_theirs"));
        assert!(cross.explanation.contains("owned by othermod"));
    }

    #[test]
    fn no_diffs_no_findings() {
        let store = FactStore::new();
        let target = test_target();
        let ctx = RuleCtx::for_test(&store, &target);
        assert!(ResourceSemanticRule.evaluate(&ctx).is_empty());
    }
}
