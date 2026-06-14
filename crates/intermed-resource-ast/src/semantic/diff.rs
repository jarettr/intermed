//! Cross-writer semantic diffs.
//!
//! Layer E already classifies *byte-level* collisions (identical, override, safe
//! union). Layer M adds the **semantic** disagreement that bytes can't express:
//! two writers at the same recipe path that craft *different outputs*, or two
//! lang writers that map the *same key to different text*. These are produced
//! here and lowered into `resource_semantic_diff` facts; rules turn the
//! meaningful ones into findings.

use std::collections::BTreeMap;

use crate::model::{ResourceDomain, ResourceSummary};
use crate::semantic::refs::ResourceAstRecord;

/// The kind of semantic disagreement between writers of one resource path.
///
/// Deliberately narrow: Layer M only reports a diff when the disagreement is
/// *semantically meaningful and not already covered by Layer E*. Tags union
/// (differing content is benign), and single-document overrides are already
/// classified by Layer E — re-flagging either would be a false positive, which is
/// the cardinal sin here. So the only diffs are the two that change *behaviour*:
/// a recipe that crafts a different result, and a locale key that maps to
/// different text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    /// Same recipe path, writers produce different output item sets.
    RecipeOutputOverride,
    /// Same locale file, writers map a shared key to different translations.
    LangKeyConflict,
}

impl DiffKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DiffKind::RecipeOutputOverride => "recipe-output-override",
            DiffKind::LangKeyConflict => "lang-key-conflict",
        }
    }
}

/// One semantic diff at a resource path.
#[derive(Debug, Clone)]
pub struct SemanticDiff {
    pub path: String,
    pub kind: DiffKind,
    pub writers: Vec<String>,
    /// Human-readable detail (e.g. the conflicting outputs / keys), bounded.
    pub detail: String,
}

/// Compute all semantic diffs across the pack. Records are grouped by path; a
/// group with a single distinct *semantic hash* agrees and is skipped (writers
/// differing only in key order hash identically, so this is conflict-free).
#[must_use]
pub fn compute(records: &[ResourceAstRecord]) -> Vec<SemanticDiff> {
    let mut by_path: BTreeMap<&str, Vec<&ResourceAstRecord>> = BTreeMap::new();
    for rec in records {
        by_path
            .entry(rec.ast.resource_path.as_str())
            .or_default()
            .push(rec);
    }

    let mut out = Vec::new();
    for (path, group) in by_path {
        // Distinct writers only — one writer shipping a path twice is not a
        // cross-writer disagreement.
        let mut writers: Vec<String> = group.iter().map(|r| r.writer.clone()).collect();
        writers.sort();
        writers.dedup();
        if writers.len() < 2 {
            continue;
        }
        // Agreement: every writer's semantic hash matches → no diff.
        let first_hash = &group[0].ast.semantic_hash;
        if group.iter().all(|r| &r.ast.semantic_hash == first_hash) {
            continue;
        }

        let domain = group[0].ast.domain;
        if let Some(diff) = diff_group(path, domain, &group, &writers) {
            out.push(diff);
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn diff_group(
    path: &str,
    domain: ResourceDomain,
    group: &[&ResourceAstRecord],
    writers: &[String],
) -> Option<SemanticDiff> {
    match domain {
        ResourceDomain::Recipe => recipe_diff(path, group, writers),
        ResourceDomain::Lang => lang_diff(path, group, writers),
        // Every other domain: a hash mismatch is either a benign union (tags) or a
        // single-document override already classified by Layer E. Re-flagging it
        // would be a false positive, so Layer M stays silent.
        _ => None,
    }
}

/// Two recipe writers conflict when their produced output sets differ.
fn recipe_diff(path: &str, group: &[&ResourceAstRecord], writers: &[String]) -> Option<SemanticDiff> {
    let mut output_sets: Vec<Vec<String>> = Vec::new();
    for rec in group {
        if let ResourceSummary::Recipe(s) = &rec.ast.summary {
            output_sets.push(s.outputs.clone());
        }
    }
    if output_sets.len() < 2 {
        return None;
    }
    let first = &output_sets[0];
    if output_sets.iter().all(|o| o == first) {
        // Same outputs, different ingredients/type: the crafting *result* is
        // stable, so this is a benign override already classified by Layer E.
        // Reporting it would be a false positive.
        return None;
    }
    let mut all_outputs: Vec<String> = output_sets.into_iter().flatten().collect();
    all_outputs.sort();
    all_outputs.dedup();
    Some(SemanticDiff {
        path: path.to_string(),
        kind: DiffKind::RecipeOutputOverride,
        writers: writers.to_vec(),
        detail: format!("conflicting outputs: {}", truncate_list(&all_outputs)),
    })
}

/// Two lang writers conflict when they map a shared key to different values.
fn lang_diff(path: &str, group: &[&ResourceAstRecord], writers: &[String]) -> Option<SemanticDiff> {
    // key → distinct values seen
    let mut values: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    for rec in group {
        if let ResourceSummary::Lang(s) = &rec.ast.summary {
            for (k, v) in &s.entries {
                values.entry(k.clone()).or_default().insert(v.clone());
            }
        }
    }
    let conflicts: Vec<String> = values
        .into_iter()
        .filter(|(_, vs)| vs.len() > 1)
        .map(|(k, _)| k)
        .collect();
    if conflicts.is_empty() {
        return None;
    }
    Some(SemanticDiff {
        path: path.to_string(),
        kind: DiffKind::LangKeyConflict,
        writers: writers.to_vec(),
        detail: format!(
            "{} key(s) map to different text: {}",
            conflicts.len(),
            truncate_list(&conflicts)
        ),
    })
}

/// Join up to 8 ids for a bounded, deterministic detail string.
fn truncate_list(items: &[String]) -> String {
    const MAX: usize = 8;
    if items.len() <= MAX {
        return items.join(", ");
    }
    format!("{}, … (+{} more)", items[..MAX].join(", "), items.len() - MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::lang::LangSummary;
    use crate::domain::recipe::RecipeSummary;
    use crate::model::{CachedResourceAst, ParseStatus, ResourceDomain};

    fn rec(writer: &str, path: &str, domain: ResourceDomain, hash: &str, summary: ResourceSummary) -> ResourceAstRecord {
        ResourceAstRecord {
            archive: format!("{writer}.jar"),
            writer: writer.into(),
            ast: CachedResourceAst {
                schema: "s".into(),
                parser_version: "v".into(),
                resource_path: path.into(),
                domain,
                parse_status: ParseStatus::Parsed,
                semantic_hash: hash.into(),
                summary,
                references: vec![],
                diagnostics: vec![],
            },
        }
    }

    fn recipe(outputs: &[&str]) -> ResourceSummary {
        ResourceSummary::Recipe(RecipeSummary {
            recipe_type: "minecraft:crafting_shaped".into(),
            ingredient_count: 1,
            output_count: outputs.len(),
            has_conditions: false,
            outputs: outputs.iter().map(|s| s.to_string()).collect(),
            ingredients: vec!["minecraft:stick".into()],
        })
    }

    fn lang(pairs: &[(&str, &str)]) -> ResourceSummary {
        ResourceSummary::Lang(LangSummary {
            format: "json".into(),
            key_count: pairs.len(),
            entries: pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        })
    }

    #[test]
    fn recipe_output_override_detected() {
        let recs = vec![
            rec("a", "data/c/recipe/r.json", ResourceDomain::Recipe, "h1", recipe(&["a:gear"])),
            rec("b", "data/c/recipe/r.json", ResourceDomain::Recipe, "h2", recipe(&["b:cog"])),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::RecipeOutputOverride);
    }

    #[test]
    fn identical_hash_is_no_diff() {
        let recs = vec![
            rec("a", "data/c/recipe/r.json", ResourceDomain::Recipe, "same", recipe(&["a:gear"])),
            rec("b", "data/c/recipe/r.json", ResourceDomain::Recipe, "same", recipe(&["a:gear"])),
        ];
        assert!(compute(&recs).is_empty());
    }

    #[test]
    fn lang_key_conflict_detected() {
        let recs = vec![
            rec("a", "assets/c/lang/en_us.json", ResourceDomain::Lang, "h1", lang(&[("item.x", "Sword")])),
            rec("b", "assets/c/lang/en_us.json", ResourceDomain::Lang, "h2", lang(&[("item.x", "Blade")])),
        ];
        let diffs = compute(&recs);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].kind, DiffKind::LangKeyConflict);
    }

    #[test]
    fn lang_disjoint_keys_no_conflict() {
        let recs = vec![
            rec("a", "assets/c/lang/en_us.json", ResourceDomain::Lang, "h1", lang(&[("item.x", "Sword")])),
            rec("b", "assets/c/lang/en_us.json", ResourceDomain::Lang, "h2", lang(&[("item.y", "Shield")])),
        ];
        assert!(compute(&recs).is_empty());
    }
}
