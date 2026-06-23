//! Cross-rule finding suppression / merge.
//!
//! Different layers legitimately observe the *same* underlying situation. Layer E
//! (byte-level VFS) sees that `create` and `createaddition` both write
//! `data/create/recipes/crushing/tuff.json` — a `json-override` collision. Layer M
//! (typed AST) sees *why* it matters — the recipe outputs differ. Emitting both
//!
//! ```text
//! resource-conflict:json-override:data/create/recipes/crushing/tuff.json
//! recipe-output-override:data/create/recipes/crushing/tuff.json
//! ```
//!
//! gives the user two warnings for one path. That is noise.
//!
//! The Layer-M semantic-override finding is the *meaning* of the byte-level
//! Layer-E collision on the same path; the suppressor keeps the semantic finding
//! and folds the byte one's evidence into it (recording the contributing rule in
//! `rule_sources`) rather than dropping it.

use intermed_evidence::{Finding, Severity};
use intermed_facts::{FactStore, kind};
use intermed_resource_identity::ResourceKey;

/// Fold every Layer-E `resource-conflict:<class>:<path>` finding into the Layer-M
/// semantic-override finding for the *same path*, when one exists.
///
/// Layer-M override findings are tagged `semantic-override` and have the id form
/// `<diff-kind>:<path>`; Layer-E findings have `resource-conflict:<class>:<path>`.
/// Both encode the path as the id's tail, so a single pass matches any present or
/// future override domain (recipe / loot / atlas / model / blockstate /
/// advancement / predicate / registry object) without a per-pair table — the
/// path is the shared key. Returns the number of Layer-E findings folded away.
pub fn apply_semantic_override_suppression(findings: &mut Vec<Finding>) -> usize {
    // path -> index of the Layer-M semantic-override finding for that path.
    let mut winner_by_path: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        if f.machine_tags.iter().any(|t| t == "semantic-override") {
            if let Some((_, path)) = f.id.split_once(':') {
                winner_by_path.insert(path.to_string(), i);
            }
        }
    }
    if winner_by_path.is_empty() {
        return 0;
    }

    // Collect (winner, loser) folds for Layer-E collisions on a covered path.
    let mut folds: Vec<(usize, usize)> = Vec::new();
    for (j, f) in findings.iter().enumerate() {
        let Some(rest) = f.id.strip_prefix("resource-conflict:") else {
            continue;
        };
        // rest = "<class>:<path>" → path is everything after the first ':'.
        let Some((_, path)) = rest.split_once(':') else {
            continue;
        };
        if let Some(&winner) = winner_by_path.get(path) {
            if winner != j {
                folds.push((winner, j));
            }
        }
    }

    let mut remove = vec![false; findings.len()];
    for (winner, loser) in folds {
        if remove[loser] {
            continue;
        }
        let loser_evidence = findings[loser].evidence.clone();
        let loser_rule = findings[loser].rule_id.clone();
        let loser_tags = findings[loser].machine_tags.clone();
        let w = &mut findings[winner];
        w.evidence.extend(loser_evidence);
        for tag in loser_tags {
            if !w.machine_tags.contains(&tag) {
                w.machine_tags.push(tag);
            }
        }
        if loser_rule != w.rule_id && !w.rule_sources.contains(&loser_rule) {
            w.rule_sources.push(loser_rule);
        }
        remove[loser] = true;
    }

    let removed = remove.iter().filter(|&&r| r).count();
    let mut iter = remove.into_iter();
    findings.retain(|_| !iter.next().unwrap_or(false));
    removed
}

/// Finding-id prefixes whose subject is a recipe resource path, paired with the
/// fact kinds that mean "a data-pack script touches this recipe".
const RECIPE_OVERRIDE_PREFIXES: &[&str] = &[
    "recipe-output-override:",
    "recipe-type-override:",
    "recipe-ingredient-override:",
    "recipe-condition-override:",
];

/// Downgrade a static resource finding when a data-pack script (KubeJS /
/// CraftTweaker) removes or replaces the very resource it concerns.
///
/// Layer M concludes "this recipe resolves differently by load order" from the
/// *static* files. But if a script deletes or replaces that recipe at load time,
/// the static conflict never reaches the player — warning at full severity would
/// be a false positive. We don't silently drop it (the script read is a
/// heuristic): we downgrade `Warn`→`Note`, lower confidence, and append a caveat
/// so a human can audit. Returns the number of findings downgraded.
pub fn apply_runtime_caveats(findings: &mut [Finding], store: &FactStore) -> usize {
    // Recipe ids/namespaces a script removed or modified.
    let mut scripted_recipes: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for k in [
        kind::RUNTIME_REMOVED_RECIPE,
        kind::RUNTIME_SCRIPT_MODIFIES_RECIPE,
    ] {
        for f in store.by_kind(k) {
            scripted_recipes.insert(f.subject.clone());
        }
    }
    let mut scripted_loot: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for f in store.by_kind(kind::RUNTIME_REMOVED_LOOT_TABLE) {
        scripted_loot.insert(f.subject.clone());
    }
    if scripted_recipes.is_empty() && scripted_loot.is_empty() {
        return 0;
    }

    let mut downgraded = 0;
    for f in findings.iter_mut() {
        let scripted = if let Some(path) = strip_any_prefix(&f.id, RECIPE_OVERRIDE_PREFIXES) {
            recipe_is_scripted(path, &scripted_recipes)
        } else if let Some(path) = f.id.strip_prefix("loot-table-output-override:") {
            recipe_is_scripted(path, &scripted_loot)
        } else {
            false
        };
        if scripted {
            if f.severity > Severity::Note {
                f.severity = Severity::Note;
            }
            f.confidence = (f.confidence * 0.7).min(0.7);
            if !f.explanation.contains("data-pack script") {
                f.explanation.push_str(
                    " A data-pack script (KubeJS/CraftTweaker) removes or replaces this resource at \
                     load time, so the static conflict may never reach the player — downgraded and \
                     flagged for audit.",
                );
            }
            if !f.machine_tags.iter().any(|t| t == "runtime-script-caveat") {
                f.machine_tags.push("runtime-script-caveat".to_string());
            }
            downgraded += 1;
        }
    }
    downgraded
}

/// Whether the resource at `path` matches a scripted id set, by its object id
/// (`create:crushing/tuff`) or its namespace (mod-scoped script removal).
fn recipe_is_scripted(path: &str, scripted: &std::collections::BTreeSet<String>) -> bool {
    let key = ResourceKey::from_path(path);
    if let Some(id) = &key.object_id {
        if scripted.contains(&id.to_string()) {
            return true;
        }
    }
    // Mod-scoped removal (`removeByModid("create")`) names the namespace only.
    key.namespace
        .as_deref()
        .is_some_and(|ns| scripted.contains(ns))
}

fn strip_any_prefix<'a>(id: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes.iter().find_map(|p| id.strip_prefix(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_evidence::EvidenceEdge;
    use intermed_facts::FactId;

    fn f(id: &str, rule: &str) -> Finding {
        Finding::builder(rule, id)
            .severity(Severity::Warn)
            .evidence(EvidenceEdge::subject(FactId(1)))
            .build()
    }

    /// A Layer-M semantic-override finding (tagged `semantic-override`).
    fn semantic(id: &str) -> Finding {
        Finding::builder("resource-semantics", id)
            .severity(Severity::Warn)
            .evidence(EvidenceEdge::subject(FactId(1)))
            .tag("semantic-override")
            .build()
    }

    #[test]
    fn semantic_override_suppresses_generic_collision() {
        let path = "data/create/recipes/crushing/tuff.json";
        let mut findings = vec![
            semantic(&format!("recipe-output-override:{path}")),
            f(
                &format!("resource-conflict:json-override:{path}"),
                "resource-conflict",
            ),
        ];
        let removed = apply_semantic_override_suppression(&mut findings);
        assert_eq!(removed, 1);
        assert_eq!(findings.len(), 1);
        let kept = &findings[0];
        assert!(kept.id.starts_with("recipe-output-override:"));
        // The VFS collision's evidence was folded in (2 edges now).
        assert_eq!(kept.evidence.len(), 2);
        assert!(kept.rule_sources.contains(&"resource-conflict".to_string()));
    }

    #[test]
    fn generic_pass_folds_any_override_domain() {
        // An atlas semantic override folds the Layer-E order-dependent-atlas finding.
        let path = "assets/minecraft/atlases/blocks.json";
        let mut findings = vec![
            semantic(&format!("atlas-source-override:{path}")),
            f(
                &format!("resource-conflict:order-dependent-atlas:{path}"),
                "resource-conflict",
            ),
        ];
        assert_eq!(apply_semantic_override_suppression(&mut findings), 1);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].id.starts_with("atlas-source-override:"));
    }

    #[test]
    fn runtime_script_removal_downgrades_recipe_finding() {
        let mut store = FactStore::new();
        // A script removes recipe id `create:crushing/tuff`.
        store
            .fact("static-script-scanner", kind::RUNTIME_REMOVED_RECIPE)
            .subject("create:crushing/tuff")
            .emit();
        let mut findings = vec![
            Finding::builder(
                "resource-semantics",
                "recipe-output-override:data/create/recipes/crushing/tuff.json",
            )
            .severity(Severity::Warn)
            .build(),
        ];
        let n = apply_runtime_caveats(&mut findings, &store);
        assert_eq!(n, 1);
        assert_eq!(findings[0].severity, Severity::Note);
        assert!(
            findings[0]
                .machine_tags
                .iter()
                .any(|t| t == "runtime-script-caveat")
        );
        assert!(findings[0].explanation.contains("data-pack script"));
    }

    #[test]
    fn mod_scoped_removal_downgrades_by_namespace() {
        let mut store = FactStore::new();
        store
            .fact("static-script-scanner", kind::RUNTIME_REMOVED_RECIPE)
            .subject("create")
            .emit();
        let mut findings = vec![
            Finding::builder(
                "resource-semantics",
                "recipe-output-override:data/create/recipes/x.json",
            )
            .severity(Severity::Warn)
            .build(),
        ];
        assert_eq!(apply_runtime_caveats(&mut findings, &store), 1);
        assert_eq!(findings[0].severity, Severity::Note);
    }

    #[test]
    fn unrelated_recipe_not_downgraded() {
        let mut store = FactStore::new();
        store
            .fact("static-script-scanner", kind::RUNTIME_REMOVED_RECIPE)
            .subject("thermal:smelting/x")
            .emit();
        let mut findings = vec![
            Finding::builder(
                "resource-semantics",
                "recipe-output-override:data/create/recipes/x.json",
            )
            .severity(Severity::Warn)
            .build(),
        ];
        assert_eq!(apply_runtime_caveats(&mut findings, &store), 0);
        assert_eq!(findings[0].severity, Severity::Warn);
    }

    #[test]
    fn unrelated_paths_are_not_suppressed() {
        let mut findings = vec![
            semantic("recipe-output-override:data/a/recipes/x.json"),
            f(
                "resource-conflict:json-override:data/b/recipes/y.json",
                "resource-conflict",
            ),
        ];
        let removed = apply_semantic_override_suppression(&mut findings);
        assert_eq!(removed, 0);
        assert_eq!(findings.len(), 2);
    }
}
