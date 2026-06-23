//! Human-readable PubGrub unsatisfiability reports.

use pubgrub::{DefaultStringReporter, DerivationTree, Reporter};

use crate::ranges::ModRange;

/// Render a PubGrub derivation tree into a single explanation paragraph.
pub fn format_derivation_tree(tree: &DerivationTree<String, ModRange, String>) -> String {
    DefaultStringReporter::report(tree)
}

/// Collapse noisy `NoVersions` nodes, then format for doctor findings.
pub fn format_unsat_tree(mut tree: DerivationTree<String, ModRange, String>) -> String {
    tree.collapse_no_versions();
    let raw = sanitize_modpack_root(&format_derivation_tree(&tree));
    enhance_unsat_actionability(&raw)
}

/// Replace the internal PubGrub synthetic root with user-facing language.
fn sanitize_modpack_root(text: &str) -> String {
    text.replace(crate::graph::MODPACK_ROOT_ID, "the modpack")
        .replace(
            &format!("{} {{ 1.0.0 }}", crate::graph::MODPACK_ROOT_ID),
            "the modpack",
        )
}

/// Append a short bullet list of mod↔mod conflicts extracted from PubGrub prose.
fn enhance_unsat_actionability(text: &str) -> String {
    let bullets = extract_conflict_bullets(text);
    if bullets.is_empty() {
        return text.to_string();
    }
    format!(
        "{text}\n\nActionable summary:\n{}",
        bullets
            .into_iter()
            .map(|b| format!("- {b}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn extract_conflict_bullets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for sentence in text.split('.') {
        let s = sentence.trim();
        if let Some(rest) = s.strip_prefix("Because no versions of ") {
            let id = rest
                .split(|c: char| c.is_whitespace() || c == '{')
                .next()
                .unwrap_or(rest)
                .trim();
            if !id.is_empty() && id != "the" {
                out.push(format!(
                    "No installed version of `{id}` satisfies the combined constraints — check its declared range or remove a conflicting mod."
                ));
            }
        }
        if let Some(idx) = s.find(" depends on ") {
            let left = s[..idx]
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_matches('`');
            let right = s[idx + " depends on ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('`');
            if !left.is_empty() && !right.is_empty() && left != "the" && right != "modpack" {
                out.push(format!(
                    "`{left}` requires `{right}` — verify `{right}` is installed at a compatible version."
                ));
            }
        }
        if s.contains("are incompatible") {
            out.push(
                "Two mods declare mutually incompatible version ranges — update one side or drop a mod."
                    .to_string(),
            );
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsat_text_hides_synthetic_modpack_root() {
        let raw = format!(
            "Because {} depends on iris, {} is forbidden.",
            crate::graph::MODPACK_ROOT_ID,
            crate::graph::MODPACK_ROOT_ID
        );
        let text = sanitize_modpack_root(&raw);
        assert!(!text.contains(crate::graph::MODPACK_ROOT_ID));
        assert!(text.contains("the modpack"));
    }

    #[test]
    fn actionable_summary_lists_mod_pairs() {
        let raw = "Because no versions of fabric-api match >=0.90.0 <0.91.0 and alpha depends on fabric-api >=0.90.0 <0.91.0, version solving failed.";
        let text = enhance_unsat_actionability(raw);
        assert!(text.contains("Actionable summary:"));
        assert!(text.contains("fabric-api"));
        assert!(text.contains("alpha"));
    }
}
