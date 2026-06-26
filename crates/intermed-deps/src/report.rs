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

/// Extract the trailing package id from a PubGrub fragment such as
/// `Because structory { 1.3.5 }`, stripping a trailing `{ <version> }` block so
/// the version's closing brace is not mistaken for the package name.
fn last_package_id(segment: &str) -> &str {
    let seg = segment.trim_end();
    let head = if seg.ends_with('}') {
        match seg.rfind('{') {
            Some(brace) => seg[..brace].trim_end(),
            None => seg,
        }
    } else {
        seg
    };
    head.split_whitespace()
        .last()
        .unwrap_or("")
        .trim_matches('`')
}

/// Split PubGrub prose into sentences without slicing version numbers.
///
/// A naive `split('.')` shreds `1.3.5` into fragments; we only break on a `.`
/// that ends a sentence (followed by whitespace or end-of-text).
fn split_sentences(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in text.char_indices() {
        if c == '.'
            && text[i + c.len_utf8()..]
                .chars()
                .next()
                .is_none_or(char::is_whitespace)
        {
            out.push(&text[start..i]);
            start = i + c.len_utf8();
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

fn extract_conflict_bullets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for sentence in split_sentences(text) {
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
            // The dependent id is the token immediately before " depends on ",
            // but PubGrub renders it as `<id> { <version> }` — so a naive
            // last-token grab yields the version block's closing `}`. Strip any
            // trailing `{ … }` block first.
            let left = last_package_id(&s[..idx]);
            let right = s[idx + " depends on ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('`');
            // "the modpack" is the synthetic PubGrub root, not a real mod — skip
            // it on either side so bullets only name installable mods.
            let is_root = |id: &str| matches!(id, "the" | "modpack");
            if !left.is_empty() && !right.is_empty() && !is_root(left) && !is_root(right) {
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

    #[test]
    fn dependent_id_skips_version_block() {
        // Real PubGrub prose renders the dependent as `<id> { <version> }`; the
        // bullet must name the mod, not the version block's closing brace.
        let raw = "Because structory { 1.3.5 } depends on fabric-api-base and the modpack depends on structory { 1.3.5 }, the modpack is forbidden.";
        let text = enhance_unsat_actionability(raw);
        assert!(
            text.contains("`structory` requires `fabric-api-base`"),
            "got: {text}"
        );
        assert!(!text.contains("`}` requires"), "leaked brace: {text}");
    }

    #[test]
    fn synthetic_modpack_root_is_not_a_bullet() {
        let raw = "Because iris { 1.8 } depends on sodium and the modpack { 1.0.0 } depends on sodium { >=0.6.0 }, the modpack { 1.0.0 } is forbidden.";
        let text = enhance_unsat_actionability(raw);
        assert!(text.contains("`iris` requires `sodium`"), "got: {text}");
        assert!(!text.contains("`modpack` requires"), "root leaked: {text}");
    }

    #[test]
    fn last_package_id_handles_brace_and_plain() {
        assert_eq!(last_package_id("Because structory { 1.3.5 }"), "structory");
        assert_eq!(last_package_id("alpha"), "alpha");
        assert_eq!(last_package_id("and `beta`"), "beta");
    }
}
