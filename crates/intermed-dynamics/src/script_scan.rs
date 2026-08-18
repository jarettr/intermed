//! Static data-pack script scanner (KubeJS `.js`, CraftTweaker `.zs`).
//!
//! The log scanner in the crate root reads what a *previous run* logged. But a
//! pack ships its scripts on disk, and a static analysis (mods-dir / instance with
//! no run yet) still needs to know what they remove or replace — otherwise Layer M
//! will warn about a recipe override that a script deletes anyway (a false
//! positive). This module reads the script *source* and extracts the
//! removals/replacements with a confidence label.
//!
//! Honesty: this is a bounded tokenizer and call-context recognizer, not a full
//! JS/ZenScript parser. It ignores comments and string contents when classifying
//! calls, and emits only when a concrete namespaced id literal (`mod:path`) is an
//! argument to a supported removal/replacement call. Dynamic expressions yield
//! no fact rather than a guess.

use std::path::{Path, PathBuf};

use intermed_doctor_core::Target;
use intermed_doctor_core::facts::{FactStore, SourceRef, kind};

/// Confidence for a concrete `mod:id` literal on a removal/replace line.
const CONF_EXACT: f32 = 0.8;
/// Confidence for a mod-scoped removal (`removeByModid("create")`) — a namespace,
/// not a specific recipe.
const CONF_MOD_SCOPED: f32 = 0.5;

/// Max script files scanned and max bytes per file (untrusted-input guards).
const MAX_SCRIPT_FILES: usize = 5_000;
const MAX_SCRIPT_BYTES: u64 = 4 * 1024 * 1024;
/// Max directory recursion depth under a script root.
const MAX_DEPTH: usize = 12;

/// Locate script files under the target's roots. Returns `(path, engine)`.
pub fn script_files(target: &Target) -> Vec<(PathBuf, &'static str)> {
    discover_script_files(target).files
}

/// Whether a conventional script root exists, even if its contents cannot be
/// enumerated. This lets the collector report an incomplete discovery instead
/// of being marked not-applicable.
pub fn has_script_roots(target: &Target) -> bool {
    let mut roots = target.candidate_roots();
    if let Some(parent) = target.path.parent() {
        roots.push(parent.to_path_buf());
    }
    roots
        .iter()
        .any(|root| root.join("kubejs").exists() || root.join("scripts").exists())
}

/// Bounded discovery result. Gaps are part of collector completeness rather
/// than silently disappearing when a directory cannot be read or a cap fires.
#[derive(Debug, Default)]
pub struct ScriptDiscovery {
    pub files: Vec<(PathBuf, &'static str)>,
    pub gaps: Vec<String>,
}

pub fn discover_script_files(target: &Target) -> ScriptDiscovery {
    let mut roots: Vec<PathBuf> = target.candidate_roots();
    // A mods-dir target points *at* `mods/`; scripts live beside it in the game
    // root, so include the parent.
    if let Some(parent) = target.path.parent() {
        roots.push(parent.to_path_buf());
    }
    roots.sort();
    roots.dedup();

    let mut out = Vec::new();
    let mut gaps = Vec::new();
    for root in &roots {
        // KubeJS: kubejs/{server,startup,client}_scripts/**.js
        let kubejs = root.join("kubejs");
        for sub in ["server_scripts", "startup_scripts", "client_scripts"] {
            collect_files(
                &kubejs.join(sub),
                "js",
                crate::engine::KUBEJS,
                0,
                &mut out,
                &mut gaps,
            );
        }
        // CraftTweaker: scripts/**.zs
        collect_files(
            &root.join("scripts"),
            "zs",
            crate::engine::CRAFTTWEAKER,
            0,
            &mut out,
            &mut gaps,
        );
        if out.len() >= MAX_SCRIPT_FILES {
            break;
        }
    }
    if out.len() >= MAX_SCRIPT_FILES {
        gaps.push(format!(
            "script discovery reached the {MAX_SCRIPT_FILES} file cap"
        ));
    }
    out.truncate(MAX_SCRIPT_FILES);
    gaps.sort();
    gaps.dedup();
    ScriptDiscovery { files: out, gaps }
}

fn collect_files(
    dir: &Path,
    ext: &str,
    engine: &'static str,
    depth: usize,
    out: &mut Vec<(PathBuf, &'static str)>,
    gaps: &mut Vec<String>,
) {
    if depth > MAX_DEPTH {
        gaps.push(format!(
            "script discovery exceeded recursion depth {MAX_DEPTH} under {}",
            dir.display()
        ));
        return;
    }
    if out.len() >= MAX_SCRIPT_FILES || !dir.exists() {
        return;
    }
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            gaps.push(format!(
                "script discovery rejected symlinked directory {}",
                dir.display()
            ));
            return;
        }
        Ok(metadata) if !metadata.is_dir() => return,
        Err(error) => {
            gaps.push(format!(
                "cannot inspect script directory {}: {error}",
                dir.display()
            ));
            return;
        }
        _ => {}
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            gaps.push(format!(
                "cannot read script directory {}: {error}",
                dir.display()
            ));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                gaps.push(format!("cannot enumerate {}: {error}", dir.display()));
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                gaps.push(format!(
                    "cannot inspect script entry {}: {error}",
                    path.display()
                ));
                continue;
            }
        };
        if file_type.is_symlink() {
            gaps.push(format!(
                "script discovery rejected symlink {}",
                path.display()
            ));
        } else if file_type.is_dir() {
            collect_files(&path, ext, engine, depth + 1, out, gaps);
        } else if file_type.is_file() && path.extension().and_then(|e| e.to_str()) == Some(ext) {
            out.push((path, engine));
        }
        if out.len() >= MAX_SCRIPT_FILES {
            return;
        }
    }
}

/// One extracted script action.
struct ScriptHit {
    fact_kind: &'static str,
    via: &'static str,
    target: String,
    confidence: f32,
    lineno: usize,
    excerpt: String,
}

/// Scan one script file's text for removals/replacements.
fn scan_text(text: &str, engine: &str) -> Vec<ScriptHit> {
    let mut hits = Vec::new();
    let mut in_block_comment = false;
    for (lineno, raw) in text.lines().enumerate() {
        let parsed = tokenize_line(raw, &mut in_block_comment);
        let line = raw.trim();
        if parsed.code.is_empty() {
            continue;
        }

        // Classify actual call tokens, not arbitrary keyword presence in prose or strings.
        let (fact_kind, via, mod_scoped) = if parsed.calls.iter().any(|call| {
            matches!(
                call.as_str(),
                "replaceoutput" | "replaceinput" | "event.replaceoutput" | "event.replaceinput"
            )
        }) {
            (
                kind::RUNTIME_SCRIPT_MODIFIES_RECIPE,
                "recipe-replaced",
                false,
            )
        } else if parsed
            .calls
            .iter()
            .any(|call| call.ends_with("removebymodid") || call.ends_with("removebymod"))
        {
            (kind::RUNTIME_REMOVED_RECIPE, "recipe-removed", true)
        } else if is_tag_removal(&parsed) {
            (kind::RUNTIME_REMOVED_TAG, "tag-removed", false)
        } else if is_recipe_removal(&parsed, engine) {
            (kind::RUNTIME_REMOVED_RECIPE, "recipe-removed", false)
        } else {
            continue;
        };

        // The first namespaced/namespace literal on the line is the target.
        let Some(target) = parsed.strings.iter().find(|value| valid_id_literal(value)) else {
            continue; // dynamic / computed id — no confident fact.
        };
        let target = target.clone();
        let has_colon = target.trim_start_matches('#').contains(':');
        // A mod-scoped removal names a namespace; otherwise we need a full id.
        let confidence = if mod_scoped {
            CONF_MOD_SCOPED
        } else if has_colon {
            CONF_EXACT
        } else {
            // `remove('create')`-style namespace-only literal on a non-mod-scoped
            // call: still useful but lower confidence.
            CONF_MOD_SCOPED
        };
        hits.push(ScriptHit {
            fact_kind,
            via,
            target,
            confidence,
            lineno,
            excerpt: truncate(line, 200),
        });
    }
    hits
}

#[derive(Debug, Default)]
struct ParsedLine {
    code: String,
    calls: Vec<String>,
    strings: Vec<String>,
    identifiers: Vec<String>,
}

fn tokenize_line(raw: &str, in_block_comment: &mut bool) -> ParsedLine {
    let mut parsed = ParsedLine::default();
    let chars = raw.chars().collect::<Vec<_>>();
    let mut index = 0usize;
    while index < chars.len() {
        if *in_block_comment {
            if chars.get(index) == Some(&'*') && chars.get(index + 1) == Some(&'/') {
                *in_block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if chars.get(index) == Some(&'/') && chars.get(index + 1) == Some(&'*') {
            *in_block_comment = true;
            index += 2;
            continue;
        }
        if chars.get(index) == Some(&'/') && chars.get(index + 1) == Some(&'/') {
            break;
        }
        if matches!(chars[index], '\'' | '"') {
            let quote = chars[index];
            index += 1;
            let mut value = String::new();
            while index < chars.len() {
                if chars[index] == '\\' && index + 1 < chars.len() {
                    value.push(chars[index + 1]);
                    index += 2;
                    continue;
                }
                if chars[index] == quote {
                    index += 1;
                    break;
                }
                value.push(chars[index]);
                index += 1;
            }
            parsed.strings.push(value);
            parsed.code.push_str(" <string> ");
            continue;
        }
        parsed.code.push(chars[index]);
        index += 1;
    }
    let chars = parsed.code.chars().collect::<Vec<_>>();
    let mut index = 0usize;
    while index < chars.len() {
        if chars[index].is_ascii_alphabetic() || matches!(chars[index], '_' | '$') {
            let start = index;
            index += 1;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || matches!(chars[index], '_' | '$' | '.'))
            {
                index += 1;
            }
            let ident = chars[start..index]
                .iter()
                .collect::<String>()
                .trim_matches('.')
                .to_ascii_lowercase();
            let mut next = index;
            while next < chars.len() && chars[next].is_whitespace() {
                next += 1;
            }
            if chars.get(next) == Some(&'(') {
                parsed.calls.push(ident.clone());
            }
            parsed.identifiers.push(ident);
        } else {
            index += 1;
        }
    }
    parsed
}

fn valid_id_literal(value: &str) -> bool {
    let value = value.trim_start_matches('#');
    !value.is_empty()
        && value.chars().all(|ch| {
            ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || matches!(ch, '_' | '.' | '-' | ':' | '/')
        })
}

fn is_recipe_removal(parsed: &ParsedLine, engine: &str) -> bool {
    if engine == crate::engine::CRAFTTWEAKER {
        parsed.calls.iter().any(|call| {
            call.ends_with("removebyname")
                || call.ends_with("removerecipe")
                || call == "recipes.remove"
                || call.ends_with(".remove")
        })
    } else {
        parsed.calls.iter().any(|call| call == "event.remove")
    }
}

fn is_tag_removal(parsed: &ParsedLine) -> bool {
    parsed.identifiers.iter().any(|identifier| identifier.contains("tag"))
        && parsed.calls.iter().any(|call| call.ends_with(".remove") || call.ends_with("removefrom"))
        // Avoid double-counting recipe removals that merely mention "tag".
        && !parsed.identifiers.iter().any(|identifier| identifier.contains("recipe"))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

/// Scan all script files under `target` and emit facts. Returns count emitted.
#[derive(Debug, Default)]
pub struct ScriptScanResult {
    pub emitted: usize,
    pub files_discovered: usize,
    pub gaps: Vec<String>,
}

pub fn emit(store: &mut FactStore, target: &Target) -> ScriptScanResult {
    let discovery = discover_script_files(target);
    let files = discovery.files;
    let mut gaps = discovery.gaps;
    if files.is_empty() {
        return ScriptScanResult {
            emitted: 0,
            files_discovered: 0,
            gaps,
        };
    }
    let mut emitted = 0usize;
    for (path, engine) in &files {
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(error) => {
                gaps.push(format!("cannot stat script {}: {error}", path.display()));
                continue;
            }
        };
        if meta.len() > MAX_SCRIPT_BYTES {
            gaps.push(format!(
                "script {} exceeds the {MAX_SCRIPT_BYTES} byte cap",
                path.display()
            ));
            continue;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                gaps.push(format!("cannot read script {}: {error}", path.display()));
                continue;
            }
        };
        let locator = path.display().to_string();
        let scope = if locator.contains("/server_scripts/") {
            "server"
        } else if locator.contains("/client_scripts/") {
            "client"
        } else if locator.contains("/startup_scripts/") {
            "startup"
        } else {
            "shared"
        };
        for hit in scan_text(&text, engine) {
            store
                .fact("static-script-scanner", hit.fact_kind)
                .subject(hit.target)
                .attr("engine", *engine)
                .attr("via", hit.via)
                .attr("source_kind", "script")
                .attr("script_scope", scope)
                .attr("line", (hit.lineno as i64) + 1)
                .attr("excerpt", hit.excerpt)
                .source(SourceRef::at_line(locator.clone(), (hit.lineno as u32) + 1))
                .confidence(hit.confidence)
                .emit();
            emitted += 1;
        }
    }
    gaps.sort();
    gaps.dedup();
    ScriptScanResult {
        emitted,
        files_discovered: files.len(),
        gaps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubejs_remove_captures_recipe_id() {
        let text =
            "ServerEvents.recipes(event => {\n  event.remove({ id: 'minecraft:cobblestone' })\n})";
        let hits = scan_text(text, crate::engine::KUBEJS);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].target, "minecraft:cobblestone");
        assert_eq!(hits[0].fact_kind, kind::RUNTIME_REMOVED_RECIPE);
        assert_eq!(hits[0].confidence, CONF_EXACT);
    }

    #[test]
    fn kubejs_replace_output_is_modify() {
        let text = "event.replaceOutput({}, 'minecraft:diamond', 'minecraft:coal')";
        let hits = scan_text(text, crate::engine::KUBEJS);
        assert_eq!(hits[0].fact_kind, kind::RUNTIME_SCRIPT_MODIFIES_RECIPE);
    }

    #[test]
    fn crafttweaker_remove_by_name() {
        let text = r#"craftingTable.removeByName("minecraft:torch");"#;
        let hits = scan_text(text, crate::engine::CRAFTTWEAKER);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].target, "minecraft:torch");
        assert_eq!(hits[0].fact_kind, kind::RUNTIME_REMOVED_RECIPE);
    }

    #[test]
    fn remove_by_modid_is_mod_scoped() {
        let text = r#"craftingTable.removeByModid("create");"#;
        let hits = scan_text(text, crate::engine::CRAFTTWEAKER);
        assert_eq!(hits[0].target, "create");
        assert_eq!(hits[0].confidence, CONF_MOD_SCOPED);
    }

    #[test]
    fn dynamic_id_yields_no_fact() {
        let text = "event.remove({ id: someVariable })";
        let hits = scan_text(text, crate::engine::KUBEJS);
        assert!(hits.is_empty());
    }

    #[test]
    fn comment_lines_ignored() {
        let text = "// event.remove({ id: 'minecraft:cobblestone' })";
        let hits = scan_text(text, crate::engine::KUBEJS);
        assert!(hits.is_empty());
    }

    #[test]
    fn keywords_in_strings_and_unrelated_calls_do_not_create_actions() {
        let text = r#"
            console.info("event.remove('minecraft:diamond')");
            helper.remove("minecraft:diamond");
        "#;
        let hits = scan_text(text, crate::engine::KUBEJS);
        assert!(hits.is_empty());
    }
}
