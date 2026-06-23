//! Static data-pack script scanner (KubeJS `.js`, CraftTweaker `.zs`).
//!
//! The log scanner in the crate root reads what a *previous run* logged. But a
//! pack ships its scripts on disk, and a static analysis (mods-dir / instance with
//! no run yet) still needs to know what they remove or replace — otherwise Layer M
//! will warn about a recipe override that a script deletes anyway (a false
//! positive). This module reads the script *source* and extracts the
//! removals/replacements with a confidence label.
//!
//! Honesty: this is a line/keyword heuristic, not a JS/ZenScript parser. We only
//! emit a fact when a concrete namespaced id literal (`mod:path`) is present on a
//! removal/replacement line, and stamp it with a confidence below the structural
//! collectors. A dynamic expression (computed id) yields no fact rather than a
//! guess.

use std::path::{Path, PathBuf};

use intermed_doctor_core::Target;
use intermed_doctor_core::facts::{FactStore, SourceRef, kind};
use regex::Regex;

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

/// A namespaced id (`mod:path`) or bare namespace literal inside quotes.
fn id_regex() -> Regex {
    Regex::new(r#"['"](#?[a-z0-9_.\-]+(?::[a-z0-9_./\-]+)?)['"]"#).expect("valid id regex")
}

/// Locate script files under the target's roots. Returns `(path, engine)`.
pub fn script_files(target: &Target) -> Vec<(PathBuf, &'static str)> {
    let mut roots: Vec<PathBuf> = target.candidate_roots();
    // A mods-dir target points *at* `mods/`; scripts live beside it in the game
    // root, so include the parent.
    if let Some(parent) = target.path.parent() {
        roots.push(parent.to_path_buf());
    }
    roots.sort();
    roots.dedup();

    let mut out = Vec::new();
    for root in &roots {
        // KubeJS: kubejs/{server,startup,client}_scripts/**.js
        let kubejs = root.join("kubejs");
        for sub in ["server_scripts", "startup_scripts", "client_scripts"] {
            collect_files(&kubejs.join(sub), "js", crate::engine::KUBEJS, 0, &mut out);
        }
        // CraftTweaker: scripts/**.zs
        collect_files(
            &root.join("scripts"),
            "zs",
            crate::engine::CRAFTTWEAKER,
            0,
            &mut out,
        );
        if out.len() >= MAX_SCRIPT_FILES {
            break;
        }
    }
    out.truncate(MAX_SCRIPT_FILES);
    out
}

fn collect_files(
    dir: &Path,
    ext: &str,
    engine: &'static str,
    depth: usize,
    out: &mut Vec<(PathBuf, &'static str)>,
) {
    if depth > MAX_DEPTH || out.len() >= MAX_SCRIPT_FILES || !dir.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, ext, engine, depth + 1, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
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
fn scan_text(text: &str, engine: &str, id_re: &Regex) -> Vec<ScriptHit> {
    let mut hits = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('*') {
            continue;
        }
        let lower = line.to_ascii_lowercase();

        // Classify the action on this line (replace > remove; mod-scoped remove).
        let (fact_kind, via, mod_scoped) =
            if lower.contains("replaceoutput") || lower.contains("replaceinput") {
                (
                    kind::RUNTIME_SCRIPT_MODIFIES_RECIPE,
                    "recipe-replaced",
                    false,
                )
            } else if lower.contains("removebymodid") || lower.contains("removebymod(") {
                (kind::RUNTIME_REMOVED_RECIPE, "recipe-removed", true)
            } else if is_tag_removal(&lower) {
                (kind::RUNTIME_REMOVED_TAG, "tag-removed", false)
            } else if is_recipe_removal(&lower, engine) {
                (kind::RUNTIME_REMOVED_RECIPE, "recipe-removed", false)
            } else {
                continue;
            };

        // The first namespaced/namespace literal on the line is the target.
        let Some(cap) = id_re.captures(line).and_then(|c| c.get(1)) else {
            continue; // dynamic / computed id — no confident fact.
        };
        let target = cap.as_str().to_string();
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

fn is_recipe_removal(lower: &str, engine: &str) -> bool {
    if engine == crate::engine::CRAFTTWEAKER {
        lower.contains("removebyname")
            || lower.contains("removerecipe")
            || lower.contains("recipes.remove")
            || lower.contains(".remove(")
    } else {
        // KubeJS: event.remove(...) inside a recipes(event => …) block.
        lower.contains(".remove(") || lower.contains("event.remove")
    }
}

fn is_tag_removal(lower: &str) -> bool {
    lower.contains("tag") && (lower.contains(".remove(") || lower.contains("removefrom"))
        // Avoid double-counting recipe removals that merely mention "tag".
        && !lower.contains("recipe")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

/// Scan all script files under `target` and emit facts. Returns count emitted.
pub fn emit(store: &mut FactStore, target: &Target) -> usize {
    let files = script_files(target);
    if files.is_empty() {
        return 0;
    }
    let id_re = id_regex();
    let mut emitted = 0usize;
    for (path, engine) in &files {
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        if meta.len() > MAX_SCRIPT_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let locator = path.display().to_string();
        for hit in scan_text(&text, engine, &id_re) {
            store
                .fact("static-script-scanner", hit.fact_kind)
                .subject(hit.target)
                .attr("engine", *engine)
                .attr("via", hit.via)
                .attr("source_kind", "script")
                .attr("line", (hit.lineno as i64) + 1)
                .attr("excerpt", hit.excerpt)
                .source(SourceRef::at_line(locator.clone(), (hit.lineno as u32) + 1))
                .confidence(hit.confidence)
                .emit();
            emitted += 1;
        }
    }
    emitted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubejs_remove_captures_recipe_id() {
        let text =
            "ServerEvents.recipes(event => {\n  event.remove({ id: 'minecraft:cobblestone' })\n})";
        let hits = scan_text(text, crate::engine::KUBEJS, &id_regex());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].target, "minecraft:cobblestone");
        assert_eq!(hits[0].fact_kind, kind::RUNTIME_REMOVED_RECIPE);
        assert_eq!(hits[0].confidence, CONF_EXACT);
    }

    #[test]
    fn kubejs_replace_output_is_modify() {
        let text = "event.replaceOutput({}, 'minecraft:diamond', 'minecraft:coal')";
        let hits = scan_text(text, crate::engine::KUBEJS, &id_regex());
        assert_eq!(hits[0].fact_kind, kind::RUNTIME_SCRIPT_MODIFIES_RECIPE);
    }

    #[test]
    fn crafttweaker_remove_by_name() {
        let text = r#"craftingTable.removeByName("minecraft:torch");"#;
        let hits = scan_text(text, crate::engine::CRAFTTWEAKER, &id_regex());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].target, "minecraft:torch");
        assert_eq!(hits[0].fact_kind, kind::RUNTIME_REMOVED_RECIPE);
    }

    #[test]
    fn remove_by_modid_is_mod_scoped() {
        let text = r#"craftingTable.removeByModid("create");"#;
        let hits = scan_text(text, crate::engine::CRAFTTWEAKER, &id_regex());
        assert_eq!(hits[0].target, "create");
        assert_eq!(hits[0].confidence, CONF_MOD_SCOPED);
    }

    #[test]
    fn dynamic_id_yields_no_fact() {
        let text = "event.remove({ id: someVariable })";
        let hits = scan_text(text, crate::engine::KUBEJS, &id_regex());
        assert!(hits.is_empty());
    }

    #[test]
    fn comment_lines_ignored() {
        let text = "// event.remove({ id: 'minecraft:cobblestone' })";
        let hits = scan_text(text, crate::engine::KUBEJS, &id_regex());
        assert!(hits.is_empty());
    }
}
