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
use intermed_doctor_core::facts::{FactWrite, SourceRef, kind};
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

/// Locate script files under the target's roots. Returns `(path, engine)`.
pub fn script_files(target: &Target) -> Vec<(PathBuf, &'static str)> {
    discover_script_files(target).files
}

/// Whether a conventional script root exists, even if its contents cannot be
/// enumerated. This lets the collector report an incomplete discovery instead
/// of being marked not-applicable.
pub fn has_script_roots(target: &Target) -> bool {
    script_search_roots(target)
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
    let roots = script_search_roots(target);

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

fn script_search_roots(target: &Target) -> Vec<PathBuf> {
    let mut roots = target.candidate_roots();
    // A mods-dir target points *at* `mods/`; scripts live beside it in the game
    // root. Other target kinds already name their containment boundary, and
    // scanning their parent could leak scripts from an adjacent instance.
    if target.kind == intermed_doctor_core::TargetKind::ModsDir
        && let Some(parent) = target.path.parent()
    {
        roots.push(parent.to_path_buf());
    }
    roots.sort();
    roots.dedup();
    roots
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
    let mut entries = entries.collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        let left = left.as_ref().ok().map(|entry| entry.file_name());
        let right = right.as_ref().ok().map(|entry| entry.file_name());
        left.cmp(&right)
    });
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
    operation: &'static str,
    domain: &'static str,
    selector_kind: String,
    target: String,
    selector_json: String,
    confidence: f32,
    lineno: usize,
    excerpt: String,
}

/// Scan one script file's text for removals/replacements.
fn scan_text(text: &str, engine: &str) -> Vec<ScriptHit> {
    let mut hits = Vec::new();
    for call in logical_calls(text) {
        let lower = call.name.to_ascii_lowercase();
        let pairs = object_literal_selectors(&call.body);
        let strings = string_literals(&call.body);
        let (fact_kind, via, operation, domain, selectors) = if matches!(
            lower.as_str(),
            "replaceoutput" | "replaceinput" | "event.replaceoutput" | "event.replaceinput"
        ) {
            let selectors = if !pairs.is_empty() {
                pairs
            } else {
                strings
                    .first()
                    .filter(|value| valid_id_literal(value))
                    .map(|value| {
                        vec![(
                            if lower.contains("input") {
                                "input-item"
                            } else {
                                "output-item"
                            }
                            .to_string(),
                            value.clone(),
                        )]
                    })
                    .unwrap_or_default()
            };
            (
                kind::RUNTIME_SCRIPT_MODIFIES_RECIPE,
                "recipe-replaced",
                "replace",
                "recipe",
                selectors,
            )
        } else if lower.ends_with("removebymodid") || lower.ends_with("removebymod") {
            let Some(value) = strings.first().filter(|value| valid_id_literal(value)) else {
                continue;
            };
            (
                kind::RUNTIME_REMOVED_RECIPE,
                "recipe-removed",
                "remove",
                "recipe",
                vec![("recipe-namespace".to_string(), value.clone())],
            )
        } else if lower.ends_with("removebyname") || lower.ends_with("removerecipe") {
            let Some(value) = strings.iter().find(|value| valid_id_literal(value)) else {
                continue;
            };
            (
                kind::RUNTIME_REMOVED_RECIPE,
                "recipe-removed",
                "remove",
                "recipe",
                vec![("recipe-id".to_string(), value.clone())],
            )
        } else if lower == "event.remove"
            || (engine == crate::engine::CRAFTTWEAKER && lower.ends_with(".remove"))
        {
            let selectors = if !pairs.is_empty() {
                pairs
            } else if let Some(item) = bracket_item_literal(&call.body) {
                vec![("output-item".to_string(), item)]
            } else {
                strings
                    .iter()
                    .find(|value| valid_id_literal(value))
                    .map(|value| vec![("recipe-id".to_string(), value.clone())])
                    .unwrap_or_default()
            };
            (
                kind::RUNTIME_REMOVED_RECIPE,
                "recipe-removed",
                "remove",
                "recipe",
                selectors,
            )
        } else if lower.contains("tag")
            && (lower.ends_with(".remove") || lower.ends_with("removefrom"))
        {
            let Some(value) = strings.iter().find(|value| valid_id_literal(value)) else {
                continue;
            };
            (
                kind::RUNTIME_REMOVED_TAG,
                "tag-removed",
                "remove",
                "tag",
                vec![("tag".to_string(), value.clone())],
            )
        } else {
            continue;
        };
        if selectors.is_empty() {
            continue;
        }
        let selector_json = serde_json::to_string(&selectors).unwrap_or_default();
        let (selector_kind, target, confidence) = if selectors.len() == 1 {
            let (selector_kind, value) = &selectors[0];
            (
                selector_kind.clone(),
                value.clone(),
                if selector_kind == "recipe-namespace" {
                    CONF_MOD_SCOPED
                } else {
                    CONF_EXACT
                },
            )
        } else {
            ("composite".to_string(), selector_json.clone(), CONF_EXACT)
        };
        hits.push(ScriptHit {
            fact_kind,
            via,
            operation,
            domain,
            selector_kind,
            target,
            selector_json,
            confidence,
            lineno: call.line,
            excerpt: truncate(&call.body.replace('\n', " "), 200),
        });
    }
    hits
}

struct LogicalCall {
    name: String,
    body: String,
    line: usize,
}

/// Extract balanced calls across physical lines. Comments are blanked while
/// newlines and quoted literals are preserved, so provenance remains physical.
fn logical_calls(text: &str) -> Vec<LogicalCall> {
    const MAX_CALL_BYTES: usize = 256 * 1024;
    let clean = strip_comments(text);
    let re = Regex::new(r"(?m)([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(")
        .expect("static call regex");
    let bytes = clean.as_bytes();
    let code_mask = code_position_mask(&clean);
    let mut out = Vec::new();
    for captures in re.captures_iter(&clean) {
        let whole = captures.get(0).expect("whole match");
        if !code_mask.get(whole.start()).copied().unwrap_or(false) {
            continue;
        }
        let open = whole.end() - 1;
        let end_limit = bytes.len().min(open.saturating_add(MAX_CALL_BYTES));
        let mut depth = 0usize;
        let mut quote = None;
        let mut escaped = false;
        let mut end = None;
        for (offset, byte) in bytes[open..end_limit].iter().copied().enumerate() {
            if let Some(current) = quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == current {
                    quote = None;
                }
                continue;
            }
            match byte {
                b'\'' | b'"' | b'`' => quote = Some(byte),
                b'(' => depth += 1,
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = Some(open + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { continue };
        out.push(LogicalCall {
            name: captures.get(1).expect("call name").as_str().to_string(),
            body: clean[open + 1..end - 1].to_string(),
            line: clean[..whole.start()]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
        });
    }
    out
}

fn code_position_mask(text: &str) -> Vec<bool> {
    let bytes = text.as_bytes();
    let mut mask = vec![true; bytes.len()];
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if let Some(current) = quote {
            mask[index] = false;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == current {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"' | b'`') {
            mask[index] = false;
            quote = Some(byte);
        }
    }
    mask
}

fn strip_comments(text: &str) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(text.len());
    let mut index = 0usize;
    let mut quote = None;
    let mut block = false;
    while index < chars.len() {
        if block {
            if chars.get(index) == Some(&'*') && chars.get(index + 1) == Some(&'/') {
                block = false;
                out.extend([' ', ' ']);
                index += 2;
            } else {
                out.push(if chars[index] == '\n' { '\n' } else { ' ' });
                index += 1;
            }
        } else if let Some(current) = quote {
            out.push(chars[index]);
            if chars[index] == '\\' && index + 1 < chars.len() {
                index += 1;
                out.push(chars[index]);
            } else if chars[index] == current {
                quote = None;
            }
            index += 1;
        } else if matches!(chars[index], '\'' | '"' | '`') {
            quote = Some(chars[index]);
            out.push(chars[index]);
            index += 1;
        } else if chars.get(index) == Some(&'/') && chars.get(index + 1) == Some(&'/') {
            while index < chars.len() && chars[index] != '\n' {
                out.push(' ');
                index += 1;
            }
        } else if chars.get(index) == Some(&'/') && chars.get(index + 1) == Some(&'*') {
            block = true;
            out.extend([' ', ' ']);
            index += 2;
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }
    out
}

fn string_literals(text: &str) -> Vec<String> {
    Regex::new(r#"['\"]([^'\"]+)['\"]"#)
        .expect("static string regex")
        .captures_iter(text)
        .filter_map(|captures| captures.get(1).map(|value| value.as_str().to_string()))
        .collect()
}

fn object_literal_selectors(text: &str) -> Vec<(String, String)> {
    let re = Regex::new(r#"(?i)\b(id|mod|type|input|output|tag)\s*:\s*['\"]([^'\"]+)['\"]"#)
        .expect("static selector regex");
    re.captures_iter(text)
        .filter_map(|captures| {
            let key = captures.get(1)?.as_str().to_ascii_lowercase();
            let value = captures.get(2)?.as_str().to_string();
            valid_id_literal(&value).then(|| {
                let selector = match key.as_str() {
                    "id" => "recipe-id",
                    "mod" => "recipe-namespace",
                    "type" => "recipe-type",
                    "input" => "input-item",
                    "output" => "output-item",
                    "tag" => "tag",
                    _ => unreachable!(),
                };
                (selector.to_string(), value)
            })
        })
        .collect()
}

fn bracket_item_literal(text: &str) -> Option<String> {
    Regex::new(r"(?i)<item:([a-z0-9_.-]+:[a-z0-9_./-]+)>")
        .expect("static item regex")
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
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

pub fn emit(store: &mut dyn FactWrite, target: &Target) -> ScriptScanResult {
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
        let scope = script_scope(path);
        for (ordinal, hit) in scan_text(&text, engine).into_iter().enumerate() {
            let occurrence = format!("{}:{}:{}", locator, hit.lineno + 1, ordinal);
            store
                .fact("static-script-scanner", kind::SCRIPT_MUTATION)
                .subject(occurrence)
                .attr("operation", hit.operation)
                .attr("domain", hit.domain)
                .attr("selector_kind", hit.selector_kind.clone())
                .attr("selector_value", hit.target.clone())
                .attr("selector_json", hit.selector_json.clone())
                .attr("origin", "static-declared")
                .attr("applicability", scope)
                .attr("session_relation", "not-applicable")
                .attr("session_id", "")
                .attr("engine", *engine)
                .attr("via", hit.via)
                .attr("line", (hit.lineno as i64) + 1)
                .attr("excerpt", hit.excerpt.clone())
                .source(SourceRef::at_line(locator.clone(), (hit.lineno as u32) + 1))
                .confidence(hit.confidence)
                .emit();
            emitted += 1;
            store
                .fact("static-script-scanner", hit.fact_kind)
                .subject(hit.target)
                .attr("engine", *engine)
                .attr("via", hit.via)
                .attr("source_kind", "script")
                .attr("evidence_origin", "static-declared")
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

fn script_scope(path: &Path) -> &'static str {
    for component in path.components() {
        let value = component.as_os_str().to_string_lossy();
        match value.as_ref() {
            "server_scripts" => return "server",
            "client_scripts" => return "client",
            "startup_scripts" => return "startup",
            _ => {}
        }
    }
    "shared"
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
    fn multiline_kubejs_selector_is_one_typed_action() {
        let text = r#"
            event.remove({
                output: 'minecraft:diamond',
                type: 'minecraft:crafting_shaped'
            })
        "#;
        let hits = scan_text(text, crate::engine::KUBEJS);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].selector_kind, "composite");
        assert!(hits[0].selector_json.contains("output-item"));
        assert!(hits[0].selector_json.contains("recipe-type"));
    }

    #[test]
    fn component_scope_does_not_match_filename_substrings() {
        assert_eq!(
            script_scope(Path::new("/pack/kubejs/server_scripts/a.js")),
            "server"
        );
        assert_eq!(
            script_scope(Path::new("/pack/not_server_scripts/a.js")),
            "shared"
        );
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

    #[test]
    fn instance_discovery_never_crosses_into_a_sibling_parent_root() {
        let root = std::env::temp_dir().join(format!(
            "intermed-script-containment-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let instance = root.join("instances").join("one");
        let adjacent = root.join("instances").join("kubejs/server_scripts");
        std::fs::create_dir_all(&instance).unwrap();
        std::fs::create_dir_all(&adjacent).unwrap();
        std::fs::write(
            adjacent.join("leak.js"),
            "event.remove({ id: 'minecraft:stone' })",
        )
        .unwrap();
        let target = Target::with_kind(&instance, intermed_doctor_core::TargetKind::Instance);

        assert!(discover_script_files(&target).files.is_empty());
        std::fs::remove_dir_all(root).ok();
    }
}
