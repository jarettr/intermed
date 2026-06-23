//! Manifest-only modpack detection (`.mrpack`, CurseForge export).
//!
//! A Modrinth `.mrpack` or CurseForge export describes its mods *by reference* —
//! a download URL + hash, or a `(projectID, fileID)` pair — and ships only
//! `overrides/`. The actual jars are not in the archive. After extraction the
//! `mods/` tree can therefore be empty, and the metadata/deps/security/SBOM
//! layers would scan nothing and (misleadingly) report a clean bill of health.
//!
//! This collector parses the manifest into `MODPACK_*` facts and, when the
//! referenced mod jars are not materialized on disk, emits a
//! [`MODPACK_INCOMPLETE`](intermed_facts::kind::MODPACK_INCOMPLETE) fact that
//! [`ModpackIntegrityRule`] turns into a clear "analysis is incomplete" finding.
//! It never downloads anything.

use std::path::Path;

use intermed_evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_facts::{SourceRef, kind};
use serde::Deserialize;

use crate::collector::{CollectCtx, Collector, CollectorOutcome};
use crate::layer::Layer;
use crate::rule::{Rule, RuleCtx};
use crate::target::Target;

const EXTRACTOR: &str = "modpack-manifest";

/// Collector: parse a modpack manifest and flag manifest-only packs.
pub struct ModpackManifestCollector;

impl Collector for ModpackManifestCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }
    fn layer(&self) -> Layer {
        Layer::TargetDetection
    }
    fn applies(&self, target: &Target) -> bool {
        find_manifest(target).is_some()
    }
    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let Some((root, manifest)) = find_manifest(ctx.target) else {
            return CollectorOutcome::skipped("no modpack manifest present");
        };
        let mut emitted = 0usize;
        let locator = manifest.locator.clone();

        match manifest.parsed {
            ParsedManifest::Modrinth {
                name,
                mod_file_count,
                files,
            } => {
                let manifest_id = ctx
                    .store
                    .fact(EXTRACTOR, kind::MODPACK_MANIFEST)
                    .subject(name.clone().unwrap_or_else(|| "modrinth-pack".into()))
                    .attr("format", "modrinth")
                    .attr("referenced_mods", mod_file_count as i64)
                    .source(SourceRef::file(locator.clone()))
                    .emit();
                emitted += 1;
                for f in &files {
                    ctx.store
                        .fact(EXTRACTOR, kind::MODPACK_FILE_REF)
                        .subject(f.path.clone())
                        .attr("hash", f.sha512.clone().unwrap_or_default())
                        .attr("download", f.download.clone().unwrap_or_default())
                        .source(SourceRef::file(locator.clone()))
                        .emit();
                    emitted += 1;
                }
                emitted += emit_incomplete_if_needed(
                    ctx,
                    &root,
                    manifest_id,
                    mod_file_count,
                    "modrinth",
                    &locator,
                );
            }
            ParsedManifest::CurseForge { name, projects } => {
                let manifest_id = ctx
                    .store
                    .fact(EXTRACTOR, kind::MODPACK_MANIFEST)
                    .subject(name.clone().unwrap_or_else(|| "curseforge-pack".into()))
                    .attr("format", "curseforge")
                    .attr("referenced_mods", projects.len() as i64)
                    .source(SourceRef::file(locator.clone()))
                    .emit();
                emitted += 1;
                for p in &projects {
                    ctx.store
                        .fact(EXTRACTOR, kind::MODPACK_PROJECT_REF)
                        .subject(format!("curseforge:{}", p.project_id))
                        .attr("project_id", p.project_id)
                        .attr("file_id", p.file_id)
                        .attr("required", p.required)
                        .source(SourceRef::file(locator.clone()))
                        .emit();
                    emitted += 1;
                }
                emitted += emit_incomplete_if_needed(
                    ctx,
                    &root,
                    manifest_id,
                    projects.len(),
                    "curseforge",
                    &locator,
                );
            }
        }

        CollectorOutcome::active(emitted, "parsed modpack manifest")
    }
}

/// Below this materialized/referenced ratio the analysis covered too little of the
/// pack to be trusted, so a `MODPACK_INCOMPLETE` fact is emitted. At or above it
/// (near-exact materialization), the difference is treated as launcher noise and
/// stays silent.
const COMPLETENESS_SILENT_THRESHOLD: f64 = 0.9;

/// Emit a `MODPACK_INCOMPLETE` fact when the manifest references mods but the pack
/// is **not sufficiently materialized** on disk — not just the zero-jar case but
/// any partial export, carrying a completeness ratio so the rule can scale
/// severity. Returns the number of facts emitted (0 or 1).
fn emit_incomplete_if_needed(
    ctx: &mut CollectCtx<'_>,
    root: &Path,
    manifest_fact: intermed_facts::FactId,
    referenced_mods: usize,
    format: &str,
    locator: &str,
) -> usize {
    if referenced_mods == 0 {
        return 0;
    }
    let materialized = count_materialized_jars(root);
    let completeness = materialized as f64 / referenced_mods as f64;
    if completeness >= COMPLETENESS_SILENT_THRESHOLD {
        return 0;
    }
    ctx.store
        .fact(EXTRACTOR, kind::MODPACK_INCOMPLETE)
        .subject(format.to_string())
        .attr("referenced_mods", referenced_mods as i64)
        .attr("materialized_jars", materialized as i64)
        .attr("completeness_pct", (completeness * 100.0).round() as i64)
        // Fact-to-fact provenance: the Fact model carries finding-level evidence
        // edges, so a fact references another fact by id attribute. `--explain`
        // and the DuckDB backend can join on it.
        .attr("manifest_fact_id", manifest_fact.0 as i64)
        .source(SourceRef::file(locator.to_string()))
        .confidence(0.95)
        .emit();
    1
}

/// Rule: turn `MODPACK_INCOMPLETE` into a user-facing warning, severity scaled by
/// how little of the pack was actually materialized.
pub struct ModpackIntegrityRule;

impl Rule for ModpackIntegrityRule {
    fn id(&self) -> &'static str {
        "modpack-incomplete"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in ctx.store.by_kind(kind::MODPACK_INCOMPLETE) {
            let referenced = f.attr_int("referenced_mods").unwrap_or(0);
            let materialized = f.attr_int("materialized_jars").unwrap_or(0);
            let completeness_pct = f.attr_int("completeness_pct").unwrap_or_else(|| {
                if referenced > 0 {
                    materialized * 100 / referenced
                } else {
                    0
                }
            });
            // 0 jars or < 50% covered is pack-breaking for analysis (Warn);
            // 50–89% covered is a coverage caveat (Note).
            let severity = if completeness_pct < 50 {
                Severity::Warn
            } else {
                Severity::Note
            };
            out.push(
                Finding::builder(
                    "modpack-incomplete",
                    format!("modpack-incomplete:{}", f.subject),
                )
                .severity(severity)
                .category(Category::Packaging)
                .title(if materialized == 0 {
                    "Manifest-only modpack: mod jars are not present".to_string()
                } else {
                    format!("Partially materialized modpack: {completeness_pct}% of mods present")
                })
                .explanation(format!(
                    "This {} modpack references {referenced} mod file(s) by download \
                         reference, but only {materialized} mod jar(s) are materialized on disk \
                         ({completeness_pct}% coverage). Dependency, security and SBOM analysis \
                         covers only the materialized jars plus the pack's `overrides/` and \
                         manifest — the rest was not inspected.",
                    f.subject
                ))
                .evidence(EvidenceEdge::subject(f.id))
                .fix(FixCandidate::advice(
                    "Install/export the pack with its mods materialized (e.g. let the \
                         launcher download them), then re-run intermed against the instance.",
                ))
                .tag("modpack")
                .tag("incomplete")
                .build(),
            );
        }
        out
    }
}

// ── Manifest discovery + parsing ──────────────────────────────────────────────

struct DiscoveredManifest {
    locator: String,
    parsed: ParsedManifest,
}

enum ParsedManifest {
    Modrinth {
        name: Option<String>,
        mod_file_count: usize,
        files: Vec<ModrinthFile>,
    },
    CurseForge {
        name: Option<String>,
        projects: Vec<CurseProject>,
    },
}

struct ModrinthFile {
    path: String,
    sha512: Option<String>,
    download: Option<String>,
}

struct CurseProject {
    project_id: i64,
    file_id: i64,
    required: bool,
}

fn find_manifest(target: &Target) -> Option<(std::path::PathBuf, DiscoveredManifest)> {
    for root in target.candidate_roots() {
        let modrinth = root.join("modrinth.index.json");
        if modrinth.is_file() {
            if let Some(parsed) = parse_modrinth(&modrinth) {
                return Some((
                    root.clone(),
                    DiscoveredManifest {
                        locator: "modrinth.index.json".to_string(),
                        parsed,
                    },
                ));
            }
        }
        let curse = root.join("manifest.json");
        if curse.is_file() {
            if let Some(parsed) = parse_curseforge(&curse) {
                return Some((
                    root.clone(),
                    DiscoveredManifest {
                        locator: "manifest.json".to_string(),
                        parsed,
                    },
                ));
            }
        }
    }
    None
}

#[derive(Deserialize)]
struct RawModrinth {
    #[serde(rename = "formatVersion", default)]
    format_version: u32,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    files: Vec<RawModrinthFile>,
}

#[derive(Deserialize)]
struct RawModrinthFile {
    path: String,
    #[serde(default)]
    hashes: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    downloads: Vec<String>,
}

fn parse_modrinth(path: &Path) -> Option<ParsedManifest> {
    let text = std::fs::read_to_string(path).ok()?;
    let raw: RawModrinth = serde_json::from_str(&text).ok()?;
    if raw.format_version == 0 {
        return None;
    }
    let files: Vec<ModrinthFile> = raw
        .files
        .into_iter()
        .map(|f| ModrinthFile {
            sha512: f.hashes.get("sha512").cloned(),
            download: f.downloads.into_iter().next(),
            path: f.path,
        })
        .collect();
    let mod_file_count = files.iter().filter(|f| is_mod_path(&f.path)).count();
    Some(ParsedManifest::Modrinth {
        name: raw.name,
        mod_file_count,
        files,
    })
}

#[derive(Deserialize)]
struct RawCurse {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    files: Vec<RawCurseFile>,
}

#[derive(Deserialize)]
struct RawCurseFile {
    #[serde(rename = "projectID", default)]
    project_id: i64,
    #[serde(rename = "fileID", default)]
    file_id: i64,
    #[serde(default = "default_true")]
    required: bool,
}

fn default_true() -> bool {
    true
}

fn parse_curseforge(path: &Path) -> Option<ParsedManifest> {
    let text = std::fs::read_to_string(path).ok()?;
    let raw: RawCurse = serde_json::from_str(&text).ok()?;
    // A CurseForge manifest must carry a files array to be one we understand.
    if raw.files.is_empty() {
        return None;
    }
    let projects = raw
        .files
        .into_iter()
        .map(|f| CurseProject {
            project_id: f.project_id,
            file_id: f.file_id,
            required: f.required,
        })
        .collect();
    Some(ParsedManifest::CurseForge {
        name: raw.name,
        projects,
    })
}

fn is_mod_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("mods/") && lower.ends_with(".jar")
}

/// Count actual `*.jar` files under the mod directories of an extracted pack.
fn count_materialized_jars(root: &Path) -> usize {
    let mut count = 0;
    for sub in ["mods", "overrides/mods"] {
        let dir = root.join(sub);
        if let Ok(rd) = std::fs::read_dir(&dir) {
            count += rd
                .flatten()
                .filter(|e| {
                    e.path()
                        .extension()
                        .and_then(|x| x.to_str())
                        .is_some_and(|x| x.eq_ignore_ascii_case("jar"))
                })
                .count();
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::TargetKind;
    use intermed_facts::FactStore;

    #[test]
    fn manifest_parsers_survive_garbage_input() {
        // Untrusted modpack manifests: malformed JSON must yield `None`, not panic.
        let root = temp_dir("fuzz");
        let nasty = [
            "",
            "{",
            "[]",
            "null",
            "\u{0}\u{0}",
            "{\"files\":1}",
            "{\"files\":[{\"path\":42}]}",
            "{\"minecraft\":{\"modLoaders\":\"x\"}}",
            "not json",
            "{\"files\":[null,null]}",
            "{\"dependencies\":[]}",
            "{\"files\":[{}]}",
            "{\"manifestType\":\"minecraftModpack\",\"files\":\"\"}",
        ];
        for (i, input) in nasty.iter().enumerate() {
            let mr = root.join(format!("modrinth-{i}.json"));
            let cf = root.join(format!("curse-{i}.json"));
            std::fs::write(&mr, input).unwrap();
            std::fs::write(&cf, input).unwrap();
            let _ = parse_modrinth(&mr);
            let _ = parse_curseforge(&cf);
        }
        std::fs::remove_dir_all(root).ok();
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "imd-modpack-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn target_at(root: &Path) -> Target {
        Target {
            path: root.to_path_buf(),
            kind: TargetKind::Instance,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        }
    }

    #[test]
    fn mrpack_without_jars_flags_incomplete() {
        let root = temp_dir("mrpack");
        std::fs::write(
            root.join("modrinth.index.json"),
            r#"{"formatVersion":1,"name":"Test","files":[
                {"path":"mods/sodium.jar","hashes":{"sha512":"abc"},"downloads":["https://e/x.jar"]}
            ]}"#,
        )
        .unwrap();
        let target = target_at(&root);
        assert!(ModpackManifestCollector.applies(&target));

        let mut store = FactStore::new();
        let settings = crate::settings::DiagnosisSettings::default();
        let mut ctx = CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: &settings,
        };
        ModpackManifestCollector.collect(&mut ctx);
        assert_eq!(store.by_kind(kind::MODPACK_MANIFEST).count(), 1);
        assert_eq!(store.by_kind(kind::MODPACK_FILE_REF).count(), 1);
        assert_eq!(store.by_kind(kind::MODPACK_INCOMPLETE).count(), 1);

        let rctx = RuleCtx::for_test(&store, &target);
        let findings = ModpackIntegrityRule.evaluate(&rctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn partially_materialized_pack_is_flagged_with_ratio() {
        let root = temp_dir("mrpack-partial");
        std::fs::create_dir_all(root.join("mods")).unwrap();
        std::fs::write(root.join("mods").join("sodium.jar"), b"jar").unwrap();
        // 4 referenced mods, only 1 jar on disk → 25% coverage.
        std::fs::write(
            root.join("modrinth.index.json"),
            r#"{"formatVersion":1,"name":"P","files":[
                {"path":"mods/sodium.jar","hashes":{}},
                {"path":"mods/lithium.jar","hashes":{}},
                {"path":"mods/iris.jar","hashes":{}},
                {"path":"mods/ferrite.jar","hashes":{}}
            ]}"#,
        )
        .unwrap();
        let target = target_at(&root);
        let mut store = FactStore::new();
        let settings = crate::settings::DiagnosisSettings::default();
        let mut ctx = CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: &settings,
        };
        ModpackManifestCollector.collect(&mut ctx);
        let incomplete = store
            .by_kind(kind::MODPACK_INCOMPLETE)
            .next()
            .expect("partial pack flagged");
        assert_eq!(incomplete.attr_int("completeness_pct"), Some(25));
        assert!(incomplete.attr_int("manifest_fact_id").is_some());

        let rctx = RuleCtx::for_test(&store, &target);
        let findings = ModpackIntegrityRule.evaluate(&rctx);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].title.contains("25%"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn mrpack_with_jars_is_not_flagged() {
        let root = temp_dir("mrpack-ok");
        std::fs::create_dir_all(root.join("mods")).unwrap();
        std::fs::write(root.join("mods").join("sodium.jar"), b"jar").unwrap();
        std::fs::write(
            root.join("modrinth.index.json"),
            r#"{"formatVersion":1,"files":[{"path":"mods/sodium.jar","hashes":{}}]}"#,
        )
        .unwrap();
        let target = target_at(&root);
        let mut store = FactStore::new();
        let settings = crate::settings::DiagnosisSettings::default();
        let mut ctx = CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: &settings,
        };
        ModpackManifestCollector.collect(&mut ctx);
        assert_eq!(store.by_kind(kind::MODPACK_INCOMPLETE).count(), 0);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn curseforge_manifest_emits_project_refs() {
        let root = temp_dir("curse");
        std::fs::write(
            root.join("manifest.json"),
            r#"{"name":"CF","files":[{"projectID":238222,"fileID":4949,"required":true}]}"#,
        )
        .unwrap();
        let target = target_at(&root);
        let mut store = FactStore::new();
        let settings = crate::settings::DiagnosisSettings::default();
        let mut ctx = CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: &settings,
        };
        ModpackManifestCollector.collect(&mut ctx);
        assert_eq!(store.by_kind(kind::MODPACK_PROJECT_REF).count(), 1);
        assert_eq!(store.by_kind(kind::MODPACK_INCOMPLETE).count(), 1);
        std::fs::remove_dir_all(root).ok();
    }
}
