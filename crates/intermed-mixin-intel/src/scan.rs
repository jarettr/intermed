//! Jar-level mixin scanning and modpack aggregation.

use std::io::Read;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use intermed_doctor_core::settings::MixinSettings;
use intermed_doctor_core::{JarCache, Target, TargetKind};

use crate::analyzer::MixinInteractionEngine;
use crate::effect::enrich_classes_with_effects;
use crate::recommendation::recommend_for_scan;
use crate::class_parser::{parse_mixin_class_with_hierarchy, resolve_parse};
use crate::hierarchy::HierarchyIndex;
use crate::hot_path::{any_hot_path, HotPathRules};
use crate::model::{
    MixinAnalysis, MixinClassRecord, MixinConfigRecord, MixinScan, MixinScanFailure,
};
use crate::model::TargetNamespace;
use crate::refmap::{dotted_name, MappingContext, Refmap, TinyMappings};

const EXTRACTOR: &str = "mixin-analyzer";
/// Bump trailing revision when parse / analysis logic changes within a release.
const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-r22");

/// Stable collector / fact extractor id (`mixin-analyzer`).
pub fn extractor_id() -> &'static str {
    EXTRACTOR
}

/// Jar cache revision — bump trailing `-rN` when parse/analysis logic changes in a release.
pub fn cache_version() -> &'static str {
    CACHE_VERSION
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct MixinScanError(pub String);

pub fn scan_target(target: &Target) -> Result<MixinScan, MixinScanError> {
    let Some(dir) = mods_dir(target) else {
        return Err(MixinScanError("target has no mods directory".into()));
    };
    scan_mods_dir(&dir)
}

pub fn scan_mods_dir(dir: &Path) -> Result<MixinScan, MixinScanError> {
    scan_mods_dir_with_cache(dir, None)
}

pub fn scan_mods_dir_with_cache(
    dir: &Path,
    cache: Option<&JarCache>,
) -> Result<MixinScan, MixinScanError> {
    scan_mods_dir_filtered(
        dir,
        cache,
        &intermed_doctor_core::ScanSettings::default(),
        MixinSettings::default(),
        None,
        None,
    )
}

/// Like [`scan_mods_dir_with_cache`] but honors incremental [`ScanSettings`].
pub fn scan_mods_dir_filtered(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
    mixin: MixinSettings,
    minecraft_jar: Option<&Path>,
    minecraft_mappings: Option<&Path>,
) -> Result<MixinScan, MixinScanError> {
    if !dir.is_dir() {
        return Err(MixinScanError(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }

    let jars = intermed_doctor_core::list_jar_archives(dir, scan)
        .map_err(|e| MixinScanError(format!("read {}: {e}", dir.display())))?;

    let results: Vec<_> = jars
        .par_iter()
        .map(|jar| match cache {
            Some(c) => c.get_or_scan(EXTRACTOR, CACHE_VERSION, jar, || scan_jar_cached(jar)),
            None => scan_jar_cached(jar),
        })
        .collect();

    let mut configs = Vec::new();
    let mut classes = Vec::new();
    let mut failures = Vec::new();
    let mut hierarchy = HierarchyIndex::new();
    let mut target_index = crate::apply_failure::TargetClassIndex::new();
    for result in results {
        match result {
            CachedMixinJar::Ok(mut partial) => {
                configs.append(&mut partial.configs);
                classes.append(&mut partial.classes);
                failures.append(&mut partial.failures);
                hierarchy.merge(&partial.hierarchy);
                target_index.merge(&partial.target_index);
            }
            CachedMixinJar::Err { archive, reason } => failures.push(MixinScanFailure {
                archive,
                path: None,
                reason,
            }),
        }
    }

    // Optional Minecraft jar broadens the index to MC classes, so apply-failure
    // checks cover vanilla-targeting mixins (not just mod-targeting ones).
    if let Some(mc_jar) = minecraft_jar {
        if let Err(e) = ingest_minecraft_jar(mc_jar, &mut target_index) {
            failures.push(MixinScanFailure {
                archive: mc_jar.display().to_string(),
                path: None,
                reason: format!("minecraft jar index: {e}"),
            });
        }
    }

    let global_mappings = minecraft_mappings.and_then(load_tiny_mappings_file);

    enrich_classes_with_effects(&mut classes);
    let mut analysis = MixinInteractionEngine::new()
        .with_hierarchy(hierarchy)
        .analyze(&classes);
    let apply_failures = crate::apply_failure::detect_apply_failures(
        &classes,
        &target_index,
        &std::collections::BTreeSet::new(),
        global_mappings.as_ref(),
    );
    // Fold confirmed apply failures into the risk heatmap (risk v2).
    crate::analyzer::fold_apply_failures(&mut analysis.risk_assessments, &apply_failures);
    let recommendations = if mixin.emit_recommendation_facts() {
        recommend_for_scan(
            &classes,
            &analysis.mixin_effects,
            &analysis.conflict_edges,
            &apply_failures,
        )
    } else {
        Vec::new()
    };
    Ok(assemble_scan(
        dir,
        configs,
        classes,
        analysis,
        apply_failures,
        recommendations,
        failures,
    ))
}

/// Ingest every class in a Minecraft client/server jar into the target index.
/// Load a Yarn/Mojmap Tiny v2 file for global named↔intermediary bridging.
fn load_tiny_mappings_file(path: &Path) -> Option<TinyMappings> {
    let text = std::fs::read_to_string(path).ok()?;
    TinyMappings::parse(&text)
}

fn ingest_minecraft_jar(
    jar: &Path,
    target_index: &mut crate::apply_failure::TargetClassIndex,
) -> Result<(), String> {
    let file = std::fs::File::open(jar).map_err(|e| format!("open {}: {e}", jar.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("zip {}: {e}", jar.display()))?;
    let mut hierarchy = HierarchyIndex::new();
    index_jar_classes(&mut archive, &mut hierarchy, target_index);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn assemble_scan(
    dir: &Path,
    configs: Vec<MixinConfigRecord>,
    classes: Vec<MixinClassRecord>,
    analysis: MixinAnalysis,
    apply_failures: Vec<crate::apply_failure::ApplyFailure>,
    recommendations: Vec<crate::model::MixinRecommendationRecord>,
    failures: Vec<MixinScanFailure>,
) -> MixinScan {
    MixinScan {
        target: dir.display().to_string(),
        configs,
        classes,
        overlaps: analysis.overlaps,
        high_risk_overwrites: analysis.high_risk_overwrites,
        interactions: analysis.interactions,
        conflict_edges: analysis.conflict_edges,
        priority_conflicts: analysis.priority_conflicts,
        risk_assessments: analysis.risk_assessments,
        mixin_effects: analysis.mixin_effects,
        recommendations,
        class_complexity: analysis.class_complexity,
        mod_complexity: analysis.mod_complexity,
        bloat: analysis.bloat,
        graph_export: Some(analysis.graph.export()),
        apply_failures,
        failures,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JarScanPartial {
    configs: Vec<MixinConfigRecord>,
    classes: Vec<MixinClassRecord>,
    failures: Vec<MixinScanFailure>,
    #[serde(default)]
    hierarchy: HierarchyIndex,
    /// Member index of this jar's classes, for apply-failure target checks.
    #[serde(default)]
    target_index: crate::apply_failure::TargetClassIndex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CachedMixinJar {
    Ok(JarScanPartial),
    Err { archive: String, reason: String },
}

fn scan_jar_cached(jar: &Path) -> CachedMixinJar {
    match scan_jar(jar) {
        Ok(partial) => CachedMixinJar::Ok(partial),
        Err(e) => CachedMixinJar::Err {
            archive: e.archive,
            reason: e.reason,
        },
    }
}

struct JarScanError {
    archive: String,
    reason: String,
}

fn scan_jar(jar: &Path) -> Result<JarScanPartial, JarScanError> {
    let archive_label = archive_name(jar);
    let file = std::fs::File::open(jar).map_err(|e| JarScanError {
        archive: archive_label.clone(),
        reason: format!("open {}: {e}", jar.display()),
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| JarScanError {
        archive: archive_label.clone(),
        reason: format!("zip {}: {e}", jar.display()),
    })?;
    let mod_id = detect_mod_id(&mut archive).unwrap_or_else(|| archive_stem(&archive_label));
    let config_paths = discover_mixin_configs(&mut archive);
    let tiny = discover_tiny_mappings(&mut archive);

    let mut hierarchy = HierarchyIndex::new();
    let mut target_index = crate::apply_failure::TargetClassIndex::new();
    index_jar_classes(&mut archive, &mut hierarchy, &mut target_index);

    let mut partial = JarScanPartial {
        configs: Vec::new(),
        classes: Vec::new(),
        failures: Vec::new(),
        hierarchy,
        target_index,
    };

    for config_path in config_paths {
        match read_zip_text(&mut archive, &config_path)
            .and_then(|text| parse_config(&archive_label, &config_path, &mod_id, &text).ok())
        {
            Some(config) => {
                let mut mapping = MappingContext::new();
                if let Some(t) = &tiny {
                    mapping = mapping.with_tiny(t.clone());
                }
                if let Some(ref rpath) = config.refmap {
                    if let Some(text) = read_zip_text(&mut archive, rpath) {
                        if let Ok(refmap) = Refmap::parse(&text) {
                            mapping = mapping.with_refmap(refmap);
                        }
                    }
                }

                let hierarchy = &partial.hierarchy;
                for mixin in &config.mixins {
                    let class_path = mixin_class_path(&config.package, mixin);
                    match read_zip_bytes(&mut archive, &class_path) {
                        Some(bytes) => partial.classes.push(analyze_class(
                            &config,
                            mixin,
                            &class_path,
                            &bytes,
                            &mut mapping,
                            hierarchy,
                        )),
                        None => partial.failures.push(MixinScanFailure {
                            archive: archive_label.clone(),
                            path: Some(class_path),
                            reason: "mixin class listed in config but not found".to_string(),
                        }),
                    }
                }
                partial.configs.push(config);
            }
            None => partial.failures.push(MixinScanFailure {
                archive: archive_label.clone(),
                path: Some(config_path),
                reason: "mixin config could not be parsed".to_string(),
            }),
        }
    }
    Ok(partial)
}

pub(crate) fn analyze_class(
    config: &MixinConfigRecord,
    mixin: &str,
    class_path: &str,
    bytes: &[u8],
    mapping: &mut MappingContext,
    hierarchy: &HierarchyIndex,
) -> MixinClassRecord {
    let class_name = join_class_name(&config.package, mixin);
    let tiny_ref = mapping.tiny.as_ref();
    let parsed = parse_mixin_class_with_hierarchy(bytes, hierarchy, tiny_ref);
    let target_namespace = resolve_target_namespaces(&parsed.targets, tiny_ref);
    let rules = HotPathRules::default();
    let hot_paths = any_hot_path(&rules, &parsed.targets, &parsed.raw_injections);
    let injected_methods = resolve_parse(&parsed, mapping);

    MixinClassRecord {
        archive: config.archive.clone(),
        mod_id: config.mod_id.clone(),
        config: config.path.clone(),
        class_name,
        class_path: class_path.to_string(),
        targets: parsed.targets.clone(),
        target_namespace,
        operations: parsed.operations.into_iter().collect(),
        injected_methods,
        shadows: parsed.shadows,
        added_members: parsed.added_members,
        calls: parsed.calls,
        handler_bodies: parsed.handler_bodies,
        target_hierarchy: parsed.target_hierarchy,
        priority: config.priority,
        refmap: config.refmap.clone(),
        hot_paths,
        effects: Vec::new(),
        plugin_gated: config.plugin.is_some(),
    }
}

fn index_jar_classes(
    archive: &mut zip::ZipArchive<std::fs::File>,
    hierarchy: &mut HierarchyIndex,
    target_index: &mut crate::apply_failure::TargetClassIndex,
) {
    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        if !entry.name().ends_with(".class") {
            continue;
        }
        let mut bytes = Vec::new();
        if entry.read_to_end(&mut bytes).is_ok() {
            hierarchy.ingest_class(&bytes);
            target_index.ingest_class(&bytes);
        }
    }
}

fn discover_tiny_mappings(archive: &mut zip::ZipArchive<std::fs::File>) -> Option<TinyMappings> {
    for name in [
        "mappings/mappings.tiny",
        "META-INF/mappings.tiny",
        "mappings.tiny",
    ] {
        if let Some(text) = read_zip_text(archive, name) {
            if let Some(map) = TinyMappings::parse(&text) {
                return Some(map);
            }
        }
    }
    None
}

/// Discover a jar's mixin config files across every loader in one pass:
/// Fabric `fabric.mod.json:mixins`, Quilt `quilt_loader.mixins`, Forge/NeoForge
/// `MANIFEST.MF` `MixinConfigs` *and* `mods.toml` `[[mixins]] config`. If a jar
/// declares none but still ships `*.mixins.json` files, fall back to globbing them
/// (some coremod-era / shaded jars wire mixins without a manifest entry).
fn discover_mixin_configs(archive: &mut zip::ZipArchive<std::fs::File>) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    if let Some(text) = read_zip_text(archive, "fabric.mod.json") {
        out.extend(mixin_paths_from_json(&text, &["mixins"]));
    }
    if let Some(text) = read_zip_text(archive, "quilt.mod.json") {
        out.extend(mixin_paths_from_json(&text, &["quilt_loader", "mixins"]));
        out.extend(mixin_paths_from_json(&text, &["mixins"]));
    }
    if let Some(text) = read_zip_text(archive, "META-INF/MANIFEST.MF") {
        out.extend(mixin_paths_from_manifest(&text));
    }
    for toml in ["META-INF/mods.toml", "META-INF/neoforge.mods.toml"] {
        if let Some(text) = read_zip_text(archive, toml) {
            out.extend(mixin_paths_from_mods_toml(&text));
        }
    }
    if out.is_empty() {
        out.extend(glob_mixin_configs(archive));
    }
    out.into_iter().collect()
}

/// Extract `config = "x.mixins.json"` entries from a Forge/NeoForge `mods.toml`,
/// reading `config` **only inside a `[[mixins]]` table**.
///
/// A naive scan for any `config = …` line is wrong: `mods.toml` has unrelated
/// `config` keys elsewhere (and `[[dependencies]]` tables), so the parser must
/// track which TOML section it is in. Prefer a real parse; fall back to a
/// section-aware state machine if the file does not parse.
fn mixin_paths_from_mods_toml(text: &str) -> Vec<String> {
    if let Ok(value) = toml::from_str::<toml::Value>(text) {
        if let Some(arr) = value.get("mixins").and_then(|m| m.as_array()) {
            return arr
                .iter()
                .filter_map(|m| m.get("config").and_then(|c| c.as_str()))
                .filter(|p| p.ends_with(".json") && is_safe_path(p))
                .map(str::to_string)
                .collect();
        }
        // Parsed fine but no [[mixins]] table → nothing to report.
        if value.is_table() {
            return Vec::new();
        }
    }
    // Fallback: state machine that only honors `config` inside `[[mixins]]`.
    let mut out = Vec::new();
    let mut in_mixins = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_mixins = line == "[[mixins]]";
            continue;
        }
        if !in_mixins {
            continue;
        }
        let Some(rest) = line.strip_prefix("config") else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let path = value.trim().trim_matches('"');
        if path.ends_with(".json") && is_safe_path(path) {
            out.push(path.to_string());
        }
    }
    out
}

/// Fallback: archive entries that look like mixin configs by name (`*.mixins.json`
/// or `mixins.*.json`), at any depth. Used only when no manifest declared them.
fn glob_mixin_configs(archive: &mut zip::ZipArchive<std::fs::File>) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        let name = entry.name();
        let file = name.rsplit('/').next().unwrap_or(name);
        let looks_like_config = file.ends_with(".mixins.json")
            || (file.starts_with("mixins.") && file.ends_with(".json"));
        if looks_like_config && is_safe_path(name) {
            out.push(name.to_string());
        }
    }
    out
}

fn mixin_paths_from_json(text: &str, path: &[&str]) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut cur = &v;
    for key in path {
        let Some(next) = cur.get(*key) else {
            return Vec::new();
        };
        cur = next;
    }
    match cur {
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(mixin_config_entry_path)
            .filter(|p| is_safe_path(p))
            .collect(),
        serde_json::Value::String(s) if is_safe_path(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// A Fabric/Quilt `mixins` array entry is either a bare string config path or an
/// object `{ "config": "foo.mixins.json", "environment": "client" }`. The old
/// code read only strings, silently dropping every object-form config (common in
/// client/server-split mods).
fn mixin_config_entry_path(entry: &serde_json::Value) -> Option<String> {
    match entry {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o
            .get("config")
            .and_then(|c| c.as_str())
            .map(str::to_string),
        _ => None,
    }
}

fn mixin_paths_from_manifest(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in unfold_manifest_lines(text) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("MixinConfigs") {
            for part in value.split(',') {
                let path = part.trim();
                if is_safe_path(path) {
                    out.push(path.to_string());
                }
            }
        }
    }
    out
}

/// Unfold JMF (`META-INF/MANIFEST.MF`) continuation lines.
///
/// A `META-INF/MANIFEST.MF` header value wraps at 72 bytes and continues on the
/// next physical line, which begins with a single leading space. Reading the
/// manifest line-by-line without unfolding truncates a long `MixinConfigs:`
/// value mid-list and silently drops the wrapped configs.
fn unfold_manifest_lines(text: &str) -> Vec<String> {
    let mut logical: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(cont) = line.strip_prefix(' ') {
            if let Some(last) = logical.last_mut() {
                last.push_str(cont);
                continue;
            }
        }
        logical.push(line.to_string());
    }
    logical
}

#[derive(Deserialize)]
struct RawMixinConfig {
    #[serde(default)]
    package: String,
    #[serde(default)]
    priority: Option<i64>,
    #[serde(default)]
    refmap: Option<String>,
    #[serde(default)]
    mixins: Vec<serde_json::Value>,
    #[serde(default)]
    client: Vec<serde_json::Value>,
    #[serde(default)]
    server: Vec<serde_json::Value>,
    #[serde(default)]
    plugin: Option<String>,
}

fn parse_config(
    archive: &str,
    path: &str,
    mod_id: &str,
    text: &str,
) -> Result<MixinConfigRecord, serde_json::Error> {
    let raw: RawMixinConfig = serde_json::from_str(text)?;
    let mut mixins = std::collections::BTreeSet::new();
    for value in raw
        .mixins
        .iter()
        .chain(raw.client.iter())
        .chain(raw.server.iter())
    {
        if let Some(name) = mixin_name(value) {
            mixins.insert(name);
        }
    }

    Ok(MixinConfigRecord {
        archive: archive.to_string(),
        path: path.to_string(),
        mod_id: mod_id.to_string(),
        package: raw.package,
        priority: raw.priority.unwrap_or(1000),
        refmap: raw.refmap,
        mixins: mixins.into_iter().collect(),
        plugin: raw.plugin.filter(|p| !p.trim().is_empty()),
    })
}

fn mixin_name(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o
            .get("class")
            .or_else(|| o.get("name"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
        _ => None,
    }
}

fn mixin_class_path(package: &str, mixin: &str) -> String {
    format!(
        "{}.class",
        join_class_name(package, mixin).replace('.', "/")
    )
}

/// Build named↔intermediary aliases for mixin targets using this jar's Tiny file.
fn resolve_target_namespaces(
    targets: &[String],
    tiny: Option<&TinyMappings>,
) -> std::collections::BTreeMap<String, TargetNamespace> {
    let Some(map) = tiny else {
        return std::collections::BTreeMap::new();
    };
    let mut out = std::collections::BTreeMap::new();
    for target in targets {
        let slash = target.replace('.', "/");
        let mut ns = TargetNamespace::default();
        if let Some(inter) = map.to_intermediary_class(target) {
            ns.intermediary = Some(dotted_name(&inter));
        }
        if let Some(named) = map.to_named_class(&slash) {
            ns.named = Some(named);
        } else if !target.contains("class_") {
            ns.named = Some(target.clone());
        }
        if ns.named.is_some() || ns.intermediary.is_some() {
            out.insert(target.clone(), ns);
        }
    }
    out
}

pub(crate) fn join_class_name(package: &str, mixin: &str) -> String {
    // Mixin entries in `mixins`/`client`/`server` are *always* relative to
    // `package`; dots inside them denote sub-packages (`accessor.FooAccessor`),
    // not a fully-qualified name. The only time an entry is already absolute is
    // when the config declares no package at all.
    if package.is_empty() {
        mixin.to_string()
    } else {
        format!("{package}.{mixin}")
    }
}

pub(crate) fn mods_dir(target: &Target) -> Option<PathBuf> {
    if let Some(dir) = &target.mods_dir {
        return Some(dir.clone());
    }
    if matches!(target.kind, TargetKind::ModsDir) {
        return Some(target.path.clone());
    }
    let direct = target.path.join("mods");
    if direct.is_dir() {
        return Some(direct);
    }
    None
}

fn archive_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| "?".to_string())
}

fn archive_stem(name: &str) -> String {
    name.strip_suffix(".jar").unwrap_or(name).to_string()
}

fn is_safe_path(path: &str) -> bool {
    !path.starts_with('/')
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn detect_mod_id(archive: &mut zip::ZipArchive<std::fs::File>) -> Option<String> {
    read_zip_text(archive, "fabric.mod.json")
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_string))
        })
        .or_else(|| {
            read_zip_text(archive, "quilt.mod.json").and_then(|text| {
                serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| {
                        v.get("quilt_loader")
                            .and_then(|q| q.get("id"))
                            .and_then(|x| x.as_str())
                            .map(str::to_string)
                    })
            })
        })
}

fn read_zip_text(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Option<String> {
    let mut entry = archive.by_name(name).ok()?;
    let mut text = String::new();
    entry.read_to_string(&mut text).ok()?;
    Some(text)
}

fn read_zip_bytes(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Option<Vec<u8>> {
    let mut entry = archive.by_name(name).ok()?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}
#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn forge_mods_toml_mixins_block_is_parsed() {
        let toml = r#"
modLoader="javafml"
[[mods]]
modId="example"
[[mixins]]
config="example.mixins.json"
[[mixins]]
config = "example.client.mixins.json"
"#;
        let paths = mixin_paths_from_mods_toml(toml);
        assert_eq!(
            paths,
            vec!["example.mixins.json", "example.client.mixins.json"]
        );
    }

    #[test]
    fn mods_toml_only_reads_config_inside_mixins_table() {
        // A `config` key in another table (here a [[dependencies]]-style block)
        // must NOT be picked up — only `[[mixins]] config` counts. The old line
        // scan wrongly grabbed any `config = …` line.
        let toml = r#"
[[dependencies.example]]
modId="other"
config="not-a-mixin.json"
[[mixins]]
config="real.mixins.json"
"#;
        assert_eq!(mixin_paths_from_mods_toml(toml), vec!["real.mixins.json"]);
    }

    #[test]
    fn mods_toml_rejects_unsafe_mixin_path() {
        let toml = "[[mixins]]\nconfig=\"../escape.mixins.json\"\n";
        assert!(mixin_paths_from_mods_toml(toml).is_empty());
    }

    #[test]
    fn fabric_object_form_mixin_entries_are_discovered() {
        // Fabric/Quilt `mixins` may be objects `{config, environment}`, not just
        // strings; the old reader dropped these silently.
        let json = r#"{
            "mixins": [
                "plain.mixins.json",
                {"config": "client.mixins.json", "environment": "client"}
            ]
        }"#;
        let paths = mixin_paths_from_json(json, &["mixins"]);
        assert!(paths.contains(&"plain.mixins.json".to_string()));
        assert!(paths.contains(&"client.mixins.json".to_string()));
    }

    #[test]
    fn manifest_continuation_lines_are_unfolded() {
        // A MixinConfigs header wrapped across two physical lines (the second
        // starting with a space) must reassemble into the full list.
        let mf = "Manifest-Version: 1.0\r\nMixinConfigs: a.mixins.json,\r\n b.mixins.json\r\n";
        let paths = mixin_paths_from_manifest(mf);
        assert_eq!(paths, vec!["a.mixins.json", "b.mixins.json"]);
    }

    #[test]
    fn config_plugin_is_parsed() {
        let json = r#"{"package":"x","plugin":"com.example.MyPlugin","mixins":["A"]}"#;
        let rec = parse_config("a.jar", "x.mixins.json", "x", json).unwrap();
        assert_eq!(rec.plugin.as_deref(), Some("com.example.MyPlugin"));
    }
}
