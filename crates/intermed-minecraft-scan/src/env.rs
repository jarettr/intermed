//! Layer A — environment / target enrichment.
//!
//! Emits `environment` and `java_runtime` facts. Detection is heuristic and
//! best-effort: every attribute is optional, and missing data simply produces
//! fewer facts rather than a hard failure.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs::File, io::Read};

use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, CollectorScope, CompletenessModel, InstanceType,
    Layer, LayoutKind, Loader, Side, Target, TargetKind, TargetRegion,
};

pub struct EnvironmentCollector;

impl Collector for EnvironmentCollector {
    fn id(&self) -> &'static str {
        "environment-detector"
    }
    fn layer(&self) -> Layer {
        Layer::TargetDetection
    }
    fn scope(&self) -> CollectorScope {
        CollectorScope::new(CompletenessModel::AllOrNothing)
            .produces([kind::ENVIRONMENT, kind::JAVA_RUNTIME])
            .regions([TargetRegion::Manifest])
    }
    fn applies(&self, target: &Target) -> bool {
        // Logs/crash reports get their environment from the log layer instead.
        !target.kind.is_log()
    }
    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let mut emitted = 0;
        let surface = &ctx.target.path;
        let game_root = ctx.target.game_root.as_deref().unwrap_or(surface.as_path());

        let layout = ctx.target.layout;
        let instance_type = ctx
            .target
            .instance_type
            .or_else(|| Some(detect_instance_type_fallback(ctx.target)));

        let (loader_info, loader_source) = ctx
            .settings
            .pack_manifest
            .as_deref()
            .and_then(loader_from_manifest_locator)
            .map(|info| (info, "explicit-pack-manifest"))
            .unwrap_or_else(|| detect_loader_with_source(game_root, surface, ctx.target));
        let host_launcher = detect_host_launcher(surface, layout);
        let runtime_evidence = detect_runtime_environment(surface, game_root);
        let explicit_mc = ctx
            .settings
            .pack_manifest
            .as_deref()
            .and_then(mc_from_manifest_locator);
        let instance_mc = detect_mc_version(surface, game_root, layout);
        let mc = explicit_mc
            .clone()
            .or_else(|| instance_mc.clone())
            .or_else(|| runtime_evidence.as_ref().and_then(|e| e.minecraft.clone()));

        let mut b = ctx
            .store
            .fact(self.id(), kind::ENVIRONMENT)
            .attr("os", std::env::consts::OS)
            .source(intermed_doctor_core::facts::SourceRef::file(
                surface.display().to_string(),
            ))
            .confidence(0.9);

        if let Some(l) = loader_info.loader {
            b = b.attr("loader", l.as_str());
            b = b.attr("loader_source", loader_source);
        }
        if let Some(component) = &loader_info.component {
            b = b.attr("launcher", component.as_str());
        }
        if let Some(version) = &loader_info.version {
            b = b.attr("loader_version", version.as_str());
        }
        if let Some(it) = instance_type {
            b = b.attr("instance_type", it.as_str());
            b = b.attr("side", it.to_side().as_str());
        }
        if let Some(m) = &mc {
            b = b.attr("mc_version", m.as_str());
            b = b.attr(
                "mc_version_source",
                if explicit_mc.is_some() {
                    "explicit-pack-manifest"
                } else if instance_mc.is_some() {
                    "instance-manifest"
                } else {
                    "runtime-log"
                },
            );
        }
        if let Some(host) = &host_launcher {
            b = b.attr("host_launcher", host.as_str());
        }
        if let Some(layout) = layout {
            b = b.attr("layout", layout.as_str());
        }
        b.emit();
        emitted += 1;

        if let Some(java) = runtime_evidence.as_ref().and_then(|e| e.java.clone()) {
            ctx.store
                .fact(self.id(), kind::JAVA_RUNTIME)
                .attr("version", java.as_str())
                .attr("source", "runtime-log")
                .source(intermed_doctor_core::facts::SourceRef::file(
                    runtime_evidence
                        .as_ref()
                        .map(|e| e.source.clone())
                        .unwrap_or_default(),
                ))
                .confidence(0.98)
                .emit();
            emitted += 1;
        }

        let mut analysis = ctx
            .store
            .fact(self.id(), kind::ANALYSIS_ENVIRONMENT)
            .subject("intermed-process")
            .attr("os", std::env::consts::OS)
            .confidence(1.0);
        if let Some(java) = detect_java_version() {
            analysis = analysis.attr("java", java);
        }
        analysis.emit();
        emitted += 1;

        CollectorOutcome::active(emitted, "environment detected")
    }
}

/// Loader detection output: enum family + optional precise component id + the
/// loader's own version (when extractable from pack metadata or library paths).
struct LoaderInfo {
    loader: Option<Loader>,
    component: Option<String>,
    version: Option<String>,
}

fn detect_instance_type_fallback(target: &Target) -> InstanceType {
    target.instance_type.unwrap_or(match target.kind {
        TargetKind::Server => InstanceType::Server,
        TargetKind::ModsDir => InstanceType::Integrated,
        TargetKind::Instance => InstanceType::Integrated,
        _ => InstanceType::Integrated,
    })
}

fn detect_loader(root: &Path, surface: &Path, target: &Target) -> LoaderInfo {
    detect_loader_with_source(root, surface, target).0
}

fn detect_loader_with_source(
    root: &Path,
    surface: &Path,
    target: &Target,
) -> (LoaderInfo, &'static str) {
    if let Some(from_pack) = loader_from_pack_metadata(surface, root) {
        return from_pack;
    }
    if let Some(runtime) = detect_runtime_environment(surface, root)
        && let Some(loader) = runtime.loader
    {
        return (
            LoaderInfo {
                loader: Some(loader),
                component: runtime.loader_component,
                version: runtime.loader_version,
            },
            "runtime-log",
        );
    }

    let has = |base: &Path, rel: &str| base.join(rel).exists();
    let check_roots = |rel: &str| has(root, rel) || has(surface, rel);

    if check_roots("libraries/net/fabricmc")
        || check_roots("fabric-server-launch.jar")
        || check_roots(".fabric")
    {
        return (
            LoaderInfo {
                loader: Some(Loader::Fabric),
                component: Some("fabric-loader".to_string()),
                version: None,
            },
            "filesystem-heuristic",
        );
    }
    if check_roots("libraries/org/quiltmc") || check_roots("quilt-server-launch.jar") {
        return (
            LoaderInfo {
                loader: Some(Loader::Quilt),
                component: Some("quilt-loader".to_string()),
                version: None,
            },
            "filesystem-heuristic",
        );
    }
    if check_roots("libraries/net/neoforged") {
        return (
            LoaderInfo {
                loader: Some(Loader::NeoForge),
                component: Some("neoforge".to_string()),
                version: None,
            },
            "filesystem-heuristic",
        );
    }
    if check_roots("libraries/net/minecraftforge") || dir_has_prefixed_jar(root, "forge-") {
        return (
            LoaderInfo {
                loader: Some(Loader::Forge),
                component: Some("forge".to_string()),
                version: None,
            },
            "filesystem-heuristic",
        );
    }
    // Most specific fork first: a Paper server ships Spigot/Bukkit compatibility
    // files too, so checking Spigot first would misclassify Paper as Spigot.
    if check_roots("plugins")
        && (check_roots("paper.yml")
            || check_roots("config/paper-global.yml")
            || dir_has_prefixed_jar(root, "paper"))
    {
        return (
            LoaderInfo {
                loader: Some(Loader::Paper),
                component: Some("paper".to_string()),
                version: None,
            },
            "filesystem-heuristic",
        );
    }
    if check_roots("plugins") && (check_roots("spigot.yml") || dir_has_prefixed_jar(root, "spigot"))
    {
        return (
            LoaderInfo {
                loader: Some(Loader::Spigot),
                component: Some("spigot".to_string()),
                version: None,
            },
            "filesystem-heuristic",
        );
    }
    if check_roots("plugins") && check_roots("bukkit.yml") {
        return (
            LoaderInfo {
                loader: Some(Loader::Bukkit),
                component: Some("bukkit".to_string()),
                version: None,
            },
            "filesystem-heuristic",
        );
    }

    let _ = target;
    (
        LoaderInfo {
            loader: None,
            component: None,
            version: None,
        },
        "undecidable",
    )
}

/// Resolve the loader family from instance/pack evidence without running the
/// collector. Metadata scanning uses the same resolver to select the descriptor
/// that is active for this instance; duplicating a different heuristic there
/// would make Layer A and Layer B disagree.
pub(crate) fn loader_for_target(target: &Target) -> Option<Loader> {
    let surface = &target.path;
    let game_root = target.game_root.as_deref().unwrap_or(surface.as_path());
    detect_loader(game_root, surface, target).loader
}

fn loader_from_pack_metadata(
    surface: &Path,
    game_root: &Path,
) -> Option<(LoaderInfo, &'static str)> {
    // Pack declarations are authoritative configuration and outrank launcher
    // components. A cross-loader artifact remains a separate mismatch fact.
    if let Some(info) = loader_from_modrinth_index(&surface.join("modrinth.index.json")) {
        return Some((info, "pack-manifest"));
    }
    if let Some(info) = loader_from_modrinth_index(&game_root.join("modrinth.index.json")) {
        return Some((info, "pack-manifest"));
    }
    if let Some(info) = loader_from_curseforge_manifest(&surface.join("manifest.json")) {
        return Some((info, "pack-manifest"));
    }
    if let Some(info) = loader_from_curseforge_manifest(&game_root.join("manifest.json")) {
        return Some((info, "pack-manifest"));
    }
    if let Some(info) = loader_from_mmc_pack(&surface.join("mmc-pack.json")) {
        return Some((info, "launcher-manifest"));
    }
    if let Some(info) = loader_from_mmc_pack(&game_root.join("mmc-pack.json")) {
        return Some((info, "launcher-manifest"));
    }
    None
}

fn loader_from_mmc_pack(path: &Path) -> Option<LoaderInfo> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let components = v.get("components")?.as_array()?;
    for component in components {
        let uid = component.get("uid")?.as_str()?;
        let version = component
            .get("version")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if let Some(info) = loader_from_component_uid(uid, version) {
            return Some(info);
        }
    }
    None
}

fn loader_from_modrinth_index(path: &Path) -> Option<LoaderInfo> {
    let text = std::fs::read_to_string(path).ok()?;
    loader_from_modrinth_text(&text)
}

fn loader_from_modrinth_text(text: &str) -> Option<LoaderInfo> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let deps = v.get("dependencies")?.as_object()?;
    for (key, value) in deps {
        let version = value.as_str().unwrap_or("");
        if let Some(info) = loader_from_modrinth_dep_key(key, version) {
            return Some(info);
        }
    }
    None
}

fn loader_from_curseforge_manifest(path: &Path) -> Option<LoaderInfo> {
    let text = std::fs::read_to_string(path).ok()?;
    loader_from_curseforge_text(&text)
}

fn loader_from_curseforge_text(text: &str) -> Option<LoaderInfo> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let loaders = v
        .pointer("/minecraft/modLoaders")
        .and_then(|x| x.as_array())?;
    for entry in loaders {
        let id = entry.get("id").and_then(|x| x.as_str())?;
        if let Some(info) = loader_from_curseforge_loader_id(id) {
            return Some(info);
        }
    }
    None
}

/// Read an explicitly supplied manifest either directly or from its original
/// pack archive. This preserves authoritative loader provenance even when an
/// external materializer retained only `overrides/` and downloaded jars.
fn loader_from_manifest_locator(path: &Path) -> Option<LoaderInfo> {
    if path.file_name().and_then(|name| name.to_str()) == Some("modrinth.index.json") {
        return loader_from_modrinth_index(path);
    }
    if path.file_name().and_then(|name| name.to_str()) == Some("manifest.json") {
        return loader_from_curseforge_manifest(path);
    }

    let file = std::fs::File::open(path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    if let Some(text) = intermed_doctor_core::bounded_zip::read_zip_text_opt(
        &mut archive,
        "modrinth.index.json",
        intermed_doctor_core::bounded_zip::MAX_MANIFEST_BYTES,
    ) && let Some(info) = loader_from_modrinth_text(&text)
    {
        return Some(info);
    }
    let text = intermed_doctor_core::bounded_zip::read_zip_text_opt(
        &mut archive,
        "manifest.json",
        intermed_doctor_core::bounded_zip::MAX_MANIFEST_BYTES,
    )?;
    loader_from_curseforge_text(&text)
}

fn mc_from_manifest_locator(path: &Path) -> Option<String> {
    let file_name = path.file_name().and_then(|name| name.to_str());
    if matches!(file_name, Some("modrinth.index.json" | "manifest.json")) {
        let text = std::fs::read_to_string(path).ok()?;
        return mc_from_manifest_text(&text);
    }

    let file = std::fs::File::open(path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    for entry in ["modrinth.index.json", "manifest.json"] {
        if let Some(text) = intermed_doctor_core::bounded_zip::read_zip_text_opt(
            &mut archive,
            entry,
            intermed_doctor_core::bounded_zip::MAX_MANIFEST_BYTES,
        ) && let Some(version) = mc_from_manifest_text(&text)
        {
            return Some(version);
        }
    }
    None
}

fn mc_from_manifest_text(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value
        .pointer("/dependencies/minecraft")
        .or_else(|| value.pointer("/minecraft/version"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn loader_from_component_uid(uid: &str, version: &str) -> Option<LoaderInfo> {
    match uid {
        "net.fabricmc.fabric-loader" => Some(LoaderInfo {
            loader: Some(Loader::Fabric),
            component: Some(format_component("fabric-loader", version)),
            version: opt_ver(version),
        }),
        "org.quiltmc.quilt-loader" => Some(LoaderInfo {
            loader: Some(Loader::Quilt),
            component: Some(format_component("quilt-loader", version)),
            version: opt_ver(version),
        }),
        "net.minecraftforge" | "net.minecraftforge.forge" => Some(LoaderInfo {
            loader: Some(Loader::Forge),
            component: Some(format_component("forge", version)),
            version: opt_ver(version),
        }),
        "net.neoforged" | "net.neoforged.neoforge" => Some(LoaderInfo {
            loader: Some(Loader::NeoForge),
            component: Some(format_component("neoforge", version)),
            version: opt_ver(version),
        }),
        _ => None,
    }
}

fn loader_from_modrinth_dep_key(key: &str, version: &str) -> Option<LoaderInfo> {
    match key {
        "fabric-loader" => Some(LoaderInfo {
            loader: Some(Loader::Fabric),
            component: Some(format_component("fabric-loader", version)),
            version: opt_ver(version),
        }),
        "quilt-loader" => Some(LoaderInfo {
            loader: Some(Loader::Quilt),
            component: Some(format_component("quilt-loader", version)),
            version: opt_ver(version),
        }),
        "forge" => Some(LoaderInfo {
            loader: Some(Loader::Forge),
            component: Some(format_component("forge", version)),
            version: opt_ver(version),
        }),
        "neoforge" => Some(LoaderInfo {
            loader: Some(Loader::NeoForge),
            component: Some(format_component("neoforge", version)),
            version: opt_ver(version),
        }),
        _ => None,
    }
}

fn loader_from_curseforge_loader_id(id: &str) -> Option<LoaderInfo> {
    let lower = id.to_ascii_lowercase();
    if lower.starts_with("fabric-") || lower == "fabric" {
        return Some(LoaderInfo {
            loader: Some(Loader::Fabric),
            component: Some(id.to_string()),
            version: version_from_loader_id(id),
        });
    }
    if lower.starts_with("quilt-") || lower == "quilt" {
        return Some(LoaderInfo {
            loader: Some(Loader::Quilt),
            component: Some(id.to_string()),
            version: version_from_loader_id(id),
        });
    }
    if lower.starts_with("neoforge-") || lower.starts_with("neoforged-") {
        return Some(LoaderInfo {
            loader: Some(Loader::NeoForge),
            component: Some(id.to_string()),
            version: version_from_loader_id(id),
        });
    }
    if lower.starts_with("forge-") || lower == "forge" {
        return Some(LoaderInfo {
            loader: Some(Loader::Forge),
            component: Some(id.to_string()),
            version: version_from_loader_id(id),
        });
    }
    None
}

fn format_component(name: &str, version: &str) -> String {
    if version.is_empty() {
        name.to_string()
    } else {
        format!("{name}-{version}")
    }
}

/// A non-empty version string, or `None` (so the environment fact only carries a
/// `loader_version` we actually know).
fn opt_ver(version: &str) -> Option<String> {
    let v = version.trim();
    (!v.is_empty()).then(|| v.to_string())
}

/// Extract the version suffix from a CurseForge modloader id like
/// `neoforge-21.1.79` or `forge-47.3.0`.
fn version_from_loader_id(id: &str) -> Option<String> {
    id.split_once('-').and_then(|(_, v)| opt_ver(v))
}

fn detect_host_launcher(surface: &Path, layout: Option<LayoutKind>) -> Option<String> {
    let has = |rel: &str| surface.join(rel).exists();
    if let Some(kind) = layout {
        return Some(
            match kind {
                LayoutKind::PrismInstance => "prism",
                LayoutKind::MultiMcInstance => "multimc",
                LayoutKind::CurseForgePack => "curseforge",
                LayoutKind::ModrinthPack => "modrinth",
                LayoutKind::DotMinecraft => "vanilla",
                LayoutKind::DedicatedServer => "dedicated",
                LayoutKind::BareModsDir | LayoutKind::Unknown => return None,
            }
            .to_string(),
        );
    }
    if has("instance.cfg") && has("mmc-pack.json") {
        return Some("prism".to_string());
    }
    if has("mmc-pack.json") {
        return Some("multimc".to_string());
    }
    if has("manifest.json") && has("modlist.html") {
        return Some("curseforge".to_string());
    }
    if has("modrinth.index.json") {
        return Some("modrinth".to_string());
    }
    if has("launcher_profiles.json") || has("launcher_accounts.json") {
        return Some("vanilla".to_string());
    }
    None
}

/// Try to read a Minecraft version from common locations. Best-effort.
fn detect_mc_version(
    surface: &Path,
    game_root: &Path,
    layout: Option<LayoutKind>,
) -> Option<String> {
    for path in mc_version_paths(surface, game_root, layout) {
        if let Some(ver) = read_mc_version_file(&path) {
            return Some(ver);
        }
    }
    None
}

fn mc_version_paths(surface: &Path, game_root: &Path, layout: Option<LayoutKind>) -> Vec<PathBuf> {
    let mut paths = vec![
        surface.join("mmc-pack.json"),
        game_root.join("mmc-pack.json"),
        surface.join("modrinth.index.json"),
        surface.join("manifest.json"),
    ];
    if matches!(
        layout,
        Some(LayoutKind::CurseForgePack | LayoutKind::ModrinthPack)
    ) {
        paths.push(surface.join("overrides/mmc-pack.json"));
    }
    paths
}

fn read_mc_version_file(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    if path.file_name().and_then(|n| n.to_str()) == Some("mmc-pack.json") {
        let components = v.get("components")?.as_array()?;
        for c in components {
            if c.get("uid").and_then(|u| u.as_str()) == Some("net.minecraft") {
                return c
                    .get("version")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
            }
        }
    }
    if path.file_name().and_then(|n| n.to_str()) == Some("modrinth.index.json") {
        return v
            .pointer("/dependencies/minecraft")
            .and_then(|x| x.as_str())
            .map(str::to_string);
    }
    if path.file_name().and_then(|n| n.to_str()) == Some("manifest.json") {
        return v
            .pointer("/minecraft/version")
            .and_then(|x| x.as_str())
            .map(str::to_string);
    }
    None
}

/// Probe the `java` on PATH. Optional — absence is not an error.
fn detect_java_version() -> Option<String> {
    let output = Command::new("java").arg("-version").output().ok()?;
    // `java -version` writes to stderr.
    let text = String::from_utf8_lossy(&output.stderr);
    let line = text.lines().next()?;
    // e.g. openjdk version "21.0.1" 2023-10-17
    let start = line.find('"')?;
    let rest = &line[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[derive(Debug, Clone)]
struct RuntimeEnvironmentEvidence {
    source: String,
    java: Option<String>,
    minecraft: Option<String>,
    loader: Option<Loader>,
    loader_component: Option<String>,
    loader_version: Option<String>,
}

/// Read a bounded set of target-owned runtime logs. Host process state is never
/// consulted here: every returned value is forensic evidence from the target.
fn detect_runtime_environment(
    surface: &Path,
    game_root: &Path,
) -> Option<RuntimeEnvironmentEvidence> {
    for path in runtime_log_candidates(surface, game_root) {
        let Ok(file) = File::open(&path) else {
            continue;
        };
        let mut text = String::new();
        if file
            .take(16 * 1024 * 1024)
            .read_to_string(&mut text)
            .is_err()
        {
            continue;
        }
        let mut evidence = RuntimeEnvironmentEvidence {
            source: path.display().to_string(),
            java: None,
            minecraft: None,
            loader: None,
            loader_component: None,
            loader_version: None,
        };
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            if evidence.java.is_none() {
                evidence.java = value_after_marker(line, &lower, "java version:")
                    .or_else(|| value_after_quoted_marker(line, &lower, "java version"));
            }
            if evidence.minecraft.is_none() {
                evidence.minecraft = value_after_marker(line, &lower, "minecraft version:")
                    .or_else(|| {
                        value_between_markers(line, &lower, "loading minecraft ", " with ")
                    });
            }
            if evidence.loader.is_none() {
                for (needle, loader, component) in [
                    ("neoforge", Loader::NeoForge, "neoforge"),
                    ("fabric loader", Loader::Fabric, "fabric-loader"),
                    ("quilt loader", Loader::Quilt, "quilt-loader"),
                    ("minecraft forge", Loader::Forge, "forge"),
                ] {
                    if let Some(at) = lower.find(needle) {
                        evidence.loader = Some(loader);
                        evidence.loader_component = Some(component.to_string());
                        evidence.loader_version = first_version_token(&line[at + needle.len()..]);
                        break;
                    }
                }
            }
        }
        if evidence.java.is_some() || evidence.minecraft.is_some() || evidence.loader.is_some() {
            return Some(evidence);
        }
    }
    None
}

fn runtime_log_candidates(surface: &Path, game_root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for root in [surface, game_root] {
        for relative in [
            "logs/latest.log",
            "logs/debug.log",
            "latest.log",
            "debug.log",
        ] {
            let path = root.join(relative);
            if path.is_file() && !paths.contains(&path) {
                paths.push(path);
            }
        }
        let crash_dir = root.join("crash-reports");
        if let Ok(entries) = std::fs::read_dir(crash_dir) {
            let mut crashes: Vec<_> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
                .collect();
            crashes.sort_by_key(|path| {
                std::cmp::Reverse(path.metadata().and_then(|m| m.modified()).ok())
            });
            for path in crashes.into_iter().take(4) {
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
    }
    paths
}

fn value_after_marker(original: &str, lower: &str, marker: &str) -> Option<String> {
    let at = lower.find(marker)? + marker.len();
    first_version_token(&original[at..])
}

fn value_after_quoted_marker(original: &str, lower: &str, marker: &str) -> Option<String> {
    let at = lower.find(marker)? + marker.len();
    let tail = &original[at..];
    let start = tail.find('"')? + 1;
    let end = tail[start..].find('"')?;
    Some(tail[start..start + end].to_string())
}

fn value_between_markers(original: &str, lower: &str, start: &str, end: &str) -> Option<String> {
    let from = lower.find(start)? + start.len();
    let to = lower[from..].find(end)? + from;
    Some(original[from..to].trim().to_string())
}

fn first_version_token(text: &str) -> Option<String> {
    text.split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';' | '(' | ')' | '[' | ']'))
        .map(|token| token.trim_matches(|ch: char| matches!(ch, ':' | '=' | '"' | '\'')))
        .find(|token| !token.is_empty() && token.chars().any(|ch| ch.is_ascii_digit()))
        .map(str::to_string)
}

fn dir_has_prefixed_jar(root: &Path, prefix: &str) -> bool {
    std::fs::read_dir(root)
        .map(|rd| {
            rd.flatten().any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(prefix) && n.ends_with(".jar"))
            })
        })
        .unwrap_or(false)
}

trait SideExt {
    fn as_str(&self) -> &'static str;
}

impl SideExt for Side {
    fn as_str(&self) -> &'static str {
        match self {
            Side::Client => "client",
            Side::Server => "server",
            Side::Both => "both",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, bytes).expect("write");
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "intermed-env-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn paper_with_spigot_compat_files_detects_as_paper() {
        // A Paper server ships spigot.yml/bukkit.yml too; the more specific fork
        // must win over the base platform.
        let root = temp("paper-fork");
        touch(&root.join("plugins").join(".keep"), b"");
        touch(&root.join("spigot.yml"), b"settings: {}");
        touch(&root.join("bukkit.yml"), b"settings: {}");
        touch(
            &root.join("config").join("paper-global.yml"),
            b"_version: 1",
        );
        let target = Target {
            path: root.clone(),
            kind: TargetKind::Server,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let info = detect_loader(&root, &root, &target);
        assert_eq!(info.loader, Some(Loader::Paper));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn mmc_pack_loader_detection() {
        let root = temp("mmc-loader");
        touch(
            &root.join("mmc-pack.json"),
            br#"{"components":[{"uid":"net.fabricmc.fabric-loader","version":"0.15.0"}]}"#,
        );
        let info = loader_from_mmc_pack(&root.join("mmc-pack.json")).expect("loader");
        assert_eq!(info.loader, Some(Loader::Fabric));
        assert_eq!(info.component.as_deref(), Some("fabric-loader-0.15.0"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn modrinth_index_loader_detection() {
        let root = temp("mr-loader");
        touch(
            &root.join("modrinth.index.json"),
            br#"{"dependencies":{"minecraft":"1.20.1","neoforge":"20.4.0"}}"#,
        );
        let info = loader_from_modrinth_index(&root.join("modrinth.index.json")).expect("loader");
        assert_eq!(info.loader, Some(Loader::NeoForge));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn explicit_pack_manifest_supplies_exact_minecraft_version() {
        let root = temp("mr-explicit-minecraft");
        let manifest = root.join("modrinth.index.json");
        touch(
            &manifest,
            br#"{"dependencies":{"minecraft":"1.21.1","neoforge":"21.1.248"}}"#,
        );
        assert_eq!(
            mc_from_manifest_locator(&manifest).as_deref(),
            Some("1.21.1")
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pack_manifest_outranks_launcher_manifest() {
        let root = temp("pack-priority");
        touch(
            &root.join("modrinth.index.json"),
            br#"{"dependencies":{"minecraft":"1.20.1","fabric-loader":"0.15.0"}}"#,
        );
        touch(
            &root.join("mmc-pack.json"),
            br#"{"components":[{"uid":"net.neoforged.neoforge","version":"20.4.0"}]}"#,
        );
        let (info, source) = loader_from_pack_metadata(&root, &root).expect("loader");
        assert_eq!(info.loader, Some(Loader::Fabric));
        assert_eq!(source, "pack-manifest");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn runtime_log_supplies_target_java_loader_and_minecraft() {
        let root = temp("runtime-environment");
        touch(
            &root.join("logs/latest.log"),
            b"Java Version: 21.0.7\nLoading Minecraft 1.21.1 with NeoForge 21.1.248\n",
        );

        let evidence = detect_runtime_environment(&root, &root).expect("runtime evidence");
        assert_eq!(evidence.java.as_deref(), Some("21.0.7"));
        assert_eq!(evidence.minecraft.as_deref(), Some("1.21.1"));
        assert_eq!(evidence.loader, Some(Loader::NeoForge));
        assert_eq!(evidence.loader_version.as_deref(), Some("21.1.248"));

        let target = Target {
            path: root.clone(),
            kind: TargetKind::Instance,
            mods_dir: None,
            game_root: Some(root.clone()),
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let (loader, source) = detect_loader_with_source(&root, &root, &target);
        assert_eq!(loader.loader, Some(Loader::NeoForge));
        assert_eq!(source, "runtime-log");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn analyzer_java_is_never_emitted_as_target_java() {
        let root = temp("host-java-separation");
        let target = Target {
            path: root.clone(),
            kind: TargetKind::Instance,
            mods_dir: None,
            game_root: Some(root.clone()),
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let mut store = intermed_doctor_core::facts::FactStore::new();
        let settings = intermed_doctor_core::DiagnosisSettings::default();
        let mut ctx = intermed_doctor_core::CollectCtx {
            target: &target,
            store: &mut store,
            jar_cache: None,
            settings: &settings,
        };
        EnvironmentCollector.collect(&mut ctx);

        assert_eq!(store.by_kind(kind::JAVA_RUNTIME).count(), 0);
        assert_eq!(store.by_kind(kind::ANALYSIS_ENVIRONMENT).count(), 1);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn explicit_mrpack_archive_retains_loader_provenance() {
        use std::io::Write as _;

        let root = temp("explicit-mrpack");
        let archive_path = root.join("pack.mrpack");
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file(
                "modrinth.index.json",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive
            .write_all(
                br#"{"formatVersion":1,"dependencies":{"minecraft":"1.21.1","neoforge":"21.1.0"}}"#,
            )
            .unwrap();
        archive.finish().unwrap();

        let info = loader_from_manifest_locator(&archive_path).expect("loader");
        assert_eq!(info.loader, Some(Loader::NeoForge));
        assert_eq!(info.version.as_deref(), Some("21.1.0"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn host_launcher_prism() {
        let root = temp("host");
        touch(&root.join("instance.cfg"), b"");
        touch(&root.join("mmc-pack.json"), b"{}");
        assert_eq!(
            detect_host_launcher(&root, Some(LayoutKind::PrismInstance)).as_deref(),
            Some("prism")
        );
        fs::remove_dir_all(root).ok();
    }
}
