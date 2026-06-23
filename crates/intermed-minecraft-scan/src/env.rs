//! Layer A — environment / target enrichment.
//!
//! Emits `environment` and `java_runtime` facts. Detection is heuristic and
//! best-effort: every attribute is optional, and missing data simply produces
//! fewer facts rather than a hard failure.

use std::path::{Path, PathBuf};
use std::process::Command;

use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, InstanceType, Layer, LayoutKind, Loader, Side, Target,
    TargetKind,
};

pub struct EnvironmentCollector;

impl Collector for EnvironmentCollector {
    fn id(&self) -> &'static str {
        "environment-detector"
    }
    fn layer(&self) -> Layer {
        Layer::TargetDetection
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

        let loader_info = detect_loader(game_root, surface, ctx.target);
        let host_launcher = detect_host_launcher(surface, layout);
        let mc = detect_mc_version(surface, game_root, layout);

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
        }
        if let Some(host) = &host_launcher {
            b = b.attr("host_launcher", host.as_str());
        }
        if let Some(layout) = layout {
            b = b.attr("layout", layout.as_str());
        }
        b.emit();
        emitted += 1;

        if let Some(java) = detect_java_version() {
            ctx.store
                .fact(self.id(), kind::JAVA_RUNTIME)
                .attr("version", java.as_str())
                .confidence(0.8)
                .emit();
            emitted += 1;
        }

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
    if let Some(from_pack) = loader_from_pack_metadata(surface, root) {
        return from_pack;
    }

    let has = |base: &Path, rel: &str| base.join(rel).exists();
    let check_roots = |rel: &str| has(root, rel) || has(surface, rel);

    if check_roots("libraries/net/fabricmc")
        || check_roots("fabric-server-launch.jar")
        || check_roots(".fabric")
    {
        return LoaderInfo {
            loader: Some(Loader::Fabric),
            component: Some("fabric-loader".to_string()),
            version: None,
        };
    }
    if check_roots("libraries/org/quiltmc") || check_roots("quilt-server-launch.jar") {
        return LoaderInfo {
            loader: Some(Loader::Quilt),
            component: Some("quilt-loader".to_string()),
            version: None,
        };
    }
    if check_roots("libraries/net/neoforged") {
        return LoaderInfo {
            loader: Some(Loader::NeoForge),
            component: Some("neoforge".to_string()),
            version: None,
        };
    }
    if check_roots("libraries/net/minecraftforge") || dir_has_prefixed_jar(root, "forge-") {
        return LoaderInfo {
            loader: Some(Loader::Forge),
            component: Some("forge".to_string()),
            version: None,
        };
    }
    // Most specific fork first: a Paper server ships Spigot/Bukkit compatibility
    // files too, so checking Spigot first would misclassify Paper as Spigot.
    if check_roots("plugins")
        && (check_roots("paper.yml")
            || check_roots("config/paper-global.yml")
            || dir_has_prefixed_jar(root, "paper"))
    {
        return LoaderInfo {
            loader: Some(Loader::Paper),
            component: Some("paper".to_string()),
            version: None,
        };
    }
    if check_roots("plugins") && (check_roots("spigot.yml") || dir_has_prefixed_jar(root, "spigot"))
    {
        return LoaderInfo {
            loader: Some(Loader::Spigot),
            component: Some("spigot".to_string()),
            version: None,
        };
    }
    if check_roots("plugins") && check_roots("bukkit.yml") {
        return LoaderInfo {
            loader: Some(Loader::Bukkit),
            component: Some("bukkit".to_string()),
            version: None,
        };
    }

    let _ = target;
    LoaderInfo {
        loader: None,
        component: None,
        version: None,
    }
}

fn loader_from_pack_metadata(surface: &Path, game_root: &Path) -> Option<LoaderInfo> {
    if let Some(info) = loader_from_mmc_pack(&surface.join("mmc-pack.json")) {
        return Some(info);
    }
    if let Some(info) = loader_from_mmc_pack(&game_root.join("mmc-pack.json")) {
        return Some(info);
    }
    if let Some(info) = loader_from_modrinth_index(&surface.join("modrinth.index.json")) {
        return Some(info);
    }
    if let Some(info) = loader_from_curseforge_manifest(&surface.join("manifest.json")) {
        return Some(info);
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
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
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
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
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
