//! Instance layout resolution — where the game root and `mods/` live on disk.
//!
//! Launcher exports (Prism / MultiMC / CurseForge / Modrinth) nest content under
//! several conventional paths. [`resolve_layout`] normalizes that into a single
//! [`ResolvedLayout`] so collectors and the CLI share one source of truth.

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::target::{InstanceType, TargetKind};

/// Recognized on-disk layouts for Minecraft instances and modpack exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayoutKind {
    /// Prism Launcher instance (`instance.cfg` + `mmc-pack.json`).
    PrismInstance,
    /// MultiMC instance (`mmc-pack.json` without Prism `instance.cfg`).
    MultiMcInstance,
    /// Vanilla or launcher-managed `.minecraft` directory.
    DotMinecraft,
    /// CurseForge pack export (`manifest.json` + `modlist.html`).
    CurseForgePack,
    /// Modrinth `.mrpack` export (`modrinth.index.json`).
    ModrinthPack,
    /// Dedicated modded server tree (`server.properties` / `eula.txt`).
    DedicatedServer,
    /// Bare `mods/` directory (or a folder of jars).
    BareModsDir,
    /// Could not classify beyond generic directory heuristics.
    Unknown,
}

impl LayoutKind {
    /// Stable snake-free label for facts and reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LayoutKind::PrismInstance => "prism-instance",
            LayoutKind::MultiMcInstance => "multimc-instance",
            LayoutKind::DotMinecraft => "dot-minecraft",
            LayoutKind::CurseForgePack => "curseforge-pack",
            LayoutKind::ModrinthPack => "modrinth-pack",
            LayoutKind::DedicatedServer => "dedicated-server",
            LayoutKind::BareModsDir => "bare-mods-dir",
            LayoutKind::Unknown => "unknown",
        }
    }
}

/// Normalized view of an instance after layout heuristics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLayout {
    /// Surface path the user passed to the CLI (instance root or archive extract root).
    pub surface_root: PathBuf,
    /// Directory where Minecraft expects `mods/`, `config/`, `options.txt`, etc.
    pub game_root: PathBuf,
    pub layout: LayoutKind,
    pub instance_type: InstanceType,
    /// Resolved mod jar directory, if any.
    pub mods_dir: Option<PathBuf>,
    /// Bukkit-family plugin directory, when present.
    pub plugins_dir: Option<PathBuf>,
}

/// Maximum directory depth when searching for a nested `mods/` folder.
const MODS_SEARCH_MAX_DEPTH: usize = 5;

/// Relative paths checked before a breadth-first `mods/` search.
const MODS_CANDIDATE_RELS: &[&str] = &[
    "mods",
    ".minecraft/mods",
    "minecraft/mods",
    "overrides/mods",
    "client/mods",
    "client-overrides/mods",
];

/// Resolve layout, game root, and `mods/` for a directory target.
#[must_use]
pub fn resolve_layout(surface_root: &Path) -> ResolvedLayout {
    let layout = detect_layout_kind(surface_root);
    let game_root = resolve_game_root(surface_root, layout);
    let mods_dir = find_mods_directory(surface_root).or_else(|| find_mods_directory(&game_root));
    let plugins_dir = find_plugins_directory(surface_root, &game_root);
    let instance_type = detect_instance_type(
        &game_root,
        layout,
        mods_dir.as_deref(),
        plugins_dir.as_deref(),
    );

    ResolvedLayout {
        surface_root: surface_root.to_path_buf(),
        game_root,
        layout,
        instance_type,
        mods_dir,
        plugins_dir,
    }
}

/// Find a `mods/` directory under `root`, checking known layouts then subdirectories.
#[must_use]
pub fn find_mods_directory(root: &Path) -> Option<PathBuf> {
    for rel in MODS_CANDIDATE_RELS {
        let candidate = root.join(rel);
        if is_mods_directory(&candidate) {
            return Some(candidate);
        }
    }
    search_mods_bfs(root, MODS_SEARCH_MAX_DEPTH)
}

/// Resolve the Minecraft game root inside a launcher instance or export tree.
#[must_use]
pub fn resolve_game_root(surface_root: &Path, layout: LayoutKind) -> PathBuf {
    match layout {
        LayoutKind::PrismInstance | LayoutKind::MultiMcInstance => {
            let dot_mc = surface_root.join(".minecraft");
            if dot_mc.is_dir() {
                return dot_mc;
            }
        }
        LayoutKind::CurseForgePack | LayoutKind::ModrinthPack => {
            let overrides = surface_root.join("overrides");
            if overrides.is_dir() {
                return overrides;
            }
        }
        _ => {}
    }

    if surface_root
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == ".minecraft")
    {
        return surface_root.to_path_buf();
    }

    surface_root.to_path_buf()
}

fn detect_layout_kind(root: &Path) -> LayoutKind {
    let has = |rel: &str| root.join(rel).exists();

    if has("modrinth.index.json") {
        return LayoutKind::ModrinthPack;
    }
    if has("manifest.json") && (has("modlist.html") || has("overrides")) {
        return LayoutKind::CurseForgePack;
    }
    if has("instance.cfg") && has("mmc-pack.json") {
        return LayoutKind::PrismInstance;
    }
    if has("mmc-pack.json") {
        return LayoutKind::MultiMcInstance;
    }
    if has("server.properties") || has("eula.txt") {
        return LayoutKind::DedicatedServer;
    }
    if root
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "mods")
        || (!has("mods") && dir_has_jars(root))
    {
        return LayoutKind::BareModsDir;
    }
    if has("options.txt")
        || has("launcher_profiles.json")
        || has("launcher_accounts.json")
        || root
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == ".minecraft")
    {
        return LayoutKind::DotMinecraft;
    }
    if has(".minecraft") {
        return LayoutKind::PrismInstance;
    }
    LayoutKind::Unknown
}

/// Classify how the instance is meant to run (dedicated server vs client vs integrated).
#[must_use]
pub fn detect_instance_type(
    game_root: &Path,
    layout: LayoutKind,
    mods_dir: Option<&Path>,
    plugins_dir: Option<&Path>,
) -> InstanceType {
    let server = has_dedicated_server_markers(game_root, plugins_dir);
    let client = has_client_markers(game_root, layout);

    match (server, client) {
        (true, true) => InstanceType::Integrated,
        (true, false) => InstanceType::Server,
        (false, true) if is_launcher_integrated_layout(layout) => InstanceType::Integrated,
        (false, true) if is_client_only_mods_path(mods_dir) => InstanceType::Client,
        (false, true) => InstanceType::Integrated,
        (false, false) if is_client_only_mods_path(mods_dir) => InstanceType::Client,
        (false, false) => infer_instance_type_from_layout(layout, mods_dir),
    }
}

fn is_launcher_integrated_layout(layout: LayoutKind) -> bool {
    matches!(
        layout,
        LayoutKind::PrismInstance
            | LayoutKind::MultiMcInstance
            | LayoutKind::DotMinecraft
            | LayoutKind::CurseForgePack
            | LayoutKind::ModrinthPack
    )
}

fn is_client_only_mods_path(mods_dir: Option<&Path>) -> bool {
    mods_dir
        .and_then(|p| p.parent().and_then(|parent| parent.file_name()))
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "client")
}

fn infer_instance_type_from_layout(layout: LayoutKind, mods_dir: Option<&Path>) -> InstanceType {
    match layout {
        LayoutKind::DedicatedServer => InstanceType::Server,
        LayoutKind::BareModsDir => {
            if is_client_only_mods_path(mods_dir) {
                InstanceType::Client
            } else {
                InstanceType::Integrated
            }
        }
        LayoutKind::PrismInstance
        | LayoutKind::MultiMcInstance
        | LayoutKind::DotMinecraft
        | LayoutKind::CurseForgePack
        | LayoutKind::ModrinthPack => InstanceType::Integrated,
        LayoutKind::Unknown => InstanceType::Integrated,
    }
}

fn has_dedicated_server_markers(game_root: &Path, plugins_dir: Option<&Path>) -> bool {
    let has = |rel: &str| game_root.join(rel).exists();
    if has("server.properties") {
        return true;
    }
    if has("eula.txt") && !has("options.txt") {
        return true;
    }
    if has("fabric-server-launch.jar") || has("quilt-server-launch.jar") {
        return true;
    }
    if plugins_dir.is_some() {
        return true;
    }
    false
}

fn has_client_markers(game_root: &Path, _layout: LayoutKind) -> bool {
    let has = |rel: &str| game_root.join(rel).exists();
    has("options.txt")
        || has("optionsof.txt")
        || has("launcher_profiles.json")
        || has("launcher_accounts.json")
}

fn find_plugins_directory(surface_root: &Path, game_root: &Path) -> Option<PathBuf> {
    for base in [game_root, surface_root] {
        let plugins = base.join("plugins");
        if plugins.is_dir() {
            return Some(plugins);
        }
    }
    None
}

fn is_mods_directory(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    if dir_has_jars(path) {
        return true;
    }
    // Empty `mods/` is still a valid server/instance layout marker.
    fs::read_dir(path)
        .map(|mut rd| rd.next().is_none())
        .unwrap_or(false)
}

fn search_mods_bfs(root: &Path, max_depth: usize) -> Option<PathBuf> {
    if max_depth == 0 {
        return None;
    }
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut best: Option<PathBuf> = None;

    while let Some((dir, depth)) = queue.pop_front() {
        if depth > max_depth {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let is_mods = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "mods")
                && is_mods_directory(&path);
            if is_mods {
                let replace = match &best {
                    None => true,
                    Some(current) => path.components().count() < current.components().count(),
                };
                if replace {
                    best = Some(path.clone());
                }
            }
            if depth < max_depth {
                queue.push_back((path, depth + 1));
            }
        }
    }
    best
}

fn dir_has_jars(path: &Path) -> bool {
    fs::read_dir(path)
        .map(|rd| {
            rd.flatten().any(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x.eq_ignore_ascii_case("jar"))
            })
        })
        .unwrap_or(false)
}

/// Map a resolved layout to the coarse [`TargetKind`] used by the engine.
#[must_use]
pub fn target_kind_from_layout(layout: &ResolvedLayout) -> TargetKind {
    match layout.layout {
        LayoutKind::DedicatedServer => TargetKind::Server,
        LayoutKind::BareModsDir => TargetKind::ModsDir,
        LayoutKind::Unknown if layout.mods_dir.is_none() => TargetKind::Unknown,
        _ => TargetKind::Instance,
    }
}

/// Preferred mods directory for a classified target.
#[must_use]
pub fn mods_dir_for_target(
    kind: TargetKind,
    path: &Path,
    resolved_mods_dir: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(dir) = resolved_mods_dir {
        return Some(dir.to_path_buf());
    }
    if kind == TargetKind::ModsDir {
        return Some(path.to_path_buf());
    }
    find_mods_directory(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn touch(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, contents).expect("write");
    }

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "intermed-layout-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn prism_instance_uses_dot_minecraft_game_root() {
        let root = temp_root("prism");
        touch(&root.join("instance.cfg"), b"[General]\n");
        touch(&root.join("mmc-pack.json"), br#"{"components":[]}"#);
        touch(&root.join(".minecraft/mods/sodium.jar"), b"jar");
        touch(&root.join(".minecraft/options.txt"), b"fov:70");

        let layout = resolve_layout(&root);
        assert_eq!(layout.layout, LayoutKind::PrismInstance);
        assert_eq!(layout.game_root, root.join(".minecraft"));
        assert!(
            layout
                .mods_dir
                .as_ref()
                .is_some_and(|p| p.ends_with("mods"))
        );
        assert_eq!(layout.instance_type, InstanceType::Integrated);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn multimc_without_instance_cfg() {
        let root = temp_root("multimc");
        touch(&root.join("mmc-pack.json"), br#"{"components":[]}"#);
        touch(&root.join(".minecraft/mods/a.jar"), b"j");

        let layout = resolve_layout(&root);
        assert_eq!(layout.layout, LayoutKind::MultiMcInstance);
        assert_eq!(layout.game_root, root.join(".minecraft"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn curseforge_pack_overrides_mods() {
        let root = temp_root("cf");
        touch(
            &root.join("manifest.json"),
            br#"{"minecraft":{"version":"1.20.1"}}"#,
        );
        touch(&root.join("modlist.html"), b"<html></html>");
        touch(&root.join("overrides/mods/forge-mod.jar"), b"j");

        let layout = resolve_layout(&root);
        assert_eq!(layout.layout, LayoutKind::CurseForgePack);
        assert_eq!(layout.game_root, root.join("overrides"));
        assert!(
            layout
                .mods_dir
                .as_ref()
                .is_some_and(|p| p.ends_with("overrides/mods"))
        );
        assert_eq!(layout.instance_type, InstanceType::Integrated);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn modrinth_pack_layout() {
        let root = temp_root("mr");
        touch(
            &root.join("modrinth.index.json"),
            br#"{"format_version":1,"dependencies":{"minecraft":"1.20.1"}}"#,
        );
        touch(&root.join("overrides/mods/fabric-mod.jar"), b"j");

        let layout = resolve_layout(&root);
        assert_eq!(layout.layout, LayoutKind::ModrinthPack);
        assert_eq!(layout.game_root, root.join("overrides"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn dedicated_server_detected() {
        let root = temp_root("server");
        touch(&root.join("server.properties"), b"max-players=10");
        touch(&root.join("eula.txt"), b"eula=true");
        touch(&root.join("mods/server-mod.jar"), b"j");

        let layout = resolve_layout(&root);
        assert_eq!(layout.layout, LayoutKind::DedicatedServer);
        assert_eq!(layout.instance_type, InstanceType::Server);
        assert_eq!(target_kind_from_layout(&layout), TargetKind::Server);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn nested_mods_dir_discovered() {
        let root = temp_root("nested");
        touch(&root.join("pack/instance/minecraft/mods/hidden.jar"), b"j");

        let found = find_mods_directory(&root).expect("mods");
        assert!(found.ends_with("pack/instance/minecraft/mods"));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn paper_plugins_imply_server() {
        let root = temp_root("paper");
        touch(&root.join("plugins/worldedit.jar"), b"j");
        touch(&root.join("server.properties"), b"");

        let layout = resolve_layout(&root);
        assert_eq!(layout.instance_type, InstanceType::Server);
        assert!(layout.plugins_dir.is_some());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn client_only_slice_under_client_mods() {
        let root = temp_root("client-slice");
        touch(&root.join("client/mods/client-only.jar"), b"j");

        let layout = resolve_layout(&root);
        assert_eq!(layout.instance_type, InstanceType::Client);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn integrated_when_client_and_server_markers() {
        let root = temp_root("integrated");
        touch(&root.join("server.properties"), b"");
        touch(&root.join("options.txt"), b"fov:70");
        touch(&root.join("mods/both.jar"), b"j");

        let layout = resolve_layout(&root);
        assert_eq!(layout.instance_type, InstanceType::Integrated);
        fs::remove_dir_all(root).ok();
    }
}
