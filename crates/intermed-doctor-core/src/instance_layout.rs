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

/// Physical placement of the game root, independent of which launcher or pack
/// format produced it. A nested `.minecraft` directory is topology evidence;
/// it is not, by itself, evidence for Prism or MultiMC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayoutTopology {
    DirectGameRoot,
    NestedDotMinecraft,
    OverridesRoot,
    BareArtifacts,
    DedicatedServer,
    Unknown,
}

impl LayoutTopology {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectGameRoot => "direct-game-root",
            Self::NestedDotMinecraft => "nested-dot-minecraft",
            Self::OverridesRoot => "overrides-root",
            Self::BareArtifacts => "bare-artifacts",
            Self::DedicatedServer => "dedicated-server",
            Self::Unknown => "unknown",
        }
    }
}

/// Launcher provenance established by launcher-specific files. Pack export
/// formats deliberately do not imply that the target was run by that launcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LauncherKind {
    Prism,
    MultiMc,
    Vanilla,
}

impl LauncherKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prism => "prism",
            Self::MultiMc => "multimc",
            Self::Vanilla => "vanilla",
        }
    }
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
    /// Filesystem topology, kept separate from launcher provenance.
    pub topology: LayoutTopology,
    /// Launcher identity only when launcher-specific markers establish it.
    pub launcher: Option<LauncherKind>,
    pub instance_type: InstanceType,
    pub instance_resolution: InstanceTypeResolution,
    /// Resolved mod jar directory, if any.
    pub mods_dir: Option<PathBuf>,
    /// Bukkit-family plugin directory, when present.
    pub plugins_dir: Option<PathBuf>,
    /// All equally plausible fallback `mods/` paths. Non-empty with no selected
    /// path means discovery abstained instead of choosing by directory order.
    pub mods_candidates: Vec<PathBuf>,
    pub mods_certainty: PathResolutionCertainty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstanceResolutionCertainty {
    Confirmed,
    Inferred,
    Conflict,
    Unknown,
}

/// Field-wise resolution for the runtime shape. The legacy `instance_type`
/// projection remains available, while consumers that gate hard conclusions
/// can distinguish confirmed, inferred, conflicting and absent evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceTypeResolution {
    pub value: InstanceType,
    pub certainty: InstanceResolutionCertainty,
    pub server_markers: bool,
    pub client_markers: bool,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathResolutionCertainty {
    ConfirmedKnownLayout,
    InferredUnique,
    Ambiguous,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModsDirectoryResolution {
    pub selected: Option<PathBuf>,
    pub candidates: Vec<PathBuf>,
    pub certainty: PathResolutionCertainty,
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
    let mut mods_resolution = find_mods_directory_resolution(surface_root);
    if mods_resolution.selected.is_none()
        && mods_resolution.certainty != PathResolutionCertainty::Ambiguous
        && game_root != surface_root
    {
        mods_resolution = find_mods_directory_resolution(&game_root);
    }
    let mods_dir = mods_resolution.selected.clone();
    let plugins_dir = find_plugins_directory(surface_root, &game_root);
    let instance_resolution = resolve_instance_type(
        &game_root,
        layout,
        mods_dir.as_deref(),
        plugins_dir.as_deref(),
    );
    let topology = resolve_topology(surface_root, &game_root, layout);
    let launcher = detect_launcher_kind(surface_root, layout);

    ResolvedLayout {
        surface_root: surface_root.to_path_buf(),
        game_root,
        layout,
        topology,
        launcher,
        instance_type: instance_resolution.value,
        instance_resolution,
        mods_dir,
        plugins_dir,
        mods_candidates: mods_resolution.candidates,
        mods_certainty: mods_resolution.certainty,
    }
}

fn resolve_topology(surface_root: &Path, game_root: &Path, layout: LayoutKind) -> LayoutTopology {
    match layout {
        LayoutKind::DedicatedServer => LayoutTopology::DedicatedServer,
        LayoutKind::BareModsDir => LayoutTopology::BareArtifacts,
        LayoutKind::CurseForgePack | LayoutKind::ModrinthPack
            if game_root == surface_root.join("overrides") =>
        {
            LayoutTopology::OverridesRoot
        }
        LayoutKind::PrismInstance | LayoutKind::MultiMcInstance
            if game_root == surface_root.join(".minecraft") =>
        {
            LayoutTopology::NestedDotMinecraft
        }
        LayoutKind::Unknown if game_root == surface_root.join(".minecraft") => {
            LayoutTopology::NestedDotMinecraft
        }
        LayoutKind::Unknown => LayoutTopology::Unknown,
        _ => LayoutTopology::DirectGameRoot,
    }
}

fn detect_launcher_kind(root: &Path, layout: LayoutKind) -> Option<LauncherKind> {
    match layout {
        LayoutKind::PrismInstance => Some(LauncherKind::Prism),
        LayoutKind::MultiMcInstance => Some(LauncherKind::MultiMc),
        LayoutKind::DotMinecraft
            if root.join("launcher_profiles.json").is_file()
                || root.join("launcher_accounts.json").is_file() =>
        {
            Some(LauncherKind::Vanilla)
        }
        _ => None,
    }
}

/// Find a `mods/` directory under `root`, checking known layouts then subdirectories.
#[must_use]
pub fn find_mods_directory(root: &Path) -> Option<PathBuf> {
    find_mods_directory_resolution(root).selected
}

#[must_use]
pub fn find_mods_directory_resolution(root: &Path) -> ModsDirectoryResolution {
    for rel in MODS_CANDIDATE_RELS {
        let candidate = root.join(rel);
        if is_mods_directory(&candidate) {
            return ModsDirectoryResolution {
                selected: Some(candidate.clone()),
                candidates: vec![candidate],
                certainty: PathResolutionCertainty::ConfirmedKnownLayout,
            };
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

    // Topology alone may identify the game root without proving a launcher.
    let nested_dot_mc = surface_root.join(".minecraft");
    if nested_dot_mc.is_dir() {
        return nested_dot_mc;
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
    // A nested `.minecraft` establishes topology, not Prism provenance.
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
    resolve_instance_type(game_root, layout, mods_dir, plugins_dir).value
}

#[must_use]
pub fn resolve_instance_type(
    game_root: &Path,
    layout: LayoutKind,
    mods_dir: Option<&Path>,
    plugins_dir: Option<&Path>,
) -> InstanceTypeResolution {
    let server = has_dedicated_server_markers(game_root, plugins_dir);
    let client = has_client_markers(game_root, layout);

    let (value, certainty, reason) = match (server, client) {
        (true, true) => (
            InstanceType::Unknown,
            InstanceResolutionCertainty::Conflict,
            "server-and-client-markers-conflict",
        ),
        (true, false) => (
            InstanceType::Server,
            InstanceResolutionCertainty::Confirmed,
            "dedicated-server-markers",
        ),
        (false, true) if is_launcher_integrated_layout(layout) => (
            InstanceType::Integrated,
            InstanceResolutionCertainty::Confirmed,
            "client-markers-in-instance-layout",
        ),
        (false, true) if is_client_only_mods_path(mods_dir) => (
            InstanceType::Client,
            InstanceResolutionCertainty::Confirmed,
            "client-only-artifact-root",
        ),
        (false, true) => (
            InstanceType::Integrated,
            InstanceResolutionCertainty::Inferred,
            "client-markers-without-launcher-provenance",
        ),
        (false, false) if is_client_only_mods_path(mods_dir) => (
            InstanceType::Client,
            InstanceResolutionCertainty::Inferred,
            "client-only-artifact-root",
        ),
        (false, false) => {
            let inferred = infer_instance_type_from_layout(layout, mods_dir);
            if inferred == InstanceType::Unknown {
                (
                    inferred,
                    InstanceResolutionCertainty::Unknown,
                    "no-runtime-shape-evidence",
                )
            } else {
                (
                    inferred,
                    InstanceResolutionCertainty::Inferred,
                    "layout-implies-runtime-shape",
                )
            }
        }
    };
    InstanceTypeResolution {
        value,
        certainty,
        server_markers: server,
        client_markers: client,
        reason,
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
                InstanceType::Unknown
            }
        }
        LayoutKind::PrismInstance
        | LayoutKind::MultiMcInstance
        | LayoutKind::DotMinecraft
        | LayoutKind::CurseForgePack
        | LayoutKind::ModrinthPack => InstanceType::Integrated,
        LayoutKind::Unknown => InstanceType::Unknown,
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

fn search_mods_bfs(root: &Path, max_depth: usize) -> ModsDirectoryResolution {
    if max_depth == 0 {
        return ModsDirectoryResolution {
            selected: None,
            candidates: Vec::new(),
            certainty: PathResolutionCertainty::Unavailable,
        };
    }
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut candidates = Vec::new();
    let mut best_depth = None;

    while let Some((dir, depth)) = queue.pop_front() {
        if depth > max_depth {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut entries = entries.flatten().collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
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
                let candidate_depth = depth + 1;
                match best_depth {
                    None => {
                        best_depth = Some(candidate_depth);
                        candidates.push(path.clone());
                    }
                    Some(best) if candidate_depth < best => {
                        best_depth = Some(candidate_depth);
                        candidates.clear();
                        candidates.push(path.clone());
                    }
                    Some(best) if candidate_depth == best => candidates.push(path.clone()),
                    Some(_) => {}
                }
            }
            if depth < max_depth {
                queue.push_back((path, depth + 1));
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [selected] => ModsDirectoryResolution {
            selected: Some(selected.clone()),
            candidates,
            certainty: PathResolutionCertainty::InferredUnique,
        },
        [] => ModsDirectoryResolution {
            selected: None,
            candidates,
            certainty: PathResolutionCertainty::Unavailable,
        },
        _ => ModsDirectoryResolution {
            selected: None,
            candidates,
            certainty: PathResolutionCertainty::Ambiguous,
        },
    }
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
    fn conflicting_client_and_server_markers_remain_unknown() {
        let root = temp_root("integrated");
        touch(&root.join("server.properties"), b"");
        touch(&root.join("options.txt"), b"fov:70");
        touch(&root.join("mods/both.jar"), b"j");

        let layout = resolve_layout(&root);
        assert_eq!(layout.instance_type, InstanceType::Unknown);
        assert_eq!(
            layout.instance_resolution.certainty,
            InstanceResolutionCertainty::Conflict
        );
        assert_eq!(
            layout.instance_resolution.reason,
            "server-and-client-markers-conflict"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn nested_dot_minecraft_does_not_claim_prism_launcher() {
        let root = temp_root("nested-dot-minecraft");
        touch(&root.join(".minecraft/mods/example.jar"), b"j");

        let layout = resolve_layout(&root);
        assert_eq!(layout.layout, LayoutKind::Unknown);
        assert_eq!(layout.game_root, root.join(".minecraft"));
        assert_eq!(layout.topology, LayoutTopology::NestedDotMinecraft);
        assert_eq!(layout.launcher, None);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn equal_depth_fallback_mods_directories_are_ambiguous() {
        let root = temp_root("ambiguous-mods");
        touch(&root.join("backup/mods/a.jar"), b"j");
        touch(&root.join("instance/mods/b.jar"), b"j");

        let resolution = find_mods_directory_resolution(&root);
        assert_eq!(resolution.selected, None);
        assert_eq!(resolution.certainty, PathResolutionCertainty::Ambiguous);
        assert_eq!(resolution.candidates.len(), 2);
        fs::remove_dir_all(root).ok();
    }
}
