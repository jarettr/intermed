//! Layer A primitives: what are we even pointed at?
//!
//! [`detect_target`] does only *cheap, generic* classification (file vs dir,
//! log vs archive vs mods-dir vs server). Deeper enrichment — loader, MC
//! version, side — is the job of the Layer-A collector in
//! `intermed-minecraft-scan`, which emits `environment` / `java_runtime` facts.
//! Keeping detection here means the engine can choose collectors without
//! depending on any collector crate.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::instance_layout::{
    mods_dir_for_target, resolve_layout, target_kind_from_layout, LayoutKind, ResolvedLayout,
};

/// The kind of thing a target path points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    /// A dedicated-server directory (`server.properties` / `eula.txt`).
    Server,
    /// A launcher instance (Prism / MultiMC / Modrinth / `.minecraft`).
    Instance,
    /// A bare `mods/` directory (or a directory full of jars).
    ModsDir,
    /// A `latest.log` / `debug.log` style text log.
    LogFile,
    /// A `crash-report-*.txt` / `hs_err_pid*.log`.
    CrashReport,
    /// A `.zip` / `.mrpack` / `.impack` modpack archive.
    ModpackArchive,
    /// Could not be classified.
    Unknown,
}

impl TargetKind {
    pub fn label(&self) -> &'static str {
        match self {
            TargetKind::Server => "Minecraft server",
            TargetKind::Instance => "launcher instance",
            TargetKind::ModsDir => "mods directory",
            TargetKind::LogFile => "log file",
            TargetKind::CrashReport => "crash report",
            TargetKind::ModpackArchive => "modpack archive",
            TargetKind::Unknown => "unknown target",
        }
    }

    /// Whether mod/plugin metadata scanning is meaningful for this kind.
    pub fn has_mods(&self) -> bool {
        matches!(
            self,
            TargetKind::Server
                | TargetKind::Instance
                | TargetKind::ModsDir
                | TargetKind::ModpackArchive
        )
    }

    /// Whether this kind is a text artifact to be parsed by the log layer.
    pub fn is_log(&self) -> bool {
        matches!(self, TargetKind::LogFile | TargetKind::CrashReport)
    }
}

/// Mod loader family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Loader {
    Fabric,
    Quilt,
    Forge,
    NeoForge,
    Paper,
    Spigot,
    Bukkit,
    Vanilla,
}

impl Loader {
    pub fn as_str(&self) -> &'static str {
        match self {
            Loader::Fabric => "fabric",
            Loader::Quilt => "quilt",
            Loader::Forge => "forge",
            Loader::NeoForge => "neoforge",
            Loader::Paper => "paper",
            Loader::Spigot => "spigot",
            Loader::Bukkit => "bukkit",
            Loader::Vanilla => "vanilla",
        }
    }

    pub fn parse(s: &str) -> Option<Loader> {
        Some(match s.to_ascii_lowercase().as_str() {
            "fabric" | "fabric-loader" => Loader::Fabric,
            "quilt" | "quilt-loader" => Loader::Quilt,
            "forge" => Loader::Forge,
            "neoforge" | "neoforged" => Loader::NeoForge,
            "paper" => Loader::Paper,
            "spigot" => Loader::Spigot,
            "bukkit" => Loader::Bukkit,
            "vanilla" => Loader::Vanilla,
            _ => return None,
        })
    }
}

/// How the instance is meant to run.
///
/// * **Server** — dedicated server deployment (mods/plugins apply server-side only).
/// * **Client** — client-only slice (no dedicated server markers).
/// * **Integrated** — standard modded client install; mods load in the client JVM
///   and apply to the integrated single-player / LAN server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceType {
    Server,
    Client,
    Integrated,
}

impl InstanceType {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            InstanceType::Server => "server",
            InstanceType::Client => "client",
            InstanceType::Integrated => "integrated",
        }
    }

    /// Map to the legacy [`Side`] vocabulary used by side-mismatch rules.
    #[must_use]
    pub fn to_side(self) -> Side {
        match self {
            InstanceType::Server => Side::Server,
            InstanceType::Client => Side::Client,
            InstanceType::Integrated => Side::Both,
        }
    }
}

/// Logical side an instance runs as (legacy projection of [`InstanceType`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Client,
    Server,
    Both,
}

/// A classified target plus its root path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub path: PathBuf,
    pub kind: TargetKind,
    /// For directory targets, the directory holding mod jars, if found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mods_dir: Option<PathBuf>,
    /// Minecraft game root after layout normalization (`.minecraft`, `overrides`, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game_root: Option<PathBuf>,
    /// Recognized on-disk layout, when resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<LayoutKind>,
    /// Server / client / integrated classification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<InstanceType>,
    /// Optional spark report path (`doctor --spark-report`).
    #[serde(skip)]
    pub spark_report: Option<PathBuf>,
}

impl Target {
    /// Construct a target with only path and kind; layout fields are unset.
    #[must_use]
    pub fn with_kind(path: impl Into<PathBuf>, kind: TargetKind) -> Self {
        Self {
            path: path.into(),
            kind,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        }
    }

    /// Preferred mods directory for scanning, honoring explicit detection.
    #[must_use]
    pub fn mods_dir(&self) -> Option<PathBuf> {
        mods_dir_for_target(self.kind, &self.path, self.mods_dir.as_deref())
    }

    /// Directories under which runtime artifacts (`logs/`, `crash-reports/`,
    /// script-engine logs) may live, most specific first.
    ///
    /// For launcher instances (Prism/MultiMC/CurseForge), the actual game root
    /// is `<instance>/.minecraft` while `path` is the instance directory; logs
    /// live under the game root. Collectors must search both so they don't miss
    /// `logs/latest.log` just because the target points at the instance dir.
    #[must_use]
    pub fn candidate_roots(&self) -> Vec<PathBuf> {
        let mut roots = Vec::new();
        if let Some(game_root) = &self.game_root {
            roots.push(game_root.clone());
        }
        roots.push(self.path.clone());
        roots.dedup();
        roots
    }
}

/// Environment projection, assembled from `environment` / `java_runtime` facts
/// at report time. All fields are optional: Phase 1 fills what it can detect.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Environment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_version: Option<String>,
    /// Mod loader family (`fabric`, `forge`, `paper`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loader: Option<Loader>,
    /// Precise loader component id from pack metadata (`fabric-loader`, `forge-47.2.0`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launcher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minecraft_version: Option<String>,
    /// Legacy side projection derived from [`InstanceType`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<Side>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<InstanceType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<LayoutKind>,
    /// Host launcher application (`prism`, `multimc`, `curseforge`, `vanilla`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_launcher: Option<String>,
}

/// Classify a path with cheap filesystem checks only.
pub fn detect_target(path: &Path) -> Target {
    if path.is_file() {
        let kind = classify_file(path);
        return Target {
            path: path.to_path_buf(),
            kind,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
    }
    if path.is_dir() {
        return classify_dir(path);
    }
    Target {
        path: path.to_path_buf(),
        kind: TargetKind::Unknown,
        mods_dir: None,
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    }
}

fn classify_file(path: &Path) -> TargetKind {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.starts_with("crash-report") || name.starts_with("hs_err_pid") {
        return TargetKind::CrashReport;
    }
    if name.ends_with(".log") || name.ends_with(".txt") {
        return TargetKind::LogFile;
    }
    if name.ends_with(".zip") || name.ends_with(".mrpack") || name.ends_with(".impack") {
        return TargetKind::ModpackArchive;
    }
    TargetKind::Unknown
}

fn classify_dir(path: &Path) -> Target {
    let resolved = resolve_layout(path);
    target_from_layout(path, &resolved)
}

/// Build a [`Target`] from an already-resolved layout (used after archive extract).
#[must_use]
pub fn target_from_layout(surface_path: &Path, resolved: &ResolvedLayout) -> Target {
    let kind = target_kind_from_layout(resolved);
    Target {
        path: surface_path.to_path_buf(),
        kind,
        mods_dir: resolved.mods_dir.clone(),
        game_root: Some(resolved.game_root.clone()),
        layout: Some(resolved.layout),
        instance_type: Some(resolved.instance_type),
        spark_report: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(path: &std::path::Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, bytes).expect("write");
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "intermed-target-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn detect_prism_instance_target() {
        let root = temp("prism-detect");
        touch(&root.join("instance.cfg"), b"");
        touch(&root.join("mmc-pack.json"), br#"{"components":[]}"#);
        touch(&root.join(".minecraft/mods/a.jar"), b"j");

        let target = detect_target(&root);
        assert_eq!(target.kind, TargetKind::Instance);
        assert_eq!(target.layout, Some(LayoutKind::PrismInstance));
        assert_eq!(target.instance_type, Some(InstanceType::Integrated));
        assert!(target.mods_dir().is_some_and(|p| p.ends_with("mods")));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn detect_dot_minecraft_path() {
        let root = temp("dotmc");
        touch(&root.join("options.txt"), b"");
        touch(&root.join("mods/b.jar"), b"j");

        let target = detect_target(&root);
        assert_eq!(target.kind, TargetKind::Instance);
        assert_eq!(target.layout, Some(LayoutKind::DotMinecraft));
        fs::remove_dir_all(root).ok();
    }
}