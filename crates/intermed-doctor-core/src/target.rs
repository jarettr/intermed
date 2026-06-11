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
            "fabric" => Loader::Fabric,
            "quilt" => Loader::Quilt,
            "forge" => Loader::Forge,
            "neoforge" => Loader::NeoForge,
            "paper" => Loader::Paper,
            "spigot" => Loader::Spigot,
            "bukkit" => Loader::Bukkit,
            "vanilla" => Loader::Vanilla,
            _ => return None,
        })
    }
}

/// Logical side an instance runs as.
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
}

/// Environment projection, assembled from `environment` / `java_runtime` facts
/// at report time. All fields are optional: Phase 1 fills what it can detect.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Environment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loader: Option<Loader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minecraft_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<Side>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launcher: Option<String>,
}

/// Classify a path with cheap filesystem checks only.
pub fn detect_target(path: &Path) -> Target {
    if path.is_file() {
        let kind = classify_file(path);
        return Target {
            path: path.to_path_buf(),
            kind,
            mods_dir: None,
        };
    }
    if path.is_dir() {
        return classify_dir(path);
    }
    Target {
        path: path.to_path_buf(),
        kind: TargetKind::Unknown,
        mods_dir: None,
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
    let has = |rel: &str| path.join(rel).exists();

    // A directory that *is* a mods folder, or is full of jars.
    let is_mods_dir = path.file_name().and_then(|n| n.to_str()) == Some("mods")
        || (!has("mods") && dir_has_jars(path));

    let kind = if has("server.properties") || has("eula.txt") {
        TargetKind::Server
    } else if has("instance.cfg") || has("mmc-pack.json") || has(".minecraft") {
        TargetKind::Instance
    } else if has("mods") {
        // mods/ present but no server/instance markers — treat as instance-ish.
        TargetKind::Instance
    } else if is_mods_dir {
        TargetKind::ModsDir
    } else {
        TargetKind::Unknown
    };

    let mods_dir = if kind == TargetKind::ModsDir {
        Some(path.to_path_buf())
    } else if has("mods") {
        Some(path.join("mods"))
    } else if path.join(".minecraft/mods").is_dir() {
        Some(path.join(".minecraft/mods"))
    } else {
        None
    };

    Target {
        path: path.to_path_buf(),
        kind,
        mods_dir,
    }
}

fn dir_has_jars(path: &Path) -> bool {
    std::fs::read_dir(path)
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
