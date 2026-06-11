//! Layer A — environment / target enrichment.
//!
//! Emits `environment` and `java_runtime` facts. Detection is heuristic and
//! best-effort: every attribute is optional, and missing data simply produces
//! fewer facts rather than a hard failure.

use std::path::Path;
use std::process::Command;

use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, Layer, Loader, Target, TargetKind,
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
        let root = &ctx.target.path;

        let loader = detect_loader(root, ctx.target);
        let launcher = detect_launcher(root);
        let side = detect_side(ctx.target.kind);
        let mc = detect_mc_version(root);

        let mut b = ctx
            .store
            .fact(self.id(), kind::ENVIRONMENT)
            .attr("os", std::env::consts::OS)
            .source(intermed_doctor_core::facts::SourceRef::file(
                root.display().to_string(),
            ))
            .confidence(0.9);
        if let Some(l) = loader {
            b = b.attr("loader", l.as_str());
        }
        if let Some(s) = side {
            b = b.attr("side", s);
        }
        if let Some(m) = &mc {
            b = b.attr("mc_version", m.as_str());
        }
        if let Some(la) = &launcher {
            b = b.attr("launcher", la.as_str());
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

fn detect_loader(root: &Path, target: &Target) -> Option<Loader> {
    let has = |rel: &str| root.join(rel).exists();
    if has("libraries/net/fabricmc") || has("fabric-server-launch.jar") || has(".fabric") {
        return Some(Loader::Fabric);
    }
    if has("libraries/org/quiltmc") || has("quilt-server-launch.jar") {
        return Some(Loader::Quilt);
    }
    if has("libraries/net/neoforged") {
        return Some(Loader::NeoForge);
    }
    if has("libraries/net/minecraftforge") || dir_has_prefixed_jar(root, "forge-") {
        return Some(Loader::Forge);
    }
    // Server software with a plugins/ dir → Bukkit family.
    if has("plugins") && (has("spigot.yml") || dir_has_prefixed_jar(root, "spigot")) {
        return Some(Loader::Spigot);
    }
    if has("plugins") && (has("paper.yml") || has("config/paper-global.yml")) {
        return Some(Loader::Paper);
    }
    if has("plugins") && has("bukkit.yml") {
        return Some(Loader::Bukkit);
    }
    // For a bare mods dir we leave the global loader unknown; per-mod loader
    // facts from Layer B carry that information instead.
    let _ = target;
    None
}

fn detect_launcher(root: &Path) -> Option<String> {
    let has = |rel: &str| root.join(rel).exists();
    if has("mmc-pack.json") || has("instance.cfg") {
        return Some("prism/multimc".to_string());
    }
    if has(".minecraft") && has("profile.json") {
        return Some("modrinth-app".to_string());
    }
    if has("manifest.json") && has("modlist.html") {
        return Some("curseforge".to_string());
    }
    None
}

fn detect_side(kind: TargetKind) -> Option<&'static str> {
    match kind {
        TargetKind::Server => Some("server"),
        TargetKind::Instance => Some("client"),
        _ => None,
    }
}

/// Try to read a Minecraft version from common locations. Best-effort.
fn detect_mc_version(root: &Path) -> Option<String> {
    // MultiMC/Prism record the intended MC version in mmc-pack.json.
    let mmc = root.join("mmc-pack.json");
    if let Ok(text) = std::fs::read_to_string(&mmc) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(components) = v.get("components").and_then(|c| c.as_array()) {
                for c in components {
                    if c.get("uid").and_then(|u| u.as_str()) == Some("net.minecraft") {
                        if let Some(ver) = c.get("version").and_then(|x| x.as_str()) {
                            return Some(ver.to_string());
                        }
                    }
                }
            }
        }
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
