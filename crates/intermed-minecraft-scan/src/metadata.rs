//! Layer B — mod & plugin metadata.
//!
//! For every jar under the target's mods (and `plugins/`) directory, open the
//! archive (a zip) and parse whatever manifest it contains. This is the
//! Tier-1, JVM-free port of the old `ModMetadataParser`'s **JSON path**: we
//! read `fabric.mod.json` / `quilt.mod.json` / `mods.toml` / `plugin.yml`, not
//! bytecode. Annotation-based (Forge `@Mod`) discovery is Tier-2 / Layer F and
//! deliberately not done here.

use std::io::Read;
use std::path::{Path, PathBuf};

use intermed_doctor_core::facts::{kind, SourceRef};
use intermed_doctor_core::{CollectCtx, Collector, CollectorOutcome, Layer, Loader, Target};

pub struct MetadataCollector;

impl Collector for MetadataCollector {
    fn id(&self) -> &'static str {
        "metadata-scanner"
    }
    fn layer(&self) -> Layer {
        Layer::Metadata
    }
    fn applies(&self, target: &Target) -> bool {
        target.kind.has_mods()
    }
    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let jars = gather_jars(ctx.target);
        if jars.is_empty() {
            return CollectorOutcome::active(0, "no jar archives found");
        }

        let mut emitted = 0usize;
        let mut parsed = 0usize;
        let mut failed = 0usize;

        for jar in &jars {
            let name = jar
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string();
            match parse_jar(jar) {
                Ok(Some(m)) => {
                    parsed += 1;
                    emitted += emit_artifact(ctx, &m, &name);
                }
                Ok(None) => {
                    failed += 1;
                    ctx.store
                        .fact(self.id(), kind::UNPARSEABLE_ARCHIVE)
                        .subject(name.clone())
                        .attr("reason", "no recognised manifest")
                        .source(SourceRef::file(jar.display().to_string()))
                        .confidence(0.7)
                        .emit();
                    emitted += 1;
                }
                Err(e) => {
                    failed += 1;
                    ctx.store
                        .fact(self.id(), kind::UNPARSEABLE_ARCHIVE)
                        .subject(name.clone())
                        .attr("reason", e.as_str())
                        .source(SourceRef::file(jar.display().to_string()))
                        .confidence(0.7)
                        .emit();
                    emitted += 1;
                }
            }
        }

        CollectorOutcome::active(
            emitted,
            format!(
                "{} jar(s): {} parsed, {} unparseable",
                jars.len(),
                parsed,
                failed
            ),
        )
    }
}

fn emit_artifact(ctx: &mut CollectCtx<'_>, m: &Artifact, file: &str) -> usize {
    let mut emitted = 0;
    let predicate = if m.is_plugin { kind::PLUGIN } else { kind::MOD };
    ctx.store
        .fact("metadata-scanner", predicate)
        .subject(m.id.clone())
        .attr("version", m.version.clone())
        .attr("loader", m.loader.as_str())
        .attr("file", file)
        .source(SourceRef::inside(file, m.manifest_name))
        .emit();
    emitted += 1;

    if let Some(side) = m.side {
        ctx.store
            .fact("metadata-scanner", kind::MOD_SIDE)
            .subject(m.id.clone())
            .attr("side", side)
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        emitted += 1;
    }

    for dep in &m.deps {
        ctx.store
            .fact("metadata-scanner", kind::DEPENDENCY)
            .subject(m.id.clone())
            .attr("dep", dep.id.clone())
            .attr("range", dep.range.clone())
            .attr("mandatory", dep.mandatory)
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        emitted += 1;
    }

    for p in &m.provides {
        ctx.store
            .fact("metadata-scanner", kind::PROVIDED_DEPENDENCY)
            .subject(m.id.clone())
            .attr("provides", p.clone())
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        emitted += 1;
    }

    emitted
}

/// Collect candidate jars from the mods dir and a sibling `plugins/` dir.
fn gather_jars(target: &Target) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(md) = &target.mods_dir {
        dirs.push(md.clone());
    }
    let plugins = target.path.join("plugins");
    if plugins.is_dir() {
        dirs.push(plugins);
    }
    if dirs.is_empty() && target.path.is_dir() {
        dirs.push(target.path.clone());
    }

    let mut out = Vec::new();
    for d in dirs {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x.eq_ignore_ascii_case("jar"))
                {
                    out.push(p);
                }
            }
        }
    }
    out.sort();
    out
}

// ── Parsed model ───────────────────────────────────────────────────────────

struct Dep {
    id: String,
    range: String,
    mandatory: bool,
}

struct Artifact {
    id: String,
    version: String,
    loader: Loader,
    side: Option<&'static str>,
    deps: Vec<Dep>,
    provides: Vec<String>,
    is_plugin: bool,
    manifest_name: &'static str,
}

/// Parse error reduced to a short, fact-friendly string.
struct ParseErr(String);
impl ParseErr {
    fn as_str(&self) -> &str {
        &self.0
    }
}

fn read_entry(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Option<String> {
    let mut f = archive.by_name(name).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

fn parse_jar(path: &Path) -> Result<Option<Artifact>, ParseErr> {
    let file = std::fs::File::open(path).map_err(|e| ParseErr(format!("open: {e}")))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| ParseErr(format!("zip: {e}")))?;

    if let Some(text) = read_entry(&mut archive, "fabric.mod.json") {
        return parse_fabric(&text).map(Some);
    }
    if let Some(text) = read_entry(&mut archive, "quilt.mod.json") {
        return parse_quilt(&text).map(Some);
    }
    if let Some(text) = read_entry(&mut archive, "META-INF/neoforge.mods.toml") {
        return parse_forge_toml(&text, Loader::NeoForge).map(Some);
    }
    if let Some(text) = read_entry(&mut archive, "META-INF/mods.toml") {
        return parse_forge_toml(&text, Loader::Forge).map(Some);
    }
    if let Some(text) = read_entry(&mut archive, "paper-plugin.yml") {
        return parse_plugin_yml(&text, Loader::Paper, "paper-plugin.yml").map(Some);
    }
    if let Some(text) = read_entry(&mut archive, "plugin.yml") {
        return parse_plugin_yml(&text, Loader::Bukkit, "plugin.yml").map(Some);
    }
    Ok(None)
}

fn parse_fabric(text: &str) -> Result<Artifact, ParseErr> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| ParseErr(format!("fabric.mod.json: {e}")))?;
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("?")
        .to_string();
    let version = v
        .get("version")
        .and_then(|x| x.as_str())
        .unwrap_or("0")
        .to_string();
    let side = match v.get("environment").and_then(|x| x.as_str()) {
        Some("client") => Some("client"),
        Some("server") => Some("server"),
        Some("*") => Some("both"),
        _ => None,
    };
    let mut deps = Vec::new();
    if let Some(map) = v.get("depends").and_then(|x| x.as_object()) {
        for (dep, range) in map {
            deps.push(Dep {
                id: dep.clone(),
                range: json_range(range),
                mandatory: true,
            });
        }
    }
    let provides = v
        .get("provides")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(Artifact {
        id,
        version,
        loader: Loader::Fabric,
        side,
        deps,
        provides,
        is_plugin: false,
        manifest_name: "fabric.mod.json",
    })
}

fn parse_quilt(text: &str) -> Result<Artifact, ParseErr> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| ParseErr(format!("quilt.mod.json: {e}")))?;
    let ql = v
        .get("quilt_loader")
        .ok_or_else(|| ParseErr("quilt.mod.json: no quilt_loader".into()))?;
    let id = ql
        .get("id")
        .and_then(|x| x.as_str())
        .unwrap_or("?")
        .to_string();
    let version = ql
        .get("version")
        .and_then(|x| x.as_str())
        .unwrap_or("0")
        .to_string();
    let mut deps = Vec::new();
    if let Some(arr) = ql.get("depends").and_then(|x| x.as_array()) {
        for d in arr {
            match d {
                serde_json::Value::String(s) => deps.push(Dep {
                    id: s.clone(),
                    range: "*".into(),
                    mandatory: true,
                }),
                serde_json::Value::Object(o) => {
                    if let Some(dep_id) = o.get("id").and_then(|x| x.as_str()) {
                        let range = o
                            .get("versions")
                            .map(json_range)
                            .unwrap_or_else(|| "*".into());
                        deps.push(Dep {
                            id: dep_id.to_string(),
                            range,
                            mandatory: true,
                        });
                    }
                }
                _ => {}
            }
        }
    }
    let provides = ql
        .get("provides")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(quilt_provides_id).collect())
        .unwrap_or_default();
    Ok(Artifact {
        id,
        version,
        loader: Loader::Quilt,
        side: None,
        deps,
        provides,
        is_plugin: false,
        manifest_name: "quilt.mod.json",
    })
}

fn quilt_provides_id(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o.get("id").and_then(|x| x.as_str()).map(str::to_string),
        _ => None,
    }
}

fn parse_forge_toml(text: &str, loader: Loader) -> Result<Artifact, ParseErr> {
    let v: toml::Value = text
        .parse()
        .map_err(|e| ParseErr(format!("mods.toml: {e}")))?;
    let mods = v.get("mods").and_then(|m| m.as_array());
    let first = mods.and_then(|a| a.first());
    let id = first
        .and_then(|m| m.get("modId"))
        .and_then(|x| x.as_str())
        .unwrap_or("?")
        .to_string();
    let version = first
        .and_then(|m| m.get("version"))
        .and_then(|x| x.as_str())
        .unwrap_or("0")
        .to_string();

    let mut deps = Vec::new();
    let mut side = None;
    if let Some(dep_table) = v.get("dependencies").and_then(|d| d.as_table()) {
        if let Some(arr) = dep_table.get(&id).and_then(|x| x.as_array()) {
            for d in arr {
                let dep_id = d
                    .get("modId")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string();
                let range = d
                    .get("versionRange")
                    .and_then(|x| x.as_str())
                    .unwrap_or("*")
                    .to_string();
                let mandatory = d.get("mandatory").and_then(|x| x.as_bool()).unwrap_or(true);
                if let Some(s) = d.get("side").and_then(|x| x.as_str()) {
                    side = Some(forge_side(s));
                }
                deps.push(Dep {
                    id: dep_id,
                    range,
                    mandatory,
                });
            }
        }
    }
    Ok(Artifact {
        id,
        version,
        loader,
        side,
        deps,
        provides: Vec::new(),
        is_plugin: false,
        manifest_name: if loader == Loader::NeoForge {
            "META-INF/neoforge.mods.toml"
        } else {
            "META-INF/mods.toml"
        },
    })
}

fn parse_plugin_yml(
    text: &str,
    loader: Loader,
    manifest_name: &'static str,
) -> Result<Artifact, ParseErr> {
    let v: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| ParseErr(format!("{manifest_name}: {e}")))?;
    let id = v
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or("?")
        .to_string();
    let version = yaml_scalar(v.get("version")).unwrap_or_else(|| "0".to_string());
    let mut deps = Vec::new();
    for (key, mandatory) in [("depend", true), ("softdepend", false)] {
        if let Some(arr) = v.get(key).and_then(|x| x.as_sequence()) {
            for d in arr {
                if let Some(s) = d.as_str() {
                    deps.push(Dep {
                        id: s.to_string(),
                        range: "*".into(),
                        mandatory,
                    });
                }
            }
        }
    }
    Ok(Artifact {
        id,
        version,
        loader,
        side: Some("server"),
        deps,
        provides: Vec::new(),
        is_plugin: true,
        manifest_name,
    })
}

// ── helpers ──────────────────────────────────────────────────────────────

fn forge_side(s: &str) -> &'static str {
    match s.to_ascii_uppercase().as_str() {
        "CLIENT" => "client",
        "SERVER" => "server",
        _ => "both",
    }
}

/// fabric/quilt dependency ranges may be a string or an array of strings.
fn json_range(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => {
            let parts: Vec<String> = a
                .iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect();
            if parts.is_empty() {
                "*".into()
            } else {
                parts.join(" || ")
            }
        }
        _ => "*".into(),
    }
}

/// YAML versions are often unquoted numbers; coerce to string.
fn yaml_scalar(v: Option<&serde_yaml::Value>) -> Option<String> {
    match v? {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}
