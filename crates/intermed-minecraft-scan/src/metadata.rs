//! Layer B — mod & plugin metadata.
//!
//! For every jar under the target's mods (and `plugins/`) directory, open the
//! archive (a zip) and parse whatever manifest it contains. This is the
//! Tier-1, JVM-free port of the old `ModMetadataParser`'s **JSON path**: we
//! read `fabric.mod.json` / `quilt.mod.json` / `mods.toml` / `plugin.yml`, not
//! bytecode. Annotation-based (Forge `@Mod`) discovery is Tier-2 / Layer F and
//! deliberately not done here.

use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use intermed_doctor_core::facts::{kind, SourceRef};
use intermed_doctor_core::{
    list_jar_archives, CollectCtx, Collector, CollectorOutcome, Layer, Loader, MetadataLevel,
    Target,
};
use serde::{Deserialize, Serialize};

use crate::access;
use crate::forge_annotation;

/// Cache key version for this collector's payload. The crate version invalidates
/// the cache automatically on every release; bump the trailing revision when the
/// scan/parse logic changes within a single release.
const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-r12");

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
        let jars = gather_jars(ctx.target, &ctx.settings.scan);
        if jars.is_empty() {
            return CollectorOutcome::active(0, "no jar archives found");
        }

        let mut emitted = 0usize;
        let mut parsed = 0usize;
        let mut failed = 0usize;

        // Parse jars in parallel (independent archive reads), then emit facts
        // serially — `ctx.store` is single-threaded and `par_iter().map()`
        // preserves order, so emission stays deterministic.
        let cache = ctx.jar_cache;
        let collector_id = self.id();
        let metadata_level = ctx.settings.metadata.level;
        let cache_version = format!("{CACHE_VERSION}-{}", metadata_level_name(metadata_level));
        let scanned: Vec<(PathBuf, String, CachedJarOutcome)> =
            jars.par_iter()
                .map(|jar| {
                    let name = jar
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("?")
                        .to_string();
                    let outcome = match cache {
                        Some(cache) => cache
                            .get_or_scan(collector_id, &cache_version, jar, || {
                                scan_jar_cached(jar, metadata_level)
                            }),
                        None => scan_jar_cached(jar, metadata_level),
                    };
                    (jar.clone(), name, outcome)
                })
                .collect();

        for (jar, name, outcome) in scanned {
            match outcome {
                CachedJarOutcome::Parsed(cached) => {
                    parsed += 1;
                    for m in cached.into_iter().map(cached_to_artifact) {
                        emitted += emit_artifact(ctx, &m, &name);
                    }
                }
                CachedJarOutcome::NoManifest => {
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
                CachedJarOutcome::Error(reason) => {
                    failed += 1;
                    ctx.store
                        .fact(self.id(), kind::UNPARSEABLE_ARCHIVE)
                        .subject(name.clone())
                        .attr("reason", reason)
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
    // A missing/placeholder id must never become a real subject: `?` would make
    // every malformed jar collide under `duplicate-id:?` and let dependency
    // reasoning treat `?` as a satisfiable mod. Record the broken metadata and
    // use a synthetic, archive-scoped id (unique per jar) flagged as such.
    let id_missing = m.id.trim().is_empty() || m.id == "?";
    if id_missing {
        ctx.store
            .fact("metadata-scanner", kind::INVALID_METADATA)
            .subject(file.to_string())
            .attr("reason", "missing or unparseable mod id")
            .attr("manifest", m.manifest_name)
            .attr("loader", m.loader.as_str())
            .source(SourceRef::inside(file, m.manifest_name))
            .confidence(0.9)
            .emit();
        emitted += 1;
    }
    let subject = if id_missing {
        format!("unknown:{file}")
    } else {
        m.id.clone()
    };
    let mut builder = ctx
        .store
        .fact("metadata-scanner", predicate)
        .subject(subject)
        .attr("version", m.version.clone())
        .attr("synthetic_id", id_missing)
        .attr("loader", m.loader.as_str())
        .attr("file", file)
        .source(SourceRef::inside(file, m.manifest_name));
    if let Some(ref api) = m.api_version {
        builder = builder.attr("api_version", api.as_str());
    }
    if let Some(order) = m.load_order {
        builder = builder.attr("load_order", order);
    }
    builder.emit();
    emitted += 1;

    // A hybrid jar's second role (e.g. a Bukkit plugin that also carries a Fabric
    // mod manifest) — informational, so no rule mistakes it for a separate mod.
    if let Some(secondary) = &m.secondary {
        let (role, sid) = secondary.split_once(':').unwrap_or(("mod", secondary.as_str()));
        ctx.store
            .fact("metadata-scanner", kind::SECONDARY_IDENTITY)
            .subject(m.id.clone())
            .attr("file", file)
            .attr("role", role)
            .attr("secondary_id", sid)
            .source(SourceRef::inside(file, m.manifest_name))
            .confidence(0.8)
            .emit();
        emitted += 1;
    }

    // Without a real id we cannot reliably attribute dependencies, relationships
    // or capabilities — they would all carry the synthetic subject and risk
    // phantom edges. Stop after the base + invalid_metadata facts.
    if id_missing {
        return emitted;
    }

    if ctx.settings.metadata.level != MetadataLevel::Basic {
        let mut builder = ctx
            .store
            .fact("metadata-scanner", kind::MOD_METADATA)
            .subject(m.id.clone())
            .attr("version_raw", m.version.clone())
            .attr("version_normalized", normalize_version(&m.version))
            .attr("version_ambiguous", version_ambiguous(&m.version))
            .attr("loader", m.loader.as_str())
            .attr(
                "environment",
                if m.is_plugin {
                    "dedicated_server"
                } else {
                    m.side.unwrap_or("both")
                },
            )
            .attr("authors", serde_json::to_string(&m.authors).unwrap_or_else(|_| "[]".into()))
            .source(SourceRef::inside(file, m.manifest_name));
        for (key, value) in [
            ("name", m.name.as_deref()),
            ("description", m.description.as_deref()),
            ("license", m.license.as_deref()),
            ("icon", m.icon.as_deref()),
            ("update_json", m.update_json.as_deref()),
        ] {
            if let Some(value) = value {
                builder = builder.attr(key, value);
            }
        }
        builder.emit();
        emitted += 1;
    }

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
        let mut builder = ctx
            .store
            .fact("metadata-scanner", kind::DEPENDENCY)
            .subject(m.id.clone())
            .attr("dep", dep.id.clone())
            .attr("range", dep.range.clone())
            .attr("mandatory", dep.mandatory)
            .attr("relation", dep.relation)
            .source(SourceRef::inside(file, m.manifest_name));
        if let Some(feature) = &dep.feature {
            builder = builder.attr("feature", feature.as_str());
        }
        builder.emit();
        emitted += 1;
        if ctx.settings.metadata.level != MetadataLevel::Basic {
            let relation_type = match dep.relation {
                // A manifest `breaks` is a *version-scoped* declaration ("I break
                // dep X in range R"), not a curated, versionless fact. Emitting it
                // as `known_incompatible` made the declarative rule flag any
                // installed copy as "cannot run together" regardless of version —
                // a false ERROR. Keep it as a neutral fact; the version-aware
                // pairwise check (relation == "breaks" over the DEPENDENCY fact)
                // is the single source of truth for the actual incompatibility
                // finding. `known_incompatible` is reserved for the curated KB.
                "breaks" => Some("declared_breaks"),
                "recommends" | "suggests" => Some("recommended_together"),
                "depends" if !matches!(dep.id.as_str(), "minecraft" | "java" | "fabricloader" | "forge" | "neoforge") => {
                    Some("consumes_api")
                }
                _ => None,
            };
            if let Some(relation_type) = relation_type {
                ctx.store
                    .fact("metadata-scanner", kind::MOD_RELATIONSHIP)
                    .subject(m.id.clone())
                    .attr("related", dep.id.clone())
                    .attr("type", relation_type)
                    .attr("reason", format!("manifest:{}", dep.relation))
                    .source(SourceRef::inside(file, m.manifest_name))
                    .confidence(match dep.relation {
                        "breaks" => 1.0,
                        "depends" => 0.75,
                        _ => 0.9,
                    })
                    .emit();
                emitted += 1;
            }
        }
    }

    for config in &m.mixin_configs {
        ctx.store
            .fact("metadata-scanner", kind::MIXIN_CONFIG)
            .subject(m.id.clone())
            .attr("config", config.as_str())
            .attr("loader", m.loader.as_str())
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        emitted += 1;
    }

    for p in &m.provides {
        ctx.store
            .fact("metadata-scanner", kind::PROVIDED_DEPENDENCY)
            .subject(m.id.clone())
            .attr("provides", p.clone())
            // A manifest `provides` is a loader-registered alias id, globally
            // visible to other mods' dependency resolution.
            .attr("scope", "metadata-alias")
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        emitted += 1;
        if ctx.settings.metadata.level != MetadataLevel::Basic {
            ctx.store
                .fact("metadata-scanner", kind::MOD_RELATIONSHIP)
                .subject(m.id.clone())
                .attr("related", p.clone())
                .attr("type", "provides_api")
                .attr("reason", "manifest:provides")
                .source(SourceRef::inside(file, m.manifest_name))
                .confidence(1.0)
                .emit();
            emitted += 1;
        }
    }

    // Bundled (Jar-in-Jar) modules: register each as a versioned provider so a
    // dependency satisfied by a nested library is not reported missing, and
    // record the nesting itself as evidence.
    for (id, version) in &m.bundled {
        ctx.store
            .fact("metadata-scanner", kind::PROVIDED_DEPENDENCY)
            .subject(m.id.clone())
            .attr("provides", id.clone())
            .attr("version", version.clone())
            .attr("bundled", true)
            // Jar-in-Jar libraries are added to the mod classpath by the loader,
            // so they are visible to every mod (global classpath scope).
            .attr("scope", "classpath")
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        ctx.store
            .fact("metadata-scanner", kind::NESTED_JAR)
            .subject(m.id.clone())
            .attr("nested", id.clone())
            .attr("version", version.clone())
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        emitted += 2;
    }

    for ep in &m.entrypoints {
        ctx.store
            .fact("metadata-scanner", kind::ENTRYPOINT)
            .subject(m.id.clone())
            .attr("phase", ep.phase.clone())
            .attr("class", ep.class.clone())
            .attr("loader", m.loader.as_str())
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        emitted += 1;
        if ctx.settings.metadata.level != MetadataLevel::Basic {
            let mut detail = ctx.store
                .fact("metadata-scanner", kind::ENTRYPOINT_DETAIL)
                .subject(m.id.clone())
                .attr("phase", ep.phase.clone())
                .attr("class", ep.class.clone())
                .attr("entrypoint_type", ep.entrypoint_type.clone())
                .source(SourceRef::inside(file, m.manifest_name))
                .confidence(if ep.events.is_empty() { 0.65 } else { 0.85 });
            if ctx.settings.metadata.level == MetadataLevel::Full {
                detail = detail
                    .attr("events", serde_json::to_string(&ep.events).unwrap_or_else(|_| "[]".into()))
                    .attr("priority", ep.priority);
            }
            detail.emit();
            emitted += 1;
        }
    }

    for at in &m.access_transforms {
        let mut builder = ctx
            .store
            .fact("metadata-scanner", kind::ACCESS_TRANSFORM)
            .subject(m.id.clone())
            .attr("mechanism", at.mechanism.clone())
            .attr("access", at.access.clone())
            .attr("target_class", at.target_class.clone())
            .attr("target_key", access::target_key_owned(&at.target_class, at.member.as_deref()))
            .source(SourceRef::inside(file, m.manifest_name));
        if !at.qualifier.is_empty() {
            builder = builder.attr("qualifier", at.qualifier.clone());
        }
        if let Some(member) = &at.member {
            builder = builder.attr("member", member.clone());
        }
        builder.emit();
        emitted += 1;
    }

    for coremod in &m.coremods {
        ctx.store
            .fact("metadata-scanner", kind::COREMOD)
            .subject(m.id.clone())
            .attr("name", coremod.clone())
            .attr("loader", m.loader.as_str())
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        emitted += 1;
    }

    if ctx.settings.metadata.level != MetadataLevel::Basic {
        // Curated cross-mod relationships not derivable from any manifest
        // (Sodium ⊥ OptiFine, Iris → Sodium, …).
        for rel in crate::knowledge::curated_relationships(&m.id) {
            ctx.store
                .fact("metadata-scanner", kind::MOD_RELATIONSHIP)
                .subject(m.id.clone())
                .attr("related", rel.related)
                .attr("type", rel.kind)
                .attr("reason", rel.reason)
                .source(SourceRef::inside(file, m.manifest_name))
                .confidence(rel.confidence)
                .emit();
            emitted += 1;
        }
        for (capability, reason, confidence) in infer_capabilities(m) {
            ctx.store
                .fact("metadata-scanner", kind::MOD_CAPABILITY)
                .subject(m.id.clone())
                .attr("capability", capability)
                .attr("reason", reason)
                .source(SourceRef::inside(file, m.manifest_name))
                .confidence(confidence)
                .emit();
            emitted += 1;
        }
    }

    emitted
}

/// Collect candidate jars from the mods dir and a sibling `plugins/` dir.
fn gather_jars(target: &Target, scan: &intermed_doctor_core::ScanSettings) -> Vec<PathBuf> {
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
        if let Ok(mut jars) = list_jar_archives(&d, scan) {
            out.append(&mut jars);
        }
    }
    out.sort();
    out.dedup();
    out
}

// ── Parsed model ───────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
struct CachedDep {
    id: String,
    range: String,
    mandatory: bool,
    relation: String,
    #[serde(default)]
    feature: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CachedArtifact {
    id: String,
    version: String,
    loader: String,
    side: Option<String>,
    deps: Vec<CachedDep>,
    provides: Vec<String>,
    is_plugin: bool,
    manifest_name: String,
    api_version: Option<String>,
    load_order: Option<String>,
    #[serde(default)]
    bundled: Vec<(String, String)>,
    #[serde(default)]
    entrypoints: Vec<Entrypoint>,
    #[serde(default)]
    access_transforms: Vec<AccessTransform>,
    #[serde(default)]
    coremods: Vec<String>,
    #[serde(default)]
    mixin_configs: Vec<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    authors: Vec<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    update_json: Option<String>,
    #[serde(default)]
    data_signals: DataSignals,
    #[serde(default)]
    bytecode: BytecodeSignals,
    #[serde(default)]
    secondary: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
enum CachedJarOutcome {
    Parsed(Vec<CachedArtifact>),
    NoManifest,
    Error(String),
}

fn scan_jar_cached(path: &Path, metadata_level: MetadataLevel) -> CachedJarOutcome {
    match parse_jar(path, metadata_level) {
        Ok(artifacts) if artifacts.is_empty() => CachedJarOutcome::NoManifest,
        Ok(artifacts) => {
            CachedJarOutcome::Parsed(artifacts.iter().map(artifact_to_cached).collect())
        }
        Err(e) => CachedJarOutcome::Error(e.as_str().to_string()),
    }
}

fn artifact_to_cached(m: &Artifact) -> CachedArtifact {
    CachedArtifact {
        id: m.id.clone(),
        version: m.version.clone(),
        loader: m.loader.as_str().to_string(),
        side: m.side.map(str::to_string),
        deps: m
            .deps
            .iter()
            .map(|d| CachedDep {
                id: d.id.clone(),
                range: d.range.clone(),
                mandatory: d.mandatory,
                relation: d.relation.to_string(),
                feature: d.feature.clone(),
            })
            .collect(),
        mixin_configs: m.mixin_configs.clone(),
        provides: m.provides.clone(),
        is_plugin: m.is_plugin,
        manifest_name: m.manifest_name.to_string(),
        api_version: m.api_version.clone(),
        load_order: m.load_order.map(str::to_string),
        bundled: m.bundled.clone(),
        entrypoints: m.entrypoints.clone(),
        access_transforms: m.access_transforms.clone(),
        coremods: m.coremods.clone(),
        name: m.name.clone(),
        description: m.description.clone(),
        authors: m.authors.clone(),
        license: m.license.clone(),
        icon: m.icon.clone(),
        update_json: m.update_json.clone(),
        data_signals: m.data_signals,
        bytecode: m.bytecode.clone(),
        secondary: m.secondary.clone(),
    }
}

fn cached_to_artifact(c: CachedArtifact) -> Artifact {
    Artifact {
        id: c.id,
        version: c.version,
        loader: Loader::parse(&c.loader).unwrap_or(Loader::Vanilla),
        side: c.side.as_deref().and_then(side_static),
        deps: c
            .deps
            .into_iter()
            .map(|d| Dep {
                id: d.id,
                range: d.range,
                mandatory: d.mandatory,
                relation: relation_static(&d.relation),
                feature: d.feature,
            })
            .collect(),
        mixin_configs: c.mixin_configs,
        provides: c.provides,
        is_plugin: c.is_plugin,
        manifest_name: manifest_static(&c.manifest_name),
        api_version: c.api_version,
        load_order: c.load_order.as_deref().and_then(load_order_static),
        bundled: c.bundled,
        entrypoints: c.entrypoints,
        access_widener_files: Vec::new(),
        access_transforms: c.access_transforms,
        coremods: c.coremods,
        name: c.name,
        description: c.description,
        authors: c.authors,
        license: c.license,
        icon: c.icon,
        update_json: c.update_json,
        data_signals: c.data_signals,
        bytecode: c.bytecode,
        secondary: c.secondary,
    }
}

fn relation_static(s: &str) -> &'static str {
    match s {
        "depends" => "depends",
        "breaks" => "breaks",
        "suggests" => "suggests",
        "recommends" => "recommends",
        "discouraged" => "discouraged",
        "loadbefore" => "loadbefore",
        "loadafter" => "loadafter",
        _ => "depends",
    }
}

/// Map a Forge / NeoForge `[[dependencies]]` table row to Layer-C semantics.
///
/// NeoForge documents `type` (`required`, `optional`, `incompatible`, `discouraged`);
/// legacy Forge rows omit it and rely on the `mandatory` boolean instead.
/// Optional rows stay non-mandatory so Layer C does not emit false missing-deps;
/// incompatible rows become `breaks` so a present mod triggers conflict, not absence.
/// `ordering` (`BEFORE` / `AFTER`) maps to `loadbefore` / `loadafter` constraints.
fn forge_dependency_semantics(entry: &toml::Value) -> (bool, &'static str) {
    if let Some(ordering) = entry.get("ordering").and_then(|x| x.as_str()) {
        if ordering.eq_ignore_ascii_case("BEFORE") {
            return (true, "loadbefore");
        }
        if ordering.eq_ignore_ascii_case("AFTER") {
            return (true, "loadafter");
        }
    }

    if let Some(type_name) = entry.get("type").and_then(|x| x.as_str()) {
        if type_name.eq_ignore_ascii_case("required") {
            return (true, "depends");
        }
        if type_name.eq_ignore_ascii_case("optional") {
            return (false, "recommends");
        }
        if type_name.eq_ignore_ascii_case("incompatible") {
            return (false, "breaks");
        }
        if type_name.eq_ignore_ascii_case("discouraged") {
            return (false, "discouraged");
        }
        // Jar-in-Jar siblings (`embedded`) are satisfied by nested jars, not the pack.
        if type_name.eq_ignore_ascii_case("embedded") {
            return (false, "depends");
        }
    }

    let mandatory = entry
        .get("mandatory")
        .and_then(|x| x.as_bool())
        .unwrap_or(true);
    let relation = if mandatory { "depends" } else { "suggests" };
    (mandatory, relation)
}

/// Parse one `[[dependencies.<mod>]]` row into a [`Dep`].
fn parse_forge_dep_entry(entry: &toml::Value) -> Dep {
    let dep_id = entry
        .get("modId")
        .and_then(|x| x.as_str())
        .unwrap_or("?")
        .to_string();
    let range = entry
        .get("versionRange")
        .and_then(|x| x.as_str())
        .unwrap_or("*")
        .to_string();
    let feature = entry
        .get("feature")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let (mut mandatory, relation) = forge_dependency_semantics(entry);
    // Feature-gated deps are optional until the feature is known enabled.
    if feature.is_some() {
        mandatory = false;
    }
    Dep {
        id: dep_id,
        range,
        mandatory,
        relation,
        feature,
    }
}

/// Collect dependency rows declared for `mod_id` in a parsed `mods.toml` tree.
fn collect_forge_mod_dependencies(v: &toml::Value, mod_id: &str) -> Vec<Dep> {
    let Some(deps_root) = v.get("dependencies") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(table) = deps_root.as_table() {
        if let Some(arr) = table.get(mod_id).and_then(|x| x.as_array()) {
            for entry in arr {
                out.push(parse_forge_dep_entry(entry));
            }
        }
    }
    out
}

fn load_order_static(s: &str) -> Option<&'static str> {
    match s {
        "startup" | "STARTUP" => Some("startup"),
        "postworld" | "POSTWORLD" => Some("postworld"),
        _ => None,
    }
}

fn side_static(s: &str) -> Option<&'static str> {
    match s {
        "client" => Some("client"),
        "server" => Some("server"),
        "both" => Some("both"),
        _ => None,
    }
}

fn manifest_static(s: &str) -> &'static str {
    match s {
        "fabric.mod.json" => "fabric.mod.json",
        "quilt.mod.json" => "quilt.mod.json",
        "META-INF/mods.toml" => "META-INF/mods.toml",
        "META-INF/neoforge.mods.toml" => "META-INF/neoforge.mods.toml",
        "plugin.yml" => "plugin.yml",
        "paper-plugin.yml" => "paper-plugin.yml",
        "@Mod" => "@Mod",
        _ => "unknown",
    }
}

pub(crate) struct Dep {
    id: String,
    range: String,
    mandatory: bool,
    relation: &'static str,
    /// NeoForge `feature = "modid:feature"` — dependency applies only when enabled.
    feature: Option<String>,
}

/// A loader entrypoint declared by a mod manifest: a class the loader will load
/// at a given lifecycle phase. The phantom `entrypoint` predicate, finally wired.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Entrypoint {
    /// Lifecycle phase / slot (`main`, `client`, `server`, `init`, `client_init`,
    /// `mod` for the Forge `@Mod` class, …).
    pub(crate) phase: String,
    /// Fully-qualified entry class.
    pub(crate) class: String,
    #[serde(default)]
    pub(crate) entrypoint_type: String,
    #[serde(default)]
    pub(crate) events: Vec<String>,
    #[serde(default)]
    pub(crate) priority: i64,
}

/// A parsed access-changing directive (Forge AT / Fabric-Quilt AW), in owned form
/// for caching and emission. See [`crate::access`].
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct AccessTransform {
    pub(crate) mechanism: String,
    pub(crate) access: String,
    pub(crate) qualifier: String,
    pub(crate) target_class: String,
    pub(crate) member: Option<String>,
}

pub(crate) struct Artifact {
    pub(crate) id: String,
    pub(crate) version: String,
    pub(crate) loader: Loader,
    pub(crate) side: Option<&'static str>,
    pub(crate) deps: Vec<Dep>,
    pub(crate) provides: Vec<String>,
    pub(crate) is_plugin: bool,
    pub(crate) manifest_name: &'static str,
    pub(crate) api_version: Option<String>,
    pub(crate) load_order: Option<&'static str>,
    /// Bundled (Jar-in-Jar) modules: `(id, version)` discovered under
    /// `META-INF/jars/` (Fabric/Quilt) or `META-INF/jarjar/` (Forge/NeoForge),
    /// recursively. These are real providers — a mod requiring one of them is
    /// satisfied without it appearing as a separate top-level jar.
    pub(crate) bundled: Vec<(String, String)>,
    /// Loader entrypoints declared in the manifest.
    pub(crate) entrypoints: Vec<Entrypoint>,
    /// Access widener file(s) named by the manifest (Fabric `accessWidener` /
    /// Quilt `access_widener`, which may list several). Transient: consumed by
    /// enrichment to read the files, not emitted or cached on its own.
    pub(crate) access_widener_files: Vec<String>,
    /// Parsed Access Transformer / Access Widener directives.
    pub(crate) access_transforms: Vec<AccessTransform>,
    /// Forge coremod script names declared in `META-INF/coremods.json`.
    pub(crate) coremods: Vec<String>,
    /// Mixin config paths from `mods.toml` `[[mixins]]` (Layer F also discovers these).
    pub(crate) mixin_configs: Vec<String>,
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) authors: Vec<String>,
    pub(crate) license: Option<String>,
    pub(crate) icon: Option<String>,
    pub(crate) update_json: Option<String>,
    /// Data-pack content signals scanned from the jar (worldgen / dimension /
    /// content), the honest evidence for capability inference.
    pub(crate) data_signals: DataSignals,
    /// Whole-jar bytecode intelligence (Full level only; empty otherwise).
    pub(crate) bytecode: BytecodeSignals,
    /// A second role this jar advertises beyond its primary identity, as
    /// `"loader:id"` (e.g. a Bukkit plugin that also ships `fabric.mod.json`).
    /// Emitted as an informational `secondary_identity` fact, never as a competing
    /// `mod`/`plugin` fact (that would reintroduce loader-mismatch false positives).
    pub(crate) secondary: Option<String>,
}

/// Whole-jar bytecode intelligence (Full level): events subscribed/registered
/// across *all* of the mod's classes, and capability tokens detected from
/// distinctive framework class references in their constant pools. Honest
/// structural evidence — a symbolic reference to `DeferredRegister` means the code
/// uses it — aggregated over the whole mod, not just its entrypoint class.
#[derive(Default, Clone, Serialize, Deserialize)]
pub(crate) struct BytecodeSignals {
    /// Event simple-names the mod subscribes to / registers anywhere in the jar.
    pub(crate) events: Vec<String>,
    /// Capability tokens (e.g. `registers_content`, `custom_networking`).
    pub(crate) capabilities: Vec<String>,
}

/// Data-pack content a jar ships, used as real evidence for [`infer_capabilities`]
/// instead of guessing from the mod id.
#[derive(Default, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct DataSignals {
    /// `data/<ns>/worldgen/…` present.
    pub(crate) worldgen: bool,
    /// `data/<ns>/dimension[_type]/…` present.
    pub(crate) dimension: bool,
    /// Content data (recipes / loot tables / tags) present → a content mod.
    pub(crate) content: bool,
}

/// Parse error reduced to a short, fact-friendly string.
struct ParseErr(String);
impl ParseErr {
    fn as_str(&self) -> &str {
        &self.0
    }
}

/// How deep to recurse into Jar-in-Jar archives. Real packs nest 1–2 levels
/// (Create → Registrate → its libs); the bound stops pathological archives.
const MAX_NEST_DEPTH: u8 = 4;

fn read_entry<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, name: &str) -> Option<String> {
    let mut f = archive.by_name(name).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

fn read_entry_bytes<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, name: &str) -> Option<Vec<u8>> {
    let mut f = archive.by_name(name).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Dispatch on whichever manifest an archive carries. Generic over the reader so
/// it works on both on-disk jars and in-memory nested jars.
fn parse_archive<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Result<Vec<Artifact>, ParseErr> {
    // Universal server plugins (e.g. ViaVersion) may bundle a mod manifest for
    // proxy-side hooks; the Bukkit/Paper plugin descriptor stays the *primary*
    // identity (a mod fact for the bundled manifest would re-introduce the
    // loader-mismatch false positives the ordering deliberately prevents). The
    // co-present mod manifest is recorded as a non-rule `secondary` identity so
    // the second role is not lost.
    if let Some(text) = read_entry(archive, "paper-plugin.yml") {
        let mut a = parse_plugin_yml(&text, Loader::Paper, "paper-plugin.yml")?;
        a.secondary = detect_secondary_mod(archive);
        return Ok(vec![a]);
    }
    if let Some(text) = read_entry(archive, "plugin.yml") {
        let mut a = parse_plugin_yml(&text, Loader::Bukkit, "plugin.yml")?;
        a.secondary = detect_secondary_mod(archive);
        return Ok(vec![a]);
    }
    if let Some(text) = read_entry(archive, "fabric.mod.json") {
        return parse_fabric(&text).map(|a| vec![a]);
    }
    if let Some(text) = read_entry(archive, "quilt.mod.json") {
        return parse_quilt(&text).map(|a| vec![a]);
    }
    if let Some(text) = read_entry(archive, "META-INF/neoforge.mods.toml") {
        return parse_forge_toml(&text, Loader::NeoForge);
    }
    if let Some(text) = read_entry(archive, "META-INF/mods.toml") {
        return parse_forge_toml(&text, Loader::Forge);
    }
    Ok(Vec::new())
}

/// When a plugin jar also ships a mod manifest, return its `"loader:id"` so the
/// dual role surfaces as an informational `secondary_identity` fact.
fn detect_secondary_mod<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Option<String> {
    if let Some(text) = read_entry(archive, "fabric.mod.json") {
        if let Ok(a) = parse_fabric(&text) {
            return Some(format!("fabric:{}", a.id));
        }
    }
    if let Some(text) = read_entry(archive, "quilt.mod.json") {
        if let Ok(a) = parse_quilt(&text) {
            return Some(format!("quilt:{}", a.id));
        }
    }
    if read_entry(archive, "META-INF/neoforge.mods.toml").is_some() {
        return Some("neoforge:<mods.toml>".to_string());
    }
    if read_entry(archive, "META-INF/mods.toml").is_some() {
        return Some("forge:<mods.toml>".to_string());
    }
    None
}

fn is_nested_jar(name: &str) -> bool {
    (name.starts_with("META-INF/jars/") || name.starts_with("META-INF/jarjar/"))
        && name.ends_with(".jar")
}

/// Recursively collect `(id, version)` for every bundled (Jar-in-Jar) module, so
/// dependencies satisfied by a nested library are not reported missing.
fn collect_bundled<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    depth: u8,
    out: &mut Vec<(String, String)>,
) {
    if depth == 0 {
        return;
    }
    let names: Vec<String> = (0..archive.len())
        .filter_map(|i| {
            let name = archive.by_index(i).ok()?.name().to_string();
            is_nested_jar(&name).then_some(name)
        })
        .collect();
    for name in names {
        let Some(bytes) = read_entry_bytes(archive, &name) else {
            continue;
        };
        let Ok(mut inner) = zip::ZipArchive::new(Cursor::new(bytes)) else {
            continue;
        };
        if let Ok(arts) = parse_archive(&mut inner) {
            for a in arts {
                if !a.id.is_empty() {
                    out.push((a.id, a.version));
                }
            }
        }
        collect_bundled(&mut inner, depth - 1, out);
    }
}

fn parse_jar(path: &Path, metadata_level: MetadataLevel) -> Result<Vec<Artifact>, ParseErr> {
    let file = std::fs::File::open(path).map_err(|e| ParseErr(format!("open: {e}")))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| ParseErr(format!("zip: {e}")))?;

    let mut artifacts = parse_archive(&mut archive)?;
    if artifacts.is_empty() {
        artifacts = forge_annotation::discover_mods_from_jar(&mut archive);
    } else if artifacts.iter().any(|a| {
        matches!(a.loader, Loader::Forge | Loader::NeoForge) && a.entrypoints.is_empty()
    }) {
        // A `mods.toml` names the mod but not its entry class; scan `@Mod` classes
        // so Forge/NeoForge mods still get an `entrypoint` (phase = mod).
        let entrypoints = forge_annotation::discover_mod_entrypoints(&mut archive);
        for (mod_id, class) in entrypoints {
            if let Some(art) = artifacts.iter_mut().find(|a| a.id == mod_id) {
                if art.entrypoints.is_empty() {
                    art.entrypoints.push(Entrypoint {
                        phase: "mod".to_string(),
                        class,
                        entrypoint_type: "main".to_string(),
                        events: Vec::new(),
                        priority: 0,
                    });
                }
            }
        }
    }

    // Attach bundled Jar-in-Jar providers to the primary artifact.
    let mut bundled = Vec::new();
    collect_bundled(&mut archive, MAX_NEST_DEPTH, &mut bundled);
    if !bundled.is_empty() {
        bundled.sort();
        bundled.dedup();
        let own: std::collections::HashSet<&str> =
            artifacts.iter().map(|a| a.id.as_str()).collect();
        bundled.retain(|(id, _)| !own.contains(id.as_str()));
        if let Some(primary) = artifacts.first_mut() {
            primary.bundled = bundled;
        }
    }

    enrich_access_and_coremods(&mut archive, &mut artifacts);
    if metadata_level == MetadataLevel::Full {
        enrich_entrypoint_intelligence(&mut archive, &mut artifacts);
    }

    if let Some(text) = read_entry(&mut archive, "META-INF/neoforge.mods.toml")
        .or_else(|| read_entry(&mut archive, "META-INF/mods.toml"))
    {
        if let Ok(v) = text.parse::<toml::Value>() {
            enrich_forge_toml_extras(&mut archive, &mut artifacts, &v);
        }
    }

    // Data-pack content signals (shared by all artifacts in the jar) — real
    // evidence for worldgen / dimension / content capability inference.
    let signals = collect_data_signals(&mut archive);
    for artifact in &mut artifacts {
        artifact.data_signals = signals;
    }

    Ok(artifacts)
}

/// Scan the jar's data-pack tree for content signals. `data/<ns>/worldgen/…`,
/// `data/<ns>/dimension[_type]/…`, and content folders (recipes / loot tables /
/// tags) are the honest evidence that a mod adds worldgen, dimensions, or content
/// — far better than guessing from the mod id.
fn collect_data_signals<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> DataSignals {
    let mut s = DataSignals::default();
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        let name = entry.name();
        let Some(rest) = name.strip_prefix("data/") else {
            continue;
        };
        // rest = "<namespace>/<category>/…"
        let Some(category_path) = rest.split_once('/').map(|(_, p)| p) else {
            continue;
        };
        if category_path.starts_with("worldgen/") {
            s.worldgen = true;
        }
        if category_path.starts_with("dimension/") || category_path.starts_with("dimension_type/")
        {
            s.dimension = true;
        }
        if category_path.starts_with("recipes/")
            || category_path.starts_with("recipe/")
            || category_path.starts_with("loot_tables/")
            || category_path.starts_with("loot_table/")
            || category_path.starts_with("tags/")
        {
            s.content = true;
        }
        if s.worldgen && s.dimension && s.content {
            break;
        }
    }
    s
}

/// Read and parse loader access mechanisms (Fabric/Quilt Access Wideners named by
/// the manifest, Forge/NeoForge Access Transformer at its fixed path) and Forge
/// coremod declarations, attaching the results to the jar's artifact(s).
fn enrich_access_and_coremods<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    artifacts: &mut [Artifact],
) {
    // Access wideners are listed per-artifact by the Fabric/Quilt manifest.
    for art in artifacts.iter_mut() {
        let files = std::mem::take(&mut art.access_widener_files);
        for file in files {
            if let Some(text) = read_entry(archive, &file) {
                for d in access::parse_access_widener(&text) {
                    art.access_transforms.push(directive_to_transform(&d));
                }
            }
        }
    }

    // Forge / NeoForge Access Transformer + coremods live at fixed paths and apply
    // to the jar as a whole — attach to the primary artifact.
    let at_text = read_entry(archive, "META-INF/accesstransformer.cfg");
    let coremods_text = read_entry(archive, "META-INF/coremods.json");
    if at_text.is_none() && coremods_text.is_none() {
        return;
    }
    let Some(primary) = artifacts.first_mut() else {
        return;
    };
    if let Some(text) = at_text {
        for d in access::parse_access_transformer(&text) {
            primary.access_transforms.push(directive_to_transform(&d));
        }
    }
    if let Some(text) = coremods_text {
        primary.coremods.extend(parse_coremods(&text));
    }
}

/// Inspect only declared entrypoint classes. This keeps full metadata analysis
/// bounded while still identifying loader registration and common lifecycle
/// events from class-file symbols cached with the jar result.
fn enrich_entrypoint_intelligence<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    artifacts: &mut [Artifact],
) {
    // Per-entrypoint detail: precise type / events / priority for each declared
    // entrypoint class (drives `entrypoint_detail`).
    for artifact in artifacts.iter_mut() {
        for entrypoint in &mut artifact.entrypoints {
            let class_name = entrypoint.class.split("::").next().unwrap_or(&entrypoint.class);
            let path = format!("{}.class", class_name.replace('.', "/"));
            let Some(bytes) = read_entry_bytes(archive, &path) else {
                continue;
            };
            let Some(analysis) = crate::entrypoint_analysis::analyze_entrypoint_class(&bytes) else {
                continue;
            };
            if let Some(ty) = analysis.entrypoint_type {
                entrypoint.entrypoint_type = ty.to_string();
            }
            for event in analysis.events {
                if !entrypoint.events.contains(&event) {
                    entrypoint.events.push(event);
                }
            }
            if let Some(priority) = analysis.priority {
                entrypoint.priority = priority;
            }
        }
    }

    // Whole-jar intelligence: events subscribed/registered anywhere in the mod, and
    // capability tokens evidenced by framework references across all its classes.
    let entry_classes: std::collections::BTreeSet<String> = artifacts
        .iter()
        .flat_map(|a| a.entrypoints.iter())
        .map(|e| e.class.split("::").next().unwrap_or(&e.class).to_string())
        .collect();
    let intel = crate::entrypoint_analysis::analyze_jar(archive, &entry_classes);
    for artifact in artifacts.iter_mut() {
        artifact.bytecode.events = intel.events.clone();
        artifact.bytecode.capabilities = intel.capabilities.clone();
    }
}


fn directive_to_transform(d: &access::AccessDirective) -> AccessTransform {
    AccessTransform {
        mechanism: d.mechanism.to_string(),
        access: d.access.clone(),
        qualifier: d.qualifier.clone(),
        target_class: d.target_class.clone(),
        member: d.member.clone(),
    }
}

/// Forge `META-INF/coremods.json` maps coremod name → JS script path; return the
/// declared coremod names.
fn parse_coremods(text: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .as_ref()
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
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
    push_fabric_dep_map(&mut deps, v.get("depends"), "depends", true);
    push_fabric_dep_map(&mut deps, v.get("breaks"), "breaks", true);
    push_fabric_dep_map(&mut deps, v.get("suggests"), "suggests", false);
    push_fabric_dep_map(&mut deps, v.get("recommends"), "recommends", false);
    let provides = v
        .get("provides")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let entrypoints = parse_fabric_entrypoints(v.get("entrypoints"));
    let access_widener_files = v
        .get("accessWidener")
        .and_then(|x| x.as_str())
        .map(|s| vec![s.to_string()])
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
        api_version: None,
        load_order: None,
        bundled: Vec::new(),
        entrypoints,
        access_widener_files,
        access_transforms: Vec::new(),
        coremods: Vec::new(),
        mixin_configs: json_paths(v.get("mixins")),
        name: json_string(v.get("name")),
        description: json_string(v.get("description")),
        authors: json_people(v.get("authors")),
        license: json_string_or_array(v.get("license")),
        icon: json_icon(v.get("icon")),
        update_json: v
            .get("custom")
            .and_then(|x| x.get("modmenu"))
            .and_then(|x| x.get("update_checker"))
            .and_then(|x| x.get("update_url"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        data_signals: DataSignals::default(),
        bytecode: BytecodeSignals::default(),
        secondary: None,
    })
}

/// Fabric `entrypoints`: `{ "main": ["pkg.Mod"], "client": [{"value": "...",
/// "adapter": "kotlin"}] }`. Each value is a class string or an object with a
/// `value` field.
fn parse_fabric_entrypoints(value: Option<&serde_json::Value>) -> Vec<Entrypoint> {
    let mut out = Vec::new();
    let Some(map) = value.and_then(|x| x.as_object()) else {
        return out;
    };
    for (phase, entries) in map {
        let Some(arr) = entries.as_array() else {
            continue;
        };
        for entry in arr {
            if let Some(class) = entrypoint_class(entry) {
                out.push(Entrypoint {
                    phase: phase.clone(),
                    entrypoint_type: classify_entrypoint(phase, &class).to_string(),
                    class,
                    events: Vec::new(),
                    priority: 0,
                });
            }
        }
    }
    out
}

/// Pull the entry class from a bare string or a `{ "value": "..." }` object
/// (Fabric/Quilt both allow either form).
fn entrypoint_class(entry: &serde_json::Value) -> Option<String> {
    match entry {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o.get("value").and_then(|x| x.as_str()).map(str::to_string),
        _ => None,
    }
}

fn push_fabric_dep_map(
    deps: &mut Vec<Dep>,
    value: Option<&serde_json::Value>,
    relation: &'static str,
    mandatory: bool,
) {
    let Some(map) = value.and_then(|x| x.as_object()) else {
        return;
    };
    for (dep, range) in map {
        deps.push(Dep {
            id: dep.clone(),
            range: json_range(range),
            mandatory,
            relation,
            feature: None,
        });
    }
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
    let side = quilt_environment(v.get("environment").or_else(|| ql.get("environment")));
    let mut deps = Vec::new();
    push_quilt_dep_array(&mut deps, ql.get("depends"), "depends", true);
    push_quilt_dep_array(&mut deps, ql.get("breaks"), "breaks", true);
    push_quilt_dep_array(&mut deps, ql.get("suggests"), "suggests", false);
    push_quilt_dep_array(&mut deps, ql.get("recommends"), "recommends", false);
    let provides = ql
        .get("provides")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(quilt_provides_id).collect())
        .unwrap_or_default();
    let entrypoints = parse_quilt_entrypoints(ql.get("entrypoints"));
    let access_widener_files = quilt_string_or_array(ql.get("access_widener"));
    Ok(Artifact {
        id,
        version,
        loader: Loader::Quilt,
        side,
        deps,
        provides,
        is_plugin: false,
        manifest_name: "quilt.mod.json",
        api_version: None,
        load_order: None,
        bundled: Vec::new(),
        entrypoints,
        access_widener_files,
        access_transforms: Vec::new(),
        coremods: Vec::new(),
        mixin_configs: json_paths(ql.get("mixin").or_else(|| v.get("mixin"))),
        name: json_string(ql.get("metadata").and_then(|x| x.get("name"))),
        description: json_string(ql.get("metadata").and_then(|x| x.get("description"))),
        authors: json_people(ql.get("metadata").and_then(|x| x.get("contributors"))),
        license: json_string_or_array(ql.get("metadata").and_then(|x| x.get("license"))),
        icon: json_icon(ql.get("metadata").and_then(|x| x.get("icon"))),
        update_json: json_string(ql.get("metadata").and_then(|x| x.get("update_json"))),
        data_signals: DataSignals::default(),
        bytecode: BytecodeSignals::default(),
        secondary: None,
    })
}

/// Quilt `quilt_loader.entrypoints`: a map `phase -> (string | object | array of
/// either)`. Mirrors Fabric but the per-phase value may also be a single scalar.
fn parse_quilt_entrypoints(value: Option<&serde_json::Value>) -> Vec<Entrypoint> {
    let mut out = Vec::new();
    let Some(map) = value.and_then(|x| x.as_object()) else {
        return out;
    };
    for (phase, entries) in map {
        match entries {
            serde_json::Value::Array(arr) => {
                for entry in arr {
                    if let Some(class) = entrypoint_class(entry) {
                        out.push(Entrypoint {
                            entrypoint_type: classify_entrypoint(phase, &class).to_string(),
                            phase: phase.clone(),
                            class,
                            events: Vec::new(),
                            priority: 0,
                        });
                    }
                }
            }
            other => {
                if let Some(class) = entrypoint_class(other) {
                    out.push(Entrypoint {
                        entrypoint_type: classify_entrypoint(phase, &class).to_string(),
                        phase: phase.clone(),
                        class,
                        events: Vec::new(),
                        priority: 0,
                    });
                }
            }
        }
    }
    out
}

/// Read a Quilt field that may be a single string or an array of strings.
fn quilt_string_or_array(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn quilt_environment(value: Option<&serde_json::Value>) -> Option<&'static str> {
    match value.and_then(|x| x.as_str()) {
        Some("client") => Some("client"),
        Some("server") => Some("server"),
        Some("*") => Some("both"),
        _ => None,
    }
}

fn push_quilt_dep_array(
    deps: &mut Vec<Dep>,
    value: Option<&serde_json::Value>,
    relation: &'static str,
    mandatory: bool,
) {
    let Some(arr) = value.and_then(|x| x.as_array()) else {
        return;
    };
    for d in arr {
        match d {
            serde_json::Value::String(s) => deps.push(Dep {
                id: s.clone(),
                range: "*".into(),
                mandatory,
                relation,
                feature: None,
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
                        mandatory,
                        relation,
                        feature: None,
                    });
                }
            }
            _ => {}
        }
    }
}

fn quilt_provides_id(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o.get("id").and_then(|x| x.as_str()).map(str::to_string),
        _ => None,
    }
}

fn parse_forge_toml(text: &str, loader: Loader) -> Result<Vec<Artifact>, ParseErr> {
    let v: toml::Value = text
        .parse()
        .map_err(|e| ParseErr(format!("mods.toml: {e}")))?;
    let mods = v
        .get("mods")
        .and_then(|m| m.as_array())
        .ok_or_else(|| ParseErr("mods.toml: no [[mods]]".into()))?;
    let manifest_name = if loader == Loader::NeoForge {
        "META-INF/neoforge.mods.toml"
    } else {
        "META-INF/mods.toml"
    };
    let mut out = Vec::new();
    for entry in mods {
        let id = entry
            .get("modId")
            .and_then(|x| x.as_str())
            .unwrap_or("?")
            .to_string();
        let version = entry
            .get("version")
            .and_then(|x| x.as_str())
            .unwrap_or("0")
            .to_string();
        let deps = collect_forge_mod_dependencies(&v, &id);
        let provides = entry
            .get("provides")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        // Forge mods.toml may declare dependency `side=CLIENT`, but that names the
        // dependency's environment — not the mod's own side.
        out.push(Artifact {
            id,
            version,
            loader,
            side: None,
            deps,
            provides,
            is_plugin: false,
            manifest_name,
            api_version: None,
            load_order: None,
            bundled: Vec::new(),
            entrypoints: Vec::new(),
            access_widener_files: Vec::new(),
            access_transforms: Vec::new(),
            coremods: Vec::new(),
            mixin_configs: Vec::new(),
            name: entry.get("displayName").and_then(|x| x.as_str()).map(str::to_string),
            description: entry.get("description").and_then(|x| x.as_str()).map(str::to_string),
            authors: entry
                .get("authors")
                .and_then(|x| x.as_str())
                .map(split_people)
                .unwrap_or_default(),
            license: v.get("license").and_then(|x| x.as_str()).map(str::to_string),
            icon: entry.get("logoFile").and_then(|x| x.as_str()).map(str::to_string),
            update_json: entry.get("updateJSONURL").and_then(|x| x.as_str()).map(str::to_string),
            data_signals: DataSignals::default(),
            bytecode: BytecodeSignals::default(),
            secondary: None,
        });
    }
    Ok(out)
}

/// Read `[[mixins]]` and `[[accessTransformers]]` tables from a parsed `mods.toml`.
fn enrich_forge_toml_extras<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    artifacts: &mut [Artifact],
    toml_root: &toml::Value,
) {
    if artifacts.is_empty() {
        return;
    }

    let default_owner = artifacts.first().map(|a| a.id.clone());
    if let Some(arr) = toml_root.get("mixins").and_then(|x| x.as_array()) {
        for entry in arr {
            let Some(config) = entry.get("config").and_then(|x| x.as_str()) else {
                continue;
            };
            let owner_id = entry
                .get("modId")
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .or_else(|| default_owner.clone());
            let Some(owner_id) = owner_id else {
                continue;
            };
            if let Some(art) = artifacts.iter_mut().find(|a| a.id == owner_id) {
                if !art.mixin_configs.iter().any(|c| c == config) {
                    art.mixin_configs.push(config.to_string());
                }
            }
        }
    }

    let at_entries: Vec<String> = toml_root
        .get("accessTransformers")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("file").and_then(|x| x.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    if at_entries.is_empty() {
        return;
    }
    let Some(primary) = artifacts.first_mut() else {
        return;
    };
    for file in at_entries {
        let Some(text) = read_entry(archive, &file) else {
            continue;
        };
        for d in access::parse_access_transformer(&text) {
            primary.access_transforms.push(directive_to_transform(&d));
        }
    }
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
    let api_version = yaml_scalar(v.get("api-version"));
    let load_order = v
        .get("load")
        .and_then(|x| x.as_str())
        .and_then(load_order_static);
    let mut deps = Vec::new();
    for (key, mandatory, relation) in [
        ("depend", true, "depends"),
        ("softdepend", false, "suggests"),
        ("loadbefore", true, "loadbefore"),
    ] {
        if let Some(arr) = v.get(key).and_then(|x| x.as_sequence()) {
            for d in arr {
                if let Some(s) = d.as_str() {
                    deps.push(Dep {
                        id: s.to_string(),
                        range: "*".into(),
                        mandatory,
                        relation,
                        feature: None,
                    });
                }
            }
        }
    }
    if let Some(paper_deps) = v.get("dependencies") {
        push_paper_plugin_deps(&mut deps, paper_deps);
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
        api_version,
        load_order,
        bundled: Vec::new(),
        entrypoints: yaml_scalar(v.get("main"))
            .map(|class| {
                vec![Entrypoint {
                    phase: "main".to_string(),
                    class,
                    entrypoint_type: "main".to_string(),
                    events: Vec::new(),
                    priority: 0,
                }]
            })
            .unwrap_or_default(),
        access_widener_files: Vec::new(),
        access_transforms: Vec::new(),
        coremods: Vec::new(),
        mixin_configs: Vec::new(),
        name: yaml_scalar(v.get("name")),
        description: yaml_scalar(v.get("description")),
        authors: yaml_people(v.get("authors").or_else(|| v.get("author"))),
        license: yaml_scalar(v.get("license")),
        icon: None,
        update_json: yaml_scalar(v.get("website")),
        data_signals: DataSignals::default(),
        bytecode: BytecodeSignals::default(),
        secondary: None,
    })
}

fn push_paper_plugin_deps(deps: &mut Vec<Dep>, root: &serde_yaml::Value) {
    let Some(server) = root.get("server").and_then(|x| x.as_mapping()) else {
        return;
    };
    for (key, mandatory, relation) in [
        ("required", true, "depends"),
        ("optional", false, "suggests"),
        ("join-classpath", true, "depends"),
    ] {
        if let Some(arr) = server.get(key).and_then(|x| x.as_sequence()) {
            for d in arr {
                if let Some(s) = d.as_str() {
                    deps.push(Dep {
                        id: s.to_string(),
                        range: "*".into(),
                        mandatory,
                        relation,
                        feature: None,
                    });
                }
            }
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

/// fabric/quilt dependency ranges may be a string or an array of strings.
/// Fabric uses space-separated AND (`>=0.11.6 <0.12.0`); arrays are OR.
fn json_range(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.trim().to_string(),
        serde_json::Value::Array(a) => {
            let parts: Vec<String> = a
                .iter()
                .filter_map(|e| e.as_str().map(|s| s.trim().to_string()))
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

fn json_string(v: Option<&serde_json::Value>) -> Option<String> {
    v.and_then(|x| x.as_str()).map(str::to_string)
}

fn json_string_or_array(v: Option<&serde_json::Value>) -> Option<String> {
    match v? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(values) => Some(
            values
                .iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        _ => None,
    }
}

fn json_icon(v: Option<&serde_json::Value>) -> Option<String> {
    match v? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) => map
            .iter()
            .max_by_key(|(key, _)| key.parse::<u32>().unwrap_or(0))
            .and_then(|(_, value)| value.as_str())
            .map(str::to_string),
        _ => None,
    }
}

fn json_people(v: Option<&serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::String(s)) => split_people(s),
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(|x| {
                x.as_str().map(str::to_string).or_else(|| {
                    x.get("name").and_then(|name| name.as_str()).map(str::to_string)
                })
            })
            .collect(),
        Some(serde_json::Value::Object(values)) => values.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

fn json_paths(v: Option<&serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(|x| {
                x.as_str().map(str::to_string).or_else(|| {
                    x.get("config").and_then(|path| path.as_str()).map(str::to_string)
                })
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn yaml_people(v: Option<&serde_yaml::Value>) -> Vec<String> {
    match v {
        Some(serde_yaml::Value::String(s)) => split_people(s),
        Some(serde_yaml::Value::Sequence(values)) => {
            values.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()
        }
        _ => Vec::new(),
    }
}

fn split_people(raw: &str) -> Vec<String> {
    raw.split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Best-effort normalisation of a mod version string to `major.minor.patch`.
///
/// Mod versions are wildly non-strict: `v1.2`, `1.20.1-0.5.0`, `mc1.20-1.2.3`,
/// `1.2.3.4`, `1.2.3+build.5`, `4.0.0-beta.2`. This extracts the leading numeric
/// core (stripping a `v`/`V` prefix, an `mc<version>-` game-version prefix, build
/// metadata after `+`, and a pre-release suffix after `-`), pads to three
/// components, truncates a 4th (`1.2.3.4` → `1.2.3`), and zeroes a non-numeric
/// component. Returns the trimmed original when no numeric core is found.
/// Best-effort `major.minor.patch` semver **candidate** for display/sort.
///
/// This is a lossy convenience only — `version_raw` is the authoritative value
/// (always emitted alongside). The transform is intentionally simple and
/// transparent: trim a leading `v`/`mc`, drop build (`+…`) and pre-release
/// (`-…`) suffixes, then take the first three dot-separated numeric components
/// (non-numeric components become 0). It does **not** try to guess which side of
/// a `gameversion-modversion` string is the mod version; when the raw looks like
/// that, [`version_ambiguous`] flags it so consumers can lower confidence rather
/// than trust the normalized form. Strings with no numeric lead are returned
/// untouched (e.g. `alpha`).
fn normalize_version(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    let trimmed = trimmed.strip_prefix("mc").unwrap_or(trimmed);
    // Build metadata (`+…`) and pre-release / qualifier (`-…`) are not part of
    // the core triple. NOTE: this keeps the *first* `-` group, so for an
    // ambiguous `1.20.1-0.5.0` it yields `1.20.1` — see `version_ambiguous`.
    let core = trimmed
        .split('+')
        .next()
        .unwrap_or(trimmed)
        .split('-')
        .next()
        .unwrap_or(trimmed)
        .trim();
    let num = |s: &str| -> Option<u64> { s.parse::<u64>().ok() };
    let parts: Vec<u64> = core
        .split('.')
        .map(|p| num(p).unwrap_or(0))
        .collect();
    // Require at least one genuinely-numeric component, else keep the original.
    if core.split('.').next().and_then(num).is_none() {
        return trimmed.split('+').next().unwrap_or(trimmed).trim().to_string();
    }
    let major = parts.first().copied().unwrap_or(0);
    let minor = parts.get(1).copied().unwrap_or(0);
    let patch = parts.get(2).copied().unwrap_or(0);
    format!("{major}.{minor}.{patch}")
}

/// True when the raw version looks like `gameversion-modversion` (or `mc…-…`),
/// so the normalized triple may have picked the Minecraft version rather than
/// the mod's own version. Consumers (SBOM/analytics/history) should treat
/// `version_normalized` as low-confidence when this is set and prefer
/// `version_raw`.
fn version_ambiguous(raw: &str) -> bool {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    let had_mc = trimmed.starts_with("mc");
    let trimmed = trimmed.strip_prefix("mc").unwrap_or(trimmed);
    // Strip build metadata first; pre-release `-` groups are what we inspect.
    let no_build = trimmed.split('+').next().unwrap_or(trimmed);
    let groups: Vec<&str> = no_build.split('-').collect();
    if groups.len() < 2 {
        return false;
    }
    let starts_numeric = |s: &str| s.trim().chars().next().is_some_and(|c| c.is_ascii_digit());
    // Ambiguous when the first group is a dotted version and a later group also
    // begins numerically (a second version-looking token), or when an `mc`
    // game-version prefix preceded a second numeric group.
    let first_dotted = groups[0].contains('.') && starts_numeric(groups[0]);
    let later_numeric = groups[1..].iter().any(|g| starts_numeric(g));
    (first_dotted || had_mc) && later_numeric
}

fn classify_entrypoint(phase: &str, class: &str) -> &'static str {
    let lower = format!("{phase} {class}").to_ascii_lowercase();
    if lower.contains("client") || lower.contains("render") {
        "client"
    } else if lower.contains("server") {
        "server"
    } else if lower.contains("config") {
        "config"
    } else if lower.contains("keybind") || lower.contains("key_binding") {
        "key_binding"
    } else if lower.contains("event") || lower.contains("subscriber") {
        "event_bus_subscriber"
    } else {
        "main"
    }
}

fn metadata_level_name(level: MetadataLevel) -> &'static str {
    match level {
        MetadataLevel::Basic => "basic",
        MetadataLevel::Enriched => "enriched",
        MetadataLevel::Full => "full",
    }
}

/// Infer high-level mod capabilities from **structural evidence** — data-pack
/// content the jar ships, the events its entrypoints actually subscribe to (parsed
/// from bytecode), the classes its access transforms touch, and its declared mixin
/// footprint. No mod-id guessing: a capability is only claimed when a concrete,
/// inspectable signal supports it, and confidence tracks signal strength.
fn infer_capabilities(m: &Artifact) -> Vec<(&'static str, &'static str, f32)> {
    let mut out: Vec<(&'static str, &'static str, f32)> = Vec::new();
    let mut add = |name, reason, confidence| {
        if !out.iter().any(|(existing, _, _)| *existing == name) {
            out.push((name, reason, confidence));
        }
    };

    let events: Vec<String> = m
        .entrypoints
        .iter()
        .flat_map(|e| e.events.iter())
        .chain(m.bytecode.events.iter())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let event_has = |needle: &str| events.iter().any(|e| e.contains(needle));
    let at_targets: Vec<String> = m
        .access_transforms
        .iter()
        .map(|t| t.target_class.to_ascii_lowercase())
        .collect();
    let at_touches = |pkg: &str| at_targets.iter().any(|t| t.contains(pkg));
    // Author-declared entrypoint class paths (real manifest structure, *not* the
    // mod id) are a legitimate weak signal — `client` entrypoint at `*.render.*`.
    let entry_class_hint = |needle: &str| {
        m.entrypoints
            .iter()
            .any(|e| e.class.to_ascii_lowercase().contains(needle))
    };

    // ── Worldgen / dimension: data-pack content is the honest signal ──
    if m.data_signals.worldgen {
        add("has_worldgen", "ships data/<ns>/worldgen content", 0.9);
    } else if entry_class_hint("worldgen") || entry_class_hint("dimension") {
        add("has_worldgen", "worldgen/dimension entrypoint class path", 0.55);
    }
    if m.data_signals.dimension {
        add("adds_custom_dimension", "ships data/<ns>/dimension content", 0.9);
        add("has_worldgen", "ships custom dimension data", 0.8);
    }

    // ── Rendering: a render event subscription, an AT into a render class, or an
    //    author-declared render/client entrypoint class path ──
    if event_has("render") || event_has("camera") || event_has("hud") || event_has("gui") {
        add("modifies_rendering", "subscribes to a render/HUD event", 0.85);
    } else if at_touches("client/render") || at_touches("client/gui") || at_touches("/render/") {
        add("modifies_rendering", "access transform on a render class", 0.8);
    } else if entry_class_hint("render") || entry_class_hint("shader") || entry_class_hint("gui") {
        add("modifies_rendering", "render/shader entrypoint class path", 0.6);
    }

    // ── Lifecycle / tick / world: from the real subscribed event types ──
    if event_has("tick") {
        add("hooks_game_tick", "subscribes to a tick event", 0.85);
    }
    if event_has("serverstart") || event_has("serverstopp") || event_has("serverlifecycle") {
        add("hooks_server_lifecycle", "subscribes to a server-lifecycle event", 0.85);
    }
    if event_has("world") || event_has("level") || event_has("chunk") {
        add("hooks_world_events", "subscribes to a world/chunk event", 0.8);
    }

    // ── Code-transformation footprint ──
    if !m.mixin_configs.is_empty() {
        add("modifies_game_code", "declares mixin configuration", 0.9);
    }
    if !m.access_transforms.is_empty() || !m.coremods.is_empty() {
        add("deep_runtime_integration", "declares access transforms / coremods", 0.9);
    }

    // ── Whole-jar bytecode evidence: framework references prove content
    //    registration, networking, commands, config, keybinds, … ──
    for token in &m.bytecode.capabilities {
        // `&'static str` round-trip keeps the emitted attr stable (the tokens come
        // from the fixed CAPABILITY_REFS table).
        if let Some(name) = capability_token(token) {
            add(name, "bytecode: framework class reference", 0.8);
        }
    }
    let registers_content = m.bytecode.capabilities.iter().any(|c| c == "registers_content")
        || m.data_signals.content;

    // ── Performance-oriented: a *behavioural* mod (transforms code, registers no
    //    content) — derived from evidence, never from the mod's name. ──
    let transforms_code =
        !m.mixin_configs.is_empty() || !m.access_transforms.is_empty() || !m.coremods.is_empty();
    if transforms_code && !registers_content && !m.data_signals.worldgen {
        add(
            "performance_oriented",
            "transforms game code but registers no content (behavioural mod)",
            0.55,
        );
    }

    out
}

/// Re-resolve a capability token string back to its `&'static str` form so the
/// emitted fact attribute is stable. Returns `None` for unknown tokens.
fn capability_token(token: &str) -> Option<&'static str> {
    const TOKENS: &[&str] = &[
        "registers_content",
        "custom_networking",
        "registers_commands",
        "has_config",
        "adds_keybindings",
        "adds_creative_tab",
        "adds_block_entities",
        "uses_data_attachments",
        "uses_forge_capabilities",
        "has_worldgen",
        "heavy_event_handler",
        "heavy_tick_handler",
    ];
    TOKENS.iter().copied().find(|t| *t == token)
}

#[cfg(test)]
mod version_tests {
    use super::{normalize_version, version_ambiguous};

    #[test]
    fn normalizes_non_strict_mod_versions() {
        assert_eq!(normalize_version("v1.2"), "1.2.0");
        assert_eq!(normalize_version("1"), "1.0.0");
        assert_eq!(normalize_version("1.2.3.4"), "1.2.3"); // 4-part truncated
        assert_eq!(normalize_version("1.20.1-0.5.0"), "1.20.1"); // first group kept (ambiguous)
        assert_eq!(normalize_version("4.0.0+build.7"), "4.0.0"); // build metadata stripped
        assert_eq!(normalize_version("mc1.20-2.1"), "1.20.0"); // mc prefix stripped
        assert_eq!(normalize_version("1.x"), "1.0.0"); // non-numeric component → 0
    }

    #[test]
    fn non_numeric_version_kept_verbatim() {
        assert_eq!(normalize_version("alpha"), "alpha");
        assert_eq!(normalize_version("SNAPSHOT"), "SNAPSHOT");
    }

    #[test]
    fn flags_gameversion_modversion_ambiguity() {
        // These are exactly the cases where the normalized triple may be the
        // Minecraft version, not the mod version — consumers must lower trust.
        assert!(version_ambiguous("1.20.1-0.5.0"));
        assert!(version_ambiguous("mc1.20-2.1"));
        // Plain pre-release / build / clean versions are not ambiguous.
        assert!(!version_ambiguous("1.2.3"));
        assert!(!version_ambiguous("4.0.0+build.7"));
        assert!(!version_ambiguous("1.0.0-alpha")); // alpha is not a second version
    }
}
