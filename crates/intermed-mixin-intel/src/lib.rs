//! # intermed-mixin-intel — Layer F (Phase 4)
//!
//! Static mixin intelligence. This crate does not transform classes and does
//! not execute mod code; it reads mixin configuration JSON and class-file string
//! evidence to build a preflight risk map.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use intermed_doctor_core::evidence::{
    Category, EvidenceEdge, Finding, FixCandidate, Relation, Severity,
};
use intermed_doctor_core::facts::{kind, SourceRef};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, Layer, Rule, RuleCtx, Target, TargetKind,
};
use serde::{Deserialize, Serialize};

const EXTRACTOR: &str = "mixin-analyzer";

/// Implementation status for help text.
pub const STATUS: &str = "active: Phase 4";

/// Layer-F collector.
pub fn collector() -> impl Collector {
    MixinCollector
}

/// Layer-F rule.
pub fn rule() -> impl Rule {
    MixinRiskRule
}

/// Scan result for CLI and tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinScan {
    pub target: String,
    pub configs: Vec<MixinConfigRecord>,
    pub classes: Vec<MixinClassRecord>,
    pub overlaps: Vec<MixinOverlap>,
    pub high_risk_overwrites: Vec<HighRiskOverwrite>,
    pub failures: Vec<MixinScanFailure>,
}

/// One mixin config file in a jar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinConfigRecord {
    pub archive: String,
    pub path: String,
    pub mod_id: String,
    pub package: String,
    pub priority: i64,
    pub refmap: Option<String>,
    pub mixins: Vec<String>,
}

/// One mixin class listed by a config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinClassRecord {
    pub archive: String,
    pub mod_id: String,
    pub config: String,
    pub class_name: String,
    pub class_path: String,
    pub targets: Vec<String>,
    pub operations: Vec<MixinOperation>,
    pub priority: i64,
    pub refmap: Option<String>,
    pub hot_paths: Vec<String>,
}

/// A detected mixin operation kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixinOperation {
    Inject,
    Redirect,
    Overwrite,
    ModifyArg,
    ModifyVariable,
    ModifyConstant,
    Unknown,
}

impl MixinOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            MixinOperation::Inject => "inject",
            MixinOperation::Redirect => "redirect",
            MixinOperation::Overwrite => "overwrite",
            MixinOperation::ModifyArg => "modify-arg",
            MixinOperation::ModifyVariable => "modify-variable",
            MixinOperation::ModifyConstant => "modify-constant",
            MixinOperation::Unknown => "unknown",
        }
    }
}

/// Two or more mods touching the same target class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinOverlap {
    pub target: String,
    pub mods: Vec<String>,
    pub classes: Vec<String>,
    pub operations: Vec<MixinOperation>,
    pub hot_path: bool,
}

/// An overwrite against a target class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighRiskOverwrite {
    pub mod_id: String,
    pub class_name: String,
    pub target: String,
    pub hot_path: bool,
}

/// Tolerated scanner failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinScanFailure {
    pub archive: String,
    pub path: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct MixinScanError {
    message: String,
}

impl MixinScanError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MixinScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MixinScanError {}

// ── Collector ─────────────────────────────────────────────────────────────

pub struct MixinCollector;

impl Collector for MixinCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }

    fn layer(&self) -> Layer {
        Layer::Mixin
    }

    fn applies(&self, target: &Target) -> bool {
        mods_dir(target).is_some()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let Some(dir) = mods_dir(ctx.target) else {
            return CollectorOutcome::skipped("no mods directory for mixin scan");
        };

        match scan_mods_dir(&dir) {
            Ok(scan) => {
                let emitted = emit_scan(ctx, &scan);
                CollectorOutcome::active(
                    emitted,
                    format!(
                        "{} config(s), {} mixin class(es), {} overlap(s), {} overwrite risk(s)",
                        scan.configs.len(),
                        scan.classes.len(),
                        scan.overlaps.len(),
                        scan.high_risk_overwrites.len()
                    ),
                )
            }
            Err(e) => CollectorOutcome::failed(e.to_string()),
        }
    }
}

fn emit_scan(ctx: &mut CollectCtx<'_>, scan: &MixinScan) -> usize {
    let mut emitted = 0usize;

    for c in &scan.configs {
        ctx.store
            .fact(EXTRACTOR, kind::MIXIN_CONFIG)
            .subject(c.mod_id.clone())
            .attr("archive", c.archive.clone())
            .attr("path", c.path.clone())
            .attr("package", c.package.clone())
            .attr("priority", c.priority)
            .attr("mixins", c.mixins.join(","))
            .source(SourceRef::inside(c.archive.clone(), c.path.clone()))
            .emit();
        emitted += 1;
    }

    for class in &scan.classes {
        ctx.store
            .fact(EXTRACTOR, kind::MIXIN_CLASS)
            .subject(class.class_name.clone())
            .attr("mod", class.mod_id.clone())
            .attr("archive", class.archive.clone())
            .attr("config", class.config.clone())
            .attr("class_path", class.class_path.clone())
            .attr("priority", class.priority)
            .attr(
                "operations",
                class
                    .operations
                    .iter()
                    .map(MixinOperation::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .source(SourceRef::inside(
                class.archive.clone(),
                class.class_path.clone(),
            ))
            .emit();
        emitted += 1;

        for target in &class.targets {
            ctx.store
                .fact(EXTRACTOR, kind::MIXIN_TARGET)
                .subject(class.mod_id.clone())
                .attr("target", target.clone())
                .attr("mixin", class.class_name.clone())
                .attr("priority", class.priority)
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }

        for op in &class.operations {
            for target in &class.targets {
                ctx.store
                    .fact(EXTRACTOR, kind::MIXIN_OPERATION)
                    .subject(class.mod_id.clone())
                    .attr("target", target.clone())
                    .attr("mixin", class.class_name.clone())
                    .attr("operation", op.as_str())
                    .source(SourceRef::inside(
                        class.archive.clone(),
                        class.class_path.clone(),
                    ))
                    .emit();
                emitted += 1;
            }
        }

        for hot in &class.hot_paths {
            ctx.store
                .fact(EXTRACTOR, kind::MIXIN_HOTSPOT)
                .subject(hot.clone())
                .attr("mod", class.mod_id.clone())
                .attr("mixin", class.class_name.clone())
                .source(SourceRef::inside(
                    class.archive.clone(),
                    class.class_path.clone(),
                ))
                .emit();
            emitted += 1;
        }
    }

    for overlap in &scan.overlaps {
        ctx.store
            .fact(EXTRACTOR, kind::MIXIN_OVERLAP)
            .subject(overlap.target.clone())
            .attr("mods", overlap.mods.join(","))
            .attr("classes", overlap.classes.join(","))
            .attr(
                "operations",
                overlap
                    .operations
                    .iter()
                    .map(MixinOperation::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .attr("hot_path", overlap.hot_path)
            .source(SourceRef::file(overlap.target.clone()))
            .emit();
        emitted += 1;
    }

    for overwrite in &scan.high_risk_overwrites {
        ctx.store
            .fact(EXTRACTOR, kind::HIGH_RISK_OVERWRITE)
            .subject(overwrite.mod_id.clone())
            .attr("target", overwrite.target.clone())
            .attr("mixin", overwrite.class_name.clone())
            .attr("hot_path", overwrite.hot_path)
            .source(SourceRef::file(overwrite.target.clone()))
            .emit();
        emitted += 1;
    }

    emitted
}

// ── Rule ─────────────────────────────────────────────────────────────────

pub struct MixinRiskRule;

impl Rule for MixinRiskRule {
    fn id(&self) -> &'static str {
        "mixin-risk"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();

        for f in ctx.store.by_kind(kind::MIXIN_OVERLAP) {
            let mods = split_attr(f.attr("mods"));
            let operations = split_attr(f.attr("operations"));
            let hot_path = f.attr_bool("hot_path").unwrap_or(false);
            let severity = if hot_path {
                Severity::Error
            } else {
                Severity::Warn
            };
            let mut b = Finding::builder(self.id(), format!("mixin-overlap:{}", f.subject))
                .severity(severity)
                .category(Category::Mixin)
                .title(format!("Mixin target overlap: {}", f.subject))
                .explanation(format!(
                    "{} mod(s) target {} with operation(s): {}.",
                    mods.len(),
                    f.subject,
                    operations.join(", ")
                ))
                .evidence(EvidenceEdge::subject(f.id))
                .affects(f.subject.clone())
                .fix(FixCandidate::advice(
                    "Check mod compatibility notes and prefer versions known to share this target.",
                ))
                .tag("mixin")
                .tag("overlap")
                .confidence(if hot_path { 0.7 } else { 0.65 });
            for target in ctx.store.by_kind(kind::MIXIN_TARGET) {
                if target.attr("target") == Some(f.subject.as_str()) {
                    b = b.evidence(EvidenceEdge::new(target.id, Relation::ConflictsWith, 0.75));
                }
            }
            out.push(b.build());
        }

        for f in ctx.store.by_kind(kind::HIGH_RISK_OVERWRITE) {
            let target = f.attr("target").unwrap_or(&f.subject);
            let hot_path = f.attr_bool("hot_path").unwrap_or(false);
            let severity = if hot_path {
                Severity::Error
            } else {
                Severity::Warn
            };
            out.push(
                Finding::builder(self.id(), format!("mixin-overwrite:{}->{target}", f.subject))
                    .severity(severity)
                    .category(Category::Mixin)
                    .title(format!("High-risk @Overwrite mixin: {target}"))
                    .explanation(format!(
                        "{} overwrites code in {target}. @Overwrite has a high compatibility risk because it replaces target behavior.",
                        f.subject
                    ))
                    .evidence(EvidenceEdge::subject(f.id))
                    .affects(target)
                    .fix(FixCandidate::advice(
                        "Prefer versions without competing overwrites, or remove one conflicting mod.",
                    ))
                    .tag("mixin")
                    .tag("overwrite")
                    .confidence(if hot_path { 0.72 } else { 0.68 })
                    .build(),
            );
        }

        out
    }
}

fn split_attr(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

// ── Scanner ──────────────────────────────────────────────────────────────

pub fn scan_target(target: &Target) -> Result<MixinScan, MixinScanError> {
    let Some(dir) = mods_dir(target) else {
        return Err(MixinScanError::new("target has no mods directory"));
    };
    scan_mods_dir(&dir)
}

pub fn scan_mods_dir(dir: &Path) -> Result<MixinScan, MixinScanError> {
    if !dir.is_dir() {
        return Err(MixinScanError::new(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }

    let mut jars: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| MixinScanError::new(format!("read {}: {e}", dir.display())))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("jar"))
        })
        .collect();
    jars.sort();

    let mut configs = Vec::new();
    let mut classes = Vec::new();
    let mut failures = Vec::new();
    for jar in &jars {
        if let Err(e) = scan_jar(jar, &mut configs, &mut classes, &mut failures) {
            failures.push(MixinScanFailure {
                archive: archive_name(jar),
                path: None,
                reason: e.to_string(),
            });
        }
    }

    let overlaps = classify_overlaps(&classes);
    let high_risk_overwrites = classify_overwrites(&classes);
    Ok(MixinScan {
        target: dir.display().to_string(),
        configs,
        classes,
        overlaps,
        high_risk_overwrites,
        failures,
    })
}

fn scan_jar(
    jar: &Path,
    configs: &mut Vec<MixinConfigRecord>,
    classes: &mut Vec<MixinClassRecord>,
    failures: &mut Vec<MixinScanFailure>,
) -> Result<(), MixinScanError> {
    let file = std::fs::File::open(jar)
        .map_err(|e| MixinScanError::new(format!("open {}: {e}", jar.display())))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| MixinScanError::new(format!("zip {}: {e}", jar.display())))?;
    let archive_name = archive_name(jar);
    let mod_id = detect_mod_id(&mut archive).unwrap_or_else(|| archive_stem(&archive_name));
    let config_paths = discover_mixin_configs(&mut archive);

    for config_path in config_paths {
        match read_zip_text(&mut archive, &config_path)
            .and_then(|text| parse_config(&archive_name, &config_path, &mod_id, &text).ok())
        {
            Some(config) => {
                for mixin in &config.mixins {
                    let class_path = mixin_class_path(&config.package, mixin);
                    match read_zip_bytes(&mut archive, &class_path) {
                        Some(bytes) => {
                            classes.push(analyze_class(&config, mixin, &class_path, &bytes))
                        }
                        None => failures.push(MixinScanFailure {
                            archive: archive_name.clone(),
                            path: Some(class_path),
                            reason: "mixin class listed in config but not found".to_string(),
                        }),
                    }
                }
                configs.push(config);
            }
            None => failures.push(MixinScanFailure {
                archive: archive_name.clone(),
                path: Some(config_path),
                reason: "mixin config could not be parsed".to_string(),
            }),
        }
    }
    Ok(())
}

fn discover_mixin_configs(archive: &mut zip::ZipArchive<std::fs::File>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        let name = normalize_path(entry.name());
        if is_safe_path(&name) && name.ends_with(".json") && name.contains("mixin") {
            out.insert(name);
        }
    }
    out.into_iter().collect()
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
}

fn parse_config(
    archive: &str,
    path: &str,
    mod_id: &str,
    text: &str,
) -> Result<MixinConfigRecord, serde_json::Error> {
    let raw: RawMixinConfig = serde_json::from_str(text)?;
    let mut mixins = BTreeSet::new();
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

fn analyze_class(
    config: &MixinConfigRecord,
    mixin: &str,
    class_path: &str,
    bytes: &[u8],
) -> MixinClassRecord {
    let class_name = join_class_name(&config.package, mixin);
    let strings = classfile_strings(bytes);
    let operations = detect_operations(&strings);
    let targets = detect_targets(&strings, &class_name);
    let hot_paths = targets
        .iter()
        .filter_map(|target| hot_path_tag(target))
        .collect();

    MixinClassRecord {
        archive: config.archive.clone(),
        mod_id: config.mod_id.clone(),
        config: config.path.clone(),
        class_name,
        class_path: class_path.to_string(),
        targets,
        operations,
        priority: config.priority,
        refmap: config.refmap.clone(),
        hot_paths,
    }
}

fn detect_operations(strings: &[String]) -> Vec<MixinOperation> {
    let mut ops = BTreeSet::new();
    for s in strings {
        if s.contains("/injection/Inject") || s.ends_with("/Inject;") {
            ops.insert(MixinOperation::Inject);
        }
        if s.contains("/injection/Redirect") || s.ends_with("/Redirect;") {
            ops.insert(MixinOperation::Redirect);
        }
        if s.contains("/Overwrite") || s.ends_with("/Overwrite;") {
            ops.insert(MixinOperation::Overwrite);
        }
        if s.contains("/injection/ModifyArg") || s.ends_with("/ModifyArg;") {
            ops.insert(MixinOperation::ModifyArg);
        }
        if s.contains("/injection/ModifyVariable") || s.ends_with("/ModifyVariable;") {
            ops.insert(MixinOperation::ModifyVariable);
        }
        if s.contains("/injection/ModifyConstant") || s.ends_with("/ModifyConstant;") {
            ops.insert(MixinOperation::ModifyConstant);
        }
    }
    if ops.is_empty() {
        ops.insert(MixinOperation::Unknown);
    }
    ops.into_iter().collect()
}

fn detect_targets(strings: &[String], mixin_class: &str) -> Vec<String> {
    let own = mixin_class.replace('.', "/");
    let mut out = BTreeSet::new();
    for s in strings {
        for candidate in descriptors_in_string(s) {
            if let Some(candidate) = normalize_target_candidate(&candidate) {
                if is_probable_target(&candidate, &own) {
                    out.insert(candidate.replace('/', "."));
                }
            }
        }
        if let Some(candidate) = normalize_target_candidate(s) {
            if is_probable_target(&candidate, &own) {
                out.insert(candidate.replace('/', "."));
            }
        }
    }
    out.into_iter().collect()
}

fn normalize_target_candidate(candidate: &str) -> Option<String> {
    let candidate = candidate
        .trim()
        .trim_start_matches('[')
        .strip_prefix('L')
        .unwrap_or(candidate)
        .strip_suffix(';')
        .unwrap_or(candidate)
        .to_string();
    if candidate.contains('/') {
        Some(candidate)
    } else {
        None
    }
}

fn descriptors_in_string(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'L' {
            if let Some(end) = bytes[i + 1..].iter().position(|b| *b == b';') {
                let candidate = &s[i + 1..i + 1 + end];
                out.push(candidate.to_string());
                i += end + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn is_probable_target(candidate: &str, own: &str) -> bool {
    candidate.contains('/')
        && !candidate.starts_with("java/")
        && !candidate.starts_with("javax/")
        && !candidate.starts_with("kotlin/")
        && !candidate.starts_with("scala/")
        && !candidate.starts_with("org/spongepowered/")
        && !candidate.starts_with("org/objectweb/")
        && !candidate.starts_with("com/google/")
        && candidate != own
}

fn hot_path_tag(target: &str) -> Option<String> {
    let lower = target.to_ascii_lowercase();
    let tags: &[(&str, &[&str])] = &[
        (
            "world-render",
            &["worldrenderer", "levelrenderer", "gamemode"],
        ),
        (
            "server-tick",
            &["minecraftserver", "serverlevel", "serverworld"],
        ),
        ("chunk", &["chunk", "chunkmap", "chunkmanager"]),
        ("entity", &["entity", "livingentity", "mob"]),
        ("network", &["network", "packet", "connection"]),
        ("registry", &["registry", "reloadable"]),
    ];
    for (tag, needles) in tags {
        if needles.iter().any(|needle| lower.contains(needle)) {
            return Some(tag.to_string());
        }
    }
    None
}

fn classify_overlaps(classes: &[MixinClassRecord]) -> Vec<MixinOverlap> {
    let mut by_target: BTreeMap<&str, Vec<&MixinClassRecord>> = BTreeMap::new();
    for class in classes {
        for target in &class.targets {
            by_target.entry(target).or_default().push(class);
        }
    }

    let mut out = Vec::new();
    for (target, group) in by_target {
        let mods: BTreeSet<String> = group.iter().map(|c| c.mod_id.clone()).collect();
        if mods.len() < 2 {
            continue;
        }
        let classes: BTreeSet<String> = group.iter().map(|c| c.class_name.clone()).collect();
        let operations: BTreeSet<MixinOperation> =
            group.iter().flat_map(|c| c.operations.clone()).collect();
        let hot_path = group.iter().any(|c| !c.hot_paths.is_empty());
        out.push(MixinOverlap {
            target: target.to_string(),
            mods: mods.into_iter().collect(),
            classes: classes.into_iter().collect(),
            operations: operations.into_iter().collect(),
            hot_path,
        });
    }
    out
}

fn classify_overwrites(classes: &[MixinClassRecord]) -> Vec<HighRiskOverwrite> {
    let mut out = Vec::new();
    for class in classes {
        if !class.operations.contains(&MixinOperation::Overwrite) {
            continue;
        }
        for target in &class.targets {
            out.push(HighRiskOverwrite {
                mod_id: class.mod_id.clone(),
                class_name: class.class_name.clone(),
                target: target.clone(),
                hot_path: hot_path_tag(target).is_some(),
            });
        }
    }
    out
}

fn classfile_strings(bytes: &[u8]) -> Vec<String> {
    if bytes.len() >= 10 && bytes[0..4] == [0xCA, 0xFE, 0xBA, 0xBE] {
        if let Some(strings) = constant_pool_utf8(bytes) {
            return strings;
        }
    }
    printable_strings(bytes)
}

fn constant_pool_utf8(bytes: &[u8]) -> Option<Vec<String>> {
    let count = read_u16(bytes, 8)? as usize;
    let mut pos = 10usize;
    let mut out = Vec::new();
    let mut index = 1usize;
    while index < count {
        let tag = *bytes.get(pos)?;
        pos += 1;
        match tag {
            1 => {
                let len = read_u16(bytes, pos)? as usize;
                pos += 2;
                let slice = bytes.get(pos..pos + len)?;
                pos += len;
                out.push(String::from_utf8_lossy(slice).into_owned());
            }
            3 | 4 => pos += 4,
            5 | 6 => {
                pos += 8;
                index += 1;
            }
            7 | 8 | 16 | 19 | 20 => pos += 2,
            9 | 10 | 11 | 12 | 17 | 18 => pos += 4,
            15 => pos += 3,
            _ => return None,
        }
        if pos > bytes.len() {
            return None;
        }
        index += 1;
    }
    Some(out)
}

fn printable_strings(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    for b in bytes {
        if (0x20..=0x7e).contains(b) {
            current.push(*b);
        } else if current.len() >= 4 {
            out.push(String::from_utf8_lossy(&current).into_owned());
            current.clear();
        } else {
            current.clear();
        }
    }
    if current.len() >= 4 {
        out.push(String::from_utf8_lossy(&current).into_owned());
    }
    out
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn mixin_class_path(package: &str, mixin: &str) -> String {
    format!(
        "{}.class",
        join_class_name(package, mixin).replace('.', "/")
    )
}

fn join_class_name(package: &str, mixin: &str) -> String {
    if mixin.contains('.') || package.is_empty() {
        mixin.to_string()
    } else {
        format!("{package}.{mixin}")
    }
}

fn mods_dir(target: &Target) -> Option<PathBuf> {
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
        .unwrap_or("?")
        .to_string()
}

fn archive_stem(name: &str) -> String {
    name.strip_suffix(".jar").unwrap_or(name).to_string()
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
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
mod tests {
    use super::*;

    #[test]
    fn detects_operations_and_targets_from_strings() {
        let bytes = b"Lorg/spongepowered/asm/mixin/injection/Redirect;\0Lnet/minecraft/client/render/WorldRenderer;\0";
        let class = MixinConfigRecord {
            archive: "a.jar".into(),
            path: "a.mixins.json".into(),
            mod_id: "alpha".into(),
            package: "example.mixin".into(),
            priority: 1000,
            refmap: None,
            mixins: vec!["RenderMixin".into()],
        };
        let record = analyze_class(
            &class,
            "RenderMixin",
            "example/mixin/RenderMixin.class",
            bytes,
        );
        assert_eq!(record.operations, vec![MixinOperation::Redirect]);
        assert_eq!(
            record.targets,
            vec!["net.minecraft.client.render.WorldRenderer"]
        );
        assert_eq!(record.hot_paths, vec!["world-render"]);
    }

    #[test]
    fn classifies_overlap_only_across_distinct_mods() {
        let mk = |mod_id: &str| MixinClassRecord {
            archive: format!("{mod_id}.jar"),
            mod_id: mod_id.into(),
            config: "mixins.json".into(),
            class_name: format!("{mod_id}.Mixin"),
            class_path: format!("{mod_id}/Mixin.class"),
            targets: vec!["net.minecraft.server.MinecraftServer".into()],
            operations: vec![MixinOperation::Inject],
            priority: 1000,
            refmap: None,
            hot_paths: vec!["server-tick".into()],
        };
        let overlaps = classify_overlaps(&[mk("alpha"), mk("beta")]);
        assert_eq!(overlaps.len(), 1);
        assert!(overlaps[0].hot_path);
        assert_eq!(overlaps[0].mods, vec!["alpha", "beta"]);
    }
}
