//! # intermed-vfs — Layer E (Phase 3)
//!
//! Resource / data conflict analysis for Minecraft modpacks. This crate stays
//! read-only: it scans jar resources, emits facts, and classifies collisions.
//! File-writing overlay previews live in `intermed-packops`.

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

const EXTRACTOR: &str = "vfs-scanner";

/// Implementation status for help text.
pub const STATUS: &str = "active: Phase 3";

/// The Layer-E collector.
pub fn collector() -> impl Collector {
    ResourceCollector
}

/// The Layer-E resource conflict rule.
pub fn rule() -> impl Rule {
    ResourceConflictRule
}

/// Resource collision classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictClass {
    /// Multiple jars write byte-for-byte identical content.
    Identical,
    /// JSON files look mergeable, but no commutative merge rule is known yet.
    JsonMergeCandidate,
    /// Minecraft tag JSON can be merged as a set of values.
    SafeCrdtMerge,
    /// Later writer replaces earlier content; order matters.
    UnsafeReplace,
}

impl ConflictClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ConflictClass::Identical => "identical",
            ConflictClass::JsonMergeCandidate => "json-merge-candidate",
            ConflictClass::SafeCrdtMerge => "safe-crdt-merge",
            ConflictClass::UnsafeReplace => "unsafe-replace",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "identical" => ConflictClass::Identical,
            "json-merge-candidate" => ConflictClass::JsonMergeCandidate,
            "safe-crdt-merge" => ConflictClass::SafeCrdtMerge,
            "unsafe-replace" => ConflictClass::UnsafeReplace,
            _ => return None,
        })
    }
}

/// A single resource writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceWrite {
    pub path: String,
    pub writer: String,
    pub archive: String,
    pub size: u64,
    pub json: bool,
}

/// A path written by more than one archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCollision {
    pub path: String,
    pub writers: Vec<String>,
    pub archives: Vec<String>,
    pub class: ConflictClass,
    pub reason: String,
}

/// An archive that could not be inspected. Scans are tolerant: one bad jar does
/// not hide evidence from the rest of the pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceScanFailure {
    pub archive: String,
    pub reason: String,
}

/// Result of a VFS scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceScan {
    pub target: String,
    pub writes: Vec<ResourceWrite>,
    pub collisions: Vec<ResourceCollision>,
    pub failures: Vec<ResourceScanFailure>,
    #[serde(skip)]
    blobs: Vec<ResourceBlob>,
}

impl ResourceScan {
    /// Return resource bytes for the deterministic overlay winner.
    pub fn winning_blob(&self, path: &str) -> Option<&[u8]> {
        self.blobs
            .iter()
            .filter(|b| b.path == path)
            .max_by(|a, b| {
                a.archive
                    .cmp(&b.archive)
                    .then_with(|| a.writer.cmp(&b.writer))
            })
            .map(|b| b.bytes.as_slice())
    }

    /// Return all blobs for a resource path in deterministic order.
    pub fn blobs_for_path(&self, path: &str) -> Vec<&[u8]> {
        let mut blobs: Vec<&ResourceBlob> = self.blobs.iter().filter(|b| b.path == path).collect();
        blobs.sort_by(|a, b| {
            a.archive
                .cmp(&b.archive)
                .then_with(|| a.writer.cmp(&b.writer))
        });
        blobs.into_iter().map(|b| b.bytes.as_slice()).collect()
    }
}

#[derive(Debug, Clone)]
struct ResourceBlob {
    path: String,
    writer: String,
    archive: String,
    bytes: Vec<u8>,
}

/// VFS scan failure.
#[derive(Debug, Clone)]
pub struct ScanError {
    message: String,
}

impl ScanError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ScanError {}

// ── Collector ─────────────────────────────────────────────────────────────

pub struct ResourceCollector;

impl Collector for ResourceCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }

    fn layer(&self) -> Layer {
        Layer::Resource
    }

    fn applies(&self, target: &Target) -> bool {
        mods_dir(target).is_some()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let Some(dir) = mods_dir(ctx.target) else {
            return CollectorOutcome::skipped("no mods directory for VFS scan");
        };
        match scan_mods_dir(&dir) {
            Ok(scan) => {
                let emitted = emit_scan(ctx, &scan);
                CollectorOutcome::active(
                    emitted,
                    format!(
                        "{} resource writer(s), {} collision(s), {} scan failure(s)",
                        scan.writes.len(),
                        scan.collisions.len(),
                        scan.failures.len()
                    ),
                )
            }
            Err(e) => CollectorOutcome::failed(e.to_string()),
        }
    }
}

fn emit_scan(ctx: &mut CollectCtx<'_>, scan: &ResourceScan) -> usize {
    let mut emitted = 0usize;
    for w in &scan.writes {
        ctx.store
            .fact(EXTRACTOR, kind::RESOURCE_WRITER)
            .subject(w.writer.clone())
            .attr("path", w.path.clone())
            .attr("archive", w.archive.clone())
            .attr("size", w.size as i64)
            .attr("json", w.json)
            .source(SourceRef::inside(w.archive.clone(), w.path.clone()))
            .emit();
        emitted += 1;
    }

    for c in &scan.collisions {
        ctx.store
            .fact(EXTRACTOR, kind::RESOURCE_COLLISION)
            .subject(c.path.clone())
            .attr("writers", c.writers.join(","))
            .attr("archives", c.archives.join(","))
            .attr("class", c.class.as_str())
            .attr("reason", c.reason.clone())
            .source(SourceRef::file(c.path.clone()))
            .emit();
        emitted += 1;

        let kind = match c.class {
            ConflictClass::Identical => None,
            ConflictClass::JsonMergeCandidate => Some(kind::JSON_MERGE_CANDIDATE),
            ConflictClass::SafeCrdtMerge => Some(kind::SAFE_CRDT_MERGE),
            ConflictClass::UnsafeReplace => Some(kind::UNSAFE_REPLACE_CONFLICT),
        };
        if let Some(predicate) = kind {
            ctx.store
                .fact(EXTRACTOR, predicate)
                .subject(c.path.clone())
                .attr("writers", c.writers.join(","))
                .attr("reason", c.reason.clone())
                .source(SourceRef::file(c.path.clone()))
                .emit();
            emitted += 1;
        }
    }

    for failure in &scan.failures {
        ctx.store
            .fact(EXTRACTOR, kind::UNPARSEABLE_ARCHIVE)
            .subject(failure.archive.clone())
            .attr("reason", failure.reason.clone())
            .source(SourceRef::file(failure.archive.clone()))
            .confidence(0.9)
            .emit();
        emitted += 1;
    }
    emitted
}

// ── Rule ─────────────────────────────────────────────────────────────────

pub struct ResourceConflictRule;

impl Rule for ResourceConflictRule {
    fn id(&self) -> &'static str {
        "resource-conflict"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for c in ctx.store.by_kind(kind::RESOURCE_COLLISION) {
            let path = c.subject.as_str();
            let class = c
                .attr("class")
                .and_then(ConflictClass::from_str)
                .unwrap_or(ConflictClass::UnsafeReplace);
            let writers = split_attr(c.attr("writers"));
            let reason = c.attr("reason").unwrap_or("");

            if class == ConflictClass::Identical {
                continue;
            }

            let (severity, title, fix) = match class {
                ConflictClass::SafeCrdtMerge => (
                    Severity::Note,
                    format!("Resource can be merged safely: {path}"),
                    "Generate an overlay preview and inspect the merged tag values.",
                ),
                ConflictClass::JsonMergeCandidate => (
                    Severity::Warn,
                    format!("JSON resource needs merge review: {path}"),
                    "Review the JSON files; InterMed can stage a deterministic overlay preview.",
                ),
                ConflictClass::UnsafeReplace => (
                    Severity::Warn,
                    format!("Resource override is order-dependent: {path}"),
                    "Choose the intended winner or add a compatibility datapack/resourcepack overlay.",
                ),
                ConflictClass::Identical => unreachable!(),
            };

            let mut b = Finding::builder(self.id(), format!("resource-conflict:{path}"))
                .severity(severity)
                .category(Category::Resource)
                .title(title)
                .explanation(format!(
                    "{} writer(s) touch this path: {}. {reason}",
                    writers.len(),
                    writers.join(", ")
                ))
                .evidence(EvidenceEdge::subject(c.id))
                .affects(path)
                .fix(FixCandidate::advice(fix))
                .tag("resource")
                .tag(class.as_str());

            for w in ctx.store.by_kind(kind::RESOURCE_WRITER) {
                if w.attr("path") == Some(path) {
                    b = b.evidence(EvidenceEdge::new(w.id, Relation::ConflictsWith, 0.8));
                }
            }
            out.push(b.build());
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

pub fn scan_target(target: &Target) -> Result<ResourceScan, ScanError> {
    let Some(dir) = mods_dir(target) else {
        return Err(ScanError::new("target has no mods directory"));
    };
    scan_mods_dir(&dir)
}

pub fn scan_mods_dir(dir: &Path) -> Result<ResourceScan, ScanError> {
    if !dir.is_dir() {
        return Err(ScanError::new(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }

    let mut jars: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| ScanError::new(format!("read {}: {e}", dir.display())))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("jar"))
        })
        .collect();
    jars.sort();

    let mut writes = Vec::new();
    let mut blobs = Vec::new();
    let mut failures = Vec::new();
    for jar in &jars {
        if let Err(e) = scan_jar(jar, &mut writes, &mut blobs) {
            failures.push(ResourceScanFailure {
                archive: jar
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?")
                    .to_string(),
                reason: e.to_string(),
            });
        }
    }

    let collisions = classify_collisions(&blobs);
    Ok(ResourceScan {
        target: dir.display().to_string(),
        writes,
        collisions,
        failures,
        blobs,
    })
}

fn scan_jar(
    jar: &Path,
    writes: &mut Vec<ResourceWrite>,
    blobs: &mut Vec<ResourceBlob>,
) -> Result<(), ScanError> {
    let file = std::fs::File::open(jar)
        .map_err(|e| ScanError::new(format!("open {}: {e}", jar.display())))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| ScanError::new(format!("zip {}: {e}", jar.display())))?;

    let archive_name = jar
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string();
    let writer = detect_writer_id(&mut archive).unwrap_or_else(|| archive_stem(&archive_name));

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| ScanError::new(format!("read {} entry {i}: {e}", jar.display())))?;
        if entry.is_dir() {
            continue;
        }
        let path = normalize_resource_path(entry.name());
        if !is_resource_path(&path) || !is_safe_resource_path(&path) {
            continue;
        }

        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| ScanError::new(format!("read {}!{path}: {e}", jar.display())))?;
        let json =
            is_json_path(&path) && serde_json::from_slice::<serde_json::Value>(&bytes).is_ok();

        writes.push(ResourceWrite {
            path: path.clone(),
            writer: writer.clone(),
            archive: archive_name.clone(),
            size: bytes.len() as u64,
            json,
        });
        blobs.push(ResourceBlob {
            path,
            writer: writer.clone(),
            archive: archive_name.clone(),
            bytes,
        });
    }
    Ok(())
}

fn classify_collisions(blobs: &[ResourceBlob]) -> Vec<ResourceCollision> {
    let mut by_path: BTreeMap<&str, Vec<&ResourceBlob>> = BTreeMap::new();
    for blob in blobs {
        by_path.entry(blob.path.as_str()).or_default().push(blob);
    }

    let mut out = Vec::new();
    for (path, mut group) in by_path {
        if group.len() < 2 {
            continue;
        }
        group.sort_by(|a, b| {
            a.archive
                .cmp(&b.archive)
                .then_with(|| a.writer.cmp(&b.writer))
        });
        let writers: Vec<String> = group
            .iter()
            .map(|b| b.writer.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let archives: Vec<String> = group.iter().map(|b| b.archive.clone()).collect();

        let (class, reason) = classify_group(path, &group);
        out.push(ResourceCollision {
            path: path.to_string(),
            writers,
            archives,
            class,
            reason,
        });
    }
    out
}

fn classify_group(path: &str, group: &[&ResourceBlob]) -> (ConflictClass, String) {
    if group
        .first()
        .is_some_and(|first| group.iter().all(|b| b.bytes == first.bytes))
    {
        return (
            ConflictClass::Identical,
            "all writers provide byte-identical content".to_string(),
        );
    }

    if is_tag_json_path(path) && group.iter().all(|b| tag_values(&b.bytes).is_some()) {
        return (
            ConflictClass::SafeCrdtMerge,
            "Minecraft tag values can be merged as a deterministic set".to_string(),
        );
    }

    if is_json_merge_candidate_path(path)
        && group
            .iter()
            .all(|b| serde_json::from_slice::<serde_json::Value>(&b.bytes).is_ok())
    {
        return (
            ConflictClass::JsonMergeCandidate,
            "all writers provide valid JSON, but the domain-specific merge rule is not proven safe"
                .to_string(),
        );
    }

    (
        ConflictClass::UnsafeReplace,
        "content differs and no safe merge rule is known".to_string(),
    )
}

pub fn merge_tag_values(blobs: &[&[u8]]) -> Option<Vec<u8>> {
    let mut replace = false;
    let mut values = BTreeSet::new();
    for blob in blobs {
        let (blob_replace, blob_values) = tag_values(blob)?;
        replace |= blob_replace;
        values.extend(blob_values);
    }

    let out = serde_json::json!({
        "replace": replace,
        "values": values.into_iter().collect::<Vec<_>>(),
    });
    serde_json::to_vec_pretty(&out).ok()
}

fn tag_values(bytes: &[u8]) -> Option<(bool, Vec<String>)> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = value.as_object()?;
    let values = obj.get("values")?.as_array()?;
    let mut out = Vec::new();
    for v in values {
        if let Some(s) = v.as_str() {
            out.push(s.to_string());
        } else if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
            out.push(id.to_string());
        } else {
            return None;
        }
    }
    let replace = obj
        .get("replace")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    Some((replace, out))
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

fn is_resource_path(path: &str) -> bool {
    path == "pack.mcmeta" || path.starts_with("assets/") || path.starts_with("data/")
}

fn is_safe_resource_path(path: &str) -> bool {
    !path.starts_with('/')
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn is_json_path(path: &str) -> bool {
    path.ends_with(".json") || path == "pack.mcmeta"
}

fn is_tag_json_path(path: &str) -> bool {
    path.starts_with("data/") && path.contains("/tags/") && path.ends_with(".json")
}

fn is_json_merge_candidate_path(path: &str) -> bool {
    path.starts_with("assets/") && path.contains("/lang/") && path.ends_with(".json")
}

fn normalize_resource_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn archive_stem(name: &str) -> String {
    name.strip_suffix(".jar").unwrap_or(name).to_string()
}

fn detect_writer_id(archive: &mut zip::ZipArchive<std::fs::File>) -> Option<String> {
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
        .or_else(|| {
            read_zip_text(archive, "META-INF/mods.toml")
                .or_else(|| read_zip_text(archive, "META-INF/neoforge.mods.toml"))
                .and_then(|text| {
                    text.lines()
                        .find_map(|line| line.trim().strip_prefix("modId"))
                        .and_then(|rest| rest.split_once('='))
                        .map(|(_, value)| value.trim().trim_matches('"').to_string())
                })
        })
        .or_else(|| {
            read_zip_text(archive, "plugin.yml")
                .or_else(|| read_zip_text(archive, "paper-plugin.yml"))
                .and_then(|text| {
                    text.lines()
                        .find_map(|line| line.trim().strip_prefix("name:"))
                        .map(|value| value.trim().to_string())
                })
        })
}

fn read_zip_text(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Option<String> {
    let mut entry = archive.by_name(name).ok()?;
    let mut text = String::new();
    entry.read_to_string(&mut text).ok()?;
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_tag_values_as_set() {
        let a = br#"{"values":["minecraft:stone","minecraft:dirt"]}"#;
        let b = br#"{"values":["minecraft:dirt","minecraft:granite"]}"#;
        let merged = merge_tag_values(&[a.as_slice(), b.as_slice()]).unwrap();
        let text = String::from_utf8(merged).unwrap();
        assert!(text.contains("minecraft:stone"));
        assert!(text.contains("minecraft:granite"));
    }

    #[test]
    fn classifies_tags_as_safe_merge() {
        let blobs = vec![
            ResourceBlob {
                path: "data/minecraft/tags/items/axes.json".into(),
                writer: "a".into(),
                archive: "a.jar".into(),
                bytes: br#"{"values":["a:x"]}"#.to_vec(),
            },
            ResourceBlob {
                path: "data/minecraft/tags/items/axes.json".into(),
                writer: "b".into(),
                archive: "b.jar".into(),
                bytes: br#"{"values":["b:y"]}"#.to_vec(),
            },
        ];
        let collisions = classify_collisions(&blobs);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].class, ConflictClass::SafeCrdtMerge);
    }
}
