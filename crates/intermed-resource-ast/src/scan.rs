//! Per-jar resource-AST scanning.
//!
//! This layer does **not** implement its own cache. Exactly like Layer E
//! (`vfs::scan_jar_cached` / `CachedVfsJar`) and the mixin / SBOM / security
//! layers, the per-jar [`scan_jar`] closure is run *through the shared*
//! [`JarCache`](intermed_doctor_core::JarCache) by the collector:
//!
//! ```ignore
//! cache.get_or_scan(EXTRACTOR, &cache_version(level), jar, || scan_jar(jar, level, max));
//! ```
//!
//! [`JarAstScan`] is the serialisable payload the shared cache stores; the cache
//! *key version* ([`cache_version`]) folds the crate version, the combined
//! [`parser_version`](crate::parser_version), and the resource level, so any
//! parser or level change invalidates entries without touching unrelated jars and
//! a `full` scan never reuses a `semantic` entry.
//!
//! The payload is the **compact** AST summary set — never raw JSON. Backpressure
//! (Stage 3): bytes are read, parsed, summarised, then dropped; only summaries
//! survive into the cache and the fact store.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::domain::{RESOURCE_AST_CACHE_SCHEMA, classify, parse_resource, parser_version};
use crate::model::{CachedResourceAst, DomainParseExt, ResourceLevel};
use crate::semantic::namespace::path_namespace;

/// Per-jar scan limits. Jars are untrusted: bound entry count and total parsed
/// bytes so a malicious archive cannot exhaust memory or time. The per-entry JSON
/// cap is the caller's `max_json_bytes`.
const MAX_RESOURCE_ENTRIES: usize = 50_000;
const MAX_TOTAL_PARSED_BYTES: u64 = 256 * 1024 * 1024;

/// Cached AST scan for one jar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JarAstScan {
    Ok(JarAstPartial),
    /// The jar could not be opened / read as a zip.
    Err(String),
}

/// The successful per-jar payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JarAstPartial {
    /// Resolved writer/mod id.
    pub writer: String,
    /// Compact AST summaries for parsed-domain resources.
    pub asts: Vec<CachedResourceAst>,
    /// Every namespace this jar ships *any* resource under (incl. binary-only),
    /// for namespace ownership without per-asset facts.
    pub owned_namespaces: Vec<String>,
    /// Diagnostics for resources skipped by a cap (path + reason).
    pub truncations: Vec<String>,
}

/// Stable fact-extractor / collector id, shared with [`crate::semantic::facts`].
pub const EXTRACTOR: &str = crate::semantic::facts::EXTRACTOR;

/// Cache-key version fed to the shared [`JarCache`](intermed_doctor_core::JarCache).
///
/// Like the other layers it pins the crate version (`CARGO_PKG_VERSION`); on top
/// of that it folds the combined [`parser_version`] and the resource level, since
/// both change *what* is parsed and so must invalidate the cached payload.
#[must_use]
pub fn cache_version(level: ResourceLevel) -> String {
    format!(
        "{}|{}|{}|{}",
        env!("CARGO_PKG_VERSION"),
        RESOURCE_AST_CACHE_SCHEMA,
        parser_version(),
        level.as_str()
    )
}

/// Scan one jar into its compact AST payload. Never panics: a bad jar becomes
/// [`JarAstScan::Err`], a bad resource becomes an `Invalid` AST.
#[must_use]
pub fn scan_jar(jar: &Path, level: ResourceLevel, max_json_bytes: u64) -> JarAstScan {
    let file = match std::fs::File::open(jar) {
        Ok(f) => f,
        Err(e) => return JarAstScan::Err(format!("open {}: {e}", jar.display())),
    };
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(e) => return JarAstScan::Err(format!("zip {}: {e}", jar.display())),
    };

    let archive_name = file_name_of(jar);
    let writer = detect_writer_id(&mut archive).unwrap_or_else(|| archive_stem(&archive_name));

    let mut asts = Vec::new();
    let mut owned: BTreeSet<String> = BTreeSet::new();
    let mut truncations = Vec::new();
    let mut total_parsed: u64 = 0;
    let mut entries = 0usize;

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                truncations.push(format!("entry {i}: {e}"));
                continue;
            }
        };
        if entry.is_dir() {
            continue;
        }
        let path = entry.name().replace('\\', "/");
        if !is_resource_path(&path) || !is_safe_resource_path(&path) {
            continue;
        }

        entries += 1;
        if entries > MAX_RESOURCE_ENTRIES {
            truncations.push(format!(
                "stopped after {MAX_RESOURCE_ENTRIES} resource entries (archive has more)"
            ));
            break;
        }
        if let Some(ns) = path_namespace(&path) {
            owned.insert(ns);
        }

        // Only parsed domains cost a read; binary/unmodelled resources contribute
        // namespace ownership above and nothing more.
        let domain = classify::classify(&path);
        if !domain.parsed_at(level) {
            continue;
        }
        if entry.size() > max_json_bytes {
            truncations.push(format!(
                "{path}: {} bytes exceeds {max_json_bytes} byte JSON cap, skipped",
                entry.size()
            ));
            continue;
        }
        if total_parsed >= MAX_TOTAL_PARSED_BYTES {
            truncations.push(format!(
                "reached {MAX_TOTAL_PARSED_BYTES} byte total parse cap; remaining resources skipped"
            ));
            break;
        }

        let mut bytes = Vec::new();
        let read_cap = max_json_bytes.saturating_add(1);
        if let Err(e) = Read::take(&mut entry, read_cap).read_to_end(&mut bytes) {
            truncations.push(format!("{path}: read error: {e}"));
            continue;
        }
        if bytes.len() as u64 > max_json_bytes {
            truncations.push(format!(
                "{path}: decompressed past {max_json_bytes} byte cap, skipped"
            ));
            continue;
        }
        total_parsed = total_parsed.saturating_add(bytes.len() as u64);

        // Summarise, then drop `bytes`.
        asts.push(parse_resource(&path, &bytes, level));
    }

    JarAstScan::Ok(JarAstPartial {
        writer,
        asts,
        owned_namespaces: owned.into_iter().collect(),
        truncations,
    })
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

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string()
}

fn archive_stem(name: &str) -> String {
    name.strip_suffix(".jar").unwrap_or(name).to_string()
}

/// Resolve a mod/writer id from the jar's loader metadata, mirroring the Layer-E
/// scanner so a resource is attributed to the same writer in both layers.
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
                .and_then(|text| intermed_resource_identity::mod_id_from_mods_toml(&text))
        })
}

fn read_zip_text(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Option<String> {
    let mut entry = archive.by_name(name).ok()?;
    let mut text = String::new();
    entry.read_to_string(&mut text).ok()?;
    Some(text)
}
