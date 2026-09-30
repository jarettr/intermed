//! Per-jar resource-AST scanning.
//!
//! This layer does **not** implement its own cache. Exactly like Layer E
//! (`vfs::scan_jar_cached` / `CachedVfsJar`) and the mixin / SBOM / security
//! layers, the per-jar [`scan_jar`] closure is run *through the shared*
//! [`JarCache`](intermed_doctor_core::JarCache) by the collector:
//!
//! ```ignore
//! cache.get_or_scan(EXTRACTOR, &cache_version(level, max, max_lang), jar, || {
//!     scan_jar(jar, level, max, max_lang)
//! });
//! ```
//!
//! [`JarAstScan`] is the serialisable payload the shared cache stores; the cache
//! *key version* ([`cache_version`]) folds the crate version, the combined
//! [`parser_version`](crate::parser_version), resource level, and byte bounds,
//! so parser/settings changes invalidate entries without touching unrelated jars
//! and a `full` scan never reuses a `semantic` entry.
//!
//! The payload is the **compact** AST summary set — never raw JSON. Backpressure
//! (Stage 3): bytes are read, parsed, summarised, then dropped; only summaries
//! survive into the cache and the fact store.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::domain::{RESOURCE_AST_CACHE_SCHEMA, classify, parser_version};
use crate::model::{CachedResourceAst, DomainParseExt, ResourceLevel};
use crate::semantic::namespace::path_namespace;

/// Per-jar scan limits. Jars are untrusted: bound entry count and total parsed
/// bytes so a malicious archive cannot exhaust memory or time. The per-entry JSON
/// cap is the caller's `max_json_bytes`.
const MAX_RESOURCE_ENTRIES: usize = 50_000;
const MAX_TOTAL_PARSED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DESCRIPTOR_BYTES: u64 = 1024 * 1024;

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
    /// Every safe resource path observed in the central directory, including
    /// entries whose bodies were not parsed because of level or size limits.
    #[serde(default)]
    pub present_paths: Vec<String>,
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
pub fn cache_version(
    level: ResourceLevel,
    max_json_bytes: u64,
    max_lang_json_bytes: u64,
) -> String {
    cache_version_bounded(level, max_json_bytes, max_lang_json_bytes, 256)
}

#[must_use]
pub fn cache_version_bounded(
    level: ResourceLevel,
    max_json_bytes: u64,
    max_lang_json_bytes: u64,
    max_references: usize,
) -> String {
    format!(
        "{}|{}|{}|{}|json={max_json_bytes}|lang={max_lang_json_bytes}|refs={max_references}",
        env!("CARGO_PKG_VERSION"),
        RESOURCE_AST_CACHE_SCHEMA,
        parser_version(),
        level.as_str()
    )
}

/// Scan one jar into its compact AST payload. Never panics: a bad jar becomes
/// [`JarAstScan::Err`], a bad resource becomes an `Invalid` AST.
#[must_use]
pub fn scan_jar(
    jar: &Path,
    level: ResourceLevel,
    max_json_bytes: u64,
    max_lang_json_bytes: u64,
) -> JarAstScan {
    scan_jar_bounded(jar, level, max_json_bytes, max_lang_json_bytes, 256)
}

#[must_use]
pub fn scan_jar_bounded(
    jar: &Path,
    level: ResourceLevel,
    max_json_bytes: u64,
    max_lang_json_bytes: u64,
    max_references: usize,
) -> JarAstScan {
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
    let mut present_paths = Vec::new();
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
        present_paths.push(path.clone());

        // Only parsed domains cost a read; binary/unmodelled resources contribute
        // namespace ownership above and nothing more.
        let domain = classify::classify(&path);
        if !domain.parsed_at(level) {
            continue;
        }
        let entry_cap = if domain == crate::model::ResourceDomain::Lang {
            max_lang_json_bytes
        } else {
            max_json_bytes
        };
        if entry.size() > entry_cap {
            truncations.push(format!(
                "{path}: {} bytes exceeds {entry_cap} byte {} cap, skipped",
                entry.size(),
                if domain == crate::model::ResourceDomain::Lang {
                    "language JSON"
                } else {
                    "JSON"
                },
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
        let remaining_total = MAX_TOTAL_PARSED_BYTES - total_parsed;
        let read_cap = entry_cap.min(remaining_total).saturating_add(1);
        if let Err(e) = Read::take(&mut entry, read_cap).read_to_end(&mut bytes) {
            truncations.push(format!("{path}: read error: {e}"));
            continue;
        }
        if bytes.len() as u64 > entry_cap {
            truncations.push(format!(
                "{path}: decompressed past {entry_cap} byte cap, skipped"
            ));
            continue;
        }
        if bytes.len() as u64 > remaining_total {
            truncations.push(format!(
                "{path}: would exceed {MAX_TOTAL_PARSED_BYTES} byte total parse cap; remaining resources skipped"
            ));
            break;
        }
        total_parsed = total_parsed.saturating_add(bytes.len() as u64);

        // Summarise, then drop `bytes`.
        let ast = crate::domain::parse_resource_with_limits(
            &path,
            &bytes,
            level,
            crate::domain::ExtractionLimits {
                max_references,
                ..crate::domain::ExtractionLimits::default()
            },
        );
        if let Some(gap) = &ast.reference_gap {
            truncations.push(format!("{path}: {gap}"));
        }
        asts.push(ast);
    }

    JarAstScan::Ok(JarAstPartial {
        writer,
        asts,
        owned_namespaces: owned.into_iter().collect(),
        present_paths,
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
        .and_then(|text| descriptor_writer_id(&text, false))
        .or_else(|| {
            read_zip_text(archive, "quilt.mod.json")
                .and_then(|text| descriptor_writer_id(&text, true))
        })
        .or_else(|| {
            read_zip_text(archive, "META-INF/mods.toml")
                .or_else(|| read_zip_text(archive, "META-INF/neoforge.mods.toml"))
                .and_then(|text| intermed_resource_identity::mod_id_from_mods_toml(&text))
        })
}

fn descriptor_writer_id(text: &str, quilt: bool) -> Option<String> {
    // Fabric Loader parses metadata with Gson, which accepts literal control
    // characters in strings. Use the same bounded, lenient parser as Layer B so
    // all layers attribute one artifact to the same mod identity.
    let value = intermed_doctor_core::fabric_json::parse_value(text).ok()?;
    let id = if quilt {
        value.get("quilt_loader")?.get("id")?
    } else {
        value.get("id")?
    };
    id.as_str().map(str::to_string)
}

fn read_zip_text(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Option<String> {
    let mut entry = archive.by_name(name).ok()?;
    if entry.size() > MAX_DESCRIPTOR_BYTES {
        return None;
    }
    let mut text = String::new();
    entry
        .by_ref()
        .take(MAX_DESCRIPTOR_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return None;
    }
    Some(text)
}

#[cfg(test)]
mod writer_identity_tests {
    use super::{JarAstScan, cache_version, descriptor_writer_id, scan_jar, scan_jar_bounded};
    use crate::model::ResourceLevel;
    use std::io::Write;

    #[test]
    fn fabric_gson_control_characters_do_not_split_layer_identity() {
        let metadata = "{\"id\":\"betterend\",\"description\":\"line one\nline two\"}";
        assert_eq!(
            descriptor_writer_id(metadata, false).as_deref(),
            Some("betterend")
        );
    }

    #[test]
    fn quilt_writer_comes_from_quilt_loader_identity() {
        let metadata = r#"{"quilt_loader":{"id":"quilt_mod"}}"#;
        assert_eq!(
            descriptor_writer_id(metadata, true).as_deref(),
            Some("quilt_mod")
        );
    }

    #[test]
    fn legitimate_large_language_catalog_uses_its_separate_bound() {
        let path = std::env::temp_dir().join(format!(
            "intermed-large-lang-{}-{}.jar",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let file = std::fs::File::create(&path).expect("create jar");
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        archive
            .start_file("assets/example/lang/en_us.json", options)
            .expect("start language catalog");
        let value = "x".repeat(2 * 1024 * 1024);
        write!(archive, "{{\"example.key\":\"{value}\"}}").expect("write language catalog");
        archive.finish().expect("finish jar");

        let JarAstScan::Ok(accepted) =
            scan_jar(&path, ResourceLevel::Semantic, 1024 * 1024, 4 * 1024 * 1024)
        else {
            panic!("fixture jar should be readable");
        };
        assert_eq!(accepted.asts.len(), 1);
        assert!(accepted.truncations.is_empty());

        let JarAstScan::Ok(truncated) =
            scan_jar(&path, ResourceLevel::Semantic, 1024 * 1024, 1024 * 1024)
        else {
            panic!("fixture jar should be readable");
        };
        assert!(truncated.asts.is_empty());
        assert_eq!(truncated.truncations.len(), 1);
        std::fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn resource_cache_identity_includes_every_parse_bound() {
        let baseline = cache_version(ResourceLevel::Semantic, 1024, 4096);
        assert_ne!(baseline, cache_version(ResourceLevel::Semantic, 2048, 4096));
        assert_ne!(baseline, cache_version(ResourceLevel::Semantic, 1024, 8192));
    }

    #[test]
    fn oversized_resource_remains_physically_present() {
        let path = std::env::temp_dir().join(format!(
            "intermed-oversized-resource-{}.jar",
            std::process::id()
        ));
        let file = std::fs::File::create(&path).expect("create jar");
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file(
                "data/example/recipe/large.json",
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .expect("start resource");
        write!(
            archive,
            "{{\"type\":\"minecraft:crafting_shapeless\",\"padding\":\"{}\"}}",
            "x".repeat(4096)
        )
        .expect("write resource");
        archive.finish().expect("finish jar");

        let JarAstScan::Ok(scan) = scan_jar(&path, ResourceLevel::Semantic, 128, 128) else {
            panic!("fixture jar should be readable");
        };
        assert!(scan.asts.is_empty());
        assert_eq!(scan.present_paths, vec!["data/example/recipe/large.json"]);
        assert_eq!(scan.truncations.len(), 1);
        std::fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn reference_extraction_limit_marks_scan_partial() {
        let path = std::env::temp_dir().join(format!(
            "intermed-many-resource-refs-{}.jar",
            std::process::id()
        ));
        let file = std::fs::File::create(&path).expect("create jar");
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file(
                "data/example/recipe/many.json",
                zip::write::SimpleFileOptions::default(),
            )
            .expect("start resource");
        let ingredients = (0..20)
            .map(|index| format!(r#"{{"item":"example:item_{index}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        write!(
            archive,
            r#"{{"type":"minecraft:crafting_shapeless","ingredients":[{ingredients}],"result":{{"item":"minecraft:stick"}}}}"#
        )
        .expect("write resource");
        archive.finish().expect("finish jar");

        let JarAstScan::Ok(scan) =
            scan_jar_bounded(&path, ResourceLevel::Semantic, 1 << 20, 1 << 20, 4)
        else {
            panic!("fixture jar should be readable");
        };
        assert_eq!(scan.asts.len(), 1);
        assert!(!scan.asts[0].references_complete);
        assert_eq!(scan.truncations.len(), 1);
        std::fs::remove_file(path).expect("remove fixture");
    }
}
