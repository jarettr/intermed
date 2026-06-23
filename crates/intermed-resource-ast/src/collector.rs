//! The Layer-M collector: parse every jar's resources (in parallel, through the
//! shared [`JarCache`]), aggregate them into the reference graph + semantic diffs,
//! and lower the result into facts. It never produces findings.

use std::path::{Path, PathBuf};

use rayon::prelude::*;
use thiserror::Error;

use intermed_doctor_core::facts::{SourceRef, kind};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, JarCache, Layer, ResourceSettings, ScanSettings,
    Target, TargetKind,
};

use crate::model::ResourceLevel;
use crate::scan::{self, EXTRACTOR, JarAstScan};
use crate::semantic::diff;
use crate::semantic::refs::{ResourceAstRecord, ResourceGraph};

/// The Layer-M collector.
#[must_use]
pub fn collector() -> impl Collector {
    ResourceAstCollector
}

/// Aggregated, parsed resources for a whole pack — the input to graph building,
/// diffing, and fact lowering.
#[derive(Debug, Default)]
pub struct ResourceAstScan {
    pub records: Vec<ResourceAstRecord>,
    /// `(namespace, writer)` ownership from resources with no parsed AST (binary).
    pub extra_owners: Vec<(String, String)>,
    /// `(archive, reason)` for jars that could not be inspected.
    pub failures: Vec<(String, String)>,
    /// `(archive, reason)` for resources dropped by a scan cap.
    pub truncations: Vec<(String, String)>,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ScanError(pub String);

pub struct ResourceAstCollector;

impl Collector for ResourceAstCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }

    fn layer(&self) -> Layer {
        Layer::DataSemantics
    }

    fn applies(&self, target: &Target) -> bool {
        mods_dir(target).is_some()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let settings = ctx.settings.resource;
        let level = ResourceLevel::from(settings.level);
        if !level.is_enabled() {
            return CollectorOutcome::skipped(format!(
                "resource AST disabled at `{}` level (use --resource-level semantic|full)",
                settings.level.as_str()
            ));
        }
        let Some(dir) = mods_dir(ctx.target) else {
            return CollectorOutcome::skipped("no mods directory for resource AST scan");
        };

        match scan_mods_dir_filtered(&dir, ctx.jar_cache, &ctx.settings.scan, settings, level) {
            Ok(scan) => {
                // Opt-in vanilla resource index: scan the Minecraft jar
                // (`--minecraft-jar`, shared with the mixin layer) so `minecraft:`
                // references resolve and tags expand against real vanilla resources.
                let vanilla = ctx
                    .settings
                    .minecraft_jar
                    .as_deref()
                    .map(|jar| scan_vanilla_records(jar, ctx.jar_cache, settings, level))
                    .unwrap_or_default();
                let emitted = emit(ctx, scan, &vanilla, settings);
                CollectorOutcome::active(emitted.0, emitted.1)
            }
            Err(e) => CollectorOutcome::failed(e.to_string()),
        }
    }
}

/// Scan the Minecraft jar's own resources, attributed to the `minecraft` writer,
/// for use as a vanilla index. Best-effort: any read error yields an empty index
/// (the feature is opt-in and never blocks a run).
fn scan_vanilla_records(
    jar: &Path,
    cache: Option<&JarCache>,
    settings: ResourceSettings,
    level: ResourceLevel,
) -> Vec<ResourceAstRecord> {
    if !jar.is_file() {
        return Vec::new();
    }
    let version = scan::cache_version(level);
    let max_bytes = settings.max_json_bytes;
    let result = match cache {
        Some(c) => c.get_or_scan(EXTRACTOR, &version, jar, || {
            scan::scan_jar(jar, level, max_bytes)
        }),
        None => scan::scan_jar(jar, level, max_bytes),
    };
    let archive = file_name_of(jar);
    match result {
        JarAstScan::Ok(partial) => partial
            .asts
            .into_iter()
            .map(|ast| ResourceAstRecord {
                archive: archive.clone(),
                writer: "minecraft".to_string(),
                ast,
            })
            .collect(),
        JarAstScan::Err(_) => Vec::new(),
    }
}

/// Build graph + diffs from the scan and lower everything into facts. Returns
/// `(facts_emitted, human_summary)`.
fn emit(
    ctx: &mut CollectCtx<'_>,
    scan: ResourceAstScan,
    vanilla: &[ResourceAstRecord],
    settings: ResourceSettings,
) -> (usize, String) {
    // The graph indexes pack resources *and* the vanilla index (definitions + tags
    // + `minecraft` ownership); diffs are computed over pack records only, so
    // vanilla is a resolution baseline, never a competing writer.
    let mut graph = ResourceGraph::build(&scan.records);
    for (ns, writer) in &scan.extra_owners {
        graph.add_owner(ns.clone(), writer.clone());
    }
    graph.add_vanilla_index(vanilla);
    let diffs = diff::compute(&scan.records);

    let mut emitted = crate::semantic::facts::emit(
        ctx.store,
        &scan.records,
        &graph,
        &diffs,
        settings.max_ast_facts_per_resource,
    );

    // Reuse the established Layer-E diagnostic kinds for scan health, rather than
    // minting Layer-M-specific ones.
    for (archive, reason) in &scan.truncations {
        ctx.store
            .fact(EXTRACTOR, kind::SCAN_TRUNCATED)
            .subject(archive.clone())
            .attr("layer", "data-semantics")
            .attr("reason", reason.clone())
            .source(SourceRef::file(archive.clone()))
            .confidence(0.95)
            .emit();
        emitted += 1;
    }
    for (archive, reason) in &scan.failures {
        ctx.store
            .fact(EXTRACTOR, kind::UNPARSEABLE_ARCHIVE)
            .subject(archive.clone())
            .attr("reason", reason.clone())
            .source(SourceRef::file(archive.clone()))
            .confidence(0.9)
            .emit();
        emitted += 1;
    }

    let summary = format!(
        "{} resource AST(s), {} reference edge(s), {} semantic diff(s), {} namespace owner(s)",
        scan.records.len(),
        graph.references.len(),
        diffs.len(),
        graph.namespace_owners.len(),
    );
    (emitted, summary)
}

/// Convenience scan of a mods directory at `level`, no cache and no incremental
/// filter — used by `vfs explain --ast`.
pub fn scan_mods_dir(dir: &Path, level: ResourceLevel) -> Result<ResourceAstScan, ScanError> {
    scan_mods_dir_filtered(
        dir,
        None,
        &ScanSettings::default(),
        ResourceSettings {
            level: level_to_setting(level),
            ..ResourceSettings::default()
        },
        level,
    )
}

fn level_to_setting(level: ResourceLevel) -> intermed_doctor_core::ResourceAstLevel {
    use intermed_doctor_core::ResourceAstLevel as L;
    match level {
        ResourceLevel::Basic => L::Basic,
        ResourceLevel::Semantic => L::Semantic,
        ResourceLevel::Full => L::Full,
    }
}

/// Scan a mods directory's jars into aggregated records, fanning out across cores
/// and caching each jar through the shared [`JarCache`].
pub fn scan_mods_dir_filtered(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &ScanSettings,
    settings: ResourceSettings,
    level: ResourceLevel,
) -> Result<ResourceAstScan, ScanError> {
    if !dir.is_dir() {
        return Err(ScanError(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }

    let jars = intermed_doctor_core::list_jar_archives(dir, scan)
        .map_err(|e| ScanError(format!("read {}: {e}", dir.display())))?;

    let version = scan::cache_version(level);
    let max_bytes = settings.max_json_bytes;

    let scanned: Vec<(String, JarAstScan)> = jars
        .par_iter()
        .map(|jar| {
            let archive = file_name_of(jar);
            let result = match cache {
                Some(c) => c.get_or_scan(EXTRACTOR, &version, jar, || {
                    scan::scan_jar(jar, level, max_bytes)
                }),
                None => scan::scan_jar(jar, level, max_bytes),
            };
            (archive, result)
        })
        .collect();

    let mut out = ResourceAstScan::default();
    for (archive, result) in scanned {
        match result {
            JarAstScan::Ok(partial) => {
                for ns in partial.owned_namespaces {
                    out.extra_owners.push((ns, partial.writer.clone()));
                }
                for reason in partial.truncations {
                    out.truncations.push((archive.clone(), reason));
                }
                for ast in partial.asts {
                    out.records.push(ResourceAstRecord {
                        archive: archive.clone(),
                        writer: partial.writer.clone(),
                        ast,
                    });
                }
            }
            JarAstScan::Err(reason) => out.failures.push((archive, reason)),
        }
    }

    // Deterministic order for stable fact output / golden tests.
    out.records.sort_by(|a, b| {
        a.ast
            .resource_path
            .cmp(&b.ast.resource_path)
            .then_with(|| a.writer.cmp(&b.writer))
            .then_with(|| a.archive.cmp(&b.archive))
    });
    out.extra_owners.sort();
    out.extra_owners.dedup();
    out.failures.sort();
    out.truncations.sort();
    Ok(out)
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

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string()
}
