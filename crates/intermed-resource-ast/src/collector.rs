//! The Layer-M collector: parse every jar's resources (in parallel, through the
//! shared [`JarCache`]), aggregate them into the reference graph + semantic diffs,
//! and lower the result into facts. It never produces findings.

use std::path::{Path, PathBuf};

use rayon::prelude::*;
use thiserror::Error;

use intermed_doctor_core::facts::{FactRead, SourceRef, kind};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, JarCache, Layer, ResourceSettings, ScanSettings,
    Target,
};
use intermed_evidence::ArtifactId;
use intermed_evidence::{CoverageGap, CoverageState};

use crate::model::ResourceLevel;
use crate::scan::{self, EXTRACTOR, JarAstScan};
use crate::semantic::diff;
use crate::semantic::refs::{ResourceAstRecord, ResourceGraph, ResourcePresence};

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
    pub presences: Vec<ResourcePresence>,
    /// `(namespace, writer, archive)` ownership from resources with no parsed AST (binary).
    /// The archive path is stored so writer identity normalization can be applied later.
    pub extra_owners: Vec<(String, String, String)>,
    /// `(archive, reason)` for jars that could not be inspected.
    pub failures: Vec<(String, String)>,
    /// `(archive, reason)` for resources dropped by a scan cap.
    pub truncations: Vec<(String, String)>,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct ScanError(pub String);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct IdentityBinding {
    writer: String,
    artifact_id: Option<String>,
}

type IdentityBindings =
    std::collections::BTreeMap<String, std::collections::BTreeSet<IdentityBinding>>;

fn canonical_identity_bindings(inputs: &dyn FactRead) -> IdentityBindings {
    let mut identities = IdentityBindings::new();
    for fact in inputs.by_kind(kind::RESOURCE_WRITER) {
        let archive = fact.attr("archive").unwrap_or(&fact.source.locator);
        let locator = fact.attr("source_locator").unwrap_or(&fact.source.locator);
        let portable = intermed_doctor_core::portable_artifact_locator(locator, archive);
        identities
            .entry(portable)
            .or_default()
            .insert(IdentityBinding {
                writer: fact.subject.to_string(),
                artifact_id: fact.attr("artifact_id").map(str::to_string),
            });
    }
    for fact in inputs
        .by_kind(kind::MOD)
        .chain(inputs.by_kind(kind::PLUGIN))
    {
        let Some(file) = fact.attr("file") else {
            continue;
        };
        let archive_name = Path::new(file)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(file);
        let archive = intermed_doctor_core::portable_artifact_locator(file, archive_name);
        identities
            .entry(archive)
            .or_default()
            .insert(IdentityBinding {
                writer: fact.subject.to_string(),
                artifact_id: fact.attr("artifact_id").map(str::to_string),
            });
    }
    identities
}

fn normalize_scan_identities(
    scan: &mut ResourceAstScan,
    identities: &IdentityBindings,
) -> Vec<(String, String)> {
    let unique = |archive: &str| {
        identities
            .get(archive)
            .filter(|bindings| bindings.len() == 1)
            .and_then(|bindings| bindings.first())
    };
    for record in &mut scan.records {
        if let Some(binding) = unique(&record.archive) {
            record.writer = binding.writer.clone();
            if let Some(artifact_id) = &binding.artifact_id {
                record.artifact_id = artifact_id.clone();
            }
        }
    }
    for presence in &mut scan.presences {
        if let Some(binding) = unique(&presence.archive) {
            presence.writer = binding.writer.clone();
            if let Some(artifact_id) = &binding.artifact_id {
                presence.artifact_id = artifact_id.clone();
            }
        }
    }
    scan.extra_owners
        .iter()
        .map(|(namespace, original_writer, archive)| {
            let writer = unique(archive)
                .map_or_else(|| original_writer.clone(), |binding| binding.writer.clone());
            (namespace.clone(), writer)
        })
        .collect()
}

pub struct ResourceAstCollector;

impl Collector for ResourceAstCollector {
    fn id(&self) -> &'static str {
        EXTRACTOR
    }

    fn layer(&self) -> Layer {
        Layer::DataSemantics
    }
    fn scope(&self) -> intermed_doctor_core::CollectorScope {
        intermed_doctor_core::CollectorScope::new(
            intermed_doctor_core::CompletenessModel::PerArtifact,
        )
        .produces([
            kind::RESOURCE_AST_PARSED,
            kind::RESOURCE_DEFINITION,
            kind::RESOURCE_REFERENCE,
            kind::RESOURCE_DANGLING_REFERENCE,
            kind::RESOURCE_RESOLVE_RESULT,
            kind::RESOURCE_SEMANTIC_DIFF,
            kind::RESOURCE_SEMANTIC_CONFLICT,
            kind::RESOURCE_SEMANTIC_ISSUE,
            kind::RESOURCE_PLATFORM_OBSERVATION,
            kind::IMPLICIT_DEPENDENCY_CANDIDATE,
            kind::IMPLICIT_DEPENDENCY_EDGE,
            kind::NAMESPACE_OWNER,
            kind::SCAN_TRUNCATED,
            kind::UNPARSEABLE_ARCHIVE,
        ])
        .regions([
            intermed_doctor_core::TargetRegion::Datapacks,
            intermed_doctor_core::TargetRegion::VanillaResources,
        ])
        .consumes([
            kind::MOD,
            kind::PLUGIN,
            kind::PROVIDED_DEPENDENCY,
            kind::RESOURCE_WRITER,
        ])
    }

    fn applies(&self, target: &Target) -> bool {
        !target.artifact_roots().is_empty()
    }

    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let settings = ctx.settings.resource;
        let level = ResourceLevel::from(settings.level);
        if !level.is_enabled() {
            return CollectorOutcome::not_applicable(format!(
                "resource AST disabled at `{}` level (use --resource-level semantic|full)",
                settings.level.as_str()
            ));
        }
        match scan_target_filtered(
            ctx.target,
            ctx.jar_cache,
            &ctx.settings.scan,
            settings,
            level,
        ) {
            Ok(scan) => {
                let incomplete = !scan.truncations.is_empty() || !scan.failures.is_empty();
                // Opt-in vanilla resource index: scan the Minecraft jar
                // (`--minecraft-jar`, shared with the mixin layer) so `minecraft:`
                // references resolve and tags expand against real vanilla resources.
                let vanilla = scan_vanilla_records(
                    ctx.settings.minecraft_jar.as_deref(),
                    ctx.jar_cache,
                    settings,
                    level,
                );
                let vanilla_requested = ctx.settings.minecraft_jar.is_some();
                let vanilla_incomplete = vanilla_requested && !vanilla.coverage.is_complete();
                let emitted = emit(ctx, scan, &vanilla, settings);
                if incomplete || vanilla_incomplete {
                    CollectorOutcome::incomplete(emitted.0, emitted.1)
                } else {
                    CollectorOutcome::active(emitted.0, emitted.1)
                }
            }
            Err(e) => CollectorOutcome::failed(e.to_string()),
        }
    }
}

/// Coverage-bearing result of the optional vanilla resource baseline.
#[derive(Debug)]
pub struct VanillaIndexResult {
    pub records: Vec<ResourceAstRecord>,
    pub presences: Vec<ResourcePresence>,
    pub coverage: CoverageState,
    pub reasons: Vec<CoverageGap>,
}

/// Scan the Minecraft jar's own resources, attributed to the `minecraft` writer,
/// for use as a vanilla index. Failures retain their exact coverage reason; an
/// empty vector is never treated as proof that vanilla contains no resources.
fn scan_vanilla_records(
    jar: Option<&Path>,
    cache: Option<&JarCache>,
    settings: ResourceSettings,
    level: ResourceLevel,
) -> VanillaIndexResult {
    let Some(jar) = jar else {
        let gap = CoverageGap::new(
            "minecraft-jar-not-provided",
            "no Minecraft JAR was supplied for the vanilla resource baseline",
        )
        .with_scope("vanilla-resources");
        return VanillaIndexResult {
            records: Vec::new(),
            presences: Vec::new(),
            coverage: CoverageState::Unavailable {
                reasons: vec![gap.clone()],
            },
            reasons: vec![gap],
        };
    };
    if !jar.is_file() {
        let code = if jar.exists() {
            "minecraft-jar-not-a-file"
        } else {
            "minecraft-jar-not-found"
        };
        let gap = CoverageGap::new(
            code,
            format!("Minecraft JAR cannot be read from {}", jar.display()),
        )
        .with_scope("vanilla-resources");
        return VanillaIndexResult {
            records: Vec::new(),
            presences: Vec::new(),
            coverage: CoverageState::Unavailable {
                reasons: vec![gap.clone()],
            },
            reasons: vec![gap],
        };
    }
    let version = scan::cache_version_bounded(
        level,
        settings.max_json_bytes,
        settings.max_lang_json_bytes,
        settings.max_ast_facts_per_resource,
    );
    let max_bytes = settings.max_json_bytes;
    let max_lang_bytes = settings.max_lang_json_bytes;
    let result = match cache {
        Some(c) => c.get_or_scan(EXTRACTOR, &version, jar, || {
            scan::scan_jar_bounded(
                jar,
                level,
                max_bytes,
                max_lang_bytes,
                settings.max_ast_facts_per_resource,
            )
        }),
        None => scan::scan_jar_bounded(
            jar,
            level,
            max_bytes,
            max_lang_bytes,
            settings.max_ast_facts_per_resource,
        ),
    };
    let archive = file_name_of(jar);
    match result {
        JarAstScan::Ok(partial) => {
            let reasons: Vec<CoverageGap> = partial
                .truncations
                .iter()
                .map(|reason| {
                    CoverageGap::new("vanilla-index-truncated", reason.clone())
                        .with_scope("vanilla-resources")
                })
                .collect();
            let coverage = if reasons.is_empty() {
                CoverageState::Complete
            } else {
                CoverageState::Partial {
                    gaps: reasons.clone(),
                }
            };
            let artifact_id = ArtifactId::unresolved(&archive).to_string();
            let presences = partial
                .present_paths
                .iter()
                .map(|path| ResourcePresence {
                    archive: archive.clone(),
                    artifact_id: artifact_id.clone(),
                    writer: "minecraft".to_string(),
                    path: path.clone(),
                })
                .collect();
            VanillaIndexResult {
                records: partial
                    .asts
                    .into_iter()
                    .map(|ast| ResourceAstRecord {
                        archive: archive.clone(),
                        artifact_id: artifact_id.clone(),
                        writer: "minecraft".to_string(),
                        ast,
                    })
                    .collect(),
                presences,
                coverage,
                reasons,
            }
        }
        JarAstScan::Err(reason) => {
            let gap = CoverageGap::new("vanilla-index-unreadable", reason)
                .with_scope("vanilla-resources");
            VanillaIndexResult {
                records: Vec::new(),
                presences: Vec::new(),
                coverage: CoverageState::Unavailable {
                    reasons: vec![gap.clone()],
                },
                reasons: vec![gap],
            }
        }
    }
}

/// Domain-specific baseline coverage. A successfully scanned client JAR is not a
/// proof that every hand-authored vanilla datapack domain is present in it.
fn vanilla_domain_coverage(
    result: &VanillaIndexResult,
) -> std::collections::BTreeMap<String, CoverageState> {
    use crate::model::ResourceDomain as D;
    let domains = [
        D::Tag,
        D::Recipe,
        D::Model,
        D::Blockstate,
        D::LootTable,
        D::Atlas,
        D::Advancement,
        D::Predicate,
        D::ItemModifier,
        D::GenericJson,
    ];
    let mut coverage = std::collections::BTreeMap::new();
    if !result.coverage.is_complete() {
        for domain in domains {
            coverage.insert(domain.as_str().to_string(), result.coverage.clone());
        }
        return coverage;
    }

    for domain in domains {
        let state = match domain {
            // Generated recipes and client assets are represented completely by
            // the matching game artifact when its scan completed.
            D::Recipe | D::Model | D::Blockstate | D::Atlas => CoverageState::Complete,
            // The client JAR does not contain the complete hand-authored datapack
            // universe for these domains.
            D::Tag => CoverageState::Unavailable {
                reasons: vec![CoverageGap::new(
                    "vanilla-domain-not-contained",
                    "the client Minecraft JAR does not contain the authoritative vanilla tag universe",
                )
                .with_scope("vanilla-tags")],
            },
            _ => CoverageState::Partial {
                gaps: vec![CoverageGap::new(
                    "vanilla-domain-partial",
                    format!(
                        "the Minecraft artifact provides only a partial `{}` baseline",
                        domain.as_str()
                    ),
                )
                .with_scope(format!("vanilla-{}", domain.as_str()))],
            },
        };
        coverage.insert(domain.as_str().to_string(), state);
    }
    coverage
}

/// Build graph + diffs from the scan and lower everything into facts. Returns
/// `(facts_emitted, human_summary)`.
fn emit(
    ctx: &mut CollectCtx<'_>,
    mut scan: ResourceAstScan,
    vanilla: &VanillaIndexResult,
    settings: ResourceSettings,
) -> (usize, String) {
    let identities = canonical_identity_bindings(ctx.inputs);
    let extra_owners_normalized = normalize_scan_identities(&mut scan, &identities);
    // The graph indexes pack resources *and* the vanilla index (definitions + tags
    // + `minecraft` ownership); diffs are computed over pack records only, so
    // vanilla is a resolution baseline, never a competing writer.

    let mut graph = ResourceGraph::build(&scan.records);
    graph.add_presences(&scan.presences);
    for (ns, writer) in &extra_owners_normalized {
        graph.add_owner(ns.clone(), writer.clone());
    }
    graph.add_vanilla_index(
        &vanilla.records,
        &vanilla.presences,
        vanilla_domain_coverage(vanilla),
    );
    let diffs = diff::compute(&scan.records);

    let mut emitted = crate::semantic::facts::emit(
        ctx.store,
        ctx.inputs,
        &scan.records,
        &scan.presences,
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
            .attr("relevant_entry", true)
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

    for gap in &vanilla.reasons {
        if gap.code == "minecraft-jar-not-provided" {
            continue;
        }
        ctx.store
            .fact(EXTRACTOR, kind::SCAN_TRUNCATED)
            .subject(
                ctx.settings
                    .minecraft_jar
                    .as_ref()
                    .map_or_else(|| "minecraft-jar".to_string(), |p| p.display().to_string()),
            )
            .attr("layer", "data-semantics")
            .attr("reason", gap.detail.clone())
            .attr("coverage_gap", gap.code.clone())
            .attr(
                "coverage_scope",
                gap.scope.as_deref().unwrap_or("vanilla-resources"),
            )
            .attr("relevant_entry", true)
            .confidence(1.0)
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

    scan_jars(&jars, cache, settings, level)
}

fn scan_target_filtered(
    target: &Target,
    cache: Option<&JarCache>,
    scan: &ScanSettings,
    settings: ResourceSettings,
    level: ResourceLevel,
) -> Result<ResourceAstScan, ScanError> {
    let roots = target.artifact_roots();
    if roots.is_empty() {
        return Err(ScanError("target has no artifact roots".into()));
    }
    let mut jars = Vec::new();
    for root in roots {
        let mut root_jars = intermed_doctor_core::list_jar_archives(&root.path, scan)
            .map_err(|e| ScanError(format!("read {}: {e}", root.path.display())))?;
        jars.append(&mut root_jars);
    }
    jars.sort();
    jars.dedup();
    scan_jars(&jars, cache, settings, level)
}

fn scan_jars(
    jars: &[PathBuf],
    cache: Option<&JarCache>,
    settings: ResourceSettings,
    level: ResourceLevel,
) -> Result<ResourceAstScan, ScanError> {
    let version = scan::cache_version_bounded(
        level,
        settings.max_json_bytes,
        settings.max_lang_json_bytes,
        settings.max_ast_facts_per_resource,
    );
    let max_bytes = settings.max_json_bytes;
    let max_lang_bytes = settings.max_lang_json_bytes;

    let scanned: Vec<(String, JarAstScan)> = jars
        .par_iter()
        .map(|jar| {
            let archive_name = file_name_of(jar);
            let archive = intermed_doctor_core::portable_artifact_locator(
                &jar.display().to_string(),
                &archive_name,
            );
            let result = match cache {
                Some(c) => c.get_or_scan(EXTRACTOR, &version, jar, || {
                    scan::scan_jar_bounded(
                        jar,
                        level,
                        max_bytes,
                        max_lang_bytes,
                        settings.max_ast_facts_per_resource,
                    )
                }),
                None => scan::scan_jar_bounded(
                    jar,
                    level,
                    max_bytes,
                    max_lang_bytes,
                    settings.max_ast_facts_per_resource,
                ),
            };
            (archive, result)
        })
        .collect();

    let mut out = ResourceAstScan::default();
    for (archive, result) in scanned {
        match result {
            JarAstScan::Ok(partial) => {
                let artifact_id = ArtifactId::unresolved(&archive).to_string();
                for ns in partial.owned_namespaces {
                    out.extra_owners
                        .push((ns, partial.writer.clone(), archive.clone()));
                }
                for reason in partial.truncations {
                    out.truncations.push((archive.clone(), reason));
                }
                for path in partial.present_paths {
                    out.presences.push(ResourcePresence {
                        archive: archive.clone(),
                        artifact_id: artifact_id.clone(),
                        writer: partial.writer.clone(),
                        path,
                    });
                }
                for ast in partial.asts {
                    out.records.push(ResourceAstRecord {
                        archive: archive.clone(),
                        artifact_id: artifact_id.clone(),
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
    out.presences.sort();
    out.presences.dedup();
    Ok(out)
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string()
}

#[cfg(test)]
mod vanilla_index_tests {
    use std::fs;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "intermed-vanilla-index-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_jar(path: &Path, body: &[u8]) {
        let file = fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "data/minecraft/recipes/example.json",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(body).unwrap();
        zip.finish().unwrap();
    }

    #[test]
    fn target_scan_includes_plugin_artifact_root() {
        let root = temp_dir();
        let plugins = root.join("plugins");
        fs::create_dir_all(&plugins).unwrap();
        write_jar(
            &plugins.join("plugin.jar"),
            br#"{"type":"minecraft:crafting_shapeless"}"#,
        );
        let target = Target {
            path: root.clone(),
            kind: intermed_doctor_core::TargetKind::Server,
            mods_dir: None,
            game_root: Some(root.clone()),
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let scan = scan_target_filtered(
            &target,
            None,
            &ScanSettings::default(),
            ResourceSettings::default(),
            ResourceLevel::Semantic,
        )
        .unwrap();
        assert_eq!(scan.records.len(), 1);
        assert_eq!(scan.records[0].archive, "plugins/plugin.jar");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn equal_basenames_in_different_artifact_roots_remain_distinct() {
        let root = temp_dir();
        let mods = root.join("mods");
        let plugins = root.join("plugins");
        fs::create_dir_all(&mods).unwrap();
        fs::create_dir_all(&plugins).unwrap();
        write_jar(
            &mods.join("common.jar"),
            br#"{"type":"minecraft:crafting_shapeless"}"#,
        );
        write_jar(
            &plugins.join("common.jar"),
            br#"{"type":"minecraft:crafting_shaped"}"#,
        );
        let target = Target {
            path: root.clone(),
            kind: intermed_doctor_core::TargetKind::Server,
            mods_dir: None,
            game_root: Some(root.clone()),
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let scan = scan_target_filtered(
            &target,
            None,
            &ScanSettings::default(),
            ResourceSettings::default(),
            ResourceLevel::Semantic,
        )
        .unwrap();
        let archives: std::collections::BTreeSet<_> = scan
            .records
            .iter()
            .map(|record| record.archive.as_str())
            .collect();
        assert_eq!(
            archives,
            std::collections::BTreeSet::from(["mods/common.jar", "plugins/common.jar",])
        );
        assert_ne!(scan.records[0].artifact_id, scan.records[1].artifact_id);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn binary_only_extra_owner_uses_canonical_artifact_identity() {
        let mut inputs = intermed_doctor_core::facts::FactStore::new();
        inputs
            .fact("vfs", kind::RESOURCE_WRITER)
            .subject("canonical_mod")
            .attr("archive", "binary.jar")
            .attr("source_locator", "/instance/mods/binary.jar")
            .attr("artifact_id", "sha256:binary")
            .source(SourceRef::file("/instance/mods/binary.jar"))
            .emit();
        let bindings = canonical_identity_bindings(&inputs);
        let mut scan = ResourceAstScan {
            extra_owners: vec![(
                "binary_namespace".into(),
                "binary".into(),
                "mods/binary.jar".into(),
            )],
            ..ResourceAstScan::default()
        };
        let owners = normalize_scan_identities(&mut scan, &bindings);
        assert_eq!(
            owners,
            vec![("binary_namespace".into(), "canonical_mod".into())]
        );
    }

    #[test]
    fn missing_and_unreadable_vanilla_inputs_are_distinct() {
        let root = temp_dir();
        let absent = root.join("absent.jar");
        let corrupt = root.join("corrupt.jar");
        fs::write(&corrupt, b"not a zip").unwrap();

        let none = scan_vanilla_records(
            None,
            None,
            ResourceSettings::default(),
            ResourceLevel::Semantic,
        );
        let missing = scan_vanilla_records(
            Some(&absent),
            None,
            ResourceSettings::default(),
            ResourceLevel::Semantic,
        );
        let broken = scan_vanilla_records(
            Some(&corrupt),
            None,
            ResourceSettings::default(),
            ResourceLevel::Semantic,
        );

        assert_eq!(none.reasons[0].code, "minecraft-jar-not-provided");
        assert_eq!(missing.reasons[0].code, "minecraft-jar-not-found");
        assert_eq!(broken.reasons[0].code, "vanilla-index-unreadable");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vanilla_scan_reports_complete_and_partial_coverage() {
        let root = temp_dir();
        let jar = root.join("client.jar");
        write_jar(&jar, br#"{"type":"minecraft:crafting_shapeless"}"#);

        let complete = scan_vanilla_records(
            Some(&jar),
            None,
            ResourceSettings::default(),
            ResourceLevel::Semantic,
        );
        assert!(complete.coverage.is_complete());
        assert_eq!(complete.records.len(), 1);
        let by_domain = vanilla_domain_coverage(&complete);
        assert!(matches!(
            by_domain.get(crate::model::ResourceDomain::Recipe.as_str()),
            Some(CoverageState::Complete)
        ));
        assert!(matches!(
            by_domain.get(crate::model::ResourceDomain::Tag.as_str()),
            Some(CoverageState::Unavailable { .. })
        ));
        assert!(matches!(
            by_domain.get(crate::model::ResourceDomain::LootTable.as_str()),
            Some(CoverageState::Partial { .. })
        ));

        let partial = scan_vanilla_records(
            Some(&jar),
            None,
            ResourceSettings {
                max_json_bytes: 4,
                ..ResourceSettings::default()
            },
            ResourceLevel::Semantic,
        );
        assert!(matches!(partial.coverage, CoverageState::Partial { .. }));
        assert_eq!(partial.reasons[0].code, "vanilla-index-truncated");
        fs::remove_dir_all(root).unwrap();
    }
}
