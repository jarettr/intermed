//! Jar-level mixin scanning and modpack aggregation.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use intermed_doctor_core::bounded_zip;
use intermed_doctor_core::settings::MixinSettings;
use intermed_doctor_core::{JarCache, Target, TargetKind};

use crate::analyzer::MixinInteractionEngine;
use crate::class_parser::{parse_mixin_class_with_hierarchy, resolve_parse};
use crate::effect::enrich_classes_with_effects;
use crate::hierarchy::HierarchyIndex;
use crate::hot_path::{HotPathRules, any_hot_path};
use crate::model::TargetNamespace;
use crate::model::{
    MixinAnalysis, MixinClassRecord, MixinConfigRecord, MixinScan, MixinScanFailure,
};
use crate::recommendation::recommend_for_scan;
use crate::refmap::{MappingContext, Namespace, Refmap, TinyMappings, dotted_name};

const EXTRACTOR: &str = "mixin-analyzer";
/// Bump trailing revision when parse / analysis logic changes within a release.
const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-r38");

#[derive(Debug, Clone, Default)]
pub(crate) struct ArtifactBinding {
    pub mod_id: Option<String>,
    pub identity_certainty: String,
}

/// Stable collector / fact extractor id (`mixin-analyzer`).
pub fn extractor_id() -> &'static str {
    EXTRACTOR
}

/// Jar cache revision — bump trailing `-rN` when parse/analysis logic changes in a release.
pub fn cache_version() -> &'static str {
    CACHE_VERSION
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct MixinScanError(pub String);

pub fn scan_target(target: &Target) -> Result<MixinScan, MixinScanError> {
    let Some(dir) = mods_dir(target) else {
        return Err(MixinScanError("target has no mods directory".into()));
    };
    scan_mods_dir(&dir)
}

pub fn scan_mods_dir(dir: &Path) -> Result<MixinScan, MixinScanError> {
    scan_mods_dir_with_cache(dir, None)
}

pub fn scan_mods_dir_with_cache(
    dir: &Path,
    cache: Option<&JarCache>,
) -> Result<MixinScan, MixinScanError> {
    scan_mods_dir_filtered(
        dir,
        cache,
        &intermed_doctor_core::ScanSettings::default(),
        MixinSettings::default(),
        None,
        None,
    )
}

/// Like [`scan_mods_dir_with_cache`] but honors incremental [`ScanSettings`].
pub fn scan_mods_dir_filtered(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
    mixin: MixinSettings,
    minecraft_jar: Option<&Path>,
    minecraft_mappings: Option<&Path>,
) -> Result<MixinScan, MixinScanError> {
    scan_mods_dir_filtered_with_environment(
        dir,
        cache,
        scan,
        mixin,
        minecraft_jar,
        minecraft_mappings,
        None,
    )
}

/// Environment-aware variant used by the collector. The target Minecraft
/// version is kept distinct from mapping-file identity and is used only to
/// reject wrong-version mapping graphs.
pub fn scan_mods_dir_filtered_with_environment(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
    mixin: MixinSettings,
    minecraft_jar: Option<&Path>,
    minecraft_mappings: Option<&Path>,
    target_minecraft_version: Option<&str>,
) -> Result<MixinScan, MixinScanError> {
    scan_mods_dir_filtered_with_target_environment(
        dir,
        cache,
        scan,
        mixin,
        minecraft_jar,
        minecraft_mappings,
        target_minecraft_version,
        None,
        false,
        false,
    )
}

/// Environment-aware scan with an authoritative loader family. Loader identity
/// selects the active descriptor in hybrid JARs and is part of the cache key.
#[allow(clippy::too_many_arguments)]
pub fn scan_mods_dir_filtered_with_target_environment(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
    mixin: MixinSettings,
    minecraft_jar: Option<&Path>,
    minecraft_mappings: Option<&Path>,
    target_minecraft_version: Option<&str>,
    target_loader: Option<intermed_doctor_core::Loader>,
    allow_foreign_configs: bool,
    environment_conflicted: bool,
) -> Result<MixinScan, MixinScanError> {
    scan_mods_dir_filtered_with_identity(
        dir,
        cache,
        scan,
        mixin,
        minecraft_jar,
        minecraft_mappings,
        target_minecraft_version,
        target_loader,
        crate::model::Side::Unknown,
        allow_foreign_configs,
        environment_conflicted,
        &BTreeMap::new(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_mods_dir_filtered_with_identity(
    dir: &Path,
    cache: Option<&JarCache>,
    scan: &intermed_doctor_core::ScanSettings,
    mixin: MixinSettings,
    minecraft_jar: Option<&Path>,
    minecraft_mappings: Option<&Path>,
    target_minecraft_version: Option<&str>,
    target_loader: Option<intermed_doctor_core::Loader>,
    target_side: crate::model::Side,
    allow_foreign_configs: bool,
    environment_conflicted: bool,
    identity_bindings: &BTreeMap<String, ArtifactBinding>,
) -> Result<MixinScan, MixinScanError> {
    if !dir.is_dir() {
        return Err(MixinScanError(format!(
            "mods directory does not exist: {}",
            dir.display()
        )));
    }

    let jars = intermed_doctor_core::list_jar_archives(dir, scan)
        .map_err(|e| MixinScanError(format!("read {}: {e}", dir.display())))?;

    let cache_version = format!(
        "{CACHE_VERSION}-loader-{}-foreign-{}",
        target_loader.map_or("unknown", |loader| loader.as_str()),
        allow_foreign_configs
    );
    let results: Vec<_> = jars
        .par_iter()
        .map(|jar| {
            let archive = archive_name(jar);
            let cached = match cache {
                Some(c) => c.get_or_scan(EXTRACTOR, &cache_version, jar, || {
                    scan_jar_cached(jar, target_loader, allow_foreign_configs)
                }),
                None => scan_jar_cached(jar, target_loader, allow_foreign_configs),
            };
            (jar.clone(), archive, cached)
        })
        .collect();

    let mut configs = Vec::new();
    let mut configs_discovered = 0usize;
    let mut classes = Vec::new();
    let mut failures = Vec::new();
    let mut hierarchy = HierarchyIndex::new();
    let mut target_index = crate::apply_failure::TargetClassIndex::new();
    for (jar, archive, mut result) in results {
        // Cache entries are content-addressed and may have been produced from an
        // identically-sized copy with a different filename. Locator data belongs
        // to this scan invocation, never to the reusable payload.
        rebind_archive(&mut result, &archive);
        let exact_key = format!("path:{}", jar.display());
        let archive_key = format!("name:{archive}");
        if let Some(binding) = identity_bindings
            .get(&exact_key)
            .or_else(|| identity_bindings.get(&archive_key))
        {
            rebind_identity(&mut result, binding);
        }
        match result {
            CachedMixinJar::Ok(mut partial) => {
                configs_discovered += partial.configs_discovered;
                configs.append(&mut partial.configs);
                classes.append(&mut partial.classes);
                failures.append(&mut partial.failures);
                hierarchy.merge(&partial.hierarchy);
                target_index.merge(&partial.target_index);
            }
            CachedMixinJar::Err { archive, reason } => failures.push(MixinScanFailure {
                archive,
                path: None,
                reason,
            }),
        }
    }

    // Activation is environment-dependent and identity-sensitive. Cached class
    // parsing deliberately stays neutral; re-evaluate only after canonical B
    // identity has been bound and canonical A side is known.
    apply_target_activation(&configs, &mut classes, target_side);

    let global_mappings = minecraft_mappings
        .and_then(load_tiny_mappings_file)
        .map(|mapping| {
            mapping.with_target_minecraft_version(target_minecraft_version.map(str::to_string))
        });

    // Optional Minecraft jar broadens the index to MC classes, so apply-failure
    // checks cover vanilla-targeting mixins (not just mod-targeting ones).
    let minecraft_observation = minecraft_jar.map(|mc_jar| {
        let observation = ingest_minecraft_jar(mc_jar, &mut target_index, global_mappings.as_ref());
        if let Some(error) = &observation.error {
            failures.push(MixinScanFailure {
                archive: mc_jar.display().to_string(),
                path: None,
                reason: format!("minecraft jar index: {error}"),
            });
        }
        observation
    });

    enrich_classes_with_effects(&mut classes);
    let mut analysis = MixinInteractionEngine::new()
        .with_hierarchy(hierarchy)
        .analyze(&classes);
    // Phase 4: what classes did the analyzer actually have indexed? Absence-based
    // verdicts read this so they never sound more confident than coverage allows.
    let mut classpath_coverage = crate::classpath::ClasspathCoverage::from_index(&target_index);
    // The namespace of a supplied artifact is useful provenance even when that
    // artifact is deliberately rejected for absence checks. Keep observation
    // separate from accepted coverage: an official-obfuscated jar without an
    // official mapping edge remains `mods-only`, but the passport must not call
    // the artifact itself unsupported.
    if let Some(namespace) = minecraft_observation.and_then(|observation| observation.namespace) {
        classpath_coverage.minecraft_namespace = namespace.as_str().to_string();
    }
    let refmap_statuses: std::collections::BTreeMap<(String, String), crate::refmap::RefmapStatus> =
        configs
            .iter()
            .map(|cfg| {
                (
                    (cfg.artifact_id.clone(), cfg.path.clone()),
                    cfg.refmap_status.clone(),
                )
            })
            .collect();
    let apply_failures = crate::apply_failure::detect_apply_failures(
        &classes,
        &target_index,
        &refmap_statuses,
        global_mappings.as_ref(),
    );
    // Fold confirmed apply failures into the risk heatmap (risk v2).
    crate::analyzer::fold_apply_failures(&mut analysis.risk_assessments, &apply_failures);
    let recommendations = if mixin.emit_recommendation_facts() {
        recommend_for_scan(
            &classes,
            &analysis.mixin_effects,
            &analysis.conflict_edges,
            &apply_failures,
        )
    } else {
        Vec::new()
    };
    Ok(assemble_scan(
        dir,
        configs_discovered,
        configs,
        classes,
        analysis,
        apply_failures,
        recommendations,
        Some(classpath_coverage),
        Some(&target_index),
        global_mappings.as_ref(),
        failures,
        environment_conflicted,
        match mixin.level {
            intermed_doctor_core::settings::MixinLevel::Basic => {
                crate::profile::PrecisionProfile::Fast
            }
            intermed_doctor_core::settings::MixinLevel::Standard => {
                crate::profile::PrecisionProfile::Standard
            }
            intermed_doctor_core::settings::MixinLevel::Full => {
                crate::profile::PrecisionProfile::Forensic
            }
        },
    ))
}

fn apply_target_activation(
    configs: &[MixinConfigRecord],
    classes: &mut [MixinClassRecord],
    target_side: crate::model::Side,
) {
    let config_by_identity = configs
        .iter()
        .map(|config| ((config.artifact_id.clone(), config.path.clone()), config))
        .collect::<BTreeMap<_, _>>();
    for class in classes {
        let Some(config) =
            config_by_identity.get(&(class.artifact_id.clone(), class.config.clone()))
        else {
            class.activation = crate::model::ActivationStatus::Unknown;
            class.activation_reason =
                "owning mixin config could not be joined after identity binding".to_string();
            continue;
        };
        let identity_confirmed = matches!(
            class.identity_certainty.as_str(),
            "confirmed" | "self-loader-bootstrap"
        );
        (class.activation, class.activation_reason) =
            crate::activation::class_activation_for_target(
                config,
                class.side,
                target_side,
                identity_confirmed,
            );
    }
}

fn rebind_identity(cached: &mut CachedMixinJar, binding: &ArtifactBinding) {
    let CachedMixinJar::Ok(partial) = cached else {
        return;
    };
    for config in &mut partial.configs {
        if let Some(mod_id) = &binding.mod_id {
            config.mod_id.clone_from(mod_id);
        }
        config
            .identity_certainty
            .clone_from(&binding.identity_certainty);
    }
    for class in &mut partial.classes {
        if let Some(mod_id) = &binding.mod_id {
            class.mod_id.clone_from(mod_id);
        }
        class
            .identity_certainty
            .clone_from(&binding.identity_certainty);
    }
}

fn rebind_archive(cached: &mut CachedMixinJar, archive: &str) {
    match cached {
        CachedMixinJar::Ok(partial) => {
            for config in &mut partial.configs {
                config.archive = archive.to_string();
            }
            for class in &mut partial.classes {
                class.archive = archive.to_string();
            }
            for failure in &mut partial.failures {
                failure.archive = archive.to_string();
            }
        }
        CachedMixinJar::Err {
            archive: cached_archive,
            ..
        } => *cached_archive = archive.to_string(),
    }
}

/// Ingest every class in a Minecraft client/server jar into the target index.
/// Load a Yarn/Mojmap Tiny v2 file for global named↔intermediary bridging.
fn load_tiny_mappings_file(path: &Path) -> Option<TinyMappings> {
    let text = std::fs::read_to_string(path).ok()?;
    TinyMappings::parse_with_identity(&text, path.display().to_string(), None)
}

#[derive(Debug)]
struct MinecraftJarObservation {
    namespace: Option<crate::apply_failure::MinecraftClassNamespace>,
    error: Option<String>,
}

fn ingest_minecraft_jar(
    jar: &Path,
    target_index: &mut crate::apply_failure::TargetClassIndex,
    mappings: Option<&TinyMappings>,
) -> MinecraftJarObservation {
    let file = match std::fs::File::open(jar) {
        Ok(file) => file,
        Err(error) => {
            return MinecraftJarObservation {
                namespace: None,
                error: Some(format!("open {}: {error}", jar.display())),
            };
        }
    };
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(error) => {
            return MinecraftJarObservation {
                namespace: None,
                error: Some(format!("zip {}: {error}", jar.display())),
            };
        }
    };
    let mut hierarchy = HierarchyIndex::new();
    let mut candidate = crate::apply_failure::TargetClassIndex::new();
    // The vanilla jar is trusted; class-index caps still apply but truncation
    // reporting is not meaningful here.
    let truncations = index_jar_classes(
        &mut archive,
        &mut hierarchy,
        &mut candidate,
        ClassIndexSource::Minecraft,
    );
    let namespace = candidate.minecraft_class_namespace();
    let mapping_compatibility = mappings.map(TinyMappings::mapping_compatibility);
    let error = if !truncations.is_empty() {
        Some(format!(
            "Minecraft class index is incomplete: {}",
            truncations.join("; ")
        ))
    } else if let Some(compatibility) = mapping_compatibility {
        match compatibility {
            crate::refmap::MappingCompatibility::Incompatible {
                mapping_version,
                target_version,
            } => Some(format!(
                "mapping file targets Minecraft {mapping_version}, but the analyzed environment is {target_version}; absence checks were disabled"
            )),
            crate::refmap::MappingCompatibility::VersionUnverified => Some(
                "mapping file version is unknown; method/class absence checks may be unreliable"
                    .to_string(),
            ),
            crate::refmap::MappingCompatibility::Compatible => {
                let supports_namespace = !matches!(
                    namespace,
                    crate::apply_failure::MinecraftClassNamespace::OfficialObfuscated
                ) || mappings.is_some_and(|mapping| {
                    mapping.has_namespace("official")
                        && (mapping.has_namespace("named") || mapping.has_namespace("intermediary"))
                });
                if supports_namespace
                    && namespace != crate::apply_failure::MinecraftClassNamespace::Unsupported
                {
                    candidate.mark_minecraft_coverage_complete();
                    target_index.merge_explicit_minecraft(&candidate);
                    None
                } else {
                    Some(format!(
                        "Minecraft artifact uses `{}` class names without a complete compatible mapping edge; absence checks were disabled",
                        namespace.as_str()
                    ))
                }
            }
        }
    } else if matches!(
        namespace,
        crate::apply_failure::MinecraftClassNamespace::OfficialObfuscated
            | crate::apply_failure::MinecraftClassNamespace::Unsupported
    ) {
        Some(format!(
            "Minecraft artifact uses `{}` class names; absence checks were disabled \
             because no complete mapping edge connects that artifact to the analyzed targets \
             (supply a named or intermediary Minecraft jar)",
            namespace.as_str()
        ))
    } else {
        candidate.mark_minecraft_coverage_complete();
        target_index.merge_explicit_minecraft(&candidate);
        None
    };
    MinecraftJarObservation {
        namespace: Some(namespace),
        error,
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_scan(
    dir: &Path,
    configs_discovered: usize,
    configs: Vec<MixinConfigRecord>,
    classes: Vec<MixinClassRecord>,
    analysis: MixinAnalysis,
    apply_failures: Vec<crate::apply_failure::ApplyFailure>,
    recommendations: Vec<crate::model::MixinRecommendationRecord>,
    classpath_coverage: Option<crate::classpath::ClasspathCoverage>,
    target_index: Option<&crate::apply_failure::TargetClassIndex>,
    mappings: Option<&TinyMappings>,
    failures: Vec<MixinScanFailure>,
    environment_conflicted: bool,
    precision_profile: crate::profile::PrecisionProfile,
) -> MixinScan {
    // Phase 2: flatten classes into stable, site-level application records before
    // moving `classes` into the scan. Phase 5: resolve each site's target method
    // descriptor-aware against the class index.
    // Phase 18: Standard baseline depth; Phase 19 escalates hot/destructive/required
    // /fail-hard/unresolved sites to Deep automatically, so heavy checks land where
    // they matter without paying for them on every benign observer inject.
    let application_sites =
        crate::site::build_application_sites(&classes, target_index, mappings, precision_profile);
    // Phases 9–10: order + composition of handlers sharing an exact injection point.
    let compositions = crate::composition::analyze_compositions(&application_sites);
    // Cross-layer: mixins hooking Minecraft data loaders mutate runtime resources
    // (Layer F → Layer M / Dynamics bridge).
    let resource_mutations = crate::resource_bridge::detect_resource_mutations(&application_sites);
    // Cross-layer: mixin targets reveal behaviour-grounded capabilities (Layer F → B)
    // and security-sensitive subsystem hooks (Layer F → G).
    let (capabilities, security_surfaces) = crate::subsystem::derive_subsystems(&application_sites);
    // Phase 13/14: roll site/composition/apply evidence into actionable diagnoses,
    // graded under the unified confidence/severity model. Absence is only
    // conclusive when the classpath coverage permits it (plan Phase 4/14).
    let coverage_conclusive = classpath_coverage
        .as_ref()
        .map(|c| c.level.minecraft_absence_conclusive())
        .unwrap_or(false);
    let risk_clusters = crate::clusters::build_clusters(
        &application_sites,
        &apply_failures,
        &compositions,
        coverage_conclusive,
    );
    MixinScan {
        target: dir.display().to_string(),
        configs_discovered,
        configs,
        classes,
        overlaps: analysis.overlaps,
        high_risk_overwrites: analysis.high_risk_overwrites,
        interactions: analysis.interactions,
        conflict_edges: analysis.conflict_edges,
        priority_conflicts: analysis.priority_conflicts,
        risk_assessments: analysis.risk_assessments,
        mixin_effects: analysis.mixin_effects,
        recommendations,
        class_complexity: analysis.class_complexity,
        mod_complexity: analysis.mod_complexity,
        bloat: analysis.bloat,
        graph_export: Some(analysis.graph.export()),
        apply_failures,
        application_sites,
        classpath_coverage,
        compositions,
        risk_clusters,
        resource_mutations,
        capabilities,
        security_surfaces,
        failures,
        environment_conflicted,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JarScanPartial {
    #[serde(default)]
    configs_discovered: usize,
    configs: Vec<MixinConfigRecord>,
    classes: Vec<MixinClassRecord>,
    failures: Vec<MixinScanFailure>,
    #[serde(default)]
    hierarchy: HierarchyIndex,
    /// Member index of this jar's classes, for apply-failure target checks.
    #[serde(default)]
    target_index: crate::apply_failure::TargetClassIndex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CachedMixinJar {
    Ok(Box<JarScanPartial>),
    Err { archive: String, reason: String },
}

fn scan_jar_cached(
    jar: &Path,
    target_loader: Option<intermed_doctor_core::Loader>,
    allow_foreign_configs: bool,
) -> CachedMixinJar {
    match scan_jar(jar, target_loader, allow_foreign_configs) {
        Ok(partial) => CachedMixinJar::Ok(Box::new(partial)),
        Err(e) => CachedMixinJar::Err {
            archive: e.archive,
            reason: e.reason,
        },
    }
}

struct JarScanError {
    archive: String,
    reason: String,
}

fn scan_jar(
    jar: &Path,
    target_loader: Option<intermed_doctor_core::Loader>,
    allow_foreign_configs: bool,
) -> Result<JarScanPartial, JarScanError> {
    let archive_label = archive_name(jar);
    let artifact_id = hash_artifact(jar).map_err(|e| JarScanError {
        archive: archive_label.clone(),
        reason: format!("hash {}: {e}", jar.display()),
    })?;
    let file = std::fs::File::open(jar).map_err(|e| JarScanError {
        archive: archive_label.clone(),
        reason: format!("open {}: {e}", jar.display()),
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| JarScanError {
        archive: archive_label.clone(),
        reason: format!("zip {}: {e}", jar.display()),
    })?;
    // Display-only fallback. Canonical identity is supplied by Layer B through
    // ARTIFACT_ROLE; absence of that fact must remain explicit, not trigger a
    // second descriptor-selection implementation in F.
    let mod_id = archive_stem(&archive_label);
    let config_paths = discover_mixin_configs(&mut archive, target_loader, allow_foreign_configs);
    let configs_discovered = config_paths.len();
    let tiny = discover_tiny_mappings(&mut archive);
    let runtime_namespace = match target_loader {
        Some(intermed_doctor_core::Loader::Fabric | intermed_doctor_core::Loader::Quilt) => {
            Namespace::Intermediary
        }
        Some(intermed_doctor_core::Loader::Forge | intermed_doctor_core::Loader::NeoForge) => {
            Namespace::Named
        }
        _ => detect_runtime_namespace(&mut archive),
    };

    let mut hierarchy = HierarchyIndex::new();
    let mut target_index = crate::apply_failure::TargetClassIndex::new();
    let class_truncations = index_jar_classes(
        &mut archive,
        &mut hierarchy,
        &mut target_index,
        ClassIndexSource::Mod,
    );

    let mut partial = JarScanPartial {
        configs_discovered,
        configs: Vec::new(),
        classes: Vec::new(),
        failures: Vec::new(),
        hierarchy,
        target_index,
    };
    // Surface class-index caps that fired on this jar as scan failures so an
    // oversized/crafted archive is reported, not silently under-analyzed.
    for reason in class_truncations {
        partial.failures.push(MixinScanFailure {
            archive: archive_label.clone(),
            path: None,
            reason: format!("scan truncated: {reason}"),
        });
    }

    for config_path in config_paths {
        let config_result = read_zip_text(&mut archive, &config_path)
            .and_then(|opt| {
                opt.ok_or_else(|| bounded_zip::BoundedReadError::Unreadable {
                    name: config_path.clone(),
                    reason: "not found".to_string(),
                })
            })
            .and_then(|text| {
                parse_config(&archive_label, &config_path, &mod_id, &text).map_err(|e| {
                    bounded_zip::BoundedReadError::Unreadable {
                        name: config_path.clone(),
                        reason: format!("JSON parse: {e}"),
                    }
                })
            });

        match config_result {
            Ok(mut config) => {
                config.artifact_id.clone_from(&artifact_id);
                config.identity_certainty = "unresolved-display-fallback".to_string();
                let mut mapping = MappingContext::new();
                if let Some(t) = &tiny {
                    mapping = mapping.with_tiny(t.clone());
                }

                config.refmap_status = if let Some(ref rpath) = config.refmap {
                    match bounded_zip::read_zip_text_bounded(
                        &mut archive,
                        rpath,
                        bounded_zip::cap_for_entry(rpath),
                    ) {
                        Ok(Some(text)) => match Refmap::parse(&text) {
                            Ok(refmap) => {
                                mapping = mapping.with_refmap(refmap);
                                crate::refmap::RefmapStatus::DeclaredAndLoaded {
                                    path: rpath.clone(),
                                }
                            }
                            Err(e) => crate::refmap::RefmapStatus::DeclaredInvalid {
                                path: rpath.clone(),
                                reason: format!("JSON parse: {e}"),
                            },
                        },
                        Ok(None) => crate::refmap::RefmapStatus::DeclaredMissing {
                            declared_path: rpath.clone(),
                        },
                        Err(bounded_zip::BoundedReadError::TooLarge { cap, .. }) => {
                            crate::refmap::RefmapStatus::DeclaredTooLarge {
                                path: rpath.clone(),
                                cap_bytes: cap,
                            }
                        }
                        Err(bounded_zip::BoundedReadError::Unreadable { reason, .. }) => {
                            crate::refmap::RefmapStatus::DeclaredUnreadable {
                                path: rpath.clone(),
                                reason,
                            }
                        }
                    }
                } else {
                    crate::refmap::RefmapStatus::NotDeclared
                };

                let hierarchy = &partial.hierarchy;
                for mixin in &config.mixins {
                    let class_path = mixin_class_path(&config.package, mixin);
                    match read_zip_bytes(&mut archive, &class_path) {
                        Ok(Some(bytes)) => {
                            let mut rec = analyze_class(
                                &config,
                                mixin,
                                &class_path,
                                &bytes,
                                &mut mapping,
                                hierarchy,
                            );
                            rec.runtime_namespace = runtime_namespace;
                            partial.classes.push(rec);
                        }
                        Ok(None) => partial.failures.push(MixinScanFailure {
                            archive: archive_label.clone(),
                            path: Some(class_path),
                            reason: "mixin class listed in config but not found".to_string(),
                        }),
                        Err(e) => partial.failures.push(MixinScanFailure {
                            archive: archive_label.clone(),
                            path: Some(class_path),
                            reason: e.reason(),
                        }),
                    }
                }
                partial.configs.push(config);
            }
            Err(e) => partial.failures.push(MixinScanFailure {
                archive: archive_label.clone(),
                path: Some(config_path),
                reason: e.reason(),
            }),
        }
    }
    Ok(partial)
}

fn hash_artifact(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

pub(crate) fn analyze_class(
    config: &MixinConfigRecord,
    mixin: &str,
    class_path: &str,
    bytes: &[u8],
    mapping: &mut MappingContext,
    hierarchy: &HierarchyIndex,
) -> MixinClassRecord {
    let class_name = join_class_name(&config.package, mixin);
    let tiny_ref = mapping.tiny.as_ref();
    let parsed = parse_mixin_class_with_hierarchy(bytes, hierarchy, tiny_ref);
    let target_namespace = resolve_target_namespaces(&parsed.targets, tiny_ref);
    let rules = HotPathRules::default();
    let hot_paths = any_hot_path(&rules, &parsed.targets, &parsed.raw_injections);
    let injected_methods = resolve_parse(&parsed, mapping);

    // Phase 1: resolve this mixin's application side from its config provenance,
    // then its activation status (assumed-active unless plugin-gated).
    let side = config
        .mixin_sides
        .get(mixin)
        .copied()
        .unwrap_or(crate::model::Side::Both);
    let (activation, activation_reason) = crate::activation::class_activation(config, side);

    MixinClassRecord {
        archive: config.archive.clone(),
        artifact_id: config.artifact_id.clone(),
        mod_id: config.mod_id.clone(),
        identity_certainty: config.identity_certainty.clone(),
        config: config.path.clone(),
        class_name,
        class_path: class_path.to_string(),
        targets: parsed.targets.clone(),
        target_namespace,
        // Set by the caller (`scan_jar`) from the jar's loader metadata; the
        // analyzer itself has no archive handle, so default here.
        runtime_namespace: Namespace::Unknown,
        operations: parsed.operations.into_iter().collect(),
        injected_methods,
        shadows: parsed.shadows,
        added_members: parsed.added_members,
        calls: parsed.calls,
        handler_bodies: parsed.handler_bodies,
        target_hierarchy: parsed.target_hierarchy,
        priority: config.priority,
        refmap: config.refmap.clone(),
        hot_paths,
        effects: Vec::new(),
        plugin_gated: config.plugin.is_some(),
        side,
        activation,
        activation_reason,
    }
}

/// Index every `.class` for hierarchy/target analysis, bounded against a crafted
/// archive: each class is capped at [`bounded_zip::MAX_CLASS_BYTES`] and the
/// aggregate at [`bounded_zip::MAX_CLASS_INDEX_BYTES_TOTAL`]. Returns the
/// `scan_truncated` reasons for any class skipped by a cap.
fn index_jar_classes(
    archive: &mut zip::ZipArchive<std::fs::File>,
    hierarchy: &mut HierarchyIndex,
    target_index: &mut crate::apply_failure::TargetClassIndex,
    source: ClassIndexSource,
) -> Vec<String> {
    let mut truncations = Vec::new();
    let mut total: u64 = 0;
    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        if !entry.name().ends_with(".class") {
            continue;
        }
        let name = entry.name().to_string();
        if entry.size() > bounded_zip::MAX_CLASS_BYTES {
            truncations.push(format!(
                "{name}: {} bytes exceeds {} byte class cap, skipped",
                entry.size(),
                bounded_zip::MAX_CLASS_BYTES
            ));
            continue;
        }
        if total >= bounded_zip::MAX_CLASS_INDEX_BYTES_TOTAL {
            truncations.push(format!(
                "reached {} byte class-index cap; remaining classes skipped",
                bounded_zip::MAX_CLASS_INDEX_BYTES_TOTAL
            ));
            break;
        }
        // Enforce the per-class cap on the *decompressed* stream so a lying header
        // cannot inflate past the limit.
        let mut bytes = Vec::new();
        if std::io::Read::take(&mut entry, bounded_zip::MAX_CLASS_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .is_err()
        {
            continue;
        }
        if bytes.len() as u64 > bounded_zip::MAX_CLASS_BYTES {
            truncations.push(format!("{name}: decompressed past class cap, skipped"));
            continue;
        }
        total = total.saturating_add(bytes.len() as u64);
        hierarchy.ingest_class(&bytes);
        match source {
            ClassIndexSource::Mod => target_index.ingest_class(&bytes),
            ClassIndexSource::Minecraft => target_index.ingest_minecraft_class(&bytes),
        }
    }
    truncations
}

#[derive(Debug, Clone, Copy)]
enum ClassIndexSource {
    Mod,
    Minecraft,
}

fn discover_tiny_mappings(archive: &mut zip::ZipArchive<std::fs::File>) -> Option<TinyMappings> {
    for name in [
        "mappings/mappings.tiny",
        "META-INF/mappings.tiny",
        "mappings.tiny",
    ] {
        if let Ok(Some(text)) = read_zip_text(archive, name)
            && let Some(map) =
                TinyMappings::parse_with_identity(&text, format!("embedded:{name}"), None)
        {
            return Some(map);
        }
    }
    None
}

/// Discover a jar's mixin config files across every loader in one pass:
/// Fabric `fabric.mod.json:mixins`, Quilt `quilt_loader.mixins`, Forge/NeoForge
/// `MANIFEST.MF` `MixinConfigs` *and* `mods.toml` `[[mixins]] config`. Globbing is
/// only a fallback for descriptor-less legacy/coremod jars: when authoritative
/// loader metadata exists and declares no configs, a leftover `*.mixins.json` is
/// inactive and must not create facts or incomplete-scan warnings.
fn discover_mixin_configs(
    archive: &mut zip::ZipArchive<std::fs::File>,
    target_loader: Option<intermed_doctor_core::Loader>,
    allow_foreign_configs: bool,
) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let fabric = read_zip_text(archive, "fabric.mod.json").ok().flatten();
    let quilt = read_zip_text(archive, "quilt.mod.json").ok().flatten();
    let manifest = read_zip_text(archive, "META-INF/MANIFEST.MF")
        .ok()
        .flatten();
    let forge = read_zip_text(archive, "META-INF/mods.toml").ok().flatten();
    let neoforge = read_zip_text(archive, "META-INF/neoforge.mods.toml")
        .ok()
        .flatten();
    let fabric_is_concrete = fabric.as_deref().is_some_and(json_descriptor_is_concrete);
    let quilt_is_concrete = quilt.as_deref().is_some_and(json_descriptor_is_concrete);
    let forge_is_concrete = forge.as_deref().is_some_and(toml_descriptor_is_concrete);
    let neoforge_is_concrete = neoforge.as_deref().is_some_and(toml_descriptor_is_concrete);
    let has_loader_descriptor =
        fabric_is_concrete || quilt_is_concrete || forge_is_concrete || neoforge_is_concrete;
    let compatible_descriptor = match target_loader {
        Some(intermed_doctor_core::Loader::Fabric) => fabric_is_concrete,
        Some(intermed_doctor_core::Loader::Quilt) => quilt_is_concrete || fabric_is_concrete,
        Some(intermed_doctor_core::Loader::Forge) => forge_is_concrete,
        Some(intermed_doctor_core::Loader::NeoForge) => neoforge_is_concrete || forge_is_concrete,
        _ => false,
    };

    if compatible_descriptor {
        match target_loader {
            Some(intermed_doctor_core::Loader::Fabric) => {
                if let Some(text) = fabric {
                    out.extend(mixin_paths_from_json(&text, &["mixins"]));
                }
            }
            Some(intermed_doctor_core::Loader::Quilt) if quilt_is_concrete => {
                if let Some(text) = quilt {
                    out.extend(mixin_paths_from_json(&text, &["quilt_loader", "mixins"]));
                    out.extend(mixin_paths_from_json(&text, &["mixins"]));
                }
            }
            Some(intermed_doctor_core::Loader::Quilt) => {
                if let Some(text) = fabric {
                    out.extend(mixin_paths_from_json(&text, &["mixins"]));
                }
            }
            Some(intermed_doctor_core::Loader::Forge) => {
                if let Some(text) = manifest {
                    out.extend(mixin_paths_from_manifest(&text));
                }
                if let Some(text) = forge {
                    out.extend(mixin_paths_from_mods_toml(&text));
                }
            }
            Some(intermed_doctor_core::Loader::NeoForge) => {
                if let Some(text) = manifest {
                    out.extend(mixin_paths_from_manifest(&text));
                }
                if neoforge_is_concrete {
                    if let Some(text) = neoforge {
                        out.extend(mixin_paths_from_mods_toml(&text));
                    }
                } else if let Some(text) = forge {
                    out.extend(mixin_paths_from_mods_toml(&text));
                }
            }
            _ => {}
        }
    } else if target_loader.is_some() && has_loader_descriptor && !allow_foreign_configs {
        // A concrete foreign descriptor is inactive on the authoritative target
        // loader unless a classloading bridge says it may participate.
    } else {
        if fabric_is_concrete && let Some(text) = fabric {
            out.extend(mixin_paths_from_json(&text, &["mixins"]));
        }
        if quilt_is_concrete && let Some(text) = quilt {
            out.extend(mixin_paths_from_json(&text, &["quilt_loader", "mixins"]));
            out.extend(mixin_paths_from_json(&text, &["mixins"]));
        }
        if let Some(text) = manifest {
            out.extend(mixin_paths_from_manifest(&text));
        }
        if forge_is_concrete && let Some(text) = forge {
            out.extend(mixin_paths_from_mods_toml(&text));
        }
        if neoforge_is_concrete && let Some(text) = neoforge {
            out.extend(mixin_paths_from_mods_toml(&text));
        }
    }
    if out.is_empty() && !has_loader_descriptor {
        out.extend(glob_mixin_configs(archive));
    }
    // Manifest `MixinConfigs` values are classpath-level declarations. Shaded
    // build metadata commonly retains a dependency's config name even though
    // that resource lives in another artifact (or the dependency was later
    // unshaded). Treating every non-local declaration as a failed local parse
    // produces false incomplete-scan warnings. Local configs are analyzed here;
    // provider artifacts are scanned independently.
    out.into_iter()
        .filter(|path| archive.by_name(path).is_ok())
        .collect()
}

/// The class namespace this jar's loader presents to mixins **at runtime**,
/// inferred from which loader-metadata file the jar ships.
///
/// Forge/NeoForge run mixins against official Mojang class names (since 1.20.1);
/// Fabric/Quilt run against the obfuscated→intermediary namespace. A `remap=false`
/// reference is taken verbatim, so it only resolves when it is *already* written
/// in this runtime namespace — which is exactly what the apply-failure checks
/// compare against. A multi-loader jar that ships both manifests is ambiguous
/// (its runtime depends on the instance it is installed into), so it is reported
/// `Unknown` and the namespace-mismatch checks stay silent rather than guess.
fn detect_runtime_namespace(archive: &mut zip::ZipArchive<std::fs::File>) -> Namespace {
    let forge = read_zip_text(archive, "META-INF/mods.toml")
        .ok()
        .flatten()
        .as_deref()
        .is_some_and(toml_descriptor_is_concrete)
        || read_zip_text(archive, "META-INF/neoforge.mods.toml")
            .ok()
            .flatten()
            .as_deref()
            .is_some_and(toml_descriptor_is_concrete);
    let fabric = read_zip_text(archive, "fabric.mod.json")
        .ok()
        .flatten()
        .as_deref()
        .is_some_and(json_descriptor_is_concrete)
        || read_zip_text(archive, "quilt.mod.json")
            .ok()
            .flatten()
            .as_deref()
            .is_some_and(json_descriptor_is_concrete);
    match (forge, fabric) {
        (true, false) => Namespace::Named,
        (false, true) => Namespace::Intermediary,
        _ => Namespace::Unknown,
    }
}

fn concrete_declared_id(value: &str) -> bool {
    !value.trim().is_empty() && !value.contains("${") && !value.contains('@')
}

fn json_descriptor_is_concrete(text: &str) -> bool {
    let Ok(value) = intermed_doctor_core::fabric_json::parse_value(text) else {
        return false;
    };
    value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .pointer("/quilt_loader/id")
                .and_then(serde_json::Value::as_str)
        })
        .is_some_and(concrete_declared_id)
}

fn toml_descriptor_is_concrete(text: &str) -> bool {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return false;
    };
    value
        .get("mods")
        .and_then(toml::Value::as_array)
        .is_some_and(|mods| {
            mods.iter().any(|entry| {
                entry
                    .get("modId")
                    .or_else(|| entry.get("mod_id"))
                    .and_then(toml::Value::as_str)
                    .is_some_and(concrete_declared_id)
            })
        })
}

/// Extract `config = "x.mixins.json"` entries from a Forge/NeoForge `mods.toml`,
/// reading `config` **only inside a `[[mixins]]` table**.
///
/// A naive scan for any `config = …` line is wrong: `mods.toml` has unrelated
/// `config` keys elsewhere (and `[[dependencies]]` tables), so the parser must
/// track which TOML section it is in. Prefer a real parse; fall back to a
/// section-aware state machine if the file does not parse.
fn mixin_paths_from_mods_toml(text: &str) -> Vec<String> {
    if let Ok(value) = toml::from_str::<toml::Value>(text) {
        if let Some(arr) = value.get("mixins").and_then(|m| m.as_array()) {
            return arr
                .iter()
                .filter_map(|m| m.get("config").and_then(|c| c.as_str()))
                .filter(|p| p.ends_with(".json") && is_safe_path(p))
                .map(str::to_string)
                .collect();
        }
        // Parsed fine but no [[mixins]] table → nothing to report.
        if value.is_table() {
            return Vec::new();
        }
    }
    // Fallback: state machine that only honors `config` inside `[[mixins]]`.
    let mut out = Vec::new();
    let mut in_mixins = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_mixins = line == "[[mixins]]";
            continue;
        }
        if !in_mixins {
            continue;
        }
        let Some(rest) = line.strip_prefix("config") else {
            continue;
        };
        let Some(value) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let path = value.trim().trim_matches('"');
        if path.ends_with(".json") && is_safe_path(path) {
            out.push(path.to_string());
        }
    }
    out
}

/// Fallback: archive entries that look like mixin configs by name (`*.mixins.json`
/// or `mixins.*.json`), at any depth. Used only when no manifest declared them.
fn glob_mixin_configs(archive: &mut zip::ZipArchive<std::fs::File>) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        let name = entry.name();
        let file = name.rsplit('/').next().unwrap_or(name);
        let looks_like_config = file.ends_with(".mixins.json")
            || (file.starts_with("mixins.") && file.ends_with(".json"));
        if looks_like_config && is_safe_path(name) {
            out.push(name.to_string());
        }
    }
    out
}

fn mixin_paths_from_json(text: &str, path: &[&str]) -> Vec<String> {
    let Ok(v) = intermed_doctor_core::fabric_json::parse_value(text) else {
        return Vec::new();
    };
    let mut cur = &v;
    for key in path {
        let Some(next) = cur.get(*key) else {
            return Vec::new();
        };
        cur = next;
    }
    match cur {
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(mixin_config_entry_path)
            .filter(|p| is_safe_path(p))
            .collect(),
        serde_json::Value::String(s) if is_safe_path(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// A Fabric/Quilt `mixins` array entry is either a bare string config path or an
/// object `{ "config": "foo.mixins.json", "environment": "client" }`. The old
/// code read only strings, silently dropping every object-form config (common in
/// client/server-split mods).
fn mixin_config_entry_path(entry: &serde_json::Value) -> Option<String> {
    match entry {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => {
            o.get("config").and_then(|c| c.as_str()).map(str::to_string)
        }
        _ => None,
    }
}

fn mixin_paths_from_manifest(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in unfold_manifest_lines(text) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("MixinConfigs") {
            for part in value.split(',') {
                let path = part.trim();
                if is_safe_path(path) {
                    out.push(path.to_string());
                }
            }
        }
    }
    out
}

/// Unfold JMF (`META-INF/MANIFEST.MF`) continuation lines.
///
/// A `META-INF/MANIFEST.MF` header value wraps at 72 bytes and continues on the
/// next physical line, which begins with a single leading space. Reading the
/// manifest line-by-line without unfolding truncates a long `MixinConfigs:`
/// value mid-list and silently drops the wrapped configs.
fn unfold_manifest_lines(text: &str) -> Vec<String> {
    let mut logical: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(cont) = line.strip_prefix(' ')
            && let Some(last) = logical.last_mut()
        {
            last.push_str(cont);
            continue;
        }
        logical.push(line.to_string());
    }
    logical
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
    #[serde(default)]
    plugin: Option<String>,
}

fn parse_config(
    archive: &str,
    path: &str,
    mod_id: &str,
    text: &str,
) -> Result<MixinConfigRecord, serde_json::Error> {
    let raw: RawMixinConfig =
        serde_json::from_value(intermed_doctor_core::fabric_json::parse_value(text)?)?;
    let mut mixins = std::collections::BTreeSet::new();
    // Per-mixin side, keyed by short name. The array a mixin appears in sets the
    // default side (`mixins` ⇒ both, `client`/`server` ⇒ that side); an object-form
    // `environment` overrides it. The same mixin in more than one array widens
    // (Side::merge) — declared for both sides ⇒ Both. This preserves the meaning the
    // old code dropped by flattening all three arrays into one set.
    let mut mixin_sides: std::collections::BTreeMap<String, crate::model::Side> =
        std::collections::BTreeMap::new();
    for (entries, array_default) in [
        (&raw.mixins, crate::model::Side::Both),
        (&raw.client, crate::model::Side::Client),
        (&raw.server, crate::model::Side::Server),
    ] {
        for value in entries {
            if let Some(name) = mixin_name(value) {
                let side = crate::activation::entry_side(value, array_default);
                mixin_sides
                    .entry(name.clone())
                    .and_modify(|s| *s = s.merge(side))
                    .or_insert(side);
                mixins.insert(name);
            }
        }
    }

    Ok(MixinConfigRecord {
        archive: archive.to_string(),
        artifact_id: String::new(),
        path: path.to_string(),
        mod_id: mod_id.to_string(),
        identity_certainty: "unresolved-display-fallback".to_string(),
        package: raw.package,
        priority: raw.priority.unwrap_or(1000),
        refmap: raw.refmap,
        refmap_status: crate::refmap::RefmapStatus::default(),
        mixins: mixins.into_iter().collect(),
        plugin: raw.plugin.filter(|p| !p.trim().is_empty()),
        mixin_sides,
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

fn mixin_class_path(package: &str, mixin: &str) -> String {
    format!(
        "{}.class",
        join_class_name(package, mixin).replace('.', "/")
    )
}

/// Build named↔intermediary aliases for mixin targets using this jar's Tiny file.
fn resolve_target_namespaces(
    targets: &[String],
    tiny: Option<&TinyMappings>,
) -> std::collections::BTreeMap<String, TargetNamespace> {
    let Some(map) = tiny else {
        return std::collections::BTreeMap::new();
    };
    let mut out = std::collections::BTreeMap::new();
    for target in targets {
        let slash = target.replace('.', "/");
        let mut ns = TargetNamespace::default();
        if let Some(inter) = map.to_intermediary_class(target) {
            ns.intermediary = Some(dotted_name(&inter));
        }
        if let Some(named) = map.to_named_class(&slash) {
            ns.named = Some(named);
        } else if !target.contains("class_") {
            ns.named = Some(target.clone());
        }
        if ns.named.is_some() || ns.intermediary.is_some() {
            out.insert(target.clone(), ns);
        }
    }
    out
}

pub(crate) fn join_class_name(package: &str, mixin: &str) -> String {
    // Mixin entries in `mixins`/`client`/`server` are *always* relative to
    // `package`; dots inside them denote sub-packages (`accessor.FooAccessor`),
    // not a fully-qualified name. The only time an entry is already absolute is
    // when the config declares no package at all.
    if package.is_empty() {
        mixin.to_string()
    } else {
        format!("{package}.{mixin}")
    }
}

pub(crate) fn mods_dir(target: &Target) -> Option<PathBuf> {
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
        .map(str::to_string)
        .unwrap_or_else(|| "?".to_string())
}

fn archive_stem(name: &str) -> String {
    name.strip_suffix(".jar").unwrap_or(name).to_string()
}

fn is_safe_path(path: &str) -> bool {
    !path.starts_with('/')
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

/// Bounded text read (config, refmap, manifest); cap chosen by entry name.
/// `Ok(None)` means the entry is absent; `Err` preserves too-large/unreadable
/// states so callers can surface incomplete coverage instead of treating them
/// as an ordinary missing entry.
fn read_zip_text(
    archive: &mut zip::ZipArchive<std::fs::File>,
    name: &str,
) -> Result<Option<String>, bounded_zip::BoundedReadError> {
    bounded_zip::read_zip_text_bounded(archive, name, bounded_zip::cap_for_entry(name))
}

/// Bounded byte read (mixin `.class` files); cap chosen by entry name.
/// Returns `Err` for TooLarge/Unreadable so callers can surface scan truncation.
fn read_zip_bytes(
    archive: &mut zip::ZipArchive<std::fs::File>,
    name: &str,
) -> Result<Option<Vec<u8>>, bounded_zip::BoundedReadError> {
    bounded_zip::read_zip_bytes_bounded(archive, name, bounded_zip::cap_for_entry(name))
}
#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn canonical_server_side_deactivates_parsed_client_mixin() {
        let mut mixin_sides = BTreeMap::new();
        mixin_sides.insert("ClientMixin".to_string(), crate::model::Side::Client);
        let config = MixinConfigRecord {
            archive: "client.jar".into(),
            artifact_id: "sha256:client".into(),
            mod_id: "client".into(),
            identity_certainty: "confirmed".into(),
            path: "client.mixins.json".into(),
            package: "client.mixin".into(),
            priority: 1000,
            refmap: None,
            refmap_status: crate::refmap::RefmapStatus::NotDeclared,
            mixins: vec!["ClientMixin".into()],
            plugin: None,
            mixin_sides,
        };
        let bytes = crate::fixtures::mixin_class_with_inject_at(
            "client/mixin/ClientMixin",
            "net/minecraft/client/Minecraft",
            "tick()V",
            "HEAD",
        );
        let mut classes = vec![analyze_class(
            &config,
            "ClientMixin",
            "client/mixin/ClientMixin.class",
            &bytes,
            &mut MappingContext::new(),
            &HierarchyIndex::new(),
        )];
        apply_target_activation(
            std::slice::from_ref(&config),
            &mut classes,
            crate::model::Side::Server,
        );
        assert_eq!(
            classes[0].activation,
            crate::model::ActivationStatus::InactiveBySide
        );
    }

    fn discovery_jar(entries: &[(&str, &[u8])]) -> std::path::PathBuf {
        use std::io::Write;

        let path = std::env::temp_dir().join(format!(
            "intermed-mixin-discovery-{}-{}.jar",
            std::process::id(),
            rand_suffix(entries)
        ));
        let file = std::fs::File::create(&path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        for (name, bytes) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
        path
    }

    fn rand_suffix(entries: &[(&str, &[u8])]) -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            ^ entries.len() as u128
    }

    #[test]
    fn authoritative_empty_fabric_mixin_list_disables_leftover_config() {
        let path = discovery_jar(&[
            ("fabric.mod.json", br#"{"id":"reacharound","mixins":[]}"#),
            (
                "reacharound.mixins.json",
                br#"{"package":"example.mixin","client":["MissingMixin"]}"#,
            ),
        ]);
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        assert!(discover_mixin_configs(&mut archive, None, false).is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn descriptorless_legacy_jar_still_uses_config_glob_fallback() {
        let path = discovery_jar(&[(
            "legacy.mixins.json",
            br#"{"package":"example.mixin","mixins":[]}"#,
        )]);
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        assert_eq!(
            discover_mixin_configs(&mut archive, None, false),
            vec!["legacy.mixins.json"]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn inactive_templated_neoforge_descriptor_does_not_pollute_fabric_mixins() {
        let path = discovery_jar(&[
            (
                "fabric.mod.json",
                br#"{"id":"configurable","mixins":["configurable.mixins.json"]}"#,
            ),
            (
                "META-INF/neoforge.mods.toml",
                br#"modLoader="javafml"
[[mods]]
modId="${mod_id}"
version="${version}"
[[mixins]]
config="${mod_id}.mixins.json"
"#,
            ),
            (
                "configurable.mixins.json",
                br#"{"package":"example.mixin","mixins":[]}"#,
            ),
        ]);
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        assert_eq!(
            discover_mixin_configs(
                &mut archive,
                Some(intermed_doctor_core::Loader::Fabric),
                false,
            ),
            vec!["configurable.mixins.json"]
        );
        assert_eq!(
            detect_runtime_namespace(&mut archive),
            Namespace::Intermediary
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn classpath_manifest_reference_missing_from_jar_is_not_a_parse_failure() {
        let path = discovery_jar(&[
            (
                "META-INF/MANIFEST.MF",
                b"Manifest-Version: 1.0\r\nMixinConfigs: dependency.mixins.json,local.mixins.json\r\n",
            ),
            (
                "META-INF/mods.toml",
                br#"modLoader="javafml"
[[mods]]
modId="example"
version="1"
"#,
            ),
            (
                "local.mixins.json",
                br#"{"package":"example.mixin","mixins":[]}"#,
            ),
        ]);
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        assert_eq!(
            discover_mixin_configs(&mut archive, None, false),
            vec!["local.mixins.json"]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn authoritative_loader_selects_only_its_descriptor_configs() {
        let path = discovery_jar(&[
            (
                "fabric.mod.json",
                br#"{"id":"puzzle","mixins":["fabric.mixins.json"]}"#,
            ),
            (
                "META-INF/neoforge.mods.toml",
                br#"modLoader="javafml"
[[mods]]
modId="puzzle"
version="1"
[[mixins]]
config="neoforge.mixins.json"
"#,
            ),
            ("fabric.mixins.json", br#"{"package":"fabric","mixins":[]}"#),
            (
                "neoforge.mixins.json",
                br#"{"package":"neoforge","mixins":["Missing"]}"#,
            ),
        ]);
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        assert_eq!(
            discover_mixin_configs(
                &mut archive,
                Some(intermed_doctor_core::Loader::Fabric),
                false,
            ),
            vec!["fabric.mixins.json"]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn foreign_descriptor_configs_require_a_runtime_bridge() {
        let path = discovery_jar(&[
            (
                "fabric.mod.json",
                br#"{"id":"bridged","mixins":["fabric.mixins.json"]}"#,
            ),
            ("fabric.mixins.json", br#"{"package":"fabric","mixins":[]}"#),
        ]);
        let file = std::fs::File::open(&path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        assert!(
            discover_mixin_configs(
                &mut archive,
                Some(intermed_doctor_core::Loader::NeoForge),
                false,
            )
            .is_empty()
        );
        assert_eq!(
            discover_mixin_configs(
                &mut archive,
                Some(intermed_doctor_core::Loader::NeoForge),
                true,
            ),
            vec!["fabric.mixins.json"]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejected_official_jar_preserves_observed_namespace_without_coverage() {
        use std::io::Write;

        let path = std::env::temp_dir().join(format!(
            "intermed-official-observation-{}-{}.jar",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let file = std::fs::File::create(&path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        for index in 0..40 {
            let name = format!("x{index}");
            archive
                .start_file(
                    format!("{name}.class"),
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
            archive
                .write_all(&crate::fixtures::class_with_method(&name, "a", "()V"))
                .unwrap();
        }
        archive.finish().unwrap();

        let mappings = TinyMappings::parse(
            "tiny\t2\t0\tintermediary\tnamed\n\
             c\tnet/minecraft/class_1297\tnet/minecraft/world/entity/Entity\n",
        )
        .unwrap();
        let mut target_index = crate::apply_failure::TargetClassIndex::new();
        let observation = ingest_minecraft_jar(&path, &mut target_index, Some(&mappings));
        std::fs::remove_file(path).unwrap();

        assert_eq!(
            observation.namespace,
            Some(crate::apply_failure::MinecraftClassNamespace::OfficialObfuscated)
        );
        assert!(observation.error.is_some());
        assert!(!target_index.has_minecraft_coverage());
    }

    #[test]
    fn forge_mods_toml_mixins_block_is_parsed() {
        let toml = r#"
modLoader="javafml"
[[mods]]
modId="example"
[[mixins]]
config="example.mixins.json"
[[mixins]]
config = "example.client.mixins.json"
"#;
        let paths = mixin_paths_from_mods_toml(toml);
        assert_eq!(
            paths,
            vec!["example.mixins.json", "example.client.mixins.json"]
        );
    }

    #[test]
    fn mods_toml_only_reads_config_inside_mixins_table() {
        // A `config` key in another table (here a [[dependencies]]-style block)
        // must NOT be picked up — only `[[mixins]] config` counts. The old line
        // scan wrongly grabbed any `config = …` line.
        let toml = r#"
[[dependencies.example]]
modId="other"
config="not-a-mixin.json"
[[mixins]]
config="real.mixins.json"
"#;
        assert_eq!(mixin_paths_from_mods_toml(toml), vec!["real.mixins.json"]);
    }

    #[test]
    fn mods_toml_rejects_unsafe_mixin_path() {
        let toml = "[[mixins]]\nconfig=\"../escape.mixins.json\"\n";
        assert!(mixin_paths_from_mods_toml(toml).is_empty());
    }

    #[test]
    fn fabric_object_form_mixin_entries_are_discovered() {
        // Fabric/Quilt `mixins` may be objects `{config, environment}`, not just
        // strings; the old reader dropped these silently.
        let json = r#"{
            "mixins": [
                "plain.mixins.json",
                {"config": "client.mixins.json", "environment": "client"}
            ]
        }"#;
        let paths = mixin_paths_from_json(json, &["mixins"]);
        assert!(paths.contains(&"plain.mixins.json".to_string()));
        assert!(paths.contains(&"client.mixins.json".to_string()));
    }

    #[test]
    fn manifest_continuation_lines_are_unfolded() {
        // A MixinConfigs header wrapped across two physical lines (the second
        // starting with a space) must reassemble into the full list.
        let mf = "Manifest-Version: 1.0\r\nMixinConfigs: a.mixins.json,\r\n b.mixins.json\r\n";
        let paths = mixin_paths_from_manifest(mf);
        assert_eq!(paths, vec!["a.mixins.json", "b.mixins.json"]);
    }

    #[test]
    fn config_plugin_is_parsed() {
        let json = r#"{"package":"x","plugin":"com.example.MyPlugin","mixins":["A"]}"#;
        let rec = parse_config("a.jar", "x.mixins.json", "x", json).unwrap();
        assert_eq!(rec.plugin.as_deref(), Some("com.example.MyPlugin"));
    }

    #[test]
    fn config_records_per_mixin_side_from_arrays_and_environment() {
        use crate::model::Side;
        // `mixins` ⇒ Both, `client` ⇒ Client, `server` ⇒ Server; an object-form
        // `environment` overrides the array default.
        let json = r#"{
            "package": "x",
            "mixins": ["Common", {"config":"ignored","class":"PinnedClient","environment":"client"}],
            "client": ["RenderA"],
            "server": ["TickB"]
        }"#;
        let rec = parse_config("a.jar", "x.mixins.json", "x", json).unwrap();
        assert_eq!(rec.mixin_sides.get("Common"), Some(&Side::Both));
        assert_eq!(rec.mixin_sides.get("PinnedClient"), Some(&Side::Client));
        assert_eq!(rec.mixin_sides.get("RenderA"), Some(&Side::Client));
        assert_eq!(rec.mixin_sides.get("TickB"), Some(&Side::Server));
    }

    #[test]
    fn mixin_in_both_client_and_server_widens_to_both() {
        use crate::model::Side;
        let json = r#"{"package":"x","client":["Dual"],"server":["Dual"]}"#;
        let rec = parse_config("a.jar", "x.mixins.json", "x", json).unwrap();
        assert_eq!(rec.mixin_sides.get("Dual"), Some(&Side::Both));
    }
}
