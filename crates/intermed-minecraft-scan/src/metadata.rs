//! Layer B — mod & plugin metadata.
//!
//! For every jar under the target's mods (and `plugins/`) directory, open the
//! archive (a zip) and parse whatever manifest it contains. This is the
//! JVM-free discovery of loader descriptors and structural identity evidence.
//! Basic/standard modes parse manifests; full mode also performs bounded class
//! scanning for Forge annotations, package ownership, capabilities and targeted
//! bytecode references. Layer F remains responsible for Mixin transformation
//! semantics rather than ordinary artifact identity.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use sha2::{Digest, Sha256};

use intermed_doctor_core::bounded_zip;
use intermed_doctor_core::facts::{SourceRef, kind};
use intermed_doctor_core::jar_meta;
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, CollectorScope, CompletenessModel, Layer, Loader,
    MetadataLevel, Target, TargetRegion, environment::resolve_environment_field,
};
use serde::{Deserialize, Serialize};

use crate::access;
use crate::forge_annotation;
use crate::identity::DescriptorKind as Descriptor;

mod plugin;
mod quilt;
mod roles;
mod roots;

use plugin::parse_plugin_yml;
use roles::ArtifactRole;

/// Cache key version for this collector's payload. The crate version invalidates
/// the cache automatically on every release; bump the trailing revision when the
/// scan/parse logic changes within a single release.
const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "-r36");
const MAX_PACK_CALL_EDGES: usize = 20_000;
const MAX_FABRIC_DEPENDENCY_OVERRIDES_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DependencyOverrideOperation {
    Add,
    Remove,
    Replace,
}

#[derive(Clone, Debug)]
struct DependencyOverrideEntry {
    operation: DependencyOverrideOperation,
    relation: &'static str,
    deps: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
struct FabricDependencyOverrides {
    source: PathBuf,
    sha256: String,
    by_mod: BTreeMap<String, Vec<DependencyOverrideEntry>>,
}

#[derive(Default)]
struct AppliedDependencyOverride {
    affected: bool,
    added: BTreeSet<(String, String)>,
}

struct DependencyEmissionPolicy<'a> {
    overrides: Option<&'a FabricDependencyOverrides>,
    applied: &'a AppliedDependencyOverride,
    authoritative: bool,
}

fn minecraft_uses_legacy_forge_descriptor(version: &str) -> bool {
    let mut parts = version.split(['.', '-']);
    matches!(
        (
            parts.next().and_then(|v| v.parse::<u32>().ok()),
            parts.next().and_then(|v| v.parse::<u32>().ok())
        ),
        (Some(1), Some(0..=12))
    )
}

fn dependency_relation(key: &str) -> Option<(&'static str, bool)> {
    match key {
        "depends" => Some(("depends", true)),
        "recommends" => Some(("recommends", false)),
        "suggests" => Some(("suggests", false)),
        "conflicts" => Some(("conflicts", false)),
        "breaks" => Some(("breaks", false)),
        _ => None,
    }
}

fn fabric_dependency_override_path(target: &Target) -> Option<PathBuf> {
    let mut roots = target.candidate_roots();
    if let Some(mods_dir) = target.mods_dir()
        && let Some(parent) = mods_dir.parent()
    {
        roots.push(parent.to_path_buf());
    }
    roots.sort();
    roots.dedup();
    roots
        .into_iter()
        .map(|root| root.join("config/fabric_loader_dependencies.json"))
        .find(|path| path.is_file())
}

fn load_fabric_dependency_overrides(
    target: &Target,
) -> Result<Option<FabricDependencyOverrides>, (PathBuf, String)> {
    let Some(path) = fabric_dependency_override_path(target) else {
        return Ok(None);
    };
    parse_fabric_dependency_overrides(&path)
        .map(Some)
        .map_err(|reason| (path, reason))
}

fn parse_fabric_dependency_overrides(path: &Path) -> Result<FabricDependencyOverrides, String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("cannot open Fabric dependency overrides: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_FABRIC_DEPENDENCY_OVERRIDES_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read Fabric dependency overrides: {error}"))?;
    if bytes.len() as u64 > MAX_FABRIC_DEPENDENCY_OVERRIDES_BYTES {
        return Err(format!(
            "Fabric dependency overrides exceed the {} byte limit",
            MAX_FABRIC_DEPENDENCY_OVERRIDES_BYTES
        ));
    }
    let root: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid Fabric dependency overrides JSON: {error}"))?;
    let object = root
        .as_object()
        .ok_or_else(|| "Fabric dependency overrides root must be an object".to_string())?;
    if object
        .keys()
        .any(|key| key != "version" && key != "overrides")
    {
        return Err("Fabric dependency overrides contain an unsupported root key".to_string());
    }
    if object.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err("Fabric dependency overrides version must be 1".to_string());
    }
    let overrides = object
        .get("overrides")
        .map_or_else(|| Ok(None), |value| value.as_object().map(Some).ok_or(()))
        .map_err(|()| "Fabric dependency overrides must be an object".to_string())?;
    let mut by_mod = BTreeMap::new();
    if let Some(overrides) = overrides {
        for (mod_id, raw_entries) in overrides {
            let raw_entries = raw_entries.as_object().ok_or_else(|| {
                format!("dependency override container for {mod_id} must be an object")
            })?;
            let mut entries = Vec::new();
            for (raw_kind, raw_deps) in raw_entries {
                let (operation, kind_name) = match raw_kind.as_bytes().first() {
                    Some(b'+') => (DependencyOverrideOperation::Add, &raw_kind[1..]),
                    Some(b'-') => (DependencyOverrideOperation::Remove, &raw_kind[1..]),
                    _ => (DependencyOverrideOperation::Replace, raw_kind.as_str()),
                };
                let Some((relation, _)) = dependency_relation(kind_name) else {
                    return Err(format!(
                        "unsupported Fabric dependency override kind: {raw_kind}"
                    ));
                };
                let dependency_map = raw_deps.as_object().ok_or_else(|| {
                    format!("Fabric dependency override {raw_kind} must be an object")
                })?;
                let mut deps = Vec::new();
                for (dep_id, raw_range) in dependency_map {
                    let valid_range = raw_range.is_string()
                        || raw_range
                            .as_array()
                            .is_some_and(|values| values.iter().all(serde_json::Value::is_string));
                    if !valid_range {
                        return Err(format!(
                            "Fabric dependency override range for {mod_id}->{dep_id} must be a string or string array"
                        ));
                    }
                    deps.push((dep_id.clone(), json_range(raw_range)));
                }
                entries.push(DependencyOverrideEntry {
                    operation,
                    relation,
                    deps,
                });
            }
            by_mod.insert(mod_id.clone(), entries);
        }
    }
    Ok(FabricDependencyOverrides {
        source: path.to_path_buf(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        by_mod,
    })
}

impl FabricDependencyOverrides {
    fn apply(&self, artifact: &mut Artifact) -> AppliedDependencyOverride {
        let Some(entries) = self.by_mod.get(&artifact.id) else {
            return AppliedDependencyOverride::default();
        };
        let mut applied = AppliedDependencyOverride {
            affected: true,
            added: BTreeSet::new(),
        };
        for relation in ["depends", "recommends", "suggests", "conflicts", "breaks"] {
            let relation_entries = entries
                .iter()
                .filter(|entry| entry.relation == relation)
                .collect::<Vec<_>>();
            if relation_entries.is_empty() {
                continue;
            }
            let replace = relation_entries
                .iter()
                .find(|entry| entry.operation == DependencyOverrideOperation::Replace);
            if let Some(replace) = replace {
                artifact.deps.retain(|dep| dep.relation != relation);
                add_override_dependencies(artifact, replace, &mut applied.added);
                continue;
            }
            for entry in relation_entries
                .iter()
                .filter(|entry| entry.operation == DependencyOverrideOperation::Remove)
            {
                artifact.deps.retain(|dep| {
                    dep.relation != relation || !entry.deps.iter().any(|(id, _)| id == &dep.id)
                });
            }
            for entry in relation_entries
                .iter()
                .filter(|entry| entry.operation == DependencyOverrideOperation::Add)
            {
                add_override_dependencies(artifact, entry, &mut applied.added);
            }
        }
        applied
    }
}

fn add_override_dependencies(
    artifact: &mut Artifact,
    entry: &DependencyOverrideEntry,
    added: &mut BTreeSet<(String, String)>,
) {
    let mandatory = dependency_relation(entry.relation)
        .map(|(_, mandatory)| mandatory)
        .unwrap_or(false);
    for (id, range) in &entry.deps {
        artifact.deps.push(Dep {
            id: id.clone(),
            range: range.clone(),
            mandatory,
            relation: entry.relation,
            feature: None,
            lifecycle: None,
            ordering: None,
            join_classpath: None,
            condition: None,
            side: None,
        });
        added.insert((entry.relation.to_string(), id.clone()));
    }
}

pub struct MetadataCollector;

impl Collector for MetadataCollector {
    fn id(&self) -> &'static str {
        "metadata-scanner"
    }
    fn layer(&self) -> Layer {
        Layer::Metadata
    }
    fn scope(&self) -> CollectorScope {
        CollectorScope::new(CompletenessModel::PerArtifact)
            .produces([
                kind::MOD,
                kind::PLUGIN,
                kind::INVALID_METADATA,
                kind::SECONDARY_IDENTITY,
                kind::ARTIFACT_ROLE,
                kind::MOD_METADATA,
                kind::MOD_CAPABILITY,
                kind::MOD_SIDE,
                kind::ENTRYPOINT,
                kind::ENTRYPOINT_DETAIL,
                kind::DEPENDENCY,
                kind::DEPENDENCY_EXPRESSION,
                kind::PROVIDED_DEPENDENCY,
                kind::BYTECODE_REFERENCE,
                kind::BYTECODE_CALL_EDGE,
                kind::CALL_SLICE_COVERAGE,
                kind::PACKAGE_OWNER,
                kind::MOD_RELATIONSHIP,
                kind::NESTED_JAR,
                kind::COMPATIBILITY_BRIDGE,
                kind::ACCESS_TRANSFORM,
                kind::COREMOD,
                kind::MIXIN_CONFIG,
                kind::CHECKSUM,
                kind::SCAN_TRUNCATED,
                kind::UNPARSEABLE_ARCHIVE,
            ])
            .regions([TargetRegion::Artifacts, TargetRegion::Metadata])
            .consumes([kind::ENVIRONMENT])
    }
    fn applies(&self, target: &Target) -> bool {
        target.kind.has_mods()
    }
    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let jars = roots::gather_jars(ctx.target, &ctx.settings.scan);
        if jars.is_empty() {
            return CollectorOutcome::active(0, "no jar archives found");
        }

        let mut emitted = 0usize;
        let mut parsed = 0usize;
        let mut no_manifest = 0usize;
        let mut invalid_or_unreadable = 0usize;
        let mut coverage_gaps = 0usize;
        let mut incomplete = false;

        // Parse jars in parallel (independent archive reads), then emit facts
        // serially — `ctx.store` is single-threaded and `par_iter().map()`
        // preserves order, so emission stays deterministic.
        let cache = ctx.jar_cache;
        let collector_id = self.id();
        let metadata_level = ctx.settings.metadata.level;
        let loader_resolution =
            resolve_environment_field(ctx.inputs, "loader", &["loader_source", "evidence_source"]);
        let expected_loader = loader_resolution.value.and_then(Loader::parse).or_else(|| {
            loader_resolution
                .conflicts
                .is_empty()
                .then(|| crate::env::loader_for_target(ctx.target))
                .flatten()
        });
        let expected_minecraft = resolve_environment_field(
            ctx.inputs,
            "mc_version",
            &["mc_version_source", "evidence_source"],
        )
        .value
        .map(str::to_string);
        let mut dependency_overrides_invalid = false;
        let dependency_overrides = if expected_loader == Some(Loader::Fabric) {
            match load_fabric_dependency_overrides(ctx.target) {
                Ok(overrides) => overrides,
                Err((path, reason)) => {
                    dependency_overrides_invalid = true;
                    incomplete = true;
                    invalid_or_unreadable += 1;
                    ctx.store
                        .fact(self.id(), kind::INVALID_METADATA)
                        .subject("fabric_loader_dependencies.json")
                        .attr("reason", reason)
                        .attr("manifest", "config/fabric_loader_dependencies.json")
                        .attr("loader", "fabric")
                        .attr("active_for_instance", true)
                        .source(SourceRef::file(path.display().to_string()))
                        .confidence(1.0)
                        .emit();
                    emitted += 1;
                    None
                }
            }
        } else {
            None
        };
        if let Some(overrides) = &dependency_overrides {
            ctx.store
                .fact(self.id(), kind::CHECKSUM)
                .subject("config/fabric_loader_dependencies.json")
                .attr("algorithm", "sha256")
                .attr("hex", overrides.sha256.clone())
                .attr("input_kind", "instance-config")
                .source(SourceRef::file(overrides.source.display().to_string()))
                .confidence(1.0)
                .emit();
            emitted += 1;
        }
        let prefer_legacy_forge = expected_loader == Some(Loader::Forge)
            && expected_minecraft
                .as_deref()
                .is_some_and(minecraft_uses_legacy_forge_descriptor);
        let loader_scope = expected_loader.map_or("unknown", |loader| loader.as_str());
        let minecraft_scope = expected_minecraft.as_deref().unwrap_or("unknown");
        let cache_version = format!(
            "{CACHE_VERSION}-{}-{loader_scope}-{minecraft_scope}",
            metadata_level_name(metadata_level)
        );
        let scanned: Vec<(PathBuf, String, CachedJarOutcome)> = jars
            .par_iter()
            .map(|jar| {
                let name = jar
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?")
                    .to_string();
                let outcome = match cache {
                    Some(cache) => cache.get_or_scan(collector_id, &cache_version, jar, || {
                        scan_jar_cached(jar, metadata_level, expected_loader, prefer_legacy_forge)
                    }),
                    None => {
                        scan_jar_cached(jar, metadata_level, expected_loader, prefer_legacy_forge)
                    }
                };
                (jar.clone(), name, outcome)
            })
            .collect();

        let mut call_edges_remaining = MAX_PACK_CALL_EDGES;
        for (jar, name, outcome) in scanned {
            match outcome {
                CachedJarOutcome::Parsed {
                    artifacts,
                    roles,
                    detached_providers,
                    inactive_nested,
                    truncations,
                    identity_certainty,
                    descriptor_candidates,
                } => {
                    parsed += 1;
                    for role in roles {
                        ctx.store
                            .fact(self.id(), kind::ARTIFACT_ROLE)
                            .subject(jar.display().to_string())
                            .attr("declared_id", role.declared_id)
                            .attr("version", role.version)
                            .attr("loader", role.loader)
                            .attr("descriptor", role.descriptor)
                            .attr("ordinal", i64::from(role.ordinal))
                            .attr("activation", role.activation)
                            .attr("identity_certainty", identity_certainty.clone())
                            .source(SourceRef::file(jar.display().to_string()))
                            .confidence(1.0)
                            .emit();
                        emitted += 1;
                    }
                    for mut m in artifacts.into_iter().map(cached_to_artifact) {
                        let applied_override = dependency_overrides
                            .as_ref()
                            .map_or_else(AppliedDependencyOverride::default, |overrides| {
                                overrides.apply(&mut m)
                            });
                        emitted += emit_artifact(
                            ctx,
                            &m,
                            &name,
                            &identity_certainty,
                            &descriptor_candidates,
                            &mut call_edges_remaining,
                            DependencyEmissionPolicy {
                                overrides: dependency_overrides.as_ref(),
                                applied: &applied_override,
                                authoritative: !(dependency_overrides_invalid
                                    && m.loader == Loader::Fabric),
                            },
                        );
                    }
                    for provider in detached_providers {
                        emitted += emit_detached_provider(ctx, &name, &provider);
                    }
                    for nested in inactive_nested {
                        let mut fact = ctx
                            .store
                            .fact(self.id(), kind::NESTED_JAR)
                            .subject(format!("container:{name}"))
                            .attr("container", name.clone())
                            .attr("nested_path", nested.path.clone())
                            .attr("activation", nested.activation)
                            .source(SourceRef::inside(name.clone(), nested.path));
                        if let Some(id) = nested.id {
                            fact = fact.attr("nested", id);
                        }
                        if let Some(version) = nested.version {
                            fact = fact.attr("version", version);
                        }
                        fact.confidence(1.0).emit();
                        emitted += 1;
                    }
                    // Surface per-entry caps that fired while scanning this jar
                    // (oversized/crafted archive), consistent with the VFS /
                    // security / resource-AST layers.
                    for reason in truncations {
                        incomplete = true;
                        coverage_gaps += 1;
                        ctx.store
                            .fact(self.id(), kind::SCAN_TRUNCATED)
                            .subject(name.clone())
                            .attr("layer", "metadata")
                            .attr("reason", reason)
                            .source(SourceRef::file(jar.display().to_string()))
                            .confidence(0.9)
                            .emit();
                        emitted += 1;
                    }
                }
                CachedJarOutcome::NoManifest => {
                    no_manifest += 1;
                    // A jar without a recognised mod manifest is usually benign
                    // (a bundled library/dependency jar), so it is tagged
                    // `no-manifest` and does not raise a finding on its own.
                    ctx.store
                        .fact(self.id(), kind::UNPARSEABLE_ARCHIVE)
                        .subject(name.clone())
                        .attr("reason", "no recognised manifest")
                        .attr("failure_class", "no-manifest")
                        .source(SourceRef::file(jar.display().to_string()))
                        .confidence(0.7)
                        .emit();
                    emitted += 1;
                }
                CachedJarOutcome::InvalidDescriptor { manifest, reason } => {
                    invalid_or_unreadable += 1;
                    incomplete = true;
                    let active_for_instance = expected_loader.is_none_or(|loader| {
                        descriptor_for_manifest(&manifest)
                            .is_some_and(|descriptor| descriptor.matches_loader(loader))
                    });
                    ctx.store
                        .fact(self.id(), kind::INVALID_METADATA)
                        .subject(name.clone())
                        .attr("reason", reason)
                        .attr("manifest", manifest.clone())
                        .attr("active_for_instance", active_for_instance)
                        .source(SourceRef::inside(jar.display().to_string(), manifest))
                        .confidence(0.95)
                        .emit();
                    emitted += 1;
                }
                CachedJarOutcome::Error(reason) => {
                    invalid_or_unreadable += 1;
                    incomplete = true;
                    // A genuine read error (corrupt/truncated zip, unreadable
                    // entry) means the archive cannot load — tagged `corrupt`
                    // so the `corrupt-jar` rule surfaces it as a warning.
                    ctx.store
                        .fact(self.id(), kind::UNPARSEABLE_ARCHIVE)
                        .subject(name.clone())
                        .attr("reason", reason)
                        .attr("failure_class", "corrupt")
                        .source(SourceRef::file(jar.display().to_string()))
                        .confidence(0.7)
                        .emit();
                    emitted += 1;
                }
            }
        }

        let summary = format!(
            "{} jar(s): {} recognized, {} without a mod/plugin manifest, {} invalid or unreadable, {} bounded coverage gap(s)",
            jars.len(),
            parsed,
            no_manifest,
            invalid_or_unreadable,
            coverage_gaps
        );
        if incomplete {
            CollectorOutcome::incomplete(emitted, summary)
        } else {
            CollectorOutcome::active(emitted, summary)
        }
    }
}

fn emit_detached_provider(
    ctx: &mut CollectCtx<'_>,
    container: &str,
    provider: &NestedProvider,
) -> usize {
    let subject = format!("container:{container}");
    ctx.store
        .fact("metadata-scanner", kind::PROVIDED_DEPENDENCY)
        .subject(subject.clone())
        .attr("provides", provider.id.clone())
        .attr("version", provider.version.clone())
        .attr("bundled", true)
        .attr("scope", "classpath")
        // The nested descriptor is exact, but a descriptorless outer archive's
        // own activation is not. Keep it as a plausible provider so it blocks a
        // false "not installed" without claiming satisfaction as hard truth.
        .attr("identity_certainty", "plausible-unresolved")
        .attr("container", container)
        .attr("nested_path", provider.path.clone())
        .attr("activation", "loader-declared")
        .source(SourceRef::inside(container, provider.path.clone()))
        .emit();
    ctx.store
        .fact("metadata-scanner", kind::NESTED_JAR)
        .subject(subject)
        .attr("nested", provider.id.clone())
        .attr("version", provider.version.clone())
        .attr("container", container)
        .attr("nested_path", provider.path.clone())
        .attr("activation", "loader-declared")
        .source(SourceRef::inside(container, provider.path.clone()))
        .emit();
    2
}

fn emit_artifact(
    ctx: &mut CollectCtx<'_>,
    m: &Artifact,
    file: &str,
    identity_certainty: &str,
    descriptor_candidates: &[String],
    call_edges_remaining: &mut usize,
    dependency_policy: DependencyEmissionPolicy<'_>,
) -> usize {
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
            .attr("active_for_instance", true)
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
        .attr("identity_certainty", identity_certainty)
        .attr(
            "active_for_instance",
            identity_certainty == "confirmed" || identity_certainty == "self-loader-bootstrap",
        )
        .attr("descriptor_candidates", descriptor_candidates.join(","))
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

    if identity_certainty == "self-loader-bootstrap" {
        ctx.store
            .fact("metadata-scanner", kind::MOD_CAPABILITY)
            .subject(m.id.clone())
            .attr("capability", "target-loader-bootstrap")
            .attr(
                "reason",
                "top-level target-loader service or core-plugin entry activates this artifact independently of its foreign descriptor",
            )
            .attr("file", file)
            .source(SourceRef::file(file))
            .confidence(0.95)
            .emit();
        emitted += 1;
    }

    if dependency_policy.applied.affected {
        let source = dependency_policy
            .overrides
            .map(|overrides| overrides.source.display().to_string())
            .unwrap_or_else(|| "config/fabric_loader_dependencies.json".to_string());
        ctx.store
            .fact("metadata-scanner", kind::MOD_CAPABILITY)
            .subject(m.id.clone())
            .attr("capability", "fabric-dependency-override-applied")
            .attr(
                "reason",
                "effective dependencies were modified by Fabric Loader instance configuration",
            )
            .attr("file", source.clone())
            .source(SourceRef::file(source))
            .confidence(1.0)
            .emit();
        emitted += 1;
    }

    if let Some((from_loader, to_loader, scope)) =
        compatibility_bridge(&m.id, file, m.name.as_deref(), &m.provides, m.loader)
    {
        let (capabilities, coverage, coverage_reason) = match scope {
            "mod-runtime" => (
                "metadata,classloading",
                "partial",
                "bridge detected; runtime compatibility is version- and artifact-dependent",
            ),
            "api-surface" => (
                "api-surface",
                "complete",
                "API compatibility only; this is not a runtime loader bridge",
            ),
            _ => ("", "partial", "bridge capability is unknown"),
        };
        ctx.store
            .fact("metadata-scanner", kind::COMPATIBILITY_BRIDGE)
            .subject(m.id.clone())
            .attr("from_loader", from_loader)
            .attr("to_loader", to_loader)
            .attr("scope", scope)
            .attr("capabilities", capabilities)
            .attr("coverage", coverage)
            .attr("coverage_reason", coverage_reason)
            .source(SourceRef::inside(file, m.manifest_name))
            .confidence(0.95)
            .emit();
        emitted += 1;
    }

    // Frame-to-jar ownership: the class-package roots this mod ships. A crash stack
    // frame under an exclusively-owned root is attributed to this mod by the
    // `crash-blame` rule. Only for a real (non-synthetic) id — ownership must name a
    // mod, not an `unknown:file` placeholder.
    if !id_missing {
        for root in &m.package_roots {
            ctx.store
                .fact("metadata-scanner", kind::PACKAGE_OWNER)
                .subject(m.id.clone())
                .attr("package", root.clone())
                .attr("file", file)
                .source(SourceRef::file(file))
                .confidence(0.9)
                .emit();
            emitted += 1;
        }
        if ctx.settings.metadata.level == MetadataLevel::Full {
            for target_package in &m.bytecode.referenced_packages {
                ctx.store
                    .fact("metadata-scanner", kind::BYTECODE_REFERENCE)
                    .subject(m.id.clone())
                    .attr("target_package", target_package.clone())
                    .attr("reference_kind", "constant-pool-package")
                    .attr("scan_truncated", m.bytecode.references_truncated)
                    .source(SourceRef::file(file))
                    .confidence(0.9)
                    .emit();
                emitted += 1;
            }
            let retained_edges = m.bytecode.call_edges.len().min(*call_edges_remaining);
            for edge in m.bytecode.call_edges.iter().take(retained_edges) {
                ctx.store
                    .fact("metadata-scanner", kind::BYTECODE_CALL_EDGE)
                    .subject(m.id.clone())
                    .attr("caller_class", edge.caller_class.clone())
                    .attr("caller_method", edge.caller_method.clone())
                    .attr("caller_descriptor", edge.caller_descriptor.clone())
                    .attr("target_class", edge.target_class.clone())
                    .attr("target_method", edge.target_method.clone())
                    .attr("target_descriptor", edge.target_descriptor.clone())
                    .attr("dispatch", edge.dispatch.clone())
                    .attr("archive", file)
                    .source(SourceRef::file(file))
                    .confidence(if edge.dispatch == "exact" { 1.0 } else { 0.8 })
                    .emit();
                emitted += 1;
            }
            *call_edges_remaining = call_edges_remaining.saturating_sub(retained_edges);
            let pack_budget_truncated = retained_edges < m.bytecode.call_edges.len();
            ctx.store
                .fact("metadata-scanner", kind::CALL_SLICE_COVERAGE)
                .subject(m.id.clone())
                .attr("edges_retained", retained_edges as i64)
                .attr("max_edges", MAX_PACK_CALL_EDGES as i64)
                .attr(
                    "truncated",
                    m.bytecode.call_edges_truncated || pack_budget_truncated,
                )
                .attr(
                    "reason",
                    if pack_budget_truncated {
                        "pack-wide bounded call-edge budget exhausted"
                    } else if m.bytecode.call_edges_truncated {
                        "artifact bounded call-edge budget exhausted"
                    } else {
                        "complete within bounded scanned classes"
                    },
                )
                .source(SourceRef::file(file))
                .emit();
            emitted += 1;
        }
    }

    // A hybrid jar's second role (e.g. a Bukkit plugin that also carries a Fabric
    // mod manifest) — informational, so no rule mistakes it for a separate mod.
    if let Some(secondary) = &m.secondary {
        let (role, sid) = secondary
            .split_once(':')
            .unwrap_or(("mod", secondary.as_str()));
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
            .attr(
                "authors",
                serde_json::to_string(&m.authors).unwrap_or_else(|_| "[]".into()),
            )
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

    for dep in m.deps.iter().filter(|_| dependency_policy.authoritative) {
        let override_source = dependency_policy
            .applied
            .added
            .contains(&(dep.relation.to_string(), dep.id.clone()))
            .then(|| {
                dependency_policy
                    .overrides
                    .map(|overrides| overrides.source.display().to_string())
                    .unwrap_or_else(|| "config/fabric_loader_dependencies.json".to_string())
            });
        let mut builder = ctx
            .store
            .fact("metadata-scanner", kind::DEPENDENCY)
            .subject(m.id.clone())
            .attr("dep", dep.id.clone())
            .attr("range", dep.range.clone())
            .attr("mandatory", dep.mandatory)
            .attr("relation", dep.relation)
            .attr("version_dialect", version_dialect_for_loader(m.loader))
            .attr("identity_certainty", identity_certainty)
            .source(
                override_source
                    .as_ref()
                    .map_or_else(|| SourceRef::inside(file, m.manifest_name), SourceRef::file),
            );
        if let Some(feature) = &dep.feature {
            builder = builder.attr("feature", feature.as_str());
        }
        if let Some(lifecycle) = &dep.lifecycle {
            builder = builder.attr("lifecycle", lifecycle.as_str());
        }
        if let Some(ordering) = &dep.ordering {
            builder = builder.attr("ordering", ordering.as_str());
        }
        if let Some(join_classpath) = dep.join_classpath {
            builder = builder.attr("join_classpath", join_classpath);
        }
        if let Some(condition) = &dep.condition {
            builder = builder.attr("condition", condition.as_str());
        }
        if let Some(side) = &dep.side {
            builder = builder.attr("side", side.as_str());
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
                "depends"
                    if !matches!(
                        dep.id.as_str(),
                        "minecraft" | "java" | "fabricloader" | "forge" | "neoforge"
                    ) =>
                {
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

    if dependency_policy.authoritative {
        for expression in &m.dependency_expressions {
            ctx.store
                .fact("metadata-scanner", kind::DEPENDENCY_EXPRESSION)
                .subject(m.id.clone())
                .attr("relation", expression.relation.clone())
                .attr("expression", expression.expression.clone())
                .attr("version_dialect", version_dialect_for_loader(m.loader))
                .attr("identity_certainty", identity_certainty)
                .source(SourceRef::inside(file, m.manifest_name))
                .confidence(1.0)
                .emit();
            emitted += 1;
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
        let mut provider = ctx
            .store
            .fact("metadata-scanner", kind::PROVIDED_DEPENDENCY)
            .subject(m.id.clone())
            .attr("provides", p.clone())
            // A manifest `provides` is a loader-registered alias id, globally
            // visible to other mods' dependency resolution.
            .attr("scope", "metadata-alias")
            .attr("identity_certainty", identity_certainty)
            .attr(
                "activation",
                if dependency_policy.authoritative {
                    "active-descriptor"
                } else {
                    "descriptor-unresolved"
                },
            )
            .source(SourceRef::inside(file, m.manifest_name));
        if let Some(version) = m.provided_versions.get(p) {
            provider = provider.attr("version", version.clone());
        }
        provider.emit();
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
            .attr("activation", "loader-declared")
            // Jar-in-Jar libraries are added to the mod classpath by the loader,
            // so they are visible to every mod (global classpath scope).
            .attr("scope", "classpath")
            .attr("identity_certainty", identity_certainty)
            .source(SourceRef::inside(file, m.manifest_name))
            .emit();
        ctx.store
            .fact("metadata-scanner", kind::NESTED_JAR)
            .subject(m.id.clone())
            .attr("nested", id.clone())
            .attr("version", version.clone())
            .attr("activation", "loader-declared")
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
            let mut detail = ctx
                .store
                .fact("metadata-scanner", kind::ENTRYPOINT_DETAIL)
                .subject(m.id.clone())
                .attr("phase", ep.phase.clone())
                .attr("class", ep.class.clone())
                .attr("entrypoint_type", ep.entrypoint_type.clone())
                .source(SourceRef::inside(file, m.manifest_name))
                .confidence(if ep.events.is_empty() { 0.65 } else { 0.85 });
            if ctx.settings.metadata.level == MetadataLevel::Full {
                detail = detail
                    .attr(
                        "events",
                        serde_json::to_string(&ep.events).unwrap_or_else(|_| "[]".into()),
                    )
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
            .attr(
                "target_key",
                access::target_key_owned(&at.target_class, at.member.as_deref()),
            )
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
                .attr("archive", file)
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

fn compatibility_bridge(
    mod_id: &str,
    archive: &str,
    display_name: Option<&str>,
    provides: &[String],
    loader: Loader,
) -> Option<(&'static str, &'static str, &'static str)> {
    let normalized = mod_id.to_ascii_lowercase().replace('-', "_");
    let is_forgified_api = normalized == "forgified_fabric_api"
        || (normalized == "fabric_api"
            && (archive.to_ascii_lowercase().contains("forgified")
                || display_name.is_some_and(|name| {
                    name.to_ascii_lowercase().contains("forgified fabric api")
                })
                || provides.iter().any(|provided| provided == "fabric-api")));
    let target = match loader {
        Loader::Forge => "forge",
        Loader::NeoForge => "neoforge",
        _ => "forge-family",
    };
    match normalized.as_str() {
        "connector" | "connectormod" | "sinytra_connector" => {
            Some(("fabric", target, "mod-runtime"))
        }
        _ if is_forgified_api => Some(("fabric-api", target, "api-surface")),
        _ => None,
    }
}

fn version_dialect_for_loader(loader: Loader) -> &'static str {
    match loader {
        Loader::Fabric => "fabric-extended-semver",
        Loader::Quilt => "quilt",
        Loader::Forge | Loader::NeoForge => "maven-range",
        Loader::Paper | Loader::Spigot | Loader::Bukkit | Loader::Vanilla => "generic-semver",
    }
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
    #[serde(default)]
    lifecycle: Option<String>,
    #[serde(default)]
    ordering: Option<String>,
    #[serde(default)]
    join_classpath: Option<bool>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    side: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CachedArtifact {
    id: String,
    version: String,
    loader: String,
    side: Option<String>,
    deps: Vec<CachedDep>,
    #[serde(default)]
    dependency_expressions: Vec<quilt::DependencyExpression>,
    provides: Vec<String>,
    #[serde(default)]
    provided_versions: BTreeMap<String, String>,
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
    #[serde(default)]
    package_roots: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NestedProvider {
    id: String,
    version: String,
    path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct InactiveNested {
    path: String,
    activation: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
enum CachedJarOutcome {
    Parsed {
        artifacts: Vec<CachedArtifact>,
        #[serde(default)]
        roles: Vec<ArtifactRole>,
        #[serde(default)]
        detached_providers: Vec<NestedProvider>,
        #[serde(default)]
        inactive_nested: Vec<InactiveNested>,
        #[serde(default)]
        truncations: Vec<String>,
        #[serde(default = "confirmed_identity_certainty")]
        identity_certainty: String,
        #[serde(default)]
        descriptor_candidates: Vec<String>,
    },
    NoManifest,
    InvalidDescriptor {
        manifest: String,
        reason: String,
    },
    Error(String),
}

fn confirmed_identity_certainty() -> String {
    "confirmed".to_string()
}

fn scan_jar_cached(
    path: &Path,
    metadata_level: MetadataLevel,
    expected_loader: Option<Loader>,
    prefer_legacy_forge: bool,
) -> CachedJarOutcome {
    match parse_jar_for_instance(path, metadata_level, expected_loader, prefer_legacy_forge) {
        // No artifacts and nothing truncated: a benign manifest-less jar.
        Ok(parsed)
            if parsed.artifacts.is_empty()
                && parsed.detached_providers.is_empty()
                && parsed.inactive_nested.is_empty()
                && parsed.truncations.is_empty() =>
        {
            CachedJarOutcome::NoManifest
        }
        Ok(parsed) => CachedJarOutcome::Parsed {
            artifacts: parsed.artifacts.iter().map(artifact_to_cached).collect(),
            roles: parsed.roles,
            detached_providers: parsed.detached_providers,
            inactive_nested: parsed.inactive_nested,
            truncations: parsed.truncations,
            identity_certainty: parsed.identity_certainty.to_string(),
            descriptor_candidates: parsed.descriptor_candidates,
        },
        Err(e) => match e.descriptor_manifest() {
            Some(manifest) => CachedJarOutcome::InvalidDescriptor {
                manifest: manifest.to_string(),
                reason: e.as_str().to_string(),
            },
            None => CachedJarOutcome::Error(e.as_str().to_string()),
        },
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
                lifecycle: d.lifecycle.clone(),
                ordering: d.ordering.clone(),
                join_classpath: d.join_classpath,
                condition: d.condition.clone(),
                side: d.side.clone(),
            })
            .collect(),
        dependency_expressions: m.dependency_expressions.clone(),
        mixin_configs: m.mixin_configs.clone(),
        provides: m.provides.clone(),
        provided_versions: m.provided_versions.clone(),
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
        package_roots: m.package_roots.clone(),
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
                lifecycle: d.lifecycle,
                ordering: d.ordering,
                join_classpath: d.join_classpath,
                condition: d.condition,
                side: d.side,
            })
            .collect(),
        dependency_expressions: c.dependency_expressions,
        mixin_configs: c.mixin_configs,
        provides: c.provides,
        provided_versions: c.provided_versions,
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
        package_roots: c.package_roots,
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
    let side = entry
        .get("side")
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_ascii_lowercase());
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
        lifecycle: None,
        ordering: None,
        join_classpath: None,
        condition: None,
        side,
    }
}

/// Collect dependency rows declared for `mod_id` in a parsed `mods.toml` tree.
fn collect_forge_mod_dependencies(v: &toml::Value, mod_id: &str) -> Vec<Dep> {
    let Some(deps_root) = v.get("dependencies") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(table) = deps_root.as_table()
        && let Some(arr) = table.get(mod_id).and_then(|x| x.as_array())
    {
        for entry in arr {
            out.push(parse_forge_dep_entry(entry));
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
        "mcmod.info" => "mcmod.info",
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
    /// Loader lifecycle in which the relation applies (`bootstrap`/`server`).
    lifecycle: Option<String>,
    /// Relative load order (`before`/`after`/`omit`).
    ordering: Option<String>,
    /// Paper classloader visibility, independent of dependency presence.
    join_classpath: Option<bool>,
    /// Serialized loader condition when the dependency is not unconditional.
    condition: Option<String>,
    /// Loader side on which the dependency applies (`client`, `server`, `both`).
    side: Option<String>,
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
    /// Lossless loader-native dependency groups. Ordinary edges remain as a
    /// compatibility projection, while Layer C evaluates these expressions as
    /// groups so `any`/`unless` do not become false independent requirements.
    pub(crate) dependency_expressions: Vec<quilt::DependencyExpression>,
    pub(crate) provides: Vec<String>,
    /// Loader aliases and their independently declared versions. Quilt's
    /// `provides` objects may expose a compatibility API version that differs
    /// from the containing module version.
    pub(crate) provided_versions: BTreeMap<String, String>,
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
    /// Distinctive class-package roots this jar ships (dotted, e.g. `com.foo.mymod`),
    /// excluding vanilla/JDK packages — the frame-to-jar ownership index. Filled in
    /// `parse_jar` (Standard+ level); emitted as `package_owner` facts.
    pub(crate) package_roots: Vec<String>,
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
    /// Bounded ordinary class references from the jar constant pools.
    pub(crate) referenced_packages: Vec<String>,
    pub(crate) references_truncated: bool,
    pub(crate) call_edges: Vec<crate::entrypoint_analysis::CallEdge>,
    pub(crate) call_edges_truncated: bool,
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

/// Typed parse failure: archive I/O/corruption and descriptor syntax are
/// operationally different and must never collapse into the same diagnosis.
#[derive(Debug)]
struct ParseErr {
    kind: ParseErrKind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseErrKind {
    Archive,
    Descriptor { manifest: &'static str },
}

impl ParseErr {
    fn archive(message: impl Into<String>) -> Self {
        Self {
            kind: ParseErrKind::Archive,
            message: message.into(),
        }
    }

    fn descriptor(manifest: &'static str, message: impl Into<String>) -> Self {
        let detail = message.into();
        Self {
            kind: ParseErrKind::Descriptor { manifest },
            message: format!("{manifest}: {detail}"),
        }
    }

    fn as_str(&self) -> &str {
        &self.message
    }

    fn descriptor_manifest(&self) -> Option<&'static str> {
        match self.kind {
            ParseErrKind::Descriptor { manifest } => Some(manifest),
            ParseErrKind::Archive => None,
        }
    }
}

/// How deep to recurse into Jar-in-Jar archives. Real packs nest 1–2 levels
/// (Create → Registrate → its libs); the bound stops pathological archives.
const MAX_NEST_DEPTH: u8 = 4;

use bounded_zip::cap_for_entry as cap_for;

/// Best-effort bounded read used only while probing an *inactive* secondary
/// descriptor. Failures here deliberately do not make the selected descriptor
/// incomplete: a broken foreign descriptor must not poison an otherwise valid
/// active plugin identity. Reads which affect active metadata use the typed
/// bounded API directly and surface a coverage gap.
fn read_entry<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, name: &str) -> Option<String> {
    bounded_zip::read_zip_text_opt(archive, name, cap_for(name))
}

/// Whether this collector can consume an entry as metadata or bytecode input.
/// Large assets still remain bounded by the ZIP layer, but they must not make a
/// metadata scan look incomplete when this collector never intended to read
/// them (music files were the motivating real-world case).
fn is_metadata_scan_entry(name: &str) -> bool {
    matches!(
        name,
        "fabric.mod.json"
            | "quilt.mod.json"
            | "paper-plugin.yml"
            | "plugin.yml"
            | "META-INF/mods.toml"
            | "META-INF/neoforge.mods.toml"
            | "mcmod.info"
            | "META-INF/MANIFEST.MF"
            | "META-INF/accesstransformer.cfg"
            | "META-INF/coremods.json"
            | "META-INF/jarjar/metadata.json"
    ) || name.ends_with(".class")
        || name.ends_with(".mixins.json")
        || name.ends_with("-refmap.json")
        || name.ends_with(".accesswidener")
        || is_nested_jar(name)
}

/// Report oversized entries only when they are inputs to this collector. The
/// bounded ZIP readers enforce caps for every attempted read; this sweep is
/// solely the user-facing completeness diagnostic.
fn oversized_entries<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        if !is_metadata_scan_entry(&name) {
            continue;
        }
        let cap = cap_for(&name);
        if entry.size() > cap {
            out.push(format!(
                "{name}: {} bytes exceeds {cap} byte cap, skipped",
                entry.size()
            ));
        }
    }
    out
}

/// Dispatch on whichever manifest an archive carries. Generic over the reader so
/// it works on both on-disk jars and in-memory nested jars.
struct ParsedArchive {
    artifacts: Vec<Artifact>,
    identity_certainty: &'static str,
    descriptor_candidates: Vec<String>,
    roles: Vec<ArtifactRole>,
    truncations: Vec<String>,
}

/// Parse every descriptor before choosing an active identity. This prevents the
/// deterministic descriptor iteration order from becoming evidence about the
/// target loader when the instance itself did not establish one.
fn parse_archive_for_instance<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    expected_loader: Option<Loader>,
    prefer_legacy_forge: bool,
) -> Result<ParsedArchive, ParseErr> {
    // Universal server plugins (e.g. ViaVersion) may bundle a mod manifest for
    // proxy-side hooks; the Bukkit/Paper plugin descriptor stays the *primary*
    // identity (a mod fact for the bundled manifest would re-introduce the
    // loader-mismatch false positives the ordering deliberately prevents). The
    // co-present mod manifest is recorded as a non-rule `secondary` identity so
    // the second role is not lost.
    let preferred = preferred_descriptor(expected_loader, prefer_legacy_forge);
    let mut first_inactive_error = None;
    let mut parsed_candidates: Vec<(Descriptor, Vec<Artifact>)> = Vec::new();
    let mut truncations = Vec::new();
    for descriptor in descriptor_order(expected_loader, prefer_legacy_forge) {
        let manifest = descriptor.manifest_name();
        let text_result = if descriptor == Descriptor::LegacyForge {
            bounded_zip::read_zip_bytes_bounded(archive, manifest, cap_for(manifest))
                .map(|bytes| bytes.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
        } else {
            bounded_zip::read_zip_text_bounded(archive, manifest, cap_for(manifest))
        };
        let text = match text_result {
            Ok(text) => text,
            Err(error) => {
                if expected_loader.is_none_or(|loader| descriptor.matches_loader(loader)) {
                    truncations.push(error.reason());
                }
                continue;
            }
        };
        let parsed = match descriptor {
            Descriptor::Paper => text.map(|text| {
                parse_plugin_yml(&text, Loader::Paper, "paper-plugin.yml").map(|mut artifact| {
                    artifact.secondary = detect_secondary_mod(archive);
                    vec![artifact]
                })
            }),
            Descriptor::Bukkit => text.map(|text| {
                parse_plugin_yml(&text, Loader::Bukkit, "plugin.yml").map(|mut artifact| {
                    artifact.secondary = detect_secondary_mod(archive);
                    vec![artifact]
                })
            }),
            Descriptor::Fabric => {
                text.map(|text| parse_fabric(&text).map(|artifact| vec![artifact]))
            }
            Descriptor::Quilt => text.map(|text| parse_quilt(&text).map(|artifact| vec![artifact])),
            Descriptor::NeoForge => text.map(|text| parse_forge_toml(&text, Loader::NeoForge)),
            Descriptor::Forge => text.map(|text| parse_forge_toml(&text, Loader::Forge)),
            Descriptor::LegacyForge => text.map(|text| parse_legacy_forge(&text)),
        };
        if let Some(result) = parsed {
            match result {
                Ok(artifacts) => parsed_candidates.push((descriptor, artifacts)),
                Err(error)
                    if expected_loader.is_some_and(|loader| descriptor.matches_loader(loader)) =>
                {
                    return Err(error);
                }
                Err(error) => {
                    // With no matching instance descriptor, continue looking for
                    // a valid co-present identity. Report the first syntax error
                    // only when no descriptor can be parsed at all.
                    first_inactive_error.get_or_insert(error);
                }
            }
        }
    }

    if parsed_candidates.is_empty() {
        return first_inactive_error.map_or_else(
            || {
                Ok(ParsedArchive {
                    artifacts: Vec::new(),
                    identity_certainty: "confirmed",
                    descriptor_candidates: Vec::new(),
                    roles: Vec::new(),
                    truncations,
                })
            },
            Err,
        );
    }

    let descriptor_candidates = parsed_candidates
        .iter()
        .map(|(descriptor, _)| descriptor.manifest_name().to_string())
        .collect::<Vec<_>>();
    let selected = preferred
        .and_then(|wanted| {
            parsed_candidates
                .iter()
                .position(|(descriptor, _)| *descriptor == wanted)
        })
        .unwrap_or(0);

    // An explicit instance loader makes its matching descriptor authoritative.
    // With no such evidence, one descriptor is unambiguous; multiple mod-loader
    // descriptors are candidates, not permission to treat the first one's
    // dependency assertions as hard truth. Plugin descriptors retain their
    // established primary-role precedence for universal proxy/plugin jars.
    let selected_descriptor = parsed_candidates[selected].0;
    let identity_certainty =
        if expected_loader.is_some_and(|loader| selected_descriptor.matches_loader(loader)) {
            "confirmed"
        } else if preferred.is_some() {
            // The instance has an authoritative loader, but this archive exposes no
            // matching descriptor. Preserve the candidate for loader/bridge
            // diagnosis without treating its dependency declarations as active.
            "cross-loader-unresolved"
        } else if parsed_candidates.len() == 1 {
            "confirmed"
        } else {
            "undecidable"
        };
    let roles = roles::classify(
        &parsed_candidates,
        selected,
        expected_loader,
        identity_certainty,
    );
    let (_, artifacts) = parsed_candidates.swap_remove(selected);
    Ok(ParsedArchive {
        artifacts,
        identity_certainty,
        descriptor_candidates,
        roles,
        truncations,
    })
}

/// Active-instance descriptor first, then deterministic fallbacks. A malformed
/// inactive descriptor can no longer shadow a valid active one merely because
/// its filename happened to appear earlier in a global priority list.
fn descriptor_order(expected_loader: Option<Loader>, prefer_legacy_forge: bool) -> Vec<Descriptor> {
    let preferred = preferred_descriptor(expected_loader, prefer_legacy_forge);
    let mut order = Vec::with_capacity(7);
    if let Some(preferred) = preferred {
        order.push(preferred);
    }
    for descriptor in [
        Descriptor::Paper,
        Descriptor::Bukkit,
        Descriptor::Fabric,
        Descriptor::Quilt,
        Descriptor::NeoForge,
        Descriptor::Forge,
        Descriptor::LegacyForge,
    ] {
        if Some(descriptor) != preferred {
            order.push(descriptor);
        }
    }
    order
}

fn preferred_descriptor(
    expected_loader: Option<Loader>,
    prefer_legacy_forge: bool,
) -> Option<Descriptor> {
    match expected_loader {
        Some(Loader::Paper) => Some(Descriptor::Paper),
        Some(Loader::Spigot | Loader::Bukkit) => Some(Descriptor::Bukkit),
        Some(Loader::Fabric) => Some(Descriptor::Fabric),
        Some(Loader::Quilt) => Some(Descriptor::Quilt),
        Some(Loader::NeoForge) => Some(Descriptor::NeoForge),
        Some(Loader::Forge) => Some(if prefer_legacy_forge {
            Descriptor::LegacyForge
        } else {
            Descriptor::Forge
        }),
        Some(Loader::Vanilla) | None => None,
    }
}

fn descriptor_for_manifest(manifest: &str) -> Option<Descriptor> {
    match manifest {
        "paper-plugin.yml" => Some(Descriptor::Paper),
        "plugin.yml" => Some(Descriptor::Bukkit),
        "fabric.mod.json" => Some(Descriptor::Fabric),
        "quilt.mod.json" => Some(Descriptor::Quilt),
        "META-INF/neoforge.mods.toml" => Some(Descriptor::NeoForge),
        "META-INF/mods.toml" => Some(Descriptor::Forge),
        "mcmod.info" => Some(Descriptor::LegacyForge),
        _ => None,
    }
}

/// When a plugin jar also ships a mod manifest, return its `"loader:id"` so the
/// dual role surfaces as an informational `secondary_identity` fact.
fn detect_secondary_mod<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Option<String> {
    if let Some(text) = read_entry(archive, "fabric.mod.json")
        && let Ok(a) = parse_fabric(&text)
    {
        return Some(format!("fabric:{}", a.id));
    }
    if let Some(text) = read_entry(archive, "quilt.mod.json")
        && let Ok(a) = parse_quilt(&text)
    {
        return Some(format!("quilt:{}", a.id));
    }
    if read_entry(archive, "META-INF/neoforge.mods.toml").is_some() {
        return Some("neoforge:<mods.toml>".to_string());
    }
    if read_entry(archive, "META-INF/mods.toml").is_some() {
        return Some("forge:<mods.toml>".to_string());
    }
    if let Some(text) = read_entry(archive, "mcmod.info")
        && let Ok(mods) = intermed_doctor_core::legacy_forge::parse_mcmod_info(&text)
        && let Some(first) = mods.first()
    {
        return Some(format!("forge:{}", first.mod_id));
    }
    None
}

fn is_nested_jar(name: &str) -> bool {
    (name.starts_with("META-INF/jars/") || name.starts_with("META-INF/jarjar/"))
        && name.ends_with(".jar")
}

fn physical_nested_paths<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Vec<String> {
    (0..archive.len())
        .filter_map(|index| {
            let name = archive.by_index(index).ok()?.name().to_string();
            is_nested_jar(&name).then_some(name)
        })
        .collect()
}

fn declared_nested_paths<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    loader: Option<Loader>,
) -> (BTreeSet<String>, Vec<String>) {
    let mut paths = BTreeSet::new();
    let descriptor = match loader {
        Some(Loader::Fabric) => "fabric.mod.json",
        Some(Loader::Quilt) => "quilt.mod.json",
        Some(Loader::Forge | Loader::NeoForge) => "META-INF/jarjar/metadata.json",
        _ => return (paths, Vec::new()),
    };
    let text = match bounded_zip::read_zip_text_bounded(archive, descriptor, cap_for(descriptor)) {
        Ok(Some(text)) => text,
        Ok(None) => return (paths, Vec::new()),
        Err(error) => return (paths, vec![error.reason()]),
    };
    let parsed = if loader == Some(Loader::Fabric) {
        // The active Fabric descriptor was parsed with Loader-compatible Gson
        // semantics above.  Reusing strict serde_json here would make nested
        // discovery disagree with artifact identity for otherwise valid files
        // containing literal control characters or other supported leniency.
        intermed_doctor_core::fabric_json::parse_value(&text)
    } else {
        serde_json::from_str::<serde_json::Value>(&text)
    };
    let value = match parsed {
        Ok(value) => value,
        Err(error) => {
            return (
                paths,
                vec![format!(
                    "{descriptor}: nested declaration is invalid: {error}"
                )],
            );
        }
    };
    // Nested-archive declarations live at loader-specific locations.  Do not
    // recursively search the entire descriptor: an unrelated custom metadata
    // object is allowed to contain a `jars` key and must not activate archives.
    // Quilt, in particular, nests the declaration below `quilt_loader`, unlike
    // Fabric and Forge/NeoForge which place it at the descriptor root.
    let declaration = match loader {
        Some(Loader::Fabric | Loader::Forge | Loader::NeoForge) => value.get("jars"),
        Some(Loader::Quilt) => value.pointer("/quilt_loader/jars"),
        _ => None,
    };
    if let Some(declaration) = declaration {
        collect_declared_jar_strings(declaration, &mut paths);
    }
    (paths, Vec::new())
}

fn collect_declared_jar_strings(value: &serde_json::Value, paths: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(path) if path.ends_with(".jar") => {
            paths.insert(path.trim_start_matches('/').to_string());
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_declared_jar_strings(value, paths);
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                if matches!(key.as_str(), "file" | "path" | "jars" | "jar") {
                    collect_declared_jar_strings(value, paths);
                }
            }
        }
        _ => {}
    }
}

/// Recursively collect `(id, version)` for every bundled (Jar-in-Jar) module, so
/// dependencies satisfied by a nested library are not reported missing.
#[derive(Clone, Copy)]
struct BundledScanContext {
    expected_loader: Option<Loader>,
    prefer_legacy_forge: bool,
}

fn collect_bundled<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    depth: u8,
    context: BundledScanContext,
    parent_path: &str,
    out: &mut Vec<NestedProvider>,
    inactive: &mut Vec<InactiveNested>,
    gaps: &mut Vec<String>,
) {
    let BundledScanContext {
        expected_loader,
        prefer_legacy_forge,
    } = context;
    if depth == 0 {
        let (declared, declaration_gaps) = declared_nested_paths(archive, expected_loader);
        gaps.extend(declaration_gaps);
        if !declared.is_empty() {
            gaps.push(format!(
                "{parent_path}: nested archive depth exceeds {MAX_NEST_DEPTH}"
            ));
        }
        return;
    }
    let (declared, declaration_gaps) = declared_nested_paths(archive, expected_loader);
    gaps.extend(declaration_gaps);
    // Activation is driven by the descriptor, not a conventional directory.
    // Fabric/Quilt may legally declare a nested archive outside META-INF/jars.
    let names = declared.into_iter().collect::<Vec<_>>();
    for name in names {
        let nested_path = if parent_path.is_empty() {
            name.clone()
        } else {
            format!("{parent_path}!/{name}")
        };
        let bytes = match bounded_zip::read_zip_bytes_bounded(archive, &name, cap_for(&name)) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                gaps.push(format!(
                    "{nested_path}: loader-declared nested archive is missing"
                ));
                continue;
            }
            Err(error) => {
                gaps.push(error.reason());
                continue;
            }
        };
        let mut inner = match zip::ZipArchive::new(Cursor::new(bytes)) {
            Ok(inner) => inner,
            Err(error) => {
                gaps.push(format!(
                    "{nested_path}: nested archive is unreadable: {error}"
                ));
                continue;
            }
        };
        let recursive_loader =
            match parse_archive_for_instance(&mut inner, expected_loader, prefer_legacy_forge) {
                Ok(parsed) => {
                    gaps.extend(
                        parsed
                            .truncations
                            .iter()
                            .map(|gap| format!("{nested_path}!/{gap}")),
                    );
                    if parsed.identity_certainty == "cross-loader-unresolved" {
                        for artifact in parsed.artifacts {
                            inactive.push(InactiveNested {
                                path: nested_path.clone(),
                                activation: "classpath-only-cross-loader-descriptor".to_string(),
                                id: (!artifact.id.is_empty()).then_some(artifact.id),
                                version: (!artifact.version.is_empty()).then_some(artifact.version),
                            });
                        }
                        // A loader-declared foreign-descriptor library is visible on
                        // the parent's classpath but is not an active mod provider.
                        // Its own loader-specific nested declarations are therefore
                        // not activation instructions for the target loader.
                        continue;
                    }
                    if parsed.identity_certainty != "confirmed" {
                        gaps.push(format!(
                            "{nested_path}: loader-declared nested identity is {}",
                            parsed.identity_certainty
                        ));
                        continue;
                    }
                    let recursive_loader = parsed
                        .artifacts
                        .first()
                        .map(|artifact| artifact.loader)
                        .or(expected_loader);
                    for a in parsed.artifacts {
                        if !a.id.is_empty() {
                            // Resolve the nested jar's own `${file.jarVersion}` against
                            // its manifest, so a bundled provider carries a real version.
                            let version = jar_meta::resolve_jar_version(&a.version, &mut inner);
                            out.push(NestedProvider {
                                id: a.id,
                                version,
                                path: nested_path.clone(),
                            });
                        }
                        for alias in a.provides {
                            out.push(NestedProvider {
                                version: a
                                    .provided_versions
                                    .get(&alias)
                                    .cloned()
                                    .unwrap_or_default(),
                                id: alias,
                                path: nested_path.clone(),
                            });
                        }
                    }
                    recursive_loader
                }
                Err(error) => {
                    gaps.push(format!(
                        "{nested_path}: nested descriptor is invalid: {}",
                        error.as_str()
                    ));
                    expected_loader
                }
            };
        collect_bundled(
            &mut inner,
            depth - 1,
            BundledScanContext {
                expected_loader: recursive_loader,
                prefer_legacy_forge,
            },
            &nested_path,
            out,
            inactive,
            gaps,
        );
    }
}

struct ParsedJar {
    artifacts: Vec<Artifact>,
    roles: Vec<ArtifactRole>,
    detached_providers: Vec<NestedProvider>,
    inactive_nested: Vec<InactiveNested>,
    truncations: Vec<String>,
    identity_certainty: &'static str,
    descriptor_candidates: Vec<String>,
}

#[cfg(test)]
fn parse_jar(
    path: &Path,
    metadata_level: MetadataLevel,
    expected_loader: Option<Loader>,
) -> Result<ParsedJar, ParseErr> {
    parse_jar_for_instance(path, metadata_level, expected_loader, false)
}

fn parse_jar_for_instance(
    path: &Path,
    metadata_level: MetadataLevel,
    expected_loader: Option<Loader>,
    prefer_legacy_forge: bool,
) -> Result<ParsedJar, ParseErr> {
    let file = std::fs::File::open(path).map_err(|e| ParseErr::archive(format!("open: {e}")))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| ParseErr::archive(format!("zip: {e}")))?;

    // Report entries skipped by the per-entry caps (the bounded readers enforce
    // them; this is the diagnostic half).
    let mut truncations = oversized_entries(&mut archive);

    let parsed_archive =
        parse_archive_for_instance(&mut archive, expected_loader, prefer_legacy_forge)?;
    truncations.extend(parsed_archive.truncations);
    let mut artifacts = parsed_archive.artifacts;
    let roles = parsed_archive.roles;
    let mut identity_certainty = parsed_archive.identity_certainty;
    let mut descriptor_candidates = parsed_archive.descriptor_candidates;
    if identity_certainty == "cross-loader-unresolved"
        && expected_loader.is_some_and(|loader| has_self_loader_bootstrap(&mut archive, loader))
    {
        // The foreign descriptor describes only one frontend of a universal
        // bootstrap artifact. ModLauncher/Forge will activate the top-level
        // service directly, so declaring that the whole JAR cannot load is
        // unsound. Keep descriptor dependencies non-authoritative while
        // recording the exact bootstrap path that made the artifact plausible.
        identity_certainty = "self-loader-bootstrap";
        descriptor_candidates.push("META-INF/services/<target-loader-bootstrap>".to_string());
    }
    if artifacts.is_empty() {
        let (discovered, gaps) = forge_annotation::discover_mods_from_jar(&mut archive);
        artifacts = discovered;
        truncations.extend(gaps);
        // Bootstrap bridges such as Sinytra Connector are loader services whose
        // actual mod descriptor is nested. Identify the outer artifact from its
        // manifest plus exact service-provider entries; do not guess from its
        // filename.
        if artifacts.is_empty()
            && let Some(bridge) = discover_bootstrap_bridge(&mut archive, expected_loader)
        {
            artifacts.push(bridge);
        }
    } else if artifacts
        .iter()
        .any(|a| matches!(a.loader, Loader::Forge | Loader::NeoForge) && a.entrypoints.is_empty())
    {
        // A `mods.toml` names the mod but not its entry class; scan `@Mod` classes
        // so Forge/NeoForge mods still get an `entrypoint` (phase = mod).
        let (entrypoints, gaps) = forge_annotation::discover_mod_entrypoints(&mut archive);
        truncations.extend(gaps);
        for (mod_id, class) in entrypoints {
            if let Some(art) = artifacts.iter_mut().find(|a| a.id == mod_id)
                && art.entrypoints.is_empty()
            {
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

    // Physical containment is not loader activation. Only descriptor/JarJar
    // declared nested paths may enter the provider universe.
    let nested_loader = if identity_certainty == "confirmed" {
        // The declaration syntax belongs to the selected descriptor, not to the
        // host loader. Quilt can activate a Fabric descriptor, whose nested jars
        // remain declared under `fabric.mod.json#jars`.
        artifacts
            .first()
            .map(|artifact| artifact.loader)
            .or(expected_loader)
    } else {
        // A foreign or ambiguous descriptor is not authoritative activation
        // evidence. Keep using the target loader's declaration mechanism so a
        // co-present foreign descriptor cannot smuggle providers into the graph.
        expected_loader.or_else(|| artifacts.first().map(|artifact| artifact.loader))
    };
    let physical_nested = physical_nested_paths(&mut archive);
    let (declared_nested, declaration_gaps) = declared_nested_paths(&mut archive, nested_loader);
    truncations.extend(declaration_gaps);
    let mut inactive_nested = physical_nested
        .into_iter()
        .filter(|path| !declared_nested.contains(path))
        .map(|path| InactiveNested {
            path,
            activation: "not-loader-declared".to_string(),
            id: None,
            version: None,
        })
        .collect::<Vec<_>>();

    // Attach loader-active Jar-in-Jar providers to the primary artifact.
    let mut bundled = Vec::new();
    collect_bundled(
        &mut archive,
        MAX_NEST_DEPTH,
        BundledScanContext {
            expected_loader: nested_loader,
            prefer_legacy_forge,
        },
        "",
        &mut bundled,
        &mut inactive_nested,
        &mut truncations,
    );
    let mut detached_providers = Vec::new();
    if !bundled.is_empty() {
        bundled.sort();
        bundled.dedup();
        let own: std::collections::HashSet<&str> =
            artifacts.iter().map(|a| a.id.as_str()).collect();
        bundled.retain(|provider| !own.contains(provider.id.as_str()));
        if let Some(primary) = artifacts.first_mut() {
            primary.bundled = bundled
                .iter()
                .map(|provider| (provider.id.clone(), provider.version.clone()))
                .collect();
        } else {
            detached_providers = bundled;
        }
    }

    truncations.extend(enrich_access_and_coremods(&mut archive, &mut artifacts));
    if metadata_level == MetadataLevel::Full {
        truncations.extend(enrich_entrypoint_intelligence(&mut archive, &mut artifacts));
    }

    let forge_descriptor = if artifacts
        .iter()
        .any(|artifact| artifact.loader == Loader::NeoForge)
        && archive.by_name("META-INF/neoforge.mods.toml").is_ok()
    {
        Some("META-INF/neoforge.mods.toml")
    } else if artifacts
        .iter()
        .any(|artifact| artifact.loader == Loader::Forge)
        && archive.by_name("META-INF/mods.toml").is_ok()
    {
        Some("META-INF/mods.toml")
    } else {
        None
    };
    if let Some(descriptor) = forge_descriptor {
        match bounded_zip::read_zip_text_bounded(&mut archive, descriptor, cap_for(descriptor)) {
            Ok(Some(text)) => match text.parse::<toml::Value>() {
                Ok(value) => truncations.extend(enrich_forge_toml_extras(
                    &mut archive,
                    &mut artifacts,
                    &value,
                )),
                Err(error) => truncations.push(format!(
                    "{descriptor}: cannot enrich malformed active descriptor: {error}"
                )),
            },
            Ok(None) => {}
            Err(error) => truncations.push(error.reason()),
        }
    }

    // Forge substitutes `${file.jarVersion}` in `mods.toml` with the jar
    // manifest's `Implementation-Version` at load time. Resolve it the same way
    // (shared with the SBOM/identity scanners) so the literal placeholder is not
    // an unparseable version that drops the mod from the dependency graph.
    for a in &mut artifacts {
        a.version = jar_meta::resolve_jar_version(&a.version, &mut archive);
    }

    // Data-pack content signals (shared by all artifacts in the jar) — real
    // evidence for worldgen / dimension / content capability inference.
    let signals = collect_data_signals(&mut archive);
    for artifact in &mut artifacts {
        artifact.data_signals = signals;
    }

    // Frame-to-jar ownership index: the distinctive class-package roots this jar
    // ships, attached to the primary artifact (Enriched+ level — it enumerates
    // every class entry). A crash frame under one of these roots is owned by this
    // mod. Shared with all artifacts so a hybrid jar's roots are not lost.
    if metadata_level != MetadataLevel::Basic && !artifacts.is_empty() {
        let roots = collect_package_roots(&mut archive);
        if let Some(primary) = artifacts.first_mut() {
            primary.package_roots = roots;
        }
    }

    truncations.sort();
    truncations.dedup();

    Ok(ParsedJar {
        artifacts,
        roles,
        detached_providers,
        inactive_nested,
        truncations,
        identity_certainty,
        descriptor_candidates,
    })
}

fn has_self_loader_bootstrap<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    expected_loader: Loader,
) -> bool {
    let has = |archive: &mut zip::ZipArchive<R>, name: &str| archive.by_name(name).is_ok();
    let transformation_service = has(
        archive,
        "META-INF/services/cpw.mods.modlauncher.api.ITransformationService",
    );
    match expected_loader {
        Loader::Forge => {
            transformation_service
                || has(
                    archive,
                    "META-INF/services/net.minecraftforge.forgespi.locating.IModLocator",
                )
                || has(
                    archive,
                    "META-INF/services/net.minecraftforge.forgespi.locating.IDependencyLocator",
                )
                || bounded_zip::read_zip_text_opt(
                    archive,
                    "META-INF/MANIFEST.MF",
                    bounded_zip::MAX_MANIFEST_BYTES,
                )
                .is_some_and(|manifest| {
                    manifest
                        .lines()
                        .any(|line| line.starts_with("FMLCorePlugin:"))
                })
        }
        Loader::NeoForge => {
            transformation_service
                || has(
                    archive,
                    "META-INF/services/net.neoforged.neoforgespi.locating.IModFileCandidateLocator",
                )
                || has(
                    archive,
                    "META-INF/services/net.neoforged.neoforgespi.locating.IModLocator",
                )
                || has(
                    archive,
                    "META-INF/services/net.neoforged.neoforgespi.transformation.ClassProcessorProvider",
                )
        }
        _ => false,
    }
}

fn discover_bootstrap_bridge<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    expected_loader: Option<Loader>,
) -> Option<Artifact> {
    let bridge = intermed_doctor_core::bootstrap_bridge::detect_connector(archive)?;
    let loader = match expected_loader {
        Some(Loader::Forge) => Loader::Forge,
        Some(Loader::NeoForge) => Loader::NeoForge,
        _ => Loader::NeoForge, // the exact NeoForge SPI establishes this family
    };
    Some(Artifact {
        id: bridge.id,
        version: bridge.version.unwrap_or_else(|| "unknown".to_string()),
        loader,
        side: Some("both"),
        deps: Vec::new(),
        dependency_expressions: Vec::new(),
        provides: vec!["fabric-loader".to_string()],
        provided_versions: BTreeMap::new(),
        is_plugin: false,
        manifest_name: "META-INF/MANIFEST.MF",
        api_version: None,
        load_order: None,
        bundled: Vec::new(),
        entrypoints: Vec::new(),
        access_widener_files: Vec::new(),
        access_transforms: Vec::new(),
        coremods: Vec::new(),
        mixin_configs: Vec::new(),
        name: Some("Connector".to_string()),
        description: Some(
            "Loader bootstrap bridge identified from manifest and service-provider entries"
                .to_string(),
        ),
        authors: Vec::new(),
        license: None,
        icon: None,
        update_json: None,
        data_signals: DataSignals::default(),
        bytecode: BytecodeSignals::default(),
        secondary: None,
        package_roots: Vec::new(),
    })
}

/// Distinctive class-package roots a jar ships, for frame-to-jar ownership. Returns
/// dotted 3-segment roots (e.g. `com.foo.mymod`) with ≥2 classes, excluding vanilla
/// and JDK packages a mod jar never legitimately owns. Shaded libraries (kotlin,
/// apache, …) are deliberately *not* excluded — the blame rule treats a package
/// owned by ≥2 mods as ambiguous, so a shared shaded lib yields no wrong blame.
fn collect_package_roots<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Vec<String> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let name = entry.name();
        if !name.ends_with(".class") {
            continue;
        }
        let Some(slash) = name.rfind('/') else {
            continue; // default-package class — no useful root
        };
        let dir = &name[..slash];
        let root: String = dir.split('/').take(3).collect::<Vec<_>>().join("/");
        if root.is_empty() || is_excluded_owner_package(&root) {
            continue;
        }
        *counts.entry(root).or_default() += 1;
    }
    counts
        .into_iter()
        .filter(|(_, n)| *n >= 2)
        .map(|(r, _)| r.replace('/', "."))
        .collect()
}

/// Packages a mod jar never legitimately *owns* — vanilla and the JDK. Returned
/// roots are slash-form, 3 segments deep.
fn is_excluded_owner_package(root: &str) -> bool {
    const EXCLUDED: &[&str] = &[
        "net/minecraft",
        "com/mojang",
        "java/",
        "javax/",
        "jdk/",
        "sun/",
    ];
    EXCLUDED
        .iter()
        .any(|p| root == p.trim_end_matches('/') || root.starts_with(p))
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
        if category_path.starts_with("dimension/") || category_path.starts_with("dimension_type/") {
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
) -> Vec<String> {
    let mut gaps = Vec::new();
    // Access wideners are listed per-artifact by the Fabric/Quilt manifest.
    for art in artifacts.iter_mut() {
        let files = std::mem::take(&mut art.access_widener_files);
        for file in files {
            let text = match bounded_zip::read_zip_text_bounded(archive, &file, cap_for(&file)) {
                Ok(Some(text)) => text,
                Ok(None) => {
                    gaps.push(format!("loader-declared access widener {file} is missing"));
                    continue;
                }
                Err(error) => {
                    gaps.push(error.reason());
                    continue;
                }
            };
            for d in access::parse_access_widener(&text) {
                art.access_transforms.push(directive_to_transform(&d));
            }
        }
    }

    // Forge / NeoForge Access Transformer + coremods live at fixed paths and apply
    // to the jar as a whole — attach to the primary artifact.
    let at_text = match bounded_zip::read_zip_text_bounded(
        archive,
        "META-INF/accesstransformer.cfg",
        cap_for("META-INF/accesstransformer.cfg"),
    ) {
        Ok(text) => text,
        Err(error) => {
            gaps.push(error.reason());
            None
        }
    };
    let coremods_text = match bounded_zip::read_zip_text_bounded(
        archive,
        "META-INF/coremods.json",
        cap_for("META-INF/coremods.json"),
    ) {
        Ok(text) => text,
        Err(error) => {
            gaps.push(error.reason());
            None
        }
    };
    if at_text.is_none() && coremods_text.is_none() {
        return gaps;
    }
    let Some(primary) = artifacts.first_mut() else {
        return gaps;
    };
    if let Some(text) = at_text {
        for d in access::parse_access_transformer(&text) {
            primary.access_transforms.push(directive_to_transform(&d));
        }
    }
    if let Some(text) = coremods_text {
        match parse_coremods(&text) {
            Ok(coremods) => primary.coremods.extend(coremods),
            Err(error) => gaps.push(error),
        }
    }
    gaps
}

/// Inspect only declared entrypoint classes. This keeps full metadata analysis
/// bounded while still identifying loader registration and common lifecycle
/// events from class-file symbols cached with the jar result.
fn enrich_entrypoint_intelligence<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    artifacts: &mut [Artifact],
) -> Vec<String> {
    let mut coverage_gaps = Vec::new();
    // Per-entrypoint detail: precise type / events / priority for each declared
    // entrypoint class (drives `entrypoint_detail`).
    for artifact in artifacts.iter_mut() {
        for entrypoint in &mut artifact.entrypoints {
            let class_name = entrypoint
                .class
                .split("::")
                .next()
                .unwrap_or(&entrypoint.class);
            let path = format!("{}.class", class_name.replace('.', "/"));
            let bytes = match bounded_zip::read_zip_bytes_bounded(archive, &path, cap_for(&path)) {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    coverage_gaps.push(format!("declared entrypoint class {path} is missing"));
                    continue;
                }
                Err(error) => {
                    coverage_gaps.push(error.reason());
                    continue;
                }
            };
            let Some(analysis) = crate::entrypoint_analysis::analyze_entrypoint_class(&bytes)
            else {
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
        artifact.bytecode.referenced_packages = intel.referenced_packages.clone();
        artifact.bytecode.references_truncated = intel.references_truncated;
        artifact.bytecode.call_edges = intel.call_edges.clone();
        artifact.bytecode.call_edges_truncated = intel.call_edges_truncated;
    }
    coverage_gaps.extend(intel.coverage_gaps);
    coverage_gaps
        .into_iter()
        .map(|gap| {
            format!(
                "bytecode metadata scan incomplete ({}/{} class entries processed): {gap}",
                intel.classes_scanned, intel.classes_seen
            )
        })
        .collect()
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
fn parse_coremods(text: &str) -> Result<Vec<String>, String> {
    // ModLauncher uses a Gson-compatible reader; real coremods manifests often
    // retain commented-out entries. Treat those comments as inactive entries,
    // not as corruption of otherwise valid loader metadata.
    let value = intermed_doctor_core::fabric_json::parse_value(text)
        .map_err(|error| format!("META-INF/coremods.json is invalid: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "META-INF/coremods.json root is not an object".to_string())?;
    Ok(object.keys().cloned().collect())
}

fn parse_fabric(text: &str) -> Result<Artifact, ParseErr> {
    let v: serde_json::Value = intermed_doctor_core::fabric_json::parse_value(text)
        .map_err(|e| ParseErr::descriptor("fabric.mod.json", e.to_string()))?;
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
    push_fabric_dep_map(&mut deps, v.get("conflicts"), "conflicts", false);
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
        dependency_expressions: Vec::new(),
        provides,
        provided_versions: BTreeMap::new(),
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
        package_roots: Vec::new(),
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
            lifecycle: None,
            ordering: None,
            join_classpath: None,
            condition: None,
            side: None,
        });
    }
}

fn parse_quilt(text: &str) -> Result<Artifact, ParseErr> {
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| ParseErr::descriptor("quilt.mod.json", e.to_string()))?;
    let ql = v
        .get("quilt_loader")
        .ok_or_else(|| ParseErr::descriptor("quilt.mod.json", "no quilt_loader"))?;
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
    let mut dependency_expressions = Vec::new();
    for (field, relation, mandatory) in [
        ("depends", "depends", true),
        ("breaks", "breaks", true),
        ("suggests", "suggests", false),
        ("recommends", "recommends", false),
    ] {
        let (mut projected, mut expressions) =
            quilt::parse_array(ql.get(field), relation, mandatory);
        deps.append(&mut projected);
        dependency_expressions.append(&mut expressions);
    }
    let provides = ql
        .get("provides")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(quilt_provides_id).collect())
        .unwrap_or_default();
    let provided_versions = ql
        .get("provides")
        .and_then(|x| x.as_array())
        .map(|aliases| {
            aliases
                .iter()
                .filter_map(|alias| {
                    let object = alias.as_object()?;
                    Some((
                        object.get("id")?.as_str()?.to_string(),
                        object.get("version")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let entrypoints = parse_quilt_entrypoints(ql.get("entrypoints"));
    let access_widener_files = quilt_string_or_array(ql.get("access_widener"));
    Ok(Artifact {
        id,
        version,
        loader: Loader::Quilt,
        side,
        deps,
        dependency_expressions,
        provides,
        provided_versions,
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
        package_roots: Vec::new(),
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
        Some("server" | "dedicated_server") => Some("server"),
        Some("*") => Some("both"),
        _ => None,
    }
}

fn quilt_provides_id(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(o) => o.get("id").and_then(|x| x.as_str()).map(str::to_string),
        _ => None,
    }
}

fn parse_legacy_forge(text: &str) -> Result<Vec<Artifact>, ParseErr> {
    let mods = intermed_doctor_core::legacy_forge::parse_mcmod_info(text)
        .map_err(|error| ParseErr::descriptor("mcmod.info", error.to_string()))?;
    if mods.is_empty() {
        return Err(ParseErr::descriptor("mcmod.info", "no mod entries"));
    }
    Ok(mods
        .into_iter()
        .map(|entry| Artifact {
            id: entry.mod_id,
            version: entry.version.unwrap_or_else(|| "unknown".to_string()),
            loader: Loader::Forge,
            side: None,
            deps: entry
                .required_mods
                .iter()
                .filter_map(|requirement| parse_legacy_forge_requirement(requirement))
                .collect(),
            dependency_expressions: Vec::new(),
            provides: Vec::new(),
            provided_versions: BTreeMap::new(),
            is_plugin: false,
            manifest_name: "mcmod.info",
            api_version: None,
            load_order: None,
            bundled: Vec::new(),
            entrypoints: Vec::new(),
            access_widener_files: Vec::new(),
            access_transforms: Vec::new(),
            coremods: Vec::new(),
            mixin_configs: Vec::new(),
            name: entry.name,
            description: entry.description,
            authors: entry.authors,
            license: None,
            icon: entry.logo_file,
            update_json: entry.update_url,
            data_signals: DataSignals::default(),
            bytecode: BytecodeSignals::default(),
            secondary: None,
            package_roots: Vec::new(),
        })
        .collect())
}

/// Legacy Forge dependency tokens occur as `modid`, `modid@range`, or with a
/// load-order prefix such as `required-after:modid@range`. `requiredMods`
/// already establishes mandatory semantics; load-order prefixes are therefore
/// normalized away rather than mistaken for part of the provider id.
fn parse_legacy_forge_requirement(requirement: &str) -> Option<Dep> {
    let token = requirement.trim();
    let token = token
        .split_once(':')
        .filter(|(prefix, _)| {
            matches!(
                *prefix,
                "required-after" | "required-before" | "after" | "before"
            )
        })
        .map_or(token, |(_, value)| value);
    let (id, range) = token
        .split_once('@')
        .map_or((token, "*"), |(id, range)| (id, range));
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    Some(Dep {
        // Legacy FML treated dependency labels as mod identifiers while many
        // published `mcmod.info` files used `Forge` with title case. Canonical
        // provider ids in the fact graph are lowercase (`forge`).
        id: id.to_ascii_lowercase(),
        range: if range.trim().is_empty() {
            "*".to_string()
        } else {
            range.trim().to_string()
        },
        mandatory: true,
        relation: "depends",
        feature: None,
        lifecycle: None,
        ordering: None,
        join_classpath: None,
        condition: None,
        side: None,
    })
}

fn parse_forge_toml(text: &str, loader: Loader) -> Result<Vec<Artifact>, ParseErr> {
    let manifest_name = if loader == Loader::NeoForge {
        "META-INF/neoforge.mods.toml"
    } else {
        "META-INF/mods.toml"
    };
    let v: toml::Value = text
        .parse::<toml::Value>()
        .map_err(|e| ParseErr::descriptor(manifest_name, e.to_string()))?;
    let mods = v
        .get("mods")
        .and_then(|m| m.as_array())
        .ok_or_else(|| ParseErr::descriptor(manifest_name, "no [[mods]]"))?;
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
            dependency_expressions: Vec::new(),
            provides,
            provided_versions: BTreeMap::new(),
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
            name: entry
                .get("displayName")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            description: entry
                .get("description")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            authors: entry
                .get("authors")
                .and_then(|x| x.as_str())
                .map(split_people)
                .unwrap_or_default(),
            license: v
                .get("license")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            icon: entry
                .get("logoFile")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            update_json: entry
                .get("updateJSONURL")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            data_signals: DataSignals::default(),
            bytecode: BytecodeSignals::default(),
            secondary: None,
            package_roots: Vec::new(),
        });
    }
    Ok(out)
}

/// Read `[[mixins]]` and `[[accessTransformers]]` tables from a parsed `mods.toml`.
fn enrich_forge_toml_extras<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    artifacts: &mut [Artifact],
    toml_root: &toml::Value,
) -> Vec<String> {
    let mut gaps = Vec::new();
    if artifacts.is_empty() {
        return gaps;
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
            if let Some(art) = artifacts.iter_mut().find(|a| a.id == owner_id)
                && !art.mixin_configs.iter().any(|c| c == config)
            {
                art.mixin_configs.push(config.to_string());
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
        return gaps;
    }
    let Some(primary) = artifacts.first_mut() else {
        return gaps;
    };
    for file in at_entries {
        let fallback = (!file.contains('/')).then(|| format!("META-INF/{file}"));
        let read = bounded_zip::read_zip_text_bounded(archive, &file, cap_for(&file));
        let text = match read {
            Ok(Some(text)) => text,
            Ok(None) if fallback.is_some() => {
                let Some(fallback) = fallback.as_deref() else {
                    unreachable!("guard guarantees a fallback path")
                };
                match bounded_zip::read_zip_text_bounded(archive, fallback, cap_for(fallback)) {
                    Ok(Some(text)) => text,
                    Ok(None) => {
                        gaps.push(format!(
                            "loader-declared access transformer {file} is missing"
                        ));
                        continue;
                    }
                    Err(error) => {
                        gaps.push(error.reason());
                        continue;
                    }
                }
            }
            Ok(None) => {
                gaps.push(format!(
                    "loader-declared access transformer {file} is missing"
                ));
                continue;
            }
            Err(error) => {
                gaps.push(error.reason());
                continue;
            }
        };
        for d in access::parse_access_transformer(&text) {
            primary.access_transforms.push(directive_to_transform(&d));
        }
    }
    gaps
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
                    x.get("name")
                        .and_then(|name| name.as_str())
                        .map(str::to_string)
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
                    x.get("config")
                        .and_then(|path| path.as_str())
                        .map(str::to_string)
                })
            })
            .collect(),
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
    let parts: Vec<u64> = core.split('.').map(|p| num(p).unwrap_or(0)).collect();
    // Require at least one genuinely-numeric component, else keep the original.
    if core.split('.').next().and_then(num).is_none() {
        return trimmed
            .split('+')
            .next()
            .unwrap_or(trimmed)
            .trim()
            .to_string();
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
    // A numeric SemVer prerelease (`1.2.3-1`) is not automatically a Minecraft
    // prefix. Require the leading group to look like an actual game version and
    // the following component to look like another dotted version. An explicit
    // `mc` prefix is sufficient game-version evidence, but still needs a numeric
    // mod-version component after the dash.
    let game_prefix = looks_like_minecraft_version(groups[0]);
    let later_version = groups[1..]
        .iter()
        .any(|group| starts_numeric(group) && (had_mc || group.contains('.')));
    game_prefix && later_version
}

fn looks_like_minecraft_version(value: &str) -> bool {
    let mut parts = value.split('.');
    matches!(parts.next(), Some("1"))
        && parts
            .next()
            .and_then(|minor| minor.parse::<u16>().ok())
            .is_some_and(|minor| (7..=99).contains(&minor))
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
        add(
            "has_worldgen",
            "worldgen/dimension entrypoint class path",
            0.55,
        );
    }
    if m.data_signals.dimension {
        add(
            "adds_custom_dimension",
            "ships data/<ns>/dimension content",
            0.9,
        );
        add("has_worldgen", "ships custom dimension data", 0.8);
    }

    // ── Rendering: a render event subscription, an AT into a render class, or an
    //    author-declared render/client entrypoint class path ──
    if event_has("render") || event_has("camera") || event_has("hud") || event_has("gui") {
        add(
            "modifies_rendering",
            "subscribes to a render/HUD event",
            0.85,
        );
    } else if at_touches("client/render") || at_touches("client/gui") || at_touches("/render/") {
        add(
            "modifies_rendering",
            "access transform on a render class",
            0.8,
        );
    } else if entry_class_hint("render") || entry_class_hint("shader") || entry_class_hint("gui") {
        add(
            "modifies_rendering",
            "render/shader entrypoint class path",
            0.6,
        );
    }

    // ── Lifecycle / tick / world: from the real subscribed event types ──
    if event_has("tick") {
        add("hooks_game_tick", "subscribes to a tick event", 0.85);
    }
    if event_has("serverstart") || event_has("serverstopp") || event_has("serverlifecycle") {
        add(
            "hooks_server_lifecycle",
            "subscribes to a server-lifecycle event",
            0.85,
        );
    }
    if event_has("world") || event_has("level") || event_has("chunk") {
        add(
            "hooks_world_events",
            "subscribes to a world/chunk event",
            0.8,
        );
    }

    // ── Code-transformation footprint ──
    if !m.mixin_configs.is_empty() {
        add("modifies_game_code", "declares mixin configuration", 0.9);
    }
    if !m.access_transforms.is_empty() || !m.coremods.is_empty() {
        add(
            "deep_runtime_integration",
            "declares access transforms / coremods",
            0.9,
        );
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
    let registers_content = m
        .bytecode
        .capabilities
        .iter()
        .any(|c| c == "registers_content")
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
mod compatibility_bridge_tests {
    use std::io::{Cursor, Write};

    use super::{Loader, compatibility_bridge, discover_bootstrap_bridge};
    use zip::write::SimpleFileOptions;

    #[test]
    fn recognizes_connector_and_forgified_fabric_api_identities() {
        assert_eq!(
            compatibility_bridge(
                "connectormod",
                "Connector-2.0.jar",
                Some("Sinytra Connector"),
                &[],
                Loader::NeoForge,
            ),
            Some(("fabric", "neoforge", "mod-runtime"))
        );
        assert_eq!(
            compatibility_bridge(
                "fabric_api",
                "fabric-api.jar",
                Some("Forgified Fabric API"),
                &["fabric-api".to_string()],
                Loader::Forge,
            ),
            Some(("fabric-api", "forge", "api-surface"))
        );
        assert_eq!(
            compatibility_bridge(
                "fabric_api",
                "fabric-api.jar",
                Some("Fabric API"),
                &[],
                Loader::Fabric,
            ),
            None
        );
    }

    #[test]
    fn recognizes_descriptorless_connector_from_manifest_and_loader_services() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default();
            writer.start_file("META-INF/MANIFEST.MF", options).unwrap();
            writer
                .write_all(
                    b"Manifest-Version: 1.0\nSpecification-Title: connector\nImplementation-Version: 2.0.0\n",
                )
                .unwrap();
            writer
                .start_file(
                    "META-INF/services/cpw.mods.modlauncher.api.ITransformationService",
                    options,
                )
                .unwrap();
            writer
                .write_all(b"org.sinytra.connector.service.ConnectorLoaderService\n")
                .unwrap();
            writer
                .start_file(
                    "META-INF/services/net.neoforged.neoforgespi.locating.IModFileCandidateLocator",
                    options,
                )
                .unwrap();
            writer.write_all(b"org.sinytra.Locator\n").unwrap();
            writer.finish().unwrap();
        }
        cursor.set_position(0);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        let bridge = discover_bootstrap_bridge(&mut archive, Some(Loader::NeoForge))
            .expect("bootstrap bridge");
        assert_eq!(bridge.id, "connector");
        assert_eq!(bridge.version, "2.0.0");
        assert_eq!(bridge.loader, Loader::NeoForge);
    }

    #[test]
    fn recognizes_forge_1_20_connector_locator_contract() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default();
            writer.start_file("META-INF/MANIFEST.MF", options).unwrap();
            writer
                .write_all(
                    b"Manifest-Version: 1.0\nSpecification-Title: Connector\nImplementation-Version: 1.0.0-beta.47+1.20.1\n",
                )
                .unwrap();
            for (service, provider) in [
                (
                    "cpw.mods.modlauncher.api.ITransformationService",
                    "org.sinytra.connector.service.ConnectorLoaderService\n",
                ),
                (
                    "net.minecraftforge.forgespi.locating.IModLocator",
                    "org.sinytra.connector.locator.ConnectorEarlyLocator\n",
                ),
                (
                    "net.minecraftforge.forgespi.locating.IDependencyLocator",
                    "org.sinytra.connector.locator.ConnectorLocator\n",
                ),
            ] {
                writer
                    .start_file(format!("META-INF/services/{service}"), options)
                    .unwrap();
                writer.write_all(provider.as_bytes()).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.set_position(0);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        let bridge = discover_bootstrap_bridge(&mut archive, Some(Loader::Forge))
            .expect("Forge bootstrap bridge");
        assert_eq!(bridge.id, "connector");
        assert_eq!(bridge.version, "1.0.0-beta.47+1.20.1");
        assert_eq!(bridge.loader, Loader::Forge);
    }
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
        assert!(!version_ambiguous("1.2.3-1")); // valid numeric SemVer prerelease
    }
}

#[cfg(test)]
mod fabric_dependency_override_tests {
    use super::{parse_fabric, parse_fabric_dependency_overrides};

    fn override_file(contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "imd-fabric-overrides-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fabric_loader_dependencies.json");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn remove_operation_changes_effective_breaks_without_touching_other_kinds() {
        let path = override_file(
            r#"{
                "version": 1,
                "overrides": {
                    "supplementaries": {
                        "-breaks": { "particular": "*" }
                    }
                }
            }"#,
        );
        let overrides = parse_fabric_dependency_overrides(&path).unwrap();
        let mut artifact = parse_fabric(
            r#"{
                "schemaVersion": 1,
                "id": "supplementaries",
                "version": "3.1.43",
                "depends": { "fabric-api": "*" },
                "breaks": {
                    "particular": "<=1.1.1",
                    "another_mod": "*"
                }
            }"#,
        )
        .unwrap();

        let applied = overrides.apply(&mut artifact);
        assert!(applied.affected);
        assert!(
            artifact
                .deps
                .iter()
                .any(|dep| dep.relation == "depends" && dep.id == "fabric-api")
        );
        assert!(
            artifact
                .deps
                .iter()
                .any(|dep| dep.relation == "breaks" && dep.id == "another_mod")
        );
        assert!(
            !artifact
                .deps
                .iter()
                .any(|dep| dep.relation == "breaks" && dep.id == "particular")
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn replace_suppresses_add_and_remove_for_the_same_dependency_kind() {
        let path = override_file(
            r#"{
                "version": 1,
                "overrides": {
                    "consumer": {
                        "+depends": { "ignored_add": "*" },
                        "-depends": { "old": "*" },
                        "depends": { "replacement": [">=1.0.0", "2.x"] }
                    }
                }
            }"#,
        );
        let overrides = parse_fabric_dependency_overrides(&path).unwrap();
        let mut artifact = parse_fabric(
            r#"{
                "schemaVersion": 1,
                "id": "consumer",
                "version": "1.0.0",
                "depends": { "old": "*" }
            }"#,
        )
        .unwrap();

        let applied = overrides.apply(&mut artifact);
        assert!(applied.affected);
        assert_eq!(artifact.deps.len(), 1);
        assert_eq!(artifact.deps[0].id, "replacement");
        assert_eq!(artifact.deps[0].range, ">=1.0.0 || 2.x");
        assert!(
            applied
                .added
                .contains(&("depends".to_string(), "replacement".to_string()))
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn malformed_override_range_is_rejected_instead_of_weakening_truth() {
        let path = override_file(
            r#"{
                "version": 1,
                "overrides": { "consumer": { "depends": { "api": 3 } } }
            }"#,
        );
        let error = parse_fabric_dependency_overrides(&path).unwrap_err();
        assert!(error.contains("must be a string or string array"));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}

#[cfg(test)]
mod fabric_json_compat_tests {
    use super::parse_fabric;

    #[test]
    fn literal_newlines_inside_strings_match_fabric_loader() {
        let artifact = parse_fabric(
            "{\"schemaVersion\":1,\"id\":\"multiline\",\"version\":\"1.0.0\",\
             \"description\":\"first line\nsecond line\"}",
        )
        .expect("Fabric Loader accepts physical newlines inside quoted strings");
        assert_eq!(artifact.id, "multiline");
        assert_eq!(
            artifact.description.as_deref(),
            Some("first line\nsecond line")
        );
    }

    #[test]
    fn structural_json_errors_remain_errors() {
        assert!(parse_fabric("{\"schemaVersion\":1,\"id\":}").is_err());
        assert!(parse_fabric("{not valid json").is_err());
    }

    #[test]
    fn fabric_soft_conflicts_are_preserved_separately_from_breaks() {
        let artifact = parse_fabric(
            r#"{"schemaVersion":1,"id":"a","version":"1.0.0",
                 "conflicts":{"b":">=2"},"breaks":{"c":"<1"}}"#,
        )
        .expect("fabric metadata");
        assert!(
            artifact
                .deps
                .iter()
                .any(|dependency| dependency.id == "b" && dependency.relation == "conflicts")
        );
        assert!(
            artifact
                .deps
                .iter()
                .any(|dependency| dependency.id == "c" && dependency.relation == "breaks")
        );
    }
}

#[cfg(test)]
mod jar_version_tests {
    use super::{
        MetadataLevel, bounded_zip, parse_jar, parse_jar_for_instance, parse_plugin_yml,
        parse_quilt,
    };
    use intermed_doctor_core::Loader;
    use std::io::Write;

    fn write_jar(entries: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "imd-jarver-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mod.jar");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in entries {
            zip.start_file(*name, opts).unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
        path
    }

    #[test]
    fn quilt_optional_unless_complex_versions_and_server_side_are_preserved() {
        let artifact = parse_quilt(
            r#"{
              "quilt_loader": {
                "id": "quilt_case",
                "version": "1.0.0",
                "depends": [
                  {"id":"optional_api","optional":true,"versions":">=1"},
                  {"id":"conditional_api","unless":"alternative","versions":{"all":[">=2","<3"]}},
                  {"id":"required_a","versions":">=1"},
                  {"id":"required_b","versions":"<2"},
                  [{"id":"choice_a"},{"id":"choice_b"}]
                ]
              },
              "environment": "dedicated_server"
            }"#,
        )
        .expect("Quilt descriptor");
        assert_eq!(artifact.side, Some("server"));
        let optional = artifact
            .deps
            .iter()
            .find(|dep| dep.id == "optional_api")
            .unwrap();
        assert!(!optional.mandatory);
        let conditional = artifact
            .deps
            .iter()
            .find(|dep| dep.id == "conditional_api")
            .unwrap();
        assert!(!conditional.mandatory);
        assert!(
            conditional
                .condition
                .as_deref()
                .is_some_and(|value| value.contains("unless"))
        );
        assert!(conditional.range.contains("\"all\""));
        assert!(
            artifact
                .deps
                .iter()
                .find(|dep| dep.id == "required_a")
                .unwrap()
                .mandatory
        );
        assert!(
            !artifact
                .deps
                .iter()
                .find(|dep| dep.id == "choice_a")
                .unwrap()
                .mandatory
        );
    }

    #[test]
    fn modern_paper_dependencies_and_legacy_provides_keep_their_semantics() {
        let paper = parse_plugin_yml(
            "name: ModernPaper\nversion: 1.0\ndependencies:\n  bootstrap:\n    RegistryPlugin:\n      load: BEFORE\n      required: true\n      join-classpath: false\n  server:\n    OptionalPlugin:\n      load: AFTER\n      required: false\n",
            Loader::Paper,
            "paper-plugin.yml",
        )
        .expect("Paper descriptor");
        let required = paper
            .deps
            .iter()
            .find(|dep| dep.id == "RegistryPlugin")
            .unwrap();
        assert!(required.mandatory);
        assert_eq!(required.lifecycle.as_deref(), Some("bootstrap"));
        assert_eq!(required.ordering.as_deref(), Some("before"));
        assert_eq!(required.join_classpath, Some(false));
        assert!(
            !paper
                .deps
                .iter()
                .find(|dep| dep.id == "OptionalPlugin")
                .unwrap()
                .mandatory
        );

        let legacy = parse_plugin_yml(
            "name: LegacyPlugin\nversion: 1.0\nprovides: [VaultCompat]\nloadbefore: [WorldEdit]\n",
            Loader::Bukkit,
            "plugin.yml",
        )
        .expect("Bukkit descriptor");
        assert_eq!(legacy.provides, vec!["VaultCompat"]);
        assert!(
            !legacy.deps[0].mandatory,
            "loadbefore is ordering, not presence"
        );
    }

    #[test]
    fn bukkit_plugin_is_active_on_paper_but_paper_plugin_is_not_active_on_spigot() {
        let bukkit = write_jar(&[("plugin.yml", "name: BukkitPlugin\nversion: 1.0\n")]);
        let parsed = parse_jar(&bukkit, MetadataLevel::Basic, Some(Loader::Paper)).unwrap();
        assert_eq!(parsed.identity_certainty, "confirmed");
        assert_eq!(parsed.artifacts[0].id, "BukkitPlugin");

        let paper = write_jar(&[("paper-plugin.yml", "name: PaperPlugin\nversion: 1.0\n")]);
        let parsed = parse_jar(&paper, MetadataLevel::Basic, Some(Loader::Spigot)).unwrap();
        assert_eq!(parsed.identity_certainty, "cross-loader-unresolved");
        std::fs::remove_dir_all(bukkit.parent().unwrap()).ok();
        std::fs::remove_dir_all(paper.parent().unwrap()).ok();
    }

    #[test]
    fn forge_jar_version_placeholder_resolves_from_manifest() {
        // Forge replaces `${file.jarVersion}` with the manifest's
        // Implementation-Version at load time; the scanner must do the same so
        // the mod is not dropped from the dependency graph.
        let jar = write_jar(&[
            (
                "META-INF/mods.toml",
                "[[mods]]\nmodId=\"jade\"\nversion=\"${file.jarVersion}\"\n",
            ),
            (
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\nImplementation-Version: 11.13.2+forge\n",
            ),
        ]);
        let parsed = parse_jar(&jar, MetadataLevel::Basic, None).expect("parse");
        let arts = parsed.artifacts;
        let jade = arts.iter().find(|a| a.id == "jade").expect("jade");
        assert_eq!(jade.version, "11.13.2+forge");
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
    }

    #[test]
    fn placeholder_without_manifest_attribute_is_left_intact() {
        // No Implementation-Version to substitute → leave the raw value so the
        // caller can still record it rather than fabricating a version.
        let jar = write_jar(&[(
            "META-INF/mods.toml",
            "[[mods]]\nmodId=\"x\"\nversion=\"${file.jarVersion}\"\n",
        )]);
        let parsed = parse_jar(&jar, MetadataLevel::Basic, None).expect("parse");
        let arts = parsed.artifacts;
        assert_eq!(arts[0].version, "${file.jarVersion}");
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
    }

    #[test]
    fn active_instance_descriptor_wins_over_malformed_inactive_descriptor() {
        let jar = write_jar(&[
            ("fabric.mod.json", "{not valid json"),
            (
                "META-INF/mods.toml",
                "[[mods]]\nmodId=\"forge_mod\"\nversion=\"1.0.0\"\n",
            ),
        ]);

        let artifacts = parse_jar(&jar, MetadataLevel::Basic, Some(Loader::Forge))
            .expect("the active Forge descriptor is valid")
            .artifacts;
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].id, "forge_mod");
        assert_eq!(artifacts[0].loader, Loader::Forge);

        let error = parse_jar(&jar, MetadataLevel::Basic, Some(Loader::Fabric))
            .err()
            .expect("the same malformed descriptor is active for Fabric");
        assert!(error.as_str().contains("fabric.mod.json"));

        let unknown_artifacts = parse_jar(&jar, MetadataLevel::Basic, None)
            .expect("without an instance, select a valid descriptor rather than a broken one")
            .artifacts;
        assert_eq!(unknown_artifacts[0].id, "forge_mod");
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
    }

    #[test]
    fn foreign_descriptor_with_target_loader_service_is_not_a_hard_mismatch() {
        let jar = write_jar(&[
            (
                "fabric.mod.json",
                "{\"schemaVersion\":1,\"id\":\"universal_bootstrap\",\"version\":\"1.0.0\",\"depends\":{\"fabricloader\":\"*\"}}",
            ),
            (
                "META-INF/services/cpw.mods.modlauncher.api.ITransformationService",
                "example.UniversalTransformationService\n",
            ),
        ]);

        let parsed = parse_jar(&jar, MetadataLevel::Basic, Some(Loader::Forge))
            .expect("universal bootstrap");
        assert_eq!(parsed.artifacts[0].id, "universal_bootstrap");
        assert_eq!(parsed.identity_certainty, "self-loader-bootstrap");
        assert!(
            parsed
                .descriptor_candidates
                .iter()
                .any(|candidate| candidate.contains("target-loader-bootstrap"))
        );

        let plain = write_jar(&[(
            "fabric.mod.json",
            "{\"schemaVersion\":1,\"id\":\"fabric_only\",\"version\":\"1.0.0\"}",
        )]);
        assert_eq!(
            parse_jar(&plain, MetadataLevel::Basic, Some(Loader::Forge))
                .expect("foreign descriptor")
                .identity_certainty,
            "cross-loader-unresolved"
        );
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
        std::fs::remove_dir_all(plain.parent().unwrap()).ok();
    }

    #[test]
    fn forge_1_12_prefers_mcmod_info_over_inert_mods_toml() {
        let jar = write_jar(&[
            (
                "META-INF/mods.toml",
                "[[mods]]\nmodId=\"enhancedvisuals\"\nversion=\"1.3.0\"\n\n[[dependencies.enhancedvisuals]]\nmodId=\"creativecore\"\nmandatory=true\nversionRange=\"[2.0.0,)\"\n",
            ),
            (
                "mcmod.info",
                r#"[{"modid":"enhancedvisuals","version":"1.3","requiredMods":[]}]"#,
            ),
        ]);
        let parsed = parse_jar_for_instance(&jar, MetadataLevel::Basic, Some(Loader::Forge), true)
            .expect("parse legacy Forge identity");
        assert_eq!(parsed.artifacts[0].manifest_name, "mcmod.info");
        assert!(parsed.artifacts[0].deps.is_empty());
        assert_eq!(parsed.identity_certainty, "confirmed");
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
    }

    #[test]
    fn neoforge_instance_selects_neoforge_descriptor_when_both_exist() {
        let jar = write_jar(&[
            (
                "META-INF/mods.toml",
                "[[mods]]\nmodId=\"forge_identity\"\nversion=\"1.0.0\"\n",
            ),
            (
                "META-INF/neoforge.mods.toml",
                "[[mods]]\nmodId=\"neoforge_identity\"\nversion=\"1.0.0\"\n",
            ),
        ]);
        let artifacts = parse_jar(&jar, MetadataLevel::Basic, Some(Loader::NeoForge))
            .expect("parse NeoForge descriptor")
            .artifacts;
        assert_eq!(artifacts[0].id, "neoforge_identity");
        assert_eq!(artifacts[0].loader, Loader::NeoForge);
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
    }

    #[test]
    fn unknown_loader_does_not_promote_first_of_multiple_descriptors() {
        let jar = write_jar(&[
            (
                "fabric.mod.json",
                r#"{"schemaVersion":1,"id":"fabric_identity","version":"1.0.0","depends":{"fabric-api":"*"}}"#,
            ),
            (
                "META-INF/neoforge.mods.toml",
                "[[mods]]\nmodId=\"neoforge_identity\"\nversion=\"1.0.0\"\n",
            ),
        ]);
        let parsed = parse_jar(&jar, MetadataLevel::Basic, None).expect("parse candidates");
        assert_eq!(parsed.identity_certainty, "undecidable");
        assert_eq!(parsed.descriptor_candidates.len(), 2);
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
    }

    #[test]
    fn authoritative_forge_does_not_activate_fabric_only_descriptor() {
        let jar = write_jar(&[(
            "fabric.mod.json",
            r#"{"schemaVersion":1,"id":"geckolib3","version":"3.0.42","depends":{"fabric":"*"}}"#,
        )]);
        let parsed = parse_jar(&jar, MetadataLevel::Basic, Some(Loader::Forge)).expect("parse");
        assert_eq!(parsed.artifacts[0].id, "geckolib3");
        assert_eq!(parsed.identity_certainty, "cross-loader-unresolved");
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
    }

    #[test]
    fn cap_for_picks_per_entry_limit() {
        use super::cap_for;
        assert_eq!(
            cap_for("META-INF/jars/inner.jar"),
            bounded_zip::MAX_NESTED_JAR_BYTES
        );
        assert_eq!(cap_for("foo/Bar.class"), bounded_zip::MAX_CLASS_BYTES);
        assert_eq!(cap_for("mymod-refmap.json"), bounded_zip::MAX_REFMAP_BYTES);
        assert_eq!(
            cap_for("mymod.mixins.json"),
            bounded_zip::MAX_MIXIN_CONFIG_BYTES
        );
        assert_eq!(cap_for("fabric.mod.json"), bounded_zip::MAX_MANIFEST_BYTES);
    }

    #[test]
    fn oversized_manifest_truncates_and_is_skipped() {
        // A manifest past the cap must not be parsed (the mod is dropped) and the
        // truncation must be reported, not silently swallowed.
        let huge = format!(
            "{{\"id\":\"x\",\"version\":\"1.0.0\",\"_pad\":\"{}\"}}",
            "a".repeat((bounded_zip::MAX_MANIFEST_BYTES as usize) + 16)
        );
        let jar = write_jar(&[("fabric.mod.json", &huge)]);
        let parsed = parse_jar(&jar, MetadataLevel::Basic, None).expect("parse");
        let arts = parsed.artifacts;
        let trunc = parsed.truncations;
        assert!(
            arts.is_empty(),
            "oversized manifest must not yield an artifact"
        );
        assert!(
            trunc
                .iter()
                .any(|t| t.contains("fabric.mod.json") && t.contains("cap")),
            "expected a scan_truncated reason, got: {trunc:?}"
        );
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
    }

    #[test]
    fn oversized_media_does_not_mark_metadata_scan_incomplete() {
        let descriptor = r#"{"id":"music_mod","version":"1.0.0"}"#;
        let huge_media = "x".repeat((bounded_zip::MAX_MANIFEST_BYTES as usize) + 16);
        let jar = write_jar(&[
            ("fabric.mod.json", descriptor),
            ("musicpack/music/theme.mp3", &huge_media),
            ("assets/music/sounds/theme.ogg", &huge_media),
        ]);
        let parsed = parse_jar(&jar, MetadataLevel::Basic, None).expect("parse");
        let arts = parsed.artifacts;
        let trunc = parsed.truncations;
        assert_eq!(arts.len(), 1);
        assert!(
            trunc.is_empty(),
            "irrelevant assets must not imply incomplete metadata: {trunc:?}"
        );
        std::fs::remove_dir_all(jar.parent().unwrap()).ok();
    }
}
