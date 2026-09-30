//! Shared artifact identity detection.
//!
//! A jar's `(mod_id, loader, version)` is read from exactly one place so that
//! every layer that attributes facts to a mod — metadata, SBOM, security audit,
//! VFS writer attribution — agrees on the subject. Before this existed each
//! layer rolled its own probe: the SBOM read all loader manifests while the
//! security scanner read only `fabric.mod.json` and otherwise fell back to the
//! file name, so `mods/foo-1.2.jar` could appear as `foo` in one layer and
//! `actual_mod_id` in another, breaking cross-layer correlation and dedupe.
//!
//! Every recognised descriptor is collected first. Resolution is explicit and
//! target-aware; an unscoped hybrid archive is ambiguous rather than silently
//! inheriting the parser's iteration order.

use std::fs::File;
use std::path::Path;

use zip::ZipArchive;

use intermed_doctor_core::Loader;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DescriptorKind {
    Paper,
    Bukkit,
    Fabric,
    Quilt,
    NeoForge,
    Forge,
    LegacyForge,
}

impl DescriptorKind {
    pub(crate) const fn manifest_name(self) -> &'static str {
        match self {
            Self::Paper => "paper-plugin.yml",
            Self::Bukkit => "plugin.yml",
            Self::Fabric => "fabric.mod.json",
            Self::Quilt => "quilt.mod.json",
            Self::NeoForge => "META-INF/neoforge.mods.toml",
            Self::Forge => "META-INF/mods.toml",
            Self::LegacyForge => "mcmod.info",
        }
    }

    pub(crate) const fn matches_loader(self, loader: Loader) -> bool {
        matches!(
            (self, loader),
            (Self::Paper, Loader::Paper)
                | (
                    Self::Bukkit,
                    Loader::Bukkit | Loader::Spigot | Loader::Paper
                )
                // Quilt Loader intentionally accepts Fabric mod metadata. A
                // native quilt.mod.json remains preferred when both exist.
                | (Self::Fabric, Loader::Fabric | Loader::Quilt)
                | (Self::Quilt, Loader::Quilt)
                | (Self::NeoForge, Loader::NeoForge)
                | (Self::Forge | Self::LegacyForge, Loader::Forge)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorCandidate {
    pub manifest: String,
    pub identity: ArtifactIdentity,
}

/// A descriptor was physically present but could not participate in identity
/// resolution. Keeping this separate from an absent descriptor prevents shared
/// identity consumers from silently turning malformed metadata into "no
/// manifest".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorFailure {
    pub manifest: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactDescriptorSet {
    pub candidates: Vec<DescriptorCandidate>,
    pub parse_failures: Vec<DescriptorFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityResolutionCertainty {
    Confirmed,
    Ambiguous,
    CrossLoader,
    Invalid,
    Unidentified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIdentityResolution {
    pub identity: Option<ArtifactIdentity>,
    pub certainty: IdentityResolutionCertainty,
    pub candidates: Vec<String>,
    pub failures: Vec<DescriptorFailure>,
}

/// The loader-independent identity of a mod/plugin jar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactIdentity {
    /// Mod/plugin id declared by a loader manifest, if any.
    pub mod_id: Option<String>,
    /// Declared version, if the manifest carried one.
    pub version: Option<String>,
    /// Loader family the identity came from (`fabric`, `quilt`, `forge`,
    /// `neoforge`, `bukkit`, `paper`). `None` when no manifest was recognized.
    pub loader: Option<String>,
}

impl ArtifactIdentity {
    /// True when no loader manifest was recognized (genuinely opaque jar).
    #[must_use]
    pub fn is_unidentified(&self) -> bool {
        self.loader.is_none() && self.mod_id.is_none()
    }
}

fn descriptor_text(
    archive: &mut ZipArchive<File>,
    name: &str,
    failures: &mut Vec<DescriptorFailure>,
) -> Option<String> {
    if name == "mcmod.info" {
        return match intermed_doctor_core::bounded_zip::read_zip_bytes_bounded(
            archive,
            name,
            intermed_doctor_core::bounded_zip::cap_for_entry(name),
        ) {
            Ok(bytes) => bytes.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
            Err(error) => {
                failures.push(DescriptorFailure {
                    manifest: name.to_string(),
                    reason: error.reason(),
                });
                None
            }
        };
    }
    match intermed_doctor_core::bounded_zip::read_zip_text_bounded(
        archive,
        name,
        intermed_doctor_core::bounded_zip::cap_for_entry(name),
    ) {
        Ok(text) => text,
        Err(error) => {
            failures.push(DescriptorFailure {
                manifest: name.to_string(),
                reason: error.reason(),
            });
            None
        }
    }
}

fn parse_failure(failures: &mut Vec<DescriptorFailure>, manifest: &str, reason: impl Into<String>) {
    failures.push(DescriptorFailure {
        manifest: manifest.to_string(),
        reason: reason.into(),
    });
}

fn forge_identity(text: &str, loader: &str) -> Option<ArtifactIdentity> {
    let v: toml::Value = toml::from_str(text).ok()?;
    let entry = v.get("mods").and_then(|m| m.as_array())?.first()?;
    Some(ArtifactIdentity {
        mod_id: entry
            .get("modId")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        version: entry
            .get("version")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        loader: Some(loader.to_string()),
    })
}

fn json_identity(text: &str, loader: &str) -> Option<ArtifactIdentity> {
    // Fabric metadata is parsed by Loader through a lenient Gson reader.  The
    // identity fallback must use the same accepted language as canonical Layer
    // B metadata or one physical artifact can acquire contradictory identities.
    let v = intermed_doctor_core::fabric_json::parse_value(text).ok()?;
    Some(ArtifactIdentity {
        mod_id: v.get("id").and_then(|x| x.as_str()).map(str::to_string),
        version: v
            .get("version")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        loader: Some(loader.to_string()),
    })
}

fn yaml_plugin_identity(text: &str, loader: &str) -> Option<ArtifactIdentity> {
    let v: serde_yaml::Value = serde_yaml::from_str(text).ok()?;
    Some(ArtifactIdentity {
        mod_id: v.get("name").and_then(|x| x.as_str()).map(str::to_string),
        version: v
            .get("version")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        loader: Some(loader.to_string()),
    })
}

/// Parse every supported logical descriptor in an archive.
pub fn descriptor_set_from_zip(archive: &mut ZipArchive<File>) -> ArtifactDescriptorSet {
    let mut candidates = Vec::new();
    let mut parse_failures = Vec::new();
    if let Some(text) = descriptor_text(archive, "fabric.mod.json", &mut parse_failures) {
        if let Some(id) = json_identity(&text, "fabric") {
            candidates.push(DescriptorCandidate {
                manifest: "fabric.mod.json".into(),
                identity: id,
            });
        } else {
            parse_failure(
                &mut parse_failures,
                "fabric.mod.json",
                "descriptor JSON or identity is invalid",
            );
        }
    }
    if let Some(text) = descriptor_text(archive, "quilt.mod.json", &mut parse_failures) {
        // Quilt nests under `quilt_loader`; fall back to flat `id` form too.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            let ql = v.get("quilt_loader");
            let mod_id = ql
                .and_then(|q| q.get("id"))
                .or_else(|| v.get("id"))
                .and_then(|x| x.as_str())
                .map(str::to_string);
            let version = ql
                .and_then(|q| q.get("version"))
                .or_else(|| v.get("version"))
                .and_then(|x| x.as_str())
                .map(str::to_string);
            candidates.push(DescriptorCandidate {
                manifest: "quilt.mod.json".into(),
                identity: ArtifactIdentity {
                    mod_id,
                    version,
                    loader: Some("quilt".to_string()),
                },
            });
        } else {
            parse_failure(
                &mut parse_failures,
                "quilt.mod.json",
                "descriptor JSON is invalid",
            );
        }
    }
    if let Some(text) = descriptor_text(archive, "META-INF/mods.toml", &mut parse_failures) {
        if let Some(id) = forge_identity(&text, "forge") {
            let identity = resolve_identity_version(archive, id);
            candidates.push(DescriptorCandidate {
                manifest: "META-INF/mods.toml".into(),
                identity,
            });
        } else {
            parse_failure(
                &mut parse_failures,
                "META-INF/mods.toml",
                "descriptor TOML or first mod identity is invalid",
            );
        }
    }
    if let Some(text) = descriptor_text(archive, "mcmod.info", &mut parse_failures) {
        match intermed_doctor_core::legacy_forge::parse_mcmod_info(&text) {
            Ok(mods) if !mods.is_empty() => {
                let first = &mods[0];
                candidates.push(DescriptorCandidate {
                    manifest: "mcmod.info".into(),
                    identity: ArtifactIdentity {
                        mod_id: Some(first.mod_id.clone()),
                        version: first.version.clone(),
                        loader: Some("forge".to_string()),
                    },
                });
            }
            Ok(_) => parse_failure(
                &mut parse_failures,
                "mcmod.info",
                "descriptor contains no mod identity",
            ),
            Err(error) => parse_failure(&mut parse_failures, "mcmod.info", error.to_string()),
        }
    }
    if let Some(text) = descriptor_text(archive, "plugin.yml", &mut parse_failures) {
        if let Some(id) = yaml_plugin_identity(&text, "bukkit") {
            candidates.push(DescriptorCandidate {
                manifest: "plugin.yml".into(),
                identity: id,
            });
        } else {
            parse_failure(
                &mut parse_failures,
                "plugin.yml",
                "descriptor YAML or plugin identity is invalid",
            );
        }
    }
    if let Some(text) = descriptor_text(archive, "paper-plugin.yml", &mut parse_failures) {
        if let Some(id) = yaml_plugin_identity(&text, "paper") {
            candidates.push(DescriptorCandidate {
                manifest: "paper-plugin.yml".into(),
                identity: id,
            });
        } else {
            parse_failure(
                &mut parse_failures,
                "paper-plugin.yml",
                "descriptor YAML or plugin identity is invalid",
            );
        }
    }
    if let Some(text) = descriptor_text(archive, "META-INF/neoforge.mods.toml", &mut parse_failures)
    {
        if let Some(id) = forge_identity(&text, "neoforge") {
            let identity = resolve_identity_version(archive, id);
            candidates.push(DescriptorCandidate {
                manifest: "META-INF/neoforge.mods.toml".into(),
                identity,
            });
        } else {
            parse_failure(
                &mut parse_failures,
                "META-INF/neoforge.mods.toml",
                "descriptor TOML or first mod identity is invalid",
            );
        }
    }
    candidates.sort_by(|left, right| left.manifest.cmp(&right.manifest));
    parse_failures.sort_by(|left, right| left.manifest.cmp(&right.manifest));
    ArtifactDescriptorSet {
        candidates,
        parse_failures,
    }
}

fn descriptor_kind(manifest: &str) -> Option<DescriptorKind> {
    match manifest {
        "paper-plugin.yml" => Some(DescriptorKind::Paper),
        "plugin.yml" => Some(DescriptorKind::Bukkit),
        "fabric.mod.json" => Some(DescriptorKind::Fabric),
        "quilt.mod.json" => Some(DescriptorKind::Quilt),
        "META-INF/neoforge.mods.toml" => Some(DescriptorKind::NeoForge),
        "META-INF/mods.toml" => Some(DescriptorKind::Forge),
        "mcmod.info" => Some(DescriptorKind::LegacyForge),
        _ => None,
    }
}

#[must_use]
pub fn resolve_descriptor_set(
    set: &ArtifactDescriptorSet,
    target_loader: Option<Loader>,
) -> ArtifactIdentityResolution {
    let names = set
        .candidates
        .iter()
        .map(|candidate| candidate.manifest.clone())
        .collect::<Vec<_>>();
    let failures = set.parse_failures.clone();
    if set.candidates.is_empty() {
        return ArtifactIdentityResolution {
            identity: None,
            certainty: if failures.is_empty() {
                IdentityResolutionCertainty::Unidentified
            } else {
                IdentityResolutionCertainty::Invalid
            },
            candidates: names,
            failures,
        };
    }
    if let Some(loader) = target_loader {
        let matching = set
            .candidates
            .iter()
            .filter(|candidate| {
                descriptor_kind(&candidate.manifest).is_some_and(|kind| kind.matches_loader(loader))
            })
            .collect::<Vec<_>>();
        let active_failure = set.parse_failures.iter().any(|failure| {
            descriptor_kind(&failure.manifest).is_some_and(|kind| kind.matches_loader(loader))
        });
        if active_failure {
            return ArtifactIdentityResolution {
                identity: None,
                certainty: IdentityResolutionCertainty::Invalid,
                candidates: names,
                failures,
            };
        }
        // Paper and Quilt accept a compatibility descriptor family, but their
        // native descriptor remains the active primary role when both exist.
        if loader == Loader::Paper
            && let Some(candidate) = matching
                .iter()
                .find(|candidate| candidate.manifest == "paper-plugin.yml")
        {
            return ArtifactIdentityResolution {
                identity: Some(candidate.identity.clone()),
                certainty: IdentityResolutionCertainty::Confirmed,
                candidates: names,
                failures,
            };
        }
        if loader == Loader::Quilt
            && let Some(candidate) = matching
                .iter()
                .find(|candidate| candidate.manifest == "quilt.mod.json")
        {
            return ArtifactIdentityResolution {
                identity: Some(candidate.identity.clone()),
                certainty: IdentityResolutionCertainty::Confirmed,
                candidates: names,
                failures,
            };
        }
        return match matching.as_slice() {
            [candidate] => ArtifactIdentityResolution {
                identity: Some(candidate.identity.clone()),
                certainty: IdentityResolutionCertainty::Confirmed,
                candidates: names,
                failures,
            },
            [] => ArtifactIdentityResolution {
                identity: None,
                certainty: IdentityResolutionCertainty::CrossLoader,
                candidates: names,
                failures,
            },
            _ => ArtifactIdentityResolution {
                identity: None,
                certainty: IdentityResolutionCertainty::Ambiguous,
                candidates: names,
                failures,
            },
        };
    }
    match set.candidates.as_slice() {
        [candidate] => ArtifactIdentityResolution {
            identity: Some(candidate.identity.clone()),
            certainty: IdentityResolutionCertainty::Confirmed,
            candidates: names,
            failures,
        },
        _ => ArtifactIdentityResolution {
            identity: None,
            certainty: IdentityResolutionCertainty::Ambiguous,
            candidates: names,
            failures,
        },
    }
}

/// Compatibility helper for callers without target context. It is deliberately
/// conservative: hybrid descriptors no longer acquire an identity by parse order.
pub fn detect_from_zip(archive: &mut ZipArchive<File>) -> ArtifactIdentity {
    resolve_descriptor_set(&descriptor_set_from_zip(archive), None)
        .identity
        .unwrap_or_default()
}

/// Resolve identity for a known target loader. New cross-layer collectors
/// should prefer this over the compatibility helper above; unscoped hybrid
/// archives intentionally remain unidentified.
#[must_use]
pub fn detect_from_zip_for_loader(
    archive: &mut ZipArchive<File>,
    target_loader: Loader,
) -> ArtifactIdentityResolution {
    resolve_descriptor_set(&descriptor_set_from_zip(archive), Some(target_loader))
}

/// Apply Forge's `${file.jarVersion}` → `Implementation-Version` substitution
/// (shared [`jar_meta`] helper) so this identity layer agrees with the metadata
/// and SBOM scanners instead of leaking the raw placeholder.
fn resolve_identity_version(
    archive: &mut ZipArchive<File>,
    mut identity: ArtifactIdentity,
) -> ArtifactIdentity {
    if let Some(version) = identity.version.as_ref() {
        identity.version = Some(intermed_doctor_core::jar_meta::resolve_jar_version(
            version, archive,
        ));
    }
    identity
}

/// The file stem of an archive path (used as a last-resort id).
#[must_use]
pub fn archive_stem(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name)
        .to_string()
}

/// Detect the mod id, falling back to the archive file stem when no manifest id
/// is found. This is the canonical subject for facts about a jar.
pub fn mod_id_or_stem(archive: &mut ZipArchive<File>, archive_path: &str) -> String {
    detect_from_zip(archive)
        .mod_id
        .unwrap_or_else(|| archive_stem(archive_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    fn jar_with(entries: &[(&str, &str)]) -> ZipArchive<File> {
        let dir = std::env::temp_dir().join(format!(
            "imd-identity-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.jar");
        let mut zip = ZipWriter::new(File::create(&path).unwrap());
        for (name, body) in entries {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(body.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
        ZipArchive::new(File::open(&path).unwrap()).unwrap()
    }

    #[test]
    fn reads_fabric_id() {
        let mut z = jar_with(&[("fabric.mod.json", r#"{"id":"sodium","version":"0.5.3"}"#)]);
        let id = detect_from_zip(&mut z);
        assert_eq!(id.mod_id.as_deref(), Some("sodium"));
        assert_eq!(id.loader.as_deref(), Some("fabric"));
        assert_eq!(id.version.as_deref(), Some("0.5.3"));
    }

    #[test]
    fn fabric_identity_accepts_loader_compatible_control_characters() {
        let mut z = jar_with(&[(
            "fabric.mod.json",
            "{\"id\":\"lenient\",\"version\":\"1.2.3\",\"description\":\"first line\nsecond line\"}",
        )]);
        let set = descriptor_set_from_zip(&mut z);
        assert!(set.parse_failures.is_empty());
        let resolved = resolve_descriptor_set(&set, Some(Loader::Fabric));
        assert_eq!(resolved.certainty, IdentityResolutionCertainty::Confirmed);
        assert_eq!(
            resolved.identity.and_then(|identity| identity.mod_id),
            Some("lenient".to_string())
        );
    }

    #[test]
    fn reads_forge_modid_not_filename() {
        // The old security scanner missed this and fell back to the file stem.
        let mut z = jar_with(&[(
            "META-INF/mods.toml",
            "[[mods]]\nmodId=\"create\"\nversion=\"6.0.0\"\n",
        )]);
        let id = detect_from_zip(&mut z);
        assert_eq!(id.mod_id.as_deref(), Some("create"));
        assert_eq!(id.loader.as_deref(), Some("forge"));
    }

    #[test]
    fn reads_neoforge_modid() {
        let mut z = jar_with(&[(
            "META-INF/neoforge.mods.toml",
            "[[mods]]\nmodId=\"jei\"\nversion=\"19.0\"\n",
        )]);
        let id = detect_from_zip(&mut z);
        assert_eq!(id.mod_id.as_deref(), Some("jei"));
        assert_eq!(id.loader.as_deref(), Some("neoforge"));
    }

    #[test]
    fn reads_legacy_forge_mcmod_info() {
        let mut z = jar_with(&[(
            "mcmod.info",
            r#"[{"modid":"creativecore","version":"1.10.71"}]"#,
        )]);
        let id = detect_from_zip(&mut z);
        assert_eq!(id.mod_id.as_deref(), Some("creativecore"));
        assert_eq!(id.loader.as_deref(), Some("forge"));
        assert_eq!(id.version.as_deref(), Some("1.10.71"));
    }

    #[test]
    fn reads_paper_plugin_name() {
        let mut z = jar_with(&[("paper-plugin.yml", "name: MyPlugin\nversion: 1.2.3\n")]);
        let id = detect_from_zip(&mut z);
        assert_eq!(id.mod_id.as_deref(), Some("MyPlugin"));
        assert_eq!(id.loader.as_deref(), Some("paper"));
    }

    #[test]
    fn falls_back_to_stem_when_opaque() {
        let mut z = jar_with(&[("com/example/Foo.class", "x")]);
        assert!(detect_from_zip(&mut z).is_unidentified());
        assert_eq!(
            mod_id_or_stem(&mut z, "mods/mystery-1.0.jar"),
            "mystery-1.0"
        );
    }

    #[test]
    fn hybrid_archive_abstains_without_target_and_resolves_with_target() {
        let mut z = jar_with(&[
            (
                "fabric.mod.json",
                r#"{"id":"fabric_role","version":"1.0.0"}"#,
            ),
            ("plugin.yml", "name: PaperRole\nversion: 2.0.0\n"),
        ]);
        let set = descriptor_set_from_zip(&mut z);
        assert_eq!(set.candidates.len(), 2);
        assert_eq!(
            resolve_descriptor_set(&set, None).certainty,
            IdentityResolutionCertainty::Ambiguous
        );
        let paper = resolve_descriptor_set(&set, Some(Loader::Paper));
        assert_eq!(paper.certainty, IdentityResolutionCertainty::Confirmed);
        assert_eq!(paper.identity.unwrap().mod_id.as_deref(), Some("PaperRole"));
    }

    #[test]
    fn paper_descriptor_is_not_compatible_with_spigot() {
        let mut z = jar_with(&[("paper-plugin.yml", "name: PaperOnly\nversion: 1.0.0\n")]);
        let set = descriptor_set_from_zip(&mut z);
        assert_eq!(
            resolve_descriptor_set(&set, Some(Loader::Spigot)).certainty,
            IdentityResolutionCertainty::CrossLoader
        );
    }

    #[test]
    fn native_paper_descriptor_wins_over_bukkit_fallback_on_paper() {
        let mut z = jar_with(&[
            ("plugin.yml", "name: BukkitRole\nversion: 1.0\n"),
            ("paper-plugin.yml", "name: PaperRole\nversion: 2.0\n"),
        ]);
        let set = descriptor_set_from_zip(&mut z);
        let resolved = resolve_descriptor_set(&set, Some(Loader::Paper));
        assert_eq!(resolved.certainty, IdentityResolutionCertainty::Confirmed);
        assert_eq!(
            resolved.identity.unwrap().mod_id.as_deref(),
            Some("PaperRole")
        );
    }

    #[test]
    fn fabric_descriptor_is_compatible_with_quilt_target() {
        let mut z = jar_with(&[(
            "fabric.mod.json",
            r#"{"id":"fabric_on_quilt","version":"1.0.0"}"#,
        )]);
        let set = descriptor_set_from_zip(&mut z);
        let resolved = resolve_descriptor_set(&set, Some(Loader::Quilt));
        assert_eq!(resolved.certainty, IdentityResolutionCertainty::Confirmed);
        assert_eq!(
            resolved.identity.unwrap().mod_id.as_deref(),
            Some("fabric_on_quilt")
        );
    }

    #[test]
    fn native_quilt_descriptor_wins_over_fabric_fallback_on_quilt() {
        let mut z = jar_with(&[
            (
                "fabric.mod.json",
                r#"{"id":"fabric_role","version":"1.0.0"}"#,
            ),
            (
                "quilt.mod.json",
                r#"{"quilt_loader":{"id":"quilt_role","version":"2.0.0"}}"#,
            ),
        ]);
        let set = descriptor_set_from_zip(&mut z);
        let resolved = resolve_descriptor_set(&set, Some(Loader::Quilt));
        assert_eq!(resolved.certainty, IdentityResolutionCertainty::Confirmed);
        assert_eq!(
            resolved.identity.unwrap().mod_id.as_deref(),
            Some("quilt_role")
        );
    }

    #[test]
    fn malformed_descriptor_is_not_equivalent_to_absent_descriptor() {
        let mut z = jar_with(&[("fabric.mod.json", "{not-json")]);
        let set = descriptor_set_from_zip(&mut z);
        assert!(set.candidates.is_empty());
        assert_eq!(set.parse_failures.len(), 1);
        assert_eq!(set.parse_failures[0].manifest, "fabric.mod.json");
        let resolution = resolve_descriptor_set(&set, Some(Loader::Fabric));
        assert_eq!(resolution.certainty, IdentityResolutionCertainty::Invalid);
    }

    #[test]
    fn target_aware_public_resolution_uses_platform_compatibility() {
        let mut z = jar_with(&[("plugin.yml", "name: LegacyPlugin\nversion: 1.0\n")]);
        let resolution = detect_from_zip_for_loader(&mut z, Loader::Paper);
        assert_eq!(resolution.certainty, IdentityResolutionCertainty::Confirmed);
        assert_eq!(
            resolution.identity.and_then(|identity| identity.mod_id),
            Some("LegacyPlugin".to_string())
        );
    }
}
