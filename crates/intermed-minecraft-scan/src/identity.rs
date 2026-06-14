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
//! The probe order matches loader precedence: Fabric → Quilt → Forge → Bukkit →
//! Paper → NeoForge. The first manifest that yields an id wins.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use zip::ZipArchive;

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

/// Read a UTF-8 text entry from a zip archive by exact name.
fn read_zip_text(archive: &mut ZipArchive<File>, name: &str) -> Option<String> {
    let mut entry = archive.by_name(name).ok()?;
    let mut buf = String::new();
    entry.read_to_string(&mut buf).ok()?;
    Some(buf)
}

fn forge_identity(text: &str, loader: &str) -> Option<ArtifactIdentity> {
    let v: toml::Value = toml::from_str(text).ok()?;
    let entry = v.get("mods").and_then(|m| m.as_array())?.first()?;
    Some(ArtifactIdentity {
        mod_id: entry.get("modId").and_then(|x| x.as_str()).map(str::to_string),
        version: entry.get("version").and_then(|x| x.as_str()).map(str::to_string),
        loader: Some(loader.to_string()),
    })
}

fn json_identity(text: &str, loader: &str) -> Option<ArtifactIdentity> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    Some(ArtifactIdentity {
        mod_id: v.get("id").and_then(|x| x.as_str()).map(str::to_string),
        version: v.get("version").and_then(|x| x.as_str()).map(str::to_string),
        loader: Some(loader.to_string()),
    })
}

fn yaml_plugin_identity(text: &str, loader: &str) -> Option<ArtifactIdentity> {
    let v: serde_yaml::Value = serde_yaml::from_str(text).ok()?;
    Some(ArtifactIdentity {
        mod_id: v.get("name").and_then(|x| x.as_str()).map(str::to_string),
        version: v.get("version").and_then(|x| x.as_str()).map(str::to_string),
        loader: Some(loader.to_string()),
    })
}

/// Detect a jar's identity by probing its loader manifests in precedence order.
pub fn detect_from_zip(archive: &mut ZipArchive<File>) -> ArtifactIdentity {
    if let Some(text) = read_zip_text(archive, "fabric.mod.json") {
        if let Some(id) = json_identity(&text, "fabric") {
            return id;
        }
    }
    if let Some(text) = read_zip_text(archive, "quilt.mod.json") {
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
            return ArtifactIdentity {
                mod_id,
                version,
                loader: Some("quilt".to_string()),
            };
        }
    }
    if let Some(text) = read_zip_text(archive, "META-INF/mods.toml") {
        if let Some(id) = forge_identity(&text, "forge") {
            return id;
        }
    }
    if let Some(text) = read_zip_text(archive, "plugin.yml") {
        if let Some(id) = yaml_plugin_identity(&text, "bukkit") {
            return id;
        }
    }
    if let Some(text) = read_zip_text(archive, "paper-plugin.yml") {
        if let Some(id) = yaml_plugin_identity(&text, "paper") {
            return id;
        }
    }
    if let Some(text) = read_zip_text(archive, "META-INF/neoforge.mods.toml") {
        if let Some(id) = forge_identity(&text, "neoforge") {
            return id;
        }
    }
    ArtifactIdentity::default()
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
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

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
        assert_eq!(mod_id_or_stem(&mut z, "mods/mystery-1.0.jar"), "mystery-1.0");
    }
}
