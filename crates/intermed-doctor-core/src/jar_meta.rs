//! Shared jar-manifest helpers — the single source of truth for reading a jar's
//! `META-INF/MANIFEST.MF` attributes and resolving Forge's load-time version
//! placeholder.
//!
//! Forge substitutes `${file.jarVersion}` in `mods.toml` with the manifest's
//! `Implementation-Version` when the mod loads. Three scanners (metadata, SBOM,
//! identity) need the same substitution; keeping it here prevents the logic from
//! drifting between them (it previously did). All reads go through
//! [`crate::bounded_zip`] so a crafted manifest cannot drive unbounded
//! decompression.

use std::io::{Read, Seek};

use zip::ZipArchive;

use crate::bounded_zip::{self, MAX_MANIFEST_BYTES};

/// The placeholder Forge expands from the jar manifest at load time.
pub const JAR_VERSION_PLACEHOLDER: &str = "${file.jarVersion}";

/// Read a single `Key: Value` attribute from `META-INF/MANIFEST.MF`
/// (e.g. `Implementation-Version`). Returns `None` when the manifest, the
/// attribute, or a value is absent. Manifest line-continuations are not unfolded;
/// the attributes used here (`Implementation-Version`) are short single lines.
#[must_use]
pub fn manifest_attribute<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    key: &str,
) -> Option<String> {
    let text = bounded_zip::read_zip_text_opt(archive, "META-INF/MANIFEST.MF", MAX_MANIFEST_BYTES)?;
    let prefix = format!("{key}:");
    text.lines().find_map(|line| {
        let value = line.strip_prefix(&prefix)?.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

/// Resolve Forge's `${file.jarVersion}` placeholder against the manifest's
/// `Implementation-Version`, mirroring Forge's load-time substitution.
///
/// Returns the version unchanged when it carries no placeholder or the manifest
/// has no `Implementation-Version` — never fabricates a version.
#[must_use]
pub fn resolve_jar_version<R: Read + Seek>(version: &str, archive: &mut ZipArchive<R>) -> String {
    if !version.contains(JAR_VERSION_PLACEHOLDER) {
        return version.to_string();
    }
    match manifest_attribute(archive, "Implementation-Version") {
        Some(impl_version) => version.replace(JAR_VERSION_PLACEHOLDER, &impl_version),
        None => version.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn zip_with(entries: &[(&str, &str)]) -> ZipArchive<Cursor<Vec<u8>>> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            for (name, body) in entries {
                zip.start_file(*name, SimpleFileOptions::default()).unwrap();
                zip.write_all(body.as_bytes()).unwrap();
            }
            zip.finish().unwrap();
        }
        cursor.set_position(0);
        ZipArchive::new(cursor).unwrap()
    }

    #[test]
    fn resolves_placeholder_from_manifest() {
        let mut z = zip_with(&[(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nImplementation-Version: 11.13.2+forge\n",
        )]);
        assert_eq!(
            resolve_jar_version("${file.jarVersion}", &mut z),
            "11.13.2+forge"
        );
    }

    #[test]
    fn leaves_plain_version_untouched() {
        let mut z = zip_with(&[("META-INF/MANIFEST.MF", "Implementation-Version: 9.9\n")]);
        assert_eq!(resolve_jar_version("1.2.3", &mut z), "1.2.3");
    }

    #[test]
    fn keeps_placeholder_when_attribute_absent() {
        let mut z = zip_with(&[("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")]);
        assert_eq!(
            resolve_jar_version("${file.jarVersion}", &mut z),
            "${file.jarVersion}"
        );
    }
}
