//! Forge / NeoForge `@Mod` annotation discovery (Tier-2 metadata path).
//!
//! Some jars ship without `mods.toml` but declare mod ids via
//! `net.minecraftforge.fml.common.Mod` or NeoForge equivalents on the entry
//! class. We scan `.class` files with [`cafebabe`] (attributes only, no
//! bytecode) so Layer B can still emit `mod` + `dependency` facts.

use std::io::Read;

use cafebabe::attributes::{Annotation, AnnotationElementValue, AttributeData};
use cafebabe::constant_pool::{ConstantPoolItem, LiteralConstant};
use cafebabe::{ParseOptions, parse_class_with_options};

use intermed_doctor_core::Loader;

use crate::metadata::Artifact;

/// Known `@Mod` annotation descriptors (internal JVM form).
const FORGE_MOD_DESCRIPTOR: &str = "Lnet/minecraftforge/fml/common/Mod;";
const NEOFORGE_MOD_DESCRIPTORS: &[&str] = &[
    "Lnet/neoforged/fml/common/Mod;",
    "Lnet/neoforged/bus/api/Mod;",
];

/// Scan a jar for every `@Mod`-annotated class, returning `(mod_id, entry_class)`.
///
/// Unlike [`discover_mods_from_jar`], this runs even when a `mods.toml` is present:
/// the TOML names the mod but not its entry class, so this is how a `mods.toml`
/// Forge mod gets an `entrypoint` fact (the `@Mod` class is the entrypoint).
pub fn discover_mod_entrypoints(
    archive: &mut zip::ZipArchive<std::fs::File>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        let name = entry.name().to_string();
        if !name.ends_with(".class") || name.contains('$') {
            continue;
        }
        let mut bytes = Vec::new();
        if entry.read_to_end(&mut bytes).is_err() {
            continue;
        }
        if let Some((mod_id, _loader)) = extract_mod_annotation(&bytes) {
            if out.iter().any(|(id, _)| id == &mod_id) {
                continue;
            }
            let entry_class = name
                .strip_suffix(".class")
                .unwrap_or(&name)
                .replace('/', ".");
            out.push((mod_id, entry_class));
        }
    }
    out
}

/// Scan a jar for `@Mod`-annotated classes when no JSON/TOML/YAML manifest exists.
pub fn discover_mods_from_jar(archive: &mut zip::ZipArchive<std::fs::File>) -> Vec<Artifact> {
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(i) else {
            continue;
        };
        let name = entry.name().to_string();
        if !name.ends_with(".class") || name.contains('$') {
            continue;
        }
        let mut bytes = Vec::new();
        if entry.read_to_end(&mut bytes).is_err() {
            continue;
        }
        if let Some((mod_id, loader)) = extract_mod_annotation(&bytes) {
            if out.iter().any(|a: &Artifact| a.id == mod_id) {
                continue;
            }
            // The `@Mod`-annotated class is the mod's entrypoint.
            let entry_class = name
                .strip_suffix(".class")
                .unwrap_or(&name)
                .replace('/', ".");
            out.push(Artifact {
                id: mod_id,
                version: "0".to_string(),
                loader,
                side: None,
                deps: Vec::new(),
                provides: Vec::new(),
                is_plugin: false,
                manifest_name: "@Mod",
                api_version: None,
                load_order: None,
                bundled: Vec::new(),
                entrypoints: vec![crate::metadata::Entrypoint {
                    phase: "mod".to_string(),
                    class: entry_class,
                    entrypoint_type: "main".to_string(),
                    events: Vec::new(),
                    priority: 0,
                }],
                access_widener_files: Vec::new(),
                access_transforms: Vec::new(),
                coremods: Vec::new(),
                mixin_configs: Vec::new(),
                name: None,
                description: None,
                authors: Vec::new(),
                license: None,
                icon: None,
                update_json: None,
                data_signals: crate::metadata::DataSignals::default(),
                bytecode: crate::metadata::BytecodeSignals::default(),
                secondary: None,
                package_roots: Vec::new(),
            });
        }
    }
    out
}

fn extract_mod_annotation(class_bytes: &[u8]) -> Option<(String, Loader)> {
    if class_bytes.len() < 4 || class_bytes[..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
        return None;
    }
    let mut opts = ParseOptions::default();
    opts.parse_bytecode(false);
    if let Ok(class) = parse_class_with_options(class_bytes, &opts) {
        for attr in &class.attributes {
            let AttributeData::RuntimeVisibleAnnotations(annotations) = &attr.data else {
                continue;
            };
            for annotation in annotations {
                if let Some(id) = mod_id_from_annotation(annotation) {
                    let loader =
                        loader_from_mod_descriptor(&annotation.type_descriptor.to_string());
                    return Some((id, loader));
                }
            }
        }
        if let Some(found) = extract_mod_from_constant_pool_strings(class_bytes) {
            return Some(found);
        }
    }
    extract_mod_from_embedded_strings(class_bytes)
}

/// Fallback when attribute parsing fails: `@Mod` leaves descriptor + id strings in the pool.
fn extract_mod_from_constant_pool_strings(class_bytes: &[u8]) -> Option<(String, Loader)> {
    let mut opts = ParseOptions::default();
    opts.parse_bytecode(false);
    let class = parse_class_with_options(class_bytes, &opts).ok()?;
    let mut strings = Vec::new();
    for item in class.constantpool_iter() {
        if let ConstantPoolItem::LiteralConstant(LiteralConstant::String(value)) = item {
            strings.push(value.to_string());
        }
    }
    let loader = if strings
        .iter()
        .any(|s| NEOFORGE_MOD_DESCRIPTORS.contains(&s.as_str()))
    {
        Loader::NeoForge
    } else if strings.iter().any(|s| s == FORGE_MOD_DESCRIPTOR) {
        Loader::Forge
    } else {
        return None;
    };
    strings
        .into_iter()
        .find(|s| looks_like_mod_id(s))
        .map(|id| (id, loader))
}

fn loader_from_mod_descriptor(descriptor: &str) -> Loader {
    if descriptor.contains("neoforged") {
        Loader::NeoForge
    } else {
        Loader::Forge
    }
}

/// Last-resort constant-pool UTF8 scan when the structured class parser fails.
fn extract_mod_from_embedded_strings(class_bytes: &[u8]) -> Option<(String, Loader)> {
    let loader = if NEOFORGE_MOD_DESCRIPTORS
        .iter()
        .any(|d| pool_contains_utf8(class_bytes, d))
    {
        Loader::NeoForge
    } else if pool_contains_utf8(class_bytes, FORGE_MOD_DESCRIPTOR) {
        Loader::Forge
    } else {
        return None;
    };
    let mut mod_ids = Vec::new();
    let mut i = 0usize;
    while i + 3 < class_bytes.len() {
        if class_bytes[i] != 1 {
            i += 1;
            continue;
        }
        let len = u16::from_be_bytes([class_bytes[i + 1], class_bytes[i + 2]]) as usize;
        let start = i + 3;
        let end = start.checked_add(len)?;
        if end > class_bytes.len() {
            i += 1;
            continue;
        }
        if let Ok(s) = std::str::from_utf8(&class_bytes[start..end]) {
            if looks_like_mod_id(s) {
                mod_ids.push(s.to_string());
            }
        }
        i = end;
    }
    mod_ids.into_iter().next().map(|id| (id, loader))
}

fn pool_contains_utf8(haystack: &[u8], needle: &str) -> bool {
    let mut i = 0usize;
    while i + 3 < haystack.len() {
        if haystack[i] != 1 {
            i += 1;
            continue;
        }
        let len = u16::from_be_bytes([haystack[i + 1], haystack[i + 2]]) as usize;
        let start = i + 3;
        // `checked_add` to match the twin loop in `forge_mod_ids` (no 64-bit
        // overflow is reachable since `len` is a `u16`, but keep the two scanners
        // consistent).
        let Some(end) = start.checked_add(len) else {
            i += 1;
            continue;
        };
        if end > haystack.len() {
            i += 1;
            continue;
        }
        if let Ok(s) = std::str::from_utf8(&haystack[start..end]) {
            if s == needle {
                return true;
            }
        }
        i = end;
    }
    false
}

fn looks_like_mod_id(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.len() > 64 {
        return false;
    }
    if candidate.contains('/')
        || candidate.contains('.')
        || candidate.starts_with('L')
        || candidate.contains(';')
        || candidate == "value"
        || candidate == "modId"
        || candidate == "Code"
        || candidate == "RuntimeVisibleAnnotations"
        || candidate == "net"
        || candidate == "com"
        || candidate == "java"
        || candidate == "example"
    {
        return false;
    }
    candidate
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn mod_id_from_annotation(annotation: &Annotation<'_>) -> Option<String> {
    let desc = annotation.type_descriptor.to_string();
    if desc != FORGE_MOD_DESCRIPTOR && !NEOFORGE_MOD_DESCRIPTORS.contains(&desc.as_str()) {
        return None;
    }
    for element in &annotation.elements {
        if element.name == "value" || element.name == "modId" {
            if let Some(id) = string_from_element_value(&element.value) {
                return Some(id);
            }
        }
    }
    if annotation.elements.len() == 1 {
        return string_from_element_value(&annotation.elements[0].value);
    }
    None
}

fn string_from_element_value(value: &AnnotationElementValue<'_>) -> Option<String> {
    match value {
        AnnotationElementValue::StringConstant(s) => Some(s.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    #[test]
    fn ignores_non_class_bytes() {
        assert!(extract_mod_annotation(b"not-a-class").is_none());
    }

    #[test]
    fn discovers_mod_id_from_annotation_class() {
        let bytes = include_bytes!("../tests/fixtures/forge_mod_annotated.class");
        let (id, loader) = extract_mod_annotation(bytes).expect("mod");
        assert_eq!(id, "testmod");
        assert_eq!(loader, Loader::Forge);
    }

    fn write_jar(path: &std::path::Path, entries: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in entries {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn jar_scan_finds_mod_without_mods_toml() {
        let dir = std::env::temp_dir().join(format!(
            "intermed-forge-annot-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let jar = dir.join("mod.jar");
        write_jar(
            &jar,
            &[(
                "com/example/ExampleMod.class",
                include_bytes!("../tests/fixtures/forge_mod_annotated.class"),
            )],
        );
        let file = std::fs::File::open(&jar).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mods = discover_mods_from_jar(&mut archive);
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0].id, "testmod");
        std::fs::remove_dir_all(dir).ok();
    }
}
