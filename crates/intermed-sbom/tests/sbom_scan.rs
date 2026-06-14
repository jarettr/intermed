use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_sbom::{scan_mods_dir, DistributionPlatform, SignatureStrength, SourceClass};
use zip::write::SimpleFileOptions;

#[test]
fn scan_records_checksum_and_identity_for_fabric_jar() {
    let root = temp_dir("fabric");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_fabric_jar(&mods.join("alpha.jar"), "alpha");

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.failures.len(), 0);
    assert_eq!(scan.records.len(), 1);
    let r = &scan.records[0];
    assert_eq!(r.archive, "alpha.jar");
    assert_eq!(r.mod_id.as_deref(), Some("alpha"));
    assert_eq!(r.version.as_deref(), Some("1.0.0"));
    assert_eq!(r.loader.as_deref(), Some("fabric"));
    assert_eq!(r.source_class, SourceClass::Identified);
    assert!(!r.is_unidentified());
    assert_eq!(r.trust_score, 90);
    assert_eq!(r.signature_strength, SignatureStrength::Unsigned);
    assert!(!r.sha256.is_empty());

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_records_forge_mods_toml_identity() {
    let root = temp_dir("forge");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_forge_jar(&mods.join("jei.jar"), "jei", "15.0.0");

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.records.len(), 1);
    let r = &scan.records[0];
    assert_eq!(r.mod_id.as_deref(), Some("jei"));
    assert_eq!(r.loader.as_deref(), Some("forge"));
    assert_eq!(r.source_class, SourceClass::Identified);
    assert!(!r.is_unidentified());

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_marks_manifestless_jar_as_unknown_source() {
    let root = temp_dir("unknown");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_raw_jar(&mods.join("mystery.jar"), b"payload");

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.records.len(), 1);
    assert!(scan.records[0].is_unidentified());
    assert_eq!(scan.records[0].source_class, SourceClass::Unidentified);
    assert_eq!(scan.records[0].trust_score, 20);

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_tolerates_corrupt_jar() {
    let root = temp_dir("corrupt");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    std::fs::write(mods.join("broken.jar"), b"not-a-zip").unwrap();

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.records.len(), 0);
    assert_eq!(scan.failures.len(), 1);
    assert_eq!(scan.failures[0].archive, "broken.jar");

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_detects_modrinth_platform_and_upgrades_source_class() {
    let root = temp_dir("modrinth");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_fabric_jar_with_custom(
        &mods.join("listed.jar"),
        "listed",
        r#""modrinth": { "project-id": "abc" }"#,
    );

    let scan = scan_mods_dir(&mods).unwrap();
    let r = &scan.records[0];
    assert_eq!(r.source_class, SourceClass::PlatformListed);
    assert_eq!(r.platform, Some(DistributionPlatform::Modrinth));
    assert!(r.trust_score >= 98);

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_detects_certified_jar_signature() {
    let root = temp_dir("signed");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_signed_fabric_jar(&mods.join("signed.jar"), "signed");

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.records[0].signature_strength, SignatureStrength::Certified);
    assert!(scan.records[0].signed);
    assert_eq!(scan.records[0].trust_score, 100);

    std::fs::remove_dir_all(root).ok();
}

fn write_forge_jar(path: &Path, id: &str, version: &str) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("META-INF/mods.toml", options).unwrap();
    write!(
        zip,
        r#"
modLoader="javafml"
loaderVersion="[47,)"
[[mods]]
modId="{id}"
version="{version}"
"#
    )
    .unwrap();
    zip.finish().unwrap();
}

fn write_fabric_jar(path: &Path, id: &str) {
    write_fabric_jar_with_custom(path, id, "");
}

fn write_fabric_jar_with_custom(path: &Path, id: &str, custom_json: &str) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("fabric.mod.json", options).unwrap();
    let custom = if custom_json.is_empty() {
        String::new()
    } else {
        format!(r#","custom": {{{custom_json}}}"#)
    };
    write!(
        zip,
        r#"{{"schemaVersion":1,"id":"{id}","version":"1.0.0"{custom}}}"#
    )
    .unwrap();
    zip.finish().unwrap();
}

fn write_signed_fabric_jar(path: &Path, id: &str) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("fabric.mod.json", options).unwrap();
    write!(
        zip,
        r#"{{"schemaVersion":1,"id":"{id}","version":"1.0.0"}}"#
    )
    .unwrap();
    zip.start_file("META-INF/MANIFEST.SF", options).unwrap();
    zip.write_all(b"Signature-Version: 1.0\n").unwrap();
    zip.start_file("META-INF/MANIFEST.RSA", options).unwrap();
    zip.write_all(b"\x30\x03fake-cert-block").unwrap();
    zip.finish().unwrap();
}

fn write_raw_jar(path: &Path, payload: &[u8]) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("data/x.txt", options).unwrap();
    zip.write_all(payload).unwrap();
    zip.finish().unwrap();
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "intermed-sbom-{label}-{}-{nanos}",
        std::process::id()
    ))
}
