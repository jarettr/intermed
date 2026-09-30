use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_doctor_core::JarCache;
use intermed_sbom::{
    DistributionPlatform, SignatureStrength, SignatureVerification, SourceClass, scan_mods_dir,
    scan_mods_dir_with_cache,
};
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
fn fabric_multiline_description_is_identified_consistently() {
    let root = temp_dir("fabric-multiline");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let file = std::fs::File::create(mods.join("euphoria.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "fabric.mod.json",
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(
        b"{\"schemaVersion\":1,\"id\":\"euphoria\",\"version\":\"1.0.0\",\"description\":\"line one\nline two\"}",
    )
    .unwrap();
    zip.finish().unwrap();

    let scan = scan_mods_dir(&mods).unwrap();
    let record = &scan.records[0];
    assert_eq!(record.mod_id.as_deref(), Some("euphoria"));
    assert_eq!(
        record.identity_status,
        intermed_sbom::IdentityStatus::Parsed
    );
    assert_eq!(record.trust_score, 90);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn descriptorless_connector_uses_exact_bootstrap_identity() {
    let root = temp_dir("connector-bootstrap");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let file = std::fs::File::create(mods.join("opaque-name.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for (name, bytes) in [
        (
            "META-INF/MANIFEST.MF",
            &b"Manifest-Version: 1.0\nSpecification-Title: connector\nImplementation-Version: 2.0.0\n"[..],
        ),
        (
            "META-INF/services/cpw.mods.modlauncher.api.ITransformationService",
            &b"org.sinytra.connector.service.ConnectorLoaderService\n"[..],
        ),
        (
            "META-INF/services/net.neoforged.neoforgespi.locating.IModFileCandidateLocator",
            &b"org.sinytra.connector.locator.ConnectorLocator\n"[..],
        ),
    ] {
        zip.start_file(name, SimpleFileOptions::default()).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();

    let scan = scan_mods_dir(&mods).unwrap();
    let record = &scan.records[0];
    assert_eq!(record.mod_id.as_deref(), Some("connector"));
    assert_eq!(record.version.as_deref(), Some("2.0.0"));
    assert_eq!(record.loader.as_deref(), Some("neoforge"));
    assert_eq!(record.source_class, SourceClass::Identified);
    assert!(!record.is_unidentified());
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn descriptorless_essential_loader_uses_service_and_properties_identity() {
    let root = temp_dir("essential-bootstrap");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let file = std::fs::File::create(mods.join("opaque-name.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for (name, bytes) in [
        (
            "META-INF/MANIFEST.MF",
            &b"Manifest-Version: 1.0\nFMLModType: LIBRARY\n"[..],
        ),
        (
            "META-INF/services/cpw.mods.modlauncher.api.ITransformationService",
            &b"gg.essential.container.loader.stage0.EssentialTransformationService\n"[..],
        ),
        (
            "essential-loader.properties",
            &b"publisherSlug=essential\nmodSlug=essential\npinnedFileVersion=1.3.10.8\n"[..],
        ),
    ] {
        zip.start_file(name, SimpleFileOptions::default()).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();

    let scan = scan_mods_dir(&mods).unwrap();
    let record = &scan.records[0];
    assert_eq!(record.mod_id.as_deref(), Some("essential"));
    assert_eq!(record.version.as_deref(), Some("1.3.10.8"));
    assert_eq!(record.source_class, SourceClass::Identified);
    assert!(!record.is_unidentified());
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn descriptorless_jarjar_container_uses_single_nested_mod_identity() {
    let root = temp_dir("nested-identity");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let nested = build_jar_bytes(&[(
        "META-INF/mods.toml",
        br#"modLoader="kotlinforforge"
loaderVersion="[4,)"
license="LGPL-3.0"
[[mods]]
modId="kotlinforforge"
version="4.12.0"
"#,
    )]);
    let file = std::fs::File::create(mods.join("opaque-container.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "META-INF/jarjar/kffmod-4.12.0.jar",
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    zip.write_all(&nested).unwrap();
    zip.finish().unwrap();

    let scan = scan_mods_dir(&mods).unwrap();
    let record = &scan.records[0];
    assert_eq!(record.mod_id.as_deref(), Some("kotlinforforge"));
    assert_eq!(record.version.as_deref(), Some("4.12.0"));
    assert_eq!(record.loader.as_deref(), Some("forge"));
    assert_eq!(record.source_class, SourceClass::Identified);
    assert!(
        record
            .identity_detail
            .as_deref()
            .is_some_and(|detail| detail.contains("META-INF/jarjar/kffmod-4.12.0.jar"))
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn multi_mod_jarjar_container_is_partial_not_unidentified() {
    let root = temp_dir("multi-nested-identity");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let alpha = build_jar_bytes(&[(
        "fabric.mod.json",
        br#"{"schemaVersion":1,"id":"alpha","version":"1.0.0"}"#,
    )]);
    let beta = build_jar_bytes(&[(
        "fabric.mod.json",
        br#"{"schemaVersion":1,"id":"beta","version":"2.0.0"}"#,
    )]);
    let file = std::fs::File::create(mods.join("multi-container.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for (name, bytes) in [
        ("META-INF/jars/alpha.jar", alpha.as_slice()),
        ("META-INF/jars/beta.jar", beta.as_slice()),
    ] {
        zip.start_file(name, SimpleFileOptions::default()).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();

    let scan = scan_mods_dir(&mods).unwrap();
    let record = &scan.records[0];
    assert_eq!(record.source_class, SourceClass::PartiallyIdentified);
    assert_eq!(record.loader.as_deref(), Some("jarjar"));
    assert!(!record.is_unidentified());
    assert!(
        record
            .identity_detail
            .as_deref()
            .is_some_and(|detail| detail.contains("alpha") && detail.contains("beta"))
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn forge_language_provider_is_partial_artifact_identity() {
    let root = temp_dir("forge-language-provider");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let file = std::fs::File::create(mods.join("configured-defaults.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for (name, bytes) in [
        (
            "META-INF/MANIFEST.MF",
            &b"Manifest-Version: 1.0\nImplementation-Title: Configured Defaults\nImplementation-Version: 8.0.4\nImplementation-URL: https://example.invalid/source\nFMLModType: LANGPROVIDER\n"[..],
        ),
        (
            "META-INF/services/net.minecraftforge.forgespi.language.IModLanguageProvider",
            &b"example.ConfiguredDefaultsLanguageProvider\n"[..],
        ),
    ] {
        zip.start_file(name, SimpleFileOptions::default()).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();

    let scan = scan_mods_dir(&mods).unwrap();
    let record = &scan.records[0];
    assert_eq!(record.mod_id, None);
    assert_eq!(record.version.as_deref(), Some("8.0.4"));
    assert_eq!(record.loader.as_deref(), Some("forge-language-provider"));
    assert_eq!(record.source_class, SourceClass::PartiallyIdentified);
    assert!(!record.is_unidentified());
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn content_cache_never_reuses_the_old_archive_locator() {
    let root = temp_dir("cache-locator");
    let first = root.join("first");
    let second = root.join("second");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let original = first.join("copy-a.jar");
    write_fabric_jar(&original, "alpha");
    std::fs::copy(&original, second.join("examplemod.jar")).unwrap();
    let cache = JarCache::new(true, Some(root.join("cache"))).unwrap();

    let a = scan_mods_dir_with_cache(&first, Some(&cache)).unwrap();
    let b = scan_mods_dir_with_cache(&second, Some(&cache)).unwrap();
    assert_eq!(a.records[0].archive, "copy-a.jar");
    assert_eq!(b.records[0].archive, "examplemod.jar");
    assert!(cache.stats().hits >= 1);

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn content_cache_does_not_freeze_pack_specific_corpus_trust() {
    let root = temp_dir("cache-corpus-context");
    let first = root.join("first");
    let second = root.join("second");
    let first_mods = first.join("mods");
    let second_mods = second.join("mods");
    std::fs::create_dir_all(&first_mods).unwrap();
    std::fs::create_dir_all(&second_mods).unwrap();
    let original = first_mods.join("alpha.jar");
    write_fabric_jar(&original, "alpha");
    std::fs::copy(&original, second_mods.join("alpha.jar")).unwrap();
    std::fs::write(
        second.join("corpus.lock"),
        r#"{"schema":"intermed-corpus-lock-v1","mods":[{"project_id":"alpha"}]}"#,
    )
    .unwrap();
    let cache = JarCache::new(true, Some(root.join("cache"))).unwrap();

    let without_lock = scan_mods_dir_with_cache(&first_mods, Some(&cache)).unwrap();
    let with_lock = scan_mods_dir_with_cache(&second_mods, Some(&cache)).unwrap();

    assert!(!without_lock.records[0].in_corpus_lock);
    assert_eq!(without_lock.records[0].trust_breakdown.corpus_lock, 0);
    assert!(with_lock.records[0].in_corpus_lock);
    assert_eq!(
        with_lock.records[0].corpus_match,
        intermed_sbom::CorpusMatchQuality::KnownProjectIdentity
    );
    assert_eq!(with_lock.records[0].trust_breakdown.corpus_lock, 4);
    assert!(
        cache.stats().hits >= 1,
        "second scan must exercise the cache hit"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn materialization_hash_corroborates_descriptorless_jar_identity() {
    use sha2::{Digest, Sha256};

    let root = temp_dir("materialization-hash-context");
    let first = root.join("first");
    let second = root.join("second");
    let first_mods = first.join("mods");
    let second_mods = second.join("mods");
    std::fs::create_dir_all(&first_mods).unwrap();
    std::fs::create_dir_all(&second_mods).unwrap();
    let original = first_mods.join("library.jar");
    let file = std::fs::File::create(&original).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("example/Library.class", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"not-real-bytecode").unwrap();
    zip.finish().unwrap();
    std::fs::copy(&original, second_mods.join("library.jar")).unwrap();
    let sha256 = format!("{:x}", Sha256::digest(std::fs::read(&original).unwrap()));
    std::fs::write(
        second.join("intermed-materialization.json"),
        format!(
            r#"{{"schema":"intermed-lab-materialization-v1","artifacts":[{{"sha256":"{sha256}"}}]}}"#
        ),
    )
    .unwrap();
    let cache = JarCache::new(true, Some(root.join("cache"))).unwrap();

    let without_manifest = scan_mods_dir_with_cache(&first_mods, Some(&cache)).unwrap();
    let with_manifest = scan_mods_dir_with_cache(&second_mods, Some(&cache)).unwrap();

    assert!(!without_manifest.records[0].in_corpus_lock);
    assert!(with_manifest.records[0].in_corpus_lock);
    assert_eq!(
        with_manifest.records[0].corpus_match,
        intermed_sbom::CorpusMatchQuality::ExactArtifactPin
    );
    assert_eq!(with_manifest.records[0].trust_breakdown.corpus_lock, 7);
    assert!(cache.stats().hits >= 1);
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
fn scan_records_legacy_forge_mcmod_info_identity() {
    let root = temp_dir("legacy-forge");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let file = std::fs::File::create(mods.join("CreativeCore.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("mcmod.info", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(br#"[{"modid":"creativecore","version":"1.10.71"}]"#)
        .unwrap();
    zip.finish().unwrap();

    let scan = scan_mods_dir(&mods).unwrap();
    let record = &scan.records[0];
    assert_eq!(record.mod_id.as_deref(), Some("creativecore"));
    assert_eq!(record.version.as_deref(), Some("1.10.71"));
    assert_eq!(record.loader.as_deref(), Some("forge"));
    assert_eq!(record.source_class, SourceClass::Identified);
    assert!(!record.is_unidentified());
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
fn signature_material_without_valid_crypto_is_not_trusted() {
    let root = temp_dir("signed");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_signed_fabric_jar(&mods.join("signed.jar"), "signed");

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(
        scan.records[0].signature_strength,
        SignatureStrength::Certified
    );
    assert_eq!(
        scan.records[0].signature_verification,
        SignatureVerification::Invalid
    );
    assert!(!scan.records[0].signed);
    assert_eq!(scan.records[0].trust_score, 90);

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn valid_jar_signature_is_cryptographically_verified_when_jdk_is_available() {
    if Command::new("jarsigner").arg("-version").output().is_err()
        || Command::new("keytool").arg("-help").output().is_err()
    {
        return;
    }
    let root = temp_dir("valid-signature");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let jar = mods.join("signed.jar");
    let keystore = root.join("test.p12");
    write_fabric_jar(&jar, "signed");
    let generated = Command::new("keytool")
        .args([
            "-genkeypair",
            "-alias",
            "test",
            "-keyalg",
            "RSA",
            "-dname",
            "CN=InterMed Test",
            "-validity",
            "1",
            "-storetype",
            "PKCS12",
            "-storepass",
            "changeit",
            "-keypass",
            "changeit",
            "-keystore",
        ])
        .arg(&keystore)
        .status()
        .unwrap();
    assert!(generated.success());
    let signed = Command::new("jarsigner")
        .args(["-keystore"])
        .arg(&keystore)
        .args(["-storepass", "changeit"])
        .arg(&jar)
        .arg("test")
        .status()
        .unwrap();
    assert!(signed.success());

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(
        scan.records[0].signature_verification,
        SignatureVerification::Verified
    );
    assert!(scan.records[0].signed);
    assert_eq!(scan.records[0].trust_breakdown.verified_signature, 10);
    assert_eq!(
        scan.records[0].provenance.binary_integrity,
        intermed_sbom::BinaryIntegrity::SignatureVerified
    );
    assert_eq!(
        scan.records[0].provenance.cryptographic_authenticity,
        intermed_sbom::CryptographicAuthenticity::Unestablished
    );

    // Adding content after signing must not retain the verified classification:
    // the new entry is outside the signed digest set.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&jar)
        .unwrap();
    let mut zip = zip::ZipWriter::new_append(file).unwrap();
    zip.start_file("assets/unsigned.txt", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"added after signing").unwrap();
    zip.finish().unwrap();
    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(
        scan.records[0].signature_verification,
        SignatureVerification::Incomplete
    );
    assert!(!scan.records[0].signed);
    assert_eq!(scan.records[0].trust_breakdown.verified_signature, 0);
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

fn build_jar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(&mut cursor);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, payload) in entries {
        zip.start_file(*name, options).unwrap();
        zip.write_all(payload).unwrap();
    }
    zip.finish().unwrap();
    cursor.into_inner()
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
