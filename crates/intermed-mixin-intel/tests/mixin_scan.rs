use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_mixin_intel::fixtures;
use intermed_mixin_intel::{scan_mods_dir, MixinOperation};
use zip::write::SimpleFileOptions;

#[test]
fn scan_detects_overlap_and_overwrite_risk() {
    let root = temp_dir("overlap");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let alpha_class = fixtures::mixin_class(
        "alpha/mixin/RenderMixin",
        "net/minecraft/client/render/WorldRenderer",
        &["injection/Inject"],
    );
    let beta_class = fixtures::mixin_class(
        "beta/mixin/RenderMixin",
        "net/minecraft/client/render/WorldRenderer",
        &["Overwrite"],
    );
    write_mixin_jar(
        &mods.join("alpha.jar"),
        "alpha",
        "alpha.mixins.json",
        "alpha.mixin",
        &[("RenderMixin", alpha_class.as_slice())],
    );
    write_mixin_jar(
        &mods.join("beta.jar"),
        "beta",
        "beta.mixins.json",
        "beta.mixin",
        &[("RenderMixin", beta_class.as_slice())],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.failures, Vec::new());
    assert_eq!(scan.configs.len(), 2);
    assert_eq!(scan.classes.len(), 2);
    assert_eq!(scan.overlaps.len(), 1);
    assert_eq!(
        scan.overlaps[0].target,
        "net.minecraft.client.render.WorldRenderer"
    );
    assert!(scan.overlaps[0].hot_path);
    assert_eq!(scan.high_risk_overwrites.len(), 1);
    assert_eq!(scan.high_risk_overwrites[0].mod_id, "beta");
    assert_eq!(scan.classes[1].operations, vec![MixinOperation::Overwrite]);

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_records_missing_mixin_class_without_failing_pack() {
    let root = temp_dir("missing-class");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    write_mixin_jar(
        &mods.join("alpha.jar"),
        "alpha",
        "alpha.mixins.json",
        "alpha.mixin",
        &[],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.configs.len(), 1);
    assert_eq!(scan.classes.len(), 0);
    assert_eq!(scan.failures.len(), 1);
    assert!(scan.failures[0].reason.contains("not found"));

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_picks_up_client_and_server_config_entries() {
    let root = temp_dir("client-server");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let client_class = fixtures::mixin_class(
        "alpha/mixin/ClientMixin",
        "net/minecraft/client/Minecraft",
        &["injection/Inject"],
    );
    let server_class = fixtures::mixin_class(
        "alpha/mixin/ServerMixin",
        "net/minecraft/server/MinecraftServer",
        &["injection/ModifyArg"],
    );
    write_mixin_jar_with_config(
        &mods.join("alpha.jar"),
        "alpha",
        "alpha.mixins.json",
        "alpha.mixin",
        r#"{"required":true,"package":"alpha.mixin","mixins":[],"client":["ClientMixin"],"server":["ServerMixin"]}"#,
        &[
            ("ClientMixin", client_class.as_slice()),
            ("ServerMixin", server_class.as_slice()),
        ],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.classes.len(), 2);
    assert!(scan
        .classes
        .iter()
        .any(|c| c.operations.contains(&MixinOperation::ModifyArg)));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_discovers_configs_from_manifest_mixinconfigs() {
    let root = temp_dir("manifest");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let class = fixtures::mixin_class(
        "alpha/mixin/RenderMixin",
        "net/minecraft/client/render/WorldRenderer",
        &["injection/Inject"],
    );
    write_manifest_mixin_jar(
        &mods.join("alpha.jar"),
        "alpha",
        "custom.mixins.json",
        "alpha.mixin",
        class.as_slice(),
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.configs.len(), 1);
    assert_eq!(scan.configs[0].path, "custom.mixins.json");
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn head_and_return_on_same_method_are_disjoint_sites() {
    let root = temp_dir("head-return");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let head_class = fixtures::mixin_class_with_inject_at(
        "alpha/mixin/RenderMixin",
        "net/minecraft/server/MinecraftServer",
        "tick()V",
        "HEAD",
    );
    let return_class = fixtures::mixin_class_with_inject_at(
        "beta/mixin/RenderMixin",
        "net/minecraft/server/MinecraftServer",
        "tick()V",
        "RETURN",
    );
    write_mixin_jar(
        &mods.join("alpha.jar"),
        "alpha",
        "alpha.mixins.json",
        "alpha.mixin",
        &[("RenderMixin", head_class.as_slice())],
    );
    write_mixin_jar(
        &mods.join("beta.jar"),
        "beta",
        "beta.mixins.json",
        "beta.mixin",
        &[("RenderMixin", return_class.as_slice())],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.overlaps.len(), 1);
    assert!(
        !scan.overlaps[0].method_conflict,
        "HEAD and RETURN must not be treated as the same injection site"
    );
    assert!(scan
        .conflict_edges
        .iter()
        .all(|e| e.edge_type != intermed_mixin_intel::ConflictEdgeType::SameInjectionPoint));

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_discovers_quilt_mod_json_mixins() {
    let root = temp_dir("quilt");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let class = fixtures::mixin_class(
        "alpha/mixin/RenderMixin",
        "net/minecraft/client/render/WorldRenderer",
        &["injection/Inject"],
    );
    write_quilt_mixin_jar(
        &mods.join("alpha.jar"),
        "alpha",
        "alpha.mixins.json",
        "alpha.mixin",
        class.as_slice(),
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.configs.len(), 1);
    assert_eq!(scan.classes.len(), 1);
    assert_eq!(scan.configs[0].mod_id, "alpha");

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn refmap_resolution_proves_disjoint_methods_not_conflict() {
    let root = temp_dir("refmap-disjoint");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let alpha_class = fixtures::mixin_class_with_inject_method(
        "alpha/mixin/TickMixin",
        "net/minecraft/server/MinecraftServer",
        "method_1574",
    );
    let beta_class = fixtures::mixin_class_with_inject_method(
        "beta/mixin/RenderMixin",
        "net/minecraft/server/MinecraftServer",
        "method_9999",
    );
    write_mixin_jar_with_refmap(
        &mods.join("alpha.jar"),
        "alpha",
        "alpha.mixins.json",
        "alpha.mixin",
        r#"{"mappings":{"net/minecraft/server/MinecraftServer":{"method_1574":"tick()V"}}}"#,
        &[("TickMixin", alpha_class.as_slice())],
    );
    write_mixin_jar_with_refmap(
        &mods.join("beta.jar"),
        "beta",
        "beta.mixins.json",
        "beta.mixin",
        r#"{"mappings":{"net/minecraft/server/MinecraftServer":{"method_9999":"render()V"}}}"#,
        &[("RenderMixin", beta_class.as_slice())],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.overlaps.len(), 1);
    assert!(
        !scan.overlaps[0].method_conflict,
        "refmap-resolved disjoint methods should not conflict"
    );
    assert!(!scan.risk_assessments.is_empty());

    std::fs::remove_dir_all(root).ok();
}

#[test]
#[ignore = "requires INTERMED_REAL_MODS_DIR pointing at a directory of real mod jars"]
fn scans_real_mods_dir_for_mixin_metadata_when_available() {
    let Ok(dir) = std::env::var("INTERMED_REAL_MODS_DIR") else {
        eprintln!("INTERMED_REAL_MODS_DIR not set; skipping real-mod mixin smoke");
        return;
    };

    let scan = scan_mods_dir(Path::new(&dir)).unwrap();
    assert_eq!(scan.target, dir);
}

fn write_mixin_jar_with_config(
    path: &Path,
    id: &str,
    config_name: &str,
    package: &str,
    config_json: &str,
    classes: &[(&str, &[u8])],
) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.start_file("fabric.mod.json", options).unwrap();
    write!(
        zip,
        r#"{{"schemaVersion":1,"id":"{id}","version":"1.0.0","mixins":["{config_name}"]}}"#
    )
    .unwrap();

    zip.start_file(config_name, options).unwrap();
    zip.write_all(config_json.as_bytes()).unwrap();

    for (class, bytes) in classes {
        let class_path = format!("{}/{}.class", package.replace('.', "/"), class);
        zip.start_file(class_path, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}

fn write_manifest_mixin_jar(
    path: &Path,
    _id: &str,
    config_name: &str,
    package: &str,
    class_bytes: &[u8],
) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
    write!(zip, "Manifest-Version: 1.0\nMixinConfigs: {config_name}\n").unwrap();

    zip.start_file(config_name, options).unwrap();
    write!(
        zip,
        r#"{{"required":true,"package":"{package}","mixins":["RenderMixin"]}}"#
    )
    .unwrap();

    let class_path = format!("{}/RenderMixin.class", package.replace('.', "/"));
    zip.start_file(class_path, options).unwrap();
    zip.write_all(class_bytes).unwrap();
    zip.finish().unwrap();
}

fn write_mixin_jar_with_refmap(
    path: &Path,
    id: &str,
    config_name: &str,
    package: &str,
    refmap_json: &str,
    classes: &[(&str, &[u8])],
) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let refmap_name = format!("{id}.refmap.json");

    zip.start_file("fabric.mod.json", options).unwrap();
    write!(
        zip,
        r#"{{"schemaVersion":1,"id":"{id}","version":"1.0.0","mixins":["{config_name}"]}}"#
    )
    .unwrap();

    zip.start_file(config_name, options).unwrap();
    write!(
        zip,
        r#"{{"required":true,"package":"{package}","refmap":"{refmap_name}","mixins":["{}"]}}"#,
        classes
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join("\",\"")
    )
    .unwrap();

    zip.start_file(&refmap_name, options).unwrap();
    zip.write_all(refmap_json.as_bytes()).unwrap();

    for (class, bytes) in classes {
        let class_path = format!("{}/{}.class", package.replace('.', "/"), class);
        zip.start_file(class_path, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}

fn write_mixin_jar(
    path: &Path,
    id: &str,
    config_name: &str,
    package: &str,
    classes: &[(&str, &[u8])], // bytes from fixtures::mixin_class
) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.start_file("fabric.mod.json", options).unwrap();
    write!(
        zip,
        r#"{{"schemaVersion":1,"id":"{id}","version":"1.0.0","mixins":["{config_name}"]}}"#
    )
    .unwrap();

    zip.start_file(config_name, options).unwrap();
    write!(
        zip,
        r#"{{"required":true,"package":"{package}","priority":1000,"mixins":["RenderMixin"]}}"#
    )
    .unwrap();

    for (class, bytes) in classes {
        let class_path = format!("{}/{}.class", package.replace('.', "/"), class);
        zip.start_file(class_path, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}

fn write_quilt_mixin_jar(
    path: &Path,
    id: &str,
    config_name: &str,
    package: &str,
    class_bytes: &[u8],
) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.start_file("quilt.mod.json", options).unwrap();
    write!(
        zip,
        r#"{{"schema_version":1,"quilt_loader":{{"group":"test","id":"{id}","version":"1.0.0","mixins":["{config_name}"]}}}}"#
    )
    .unwrap();

    zip.start_file(config_name, options).unwrap();
    write!(
        zip,
        r#"{{"required":true,"package":"{package}","mixins":["RenderMixin"]}}"#
    )
    .unwrap();

    let class_path = format!("{}/RenderMixin.class", package.replace('.', "/"));
    zip.start_file(class_path, options).unwrap();
    zip.write_all(class_bytes).unwrap();
    zip.finish().unwrap();
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "intermed-mixin-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
