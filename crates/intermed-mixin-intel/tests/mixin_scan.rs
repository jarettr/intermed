use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_mixin_intel::{scan_mods_dir, MixinOperation};
use zip::write::SimpleFileOptions;

#[test]
fn scan_detects_overlap_and_overwrite_risk() {
    let root = temp_dir("overlap");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    write_mixin_jar(
        &mods.join("alpha.jar"),
        "alpha",
        "alpha.mixins.json",
        "alpha.mixin",
        &[(
            "RenderMixin",
            b"Lorg/spongepowered/asm/mixin/injection/Inject;\0Lnet/minecraft/client/render/WorldRenderer;\0",
        )],
    );
    write_mixin_jar(
        &mods.join("beta.jar"),
        "beta",
        "beta.mixins.json",
        "beta.mixin",
        &[(
            "RenderMixin",
            b"Lorg/spongepowered/asm/mixin/Overwrite;\0Lnet/minecraft/client/render/WorldRenderer;\0",
        )],
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
#[ignore = "requires INTERMED_REAL_MODS_DIR pointing at a directory of real mod jars"]
fn scans_real_mods_dir_for_mixin_metadata_when_available() {
    let Ok(dir) = std::env::var("INTERMED_REAL_MODS_DIR") else {
        eprintln!("INTERMED_REAL_MODS_DIR not set; skipping real-mod mixin smoke");
        return;
    };

    let scan = scan_mods_dir(Path::new(&dir)).unwrap();
    assert_eq!(scan.target, dir);
}

fn write_mixin_jar(
    path: &Path,
    id: &str,
    config_name: &str,
    package: &str,
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
