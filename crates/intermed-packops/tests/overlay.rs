use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_packops::write_overlay_preview;
use zip::write::SimpleFileOptions;

#[test]
fn overlay_preview_merges_safe_tag_and_writes_manifest() {
    let root = temp_dir("merge");
    let mods = root.join("mods");
    let out = root.join("overlay");
    std::fs::create_dir_all(&mods).unwrap();

    write_fabric_jar(
        &mods.join("alpha.jar"),
        "alpha",
        &[(
            "data/minecraft/tags/items/test.json",
            br#"{"values":["minecraft:stone"]}"#,
        )],
    );
    write_fabric_jar(
        &mods.join("beta.jar"),
        "beta",
        &[(
            "data/minecraft/tags/items/test.json",
            br#"{"values":["minecraft:dirt","minecraft:stone"]}"#,
        )],
    );

    let plan = write_overlay_preview(&mods, &out, false).unwrap();
    assert_eq!(plan.manifest.items.len(), 1);
    assert_eq!(
        plan.manifest.items[0].path,
        "data/minecraft/tags/items/test.json"
    );
    assert_eq!(plan.manifest.items[0].source, "merged tag values");
    assert!(plan.manifest.items[0].safe_to_apply);
    assert!(plan.manifest.safe_to_apply);
    assert!(plan.manifest.skipped.is_empty());

    let merged = std::fs::read_to_string(out.join("data/minecraft/tags/items/test.json")).unwrap();
    assert!(merged.contains("minecraft:dirt"));
    assert!(merged.contains("minecraft:stone"));

    let manifest = std::fs::read_to_string(out.join("intermed-overlay-manifest.json")).unwrap();
    assert!(manifest.contains("intermed-overlay-preview-v1"));
    assert!(mods.join("alpha.jar").is_file());
    assert!(mods.join("beta.jar").is_file());

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn overlay_skips_unsafe_winners_by_default_and_stages_with_flag() {
    let root = temp_dir("unsafe");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    // Two mods write the same recipe (a single-document override).
    write_fabric_jar(
        &mods.join("gamma.jar"),
        "gamma",
        &[("data/example/recipes/widget.json", br#"{"type":"a"}"#)],
    );
    write_fabric_jar(
        &mods.join("delta.jar"),
        "delta",
        &[("data/example/recipes/widget.json", br#"{"type":"b"}"#)],
    );

    // Default: not staged, surfaced as skipped, output stays safe.
    let safe_out = root.join("overlay-safe");
    let plan = write_overlay_preview(&mods, &safe_out, false).unwrap();
    assert!(plan.manifest.items.is_empty());
    assert_eq!(plan.manifest.skipped.len(), 1);
    assert!(plan.manifest.safe_to_apply);
    assert!(!safe_out.join("data/example/recipes/widget.json").exists());

    // Opt in: staged as a lexical-winner preview, marked unsafe.
    let unsafe_out = root.join("overlay-unsafe");
    let plan = write_overlay_preview(&mods, &unsafe_out, true).unwrap();
    assert_eq!(plan.manifest.items.len(), 1);
    assert!(!plan.manifest.items[0].safe_to_apply);
    assert!(!plan.manifest.items[0].runtime_order_known);
    assert!(!plan.manifest.safe_to_apply);
    assert!(plan.manifest.skipped.is_empty());
    assert!(unsafe_out
        .join("data/example/recipes/widget.json")
        .exists());

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn overlay_refuses_existing_output_directory() {
    let root = temp_dir("existing-out");
    let mods = root.join("mods");
    let out = root.join("overlay");
    std::fs::create_dir_all(&mods).unwrap();
    std::fs::create_dir_all(&out).unwrap();

    let err = write_overlay_preview(&mods, &out, false).unwrap_err();
    assert!(err.to_string().contains("already exists"));

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn overlay_does_not_remove_preexisting_temp_directory() {
    let root = temp_dir("preexisting-tmp");
    let mods = root.join("mods");
    let out = root.join("overlay");
    let tmp = root.join(format!(".overlay.tmp-{}", std::process::id()));
    std::fs::create_dir_all(&mods).unwrap();
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(tmp.join("owner.txt"), "not ours").unwrap();

    let err = write_overlay_preview(&mods, &out, false).unwrap_err();
    assert!(err
        .to_string()
        .contains("temporary overlay path already exists"));
    assert_eq!(
        std::fs::read_to_string(tmp.join("owner.txt")).unwrap(),
        "not ours"
    );

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn overlay_cleans_temp_directory_after_stage_error() {
    let root = temp_dir("cleanup");
    let mods = root.join("missing-mods");
    let out = root.join("overlay");
    let tmp = root.join(format!(".overlay.tmp-{}", std::process::id()));

    let err = write_overlay_preview(&mods, &out, false).unwrap_err();
    assert!(err.to_string().contains("mods directory does not exist"));
    assert!(!tmp.exists());

    std::fs::remove_dir_all(root).ok();
}

fn write_fabric_jar(path: &Path, id: &str, entries: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.start_file("fabric.mod.json", options).unwrap();
    write!(
        zip,
        r#"{{"schemaVersion":1,"id":"{id}","version":"1.0.0"}}"#
    )
    .unwrap();

    for (name, bytes) in entries {
        zip.start_file(name, options).unwrap();
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
        "intermed-packops-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
