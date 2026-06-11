use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_vfs::{scan_mods_dir, ConflictClass};
use zip::write::SimpleFileOptions;

#[test]
fn scan_classifies_all_collision_classes_deterministically() {
    let root = temp_dir("classes");
    let mods = root.join("mods");
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
            br#"{"values":["minecraft:dirt"]}"#,
        )],
    );
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
    write_fabric_jar(
        &mods.join("epsilon.jar"),
        "epsilon",
        &[(
            "assets/example/lang/en_us.json",
            br#"{"item.example.a":"A"}"#,
        )],
    );
    write_fabric_jar(
        &mods.join("zeta.jar"),
        "zeta",
        &[(
            "assets/example/lang/en_us.json",
            br#"{"item.example.b":"B"}"#,
        )],
    );
    write_fabric_jar(
        &mods.join("same-a.jar"),
        "same_a",
        &[("pack.mcmeta", br#"{"pack":{"pack_format":15}}"#)],
    );
    write_fabric_jar(
        &mods.join("same-b.jar"),
        "same_b",
        &[("pack.mcmeta", br#"{"pack":{"pack_format":15}}"#)],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.failures, Vec::new());
    assert_eq!(scan.writes.len(), 8);
    assert_eq!(scan.collisions.len(), 4);

    let classes: BTreeMap<_, _> = scan
        .collisions
        .iter()
        .map(|c| (c.path.as_str(), c.class))
        .collect();
    assert_eq!(
        classes["data/minecraft/tags/items/test.json"],
        ConflictClass::SafeCrdtMerge
    );
    assert_eq!(
        classes["data/example/recipes/widget.json"],
        ConflictClass::UnsafeReplace
    );
    assert_eq!(
        classes["assets/example/lang/en_us.json"],
        ConflictClass::JsonMergeCandidate
    );
    assert_eq!(classes["pack.mcmeta"], ConflictClass::Identical);

    let second = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.collisions, second.collisions);

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_skips_unsafe_archive_paths_and_records_corrupt_jars() {
    let root = temp_dir("negative");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    write_fabric_jar(
        &mods.join("safe.jar"),
        "safe",
        &[
            (
                "data/example/tags/items/good.json",
                br#"{"values":["safe:x"]}"#,
            ),
            ("data/../outside.json", br#"{"values":["bad:x"]}"#),
            ("/assets/example/bad.txt", b"bad"),
        ],
    );
    std::fs::write(mods.join("broken.jar"), b"not a zip archive").unwrap();

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.writes.len(), 1);
    assert_eq!(scan.writes[0].path, "data/example/tags/items/good.json");
    assert_eq!(scan.failures.len(), 1);
    assert_eq!(scan.failures[0].archive, "broken.jar");
    assert!(scan.failures[0].reason.contains("zip"));

    std::fs::remove_dir_all(root).ok();
}

#[test]
#[ignore = "requires INTERMED_REAL_MODS_DIR pointing at a directory of real mod jars"]
fn scans_real_mods_dir_when_available() {
    let Ok(dir) = std::env::var("INTERMED_REAL_MODS_DIR") else {
        eprintln!("INTERMED_REAL_MODS_DIR not set; skipping real-mod smoke");
        return;
    };

    let scan = scan_mods_dir(Path::new(&dir)).unwrap();
    assert_eq!(scan.target, dir);
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
        "intermed-vfs-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
