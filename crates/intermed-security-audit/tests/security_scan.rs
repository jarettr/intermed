use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_security_audit::fixtures;
use intermed_security_audit::{scan_mods_dir, SecuritySignal, SignalProvenance};
use zip::write::SimpleFileOptions;

#[test]
fn scan_detects_process_spawn_evidence() {
    let root = temp_dir("spawn");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let class = fixtures::class_with_method_ref(
        "java/lang/Runtime",
        "exec",
        "(Ljava/lang/String;)Ljava/lang/Process;",
    );
    write_mod_jar(
        &mods.join("risky.jar"),
        "risky",
        &[("Risky", class.as_slice())],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.failures.len(), 0);
    assert_eq!(scan.records.len(), 1);
    assert!(scan.records[0].has_signal(SecuritySignal::ProcessSpawn));

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_is_clean_for_benign_jar() {
    let root = temp_dir("clean");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let class = fixtures::class_with_utf8_only(&["demo/Hello", "benign/exec/helper"]);
    write_mod_jar(
        &mods.join("safe.jar"),
        "safe",
        &[("Hello", class.as_slice())],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert!(scan.records[0].signals.is_empty());

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_skips_fake_class_entries_without_magic() {
    let root = temp_dir("fake-class");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_mod_jar(
        &mods.join("fake.jar"),
        "fake",
        &[("Fake", b"not-a-real-class-file".as_slice())],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert!(scan.records[0].signals.is_empty());
    assert_eq!(scan.records[0].classes_scanned, 0);

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_corroborates_obfuscated_process_spawn_via_reflection() {
    // Class.forName("java.lang.Runtime").getMethod("exec", …).invoke(…) leaves no
    // Runtime.exec MethodRef — only reflection machinery + string constants.
    let root = temp_dir("obfuscated");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let class = fixtures::class_with_refs_and_strings(
        &[
            (
                "java/lang/reflect/AccessibleObject",
                "setAccessible",
                "(Z)V",
            ),
            (
                "java/lang/Class",
                "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;",
            ),
        ],
        &["java.lang.Runtime", "exec"],
    );
    write_mod_jar(&mods.join("obf.jar"), "obf", &[("Obf", class.as_slice())]);

    let scan = scan_mods_dir(&mods).unwrap();
    let record = &scan.records[0];

    // Reflection machinery is structural; process spawn is corroborated.
    assert!(record.has_signal(SecuritySignal::ReflectionSetAccessible));
    let spawn = record
        .signals
        .iter()
        .find(|d| d.signal == SecuritySignal::ProcessSpawn)
        .expect("process spawn corroborated");
    assert_eq!(spawn.provenance, SignalProvenance::ReflectionCorroborated);

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn scan_does_not_corroborate_strings_without_reflection() {
    // The same strings, but no reflection machinery — must stay silent.
    let root = temp_dir("strings-only");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let class = fixtures::class_with_string_constants(&["java.lang.Runtime", "exec"]);
    write_mod_jar(
        &mods.join("plain.jar"),
        "plain",
        &[("Plain", class.as_slice())],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert!(scan.records[0].signals.is_empty());

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn parallel_scan_is_order_stable_and_deterministic() {
    // Several jars scanned in parallel must aggregate in a stable (path-sorted)
    // order, identically across runs.
    let root = temp_dir("parallel");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    for i in 0..6 {
        let class = fixtures::class_with_method_ref(
            "java/lang/Runtime",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
        );
        write_mod_jar(
            &mods.join(format!("mod-{i}.jar")),
            &format!("mod{i}"),
            &[("R", class.as_slice())],
        );
    }

    let first = scan_mods_dir(&mods).unwrap();
    let second = scan_mods_dir(&mods).unwrap();

    let archives: Vec<&str> = first.records.iter().map(|r| r.archive.as_str()).collect();
    let mut sorted = archives.clone();
    sorted.sort_unstable();
    assert_eq!(archives, sorted, "records must be in path-sorted order");

    let second_archives: Vec<&str> = second.records.iter().map(|r| r.archive.as_str()).collect();
    assert_eq!(
        archives, second_archives,
        "scan order must be deterministic"
    );
    assert_eq!(first.records.len(), 6);

    std::fs::remove_dir_all(root).ok();
}

fn write_mod_jar(path: &Path, id: &str, classes: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("fabric.mod.json", options).unwrap();
    write!(
        zip,
        r#"{{"schemaVersion":1,"id":"{id}","version":"1.0.0"}}"#
    )
    .unwrap();
    for (name, bytes) in classes {
        let class_path = format!("demo/{name}.class");
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
    std::env::temp_dir().join(format!(
        "intermed-security-{label}-{}-{nanos}",
        std::process::id()
    ))
}
