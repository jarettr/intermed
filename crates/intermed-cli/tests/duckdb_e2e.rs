use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use zip::write::SimpleFileOptions;

#[test]
fn doctor_duckdb_logic_finds_duplicate_id() {
    let fixture = Fixture::new("duckdb-logic");
    fixture.write_duplicate_id_mods();

    let output = run(["doctor", fixture.mods_str(), "--logic", "duckdb", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["id"] == "duplicate-id:dupe"));
    assert!(
        report["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == "duckdb-rule-pack")
    );
}

#[test]
fn doctor_db_persist_and_query_round_trip() {
    let fixture = Fixture::new("duckdb-persist");
    fixture.write_safe_merge_mods();
    let db = fixture.root.join("history.duckdb");

    let doctor = run([
        "doctor",
        fixture.mods_str(),
        "--db",
        db.to_str().unwrap(),
        "--json",
    ]);
    assert_success(&doctor);
    assert!(db.is_file());

    let query = run([
        "db",
        "query",
        "--db",
        db.to_str().unwrap(),
        "SELECT kind, COUNT(*) AS n FROM facts GROUP BY kind ORDER BY kind",
    ]);
    assert_success(&query);
    let stdout = String::from_utf8(query.stdout).unwrap();
    assert!(stdout.contains("kind"));
    assert!(stdout.contains("resource_writer") || stdout.contains("mod"));

    let count = run([
        "db",
        "query",
        "--db",
        db.to_str().unwrap(),
        "SELECT COUNT(*) FROM facts WHERE kind = 'resource_writer'",
    ]);
    assert_success(&count);
    let stdout = String::from_utf8(count.stdout).unwrap();
    // `parse().unwrap_or(0)`: the 2nd line may exist but not be a number if the
    // CLI's output format changes or it emits an error/localized text — degrade
    // to 0 (which fails the assertion below) instead of panicking on parse.
    let n: i64 = stdout
        .lines()
        .nth(1)
        .unwrap_or("0")
        .trim()
        .parse()
        .unwrap_or(0);
    assert!(n >= 2, "expected resource_writer facts, got: {stdout}");
}

struct Fixture {
    root: std::path::PathBuf,
    mods: std::path::PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "intermed-duckdb-e2e-{label}-{}-{nanos}",
            std::process::id()
        ));
        let mods = root.join("mods");
        std::fs::create_dir_all(&mods).unwrap();
        Self { root, mods }
    }

    fn mods_str(&self) -> &str {
        self.mods.to_str().unwrap()
    }

    fn write_duplicate_id_mods(&self) {
        write_fabric_jar(&self.mods.join("alpha.jar"), "dupe", &[]);
        write_fabric_jar(&self.mods.join("beta.jar"), "dupe", &[]);
    }

    fn write_safe_merge_mods(&self) {
        write_fabric_jar(
            &self.mods.join("alpha.jar"),
            "alpha",
            &[(
                "data/minecraft/tags/items/test.json",
                br#"{"values":["minecraft:stone"]}"#,
            )],
        );
        write_fabric_jar(
            &self.mods.join("beta.jar"),
            "beta",
            &[(
                "data/minecraft/tags/items/test.json",
                br#"{"values":["minecraft:dirt"]}"#,
            )],
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).ok();
    }
}

fn run<const N: usize>(args: [&str; N]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_intermed"))
        .args(args)
        .output()
        .unwrap()
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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
