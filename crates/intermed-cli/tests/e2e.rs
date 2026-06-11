use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use zip::write::SimpleFileOptions;

#[test]
fn vfs_explain_matches_golden_output() {
    let fixture = Fixture::new("vfs-golden");
    fixture.write_safe_merge_mods();

    let output = run(["vfs", "explain", fixture.mods_str()]);
    assert_success(&output);

    let actual = normalize_stdout(&output, &fixture.root);
    assert_eq!(actual, include_str!("golden/vfs_explain_safe_merge.txt"));
}

#[test]
fn doctor_explain_resource_finding_matches_golden_output() {
    let fixture = Fixture::new("doctor-explain");
    fixture.write_safe_merge_mods();

    let output = run([
        "doctor",
        fixture.mods_str(),
        "--explain",
        "resource-conflict:data/minecraft/tags/items/test.json",
        "--no-color",
    ]);
    assert_success(&output);

    let actual = normalize_fact_ids(&normalize_stdout(&output, &fixture.root));
    assert_eq!(actual, include_str!("golden/doctor_explain_resource.txt"));
}

#[test]
fn doctor_dump_facts_contains_phase_two_and_three_facts() {
    let fixture = Fixture::new("dump-facts");
    fixture.write_safe_merge_mods();
    let facts = fixture.root.join("facts.json");

    let output = run([
        "doctor",
        fixture.mods_str(),
        "--dump-facts",
        facts.to_str().unwrap(),
        "--json",
    ]);
    assert_success(&output);

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "intermed-doctor-report-v1");

    let facts: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(facts).unwrap()).unwrap();
    let kinds: Vec<&str> = facts
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f.get("kind").and_then(|k| k.as_str()))
        .collect();
    assert!(kinds.contains(&"resource_writer"));
    assert!(kinds.contains(&"resource_collision"));
    assert!(kinds.contains(&"safe_crdt_merge"));
}

#[test]
fn vfs_overlay_writes_preview_and_manifest_end_to_end() {
    let fixture = Fixture::new("overlay-e2e");
    fixture.write_safe_merge_mods();
    let out = fixture.root.join("overlay");

    let output = run([
        "vfs",
        "overlay",
        fixture.mods_str(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_success(&output);

    let merged = std::fs::read_to_string(out.join("data/minecraft/tags/items/test.json")).unwrap();
    assert!(merged.contains("minecraft:dirt"));
    assert!(merged.contains("minecraft:stone"));
    let manifest = std::fs::read_to_string(out.join("intermed-overlay-manifest.json")).unwrap();
    assert!(manifest.contains("intermed-overlay-preview-v1"));
}

#[test]
fn missing_target_is_a_negative_e2e() {
    let fixture = Fixture::new("missing-target");
    let missing = fixture.root.join("does-not-exist");

    let output = run(["vfs", "scan", missing.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("target does not exist"));
}

#[test]
fn mixin_map_matches_golden_output() {
    let fixture = Fixture::new("mixin-map");
    fixture.write_mixin_overlap_mods();

    let output = run(["mixin-map", fixture.mods_str()]);
    assert_success(&output);

    let actual = normalize_stdout(&output, &fixture.root);
    assert_eq!(actual, include_str!("golden/mixin_map_overlap.txt"));
}

#[test]
fn doctor_mixin_risk_flag_controls_layer_f() {
    let fixture = Fixture::new("mixin-gate");
    fixture.write_mixin_overlap_mods();

    let without = run(["doctor", fixture.mods_str(), "--json"]);
    assert_success(&without);
    let report: serde_json::Value = serde_json::from_slice(&without.stdout).unwrap();
    assert!(report["fact_stats"].get("mixin_overlap").is_none());

    let with = run(["doctor", fixture.mods_str(), "--mixin-risk", "--json"]);
    assert_eq!(with.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&with.stdout).unwrap();
    assert_eq!(report["fact_stats"]["mixin_overlap"], 1);
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["id"] == "mixin-overlap:net.minecraft.client.render.WorldRenderer"));
}

#[test]
fn doctor_datalog_logic_emits_core_rule_findings() {
    let fixture = Fixture::new("datalog-doctor");
    fixture.write_duplicate_id_mods();

    let output = run(["doctor", fixture.mods_str(), "--logic", "datalog", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["id"] == "duplicate-id:dupe"));
    assert!(report["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "datalog-rule-pack"));
}

#[test]
fn doctor_souffle_logic_is_real_optional_backend() {
    let fixture = Fixture::new("souffle-doctor");
    fixture.write_duplicate_id_mods();

    let output = run(["doctor", fixture.mods_str(), "--logic", "souffle", "--json"]);
    if souffle_available_in_path() {
        assert_eq!(output.status.code(), Some(2));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let findings = report["findings"].as_array().unwrap();
        assert!(findings.iter().any(|f| f["id"] == "duplicate-id:dupe"));
        assert!(report["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == "souffle-rule-pack"));
    } else {
        assert_eq!(output.status.code(), Some(2));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("--logic=souffle requires"));
    }
}

#[test]
fn rules_check_validates_default_rule_pack() {
    let output = run(["rules", "check", "rules"]);
    assert_success(&output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("InterMed Rules"));
    assert!(stdout.contains("Status: ok"));
}

#[test]
fn rules_check_rejects_invalid_rule_pack() {
    let fixture = Fixture::new("bad-rules");
    let rules = fixture.root.join("rules");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("bad.json"),
        r#"{"schema":"intermed-rule-pack-v1","id":"bad","rules":[]}"#,
    )
    .unwrap();

    let output = run(["rules", "check", rules.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Status: failed"));
    assert!(stdout.contains("rule pack has no rules"));
}

#[test]
#[ignore = "requires INTERMED_REAL_MODS_DIR pointing at a directory of real mod jars"]
fn real_mods_directory_runs_doctor_and_vfs() {
    let Ok(dir) = std::env::var("INTERMED_REAL_MODS_DIR") else {
        eprintln!("INTERMED_REAL_MODS_DIR not set; skipping real-mod e2e");
        return;
    };

    let vfs = run(["vfs", "scan", dir.as_str()]);
    assert_success(&vfs);
    assert!(String::from_utf8(vfs.stdout)
        .unwrap()
        .contains("InterMed VFS"));

    let mixin = run(["mixin-map", dir.as_str()]);
    assert_success(&mixin);
    assert!(String::from_utf8(mixin.stdout)
        .unwrap()
        .contains("InterMed Mixin Map"));

    let doctor = run(["doctor", dir.as_str(), "--json"]);
    assert!(
        doctor.status.success()
            || doctor.status.code() == Some(1)
            || doctor.status.code() == Some(2)
    );
    let report: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(report["schema"], "intermed-doctor-report-v1");
}

struct Fixture {
    root: PathBuf,
    mods: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "intermed-cli-{label}-{}-{nanos}",
            std::process::id()
        ));
        let mods = root.join("mods");
        std::fs::create_dir_all(&mods).unwrap();
        Self { root, mods }
    }

    fn mods_str(&self) -> &str {
        self.mods.to_str().unwrap()
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

    fn write_mixin_overlap_mods(&self) {
        write_mixin_jar(
            &self.mods.join("alpha.jar"),
            "alpha",
            "alpha.mixins.json",
            "alpha.mixin",
            &[(
                "RenderMixin",
                b"Lorg/spongepowered/asm/mixin/injection/Inject;\0Lnet/minecraft/client/render/WorldRenderer;\0",
            )],
        );
        write_mixin_jar(
            &self.mods.join("beta.jar"),
            "beta",
            "beta.mixins.json",
            "beta.mixin",
            &[(
                "RenderMixin",
                b"Lorg/spongepowered/asm/mixin/Overwrite;\0Lnet/minecraft/client/render/WorldRenderer;\0",
            )],
        );
    }

    fn write_duplicate_id_mods(&self) {
        write_fabric_jar(&self.mods.join("alpha.jar"), "dupe", &[]);
        write_fabric_jar(&self.mods.join("beta.jar"), "dupe", &[]);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).ok();
    }
}

fn run<const N: usize>(args: [&str; N]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_intermed"))
        .args(args)
        .output()
        .unwrap()
}

fn souffle_available_in_path() -> bool {
    Command::new("souffle")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn normalize_stdout(output: &Output, root: &Path) -> String {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .replace(root.to_str().unwrap(), "<TMP>")
}

fn normalize_fact_ids(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == 'f' && chars.peek().is_some_and(|c| c.is_ascii_digit()) {
            out.push_str("f#");
            while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                chars.next();
            }
        } else {
            out.push(ch);
        }
    }
    out
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
