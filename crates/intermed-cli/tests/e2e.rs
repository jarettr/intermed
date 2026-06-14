use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_mixin_intel::fixtures;
use intermed_security_audit::fixtures as security_fixtures;
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
        "resource-conflict:safe-crdt-merge:data/minecraft/tags/items/test.json",
        "--no-color",
    ]);
    assert_success(&output);

    let actual = normalize_fact_ids(&normalize_stdout(&output, &fixture.root));
    assert_eq!(actual, include_str!("golden/doctor_explain_resource.txt"));
}

#[test]
fn dumped_facts_conform_to_typed_schema() {
    // End-to-end drift guard: run the real collectors and assert every emitted
    // fact uses the typed representation the schema requires (e.g. counts as Int,
    // not Str) — the class of bug that silently NULLs DuckDB aggregation.
    let fixture = Fixture::new("schema-facts");
    fixture.write_safe_merge_mods();
    let facts_path = fixture.root.join("facts.json");
    let output = run([
        "doctor",
        fixture.mods_str(),
        "--dump-facts",
        facts_path.to_str().unwrap(),
        "--json",
    ]);
    assert_success(&output);

    let facts: Vec<intermed_doctor_core::facts::Fact> =
        serde_json::from_str(&std::fs::read_to_string(&facts_path).unwrap()).unwrap();
    let violations: Vec<String> = facts
        .iter()
        .flat_map(intermed_doctor_core::facts::schema::schema_violations)
        .collect();
    assert!(violations.is_empty(), "schema violations: {violations:?}");
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
    assert!(kinds.contains(&"checksum"));
    assert!(kinds.contains(&"sbom"));
}

#[test]
fn doctor_dump_facts_contains_security_predicates() {
    let fixture = Fixture::new("dump-facts-security");
    fixture.write_process_spawn_mod();
    let facts = fixture.root.join("security-facts.json");

    let output = run([
        "doctor",
        fixture.mods_str(),
        "--dump-facts",
        facts.to_str().unwrap(),
        "--json",
    ]);
    assert_success_or_warnings(&output);

    let facts: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(facts).unwrap()).unwrap();
    let kinds: Vec<&str> = facts
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f.get("kind").and_then(|k| k.as_str()))
        .collect();
    assert!(kinds.contains(&"uses_process_spawn"));
}

#[test]
fn doctor_explain_security_finding_matches_golden_output() {
    let fixture = Fixture::new("doctor-explain-security");
    fixture.write_process_spawn_mod();

    let output = run([
        "doctor",
        fixture.mods_str(),
        "--explain",
        "security-api-risk:risky",
        "--no-color",
    ]);
    assert_success_or_warnings(&output);

    let actual = normalize_fact_ids(&String::from_utf8(output.stdout).unwrap());
    assert_eq!(actual, include_str!("golden/doctor_explain_security.txt"));
}

#[test]
fn doctor_single_note_security_signal_does_not_emit_finding() {
    let fixture = Fixture::new("security-note-threshold");
    fixture.write_socket_only_mod();

    let output = run(["doctor", fixture.mods_str(), "--json"]);
    assert_success(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(!findings.iter().any(|f| f["rule_id"] == "security-api-risk"));
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
fn mixin_map_graph_dot_export_writes_file() {
    let fixture = Fixture::new("mixin-graph-dot");
    fixture.write_mixin_overlap_mods();
    let out = fixture.root.join("mixin.dot");

    let output = run([
        "mixin-map",
        fixture.mods_str(),
        "--graph-format",
        "dot",
        "--graph-out",
        out.to_str().unwrap(),
    ]);
    assert_success(&output);
    let dot = std::fs::read_to_string(&out).unwrap();
    assert!(dot.contains("digraph mixin_interactions"));
    assert!(dot.contains("RenderMixin") || dot.contains("Mixin"));
}

#[test]
#[ignore = "run manually to refresh golden/mixin_map_overlap.txt"]
fn write_mixin_golden_output() {
    let fixture = Fixture::new("golden-write");
    fixture.write_mixin_overlap_mods();
    let output = run(["mixin-map", fixture.mods_str()]);
    assert_success(&output);
    let actual = normalize_stdout(&output, &fixture.root);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/mixin_map_overlap.txt");
    std::fs::write(&path, actual).unwrap();
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
    assert_eq!(with.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&with.stdout).unwrap();
    assert_eq!(report["fact_stats"]["mixin_overlap"], 1);
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["id"] == "mixin-risk:net.minecraft.client.render.WorldRenderer"));
    assert!(
        report["fact_stats"]["mixin_recommendation"].as_u64().unwrap_or(0) >= 1,
        "hot-path overwrite must emit mixin_recommendation facts"
    );
    let findings = report["findings"].as_array().unwrap();
    let summary_count = findings
        .iter()
        .filter(|f| {
            f["machine_tags"]
                .as_array()
                .map(|tags| tags.iter().any(|t| t == "mixin-effect-summary"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        summary_count, 1,
        "inject-only effect summary; overwrite uses mixin-overwrite-effect"
    );
    assert!(
        findings.iter().any(|f| f["id"].as_str().unwrap_or("").starts_with("mixin-overwrite-effect:")),
        "enhanced overwrite findings must attach recommendations via site_key"
    );
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
fn doctor_profile_writes_valid_json() {
    let fixture = Fixture::new("profile-e2e");
    fixture.write_safe_merge_mods();
    let profile = fixture.root.join("profile.json");

    let output = run([
        "doctor",
        fixture.mods_str(),
        "--profile",
        profile.to_str().unwrap(),
    ]);
    assert_success(&output);

    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(profile).unwrap()).unwrap();
    assert_eq!(json["schema"], "intermed-doctor-profile-v1");
    assert!(!json["collectors"].as_array().unwrap().is_empty());
}

#[test]
fn doctor_jobs_flag_caps_threads_and_runs() {
    // `--jobs 1` forces single-threaded scanning; the result must be identical
    // to the default parallel run (determinism is independent of worker count).
    let fixture = Fixture::new("jobs-flag");
    fixture.write_safe_merge_mods();

    let single = run(["doctor", fixture.mods_str(), "--json", "--jobs", "1"]);
    assert_success(&single);
    let parallel = run(["doctor", fixture.mods_str(), "--json"]);
    assert_success(&parallel);

    let a: serde_json::Value = serde_json::from_slice(&single.stdout).unwrap();
    let b: serde_json::Value = serde_json::from_slice(&parallel.stdout).unwrap();
    assert_eq!(a["findings"], b["findings"]);
}

#[test]
fn lab_eval_scores_doctor_predictions_against_ground_truth() {
    // The precision loop end-to-end: a real doctor report (predicting a mixin
    // conflict) scored against lab ground truth that confirms the failure.
    let fixture = Fixture::new("lab-eval");
    fixture.write_mixin_overlap_mods();

    // 1. Real doctor report (mixin layer needs --mixin-risk).
    let report = run(["doctor", fixture.mods_str(), "--json", "--mixin-risk"]);
    assert_success_or_warnings(&report);
    let report_path = fixture.root.join("report.json");
    std::fs::write(&report_path, &report.stdout).unwrap();

    // 2. Lab ground truth: mixin error attributed to WorldRenderer (same target as doctor).
    let run_path = fixture.root.join("lab-run.json");
    std::fs::write(
        &run_path,
        r#"{"schema":"intermed-lab-run-v1","corpus_digest":"x",
            "environment":{"loader":"fabric","mc_version":"1.20.1","side":"server"},
            "results":[{"environment":"fabric-server","status":"fail",
                        "failure":"mixin-apply-error","detail":"Mixin failed to apply",
                        "attributions":[{"category":"mixin-apply-error",
                            "subject":"net.minecraft.client.render.WorldRenderer"}]}]}"#,
    )
    .unwrap();

    // 3. Score predictions against ground truth.
    let out = fixture.root.join("accuracy.json");
    let eval = run([
        "lab",
        "eval",
        "--report",
        report_path.to_str().unwrap(),
        "--run",
        run_path.to_str().unwrap(),
        "--min-severity",
        "warn",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_success(&eval);

    let acc: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(acc["schema"], "intermed-rule-accuracy-v3");
    let mixin = acc["by_category"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["category"] == "mixin-apply-error")
        .expect("mixin category present");
    // Category co-occurrence: one tp per mod-set.
    assert_eq!(mixin["true_positive"], 1);
    assert_eq!(mixin["false_positive"], 0);
    assert_eq!(mixin["precision"], 1.0);

    // Finding-level: attributed join; at least one tp, rest may be fp if multiple findings.
    let fl = &acc["finding_level"];
    assert_eq!(fl["attributed"], true);
    assert!(fl["true_positive"].as_u64().unwrap() >= 1);
    assert!(fl["predictions"].as_u64().unwrap() >= 1);
}

#[test]
fn doctor_json_omits_profile_when_no_cache() {
    let fixture = Fixture::new("no-cache-json");
    fixture.write_safe_merge_mods();

    let output = run(["doctor", fixture.mods_str(), "--json", "--no-cache"]);
    assert_success(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.get("profile").is_none());
}

#[test]
fn doctor_profile_file_written_with_no_cache() {
    let fixture = Fixture::new("profile-no-cache");
    fixture.write_safe_merge_mods();
    let profile = fixture.root.join("profile.json");

    let output = run([
        "doctor",
        fixture.mods_str(),
        "--no-cache",
        "--profile",
        profile.to_str().unwrap(),
    ]);
    assert_success(&output);
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(profile).unwrap()).unwrap();
    assert_eq!(json["schema"], "intermed-doctor-profile-v1");
}

#[test]
fn doctor_phase6_security_finding_for_process_spawn() {
    let fixture = Fixture::new("security-e2e");
    fixture.write_process_spawn_mod();

    let output = run(["doctor", fixture.mods_str(), "--json"]);
    assert_success_or_warnings(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| {
        f["rule_id"] == "security-api-risk"
            && f["id"].as_str() == Some("security-api-risk:risky")
            && f["severity"] == "warn"
    }));
}

#[test]
fn doctor_phase7_performance_imports_spark_report() {
    let fixture = Fixture::new("spark-e2e");
    fixture.write_safe_merge_mods();
    fixture.write_spark_report();

    let output = run([
        "doctor",
        fixture.mods_str(),
        "--performance",
        "--spark-report",
        fixture.spark_report_str(),
        "--json",
    ]);
    assert_success_or_warnings(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let stats = &report["fact_stats"];
    assert!(
        stats
            .get("tick_spike")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            >= 1
    );
    assert!(
        stats
            .get("hot_method")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            >= 1
    );
    let collectors = report["collectors"].as_array().unwrap();
    assert!(collectors
        .iter()
        .any(|c| c["id"] == "spark-importer" && c["status"] == "active"));
}

#[test]
fn spark_map_reads_report() {
    let fixture = Fixture::new("spark-map");
    fixture.write_spark_report();

    let output = run([
        "spark-map",
        fixture.root_str(),
        "--spark-report",
        fixture.spark_report_str(),
    ]);
    assert_success(&output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("InterMed Spark Map"));
    assert!(stdout.contains("hot methods: 1"));
}

#[test]
fn lab_discover_run_report_pipeline() {
    let fixture = Fixture::new("lab");
    let candidates = fixture.root.join("candidates.json");
    std::fs::write(
        &candidates,
        r#"{"schema":"intermed-corpus-candidates-v1","environment":{"loader":"fabric","mc_version":"1.20.1","side":"server"},"candidates":[{"project_id":"sodium","version_id":"1","file_name":"s.jar"}]}"#,
    )
    .unwrap();
    let lock = fixture.root.join("corpus.lock");

    let discover = run([
        "lab",
        "discover",
        candidates.to_str().unwrap(),
        "--out",
        lock.to_str().unwrap(),
    ]);
    assert_success(&discover);
    assert!(lock.is_file());

    let logs = fixture.root.join("captured");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(
        logs.join("server.json"),
        r#"{"schema":"intermed-smoke-output-v1","environment":"server","exited_ok":false,"log":"java.lang.OutOfMemoryError"}"#,
    )
    .unwrap();
    let runs = fixture.root.join("runs");

    let run_out = run([
        "lab",
        "run",
        lock.to_str().unwrap(),
        "--logs",
        logs.to_str().unwrap(),
        "--out",
        runs.to_str().unwrap(),
    ]);
    assert_success(&run_out);
    assert!(runs.join("lab-run.json").is_file());

    let site = fixture.root.join("site");
    let report = run([
        "lab",
        "report",
        runs.to_str().unwrap(),
        "--out",
        site.to_str().unwrap(),
    ]);
    assert_success(&report);
    let stdout = String::from_utf8(report.stdout).unwrap();
    assert!(stdout.contains("compatibility matrix"));
    assert!(site.join("index.html").is_file());
    let html = std::fs::read_to_string(site.join("index.html")).unwrap();
    assert!(html.contains("out-of-memory"));
}

#[test]
fn doctor_cache_records_hits_on_second_run() {
    let fixture = Fixture::new("cache-e2e");
    fixture.write_safe_merge_mods();
    let cache_dir = fixture.root.join("cache");

    let first = run([
        "doctor",
        fixture.mods_str(),
        "--json",
        "--cache-dir",
        cache_dir.to_str().unwrap(),
    ]);
    assert_success(&first);
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert!(report["profile"]["cache"]["misses"].as_u64().unwrap() >= 1);

    let second = run([
        "doctor",
        fixture.mods_str(),
        "--json",
        "--cache-dir",
        cache_dir.to_str().unwrap(),
    ]);
    assert_success(&second);
    let report2: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert!(report2["profile"]["cache"]["hits"].as_u64().unwrap() >= 1);
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
fn dump_config_prints_valid_toml_schema() {
    let output = run(["--dump-config"]);
    assert_success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(r#"schema = "intermed-config-v1""#));
    assert!(text.contains("[performance]"));
    assert!(text.contains("[security]"));
}

#[test]
fn doctor_html_report_writes_self_contained_page() {
    let fixture = Fixture::new("html-report");
    fixture.write_safe_merge_mods();
    let html_path = fixture.root.join("report.html");

    let output = run([
        "doctor",
        fixture.mods_str(),
        "--html",
        html_path.to_str().unwrap(),
    ]);
    assert_success(&output);

    let html = std::fs::read_to_string(&html_path).unwrap();
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("InterMed Doctor Report"));
    assert!(html.contains("resource-conflict"));
}

#[test]
fn doctor_config_file_overrides_security_threshold() {
    let fixture = Fixture::new("config-override");
    fixture.write_socket_only_mod();
    let config = fixture.root.join("intermed.toml");
    std::fs::write(
        &config,
        r#"
schema = "intermed-config-v1"
[security]
min_note_signals = 1
"#,
    )
    .unwrap();

    let output = run([
        "doctor",
        fixture.mods_str(),
        "--config",
        config.to_str().unwrap(),
        "--json",
    ]);
    assert_success_or_warnings(&output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "security-api-risk"));
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
    spark_report: PathBuf,
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
        let spark_report = root.join("spark/profile.json");
        Self {
            root,
            mods,
            spark_report,
        }
    }

    fn mods_str(&self) -> &str {
        self.mods.to_str().unwrap()
    }

    fn root_str(&self) -> &str {
        self.root.to_str().unwrap()
    }

    fn spark_report_str(&self) -> &str {
        self.spark_report.to_str().unwrap()
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
            &self.mods.join("alpha.jar"),
            "alpha",
            "alpha.mixins.json",
            "alpha.mixin",
            &[("RenderMixin", alpha_class.as_slice())],
        );
        write_mixin_jar(
            &self.mods.join("beta.jar"),
            "beta",
            "beta.mixins.json",
            "beta.mixin",
            &[("RenderMixin", beta_class.as_slice())],
        );
    }

    fn write_duplicate_id_mods(&self) {
        write_fabric_jar(&self.mods.join("alpha.jar"), "dupe", &[]);
        write_fabric_jar(&self.mods.join("beta.jar"), "dupe", &[]);
    }

    fn write_process_spawn_mod(&self) {
        let class = security_fixtures::class_with_method_ref(
            "java/lang/Runtime",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
        );
        write_security_jar(
            &self.mods.join("risky.jar"),
            "risky",
            &[("Risky", class.as_slice())],
        );
    }

    fn write_socket_only_mod(&self) {
        let class = security_fixtures::class_with_method_ref("java/net/Socket", "connect", "()V");
        write_security_jar(
            &self.mods.join("netty.jar"),
            "netty",
            &[("Netty", class.as_slice())],
        );
    }

    fn write_spark_report(&self) {
        if let Some(parent) = self.spark_report.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(
            &self.spark_report,
            r#"{
                "schema": "intermed-spark-report-v1",
                "tick_spikes_ms": [120],
                "hot_methods": [
                    {"class": "net.minecraft.server.MinecraftServer", "method": "tick", "percent": 42.0}
                ]
            }"#,
        )
        .unwrap();
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

fn assert_success_or_warnings(output: &Output) {
    assert!(
        output.status.success() || output.status.code() == Some(1),
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

fn write_security_jar(path: &Path, id: &str, classes: &[(&str, &[u8])]) {
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
