//! End-to-end: `discover` → `run` → `report` over real temp files.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_lab::{
    CompatibilityMatrix, FailureCategory, FileCandidateProvider, SmokeStatus, discover_lock,
    write_report,
};

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "intermed-lab-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn discover_run_report_round_trip() {
    let root = temp_dir("flow");

    // 1. discover: candidate pool → lock.
    let candidates = root.join("candidates.json");
    fs::write(
        &candidates,
        r#"{
          "schema": "intermed-corpus-candidates-v1",
          "environment": { "loader": "fabric", "mc_version": "1.20.1", "side": "server" },
          "candidates": [
            { "project_id": "sodium", "version_id": "0.5.3", "file_name": "sodium.jar", "downloads": 100 },
            { "project_id": "lithium", "version_id": "0.11", "file_name": "lithium.jar", "downloads": 50 }
          ]
        }"#,
    )
    .unwrap();
    let lock_path = root.join("corpus.lock");
    let lock = discover_lock(&FileCandidateProvider { path: &candidates }, &lock_path).unwrap();
    assert_eq!(lock.mods.len(), 2);
    assert!(lock_path.is_file());
    assert!(lock.verify_digest());

    // 2. run: captured smoke outputs → classified run.
    let logs = root.join("captured");
    fs::create_dir_all(&logs).unwrap();
    fs::write(
        logs.join("fabric-1.20.1-server.json"),
        r#"{"schema":"intermed-smoke-output-v1","environment":"fabric-1.20.1-server","exited_ok":true,"log":"Done (3.1s)!"}"#,
    )
    .unwrap();
    fs::write(
        logs.join("fabric-1.20.1-client.json"),
        r#"{"schema":"intermed-smoke-output-v1","environment":"fabric-1.20.1-client","exited_ok":false,"log":"net.fabricmc InvalidMixinException: boom"}"#,
    )
    .unwrap();

    let run_dir = root.join("runs/latest");
    let run = intermed_lab::run_lab(&lock_path, &logs, &run_dir).unwrap();
    assert_eq!(run.corpus_digest, lock.digest);
    assert_eq!(run.results.len(), 2);
    // Deterministic env-sorted order: client before server.
    assert_eq!(run.results[0].environment, "fabric-1.20.1-client");
    assert_eq!(run.results[0].status, SmokeStatus::Fail);
    assert_eq!(run.results[1].status, SmokeStatus::Pass);
    assert!(run_dir.join("lab-run.json").is_file());

    // 3. report: run → matrix + html.
    let site = root.join("site");
    let matrix = write_report(&run_dir.join("lab-run.json"), &site).unwrap();
    assert_eq!(matrix.total, 2);
    assert_eq!(matrix.passed, 1);
    assert_eq!(matrix.failed, 1);
    assert_eq!(matrix.by_category.get("mixin-apply-error"), Some(&1));
    assert!(site.join("matrix.json").is_file());
    assert!(site.join("index.html").is_file());

    // matrix.json is valid and reloadable.
    let text = fs::read_to_string(site.join("matrix.json")).unwrap();
    let reloaded: CompatibilityMatrix = serde_json::from_str(&text).unwrap();
    assert_eq!(reloaded.corpus_digest, lock.digest);

    fs::remove_dir_all(root).ok();
}

/// A realistic, non-stub scenario: several environments fail for genuinely
/// different reasons — including one log with two *independent* failures and
/// non-ASCII text (a localized German mod name + emoji) that the byte-budget
/// excerpt must not panic on.
#[test]
fn realistic_multi_failure_run_classifies_and_aggregates() {
    let root = temp_dir("realistic");

    let candidates = root.join("candidates.json");
    fs::write(
        &candidates,
        r#"{
          "schema": "intermed-corpus-candidates-v1",
          "environment": { "loader": "fabric", "mc_version": "1.20.1", "side": "both" },
          "candidates": [
            { "project_id": "sodium", "version_id": "0.5.3", "file_name": "sodium.jar", "sha512": "abc", "downloads": 100 }
          ]
        }"#,
    )
    .unwrap();
    let lock_path = root.join("corpus.lock");
    discover_lock(&FileCandidateProvider { path: &candidates }, &lock_path).unwrap();

    let logs = root.join("captured");
    fs::create_dir_all(&logs).unwrap();

    let cases = [
        // Clean startup.
        (
            "fabric-1.20.1-clean",
            true,
            "[12:00:00] [Server thread/INFO]: Done (4.231s)! For help, type \"help\"".to_string(),
        ),
        // OOM crash.
        (
            "fabric-1.20.1-oom",
            false,
            "[Server thread/ERROR]: Encountered an unexpected exception\n\
             java.lang.OutOfMemoryError: Java heap space"
                .to_string(),
        ),
        // Two independent failures in one log + non-ASCII mod name and emoji.
        (
            "fabric-1.20.1-double",
            false,
            format!(
                "[ERROR] Mod „Höhlenausbau“ 🛑 org.spongepowered.asm.mixin.injection.throwables.InvalidMixinException: apply failed\n\
                 [ERROR] Mod sicherheit requires fabric-api which is missing {}",
                "ä".repeat(120)
            ),
        ),
        // Environment problem, not the mods.
        (
            "fabric-1.20.1-port",
            false,
            "[Server thread/WARN]: **** FAILED TO BIND TO PORT!\n\
             java.net.BindException: Address already in use"
                .to_string(),
        ),
    ];
    for (env, ok, log) in &cases {
        let value = serde_json::json!({
            "schema": "intermed-smoke-output-v1",
            "environment": env,
            "exited_ok": ok,
            "log": log,
        });
        fs::write(
            logs.join(format!("{env}.json")),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    let run_dir = root.join("runs/latest");
    let run = intermed_lab::run_lab(&lock_path, &logs, &run_dir).unwrap();
    assert_eq!(run.results.len(), 4);

    // The double-failure environment: dominant = mixin, secondary = missing-dep.
    let double = run
        .results
        .iter()
        .find(|r| r.environment == "fabric-1.20.1-double")
        .unwrap();
    assert_eq!(double.status, SmokeStatus::Fail);
    assert_eq!(double.failure, Some(FailureCategory::MixinApplyError));
    assert_eq!(
        double.additional_failures,
        vec![FailureCategory::MissingDependency]
    );
    assert!(!double.attributions.is_empty());
    assert!(
        double
            .attributions
            .iter()
            .any(|a| a.category == FailureCategory::MixinApplyError)
    );
    assert!(
        double
            .attributions
            .iter()
            .any(|a| a.category == FailureCategory::MissingDependency)
    );
    assert!(double.detail.contains("+1 other failure"));
    // Excerpt was produced without panicking on the multibyte boundary.
    assert!(double.log_excerpt.is_some());

    let report_dir = root.join("site");
    let matrix = write_report(&run_dir.join("lab-run.json"), &report_dir).unwrap();
    assert_eq!(matrix.total, 4);
    assert_eq!(matrix.passed, 1);
    assert_eq!(matrix.crashed, 1); // OOM
    assert_eq!(matrix.failed, 2); // double + port

    // Histogram counts every independent failure across all environments.
    assert_eq!(matrix.by_category.get("mixin-apply-error"), Some(&1));
    assert_eq!(matrix.by_category.get("missing-dependency"), Some(&1));
    assert_eq!(matrix.by_category.get("out-of-memory"), Some(&1));
    assert_eq!(matrix.by_category.get("port-in-use"), Some(&1));
    // Families roll the flat categories up.
    assert_eq!(matrix.by_family.get("mod-integration"), Some(&2));
    assert_eq!(matrix.by_family.get("resource-exhaustion"), Some(&1));
    assert_eq!(matrix.by_family.get("environment"), Some(&1));

    let html = fs::read_to_string(report_dir.join("index.html")).unwrap();
    assert!(html.contains("Failures by family"));
    assert!(html.contains("mod-integration: 2"));

    fs::remove_dir_all(root).ok();
}

#[test]
fn tampered_lock_is_rejected() {
    let root = temp_dir("tamper");
    let candidates = root.join("candidates.json");
    fs::write(
        &candidates,
        r#"{"schema":"intermed-corpus-candidates-v1","environment":{"loader":"fabric","mc_version":"1.20.1","side":"server"},"candidates":[{"project_id":"sodium","version_id":"1","file_name":"s.jar"}]}"#,
    )
    .unwrap();
    let lock_path = root.join("corpus.lock");
    discover_lock(&FileCandidateProvider { path: &candidates }, &lock_path).unwrap();

    // Hand-edit a pinned version without updating the digest.
    let text = fs::read_to_string(&lock_path).unwrap();
    let tampered = text.replace("\"version_id\": \"1\"", "\"version_id\": \"9\"");
    assert_ne!(text, tampered);
    fs::write(&lock_path, tampered).unwrap();

    let logs = root.join("captured");
    fs::create_dir_all(&logs).unwrap();
    assert!(intermed_lab::run_lab(&lock_path, &logs, &root.join("out")).is_err());

    fs::remove_dir_all(root).ok();
}
