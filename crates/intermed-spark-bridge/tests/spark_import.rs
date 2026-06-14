use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_doctor_core::{Target, TargetKind};
use intermed_spark_bridge::{import_file, import_target, SPARK_REPORT_SCHEMA};

#[test]
fn import_file_validates_schema() {
    let root = temp_dir("schema");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("bad.json");
    std::fs::write(&path, r#"{"schema":"other"}"#).unwrap();
    assert!(import_file(&path).is_err());
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn import_target_reads_explicit_spark_report() {
    let root = temp_dir("explicit");
    std::fs::create_dir_all(&root).unwrap();
    let report = root.join("profile.json");
    std::fs::write(
        &report,
        format!(
            r#"{{
                "schema": "{SPARK_REPORT_SCHEMA}",
                "hot_methods": [{{"class": "net.minecraft.server.MinecraftServer", "method": "tick", "percent": 33.0}}]
            }}"#
        ),
    )
    .unwrap();

    let target = Target {
        path: root.clone(),
        kind: TargetKind::Server,
        mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
        spark_report: Some(report),
    };
    let import = import_target(&target).unwrap();
    assert_eq!(import.reports.len(), 1);
    assert_eq!(import.reports[0].hot_methods.len(), 1);

    std::fs::remove_dir_all(root).ok();
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "intermed-spark-test-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
