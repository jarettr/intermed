//! Mod-scale benchmarks: time and RSS for synthetic mod directories.
//!
//! Run in CI with `cargo test -p intermed-cli --test mod_scale_bench -- --nocapture`.
//! Emits `intermed-bench-v1` JSON lines to stdout for trend tracking.

use intermed_deps::DependencyRule;
use intermed_doctor_core::{DiagnosticEngine, Target, TargetKind};
use intermed_log::{LogCollector, LogSignalRule};
use intermed_minecraft_scan::{EnvironmentCollector, MetadataCollector};
use intermed_rules::{DuplicateIdRule, LoaderMismatchRule, SideMismatchRule};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zip::write::SimpleFileOptions;

const BENCH_SCHEMA: &str = "intermed-bench-v1";

/// Generous ceilings for CI shared runners (seconds). Tune when hardware changes.
const MAX_SECS_50: u64 = 30;
const MAX_SECS_100: u64 = 60;
const MAX_SECS_200: u64 = 120;

#[test]
fn mod_scale_benchmark_50_100_200() {
    for count in [50usize, 100, 200] {
        let (elapsed_ms, rss_kb) = bench_mod_count(count);
        let max_secs = match count {
            50 => MAX_SECS_50,
            100 => MAX_SECS_100,
            _ => MAX_SECS_200,
        };
        println!(
            "{{\"schema\":\"{BENCH_SCHEMA}\",\"mods\":{count},\"elapsed_ms\":{elapsed_ms},\"rss_kb\":{rss_kb}}}"
        );
        assert!(
            elapsed_ms < max_secs * 1000,
            "{count} mods took {elapsed_ms}ms (limit {max_secs}s)"
        );
    }
}

fn bench_mod_count(count: usize) -> (u64, u64) {
    let root = temp_root(count);
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    for i in 0..count {
        write_mod_jar(&mods.join(format!("mod-{i:04}.jar")), &format!("mod{i}"));
    }

    let engine = DiagnosticEngine::builder()
        .collector(EnvironmentCollector)
        .collector(MetadataCollector)
        .collector(LogCollector)
        .collector(intermed_vfs::collector())
        .collector(intermed_security_audit::collector())
        .collector(intermed_sbom::collector())
        .rule(DependencyRule)
        .rule(LogSignalRule)
        .rule(intermed_security_audit::rule())
        .rule(intermed_sbom::rule())
        .rule(DuplicateIdRule)
        .rule(LoaderMismatchRule)
        .rule(SideMismatchRule)
        .rule(intermed_vfs::rule())
        .build();

    let target = Target {
        path: root.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods),
            game_root: None,
            layout: None,
            instance_type: None,
        spark_report: None,
    };

    let rss_before = rss_kb();
    let started = Instant::now();
    let report = engine.diagnose(&target);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let rss_after = rss_kb();
    let _ = report;

    std::fs::remove_dir_all(&root).ok();
    (
        elapsed_ms,
        rss_after.saturating_sub(rss_before).max(rss_after),
    )
}

fn write_mod_jar(path: &Path, mod_id: &str) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    let manifest = format!(
        r#"{{"schemaVersion":1,"id":"{mod_id}","version":"1.0.0","name":"Bench {mod_id}"}}"#
    );
    zip.start_file("fabric.mod.json", opts).unwrap();
    zip.write_all(manifest.as_bytes()).unwrap();
    zip.finish().unwrap();
}

fn temp_root(count: usize) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("intermed-bench-{count}-{nanos}"))
}

fn rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.trim().trim_end_matches(" kB").parse().unwrap_or(0);
        }
    }
    0
}
