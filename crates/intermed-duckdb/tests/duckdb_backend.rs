//! Integration tests for the embedded DuckDB backend (requires `duckdb` feature).

use intermed_doctor_core::facts::{FactStore, kind};
use intermed_doctor_core::report::{DoctorReport, Summary, TargetView};
use intermed_doctor_core::target::{Environment, Target, TargetKind};
use intermed_doctor_core::{Rule, RuleCtx};
use intermed_duckdb::{DuckStore, DuckdbRulePack, schema::compute_run_id};
use intermed_evidence::{Category, Severity};
use intermed_facts::SourceRef;
use intermed_rules::{DuplicateIdRule, LoaderMismatchRule, SideMismatchRule, SouffleRulePack};
use intermed_vfs::ResourceConflictRule;

fn duplicate_mod_store() -> FactStore {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("dupe")
        .attr("file", "alpha.jar")
        .source(SourceRef::file("alpha.jar"))
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("dupe")
        .attr("file", "beta.jar")
        .source(SourceRef::file("beta.jar"))
        .emit();
    store
}

fn test_target() -> &'static Target {
    use std::sync::LazyLock;
    static TARGET: LazyLock<Target> = LazyLock::new(|| Target {
        path: ".".into(),
        kind: TargetKind::ModsDir,
        mods_dir: None,
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    });
    &TARGET
}

fn ctx_from_store(store: &FactStore) -> RuleCtx<'_> {
    RuleCtx::for_test(store, test_target())
}

#[test]
fn persist_run_survives_duplicate_fact_ids_in_batch() {
    let mut store = FactStore::new();
    let id = store
        .fact("mixin", kind::MIXIN_EFFECT)
        .subject("sodium")
        .attr("target", "net.minecraft.server.MinecraftServer")
        .attr("method", "tick")
        .attr("hot_path", true)
        .emit();
    let mut facts = store.all().to_vec();
    // Simulate a buggy collector re-emitting the same fact id in one batch.
    facts.push(facts[0].clone());

    let report = DoctorReport {
        schema: "intermed-doctor-report-v1".into(),
        tool_version: "0.1.0".into(),
        generated_at: chrono::Utc::now(),
        target: TargetView {
            path: "/mods".into(),
            kind: TargetKind::ModsDir,
        },
        environment: Environment::default(),
        summary: Summary::default(),
        findings: Vec::new(),
        fix_plan: Vec::new(),
        fact_stats: store.stats(),
        collectors: Vec::new(),
        rules: Vec::new(),
        deferred_layers: Vec::new(),
        profile: None,
    };
    let run_id = compute_run_id(
        &report.generated_at,
        &report.target.path,
        &report.tool_version,
    );

    let path = std::env::temp_dir().join(format!(
        "intermed-duckdb-dedup-{}-{}.duckdb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let duck = DuckStore::open(&path).unwrap();
    duck.persist_run(&report, &facts).expect("first persist");
    duck.persist_run(&report, &facts)
        .expect("idempotent re-persist");

    let count = duck
        .query(&format!(
            "SELECT COUNT(*) FROM facts WHERE run_id = '{run_id}' AND fact_id = {}",
            id.0
        ))
        .unwrap();
    assert_eq!(count.rows[0][0], "1");

    std::fs::remove_file(path).ok();
}

#[test]
fn persist_many_mixin_effects_is_idempotent() {
    let mut store = FactStore::new();
    for i in 0..32 {
        store
            .fact("mixin", kind::MIXIN_EFFECT)
            .subject(format!("mod-{i}"))
            .attr("target", format!("net.minecraft.Target{i}"))
            .attr("method", "tick")
            .attr("hot_path", i % 3 == 0)
            .emit();
    }
    let facts = store.all().to_vec();
    let report = DoctorReport {
        schema: "intermed-doctor-report-v1".into(),
        tool_version: "0.1.0".into(),
        generated_at: chrono::Utc::now(),
        target: TargetView {
            path: "/mods".into(),
            kind: TargetKind::ModsDir,
        },
        environment: Environment::default(),
        summary: Summary::default(),
        findings: Vec::new(),
        fix_plan: Vec::new(),
        fact_stats: store.stats(),
        collectors: Vec::new(),
        rules: Vec::new(),
        deferred_layers: Vec::new(),
        profile: None,
    };
    let run_id = compute_run_id(
        &report.generated_at,
        &report.target.path,
        &report.tool_version,
    );

    let path = std::env::temp_dir().join(format!(
        "intermed-duckdb-mixin-{}-{}.duckdb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let duck = DuckStore::open(&path).unwrap();
    for _ in 0..3 {
        duck.persist_run(&report, &facts).expect("re-persist");
    }
    let count = duck
        .query(&format!(
            "SELECT COUNT(*) FROM facts WHERE run_id = '{run_id}' AND kind = 'mixin_effect'"
        ))
        .unwrap();
    assert_eq!(count.rows[0][0], "32");

    std::fs::remove_file(path).ok();
}

#[test]
fn persist_run_is_idempotent() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("alpha")
        .attr("file", "a.jar")
        .emit();
    let facts = store.all().to_vec();
    let report = DoctorReport {
        schema: "intermed-doctor-report-v1".into(),
        tool_version: "0.1.0".into(),
        generated_at: chrono::Utc::now(),
        target: TargetView {
            path: "/mods".into(),
            kind: TargetKind::ModsDir,
        },
        environment: Environment::default(),
        summary: Summary::default(),
        findings: Vec::new(),
        fix_plan: Vec::new(),
        fact_stats: store.stats(),
        collectors: Vec::new(),
        rules: Vec::new(),
        deferred_layers: Vec::new(),
        profile: None,
    };
    let run_id = compute_run_id(
        &report.generated_at,
        &report.target.path,
        &report.tool_version,
    );

    let path = std::env::temp_dir().join(format!(
        "intermed-duckdb-idem-{}-{}.duckdb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let duck = DuckStore::open(&path).unwrap();
    duck.persist_run(&report, &facts).unwrap();
    duck.persist_run(&report, &facts).unwrap();

    let runs = duck
        .query(&format!(
            "SELECT COUNT(*) FROM runs WHERE run_id = '{run_id}'"
        ))
        .unwrap();
    assert_eq!(runs.rows[0][0], "1");
    let fact_count = duck
        .query(&format!(
            "SELECT COUNT(*) FROM facts WHERE run_id = '{run_id}'"
        ))
        .unwrap();
    assert_eq!(fact_count.rows[0][0], "1");

    std::fs::remove_file(path).ok();
}

#[test]
fn readonly_open_rejects_writes_but_allows_select() {
    let mut store = FactStore::new();
    store
        .fact("meta", kind::MOD)
        .subject("alpha")
        .attr("file", "a.jar")
        .emit();
    let facts = store.all().to_vec();
    let report = DoctorReport {
        schema: "intermed-doctor-report-v1".into(),
        tool_version: "0.1.0".into(),
        generated_at: chrono::Utc::now(),
        target: TargetView {
            path: "/mods".into(),
            kind: TargetKind::ModsDir,
        },
        environment: Environment::default(),
        summary: Summary::default(),
        findings: Vec::new(),
        fix_plan: Vec::new(),
        fact_stats: store.stats(),
        collectors: Vec::new(),
        rules: Vec::new(),
        deferred_layers: Vec::new(),
        profile: None,
    };
    let path = std::env::temp_dir().join(format!(
        "intermed-duckdb-ro-{}-{}.duckdb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    DuckStore::open(&path)
        .unwrap()
        .persist_run(&report, &facts)
        .unwrap();

    let ro = DuckStore::open_readonly(&path).unwrap();
    // SELECT works.
    assert_eq!(
        ro.query("SELECT COUNT(*) FROM facts").unwrap().rows[0][0],
        "1"
    );
    // Every mutating statement is rejected by the engine.
    assert!(ro.query("DROP TABLE facts").is_err());
    assert!(ro.query("DELETE FROM runs").is_err());
    assert!(ro.query("INSERT INTO runs (run_id) VALUES ('x')").is_err());
    // Data survived.
    assert_eq!(
        ro.query("SELECT COUNT(*) FROM facts").unwrap().rows[0][0],
        "1"
    );

    std::fs::remove_file(path).ok();
}

#[test]
fn duplicate_id_matches_imperative_rule() {
    let store = duplicate_mod_store();
    let ctx = ctx_from_store(&store);
    let imperative = DuplicateIdRule.evaluate(&ctx);
    let duckdb = DuckdbRulePack::default().evaluate(&ctx);

    assert_eq!(imperative.len(), 1);
    assert_eq!(duckdb.len(), 1);
    assert_eq!(imperative[0].id, "duplicate-id:dupe");
    assert_eq!(duckdb[0].id, "duplicate-id:dupe");
    assert_eq!(imperative[0].severity, Severity::Error);
    assert_eq!(duckdb[0].severity, Severity::Error);
    assert_eq!(imperative[0].category, Category::Metadata);
    assert_eq!(duckdb[0].category, Category::Metadata);
}

#[test]
fn duplicate_id_matches_souffle_when_available() {
    if !intermed_rules::souffle_available() {
        return;
    }
    let store = duplicate_mod_store();
    let ctx = ctx_from_store(&store);
    let souffle = SouffleRulePack::default().evaluate(&ctx);
    let duckdb = DuckdbRulePack::default().evaluate(&ctx);
    assert_eq!(souffle.len(), 1);
    assert_eq!(duckdb.len(), 1);
    assert_eq!(souffle[0].id, duckdb[0].id);
}

#[test]
fn mixin_overlap_sql_backend_surfaces_finding() {
    let mut store = FactStore::new();
    let id = store
        .fact("mixin", kind::MIXIN_OVERLAP)
        .subject("net.minecraft.client.render.WorldRenderer")
        .attr("mods", "alpha, beta")
        .attr("operations", "Inject, Overwrite")
        .attr("hot_path", false)
        .emit();
    let ctx = ctx_from_store(&store);
    let findings = DuckdbRulePack::default().evaluate(&ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].id,
        "mixin-overlap:net.minecraft.client.render.WorldRenderer"
    );
    assert_eq!(findings[0].severity, Severity::Warn);
    assert!(findings[0].evidence.iter().any(|e| e.fact == id));
}

#[test]
fn loader_mismatch_matches_imperative_rule() {
    let mut store = FactStore::new();
    store
        .fact("env", kind::ENVIRONMENT)
        .subject("instance")
        .attr("loader", "fabric")
        .emit();
    store
        .fact("meta", kind::MOD)
        .subject("alpha")
        .attr("loader", "forge")
        .attr("file", "alpha.jar")
        .emit();
    let ctx = ctx_from_store(&store);
    let imperative = LoaderMismatchRule.evaluate(&ctx);
    let duckdb = DuckdbRulePack::default().evaluate(&ctx);
    assert_eq!(imperative.len(), 1);
    assert_eq!(duckdb.len(), 1);
    assert_eq!(imperative[0].id, duckdb[0].id);
    assert_eq!(duckdb[0].id, "loader-mismatch:alpha");
}

#[test]
fn side_mismatch_matches_imperative_rule() {
    let mut store = FactStore::new();
    store
        .fact("env", kind::ENVIRONMENT)
        .subject("instance")
        .attr("side", "server")
        .emit();
    store
        .fact("meta", kind::MOD_SIDE)
        .subject("clientmod")
        .attr("side", "client")
        .emit();
    let ctx = ctx_from_store(&store);
    let imperative = SideMismatchRule.evaluate(&ctx);
    let duckdb = DuckdbRulePack::default().evaluate(&ctx);
    assert_eq!(imperative.len(), 1);
    assert_eq!(duckdb.len(), 1);
    assert_eq!(imperative[0].id, duckdb[0].id);
    assert_eq!(duckdb[0].id, "side-mismatch:clientmod");
}

#[test]
fn resource_conflict_matches_vfs_rule() {
    let mut store = FactStore::new();
    let collision = store
        .fact("vfs", kind::RESOURCE_COLLISION)
        .subject("data/minecraft/tags/items/test.json")
        .attr("class", "unsafe-replace")
        .attr("writers", "alpha,beta")
        .attr("reason", "order matters")
        .emit();
    store
        .fact("vfs", kind::RESOURCE_WRITER)
        .subject("alpha")
        .attr("path", "data/minecraft/tags/items/test.json")
        .emit();
    let ctx = ctx_from_store(&store);
    let vfs = ResourceConflictRule.evaluate(&ctx);
    let duckdb = DuckdbRulePack::default().evaluate(&ctx);
    assert_eq!(vfs.len(), 1);
    assert_eq!(duckdb.len(), 1);
    assert_eq!(vfs[0].id, duckdb[0].id);
    assert!(duckdb[0].evidence.iter().any(|e| e.fact == collision));
}

#[test]
fn security_signals_match_imperative_aggregation() {
    // The security path is the one place the DuckDB backend uses SQL aggregation
    // (over `val_int` counts) rather than the shared interpreter — exactly where
    // the numeric-attr-as-string bug lived. Assert the SQL backend produces the
    // same grouped finding as the imperative `security-audit` rule.
    let mut store = FactStore::new();
    for sig in [kind::USES_PROCESS_SPAWN, kind::USES_UNSAFE] {
        store
            .fact("security-scanner", sig)
            .subject("risky")
            .attr("archive", "risky.jar")
            .attr("provenance", "structural")
            .attr("evidence_strength", "high")
            .attr("dangerous_classes", 2_i64)
            .attr("classes_scanned", 5_i64)
            .attr("affected_classes", 1_i64)
            .emit();
    }
    let ctx = ctx_from_store(&store);
    let imperative = intermed_security_audit::rule().evaluate(&ctx);
    let duckdb: Vec<_> = DuckdbRulePack::default()
        .evaluate(&ctx)
        .into_iter()
        .filter(|f| f.id.starts_with("security-api-risk:"))
        .collect();

    assert!(
        !DuckdbRulePack::default()
            .evaluate(&ctx)
            .iter()
            .any(|f| f.id == "duckdb-backend-failed"),
        "duckdb security path must bind cleanly"
    );
    assert_eq!(imperative.len(), 1);
    assert_eq!(
        duckdb.len(),
        1,
        "duckdb security findings: {:?}",
        duckdb.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    assert_eq!(imperative[0].id, duckdb[0].id);
    assert_eq!(imperative[0].severity, duckdb[0].severity);
    assert_eq!(imperative[0].category, duckdb[0].category);
}

#[test]
fn core_sql_rule_catalog_is_stable() {
    // Tripwire: the DuckDB rule pack evaluates one read_* query per catalog
    // entry. Keep this in lockstep with `run_duckdb_rules` and `sql::CORE_RULES`.
    assert_eq!(intermed_duckdb::CORE_SQL_RULES.len(), 11);
    for expected in [
        "duplicate_id",
        "security_signals",
        "sbom_security_correlation",
    ] {
        assert!(
            intermed_duckdb::CORE_SQL_RULES.contains(&expected),
            "missing core sql rule: {expected}"
        );
    }
}

#[test]
fn sbom_correlation_flags_only_low_trust_capability() {
    let mut store = FactStore::new();
    // Low-provenance archive (trust 10 < 60) that also spawns processes: the
    // exact "unknown source + dangerous capability" pair the rule exists for.
    store
        .fact("sbom", kind::SBOM)
        .subject("shady.jar")
        .attr("trust_score", 10_i64)
        .emit();
    store
        .fact("security", kind::USES_PROCESS_SPAWN)
        .subject("shady.jar")
        .attr("archive", "shady.jar")
        .emit();
    // Well-identified archive (trust 95) with the same capability: must NOT flag.
    store
        .fact("sbom", kind::SBOM)
        .subject("trusted.jar")
        .attr("trust_score", 95_i64)
        .emit();
    store
        .fact("security", kind::USES_PROCESS_SPAWN)
        .subject("trusted.jar")
        .attr("archive", "trusted.jar")
        .emit();

    let ctx = ctx_from_store(&store);
    let findings = DuckdbRulePack::default().evaluate(&ctx);

    // The backend must bind/run every query cleanly, not bail with the fatal
    // failure finding (regression guard for the GROUP BY-on-aggregate bug).
    assert!(
        !findings.iter().any(|f| f.id == "duckdb-backend-failed"),
        "duckdb backend failed: {:?}",
        findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );

    let correlation: Vec<_> = findings
        .iter()
        .filter(|f| f.id == "low-trust-capability:shady.jar")
        .collect();
    assert_eq!(
        correlation.len(),
        1,
        "expected the low-trust archive to be flagged"
    );
    assert_eq!(correlation[0].severity, Severity::Warn);
    assert_eq!(correlation[0].category, Category::Security);
    assert!(
        !findings
            .iter()
            .any(|f| f.id == "low-trust-capability:trusted.jar"),
        "well-identified archive must not be flagged"
    );
}

#[test]
fn top_mixin_overlaps_query_runs_against_duckdb() {
    let path = std::env::temp_dir().join(format!(
        "intermed-overlaps-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let duck = DuckStore::open(&path).unwrap();
    let mut fact_store = FactStore::new();
    fact_store
        .fact("mixin", kind::MIXIN_OVERLAP)
        .subject("net.minecraft.server.MinecraftServer")
        .attr("mods", "lithium,sodium")
        .emit();
    let report = DoctorReport {
        schema: "intermed-doctor-report-v1".into(),
        tool_version: "0.1.0".into(),
        generated_at: chrono::Utc::now(),
        target: TargetView {
            path: "/mods".into(),
            kind: TargetKind::ModsDir,
        },
        environment: Environment::default(),
        summary: Summary::default(),
        findings: Vec::new(),
        fix_plan: Vec::new(),
        fact_stats: fact_store.stats(),
        collectors: Vec::new(),
        rules: Vec::new(),
        deferred_layers: Vec::new(),
        profile: None,
    };
    duck.persist_run(&report, fact_store.all()).unwrap();
    let analytics = intermed_duckdb::AnalyticsStore::open(&path).unwrap();
    let ranks = analytics.top_mixin_overlaps(5).expect("overlap query");
    assert_eq!(ranks.len(), 1);
    assert_eq!(ranks[0].target, "net.minecraft.server.MinecraftServer");
    std::fs::remove_file(path).ok();
}

#[test]
fn risk_patterns_view_and_method_roll_up_findings() {
    use intermed_evidence::Finding;

    let path = std::env::temp_dir().join(format!(
        "intermed-risk-patterns-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let duck = DuckStore::open(&path).unwrap();
    let findings = vec![
        Finding::builder("duplicate-id", "duplicate-id:copper")
            .severity(Severity::Error)
            .category(Category::Metadata)
            .title("dup")
            .build(),
        Finding::builder("mixin-risk", "mixin-overlap:net.minecraft.Foo")
            .severity(Severity::Warn)
            .category(Category::Mixin)
            .title("overlap")
            .build(),
    ];
    let report = DoctorReport {
        schema: "intermed-doctor-report-v1".into(),
        tool_version: "0.1.0".into(),
        generated_at: chrono::Utc::now(),
        target: TargetView {
            path: "/mods".into(),
            kind: TargetKind::ModsDir,
        },
        environment: Environment::default(),
        summary: Summary::default(),
        findings,
        fix_plan: Vec::new(),
        fact_stats: std::collections::BTreeMap::new(),
        collectors: Vec::new(),
        rules: Vec::new(),
        deferred_layers: Vec::new(),
        profile: None,
    };
    duck.persist_run(&report, &[]).unwrap();

    let analytics = intermed_duckdb::AnalyticsStore::open(&path).unwrap();
    let patterns = analytics.risk_patterns(10).expect("risk patterns");
    // Two rule×category patterns; the Error one (duplicate-id) ranks first.
    assert_eq!(patterns.len(), 2);
    assert_eq!(patterns[0].rule_id, "duplicate-id");
    assert_eq!(patterns[0].severity_rank, 3); // error
    assert!(
        patterns
            .iter()
            .any(|p| p.rule_id == "mixin-risk" && p.category == "mixin")
    );

    // The view is also directly queryable (CREATE OR REPLACE VIEW landed).
    let view = duck.query("SELECT COUNT(*) FROM risk_patterns").unwrap();
    assert_eq!(view.rows[0][0], "2");
    let hc = duck
        .query("SELECT COUNT(*) FROM historical_conflicts")
        .unwrap();
    assert_eq!(hc.rows[0][0], "2"); // duplicate-id + mixin-overlap both qualify

    std::fs::remove_file(path).ok();
}
