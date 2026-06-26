//! `intermed` — the command-line workbench.
//!
//! This binary is the **composition root**: the one place that knows about
//! every concrete collector and rule. It detects the target, builds a
//! [`DiagnosticEngine`] with the registered layers, runs it, and renders the
//! report. Adding a layer in a future phase is one `.collector(...)` line here.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result as AnyhowResult};
use clap::Parser;

use intermed_cli::command::{
    CacheArgs, CacheCommand, Command, DbArgs, DemoArgs, DemoCommand, DepsArgs, DepsCommand,
    DepsIdArgs, DepsImplicitArgs, DepsPathArgs, DoctorArgs, DoctorCacheArgs, DoctorTuningArgs,
    GraphExportFormat, HistoryArgs, ImpactArgs, ImpactCommand, ImpactRemoveArgs, ImpactUpdateArgs,
    LabArgs, LabCommand, LabEvalArgs, LogicMode, MixinMapArgs, RulesArgs, RulesCommand, SbomArgs,
    SbomCommand, SbomExportFormatCli, SparkMapArgs, TrendsArgs, VfsArgs, VfsCommand,
};
// Subcommand enums are only matched on the duckdb-backed analytics path.
#[cfg(feature = "duckdb")]
use intermed_cli::command::DbCommand;
#[cfg(feature = "duckdb")]
use intermed_cli::command::{HistoryCommand, TrendsCommand};
use intermed_cli::{detail, info};
use intermed_config::{ConfigError, IntermedConfig};
use intermed_doctor_core::evidence::Finding;
use intermed_doctor_core::facts::Fact;
use intermed_doctor_core::{
    DiagnosisSettings, DiagnosticEngine, DiagnosticRun, JarCache, Target, TargetKind,
    detect_target, materialize_modpack_archive, parse_changed_since, write_atomic,
};
use intermed_duckdb::{DuckdbRulePack, duckdb_available};
use intermed_report::{Format, write_demo_artifacts};
use intermed_spark_bridge::PerformanceThresholds;

use intermed_deps::{DependencyRule, ResolutionOutcome, build_graph, resolve_store};
use intermed_log::{LogCollector, LogSignalRule};
use intermed_minecraft_scan::{EnvironmentCollector, MetadataCollector};
use intermed_rules::{
    ColumnarRulePack, GenerateBackend, MixedLoaderPackRule, RULE_PACK_SCHEMA_V2,
    RULE_REGISTRY_SCHEMA, RulePackSelection, SouffleRulePack, check_rule_packs,
    default_rule_pack_install_dir, format_trace, generate_rules, install_pack_from_registry,
    install_pack_with_dependencies, load_registry_from_source, load_rule_pack, load_signing_key,
    load_trusted_keys, merged_default_registry, registry_to_json, resolve_doctor_packs,
    souffle_available, trace_pack, validate_rule_pack, verify_rule_pack_signature,
};
use intermed_sbom::{SbomExportFormat, export_scan, scan_mods_dir};

use intermed_cli::Cli;

mod persistence;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// mimalloc keeps RSS close to the live heap on this allocation-heavy workload (the
// fact graph is millions of small allocations that fragment glibc malloc badly).
// The dhat profiler installs its own allocator, so only swap in mimalloc otherwise.
#[cfg(not(feature = "dhat-heap"))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    #[cfg(feature = "dhat-heap")]
    let _dhat = dhat::Profiler::new_heap();
    let cli = Cli::parse();
    intermed_cli::verbosity::configure(cli.quiet, cli.verbose);

    // Bug fix: configure_thread_pool must run for ALL subcommands that use Rayon
    // (not just `doctor`), otherwise vfs/sbom/lab/deps scans ignore the jobs limit.
    // We read from INTERMED_JOBS env var as a lightweight fallback when no config
    // is loaded yet. configure_thread_pool errors are non-fatal — warn and continue.
    let early_jobs: Option<usize> = std::env::var("INTERMED_JOBS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0);
    if let Err(e) = configure_thread_pool(early_jobs) {
        eprintln!("warning: {e} (continuing with Rayon default)");
    }

    if cli.dump_config {
        match IntermedConfig::defaults().to_toml() {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: could not serialize default config: {e}");
                ExitCode::from(2)
            }
        }
    } else if let Some(command) = cli.command {
        match command {
            Command::Doctor(args) => run_doctor(args, cli.config.as_deref()),
            Command::Vfs(args) => run_vfs(args),
            Command::Deps(args) => run_deps(args),
            Command::Impact(args) => run_impact(args),
            Command::MixinMap(args) => run_mixin_map(args),
            Command::SparkMap(args) => run_spark_map(args),
            Command::Lab(args) => run_lab(args, cli.config.as_deref()),
            Command::Rules(args) => run_rules(args),
            Command::Db(args) => run_db(args),
            Command::History(args) => run_history(args),
            Command::Trends(args) => run_trends(args),
            Command::Cache(args) => run_cache(args),
            Command::Sbom(args) => run_sbom(args),
            Command::Demo(args) => run_demo(args),
        }
    } else {
        eprintln!(
            "error: subcommand required (try `intermed doctor --help` or `intermed --dump-config`)"
        );
        ExitCode::from(2)
    }
}

/// Size the global Rayon pool that every parallel scanner shares. `None` or `0`
/// leaves Rayon's default (one worker per core). A non-zero cap is for weak
/// machines and shared CI runners where saturating all cores is undesirable.
///
/// `build_global` may only be called once per process; since exactly one
/// subcommand runs per invocation, that is fine.
fn configure_thread_pool(jobs: Option<usize>) -> Result<(), String> {
    let n = match jobs {
        None | Some(0) => return Ok(()),
        Some(n) => n,
    };
    rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .build_global()
        .map_err(|e| format!("could not configure {n} worker thread(s): {e}"))
}

/// Process exit code for a completed run.
///
/// Normally follows the linter convention (`report.exit_code()`: 0 healthy,
/// 1 warnings, 2 errors). When `--exit-zero` is set, findings no longer affect
/// the exit code — only genuine operational failures (handled by earlier
/// `ExitCode::from(2)` returns) produce a non-zero status.
fn findings_exit_code(
    report: &intermed_doctor_core::report::DoctorReport,
    exit_zero: bool,
) -> ExitCode {
    if exit_zero {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(report.exit_code() as u8)
    }
}

fn stdout_artifact_count(output: &intermed_cli::command::DoctorOutputArgs) -> usize {
    [output.json.as_ref(), output.sarif.as_ref()]
        .into_iter()
        .flatten()
        .filter(|target| target.is_none())
        .count()
}

fn write_report_artifact(
    path: &Path,
    report: &intermed_doctor_core::report::DoctorReport,
    facts: &[Fact],
    format: Format,
    label: &str,
) -> AnyhowResult<()> {
    let rendered = intermed_report::render_with_facts(report, facts, format);
    write_atomic(path, rendered.as_bytes())
        .with_context(|| format!("could not write {label} report to {}", path.display()))
}

fn run_doctor(args: Box<DoctorArgs>, config_path: Option<&Path>) -> ExitCode {
    // Bug fix (Баг 10): delegate to run_doctor_inner which returns anyhow::Result
    // so error chains are preserved and displayed with full context instead of
    // a bare eprintln!("{e}") that discards intermediate causes.
    match run_doctor_inner(args, config_path) {
        Ok(code) => code,
        Err(e) => {
            // anyhow's Display already includes the chain ("context: cause: root").
            eprintln!("error: {e:?}");
            ExitCode::from(2)
        }
    }
}

fn run_doctor_inner(args: Box<DoctorArgs>, config_path: Option<&Path>) -> AnyhowResult<ExitCode> {
    if !args.target.exists() {
        anyhow::bail!("target does not exist: {}", args.target.display());
    }
    if stdout_artifact_count(&args.output) > 1 {
        anyhow::bail!(
            "--json and --sarif can both be requested as files, but only one report format can write to stdout"
        );
    }

    // Bug fix (Баг 9): fail-fast on unavailable engines before any I/O.
    if args.logic == LogicMode::Souffle && !souffle_available() {
        anyhow::bail!("--logic=souffle requires the 'souffle' binary in PATH");
    }
    if args.logic == LogicMode::Duckdb && !duckdb_available() {
        anyhow::bail!("--logic=duckdb requires building with --features duckdb");
    }
    if args.db.is_some() && !duckdb_available() {
        anyhow::bail!("--db requires building with --features duckdb");
    }

    let mut cfg = IntermedConfig::load(config_path).map_err(|e| match e {
        ConfigError::Read { path, source } => {
            anyhow::anyhow!("could not read config {}: {source}", path.display())
        }
        other => anyhow::anyhow!("{other}"),
    })?;
    apply_doctor_cli_overrides(&mut cfg, &args);

    // Bug fix (Баг 6): configure_thread_pool is hoisted to main() for all commands.
    // Here we refine it with the doctor-specific jobs setting if it was not yet set
    // via INTERMED_JOBS env var. build_global silently no-ops if already initialized.
    let jobs = args
        .jobs
        .or_else(|| (cfg.runtime.jobs > 0).then_some(cfg.runtime.jobs));
    if let Err(e) = configure_thread_pool(jobs) {
        // A second call after build_global is already done is a no-op error; ignore it.
        let _ = e;
    }

    let mut target: Target = detect_target(&args.target);
    let modpack_mount = materialize_modpack_archive(&target)
        .map(|(updated, mount)| {
            target = updated;
            mount
        })
        .context("modpack extraction failed")?;
    if let Some(md) = args.mods_dir.clone() {
        target.mods_dir = Some(md);
        if target.kind == TargetKind::Unknown {
            target.kind = TargetKind::ModsDir;
        }
    }
    // IMPORTANT: _keep_modpack must remain in scope until the engine run completes.
    // The drop guard unmounts a temporary directory; dropping it early would
    // invalidate paths the engine is still reading. Intentional binding, not dead code.
    let _keep_modpack = modpack_mount;
    if let Some(ref report) = args.performance.spark_report {
        target.spark_report = Some(report.clone());
    }

    let cache_enabled = !args.cache.no_cache;
    let jar_cache = init_jar_cache(&cfg, &args.cache, cache_enabled).map_err(anyhow::Error::msg)?;

    let performance = args.performance.performance || cfg.performance.enabled;
    if performance && target.spark_report.is_none() {
        info!(
            "note: --performance is on but no Spark report was provided, so there is no \
             runtime profile to correlate against. Capture one with the Spark mod \
             (`/spark profiler --timeout 60`) and pass it via `--spark-report <file.json>` \
             (or `spark_report` in config) to get hot-path × mixin findings."
        );
    }
    let perf_thresholds = performance_thresholds_from_config(&cfg, &args.performance);
    let changed_since = if let Some(ref since) = args.cache.changed_since {
        Some(
            parse_changed_since(since)
                .map_err(|e| anyhow::anyhow!("invalid --changed-since value: {e}"))?,
        )
    } else {
        None
    };
    let settings = diagnosis_settings_from_config(&cfg, &args.tuning, changed_since);
    let rule_pack_selection = rule_pack_selection_from(&cfg, &args);
    // `without_mixin`: when Layer-F mixin-risk runs (any logic mode), drop the
    // lighter declarative mixin rules from the pack so the two don't double-report.
    let resolved_rules = resolve_doctor_packs(args.mixin_risk, &rule_pack_selection)
        .context("rule pack resolution failed")?;
    if !resolved_rules.overlay_ids.is_empty() {
        info!(
            "rule-packs: merged overlays [{}]",
            resolved_rules.overlay_ids.join(", ")
        );
        for t in &resolved_rules.trust {
            info!("rule-pack `{}`: {}", t.id, t.trust.describe());
        }
    }
    print_rule_provenance(args.logic);
    let engine = build_engine(
        args.logic,
        args.mixin_risk,
        performance,
        perf_thresholds,
        settings,
        jar_cache,
        resolved_rules.pack,
    );
    let run = engine.diagnose_with_facts(&target);
    detail!(
        "scan: {} fact(s), {} finding(s) across {} collector(s)",
        run.facts.len(),
        run.report.findings.len(),
        run.report.collectors.len()
    );

    if let Some(path) = &args.output.profile {
        persistence::write_profile(path, &run.profile)
            .map_err(|e| anyhow::anyhow!("could not write profile to {}: {e}", path.display()))?;
    }

    if let Some(path) = &args.provenance.dump_facts {
        persistence::write_facts(path, &run.facts)
            .map_err(|e| anyhow::anyhow!("could not write facts to {}: {e}", path.display()))?;
    }

    if let Some(path) = &args.db {
        if let Err(e) = persistence::persist_duckdb_run(path, &run) {
            eprintln!("error: {e:#}");
            if !args.db_best_effort {
                return Ok(ExitCode::from(2));
            }
        }
    }

    if let Some(finding_id) = &args.provenance.explain {
        return Ok(explain_finding(
            &run,
            finding_id,
            !args.output.no_color && std::io::stdout().is_terminal(),
            args.output.exit_zero,
        ));
    }

    if let Some(path) = &args.output.html {
        let html = intermed_report::render_html_with_facts(&run.report, &run.facts);
        write_atomic(path, html.as_bytes())
            .with_context(|| format!("could not write HTML report to {}", path.display()))?;
    }

    let mut wrote_artifact = args.output.html.is_some();
    let mut wrote_stdout = false;

    if let Some(target) = &args.output.json {
        wrote_artifact = true;
        match target {
            Some(path) => {
                write_report_artifact(path, &run.report, &run.facts, Format::Json, "JSON")?
            }
            None => {
                println!(
                    "{}",
                    intermed_report::render_with_facts(&run.report, &run.facts, Format::Json)
                );
                wrote_stdout = true;
            }
        }
    }

    if let Some(target) = &args.output.sarif {
        wrote_artifact = true;
        match target {
            Some(path) => {
                write_report_artifact(path, &run.report, &run.facts, Format::Sarif, "SARIF")?
            }
            None => {
                println!(
                    "{}",
                    intermed_report::render_with_facts(&run.report, &run.facts, Format::Sarif)
                );
                wrote_stdout = true;
            }
        }
    }

    if !wrote_artifact && !wrote_stdout {
        let color = !args.output.no_color && std::io::stdout().is_terminal();
        println!(
            "{}",
            intermed_report::render_with_facts(&run.report, &run.facts, Format::Terminal { color })
        );
    }
    Ok(findings_exit_code(&run.report, args.output.exit_zero))
}

fn apply_doctor_cli_overrides(cfg: &mut IntermedConfig, args: &DoctorArgs) {
    // Note: cfg.cache.* are NOT mutated here. init_jar_cache() reads the cache
    // override args (cache_max_mib, cache_max_age_days) directly from `args`, so
    // mutating cfg would create a double-apply and confuse debugging. The config
    // file value remains the baseline; CLI args are overlaid non-destructively.
    //
    // cfg.performance.enabled is NOT mutated here either: run_doctor reads
    // `args.performance.performance || cfg.performance.enabled` directly on the
    // line that computes the `performance` bool, so a mutation here would be
    // redundant and would pollute the config value seen elsewhere.
    if let Some(ms) = args.performance.tick_spike_ms {
        cfg.performance.tick_spike_ms = ms;
    }
    if let Some(ms) = args.performance.tick_spike_warn_ms {
        cfg.performance.tick_spike_warn_ms = ms;
    }
    if let Some(pct) = args.performance.high_cpu_percent {
        cfg.performance.high_cpu_percent = pct;
    }
    if let Some(pct) = args.performance.hot_method_floor_percent {
        cfg.performance.hot_method_floor_percent = pct;
    }
    if let Some(n) = args.tuning.security_min_note_signals {
        cfg.security.min_note_signals = n;
    }
    if let Some(score) = args.tuning.sbom_well_identified_trust {
        cfg.sbom.well_identified_trust = score;
    }
    if let Some(n) = args.tuning.log_parallel_line_threshold {
        cfg.log.parallel_line_threshold = n;
    }
    if let Some(score) = args.tuning.security_corroborated_confidence {
        cfg.security.corroborated_confidence = score;
    }
    if let Some(level) = args.tuning.metadata_level {
        cfg.metadata.level = match level {
            intermed_cli::command::MetadataLevelArg::Basic => "basic".to_string(),
            intermed_cli::command::MetadataLevelArg::Enriched => "enriched".to_string(),
            intermed_cli::command::MetadataLevelArg::Full => "full".to_string(),
        };
    }
    if let Some(level) = args.tuning.resource_level {
        cfg.resource.level = match level {
            intermed_cli::command::ResourceLevelArg::Basic => "basic".to_string(),
            intermed_cli::command::ResourceLevelArg::Semantic => "semantic".to_string(),
            intermed_cli::command::ResourceLevelArg::Full => "full".to_string(),
        };
    }
    if let Some(jobs) = args.jobs {
        cfg.runtime.jobs = jobs;
    }
    if let Some(level) = args.mixin.level {
        cfg.mixin.level = match level {
            intermed_cli::command::MixinLevelArg::Normal => "normal".to_string(),
            intermed_cli::command::MixinLevelArg::Detailed => "detailed".to_string(),
            intermed_cli::command::MixinLevelArg::Full => "full".to_string(),
        };
    }
    if args.mixin.no_mixin_handler_effects {
        cfg.mixin.handler_effects = Some(false);
    } else if args.mixin.mixin_handler_effects {
        cfg.mixin.handler_effects = Some(true);
    }
    if args.mixin.no_mixin_recommendations {
        cfg.mixin.recommendations = Some(false);
    } else if args.mixin.mixin_recommendations {
        cfg.mixin.recommendations = Some(true);
    }
}

/// Initialize the [`JarCache`] for a `doctor` run (Bug fix 8: extracted from `run_doctor`).
///
/// Keeps the ~20-line initialization block out of the top-level function, giving
/// it a single clear purpose and a testable surface.
fn init_jar_cache(
    cfg: &IntermedConfig,
    cache_args: &DoctorCacheArgs,
    enabled: bool,
) -> Result<Option<JarCache>, String> {
    if !enabled {
        return Ok(Some(JarCache::disabled()));
    }
    let mut cache_config = cfg.jar_cache_config();
    if let Some(mib) = cache_args.cache_max_mib {
        cache_config = cache_config.with_max_bytes(mib.saturating_mul(1024 * 1024));
    }
    if let Some(days) = cache_args.cache_max_age_days {
        cache_config = cache_config.with_max_age_days(days);
    }
    let cache = JarCache::new_with_config(true, cache_args.cache_dir.clone(), cache_config)
        .map_err(|e| format!("could not initialize jar cache: {e}"))?;
    let cache = match &cache_args.cache_remote_dir {
        Some(dir) => cache.with_remote(std::sync::Arc::new(
            intermed_doctor_core::LocalDirRemoteTier::new(dir.clone()),
        )),
        None => cache,
    };
    Ok(Some(cache))
}

fn performance_thresholds_from_config(
    cfg: &IntermedConfig,
    perf_args: &intermed_cli::command::DoctorPerformanceArgs,
) -> PerformanceThresholds {
    let mut thresholds = PerformanceThresholds {
        tick_spike_ms: cfg.performance.tick_spike_ms,
        tick_spike_warn_ms: cfg.performance.tick_spike_warn_ms,
        high_cpu_percent: cfg.performance.high_cpu_percent,
        hot_method_floor_percent: cfg.performance.hot_method_floor_percent,
    };
    if let Some(ms) = perf_args.tick_spike_ms {
        thresholds.tick_spike_ms = ms;
    }
    if let Some(ms) = perf_args.tick_spike_warn_ms {
        thresholds.tick_spike_warn_ms = ms;
    }
    if let Some(pct) = perf_args.high_cpu_percent {
        thresholds.high_cpu_percent = pct;
    }
    if let Some(pct) = perf_args.hot_method_floor_percent {
        thresholds.hot_method_floor_percent = pct;
    }
    thresholds
}

fn diagnosis_settings_from_config(
    cfg: &IntermedConfig,
    tuning: &DoctorTuningArgs,
    changed_since: Option<std::time::SystemTime>,
) -> DiagnosisSettings {
    let mut settings = cfg.diagnosis_settings();
    if let Some(n) = tuning.security_min_note_signals {
        settings.security.min_note_signals = n;
    }
    if let Some(score) = tuning.sbom_well_identified_trust {
        settings.sbom.well_identified_trust = score;
    }
    if let Some(n) = tuning.log_parallel_line_threshold {
        settings.log.parallel_line_threshold = n;
    }
    if let Some(score) = tuning.security_corroborated_confidence {
        settings.security.corroborated_confidence = score;
    }
    if let Some(jar) = &tuning.minecraft_jar {
        settings.minecraft_jar = Some(jar.clone());
    }
    if let Some(mappings) = &tuning.minecraft_mappings {
        settings.minecraft_mappings = Some(mappings.clone());
    }
    settings.scan.changed_since = changed_since;
    settings
}

fn rule_pack_selection_from(cfg: &IntermedConfig, args: &DoctorArgs) -> RulePackSelection {
    let mut extras = cfg.rules.packs.clone();
    extras.extend(args.rule_packs.clone());
    RulePackSelection {
        extras,
        install_dir: args
            .rule_pack_dir
            .clone()
            .or_else(|| cfg.rules.install_dir.as_ref().map(PathBuf::from)),
        skip_installed: args.core_rule_pack_only || cfg.rules.core_only,
        registry_source: args
            .rule_pack_registry
            .clone()
            .or_else(|| cfg.rules.registry.clone()),
        trusted_keys_path: args
            .rule_pack_trusted_keys
            .clone()
            .or_else(|| cfg.rules.trusted_keys.as_ref().map(PathBuf::from)),
        trust_policy: intermed_rules::TrustPolicy {
            allow_insecure_registry: args.allow_insecure_registry,
            allow_unsigned_rules: args.allow_unsigned_rules,
        },
    }
}

/// Which Layer-J-adjacent rules run on the declarative backend vs. the imperative
/// fallback, for a given logic mode. Single source of truth shared by
/// [`build_engine`] (what to wire) and [`print_rule_provenance`] (what to report),
/// so the message can never drift from the actual wiring.
struct RuleBackendPlan {
    declarative_log: bool,
    declarative_security: bool,
    declarative_sbom_provenance: bool,
    declarative_sbom_correlation: bool,
}

fn rule_backend_plan(logic: LogicMode) -> RuleBackendPlan {
    RuleBackendPlan {
        declarative_log: logic == LogicMode::Duckdb,
        declarative_security: logic == LogicMode::Duckdb,
        declarative_sbom_provenance: logic == LogicMode::Duckdb,
        declarative_sbom_correlation: logic == LogicMode::Duckdb,
    }
}

/// Report which rules ran from the chosen Layer-J backend vs. the residual interpreter
/// path. The default columnar engine runs silently; provenance is only reported for an
/// explicitly-selected external backend (Soufflé / DuckDB), at `NORMAL` verbosity.
fn print_rule_provenance(logic: LogicMode) {
    if logic == LogicMode::Columnar {
        return;
    }
    let backend = match logic {
        LogicMode::Souffle => "Soufflé Datalog",
        LogicMode::Duckdb => "DuckDB SQL",
        LogicMode::Columnar => unreachable!(),
    };
    let plan = rule_backend_plan(logic);

    let mut declarative = vec![format!("Layer J core via {backend}")];
    let mut fallback = Vec::new();
    let mut place = |declarative_backed: bool, label: &str| {
        if declarative_backed {
            declarative.push(label.to_string());
        } else {
            fallback.push(label.to_string());
        }
    };
    place(plan.declarative_log, "Layer D log signals");
    place(plan.declarative_security, "Layer G security");
    place(plan.declarative_sbom_provenance, "Layer H SBOM provenance");
    place(
        plan.declarative_sbom_correlation,
        "Layer H×G SBOM-security correlation",
    );
    // These rules are always imperative regardless of backend.
    fallback.push("Layer C dependencies".into());
    fallback.push("Layer A×B mixed-loader".into());
    fallback.push("Layer E dynamics".into());

    info!("logic[{logic}]: declarative → {}", declarative.join(", "));
    info!("logic[{logic}]: imperative rules → {}", fallback.join(", "));
}

fn build_engine(
    logic: LogicMode,
    mixin_risk: bool,
    performance: bool,
    perf_thresholds: PerformanceThresholds,
    settings: DiagnosisSettings,
    jar_cache: Option<JarCache>,
    pack: intermed_rules::RulePack,
) -> DiagnosticEngine {
    let mut builder = DiagnosticEngine::builder()
        .tool_version(env!("CARGO_PKG_VERSION"))
        .jar_cache(jar_cache)
        .settings(settings)
        // ── Working collectors ──
        .collector(EnvironmentCollector) // Layer A
        .collector(intermed_doctor_core::ModpackManifestCollector) // Layer A — manifest-only packs
        .collector(MetadataCollector) // Layer B
        .collector(LogCollector) // Layer D
        .collector(intermed_vfs::collector()) // Layer E
        .collector(intermed_resource_ast::collector()) // Layer M — resource/data semantics (AST)
        .collector(intermed_dynamics::collector()) // Layer E — script-engine dynamics (logs)
        .collector(intermed_dynamics::static_script_collector()) // Layer E — static script scan
        .collector(intermed_security_audit::collector()) // Layer G
        .collector(intermed_sbom::collector()) // Layer H
        // ── Working rules ──
        // Dynamics is an independent evidence stream (not part of the swappable
        // Layer-J core pack), so it runs the same in every logic backend.
        .rule(intermed_dynamics::rule()) // Layer E — script-engine dynamics
        .rule(intermed_resource_ast::rule()) // Layer M — resource/data semantics (AST)
        .rule(DependencyRule) // Layer C — pairwise semver + PubGrub global unsat
        .rule(intermed_doctor_core::ModpackIntegrityRule) // Layer A — manifest-only packs
        .rule(MixedLoaderPackRule); // Layer A×B — mixed loaders in bare mods dirs

    let plan = rule_backend_plan(logic);

    if !plan.declarative_log {
        builder = builder.rule(LogSignalRule); // Layer D
    }
    if !plan.declarative_security {
        builder = builder.rule(intermed_security_audit::rule()); // Layer G
    }
    if !plan.declarative_sbom_provenance {
        builder = builder.rule(intermed_sbom::rule()); // Layer H
    }
    if !plan.declarative_sbom_correlation {
        builder = builder.rule(intermed_sbom::correlation_rule()); // Layer H×G
    }

    if mixin_risk {
        builder = builder.collector(intermed_mixin_intel::collector()); // Layer F
    }
    if performance {
        builder = builder
            .collector(intermed_spark_bridge::collector()) // Layer I
            .rule(intermed_spark_bridge::rule_with_thresholds(perf_thresholds));
    }

    // Every Layer-J backend evaluates the *resolved* pack (honoring --mixin-risk's
    // without-mixin selection + installed overlays); only one arm runs, so the move is
    // fine. The columnar engine is the default in-process backend.
    match logic {
        LogicMode::Souffle => builder = builder.rule(SouffleRulePack::new(pack)), // Layer J — Soufflé
        LogicMode::Duckdb => builder = builder.rule(DuckdbRulePack::new(pack)), // Layer J — DuckDB SQL
        LogicMode::Columnar => builder = builder.rule(ColumnarRulePack::new(pack)),
    }

    // Layer-F mixin-risk is an independent imperative Rust rule (full bytecode
    // analysis); it runs under *any* `--logic` backend, not only imperative — the
    // backend choice only routes the declarative Layer-J pack.
    if mixin_risk {
        builder = builder.rule(intermed_mixin_intel::rule()); // Layer F — Phase 4
    }

    builder.build()
}

fn run_db(args: DbArgs) -> ExitCode {
    if !duckdb_available() {
        eprintln!("error: `intermed db` requires building with --features duckdb");
        return ExitCode::from(2);
    }
    #[cfg(feature = "duckdb")]
    {
        match args.command {
            // Read-only at the engine level: an ad-hoc query can never DROP /
            // DELETE / mutate the analytics store (the `--help` promise is real).
            DbCommand::Query(query) => match intermed_duckdb::DuckStore::open_readonly(&query.db) {
                Ok(store) => match store.query(&query.sql) {
                    Ok(result) => {
                        if !result.columns.is_empty() {
                            println!("{}", result.columns.join("\t"));
                        }
                        for row in &result.rows {
                            println!("{}", row.join("\t"));
                        }
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("error: query failed: {e}");
                        ExitCode::from(2)
                    }
                },
                Err(e) => {
                    eprintln!("error: could not open {}: {e}", query.db.display());
                    ExitCode::from(2)
                }
            },
        }
    }
    #[cfg(not(feature = "duckdb"))]
    {
        let _ = args;
        ExitCode::from(2)
    }
}

/// Outcome of matching an `--explain <query>` argument against the report.
enum ExplainResolution<'a> {
    /// `query` is exactly a finding id.
    Exact(&'a Finding),
    /// `query` unambiguously identifies one finding by case-insensitive or
    /// substring match (auto-resolved, with a note to the user).
    Fuzzy(&'a Finding),
    /// No unambiguous match, but similar ids exist — ranked "did you mean" list.
    Suggestions(Vec<&'a Finding>),
    /// Nothing resembles `query`; fall back to the most severe findings.
    Listing(Vec<&'a Finding>),
}

/// Rank `findings` by Jaro-Winkler similarity of their (lowercased) id to
/// `query_lc`, keeping only matches at or above `min_score`, best first.
fn rank_by_similarity<'a>(
    findings: &'a [Finding],
    query_lc: &str,
    min_score: f64,
) -> Vec<&'a Finding> {
    let mut scored: Vec<(f64, &Finding)> = findings
        .iter()
        .map(|f| {
            (
                strsim::jaro_winkler(query_lc, &f.id.to_ascii_lowercase()),
                f,
            )
        })
        .filter(|(score, _)| *score >= min_score)
        .collect();
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.id.cmp(&b.1.id))
    });
    scored.truncate(10);
    scored.into_iter().map(|(_, f)| f).collect()
}

/// Resolve an `--explain` query to a finding (exact, then fuzzy), or to a list
/// of suggestions. Auto-resolution only fires on an *unambiguous* case-insensitive
/// or substring hit, so behaviour stays predictable; Jaro-Winkler is used only to
/// order suggestions, never to silently pick a finding.
fn resolve_explain_target<'a>(findings: &'a [Finding], query: &str) -> ExplainResolution<'a> {
    if let Some(f) = findings.iter().find(|f| f.id == query) {
        return ExplainResolution::Exact(f);
    }
    let query_lc = query.to_ascii_lowercase();

    let ci_exact: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.id.eq_ignore_ascii_case(query))
        .collect();
    if ci_exact.len() == 1 {
        return ExplainResolution::Fuzzy(ci_exact[0]);
    }

    let substring: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.id.to_ascii_lowercase().contains(&query_lc))
        .collect();
    match substring.len() {
        1 => return ExplainResolution::Fuzzy(substring[0]),
        n if n > 1 => {
            // Order the substring hits by similarity for a stable "did you mean".
            return ExplainResolution::Suggestions(rank_by_similarity(findings, &query_lc, 0.0));
        }
        _ => {}
    }

    let similar = rank_by_similarity(findings, &query_lc, 0.6);
    if !similar.is_empty() {
        return ExplainResolution::Suggestions(similar);
    }

    let mut by_severity: Vec<&Finding> = findings.iter().collect();
    by_severity.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    by_severity.truncate(10);
    ExplainResolution::Listing(by_severity)
}

fn explain_finding(run: &DiagnosticRun, query: &str, color: bool, exit_zero: bool) -> ExitCode {
    let finding = match resolve_explain_target(&run.report.findings, query) {
        ExplainResolution::Exact(finding) => finding,
        ExplainResolution::Fuzzy(finding) => {
            eprintln!(
                "note: no finding with id '{query}'; showing closest match '{}'",
                finding.id
            );
            finding
        }
        ExplainResolution::Suggestions(suggestions) => {
            eprintln!("error: no finding matches '{query}'. Did you mean:");
            print_finding_list(&suggestions);
            return ExitCode::from(2);
        }
        ExplainResolution::Listing(listing) => {
            if listing.is_empty() {
                eprintln!("error: no finding matches '{query}'; this report has no findings");
            } else {
                eprintln!("error: no finding matches '{query}'. Top findings in this report:");
                print_finding_list(&listing);
            }
            return ExitCode::from(2);
        }
    };

    print_finding_explanation(run, finding, color);
    findings_exit_code(&run.report, exit_zero)
}

/// Compact one-line-per-finding listing used for `--explain` suggestions.
fn print_finding_list(findings: &[&Finding]) {
    for f in findings {
        eprintln!("  {}  [{}] {}", f.id, f.severity.as_str(), f.title);
    }
}

fn print_finding_explanation(run: &DiagnosticRun, finding: &Finding, color: bool) {
    let facts_by_id: BTreeMap<_, _> = run.facts.iter().map(|f| (f.id, f)).collect();
    let sev = finding.severity.as_str().to_ascii_uppercase();
    let sev = if color {
        format!("\x1b[1m{sev}\x1b[0m")
    } else {
        sev
    };

    println!("{sev} {}", finding.title);
    println!("id: {}", finding.id);
    println!("rule: {}", finding.rule_id);
    if !finding.explanation.is_empty() {
        println!();
        println!("{}", finding.explanation);
    }
    if !finding.fix_candidates.is_empty() {
        println!();
        println!("Fix candidates:");
        for fix in &finding.fix_candidates {
            println!("- {}", fix.description);
            if let Some(command) = &fix.command {
                println!("  command: {command}");
            }
        }
    }
    println!();
    println!("Evidence:");
    for edge in &finding.evidence {
        if let Some(fact) = facts_by_id.get(&edge.fact) {
            println!(
                "- {} {:?} weight={:.2}: {} subject={}",
                fact.id, edge.relation, edge.weight, fact.kind, fact.subject
            );
            if !fact.attributes.is_empty() {
                let attrs = serde_json::to_string(&fact.attributes).unwrap_or_else(|_| "{}".into());
                println!("  attrs: {attrs}");
            }
            println!(
                "  source: {}{}{} extractor={}",
                fact.source.locator,
                fact.source
                    .line
                    .map(|line| format!(":{line}"))
                    .unwrap_or_default(),
                fact.source
                    .inner
                    .as_ref()
                    .map(|inner| format!("!{inner}"))
                    .unwrap_or_default(),
                fact.extractor
            );
        } else {
            println!(
                "- {} {:?} weight={:.2}: <missing fact>",
                edge.fact, edge.relation, edge.weight
            );
        }
    }
}

fn run_deps(args: DepsArgs) -> ExitCode {
    match args.command {
        DepsCommand::Graph(args) => {
            let target = match deps_target(&args) {
                Ok(t) => t,
                Err(code) => return code,
            };
            let store = match collect_layer_c_facts(&target) {
                Ok(s) => s,
                Err(code) => return code,
            };
            let graph = build_graph(&store);
            let payload = serde_json::json!({
                "schema": "intermed-modpack-graph-v1",
                "graph": graph,
            });
            match serde_json::to_string_pretty(&payload) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: serialize graph: {e}");
                    ExitCode::from(2)
                }
            }
        }
        DepsCommand::Resolve(args) => {
            let target = match deps_target(&args) {
                Ok(t) => t,
                Err(code) => return code,
            };
            let store = match collect_layer_c_facts(&target) {
                Ok(s) => s,
                Err(code) => return code,
            };
            match resolve_store(&store) {
                Ok(outcome) => {
                    let payload = serde_json::json!({
                        "schema": "intermed-deps-resolution-v1",
                        "outcome": outcome,
                    });
                    match serde_json::to_string_pretty(&payload) {
                        Ok(text) => {
                            println!("{text}");
                            let exit = match &outcome {
                                ResolutionOutcome::Unsatisfiable { .. } => 1,
                                _ => 0,
                            };
                            ExitCode::from(exit)
                        }
                        Err(e) => {
                            eprintln!("error: serialize resolution: {e}");
                            ExitCode::from(2)
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        DepsCommand::Why(args) => run_deps_why(args, false),
        DepsCommand::WhyMissing(args) => run_deps_why(args, true),
        DepsCommand::Implicit(args) => run_deps_implicit(args),
        DepsCommand::Path(args) => run_deps_path(args),
    }
}

/// Resolve a target from an id-bearing deps arg, collecting Layer-C facts.
fn collect_for_id(
    target_path: &std::path::Path,
    mods_dir: Option<&std::path::Path>,
) -> Result<intermed_doctor_core::facts::FactStore, ExitCode> {
    let target = detect_target_or_exit(target_path)?;
    let target = match mods_dir {
        Some(md) => Target {
            mods_dir: Some(md.to_path_buf()),
            game_root: None,
            layout: None,
            instance_type: None,
            ..target
        },
        None => target,
    };
    collect_layer_c_facts(&target)
}

fn run_deps_why(args: DepsIdArgs, missing: bool) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let report = if missing {
        intermed_deps::why_missing(&store, &args.id)
    } else {
        intermed_deps::why(&store, &args.id)
    };
    if args.json {
        emit_json("intermed-deps-why-v1", "report", &report)
    } else {
        println!("{}", report.render());
        // why-missing of an absent, required dependency is an actionable state.
        if missing && !report.present && !report.reasons.is_empty() {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}

fn run_deps_implicit(args: DepsImplicitArgs) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let refs = intermed_deps::implicit_for_namespace(&store, &args.namespace);
    if args.json {
        let payload = serde_json::json!({
            "schema": "intermed-deps-implicit-v1",
            "namespace": args.namespace,
            "references": refs,
        });
        print_json_payload(&payload)
    } else {
        if refs.is_empty() {
            println!("No implicit references to namespace `{}`.", args.namespace);
            return ExitCode::SUCCESS;
        }
        println!(
            "{} mod(s) implicitly reference namespace `{}`:",
            refs.len(),
            args.namespace
        );
        for r in &refs {
            let req = if r.required {
                "required"
            } else {
                "conditional"
            };
            println!(
                "  {} -> {} -> namespace {} ({}, {} ref(s), e.g. {}) [{}]",
                r.consumer, r.via, args.namespace, req, r.ref_count, r.sample_path, r.resolve_state
            );
        }
        ExitCode::SUCCESS
    }
}

fn run_deps_path(args: DepsPathArgs) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let chain = intermed_deps::dependency_path(&store, &args.from, &args.to);
    if args.json {
        let payload = serde_json::json!({
            "schema": "intermed-deps-path-v1",
            "from": args.from,
            "to": args.to,
            "path": chain,
        });
        print_json_payload(&payload)
    } else {
        match chain {
            Some(edges) => {
                println!("Dependency path {} -> {}:", args.from, args.to);
                for e in &edges {
                    println!("  {}", e.render());
                }
                ExitCode::SUCCESS
            }
            None => {
                println!("No dependency path from {} to {}.", args.from, args.to);
                ExitCode::SUCCESS
            }
        }
    }
}

fn run_impact(args: ImpactArgs) -> ExitCode {
    match args.command {
        ImpactCommand::Remove(args) => run_impact_remove(args),
        ImpactCommand::Update(args) => run_impact_update(args),
    }
}

fn run_impact_remove(args: ImpactRemoveArgs) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let impact = intermed_deps::remove_impact(&store, &args.id);
    if args.json {
        return emit_json("intermed-impact-remove-v1", "impact", &impact);
    }
    println!(
        "Removing {} ({}):",
        impact.target,
        if impact.installed {
            "installed"
        } else {
            "not an installed mod id"
        }
    );
    if impact.is_empty() {
        println!("  nothing in the pack references it.");
        return ExitCode::SUCCESS;
    }
    for (domain, count) in &impact.resources.by_domain {
        println!(
            "  - {count} {domain}(s) reference the {} namespace",
            impact.target
        );
    }
    if !impact.implicit_dependents.is_empty() {
        println!(
            "  - {} mod(s) have an implicit static dependency on {}",
            impact.implicit_dependents.len(),
            impact.target
        );
        for d in &impact.implicit_dependents {
            println!("      {} (via {})", d.mod_id, d.via);
        }
    }
    if !impact.declared_dependents.is_empty() {
        println!(
            "  - {} declared dependency/ies require {}",
            impact.declared_dependents.len(),
            impact.target
        );
        for d in &impact.declared_dependents {
            println!("      {d}");
        }
    }
    if !impact.provides.is_empty() {
        println!(
            "  - also provides (lost on removal): {}",
            impact.provides.join(", ")
        );
    }
    ExitCode::SUCCESS
}

fn run_impact_update(args: ImpactUpdateArgs) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let from = if args.from == "-" {
        None
    } else {
        Some(args.from.as_str())
    };
    let impact = intermed_deps::update_impact(&store, &args.id, from, &args.to);
    if args.json {
        return emit_json("intermed-impact-update-v1", "impact", &impact);
    }
    match &impact.from {
        Some(f) => println!("Updating {} {} -> {}:", impact.target, f, impact.to),
        None => println!("Updating {} to {}:", impact.target, impact.to),
    }
    if impact.breaks.is_empty() && impact.now_satisfied.is_empty() && impact.undecidable.is_empty()
    {
        println!(
            "  no declared dependency ranges constrain {}.",
            impact.target
        );
        return ExitCode::SUCCESS;
    }
    for b in &impact.breaks {
        let kind = if b.mandatory {
            "requires"
        } else {
            "optionally uses"
        };
        println!(
            "  BREAKS: {} {} {} {} — rejects {}",
            b.mod_id, kind, impact.target, b.range, impact.to
        );
    }
    for s in &impact.now_satisfied {
        println!(
            "  FIXED:  {} {} {} — now satisfied by {}",
            s.mod_id, impact.target, s.range, impact.to
        );
    }
    for u in &impact.undecidable {
        println!(
            "  CHECK:  {} {} {} — range could not be parsed",
            u.mod_id, impact.target, u.range
        );
    }
    if impact.breaks.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Serialize `value` under a `{schema, <key>: value}` envelope and print it.
fn emit_json<T: serde::Serialize>(schema: &str, key: &str, value: &T) -> ExitCode {
    let payload = serde_json::json!({ "schema": schema, key: value });
    print_json_payload(&payload)
}

fn print_json_payload(payload: &serde_json::Value) -> ExitCode {
    match serde_json::to_string_pretty(payload) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: serialize: {e}");
            ExitCode::from(2)
        }
    }
}

fn deps_target(args: &intermed_cli::command::DepsTargetArgs) -> Result<Target, ExitCode> {
    let target = detect_target_or_exit(&args.target)?;
    if let Some(mods_dir) = &args.mods_dir {
        Ok(Target {
            mods_dir: Some(mods_dir.clone()),
            game_root: None,
            layout: None,
            instance_type: None,
            ..target
        })
    } else {
        Ok(target)
    }
}

fn collect_layer_c_facts(
    target: &Target,
) -> Result<intermed_doctor_core::facts::FactStore, ExitCode> {
    // The resource AST is off by default; the implicit + effective dependency
    // levels (and the reverse resource graph behind `impact`) need it parsed, so
    // raise the level to Full for these dependency-intelligence commands. We also
    // disable fact compaction (no rules run here to cite the resource facts, so the
    // default retention policy would strip `resource_reference` / implicit edges).
    let mut settings = DiagnosisSettings::default();
    settings.resource.level = intermed_doctor_core::ResourceAstLevel::Full;
    settings.facts.retention.max_facts = usize::MAX;
    let engine = DiagnosticEngine::builder()
        .settings(settings)
        .collector(EnvironmentCollector)
        .collector(MetadataCollector)
        // Layer M — resource/data semantics: needed for the implicit + effective
        // dependency levels (`implicit_dependency_edge` / `resource_reference`).
        .collector(intermed_resource_ast::collector())
        .build();
    let run = engine.diagnose_with_facts(target);
    Ok(intermed_doctor_core::facts::FactStore::from_snapshot(
        run.facts,
    ))
}

fn run_vfs(args: VfsArgs) -> ExitCode {
    match args.command {
        VfsCommand::Scan(args) => {
            let target = match detect_target_or_exit(&args.target) {
                Ok(target) => target,
                Err(code) => return code,
            };
            match intermed_vfs::scan_target(&target) {
                Ok(scan) => {
                    print_vfs_scan(&scan);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        VfsCommand::Explain(args) => {
            let target = match detect_target_or_exit(&args.target) {
                Ok(target) => target,
                Err(code) => return code,
            };
            if args.ast || args.path.is_some() {
                return run_vfs_explain_ast(&target, &args);
            }
            match intermed_vfs::scan_target(&target) {
                Ok(scan) => {
                    print_vfs_explain(&scan);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        VfsCommand::Overlay(args) => {
            let target = match detect_target_or_exit(&args.target) {
                Ok(target) => target,
                Err(code) => return code,
            };
            let Some(mods_dir) = cli_mods_dir(&target) else {
                eprintln!("error: target has no mods directory");
                return ExitCode::from(2);
            };
            if args.explain_plan {
                match intermed_packops::build_overlay_plan_v2(&mods_dir) {
                    Ok(plan) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&plan)
                                .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
                        );
                        return ExitCode::SUCCESS;
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        return ExitCode::from(2);
                    }
                }
            }
            match intermed_packops::write_overlay_preview(
                &mods_dir,
                &args.out,
                args.include_unsafe_winners,
            ) {
                Ok(plan) => {
                    println!(
                        "Overlay preview written to {} ({} item(s){})",
                        plan.out_dir,
                        plan.manifest.items.len(),
                        if plan.manifest.safe_to_apply {
                            ", safe to apply"
                        } else {
                            ", contains unsafe winner previews — NOT safe to apply as-is"
                        }
                    );
                    if !plan.manifest.skipped.is_empty() {
                        println!(
                            "Skipped {} order-dependent collision(s); rerun with \
                             --include-unsafe-winners to stage winner previews.",
                            plan.manifest.skipped.len()
                        );
                    }
                    println!("Manifest: {}/intermed-overlay-manifest.json", plan.out_dir);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
    }
}

/// `vfs explain --path <p> --ast`: the Layer-M typed view of one resource —
/// domain, every writer, the semantic diff between writers, and the outgoing
/// reference graph.
fn run_vfs_explain_ast(
    target: &intermed_doctor_core::Target,
    args: &intermed_cli::command::VfsTargetArgs,
) -> ExitCode {
    use intermed_cli::command::ResourceLevelArg;
    use intermed_resource_ast::ResourceLevel;

    let Some(path) = args.path.as_deref() else {
        eprintln!("error: --ast requires --path <resource-path>");
        return ExitCode::from(2);
    };
    let Some(mods_dir) = cli_mods_dir(target) else {
        eprintln!("error: target has no mods directory");
        return ExitCode::from(2);
    };
    let level = match args.resource_level {
        ResourceLevelArg::Basic => ResourceLevel::Semantic, // basic = no AST; promote so explain has data
        ResourceLevelArg::Semantic => ResourceLevel::Semantic,
        ResourceLevelArg::Full => ResourceLevel::Full,
    };

    let scan = match intermed_resource_ast::scan_mods_dir(&mods_dir, level) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let records: Vec<&intermed_resource_ast::ResourceAstRecord> = scan
        .records
        .iter()
        .filter(|r| r.ast.resource_path == path)
        .collect();
    if records.is_empty() {
        println!(
            "No parsed resource at `{path}` (not present, binary, or not parsed at this level)."
        );
        return ExitCode::SUCCESS;
    }

    let domain = records[0].ast.domain.as_str();
    println!("Resource: {path}");
    println!("Domain:   {domain}");

    println!("Writers:");
    let mut writers: Vec<&str> = records.iter().map(|r| r.writer.as_str()).collect();
    writers.sort_unstable();
    writers.dedup();
    for w in &writers {
        println!("  - {w}");
    }

    // Semantic diff across writers (recipe output / lang key conflicts only).
    let diffs = intermed_resource_ast::diff::compute(&scan.records);
    if let Some(d) = diffs.iter().find(|d| d.path == path) {
        println!("Semantic diff:");
        println!("  kind:   {}", d.kind.as_str());
        println!("  detail: {}", d.detail);
    } else if writers.len() > 1 {
        let hashes: std::collections::BTreeSet<&str> = records
            .iter()
            .map(|r| r.ast.semantic_hash.as_str())
            .collect();
        if hashes.len() == 1 {
            println!("Semantic diff: none (all writers semantically identical — safe)");
        } else {
            println!(
                "Semantic diff: writers differ but not in a behaviour-changing way \
                 (benign union / single-doc override — see Layer E for the merge class)"
            );
        }
    }

    // Outgoing references from the (first writer's) AST.
    let refs = &records[0].ast.references;
    if !refs.is_empty() {
        println!("References:");
        for r in refs {
            let opt = if !r.conditions.is_empty() {
                " (conditioned)"
            } else if !r.required {
                " (optional)"
            } else {
                ""
            };
            let tag = if r.is_tag { " [tag]" } else { "" };
            println!("  - {}: {}{tag}{opt}", r.relation.as_str(), r.target);
        }
    }

    ExitCode::SUCCESS
}

fn run_spark_map(args: SparkMapArgs) -> ExitCode {
    if !args.target.exists() {
        eprintln!("error: target does not exist: {}", args.target.display());
        return ExitCode::from(2);
    }
    let mut target = detect_target(&args.target);
    if let Some(report) = args.spark_report {
        target.spark_report = Some(report);
    }
    match intermed_spark_bridge::import_target(&target) {
        Ok(import) => {
            print_spark_import(&import);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_lab(args: LabArgs, config_path: Option<&Path>) -> ExitCode {
    match args.command {
        LabCommand::Discover(args) => {
            let provider = intermed_lab::FileCandidateProvider {
                path: &args.candidates,
            };
            match intermed_lab::discover_lock(&provider, &args.out) {
                Ok(lock) => {
                    println!("InterMed Lab — corpus lock");
                    println!(
                        "Environment: {} {} ({})",
                        lock.environment.loader, lock.environment.mc_version, lock.environment.side
                    );
                    println!("Pinned mods: {}", lock.mods.len());
                    println!("Digest: {}", lock.digest);
                    println!("Written: {}", args.out.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        LabCommand::Run(args) => {
            let mut cfg = match IntermedConfig::load(config_path) {
                Ok(cfg) => cfg,
                Err(ConfigError::Read { path, source }) => {
                    eprintln!("error: could not read config {}: {source}", path.display());
                    return ExitCode::from(2);
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            if let Some(n) = args.excerpt_max {
                cfg.lab.excerpt_max = n;
            }
            let options = intermed_lab::LabRunOptions {
                excerpt_max: cfg.lab.excerpt_max,
            };
            match intermed_lab::run_lab_with(&args.lock, &args.logs, &args.out, options) {
                Ok(run) => {
                    let passed = run.results.iter().filter(|r| r.status.is_pass()).count();
                    println!("InterMed Lab — run");
                    println!("Corpus digest: {}", run.corpus_digest);
                    println!("Environments: {}", run.results.len());
                    if run.results.is_empty() {
                        println!(
                            "Note: no smoke outputs ingested — place `intermed-smoke-output-v1` JSON under {}",
                            args.logs.display()
                        );
                    }
                    println!("Passed: {passed}");
                    println!("Written: {}/lab-run.json", args.out.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        LabCommand::Report(args) => {
            let run_path = if args.run.is_dir() {
                args.run.join("lab-run.json")
            } else {
                args.run.clone()
            };
            match intermed_lab::write_report(&run_path, &args.out) {
                Ok(matrix) => {
                    println!("InterMed Lab — compatibility matrix");
                    println!(
                        "Environment: {} {} ({})",
                        matrix.environment.loader,
                        matrix.environment.mc_version,
                        matrix.environment.side
                    );
                    println!(
                        "Total: {} | passed: {} | failed: {} | crashed: {} | timed out: {}",
                        matrix.total,
                        matrix.passed,
                        matrix.failed,
                        matrix.crashed,
                        matrix.timed_out
                    );
                    println!("Pass rate: {:.0}%", matrix.pass_rate() * 100.0);
                    println!(
                        "Written: {}/matrix.json, {}/index.html",
                        args.out.display(),
                        args.out.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        LabCommand::Eval(args) => run_lab_eval(args),
    }
}

fn run_lab_eval(args: LabEvalArgs) -> ExitCode {
    use intermed_cli::command::SeverityFilter;
    use intermed_doctor_core::evidence::Severity;

    let min_severity = match args.min_severity {
        SeverityFilter::Note => Severity::Note,
        SeverityFilter::Warn => Severity::Warn,
        SeverityFilter::Error => Severity::Error,
    };

    let result = match (&args.manifest, &args.report, &args.run) {
        (Some(manifest), _, _) => {
            intermed_lab::evaluate_manifest(manifest, min_severity, &args.out)
        }
        (None, Some(report), Some(run)) => {
            intermed_lab::evaluate_pair(report, run, min_severity, &args.out)
        }
        _ => {
            eprintln!("error: provide either --manifest, or both --report and --run");
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(report) => {
            println!("InterMed Lab — rule accuracy");
            println!(
                "Cases: {} | min-severity: {}",
                report.cases, report.min_severity
            );
            println!(
                "Category co-occurrence — macro precision: {:.2} | recall: {:.2}",
                report.macro_precision_category, report.macro_recall_category
            );
            for c in &report.by_category {
                println!(
                    "  {:<24} precision {:.2} recall {:.2} (tp {} fp {} fn {}, n={}) → suggest {}",
                    c.category,
                    c.precision,
                    c.recall,
                    c.true_positive,
                    c.false_positive,
                    c.false_negative,
                    c.calibration_support,
                    c.suggested_severity,
                );
            }
            let fl = &report.finding_level;
            if fl.attributed {
                println!(
                    "Finding-level (attributed) — precision: {:.2} | recall: {:.2} (tp {} fp {} fn {}, {} predictions / {} attributions)",
                    fl.precision,
                    fl.recall,
                    fl.true_positive,
                    fl.false_positive,
                    fl.false_negative,
                    fl.predictions,
                    fl.attributions,
                );
                if !report.by_rule.is_empty() {
                    println!(
                        "Per-rule — macro precision: {:.2} | recall: {:.2}",
                        report.macro_precision_rule, report.macro_recall_rule
                    );
                    for r in &report.by_rule {
                        println!(
                            "  {:<24} precision {:.2} recall {:.2} (tp {} fp {} fn {}, n={}) → suggest {}",
                            r.rule_id,
                            r.precision,
                            r.recall,
                            r.true_positive,
                            r.false_positive,
                            r.false_negative,
                            r.calibration_support,
                            r.suggested_severity,
                        );
                    }
                }
            } else {
                println!(
                    "Finding-level: no lab attributions in dataset (category co-occurrence only)"
                );
            }
            println!("Written: {}", args.out.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_mixin_map(args: MixinMapArgs) -> ExitCode {
    let target = match detect_target_or_exit(&args.target) {
        Ok(target) => target,
        Err(code) => return code,
    };
    match intermed_mixin_intel::scan_target(&target) {
        Ok(scan) => {
            if args.graph_format == GraphExportFormat::Json {
                print_mixin_scan(&scan);
                return ExitCode::SUCCESS;
            }
            let payload = match args.graph_format {
                GraphExportFormat::GraphData => intermed_mixin_intel::graph_to_json(&scan),
                GraphExportFormat::Dot => intermed_mixin_intel::graph_to_dot(&scan),
                GraphExportFormat::Graphml => intermed_mixin_intel::graph_to_graphml(&scan),
                GraphExportFormat::Html => {
                    intermed_mixin_intel::graph_to_html(&scan, "InterMed Mixin Graph")
                }
                GraphExportFormat::Json => None,
            };
            let Some(text) = payload else {
                eprintln!("error: failed to serialize mixin graph");
                return ExitCode::from(2);
            };
            if let Some(path) = args.graph_out {
                if let Err(e) = write_atomic(&path, text.as_bytes()) {
                    eprintln!("error: write {}: {e}", path.display());
                    return ExitCode::from(2);
                }
                println!("wrote {} ({} bytes)", path.display(), text.len());
            } else {
                print!("{text}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(feature = "duckdb")]
fn print_history_diff_human(report: &intermed_duckdb::HistoryDiffReport) {
    println!("InterMed History — finding diff");
    if let Some(a) = &report.run_a {
        println!(
            "  A: {}  {}  errors={} warns={}",
            a.run_id, a.target_path, a.error_count, a.warn_count
        );
    }
    if let Some(b) = &report.run_b {
        println!(
            "  B: {}  {}  errors={} warns={}",
            b.run_id, b.target_path, b.error_count, b.warn_count
        );
    }
    let s = &report.summary;
    println!(
        "Summary: +{} added, -{} removed, ~{} severity, ~{} rule",
        s.added, s.removed, s.severity_changed, s.rule_changed
    );
    if report.deltas.is_empty() {
        println!("No finding changes between runs.");
        return;
    }
    println!("change\tcategory\tseverity\trule_id\tfinding_id\ttitle\taffected(a→b)");
    for row in &report.deltas {
        let kind = match row.change {
            intermed_duckdb::RunDeltaKind::Added => "added",
            intermed_duckdb::RunDeltaKind::Removed => "removed",
            intermed_duckdb::RunDeltaKind::SeverityChanged => "severity",
            intermed_duckdb::RunDeltaKind::RuleChanged => "rule",
            intermed_duckdb::RunDeltaKind::Unchanged => "unchanged",
        };
        let sev = match (&row.severity_a, &row.severity_b) {
            (Some(a), Some(b)) if a != b => format!("{a}→{b}"),
            _ => row.severity.clone(),
        };
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}→{}",
            kind,
            row.category,
            sev,
            row.rule_id,
            row.finding_id,
            row.title,
            row.affected_a,
            row.affected_b
        );
    }
}

fn run_history(args: HistoryArgs) -> ExitCode {
    if !duckdb_available() {
        eprintln!("error: `intermed history` requires building with --features duckdb");
        return ExitCode::from(2);
    }
    #[cfg(feature = "duckdb")]
    {
        match args.command {
            HistoryCommand::Diff(diff) => match intermed_duckdb::AnalyticsStore::open(&diff.db) {
                Ok(store) => match store.history_diff_report(&diff.run_a, &diff.run_b) {
                    Ok(report) => {
                        if diff.json {
                            #[derive(serde::Serialize)]
                            struct HistoryDiffJson<'a> {
                                schema: &'static str,
                                #[serde(flatten)]
                                report: &'a intermed_duckdb::HistoryDiffReport,
                            }
                            let payload = HistoryDiffJson {
                                schema: "intermed-history-diff-v1",
                                report: &report,
                            };
                            match serde_json::to_string_pretty(&payload) {
                                Ok(text) => println!("{text}"),
                                Err(e) => {
                                    eprintln!("error: history diff json failed: {e}");
                                    return ExitCode::from(2);
                                }
                            }
                        } else {
                            print_history_diff_human(&report);
                        }
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("error: history diff failed: {e}");
                        ExitCode::from(2)
                    }
                },
                Err(e) => {
                    eprintln!("error: could not open {}: {e}", diff.db.display());
                    ExitCode::from(2)
                }
            },
            HistoryCommand::Prune(prune) => {
                match intermed_duckdb::AnalyticsStore::open(&prune.db) {
                    Ok(store) => match store.history_prune(&prune.keep) {
                        Ok(removed) => {
                            println!("pruned {removed} run(s) older than keep={}", prune.keep);
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: history prune failed: {e}");
                            ExitCode::from(2)
                        }
                    },
                    Err(e) => {
                        eprintln!("error: could not open {}: {e}", prune.db.display());
                        ExitCode::from(2)
                    }
                }
            }
            HistoryCommand::Conflicts(conflicts) => {
                match intermed_duckdb::AnalyticsStore::open(&conflicts.db) {
                    Ok(store) => match store.history_conflicts(&conflicts.since) {
                        Ok(rows) => {
                            println!(
                                "InterMed History — recurring conflicts (since {})",
                                conflicts.since
                            );
                            println!("Database: {}", conflicts.db.display());
                            if rows.is_empty() {
                                println!("No recurring conflicts in window.");
                                return ExitCode::SUCCESS;
                            }
                            println!(
                                "finding_id\trule_id\tseverity\trun_count\ttargets\tfirst_seen\tlast_seen"
                            );
                            for row in rows {
                                println!(
                                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                                    row.finding_id,
                                    row.rule_id,
                                    row.severity,
                                    row.run_count,
                                    row.distinct_targets,
                                    row.first_seen,
                                    row.last_seen
                                );
                            }
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: history query failed: {e}");
                            ExitCode::from(2)
                        }
                    },
                    Err(e) => {
                        eprintln!("error: could not open {}: {e}", conflicts.db.display());
                        ExitCode::from(2)
                    }
                }
            }
            HistoryCommand::Patterns(patterns) => {
                match intermed_duckdb::AnalyticsStore::open(&patterns.db) {
                    Ok(store) => match store.risk_patterns(patterns.limit) {
                        Ok(rows) => {
                            println!("InterMed History — risk patterns (rule × category)");
                            println!("Database: {}", patterns.db.display());
                            if rows.is_empty() {
                                println!("No persisted findings yet.");
                                return ExitCode::SUCCESS;
                            }
                            println!(
                                "rule_id\tcategory\tseverity_rank\toccurrences\tdistinct_findings\trun_count\tfirst_seen\tlast_seen"
                            );
                            for row in rows {
                                println!(
                                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                                    row.rule_id,
                                    row.category,
                                    row.severity_rank,
                                    row.occurrences,
                                    row.distinct_findings,
                                    row.run_count,
                                    row.first_seen,
                                    row.last_seen
                                );
                            }
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: risk-patterns query failed: {e}");
                            ExitCode::from(2)
                        }
                    },
                    Err(e) => {
                        eprintln!("error: could not open {}: {e}", patterns.db.display());
                        ExitCode::from(2)
                    }
                }
            }
        }
    }
    #[cfg(not(feature = "duckdb"))]
    {
        let _ = args;
        ExitCode::from(2)
    }
}

fn run_trends(args: TrendsArgs) -> ExitCode {
    if !duckdb_available() {
        eprintln!("error: `intermed trends` requires building with --features duckdb");
        return ExitCode::from(2);
    }
    #[cfg(feature = "duckdb")]
    {
        match args.command {
            TrendsCommand::MixinRisk(trends) => {
                match intermed_duckdb::AnalyticsStore::open(&trends.db) {
                    Ok(store) => match store.trends_mixin_risk() {
                        Ok(rows) => {
                            println!("InterMed Trends — mixin-risk");
                            println!("Database: {}", trends.db.display());
                            println!("generated_at\ttarget_path\tmixin_findings");
                            for row in rows {
                                println!(
                                    "{}\t{}\t{}",
                                    row.generated_at, row.target_path, row.mixin_findings
                                );
                            }
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: trends query failed: {e}");
                            ExitCode::from(2)
                        }
                    },
                    Err(e) => {
                        eprintln!("error: could not open {}: {e}", trends.db.display());
                        ExitCode::from(2)
                    }
                }
            }
            TrendsCommand::MixinOverlaps(trends) => {
                match intermed_duckdb::AnalyticsStore::open(&trends.db) {
                    Ok(store) => match store.top_mixin_overlaps(trends.limit) {
                        Ok(rows) => {
                            println!("InterMed Trends — top mixin overlaps");
                            println!("Database: {}", trends.db.display());
                            println!("mods\ttarget\toccurrences\trun_count");
                            for row in rows {
                                println!(
                                    "{}\t{}\t{}\t{}",
                                    row.mods, row.target, row.occurrences, row.run_count
                                );
                            }
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: overlap query failed: {e}");
                            ExitCode::from(2)
                        }
                    },
                    Err(e) => {
                        eprintln!("error: could not open {}: {e}", trends.db.display());
                        ExitCode::from(2)
                    }
                }
            }
        }
    }
    #[cfg(not(feature = "duckdb"))]
    {
        let _ = args;
        ExitCode::from(2)
    }
}

fn run_rules(args: RulesArgs) -> ExitCode {
    match args.command {
        RulesCommand::Check(args) => run_rules_check(args),
        RulesCommand::Generate(args) => run_rules_generate(args),
        RulesCommand::Sign(args) => run_rules_sign(args),
        RulesCommand::Verify(args) => run_rules_verify(args),
        RulesCommand::Update(args) => run_rules_update(args),
        RulesCommand::Registry(args) => run_rules_registry(args),
        RulesCommand::Install(args) => run_rules_install(args),
        RulesCommand::Explain(args) => run_rules_explain(args),
    }
}

fn run_rules_generate(args: intermed_cli::command::RulesGenerateArgs) -> ExitCode {
    use intermed_cli::command::RulesGenerateBackend;

    let pack = match if args.pack.as_os_str().is_empty() || !args.pack.exists() {
        Ok(intermed_rules::default_core_pack_v2())
    } else if args.pack.is_file() {
        load_rule_pack(&args.pack)
    } else {
        Err(intermed_rules::RulePackError::new(format!(
            "pack not found: {}",
            args.pack.display()
        )))
    } {
        Ok(pack) => pack,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let backend = match args.backend {
        RulesGenerateBackend::Sql => GenerateBackend::Sql,
        RulesGenerateBackend::Rust => GenerateBackend::Rust,
        RulesGenerateBackend::Datalog => GenerateBackend::Datalog,
        RulesGenerateBackend::Explain => GenerateBackend::Explain,
    };
    let output = generate_rules(&pack, backend);

    if let Some(path) = args.out {
        if let Err(e) = std::fs::write(&path, &output) {
            eprintln!("error: write {}: {e}", path.display());
            return ExitCode::from(2);
        }
        println!("wrote {} ({} bytes)", path.display(), output.len());
    } else {
        print!("{output}");
    }
    ExitCode::SUCCESS
}

fn run_rules_explain(args: intermed_cli::command::RulesExplainArgs) -> ExitCode {
    let pack = match if args.pack.as_os_str().is_empty() || !args.pack.exists() {
        Ok(intermed_rules::default_core_pack_v2())
    } else if args.pack.is_file() {
        load_rule_pack(&args.pack)
    } else {
        Err(intermed_rules::RulePackError::new(format!(
            "pack not found: {}",
            args.pack.display()
        )))
    } {
        Ok(pack) => pack,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    // Optional fact dump enables EXPLAIN ANALYZE on real facts.
    let facts: Option<Vec<intermed_doctor_core::facts::Fact>> = match &args.facts {
        Some(path) => match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
        {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("error: read facts {}: {e}", path.display());
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let output = intermed_rules::explain_plans(&pack, args.rule.as_deref(), facts.as_deref());
    if output.trim().is_empty() {
        eprintln!(
            "no lowerable rule to explain{}",
            args.rule
                .as_deref()
                .map(|r| format!(" matching `{r}`"))
                .unwrap_or_default()
        );
        return ExitCode::from(1);
    }
    print!("{output}");
    ExitCode::SUCCESS
}

fn run_rules_check(args: intermed_cli::command::RulesCheckArgs) -> ExitCode {
    let check = check_rule_packs(&args.path);
    println!("InterMed Rules");
    println!("Path: {}", args.path.display());
    println!("Files: {}", check.files);
    println!("Rules: {}", check.rules);
    if !check.is_ok() {
        println!("Status: failed");
        for error in check.errors {
            println!("error: {error}");
        }
        return ExitCode::from(2);
    }
    if args.require_signature || args.trusted_keys.is_some() {
        let trusted = match &args.trusted_keys {
            Some(path) => match load_trusted_keys(path) {
                Ok(keys) => keys,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            },
            None => Vec::new(),
        };
        let mut files = Vec::new();
        if args.path.is_file() {
            files.push(args.path.clone());
        } else if let Ok(rd) = std::fs::read_dir(&args.path) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_file() {
                    files.push(p);
                }
            }
        }
        for file in files {
            if let Ok(pack) = load_rule_pack(&file) {
                if args.require_signature && pack.signature.is_none() {
                    eprintln!("error: {}: signature required but missing", file.display());
                    return ExitCode::from(2);
                }
                if pack.signature.is_some() {
                    if let Err(e) = verify_rule_pack_signature(&pack, &trusted) {
                        eprintln!("error: {}: {e}", file.display());
                        return ExitCode::from(2);
                    }
                }
            }
        }
    }
    if args.trace {
        let facts_path = match &args.facts {
            Some(p) => p,
            None => {
                eprintln!("error: --trace requires --facts FILE");
                return ExitCode::from(2);
            }
        };
        let text = match std::fs::read_to_string(facts_path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: read {}: {e}", facts_path.display());
                return ExitCode::from(2);
            }
        };
        let facts: Vec<Fact> = match serde_json::from_str(&text) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("error: parse facts json: {e}");
                return ExitCode::from(2);
            }
        };
        let store = intermed_doctor_core::facts::FactStore::from_snapshot(facts);
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = intermed_doctor_core::RuleCtx::for_test(&store, &target);
        let pack = match load_rule_pack(&args.path) {
            Ok(p) => p,
            Err(_) => default_core_pack_v2_from_path(&args.path),
        };
        let lines = trace_pack(&pack, &ctx);
        print!("{}", format_trace(&lines));
    }
    println!("Status: ok");
    ExitCode::SUCCESS
}

fn default_core_pack_v2_from_path(path: &Path) -> intermed_rules::RulePack {
    if path.is_file() {
        load_rule_pack(path).unwrap_or_else(|_| intermed_rules::default_core_pack_v2())
    } else {
        intermed_rules::default_core_pack_v2()
    }
}

fn run_rules_install(args: intermed_cli::command::RulesInstallArgs) -> ExitCode {
    let policy = intermed_rules::TrustPolicy {
        allow_insecure_registry: args.allow_insecure_registry,
        allow_unsigned_rules: args.allow_unsigned_rules,
    };
    let registry = match args.registry.as_deref() {
        Some(src) => match load_registry_from_source(src, &policy) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        None => merged_default_registry(),
    };
    let install_dir = match args
        .install_dir
        .or_else(|| default_rule_pack_install_dir().ok())
    {
        Some(d) => d,
        None => {
            eprintln!("error: could not resolve rule pack install directory");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = std::fs::create_dir_all(&install_dir) {
        eprintln!("error: create {}: {e}", install_dir.display());
        return ExitCode::from(2);
    }
    let trusted = match &args.trusted_keys {
        Some(path) => match load_trusted_keys(path) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        None => Vec::new(),
    };
    match install_pack_with_dependencies(&registry, &args.pack_id, &install_dir, &trusted, &policy)
    {
        Ok(paths) => {
            for path in paths {
                println!("installed {}", path.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_cache(args: CacheArgs) -> ExitCode {
    let cache_dir = match &args.command {
        CacheCommand::Stats(a) | CacheCommand::Prune(a) | CacheCommand::Clear(a) => {
            a.cache_dir.clone()
        }
    };
    let cache = match JarCache::new(true, cache_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cache init: {e}");
            return ExitCode::from(2);
        }
    };
    match args.command {
        CacheCommand::Stats(stats) => {
            let s = cache.stats_with_disk_usage();
            println!("InterMed Jar Cache");
            println!("root: {}", cache.root().display());
            println!("hits: {}", s.hits);
            println!("misses: {}", s.misses);
            println!("writes: {}", s.writes);
            println!("fast_hits: {}", s.fast_hits);
            println!("coalesced: {}", s.coalesced);
            println!("bytes_on_disk: {}", s.bytes_on_disk);
            let _ = stats;
            ExitCode::SUCCESS
        }
        CacheCommand::Prune(_) => match cache.prune_now() {
            Ok(freed) => {
                println!("pruned {freed} bytes");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: prune failed: {e}");
                ExitCode::from(2)
            }
        },
        CacheCommand::Clear(_) => match cache.clear_all() {
            Ok(freed) => {
                println!("cleared {freed} bytes");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: clear failed: {e}");
                ExitCode::from(2)
            }
        },
    }
}

fn run_demo(args: DemoArgs) -> ExitCode {
    match args.command {
        DemoCommand::Report(report_args) => {
            if !report_args.run_dir.is_dir() {
                eprintln!(
                    "error: demo run directory does not exist: {}",
                    report_args.run_dir.display()
                );
                return ExitCode::from(2);
            }
            let version = env!("CARGO_PKG_VERSION");
            let tool_version = format!("intermed {version}");
            match write_demo_artifacts(&report_args.run_dir, &report_args.out, &tool_version) {
                Ok((_report, artifacts)) => {
                    println!("wrote {}", artifacts.summary_md.display());
                    println!("wrote {}", artifacts.report_html.display());
                    println!("wrote {}", artifacts.report_json.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
    }
}

fn run_sbom(args: SbomArgs) -> ExitCode {
    match args.command {
        SbomCommand::Export(export) => {
            let mut target = match detect_target_or_exit(&export.target) {
                Ok(t) => t,
                Err(code) => return code,
            };
            if let Some(md) = export.mods_dir {
                target.mods_dir = Some(md);
            }
            let mods_dir = match cli_mods_dir(&target) {
                Some(d) => d,
                None => {
                    eprintln!("error: no mods directory found for SBOM export");
                    return ExitCode::from(2);
                }
            };
            let scan = match scan_mods_dir(&mods_dir) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let format = match export.format {
                SbomExportFormatCli::SpdxJson => SbomExportFormat::SpdxJson,
                SbomExportFormatCli::CycloneDxJson => SbomExportFormat::CycloneDxJson,
            };
            let text = match export_scan(&scan, format) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error: export failed: {e}");
                    return ExitCode::from(2);
                }
            };
            if let Some(path) = export.out {
                if let Err(e) = write_atomic(&path, text.as_bytes()) {
                    eprintln!("error: write {}: {e}", path.display());
                    return ExitCode::from(2);
                }
                println!("wrote {}", path.display());
            } else {
                print!("{text}");
            }
            ExitCode::SUCCESS
        }
    }
}

fn run_rules_sign(args: intermed_cli::command::RulesSignArgs) -> ExitCode {
    let pack = match load_rule_pack(&args.pack) {
        Ok(mut pack) => {
            if pack.schema != RULE_PACK_SCHEMA_V2 {
                pack.schema = RULE_PACK_SCHEMA_V2.to_string();
                if pack.version.is_empty() {
                    pack.version = env!("CARGO_PKG_VERSION").to_string();
                }
                if pack.publisher.is_none() {
                    pack.publisher = Some("intermed".to_string());
                }
            }
            pack
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = validate_rule_pack(&pack) {
        eprintln!("error: {e}");
        return ExitCode::from(2);
    }
    let key_bytes = match std::fs::read(&args.key) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("error: read {}: {e}", args.key.display());
            return ExitCode::from(2);
        }
    };
    let signing_key = match load_signing_key(&key_bytes) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let signature = match intermed_rules::sign_rule_pack_now(&pack, &signing_key) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let mut signed = pack;
    signed.signature = Some(signature);
    let out = args.out.as_ref().unwrap_or(&args.pack);
    let json = match serde_json::to_string_pretty(&signed) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("error: serialize signed pack: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = std::fs::write(out, json) {
        eprintln!("error: write {}: {e}", out.display());
        return ExitCode::from(2);
    }
    println!("Signed rule pack written to {}", out.display());
    ExitCode::SUCCESS
}

fn run_rules_verify(args: intermed_cli::command::RulesVerifyArgs) -> ExitCode {
    let pack = match load_rule_pack(&args.pack) {
        Ok(pack) => pack,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let trusted = match &args.trusted_keys {
        Some(path) => match load_trusted_keys(path) {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        None => Vec::new(),
    };
    match verify_rule_pack_signature(&pack, &trusted) {
        Ok(()) => {
            println!("Signature valid for pack `{}` v{}", pack.id, pack.version);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_rules_update(args: intermed_cli::command::RulesUpdateArgs) -> ExitCode {
    let policy = intermed_rules::TrustPolicy {
        allow_insecure_registry: args.allow_insecure_registry,
        allow_unsigned_rules: args.allow_unsigned_rules,
    };
    let registry = match &args.registry {
        Some(source) => match load_registry_from_source(source, &policy) {
            Ok(reg) => reg,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        None => merged_default_registry(),
    };
    if registry.schema != RULE_REGISTRY_SCHEMA {
        eprintln!("error: unsupported registry schema: {}", registry.schema);
        return ExitCode::from(2);
    }
    let install_dir = match args
        .install_dir
        .clone()
        .or_else(|| default_rule_pack_install_dir().ok())
    {
        Some(dir) => dir,
        None => {
            eprintln!("error: could not resolve rule-pack install directory");
            return ExitCode::from(2);
        }
    };
    let trusted = match &args.trusted_keys {
        Some(path) => match load_trusted_keys(path) {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        None => Vec::new(),
    };
    match install_pack_from_registry(&registry, &args.pack_id, &install_dir, &trusted, &policy) {
        Ok(path) => {
            println!(
                "Updated pack `{}` → {} (digest verified)",
                args.pack_id,
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_rules_registry(args: intermed_cli::command::RulesRegistryArgs) -> ExitCode {
    let policy = intermed_rules::TrustPolicy {
        allow_insecure_registry: args.allow_insecure_registry,
        allow_unsigned_rules: false,
    };
    let registry = match &args.registry {
        Some(source) => match load_registry_from_source(source, &policy) {
            Ok(reg) => reg,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        None => merged_default_registry(),
    };
    println!("{}", registry_to_json(&registry));
    ExitCode::SUCCESS
}

fn detect_target_or_exit(path: &Path) -> Result<Target, ExitCode> {
    if !path.exists() {
        eprintln!("error: target does not exist: {}", path.display());
        return Err(ExitCode::from(2));
    }
    Ok(detect_target(path))
}

fn cli_mods_dir(target: &Target) -> Option<PathBuf> {
    target.mods_dir()
}

fn print_vfs_scan(scan: &intermed_vfs::ResourceScan) {
    println!("InterMed VFS");
    println!("Target: {}", scan.target);
    println!("Resource writers: {}", scan.writes.len());
    println!("Collisions: {}", scan.collisions.len());
    println!("Scan failures: {}", scan.failures.len());
    let mut by_class: BTreeMap<&'static str, usize> = BTreeMap::new();
    for c in &scan.collisions {
        *by_class.entry(c.class.as_str()).or_default() += 1;
    }
    for (class, count) in by_class {
        println!("  {class}: {count}");
    }
}

fn print_vfs_explain(scan: &intermed_vfs::ResourceScan) {
    print_vfs_scan(scan);
    if scan.collisions.is_empty() {
        return;
    }
    println!();
    for c in &scan.collisions {
        println!("{} [{}]", c.path, c.class.as_str());
        println!("  writers: {}", c.writers.join(", "));
        println!("  archives: {}", c.archives.join(", "));
        println!("  reason: {}", c.reason);
    }
    if !scan.failures.is_empty() {
        println!();
        for failure in &scan.failures {
            println!("{} [scan-failure]", failure.archive);
            println!("  reason: {}", failure.reason);
        }
    }
}

fn print_spark_import(import: &intermed_spark_bridge::SparkImport) {
    println!("InterMed Spark Map");
    println!("Target: {}", import.target);
    println!("Reports: {}", import.reports.len());
    println!("Import failures: {}", import.failures.len());
    for (i, report) in import.reports.iter().enumerate() {
        println!();
        println!("Report #{i}");
        println!("  tick spikes: {}", report.tick_spikes_ms.len());
        println!("  gc pauses: {}", report.gc_pauses_ms.len());
        println!("  hot methods: {}", report.hot_methods.len());
        println!("  hot mods: {}", report.hot_mods.len());
        for hm in &report.hot_methods {
            println!("    {}.{} — {:.1}%", hm.class, hm.method, hm.percent);
        }
    }
    if !import.failures.is_empty() {
        println!();
        println!("Import failures:");
        for failure in &import.failures {
            println!("{}: {}", failure.path, failure.reason);
        }
    }
}

/// Suggested triage actions for one risk cluster, derived from its axes.
fn mixin_cluster_actions(r: &intermed_mixin_intel::MixinRiskAssessment) -> Vec<String> {
    let mut actions = Vec::new();
    if r.apply_failure > 0 {
        actions.push(
            "verify the target class/method exists in this version; run with --minecraft-jar for full apply verification".to_string(),
        );
    }
    if r.hot_path {
        actions
            .push("test with each conflicting mod disabled and compare Spark profiles".to_string());
    }
    if r.unresolved_points > 0 {
        actions.push("provide mappings/refmap so the injection points resolve".to_string());
    }
    if r.certainty < 60 {
        actions.push("low certainty — confirm the mixins actually apply before acting".to_string());
    }
    if actions.is_empty() {
        actions.push("inspect the exact injection sites for ordering conflicts".to_string());
    }
    actions
}

fn print_mixin_scan(scan: &intermed_mixin_intel::MixinScan) {
    println!("InterMed Mixin Map");
    println!("Target: {}", scan.target);
    println!("Configs: {}", scan.configs.len());
    println!("Mixin classes: {}", scan.classes.len());
    println!("Overlaps: {}", scan.overlaps.len());
    println!("Interactions: {}", scan.interactions.len());
    println!("Risk assessments: {}", scan.risk_assessments.len());
    println!("High-risk overwrites: {}", scan.high_risk_overwrites.len());
    println!("Apply failures: {}", scan.apply_failures.len());
    println!("Scan failures: {}", scan.failures.len());

    // Cluster-first: lead with the highest-risk targets (clusters), each with its
    // axes, top reasons, and suggested triage actions. Detailed per-injection
    // effect summaries live below, in the Overlaps expansion.
    if !scan.risk_assessments.is_empty() {
        let mut clusters: Vec<_> = scan.risk_assessments.iter().collect();
        clusters.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| a.subject.cmp(&b.subject))
        });
        println!();
        println!("Top Mixin Clusters:");
        for (i, r) in clusters.iter().enumerate() {
            println!(
                "{}. {} [{}]",
                i + 1,
                r.subject,
                if r.hot_path { "hot" } else { "normal" }
            );
            println!("   Mods: {}", r.mods.join(", "));
            println!(
                "   Risk: {} (certainty {}, apply-failure {}, semantic {}, blast {}, fragility {})",
                r.score,
                r.certainty,
                r.apply_failure,
                r.semantic_conflict,
                r.blast_radius,
                r.fragility
            );
            if r.unresolved_points > 0 {
                println!("   Unresolved points: {}", r.unresolved_points);
            }
            if !r.reasons.is_empty() {
                println!("   Main reasons:");
                for reason in r.reasons.iter().take(5) {
                    println!("   - {reason}");
                }
            }
            println!("   Actions:");
            for action in mixin_cluster_actions(r) {
                println!("   - {action}");
            }
        }
    }

    if !scan.overlaps.is_empty() {
        println!();
        println!("Overlaps:");
        for overlap in &scan.overlaps {
            println!(
                "{} [{}]",
                overlap.target,
                if overlap.hot_path { "hot" } else { "normal" }
            );
            println!("  mods: {}", overlap.mods.join(", "));
            println!("  classes: {}", overlap.classes.join(", "));
            println!(
                "  operations: {}",
                overlap
                    .operations
                    .iter()
                    .map(intermed_mixin_intel::MixinOperation::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("  method_conflict: {}", overlap.method_conflict);
            if !overlap.effect_summaries.is_empty() {
                for summary in &overlap.effect_summaries {
                    println!("  effect: {summary}");
                }
            }
        }
    }

    if !scan.mod_complexity.is_empty() {
        println!();
        println!("Mixin Complexity Score (per mod):");
        let mut mods: Vec<_> = scan.mod_complexity.iter().collect();
        mods.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.mod_id.cmp(&b.mod_id)));
        for mc in mods {
            println!(
                "{} — {}/100 ({} class(es), {} target(s), {} site(s))",
                mc.mod_id, mc.score, mc.class_count, mc.target_count, mc.total_injection_sites
            );
        }
    }

    if !scan.bloat.is_empty() {
        println!();
        println!("Mixin bloat (low-yield handlers):");
        let mut bloat: Vec<_> = scan.bloat.iter().collect();
        bloat.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.mod_id.cmp(&b.mod_id)));
        for bl in bloat {
            println!(
                "{} — {}/100 ({}/{} handler(s) inert, ~{} instr)",
                bl.mod_id, bl.score, bl.inert_handlers, bl.total_handlers, bl.inert_instructions
            );
        }
    }

    if !scan.interactions.is_empty() {
        println!();
        println!("Interactions:");
        for interaction in &scan.interactions {
            println!(
                "{} ↔ {} on {} ({})",
                interaction.mod_a, interaction.mod_b, interaction.target, interaction.detail
            );
        }
    }

    if !scan.conflict_edges.is_empty() {
        println!();
        println!("Conflict edges:");
        for edge in &scan.conflict_edges {
            println!(
                "{} — {} ({}) @ {}",
                edge.edge_type.as_str(),
                edge.source_mixin,
                edge.target_mixin,
                edge.target_class
            );
            if !edge.site.is_empty() {
                println!("  site: {}", edge.site);
            }
        }
    }

    if !scan.recommendations.is_empty() {
        println!();
        println!("Recommendations:");
        for rec in &scan.recommendations {
            println!(
                "{} — {} ({})",
                rec.recommendation.title, rec.target, rec.site_key
            );
            println!("  {}", rec.recommendation.description);
            if let Some(url) = &rec.recommendation.doc_url {
                println!("  Docs: {url}");
            }
            if let Some(example) = &rec.recommendation.example {
                println!("  Example:");
                for line in example.lines() {
                    println!("    {line}");
                }
            }
        }
    }

    if !scan.mixin_effects.is_empty() {
        println!();
        println!("Mixin effects:");
        for effect in &scan.mixin_effects {
            println!("{} — {}#{}", effect.mod_id, effect.target, effect.method);
            if !effect.site_key.is_empty() {
                println!("  site_key: {}", effect.site_key);
            }
            println!("  {}", effect.effect_description);
            if !effect.effect_kinds.is_empty() {
                println!(
                    "  kinds: {}",
                    effect
                        .effect_kinds
                        .iter()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }

    if !scan.high_risk_overwrites.is_empty() {
        println!();
        println!("High-risk overwrites:");
        for overwrite in &scan.high_risk_overwrites {
            println!("{} -> {}", overwrite.mod_id, overwrite.target);
            println!("  mixin: {}", overwrite.class_name);
            if !overwrite.site_key.is_empty() {
                println!("  site_key: {}", overwrite.site_key);
            }
            println!("  hot_path: {}", overwrite.hot_path);
            if !overwrite.effect_description.is_empty() {
                println!("  effect: {}", overwrite.effect_description);
            }
        }
    }

    if !scan.failures.is_empty() {
        println!();
        println!("Scan failures:");
        for failure in &scan.failures {
            println!("{}", failure.archive);
            if let Some(path) = &failure.path {
                println!("  path: {path}");
            }
            println!("  reason: {}", failure.reason);
        }
    }
}

#[cfg(test)]
mod explain_tests {
    use super::*;
    use intermed_doctor_core::evidence::{Finding, Severity};

    fn finding(id: &str, sev: Severity) -> Finding {
        Finding::builder("rule", id)
            .severity(sev)
            .title("t")
            .build()
    }

    fn sample() -> Vec<Finding> {
        vec![
            finding("duplicate-id:minecraft:copper", Severity::Error),
            finding("missing-dependency:create->fabric-api", Severity::Warn),
            finding("resource-conflict:assets/foo.json", Severity::Note),
        ]
    }

    #[test]
    fn exact_id_matches() {
        let f = sample();
        assert!(matches!(
            resolve_explain_target(&f, "duplicate-id:minecraft:copper"),
            ExplainResolution::Exact(_)
        ));
    }

    #[test]
    fn case_insensitive_exact_auto_resolves() {
        let f = sample();
        match resolve_explain_target(&f, "DUPLICATE-ID:MINECRAFT:COPPER") {
            ExplainResolution::Fuzzy(found) => {
                assert_eq!(found.id, "duplicate-id:minecraft:copper")
            }
            _ => panic!("expected fuzzy auto-resolve"),
        }
    }

    #[test]
    fn unique_substring_auto_resolves() {
        let f = sample();
        match resolve_explain_target(&f, "copper") {
            ExplainResolution::Fuzzy(found) => {
                assert_eq!(found.id, "duplicate-id:minecraft:copper")
            }
            _ => panic!("expected fuzzy auto-resolve from substring"),
        }
    }

    #[test]
    fn ambiguous_substring_suggests() {
        let f = sample();
        // "id" appears in two ids (duplicate-id, missing-dependency has no "id"...).
        match resolve_explain_target(&f, "duplicate") {
            // only one contains "duplicate" → resolves
            ExplainResolution::Fuzzy(_) => {}
            other => panic!("unexpected {}", matches_name(&other)),
        }
        match resolve_explain_target(&f, ":") {
            ExplainResolution::Suggestions(s) => assert!(s.len() > 1),
            other => panic!("expected suggestions, got {}", matches_name(&other)),
        }
    }

    #[test]
    fn typo_suggests_closest() {
        let f = sample();
        match resolve_explain_target(&f, "duplcate-id:minecraft:coper") {
            ExplainResolution::Suggestions(s) => {
                assert_eq!(s[0].id, "duplicate-id:minecraft:copper");
            }
            other => panic!("expected suggestions, got {}", matches_name(&other)),
        }
    }

    #[test]
    fn no_match_lists_by_severity() {
        let f = sample();
        match resolve_explain_target(&f, "zzzzzzzzzzzzzz-nothing-like-this") {
            ExplainResolution::Listing(l) => {
                assert_eq!(l[0].severity, Severity::Error); // most severe first
            }
            other => panic!("expected listing, got {}", matches_name(&other)),
        }
    }

    #[test]
    fn empty_report_lists_nothing() {
        match resolve_explain_target(&[], "anything") {
            ExplainResolution::Listing(l) => assert!(l.is_empty()),
            _ => panic!("expected empty listing"),
        }
    }

    fn matches_name(r: &ExplainResolution<'_>) -> &'static str {
        match r {
            ExplainResolution::Exact(_) => "Exact",
            ExplainResolution::Fuzzy(_) => "Fuzzy",
            ExplainResolution::Suggestions(_) => "Suggestions",
            ExplainResolution::Listing(_) => "Listing",
        }
    }
}
