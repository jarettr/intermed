use crate::*;

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn digest_serialized(value: &impl serde::Serialize) -> Option<String> {
    serde_json::to_vec(value)
        .ok()
        .map(|bytes| digest_bytes(&bytes))
}

fn digest_file(path: &Path) -> Option<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Some(format!("{:x}", digest.finalize()))
}

fn target_manifest_path(args: &DoctorArgs, target: &Target) -> Option<PathBuf> {
    if let Some(path) = &args.pack_manifest {
        return Some(path.clone());
    }
    if target.kind == TargetKind::ModpackArchive {
        return Some(target.path.clone());
    }
    let roots = [target.game_root.as_ref(), Some(&target.path)];
    for root in roots.into_iter().flatten() {
        for name in ["modrinth.index.json", "manifest.json", "instance.cfg"] {
            let candidate = root.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn populate_analyzer_fingerprint(
    report: &mut intermed_doctor_core::DoctorReport,
    config: &IntermedConfig,
    args: &DoctorArgs,
    target: &Target,
    rule_pack_sha256: Option<String>,
) {
    let mut features = Vec::new();
    if cfg!(feature = "duckdb") {
        features.push("duckdb".to_string());
    }
    if cfg!(feature = "dhat-heap") {
        features.push("dhat-heap".to_string());
    }
    if features.is_empty() {
        features.push("default".to_string());
    }
    let target_manifest = target_manifest_path(args, target);
    let target_manifest_sha256 = target_manifest.as_deref().and_then(digest_file);
    let cache_mode = if args.cache.no_cache {
        "disabled"
    } else if args.cache.cache_remote_dir.is_some() {
        "local+remote"
    } else {
        "local"
    };
    let effective_config_sha256 = config.to_toml().ok().map(|mut text| {
        use std::fmt::Write as _;
        // Options that intentionally live outside the reusable TOML schema are
        // still analysis inputs and therefore belong in the invocation digest.
        let _ = write!(
            text,
            "\n[effective_invocation]\nlogic={:?}\nno_cache={}\nchanged_since={:?}\npack_manifest={:?}\nminecraft_jar={:?}\nminecraft_mappings={:?}\n",
            args.logic,
            args.cache.no_cache,
            args.cache.changed_since,
            args.pack_manifest,
            args.tuning.minecraft_jar,
            args.tuning.minecraft_mappings,
        );
        digest_bytes(text.as_bytes())
    });
    report.analysis_configuration.fingerprint = intermed_doctor_core::report::AnalyzerFingerprint {
        executable_sha256: digest_current_executable(),
        git_commit: option_env!("INTERMED_GIT_COMMIT").map(str::to_string),
        git_dirty: option_env!("INTERMED_GIT_DIRTY").and_then(|v| v.parse().ok()),
        cargo_features: features,
        effective_config_sha256,
        rule_pack_sha256,
        minecraft_jar_sha256: report.mixin_coverage.minecraft_jar_sha256.clone(),
        mappings_sha256: report.mixin_coverage.mappings_sha256.clone(),
        target_manifest_sha256: target_manifest_sha256.clone(),
        cache_mode: cache_mode.to_string(),
    };
    if let (Some(path), Some(sha256)) = (target_manifest, target_manifest_sha256) {
        report.analysis_configuration.input_manifest.push(
            intermed_doctor_core::report::InputFingerprint {
                kind: "target-manifest".to_string(),
                path: path.display().to_string(),
                sha256,
            },
        );
    }
}

fn digest_current_executable() -> Option<String> {
    if let Ok(path) = std::env::current_exe()
        && let Some(digest) = digest_file(&path)
    {
        return Some(digest);
    }
    #[cfg(target_os = "linux")]
    {
        digest_file(Path::new("/proc/self/exe"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Process exit code for a completed run.
///
/// Normally follows the linter convention (`report.exit_code()`: 0 healthy,
/// 1 warnings, 2 errors). When `--exit-zero` is set, findings no longer affect
/// the exit code — only genuine operational failures (handled by earlier
/// `ExitCode::from(2)` returns) produce a non-zero status.
pub(crate) fn findings_exit_code(
    report: &intermed_doctor_core::report::DoctorReport,
    exit_zero: bool,
) -> ExitCode {
    if !report.operational_errors.is_empty() {
        ExitCode::from(2)
    } else if exit_zero {
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
        .with_context(|| format!("could not write {label} report to {}", path.display()))?;
    info!("wrote {label} report to {}", path.display());
    Ok(())
}

pub(crate) fn run_doctor(args: Box<DoctorArgs>, config_path: Option<&Path>) -> ExitCode {
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
    let telemetry_options = TelemetryOptions {
        out: args.output.telemetry_out.as_deref(),
        endpoint: args.output.telemetry_endpoint.as_deref(),
        include_log_excerpts: args.output.telemetry_include_log_excerpts,
    };
    telemetry::validate(telemetry_options)?;
    if !args.target.exists() {
        anyhow::bail!("target does not exist: {}", args.target.display());
    }
    if let Some(path) = &args.pack_manifest
        && !path.is_file()
    {
        anyhow::bail!(
            "pack manifest does not exist or is not a file: {}",
            path.display()
        );
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
    let mixin_enabled = cfg.mixin.enabled;

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
    if performance {
        perf_thresholds
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid performance thresholds: {error}"))?;
    }
    let changed_since = if let Some(ref since) = args.cache.changed_since {
        Some(
            parse_changed_since(since)
                .map_err(|e| anyhow::anyhow!("invalid --changed-since value: {e}"))?,
        )
    } else {
        None
    };
    let settings = diagnosis_settings_from_config(
        &cfg,
        &args.tuning,
        changed_since,
        args.pack_manifest.as_deref(),
    );
    let rule_pack_selection = rule_pack_selection_from(&cfg, &args);
    // `without_mixin`: when Layer-F mixin-risk runs (any logic mode), drop the
    // lighter declarative mixin rules from the pack so the two don't double-report.
    let resolved_rules = resolve_doctor_packs(mixin_enabled, &rule_pack_selection)
        .context("rule pack resolution failed")?;
    let rule_pack_sha256 = digest_serialized(&resolved_rules.pack);
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
        mixin_enabled,
        performance,
        perf_thresholds,
        settings,
        jar_cache,
        resolved_rules.pack,
    )?;
    let mut run = engine.diagnose_with_facts(&target);
    populate_analyzer_fingerprint(&mut run.report, &cfg, &args, &target, rule_pack_sha256);
    detail!(
        "scan: {} fact(s), {} finding(s) across {} collector(s)",
        run.facts.len(),
        run.report.findings.len(),
        run.report.collectors.len()
    );

    telemetry::deliver(&run, telemetry_options)?;
    if let Some(path) = &args.output.telemetry_out {
        info!(
            "wrote privacy-filtered telemetry event to {}",
            path.display()
        );
    }

    if let Some(path) = &args.output.profile {
        persistence::write_profile(path, &run.profile)
            .map_err(|e| anyhow::anyhow!("could not write profile to {}: {e}", path.display()))?;
    }

    if let Some(path) = &args.provenance.dump_facts {
        persistence::write_facts(path, &run.facts)
            .map_err(|e| anyhow::anyhow!("could not write facts to {}: {e}", path.display()))?;
    }

    if let Some(path) = &args.db
        && let Err(e) = persistence::persist_duckdb_run(path, &run)
    {
        eprintln!("error: {e:#}");
        if !args.db_best_effort {
            return Ok(ExitCode::from(2));
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
        info!("wrote HTML report to {}", path.display());
    }

    let mut wrote_artifact = args.output.html.is_some();
    let mut wrote_stdout = false;

    if let Some(target) = &args.output.json {
        wrote_artifact = true;
        let schema = match args.output.report_schema {
            intermed_cli::command::ReportSchemaArg::V1 => ReportSchema::V1,
            intermed_cli::command::ReportSchemaArg::V2 => ReportSchema::V2,
        };
        let json = intermed_report::render_json_schema(&run.report, schema);
        match target {
            Some(path) => {
                write_atomic(path, json.as_bytes()).with_context(|| {
                    format!("could not write JSON report to {}", path.display())
                })?;
                info!("wrote JSON report to {}", path.display());
            }
            None => {
                println!("{json}");
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

pub(crate) fn apply_doctor_cli_overrides(cfg: &mut IntermedConfig, args: &DoctorArgs) {
    // Mutate the serializable configuration itself so `--dump-config` is a true
    // effective-config view, not a view of the pre-CLI baseline. Consumers that
    // also receive the original args apply the same values idempotently.
    if let Some(mib) = args.cache.cache_max_mib {
        cfg.cache.max_size_mib = mib;
    }
    if let Some(days) = args.cache.cache_max_age_days {
        cfg.cache.max_age_days = days;
    }
    if args.performance.performance {
        cfg.performance.enabled = true;
    }
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
            intermed_cli::command::MetadataLevelArg::Basic => {
                intermed_config::MetadataLevelConfig::Basic
            }
            intermed_cli::command::MetadataLevelArg::Enriched => {
                intermed_config::MetadataLevelConfig::Enriched
            }
            intermed_cli::command::MetadataLevelArg::Full => {
                intermed_config::MetadataLevelConfig::Full
            }
        };
    }
    if let Some(level) = args.tuning.resource_level {
        cfg.resource.level = match level {
            intermed_cli::command::ResourceLevelArg::Basic => {
                intermed_config::ResourceLevelConfig::Basic
            }
            intermed_cli::command::ResourceLevelArg::Semantic => {
                intermed_config::ResourceLevelConfig::Semantic
            }
            intermed_cli::command::ResourceLevelArg::Full => {
                intermed_config::ResourceLevelConfig::Full
            }
        };
    }
    if let Some(jobs) = args.jobs {
        cfg.runtime.jobs = jobs;
    }
    if let Some(level) = args.mixin.level {
        cfg.mixin.enabled = true;
        cfg.mixin.level = match level {
            intermed_cli::command::MixinLevelArg::Basic => intermed_config::MixinLevelConfig::Basic,
            intermed_cli::command::MixinLevelArg::Standard => {
                intermed_config::MixinLevelConfig::Standard
            }
            intermed_cli::command::MixinLevelArg::Full => intermed_config::MixinLevelConfig::Full,
        };
    }
    if args.mixin_risk {
        cfg.mixin.enabled = true;
        if args.mixin.level.is_none() {
            cfg.mixin.level = intermed_config::MixinLevelConfig::Standard;
        }
    }
    if args.mixin.no_mixin_handler_effects {
        cfg.mixin.handler_effects = Some(false);
    } else if args.mixin.mixin_handler_effects {
        cfg.mixin.enabled = true;
        cfg.mixin.handler_effects = Some(true);
    }
    if args.mixin.no_mixin_recommendations {
        cfg.mixin.recommendations = Some(false);
    } else if args.mixin.mixin_recommendations {
        cfg.mixin.enabled = true;
        cfg.mixin.recommendations = Some(true);
    }
    if args.tuning.minecraft_jar.is_some() || args.tuning.minecraft_mappings.is_some() {
        cfg.mixin.enabled = true;
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
    pack_manifest: Option<&std::path::Path>,
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
    settings.pack_manifest = pack_manifest.map(std::path::Path::to_path_buf);
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

/// Remove declarative rules whose semantic family is handled by a richer
/// imperative fallback for this backend. Columnar evaluates the whole resolved
/// pack (including its residual interpreter), so merely registering the
/// fallback without filtering would execute these families twice.
fn remove_imperative_fallback_duplicates(
    pack: &mut intermed_rules::RulePack,
    plan: &RuleBackendPlan,
) {
    pack.rules.retain(|rule| {
        let imperative_provenance_duplicate = !plan.declarative_sbom_provenance
            && matches!(rule.id.as_str(), "unknown-source" | "unsigned-jar");
        let imperative_correlation_duplicate =
            !plan.declarative_sbom_correlation && rule.id == "sbom-security-correlation";
        !(imperative_provenance_duplicate || imperative_correlation_duplicate)
    });
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
    mut pack: intermed_rules::RulePack,
) -> AnyhowResult<DiagnosticEngine> {
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
    remove_imperative_fallback_duplicates(&mut pack, &plan);

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

    builder = builder.collector(GatedCollector::new(
        intermed_mixin_intel::collector(),
        mixin_risk,
        "disabled by effective configuration; use --mixin-level basic|standard|full",
    )); // Layer F
    builder = builder.collector(GatedCollector::new(
        intermed_spark_bridge::collector(),
        performance,
        "disabled by effective configuration; use --performance",
    )); // Layer I
    if performance {
        builder = builder.rule(intermed_spark_bridge::rule_with_thresholds(perf_thresholds));
    }

    // Every Layer-J backend evaluates the *resolved* pack (honoring the effective Mixin
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

    builder
        .build_checked()
        .context("invalid collector/rule registration graph")
}

pub(crate) enum ExplainResolution<'a> {
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
pub(crate) fn resolve_explain_target<'a>(
    findings: &'a [Finding],
    query: &str,
) -> ExplainResolution<'a> {
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
    println!("semantic id: {}", finding.semantic_id);
    if let Some(occurrence) = &finding.occurrence_id {
        println!("occurrence id: {occurrence}");
    }
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
    if !finding.evidence_path.is_empty() {
        println!();
        println!("Cross-layer evidence path:");
        for link in &finding.evidence_path {
            println!(
                "- {:?} --{:?}/{:?}--> {:?} (fact {})",
                link.from, link.relation, link.strength, link.to, link.source_fact
            );
        }
    }
    if !finding.recommendation_ids.is_empty() {
        println!();
        println!("Shared recommendations:");
        for id in &finding.recommendation_ids {
            println!("- {id}");
        }
    }
}

#[cfg(test)]
mod rule_backend_plan_tests {
    use super::*;

    #[test]
    fn columnar_keeps_rich_imperative_rule_families() {
        let plan = rule_backend_plan(LogicMode::Columnar);
        assert!(!plan.declarative_log);
        assert!(!plan.declarative_security);
        assert!(!plan.declarative_sbom_provenance);
        assert!(!plan.declarative_sbom_correlation);
    }

    #[test]
    fn columnar_pack_drops_only_imperative_sbom_duplicates() {
        let plan = rule_backend_plan(LogicMode::Columnar);
        let mut pack = intermed_rules::default_core_pack_v3();
        remove_imperative_fallback_duplicates(&mut pack, &plan);
        let ids = pack
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!ids.contains("unknown-source"));
        assert!(!ids.contains("unsigned-jar"));
        assert!(!ids.contains("sbom-security-correlation"));
        assert!(ids.contains("duplicate-id"));
    }
}
