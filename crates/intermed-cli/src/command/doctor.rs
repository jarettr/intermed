use super::*;

#[derive(Args)]
#[command(after_help = "Examples:\n  \
intermed doctor ./mods\n  \
intermed doctor ./server --mixin-risk --json\n  \
intermed doctor ./mods --dump-facts facts.json --explain duplicate-id:foo\n  \
intermed doctor ./mods --logic=souffle\n  \
intermed doctor ./mods --profile profile.json --no-cache")]
pub struct DoctorArgs {
    /// What to diagnose. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Override the mods directory (otherwise auto-detected).
    #[arg(long = "mods-dir")]
    pub mods_dir: Option<PathBuf>,

    /// Authoritative original pack manifest or archive. Use this when analyzing
    /// a materialized instance whose `modrinth.index.json`/`manifest.json` was
    /// not retained by the launcher or extraction pipeline.
    #[arg(long = "pack-manifest", value_name = "FILE")]
    pub pack_manifest: Option<PathBuf>,

    /// Compatibility shorthand for `--mixin-level standard`.
    #[arg(long = "mixin-risk")]
    pub mixin_risk: bool,

    /// Rule backend. The in-process columnar query engine is the default and only
    /// in-process engine; `souffle`/`duckdb` are optional external backends over the
    /// same IR (require their tool / build feature).
    #[arg(long, value_enum, default_value_t = LogicMode::Columnar)]
    pub logic: LogicMode,

    /// Cap the worker thread count for parallel jar/log scanning. Unset or `0`
    /// uses all available cores; lower it on weak machines or shared CI runners.
    #[arg(long = "jobs", visible_alias = "threads", value_name = "N")]
    pub jobs: Option<usize>,

    #[command(flatten)]
    pub output: DoctorOutputArgs,

    #[command(flatten)]
    pub cache: DoctorCacheArgs,

    #[command(flatten)]
    pub provenance: DoctorProvenanceArgs,

    #[command(flatten)]
    pub performance: DoctorPerformanceArgs,

    #[command(flatten)]
    pub tuning: DoctorTuningArgs,

    #[command(flatten)]
    pub mixin: DoctorMixinArgs,

    /// Persist this run to a DuckDB analytics file (requires `--features duckdb`).
    #[arg(long = "db", value_name = "FILE")]
    pub db: Option<PathBuf>,

    /// Treat `--db` persistence failure as a warning instead of an error exit.
    /// By default a requested `--db` write that fails returns a non-zero exit so
    /// automation notices the result was not saved.
    #[arg(long = "db-best-effort")]
    pub db_best_effort: bool,

    /// Extra declarative rule packs: file path or installed pack id (repeatable).
    #[arg(long = "rule-pack", value_name = "PATH|ID")]
    pub rule_packs: Vec<String>,

    /// Rule pack install directory (default: XDG `.../intermed/rule-packs`).
    #[arg(long = "rule-pack-dir", value_name = "DIR")]
    pub rule_pack_dir: Option<PathBuf>,

    /// Use only the embedded core rule pack (ignore installed/community overlays).
    #[arg(long = "core-rule-pack-only")]
    pub core_rule_pack_only: bool,

    /// Trusted publisher keys file for verifying signed rule pack overlays.
    #[arg(long = "rule-pack-trusted-keys", value_name = "FILE")]
    pub rule_pack_trusted_keys: Option<PathBuf>,

    /// Registry index path or URL for resolving `--rule-pack` ids.
    #[arg(long = "rule-pack-registry", value_name = "FILE|URL")]
    pub rule_pack_registry: Option<String>,

    /// Allow `http://` rule-pack registries/packs (insecure; HTTPS is required by default).
    #[arg(long = "allow-insecure-registry")]
    pub allow_insecure_registry: bool,

    /// Accept unsigned, or signed-but-unpinned, remote rule packs.
    #[arg(long = "allow-unsigned-rules")]
    pub allow_unsigned_rules: bool,
}

/// Report rendering and profiling output.
#[derive(Args, Default)]
pub struct DoctorOutputArgs {
    /// Emit the full report as canonical `intermed-doctor-report-v2` JSON.
    ///
    /// With no value, writes to stdout. With `FILE`, writes that artifact and can
    /// be combined with `--sarif FILE` / `--html FILE` in one scan.
    #[arg(long, value_name = "FILE", num_args = 0..=1)]
    pub json: Option<Option<PathBuf>>,

    /// JSON report schema. `v1` is a temporary lossy compatibility writer
    /// retained temporarily during alpha; v2 is canonical.
    #[arg(long = "report-schema", value_enum, default_value_t = ReportSchemaArg::V2)]
    pub report_schema: ReportSchemaArg,

    /// Emit SARIF 2.1.0 (for IDE / CI code-scanning).
    ///
    /// With no value, writes to stdout. With `FILE`, writes that artifact and can
    /// be combined with `--json FILE` / `--html FILE` in one scan.
    #[arg(long, value_name = "FILE", num_args = 0..=1)]
    pub sarif: Option<Option<PathBuf>>,

    /// Write a self-contained HTML report (`index.html` style).
    #[arg(long, value_name = "FILE")]
    pub html: Option<PathBuf>,

    /// Disable ANSI colour even on a TTY.
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Write wall-clock phase profile JSON (`intermed-doctor-profile-v1`).
    #[arg(long = "profile", value_name = "FILE")]
    pub profile: Option<PathBuf>,

    /// Explicitly export a privacy-filtered telemetry event to FILE.
    /// Nothing is collected or written unless this option or
    /// `--telemetry-endpoint` is supplied.
    #[arg(long = "telemetry-out", value_name = "FILE")]
    pub telemetry_out: Option<PathBuf>,

    /// Explicitly send a privacy-filtered telemetry event to an HTTPS endpoint.
    /// No built-in service is contacted; the destination must be supplied here.
    #[arg(long = "telemetry-endpoint", value_name = "HTTPS_URL")]
    pub telemetry_endpoint: Option<String>,

    /// Include up to 20 redacted, truncated log-signal excerpts in explicitly
    /// requested telemetry. Requires `--telemetry-out` or `--telemetry-endpoint`.
    #[arg(long = "telemetry-include-log-excerpts")]
    pub telemetry_include_log_excerpts: bool,

    /// Exit 0 whenever the run completes, regardless of findings.
    ///
    /// By default the process exit code follows the linter convention
    /// (0 = healthy, 1 = warnings, 2 = errors), which makes CI gating work but
    /// also reports `[FAIL]` when you only wanted the side-effect of writing a
    /// `--json` / `--sarif` / `--html` / `--profile` artifact. With this flag,
    /// findings no longer influence the exit code; a non-zero exit then means a
    /// genuine operational failure (bad target, unwritable output, etc.).
    #[arg(long = "exit-zero")]
    pub exit_zero: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ReportSchemaArg {
    V1,
    #[default]
    V2,
}

/// Jar scan cache controls.
#[derive(Args, Default)]
pub struct DoctorCacheArgs {
    /// Disable the on-disk jar scan cache (default: cache enabled at XDG path).
    #[arg(long = "no-cache")]
    pub no_cache: bool,

    /// Override jar cache root (default: $XDG_CACHE_HOME/intermed or ~/.cache/intermed).
    #[arg(long = "cache-dir", value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Shared/remote cache tier directory (Tier 3). A scan payload written by one
    /// machine is reused by any other pointed at the same directory (e.g. a network
    /// mount or CI cache). The reference `LocalDirRemoteTier`; real S3/HTTP tiers
    /// implement the same `RemoteCacheTier` trait.
    #[arg(long = "cache-remote-dir", value_name = "DIR")]
    pub cache_remote_dir: Option<PathBuf>,

    /// Soft cap on jar cache size in MiB; oldest entries are pruned first
    /// (default: 512). Useful on space-constrained or CI machines.
    #[arg(long = "cache-max-size", value_name = "MIB")]
    pub cache_max_mib: Option<u64>,

    /// Maximum age of jar cache entries in days before automatic pruning
    /// (default: 180).
    #[arg(long = "cache-max-age-days", value_name = "DAYS")]
    pub cache_max_age_days: Option<u64>,

    /// Incremental scan: only jars modified at or after this time (RFC3339 or unix seconds).
    #[arg(long = "changed-since", value_name = "TIME")]
    pub changed_since: Option<String>,
}

/// Layer-I performance / Spark import controls.
#[derive(Args, Default)]
pub struct DoctorPerformanceArgs {
    /// Enable Layer-I Spark report import during doctor.
    #[arg(long = "performance")]
    pub performance: bool,

    /// Explicit spark report JSON (`intermed-spark-report-v1`).
    #[arg(long = "spark-report", value_name = "FILE")]
    pub spark_report: Option<PathBuf>,

    /// Minimum tick spike duration in ms to report (default: 50).
    #[arg(long = "perf-tick-spike-ms", value_name = "MS")]
    pub tick_spike_ms: Option<i64>,

    /// CPU percent at or above which hot methods/mods are treated as severe
    /// (default: 50.0).
    #[arg(long = "perf-high-cpu-percent", value_name = "PCT")]
    pub high_cpu_percent: Option<f64>,

    /// Minimum CPU percent for hot-method ↔ mixin correlation (default: 5.0).
    #[arg(long = "perf-hot-method-floor", value_name = "PCT")]
    pub hot_method_floor_percent: Option<f64>,

    /// Tick spike severity bump threshold in ms (default: 100).
    #[arg(long = "perf-tick-spike-warn-ms", value_name = "MS")]
    pub tick_spike_warn_ms: Option<i64>,
}

/// Layer-F mixin scan depth controls (see `[mixin]` in config and `INTERMED_MIXIN_*` env).
#[derive(Args, Default)]
pub struct DoctorMixinArgs {
    /// Mixin analysis preset: `basic` (overlaps/risk only), `standard` (+ recommendations),
    /// `full` (+ per-handler intelligence findings).
    #[arg(long = "mixin-level", value_enum, value_name = "LEVEL")]
    pub level: Option<MixinLevelArg>,

    /// Skip per-handler bytecode intelligence facts and findings.
    #[arg(
        long = "no-mixin-handler-effects",
        conflicts_with = "mixin_handler_effects"
    )]
    pub no_mixin_handler_effects: bool,

    /// Force per-handler bytecode intelligence on (overrides preset).
    #[arg(
        long = "mixin-handler-effects",
        conflicts_with = "no_mixin_handler_effects"
    )]
    pub mixin_handler_effects: bool,

    /// Skip safer-mixin recommendation facts and fix candidates.
    #[arg(
        long = "no-mixin-recommendations",
        conflicts_with = "mixin_recommendations"
    )]
    pub no_mixin_recommendations: bool,

    /// Force safer-mixin recommendations on (overrides preset).
    #[arg(
        long = "mixin-recommendations",
        conflicts_with = "no_mixin_recommendations"
    )]
    pub mixin_recommendations: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MixinLevelArg {
    #[value(alias = "normal")]
    Basic,
    #[value(alias = "detailed")]
    Standard,
    Full,
}

/// Layer thresholds overridable from CLI (see also `INTERMED_*` env and config file).
#[derive(Args, Default)]
pub struct DoctorTuningArgs {
    /// Metadata analysis preset: `basic`, `enriched`, or `full`.
    #[arg(long = "metadata-level", value_enum, value_name = "LEVEL")]
    pub metadata_level: Option<MetadataLevelArg>,

    /// Resource/data-semantics (Layer M) AST depth: `basic` (off), `semantic`, or `full`.
    #[arg(long = "resource-level", value_enum, value_name = "LEVEL")]
    pub resource_level: Option<ResourceLevelArg>,

    /// Note-level security signals required before emitting a grouped finding (default: 2).
    #[arg(long = "security-min-note-signals", value_name = "N")]
    pub security_min_note_signals: Option<usize>,

    /// Legacy threshold for SBOM facts without typed provenance axes (default: 60).
    #[arg(long = "sbom-well-identified-trust", value_name = "SCORE")]
    pub sbom_well_identified_trust: Option<i64>,

    /// Log line count above which scanning uses parallel workers (default: 4096).
    #[arg(long = "log-parallel-line-threshold", value_name = "N")]
    pub log_parallel_line_threshold: Option<usize>,

    /// Confidence for reflection-corroborated security facts (default: 0.4).
    #[arg(long = "security-corroborated-confidence", value_name = "SCORE")]
    pub security_corroborated_confidence: Option<f32>,

    /// Minecraft client/server jar to index. Powers two layers: mixin
    /// apply-failure verification against vanilla classes (Layer F), and a vanilla
    /// resource index (Layer M) so `minecraft:` references resolve and tags expand
    /// against real vanilla data instead of being assumed present.
    #[arg(long = "minecraft-jar", value_name = "JAR")]
    pub minecraft_jar: Option<PathBuf>,

    /// Yarn/Mojmap Tiny v2 mappings (`mappings.tiny`) for named↔intermediary
    /// bridging during mixin apply-failure checks with `--minecraft-jar`.
    #[arg(long = "minecraft-mappings", value_name = "FILE")]
    pub minecraft_mappings: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MetadataLevelArg {
    Basic,
    Enriched,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ResourceLevelArg {
    Basic,
    Semantic,
    Full,
}

/// Provenance affordances for debugging findings.
#[derive(Args, Default)]
pub struct DoctorProvenanceArgs {
    /// Write the raw Phase-2 fact snapshot to a JSON file.
    #[arg(long = "dump-facts", value_name = "FILE")]
    pub dump_facts: Option<PathBuf>,

    /// Explain one finding id with its supporting facts.
    #[arg(long, value_name = "FINDING_ID")]
    pub explain: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogicMode {
    /// In-process columnar query engine (`intermed-columnar`): the default and only
    /// in-process engine — optimizing logical/physical planner with hash join/aggregate.
    /// Pure Rust, always available.
    Columnar,
    /// Experimental Soufflé parity backend (requires the `souffle` binary). Not a
    /// production-supported execution surface.
    Souffle,
    /// In-process DuckDB SQL rule backend (requires `--features duckdb`). Same IR.
    Duckdb,
}

impl LogicMode {
    /// Stable lowercase identifier matching the `--logic` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LogicMode::Souffle => "souffle",
            LogicMode::Duckdb => "duckdb",
            LogicMode::Columnar => "columnar",
        }
    }
}

impl std::fmt::Display for LogicMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
