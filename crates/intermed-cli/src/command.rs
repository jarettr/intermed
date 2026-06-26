//! Clap command definitions (shared by the binary and man-page generation).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "intermed",
    arg_required_else_help = false,
    version,
    about = "InterMed — Minecraft modpack/server evidence engine",
    long_about = "InterMed builds a fact graph from Minecraft servers, instances, mods directories, \
and logs, then derives findings with full provenance.\n\n\
See docs/guides/quickstart.md for copy-paste recipes for every subcommand.",
    after_help = "Examples:\n  \
intermed doctor ./mods\n  \
intermed doctor ./server --mixin-risk --json\n  \
intermed vfs explain ./mods\n  \
intermed mixin-map ./mods\n  \
intermed rules check ./rules\n\n\
More: docs/guides/quickstart.md | Reference: docs/reference/commands.md | Man: docs/man/intermed.1"
)]
pub struct Cli {
    /// Config file (`intermed-config-v1` TOML). Overrides discovery; see docs/reference/configuration.md.
    #[arg(long = "config", global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Print the effective default config as TOML and exit (no subcommand required).
    #[arg(long = "dump-config", global = true)]
    pub dump_config: bool,

    /// Suppress informational progress messages on stderr (errors still print).
    #[arg(long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Increase informational detail (repeatable: `-v`, `-vv`).
    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Diagnose a server, instance, mods directory, or log/crash file.
    Doctor(Box<DoctorArgs>),
    /// Inspect resource/data overrides and generate overlay previews.
    Vfs(VfsArgs),
    /// Layer-C dependency graph, resolution, and explainable queries.
    Deps(DepsArgs),
    /// Blast-radius analysis for removing or updating a mod.
    Impact(ImpactArgs),
    /// Inspect static Mixin targets, overlaps, and overwrite risks.
    MixinMap(MixinMapArgs),
    /// Import and summarize Spark performance reports.
    SparkMap(SparkMapArgs),
    /// Compatibility Lab: corpus locks, smoke-test ingestion, matrices.
    Lab(LabArgs),
    /// Validate declarative rule packs.
    Rules(RulesArgs),
    /// Query the DuckDB analytics store (`--features duckdb`).
    Db(DbArgs),
    /// Recurring conflicts across persisted diagnosis runs.
    History(HistoryArgs),
    /// Time-series analytics over persisted runs.
    Trends(TrendsArgs),
    /// Jar scan cache maintenance (`stats`, `prune`, `clear`).
    Cache(CacheArgs),
    /// SBOM export (SPDX / CycloneDX) from a mods directory.
    Sbom(SbomArgs),
    /// Presentation demo: aggregate a small real-mod run into launcher-facing reports.
    Demo(DemoArgs),
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
intermed doctor ./mods\n  \
intermed doctor ./server --mixin-risk --json\n  \
intermed doctor ./mods --dump-facts facts.json --explain duplicate-id:foo\n  \
intermed doctor ./mods --logic=datalog\n  \
intermed doctor ./mods --profile profile.json --no-cache")]
pub struct DoctorArgs {
    /// What to diagnose. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Override the mods directory (otherwise auto-detected).
    #[arg(long = "mods-dir")]
    pub mods_dir: Option<PathBuf>,

    /// Enable Layer-F Mixin risk scanning during doctor.
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
    /// Emit the full report as `intermed-doctor-report-v1` JSON.
    ///
    /// With no value, writes to stdout. With `FILE`, writes that artifact and can
    /// be combined with `--sarif FILE` / `--html FILE` in one scan.
    #[arg(long, value_name = "FILE", num_args = 0..=1)]
    pub json: Option<Option<PathBuf>>,

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
    /// Mixin analysis preset: `normal` (overlaps/risk only), `detailed` (+ recommendations),
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
    Normal,
    Detailed,
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

    /// SBOM trust score (0..=100) for well-identified jars (default: 60).
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
    /// Soufflé Datalog backend (requires the `souffle` binary). Same IR, external engine.
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

#[derive(Args)]
#[command(
    after_help = "Example:\n  intermed db query --db history.duckdb \"SELECT kind, COUNT(*) FROM facts GROUP BY kind\""
)]
pub struct DbArgs {
    #[command(subcommand)]
    pub command: DbCommand,
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
intermed history conflicts --db history.duckdb --since 30d\n  \
intermed history conflicts --db history.duckdb --since 7d")]
pub struct HistoryArgs {
    #[command(subcommand)]
    pub command: HistoryCommand,
}

#[derive(Subcommand)]
pub enum HistoryCommand {
    /// Findings that recur across multiple runs within a time window.
    Conflicts(HistoryConflictsArgs),
    /// Recurring *kinds* of risk (rule + category) rolled up across all history.
    Patterns(HistoryPatternsArgs),
    /// Compare findings between two persisted runs.
    Diff(HistoryDiffArgs),
    /// Delete analytics runs older than a retention window.
    Prune(HistoryPruneArgs),
}

#[derive(Args)]
pub struct HistoryPatternsArgs {
    /// DuckDB analytics database file.
    #[arg(long = "db", value_name = "FILE")]
    pub db: PathBuf,

    /// Maximum patterns to show (highest severity / most recurring first).
    #[arg(long = "limit", default_value_t = 20, value_name = "N")]
    pub limit: usize,
}

#[derive(Args)]
pub struct HistoryDiffArgs {
    #[arg(long = "db", value_name = "FILE")]
    pub db: PathBuf,

    #[arg(long = "run-a", value_name = "RUN_ID")]
    pub run_a: String,

    #[arg(long = "run-b", value_name = "RUN_ID")]
    pub run_b: String,

    /// Emit structured JSON (`intermed-history-diff-v1`) instead of TSV.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct HistoryPruneArgs {
    #[arg(long = "db", value_name = "FILE")]
    pub db: PathBuf,

    /// Keep runs within this window (`90d`, `30d`). Older runs are deleted.
    #[arg(long = "keep", default_value = "90d", value_name = "DURATION")]
    pub keep: String,
}

#[derive(Args)]
pub struct HistoryConflictsArgs {
    /// DuckDB analytics database file.
    #[arg(long = "db", value_name = "FILE")]
    pub db: PathBuf,

    /// Relative look-back window (`30d`, `7d`, `24h`). Default: 30d.
    #[arg(long = "since", default_value = "30d", value_name = "DURATION")]
    pub since: String,
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
intermed trends mixin-risk --db history.duckdb\n  \
intermed trends mixin-overlaps --db history.duckdb --limit 10")]
pub struct TrendsArgs {
    #[command(subcommand)]
    pub command: TrendsCommand,
}

#[derive(Subcommand)]
pub enum TrendsCommand {
    /// Mixin-category finding counts per persisted run.
    MixinRisk(TrendsDbArgs),
    /// Top-N most frequent mixin overlaps (by mod set + target).
    MixinOverlaps(TrendsMixinOverlapsArgs),
}

#[derive(Args)]
pub struct TrendsDbArgs {
    /// DuckDB analytics database file.
    #[arg(long = "db", value_name = "FILE")]
    pub db: PathBuf,
}

#[derive(Args)]
pub struct TrendsMixinOverlapsArgs {
    /// DuckDB analytics database file.
    #[arg(long = "db", value_name = "FILE")]
    pub db: PathBuf,

    /// Number of rows to return (default: 10).
    #[arg(long = "limit", default_value_t = 10)]
    pub limit: usize,
}

#[derive(Subcommand)]
pub enum DbCommand {
    /// Run a read-only SQL query against the analytics store.
    Query(DbQueryArgs),
}

#[derive(Args)]
pub struct DbQueryArgs {
    /// DuckDB analytics database file.
    #[arg(long = "db", value_name = "FILE")]
    pub db: PathBuf,

    /// SQL to execute (read-only analytics).
    pub sql: String,
}

#[derive(Args)]
#[command(
    after_help = "Examples:\n  intermed vfs scan ./mods\n  intermed vfs explain ./mods\n  intermed vfs overlay ./mods --out ./overlay-preview\n  intermed vfs overlay ./mods --out ./overlay-preview --include-unsafe-winners"
)]
pub struct VfsArgs {
    #[command(subcommand)]
    pub command: VfsCommand,
}

#[derive(Subcommand)]
pub enum VfsCommand {
    /// Scan jar assets/data writers and summarize resource collisions.
    Scan(VfsTargetArgs),
    /// Explain each resource collision and its merge/override class.
    Explain(VfsTargetArgs),
    /// Write a read-only overlay preview directory from detected collisions.
    Overlay(VfsOverlayArgs),
}

#[derive(Args)]
pub struct VfsTargetArgs {
    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Explain a single resource path (e.g. `data/create/recipes/crushing/tuff.json`).
    #[arg(long = "path", value_name = "RESOURCE_PATH")]
    pub path: Option<String>,

    /// Show the Layer-M typed AST view (domain, semantic diff, references) for
    /// `--path`. Requires `--path`.
    #[arg(long = "ast")]
    pub ast: bool,

    /// AST depth used by `--ast`: `semantic` (default) or `full`.
    #[arg(
        long = "resource-level",
        value_enum,
        value_name = "LEVEL",
        default_value = "full"
    )]
    pub resource_level: ResourceLevelArg,

    /// Accepted for script consistency; VFS output currently has no ANSI colour.
    #[arg(long = "no-color")]
    pub _no_color: bool,
}

#[derive(Args)]
pub struct VfsOverlayArgs {
    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// New output directory for the overlay preview.
    #[arg(long)]
    pub out: PathBuf,

    /// Also stage order-dependent collisions by picking a lexical winner. These
    /// are previews, NOT safe fixes: the manifest marks them safe_to_apply=false.
    /// By default only deterministic, order-independent merges are written.
    #[arg(long = "include-unsafe-winners")]
    pub include_unsafe_winners: bool,

    /// Print the semantic overlay plan (`intermed-overlay-plan-v2`: safe / review /
    /// unsafe buckets) to stdout and exit — read-only, writes nothing.
    #[arg(long = "explain-plan")]
    pub explain_plan: bool,

    /// Accepted for script consistency; VFS output currently has no ANSI colour.
    #[arg(long = "no-color")]
    pub _no_color: bool,
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
intermed deps graph ./mods\n  \
intermed deps resolve ./mods\n  \
intermed deps why create ./mods\n  \
intermed deps why-missing balm-fabric ./mods\n  \
intermed deps implicit ./mods --namespace create\n  \
intermed deps path waystones balm-fabric ./mods")]
pub struct DepsArgs {
    #[command(subcommand)]
    pub command: DepsCommand,
}

#[derive(Subcommand)]
pub enum DepsCommand {
    /// Export the modpack dependency graph (`intermed-modpack-graph-v1` JSON).
    Graph(DepsTargetArgs),
    /// Run PubGrub resolution and emit `intermed-deps-resolution-v1` JSON.
    Resolve(DepsTargetArgs),
    /// Explain why a mod/namespace is depended upon (declared + implicit reasons).
    Why(DepsIdArgs),
    /// Explain why an absent dependency is required (the requiring edges).
    WhyMissing(DepsIdArgs),
    /// List implicit references into a namespace (resource-derived dependencies).
    Implicit(DepsImplicitArgs),
    /// Find a dependency chain between two mods (`deps path <from> <to>`).
    Path(DepsPathArgs),
}

#[derive(Args)]
pub struct DepsTargetArgs {
    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Override the mods directory (otherwise auto-detected).
    #[arg(long = "mods-dir")]
    pub mods_dir: Option<PathBuf>,
}

#[derive(Args)]
pub struct DepsIdArgs {
    /// The mod id or namespace to explain.
    pub id: String,

    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Override the mods directory (otherwise auto-detected).
    #[arg(long = "mods-dir")]
    pub mods_dir: Option<PathBuf>,

    /// Emit machine-readable JSON instead of text.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args)]
pub struct DepsImplicitArgs {
    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// The provider namespace to list implicit references for.
    #[arg(long = "namespace", value_name = "NS")]
    pub namespace: String,

    /// Override the mods directory (otherwise auto-detected).
    #[arg(long = "mods-dir")]
    pub mods_dir: Option<PathBuf>,

    /// Emit machine-readable JSON instead of text.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args)]
pub struct DepsPathArgs {
    /// Source mod id.
    pub from: String,

    /// Target mod id / namespace.
    pub to: String,

    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Override the mods directory (otherwise auto-detected).
    #[arg(long = "mods-dir")]
    pub mods_dir: Option<PathBuf>,

    /// Emit machine-readable JSON instead of text.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
intermed impact remove create ./mods\n  \
intermed impact update sodium 0.5.8 0.6.0 ./mods")]
pub struct ImpactArgs {
    #[command(subcommand)]
    pub command: ImpactCommand,
}

#[derive(Subcommand)]
pub enum ImpactCommand {
    /// Blast radius of removing a mod (reverse resource graph + dependents).
    Remove(ImpactRemoveArgs),
    /// Blast radius of bumping a mod's version (which declared ranges reject it).
    Update(ImpactUpdateArgs),
}

#[derive(Args)]
pub struct ImpactRemoveArgs {
    /// The mod id / namespace to remove.
    pub id: String,

    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Override the mods directory (otherwise auto-detected).
    #[arg(long = "mods-dir")]
    pub mods_dir: Option<PathBuf>,

    /// Emit machine-readable JSON instead of text.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args)]
pub struct ImpactUpdateArgs {
    /// The mod id to update.
    pub id: String,

    /// Current version (use `-` to omit and only check the target version).
    pub from: String,

    /// Proposed new version.
    pub to: String,

    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Override the mods directory (otherwise auto-detected).
    #[arg(long = "mods-dir")]
    pub mods_dir: Option<PathBuf>,

    /// Emit machine-readable JSON instead of text.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args)]
#[command(
    after_help = "Example:\n  intermed spark-map ./server --spark-report ./spark/profile.json"
)]
pub struct SparkMapArgs {
    /// Server/instance directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Explicit spark report JSON (`intermed-spark-report-v1`).
    #[arg(long = "spark-report", value_name = "FILE")]
    pub spark_report: Option<PathBuf>,

    /// Accepted for script consistency; Spark Map output currently has no ANSI colour.
    #[arg(long = "no-color")]
    pub _no_color: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum GraphExportFormat {
    /// Human-readable mixin map summary (default).
    Json,
    /// Machine-readable interaction graph (`MixinGraphExport` JSON).
    #[value(name = "graph-json")]
    GraphData,
    Dot,
    Graphml,
    Html,
}

#[derive(Args)]
#[command(
    after_help = "Examples:\n  intermed mixin-map ./mods\n  intermed mixin-map ./mods --graph-format dot --graph-out mixin.dot"
)]
pub struct MixinMapArgs {
    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Graph export format (default: json summary).
    #[arg(long = "graph-format", value_enum, default_value_t = GraphExportFormat::Json)]
    pub graph_format: GraphExportFormat,

    /// Write graph export to file (stdout when omitted for dot/graphml).
    #[arg(long = "graph-out", value_name = "FILE")]
    pub graph_out: Option<PathBuf>,

    /// Accepted for script consistency; Mixin Map output currently has no ANSI colour.
    #[arg(long = "no-color")]
    pub _no_color: bool,
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
intermed lab discover ./candidates.json --out corpus.lock\n  \
intermed lab run corpus.lock --logs ./captured --out ./runs/latest\n  \
intermed lab report ./runs/latest --out ./site")]
pub struct LabArgs {
    #[command(subcommand)]
    pub command: LabCommand,
}

#[derive(Subcommand)]
pub enum LabCommand {
    /// Build a reproducible corpus lock from a candidate pool.
    Discover(LabDiscoverArgs),
    /// Classify captured smoke-test outputs against a corpus lock.
    Run(LabRunArgs),
    /// Render a compatibility matrix (JSON + HTML) from a lab run.
    Report(LabReportArgs),
    /// Score Doctor predictions against lab ground truth (precision/recall).
    Eval(LabEvalArgs),
}

/// Severity gate for `lab eval`: predictions weaker than this count as
/// "not flagged".
#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "lower")]
pub enum SeverityFilter {
    Note,
    Warn,
    Error,
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
intermed lab eval --report report.json --run runs/latest/lab-run.json --out accuracy.json\n  \
intermed lab eval --manifest dataset.json --min-severity warn")]
pub struct LabEvalArgs {
    /// Dataset manifest (`intermed-eval-manifest-v1`) listing report/run pairs.
    #[arg(long, conflicts_with_all = ["report", "run"])]
    pub manifest: Option<PathBuf>,

    /// A single Doctor report JSON (`intermed-doctor-report-v1`); use with `--run`.
    #[arg(long, requires = "run")]
    pub report: Option<PathBuf>,

    /// A single lab run JSON (`intermed-lab-run-v1`); use with `--report`.
    #[arg(long, requires = "report")]
    pub run: Option<PathBuf>,

    /// Minimum prediction severity that counts as "flagged".
    #[arg(long = "min-severity", value_enum, default_value_t = SeverityFilter::Warn)]
    pub min_severity: SeverityFilter,

    /// Output accuracy report path (`intermed-rule-accuracy-v3`).
    #[arg(long, default_value = "accuracy.json")]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct LabDiscoverArgs {
    /// Candidate pool JSON (`intermed-corpus-candidates-v1`).
    pub candidates: PathBuf,

    /// Output lock path.
    #[arg(long, default_value = "corpus.lock")]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct LabRunArgs {
    /// Corpus lock produced by `lab discover`.
    pub lock: PathBuf,

    /// Directory of captured smoke outputs (`intermed-smoke-output-v1` JSON).
    #[arg(long)]
    pub logs: PathBuf,

    /// Output directory for the run artifact (`lab-run.json`).
    #[arg(long, default_value = "runs/latest")]
    pub out: PathBuf,

    /// Maximum characters kept from a failure log excerpt (default: 280).
    #[arg(long = "lab-excerpt-max", value_name = "N")]
    pub excerpt_max: Option<usize>,
}

#[derive(Args)]
pub struct LabReportArgs {
    /// Run directory or `lab-run.json` produced by `lab run`.
    pub run: PathBuf,

    /// Output directory for `matrix.json` + `index.html`.
    #[arg(long, default_value = "site")]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RulesCommand,
}

#[derive(Subcommand)]
pub enum RulesCommand {
    /// Validate rule-pack JSON/YAML files under a path.
    Check(RulesCheckArgs),
    /// Generate backend artifacts (SQL, Datalog, Rust stubs) from a rule pack.
    Generate(RulesGenerateArgs),
    /// Sign a v2 rule pack with an Ed25519 key.
    Sign(RulesSignArgs),
    /// Verify a signed rule pack (optional trusted-keys file).
    Verify(RulesVerifyArgs),
    /// Refresh an installed pack from the registry (embedded core by default).
    Update(RulesUpdateArgs),
    /// List packs in a registry index (embedded default if omitted).
    Registry(RulesRegistryArgs),
    /// Install a pack and its registry dependencies into XDG rule-packs.
    Install(RulesInstallArgs),
    /// Show the query-engine plan (EXPLAIN, and EXPLAIN ANALYZE with `--facts`) per rule.
    Explain(RulesExplainArgs),
}

#[derive(Args)]
#[command(
    after_help = "Examples:\n  intermed rules explain                       # static EXPLAIN, all core rules\n  intermed rules explain --rule duplicate-id\n  intermed doctor ./mods --dump-facts f.json && intermed rules explain --facts f.json --rule resource-conflict-safe-crdt-merge"
)]
pub struct RulesExplainArgs {
    #[arg(
        default_value = "",
        help = "Rule pack JSON/YAML (default: embedded core v2 when empty or missing)"
    )]
    pub pack: PathBuf,

    /// Explain only this rule id (default: every lowerable rule).
    #[arg(long = "rule", value_name = "ID")]
    pub rule: Option<String>,

    /// A `doctor --dump-facts` JSON file: enables EXPLAIN ANALYZE on those real facts.
    #[arg(long = "facts", value_name = "FILE")]
    pub facts: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum RulesGenerateBackend {
    Sql,
    Rust,
    Datalog,
    /// Columnar query-engine `EXPLAIN` (logical + physical plan + engines) per rule.
    Explain,
}

#[derive(Args)]
#[command(
    after_help = "Example:\n  intermed rules generate --backend sql rules/core/intermed-core.rules.v2.json"
)]
pub struct RulesGenerateArgs {
    #[arg(
        default_value = "",
        help = "Rule pack JSON/YAML (default: embedded core v2 when empty or missing)"
    )]
    pub pack: PathBuf,

    /// Output backend: sql, rust, or datalog.
    #[arg(long = "backend", value_enum, default_value_t = RulesGenerateBackend::Sql)]
    pub backend: RulesGenerateBackend,

    /// Write to file instead of stdout.
    #[arg(long = "out", value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = "Example:\n  intermed rules check ./rules")]
pub struct RulesCheckArgs {
    /// Rule pack file or directory. Defaults to ./rules.
    #[arg(default_value = "rules")]
    pub path: PathBuf,

    /// Require a valid Ed25519 signature on v2 packs.
    #[arg(long = "require-signature")]
    pub require_signature: bool,

    /// Trusted publisher public keys (one base64 key per line).
    #[arg(long = "trusted-keys", value_name = "FILE")]
    pub trusted_keys: Option<PathBuf>,

    /// Dry-run: evaluate each rule against facts JSON and print a trace table.
    #[arg(long)]
    pub trace: bool,

    /// Fact snapshot JSON for `--trace` (from `doctor --dump-facts`).
    #[arg(long = "facts", value_name = "FILE", requires = "trace")]
    pub facts: Option<PathBuf>,
}

#[derive(Args)]
#[command(
    after_help = "Example:\n  intermed rules sign rules/core/intermed-core.rules.json --key ./publisher.key"
)]
pub struct RulesSignArgs {
    /// Unsigned v2 rule pack to sign.
    pub pack: PathBuf,

    /// Ed25519 seed file (32 raw bytes or base64 text).
    #[arg(long = "key", value_name = "FILE")]
    pub key: PathBuf,

    /// Output signed pack path (default: overwrite input).
    #[arg(long = "out", value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Args)]
pub struct RulesVerifyArgs {
    /// Signed rule pack to verify.
    pub pack: PathBuf,

    /// Trusted publisher public keys (one base64 key per line).
    #[arg(long = "trusted-keys", value_name = "FILE")]
    pub trusted_keys: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = "Example:\n  intermed rules update --pack intermed-core")]
pub struct RulesUpdateArgs {
    /// Registry index JSON or URL (`intermed-rule-registry-v1`). Defaults to embedded + community index.
    #[arg(long = "registry", value_name = "FILE|URL")]
    pub registry: Option<String>,

    /// Pack id to refresh (default: intermed-core).
    #[arg(long = "pack", default_value = "intermed-core")]
    pub pack_id: String,

    /// Install directory (default: XDG data/intermed/rule-packs).
    #[arg(long = "install-dir", value_name = "DIR")]
    pub install_dir: Option<PathBuf>,

    /// Trusted publisher public keys (one base64 key per line) to pin signatures against.
    #[arg(long = "trusted-keys", value_name = "FILE")]
    pub trusted_keys: Option<PathBuf>,

    /// Allow `http://` registries/packs (insecure; HTTPS is required by default).
    #[arg(long = "allow-insecure-registry")]
    pub allow_insecure_registry: bool,

    /// Accept unsigned, or signed-but-unpinned, remote rule packs.
    #[arg(long = "allow-unsigned-rules")]
    pub allow_unsigned_rules: bool,
}

#[derive(Args)]
#[command(after_help = "Example:\n  intermed rules install --pack community-mixin-pack")]
pub struct RulesInstallArgs {
    #[arg(long = "registry", value_name = "FILE|URL")]
    pub registry: Option<String>,

    #[arg(long = "pack", required = true)]
    pub pack_id: String,

    #[arg(long = "install-dir", value_name = "DIR")]
    pub install_dir: Option<PathBuf>,

    #[arg(long = "trusted-keys", value_name = "FILE")]
    pub trusted_keys: Option<PathBuf>,

    /// Allow `http://` registries/packs (insecure; HTTPS is required by default).
    #[arg(long = "allow-insecure-registry")]
    pub allow_insecure_registry: bool,

    /// Accept unsigned, or signed-but-unpinned, remote rule packs.
    #[arg(long = "allow-unsigned-rules")]
    pub allow_unsigned_rules: bool,
}

#[derive(Args)]
#[command(
    after_help = "Examples:\n  intermed cache stats\n  intermed cache prune\n  intermed cache clear"
)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub command: CacheCommand,
}

#[derive(Subcommand)]
pub enum CacheCommand {
    /// Show hit/miss counters and on-disk cache size.
    Stats(CacheStatsArgs),
    /// Force a prune pass (age + size limits).
    Prune(CacheStatsArgs),
    /// Delete all cached jar payloads and fingerprints.
    Clear(CacheStatsArgs),
}

#[derive(Args)]
pub struct CacheStatsArgs {
    #[arg(long = "cache-dir", value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SbomExportFormatCli {
    #[value(name = "spdx-json")]
    SpdxJson,
    #[value(name = "cyclonedx-json")]
    CycloneDxJson,
}

#[derive(Args)]
#[command(
    after_help = "Examples:\n  intermed sbom export ./mods --format spdx-json\n  intermed sbom export ./mods --format cyclonedx-json --out sbom.json"
)]
pub struct SbomArgs {
    #[command(subcommand)]
    pub command: SbomCommand,
}

#[derive(Subcommand)]
pub enum SbomCommand {
    /// Export SPDX or CycloneDX SBOM from jar metadata.
    Export(SbomExportArgs),
}

#[derive(Args)]
pub struct SbomExportArgs {
    #[arg(default_value = ".")]
    pub target: PathBuf,

    #[arg(long = "mods-dir")]
    pub mods_dir: Option<PathBuf>,

    #[arg(long = "format", value_enum, default_value_t = SbomExportFormatCli::SpdxJson)]
    pub format: SbomExportFormatCli,

    #[arg(long = "out", value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Args)]
#[command(after_help = "Examples:\n  \
./scripts/intermed-demo-run.sh\n  \
intermed demo report ~/intermed_demo_runs/LATEST --out .")]
pub struct DemoArgs {
    #[command(subcommand)]
    pub command: DemoCommand,
}

#[derive(Subcommand)]
pub enum DemoCommand {
    /// Render markdown, HTML, and JSON presentation artifacts from a demo run directory.
    Report(DemoReportArgs),
}

#[derive(Args)]
pub struct DemoReportArgs {
    /// Directory produced by `scripts/intermed-demo-run.sh` (contains `corpus.json` and `doctor-*.txt`).
    pub run_dir: PathBuf,

    /// Output directory for `intermed-atlauncher-demo-summary.md`, `intermed-demo-report.html`, and JSON.
    #[arg(long, short = 'o', default_value = ".")]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct RulesRegistryArgs {
    /// Registry index JSON or URL. Defaults to the embedded InterMed registry.
    #[arg(long = "registry", value_name = "FILE|URL")]
    pub registry: Option<String>,

    /// Allow `http://` registries (insecure; HTTPS is required by default).
    #[arg(long = "allow-insecure-registry")]
    pub allow_insecure_registry: bool,
}
