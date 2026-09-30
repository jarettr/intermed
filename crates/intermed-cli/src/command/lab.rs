use super::*;

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
    /// Build an authoritative lock from `modrinth.index.json`.
    DiscoverMrpack(LabDiscoverMrpackArgs),
    /// Classify captured smoke-test outputs against a corpus lock.
    Run(LabRunArgs),
    /// Render a compatibility matrix (JSON + HTML) from a lab run.
    Report(LabReportArgs),
    /// Score Doctor predictions against lab ground truth (precision/recall).
    Eval(LabEvalArgs),
    /// Materialize a locked corpus through the content-addressed Lab store.
    Materialize(LabMaterializeArgs),
    /// Execute or resume a reproducible real-pack campaign.
    Campaign(LabCampaignArgs),
    /// Convert a launcher/server log into a bounded smoke artifact.
    Capture(LabCaptureArgs),
}

#[derive(Args)]
pub struct LabCaptureArgs {
    pub log: PathBuf,
    #[arg(long)]
    pub environment: String,
    /// Observed process exit code. Omit when unavailable.
    #[arg(long)]
    pub exit_code: Option<i32>,
    #[arg(long)]
    pub timed_out: bool,
    #[arg(long)]
    pub max_bytes: Option<u64>,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct LabDiscoverMrpackArgs {
    /// `.mrpack` archive or extracted `modrinth.index.json`.
    pub manifest: PathBuf,
    #[arg(long, default_value = "corpus.lock")]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct LabMaterializeArgs {
    /// Corpus lock produced by `lab discover`.
    pub lock: PathBuf,
    /// Directory containing the locked artifacts.
    #[arg(long)]
    pub source: PathBuf,
    /// Content-addressed store root.
    #[arg(long, default_value = ".intermed-lab-store")]
    pub store: PathBuf,
    /// Immutable materialized instance directory.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args)]
pub struct LabCampaignArgs {
    /// Campaign manifest (`intermed-lab-campaign-v1`).
    pub campaign: PathBuf,
    /// Persistent state and per-case observations.
    #[arg(long, default_value = "campaign-runs/latest")]
    pub out: PathBuf,
    /// Retry budget for infrastructure failures.
    #[arg(long)]
    pub max_attempts: Option<u32>,
    /// Maximum concurrent cases. Use 1 for very large packs.
    #[arg(long)]
    pub max_parallel: Option<usize>,
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

    /// A Doctor report JSON (`intermed-doctor-report-v1` or canonical v2); use with `--run`.
    #[arg(long, requires = "run")]
    pub report: Option<PathBuf>,

    /// A single lab run JSON (`intermed-lab-run-v2`; v1 is migration-readable); use with `--report`.
    #[arg(long, requires = "report")]
    pub run: Option<PathBuf>,

    /// Minimum prediction severity that counts as "flagged".
    #[arg(long = "min-severity", value_enum, default_value_t = SeverityFilter::Warn)]
    pub min_severity: SeverityFilter,

    /// Output accuracy report path (`intermed-rule-accuracy-v4`).
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
