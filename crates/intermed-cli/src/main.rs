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

use clap::{Args, Parser, Subcommand, ValueEnum};

use intermed_doctor_core::facts::Fact;
use intermed_doctor_core::{detect_target, DiagnosticEngine, DiagnosticRun, Target, TargetKind};
use intermed_report::{render, Format};

use intermed_deps::DependencyRule;
use intermed_log::{LogCollector, LogSignalRule};
use intermed_minecraft_scan::{EnvironmentCollector, MetadataCollector};
use intermed_rules::{
    check_rule_packs, souffle_available, DatalogRulePack, DuplicateIdRule, LoaderMismatchRule,
    SideMismatchRule, SouffleRulePack,
};

#[derive(Parser)]
#[command(
    name = "intermed",
    version,
    about = "InterMed — Minecraft modpack/server evidence engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Diagnose a server, instance, mods directory, or log/crash file.
    Doctor(DoctorArgs),
    /// Inspect resource/data overrides and generate overlay previews.
    Vfs(VfsArgs),
    /// Inspect static Mixin targets, overlaps, and overwrite risks.
    MixinMap(MixinMapArgs),
    /// Validate declarative rule packs.
    Rules(RulesArgs),
}

#[derive(Args)]
struct DoctorArgs {
    /// What to diagnose. Defaults to the current directory.
    #[arg(default_value = ".")]
    target: PathBuf,

    /// Emit the full report as `intermed-doctor-report-v1` JSON.
    #[arg(long, conflicts_with = "sarif")]
    json: bool,

    /// Emit SARIF 2.1.0 (for IDE / CI code-scanning).
    #[arg(long)]
    sarif: bool,

    /// Override the mods directory (otherwise auto-detected).
    #[arg(long = "mods-dir")]
    mods_dir: Option<PathBuf>,

    /// Enable Layer-F Mixin risk scanning during doctor.
    #[arg(long = "mixin-risk")]
    mixin_risk: bool,

    /// Rule backend selection. Imperative remains the stable fallback.
    #[arg(long, value_enum, default_value_t = LogicMode::Imperative)]
    logic: LogicMode,

    /// Write the raw Phase-2 fact snapshot to a JSON file.
    #[arg(long = "dump-facts", value_name = "FILE")]
    dump_facts: Option<PathBuf>,

    /// Explain one finding id with its supporting facts.
    #[arg(long, value_name = "FINDING_ID")]
    explain: Option<String>,

    /// Disable ANSI colour even on a TTY.
    #[arg(long = "no-color")]
    no_color: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogicMode {
    Imperative,
    Datalog,
    Souffle,
}

#[derive(Args)]
struct VfsArgs {
    #[command(subcommand)]
    command: VfsCommand,
}

#[derive(Subcommand)]
enum VfsCommand {
    /// Scan jar assets/data writers and summarize resource collisions.
    Scan(VfsTargetArgs),
    /// Explain each resource collision and its merge/override class.
    Explain(VfsTargetArgs),
    /// Write a read-only overlay preview directory from detected collisions.
    Overlay(VfsOverlayArgs),
}

#[derive(Args)]
struct VfsTargetArgs {
    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    target: PathBuf,

    /// Accepted for script consistency; VFS output currently has no ANSI colour.
    #[arg(long = "no-color")]
    _no_color: bool,
}

#[derive(Args)]
struct VfsOverlayArgs {
    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    target: PathBuf,

    /// New output directory for the overlay preview.
    #[arg(long)]
    out: PathBuf,

    /// Accepted for script consistency; VFS output currently has no ANSI colour.
    #[arg(long = "no-color")]
    _no_color: bool,
}

#[derive(Args)]
struct MixinMapArgs {
    /// Mods directory or instance/server directory. Defaults to current dir.
    #[arg(default_value = ".")]
    target: PathBuf,

    /// Accepted for script consistency; Mixin Map output currently has no ANSI colour.
    #[arg(long = "no-color")]
    _no_color: bool,
}

#[derive(Args)]
struct RulesArgs {
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Validate rule-pack JSON/YAML files under a path.
    Check(RulesCheckArgs),
}

#[derive(Args)]
struct RulesCheckArgs {
    /// Rule pack file or directory. Defaults to ./rules.
    #[arg(default_value = "rules")]
    path: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Doctor(args) => run_doctor(args),
        Command::Vfs(args) => run_vfs(args),
        Command::MixinMap(args) => run_mixin_map(args),
        Command::Rules(args) => run_rules(args),
    }
}

fn run_doctor(args: DoctorArgs) -> ExitCode {
    if !args.target.exists() {
        eprintln!("error: target does not exist: {}", args.target.display());
        return ExitCode::from(2);
    }

    let mut target: Target = detect_target(&args.target);
    if let Some(md) = args.mods_dir {
        target.mods_dir = Some(md);
        if target.kind == TargetKind::Unknown {
            target.kind = TargetKind::ModsDir;
        }
    }

    if args.logic == LogicMode::Souffle && !souffle_available() {
        eprintln!("error: --logic=souffle requires the 'souffle' binary in PATH");
        return ExitCode::from(2);
    }

    let engine = build_engine(args.logic, args.mixin_risk);
    let run = engine.diagnose_with_facts(&target);

    if let Some(path) = &args.dump_facts {
        if let Err(e) = write_facts(path, &run.facts) {
            eprintln!("error: could not write facts to {}: {e}", path.display());
            return ExitCode::from(2);
        }
    }

    if let Some(finding_id) = &args.explain {
        return explain_finding(
            &run,
            finding_id,
            !args.no_color && std::io::stdout().is_terminal(),
        );
    }

    let format = if args.sarif {
        Format::Sarif
    } else if args.json {
        Format::Json
    } else {
        let color = !args.no_color && std::io::stdout().is_terminal();
        Format::Terminal { color }
    };

    println!("{}", render(&run.report, format));
    ExitCode::from(run.report.exit_code() as u8)
}

/// Register every layer. Working layers come first; deferred stubs are
/// registered too so the report shows the full roadmap.
fn build_engine(logic: LogicMode, mixin_risk: bool) -> DiagnosticEngine {
    let mut builder = DiagnosticEngine::builder()
        .tool_version(env!("CARGO_PKG_VERSION"))
        // ── Working collectors (Phase 1) ──
        .collector(EnvironmentCollector) // Layer A
        .collector(MetadataCollector) // Layer B
        .collector(LogCollector) // Layer D
        .collector(intermed_vfs::collector()) // Layer E — Phase 3
        // ── Deferred collectors (later phases) ──
        .collector(intermed_security_audit::collector()) // Layer G — Phase 6
        .collector(intermed_sbom::collector()) // Layer H — Phase 6
        .collector(intermed_spark_bridge::collector()) // Layer I — Phase 7
        .collector(intermed_runtime_preflight::collector()) // Layer L — Phase 9
        // ── Working rules ──
        .rule(DependencyRule) // Layer C
        .rule(LogSignalRule); // Layer D

    if mixin_risk {
        builder = builder.collector(intermed_mixin_intel::collector()); // Layer F — Phase 4
    }

    match logic {
        LogicMode::Imperative => builder = builder.rule(DuplicateIdRule), // Layer J
        LogicMode::Datalog => builder = builder.rule(DatalogRulePack::default_core()), // Layer J — Phase 5
        LogicMode::Souffle => builder = builder.rule(SouffleRulePack::new()), // Layer J — Phase 5
    }

    let mut builder = builder
        .rule(LoaderMismatchRule) // Layer J
        .rule(SideMismatchRule) // Layer J
        .rule(intermed_vfs::rule()); // Layer E — Phase 3

    if mixin_risk && logic == LogicMode::Imperative {
        builder = builder.rule(intermed_mixin_intel::rule()); // Layer F — Phase 4
    }

    builder.build()
}

fn write_facts(path: &Path, facts: &[Fact]) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(facts)?;
    std::fs::write(path, json)?;
    Ok(())
}

fn explain_finding(run: &DiagnosticRun, id: &str, color: bool) -> ExitCode {
    let Some(finding) = run.report.findings.iter().find(|f| f.id == id) else {
        eprintln!("error: finding id not found: {id}");
        return ExitCode::from(2);
    };

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
    ExitCode::from(run.report.exit_code() as u8)
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
            match intermed_packops::write_overlay_preview(&mods_dir, &args.out) {
                Ok(plan) => {
                    println!(
                        "Overlay preview written to {} ({} item(s))",
                        plan.out_dir,
                        plan.manifest.items.len()
                    );
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

fn run_mixin_map(args: MixinMapArgs) -> ExitCode {
    let target = match detect_target_or_exit(&args.target) {
        Ok(target) => target,
        Err(code) => return code,
    };
    match intermed_mixin_intel::scan_target(&target) {
        Ok(scan) => {
            print_mixin_scan(&scan);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_rules(args: RulesArgs) -> ExitCode {
    match args.command {
        RulesCommand::Check(args) => {
            let check = check_rule_packs(&args.path);
            println!("InterMed Rules");
            println!("Path: {}", args.path.display());
            println!("Files: {}", check.files);
            println!("Rules: {}", check.rules);
            if check.is_ok() {
                println!("Status: ok");
                ExitCode::SUCCESS
            } else {
                println!("Status: failed");
                for error in check.errors {
                    println!("error: {error}");
                }
                ExitCode::from(2)
            }
        }
    }
}

fn detect_target_or_exit(path: &Path) -> Result<Target, ExitCode> {
    if !path.exists() {
        eprintln!("error: target does not exist: {}", path.display());
        return Err(ExitCode::from(2));
    }
    Ok(detect_target(path))
}

fn cli_mods_dir(target: &Target) -> Option<PathBuf> {
    target.mods_dir.clone().or_else(|| {
        if target.kind == TargetKind::ModsDir {
            Some(target.path.clone())
        } else {
            let dir = target.path.join("mods");
            dir.is_dir().then_some(dir)
        }
    })
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

fn print_mixin_scan(scan: &intermed_mixin_intel::MixinScan) {
    println!("InterMed Mixin Map");
    println!("Target: {}", scan.target);
    println!("Configs: {}", scan.configs.len());
    println!("Mixin classes: {}", scan.classes.len());
    println!("Overlaps: {}", scan.overlaps.len());
    println!("High-risk overwrites: {}", scan.high_risk_overwrites.len());
    println!("Scan failures: {}", scan.failures.len());

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
        }
    }

    if !scan.high_risk_overwrites.is_empty() {
        println!();
        println!("High-risk overwrites:");
        for overwrite in &scan.high_risk_overwrites {
            println!("{} -> {}", overwrite.mod_id, overwrite.target);
            println!("  mixin: {}", overwrite.class_name);
            println!("  hot_path: {}", overwrite.hot_path);
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
