use crate::*;

pub(crate) fn run_lab(args: LabArgs, config_path: Option<&Path>) -> ExitCode {
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
        LabCommand::DiscoverMrpack(args) => {
            match intermed_lab::lock_modrinth_manifest(&args.manifest, &args.out) {
                Ok(lock) => {
                    println!("InterMed Lab — Modrinth corpus lock");
                    println!(
                        "Environment: {} loader {} / Minecraft {} ({})",
                        lock.environment.loader,
                        lock.environment
                            .loader_version
                            .as_deref()
                            .unwrap_or("unknown"),
                        lock.environment.mc_version,
                        lock.environment.side
                    );
                    println!(
                        "Pack files: {} | mods: {}",
                        lock.files.len(),
                        lock.mods.len()
                    );
                    println!("Digest: {}", lock.digest);
                    println!("Written: {}", args.out.display());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
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
        LabCommand::Materialize(args) => {
            let result = (|| {
                let lock = intermed_lab::read_lock(&args.lock)?;
                let store = intermed_lab::ArtifactStore::open(&args.store)?;
                store.materialize(&lock, &args.source, &args.out)
            })();
            match result {
                Ok(record) => {
                    let bytes = record
                        .artifacts
                        .iter()
                        .map(|artifact| artifact.bytes)
                        .sum::<u64>();
                    println!("InterMed Lab — materialization");
                    println!("Corpus digest: {}", record.corpus_digest);
                    println!("Artifacts: {} | bytes: {}", record.artifacts.len(), bytes);
                    println!("Written: {}", args.out.display());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(2)
                }
            }
        }
        LabCommand::Campaign(args) => {
            let cfg = match IntermedConfig::load(config_path) {
                Ok(cfg) => cfg,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::from(2);
                }
            };
            let max_attempts = args.max_attempts.unwrap_or(cfg.lab.campaign_max_attempts);
            let max_parallel = args.max_parallel.unwrap_or(cfg.lab.campaign_max_parallel);
            let result = (|| {
                let campaign = intermed_lab::read_campaign(&args.campaign)?;
                let base_dir = args
                    .campaign
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf();
                let executor = intermed_lab::FileCampaignExecutor::new(
                    base_dir,
                    campaign.doctor_args.clone(),
                    config_path.map(Path::to_path_buf),
                    campaign.analyzer_fingerprint.clone(),
                );
                intermed_lab::run_campaign(
                    &campaign,
                    &args.out,
                    &executor,
                    intermed_lab::CampaignOptions {
                        max_attempts,
                        max_parallel,
                    },
                )
            })();
            match result {
                Ok(state) => {
                    let campaign_report =
                        match intermed_lab::write_campaign_report(&state, &args.out) {
                            Ok(report) => report,
                            Err(error) => {
                                eprintln!("error: could not write campaign report: {error}");
                                return ExitCode::from(2);
                            }
                        };
                    let complete = state
                        .cases
                        .iter()
                        .filter(|case| case.status == intermed_lab::CampaignCaseStatus::Complete)
                        .count();
                    let infrastructure = state
                        .cases
                        .iter()
                        .filter(|case| {
                            case.status == intermed_lab::CampaignCaseStatus::InfrastructureFailure
                        })
                        .count();
                    let harness = state
                        .cases
                        .iter()
                        .filter(|case| {
                            case.status == intermed_lab::CampaignCaseStatus::HarnessFailure
                        })
                        .count();
                    // Use the report's canonical status accounting rather than
                    // duplicating the compatibility mapping for legacy
                    // `skipped` and current `static-complete` states here.
                    let static_only = campaign_report.static_only;
                    let unfinished = state
                        .cases
                        .iter()
                        .filter(|case| {
                            matches!(
                                case.status,
                                intermed_lab::CampaignCaseStatus::Pending
                                    | intermed_lab::CampaignCaseStatus::Running
                            )
                        })
                        .count();
                    println!("InterMed Lab — campaign");
                    println!("Campaign: {}", state.campaign_id);
                    println!(
                        "Cases: {} | runtime complete: {} | static-only: {} | infrastructure: {} | harness: {} | unfinished: {}",
                        state.cases.len(),
                        complete,
                        static_only,
                        infrastructure,
                        harness,
                        unfinished
                    );
                    println!("State: {}/campaign-state.json", args.out.display());
                    println!(
                        "Evaluation: {} FP | {} inconclusive | {} abstained",
                        campaign_report.false_positive,
                        campaign_report.inconclusive_coverage,
                        campaign_report.abstained
                    );
                    println!(
                        "Static: {} reports | {} confirmed | {} review | {} incomplete",
                        campaign_report.static_totals.reports,
                        campaign_report.static_totals.confirmed_problems,
                        campaign_report.static_totals.needs_review,
                        campaign_report.static_totals.incomplete_analysis
                    );
                    println!("Report: {}/campaign-report.html", args.out.display());
                    if infrastructure == 0 && harness == 0 && unfinished == 0 {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(2)
                    }
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(2)
                }
            }
        }
        LabCommand::Capture(args) => {
            let cfg = match IntermedConfig::load(config_path) {
                Ok(cfg) => cfg,
                Err(error) => {
                    eprintln!("error: {error}");
                    return ExitCode::from(2);
                }
            };
            match intermed_lab::capture_log(
                &args.log,
                &args.environment,
                args.exit_code,
                args.timed_out,
                args.max_bytes.unwrap_or(cfg.lab.max_log_bytes),
                &args.out,
            ) {
                Ok(raw) => {
                    let observation = intermed_lab::observe_smoke(&raw);
                    println!("InterMed Lab — captured runtime evidence");
                    println!("Status: {:?}", observation.status);
                    println!(
                        "Incidents: {} | background events: {} | log complete: {}",
                        observation.incidents.len(),
                        observation.background_events.len(),
                        observation.coverage.log_complete
                    );
                    println!("Written: {}", args.out.display());
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::from(2)
                }
            }
        }
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
                "Category co-occurrence — macro precision: {} | recall: {}",
                metric(report.macro_precision_category),
                metric(report.macro_recall_category)
            );
            for c in &report.by_category {
                println!(
                    "  {:<24} precision {} recall {} (tp {} fp {} fn {}, n={}) → suggest {}",
                    c.category,
                    metric(c.precision),
                    metric(c.recall),
                    c.true_positive,
                    c.false_positive,
                    c.false_negative,
                    c.calibration_support,
                    c.suggested_severity,
                );
            }
            let fl = &report.finding_level;
            if fl.attributed || fl.coverage_aware {
                println!(
                    "Finding-level (attributed/coverage-aware) — precision: {} | recall: {} (tp {} fp {} fn {}, {} inconclusive, {} abstained; {} predictions / {} attributions)",
                    metric(fl.precision),
                    metric(fl.recall),
                    fl.true_positive,
                    fl.false_positive,
                    fl.false_negative,
                    fl.inconclusive_coverage,
                    fl.abstained,
                    fl.predictions,
                    fl.attributions,
                );
                if !report.by_rule.is_empty() {
                    println!(
                        "Per-rule — macro precision: {} | recall: {}",
                        metric(report.macro_precision_rule),
                        metric(report.macro_recall_rule)
                    );
                    for r in &report.by_rule {
                        println!(
                            "  {:<24} precision {} recall {} (tp {} fp {} fn {}, n={}) → suggest {}",
                            r.rule_id,
                            metric(r.precision),
                            metric(r.recall),
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

fn metric(value: Option<f64>) -> String {
    value.map_or_else(|| "N/A".to_string(), |value| format!("{value:.2}"))
}
