use crate::*;

pub(crate) fn run_spark_map(args: SparkMapArgs) -> ExitCode {
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
fn print_spark_import(import: &intermed_spark_bridge::SparkImport) {
    println!("InterMed Spark Map");
    println!("Target: {}", import.target);
    println!("Reports: {}", import.reports.len());
    println!("Import failures: {}", import.failures.len());
    for (i, report) in import.reports.iter().enumerate() {
        println!();
        println!("Report #{i}: {}", report.source_locator);
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
