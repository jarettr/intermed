//! Output persistence for `intermed doctor`: DuckDB run storage and the
//! `--dump-facts` / `--profile` JSON exports.
//!
//! Extracted from the CLI composition root so `main` stays an orchestrator. All
//! writers go through [`write_atomic`](intermed_doctor_core::write_atomic) so an
//! interrupted run never leaves a half-written artifact.

use std::path::Path;

use intermed_doctor_core::facts::Fact;
use intermed_doctor_core::{write_atomic, DiagnosticProfile, DiagnosticRun};

/// Persist the run to DuckDB. Returns `Err` with a message when the requested
/// write could not be completed, so the caller can fail the command — a `--db`
/// the user asked for is a contract, not best-effort, unless they opt out.
pub(crate) fn persist_duckdb_run(path: &Path, run: &DiagnosticRun) -> Result<(), String> {
    #[cfg(feature = "duckdb")]
    {
        let store = intermed_duckdb::DuckStore::open(path)
            .map_err(|e| format!("could not open duckdb store {}: {e}", path.display()))?;
        let run_id = store
            .persist_run(&run.report, &run.facts)
            .map_err(|e| format!("could not persist duckdb run: {e}"))?;
        eprintln!(
            "duckdb: persisted run {run_id} ({} facts, {} findings) to {}",
            run.facts.len(),
            run.report.findings.len(),
            path.display()
        );
        Ok(())
    }
    #[cfg(not(feature = "duckdb"))]
    {
        let _ = run;
        Err(format!(
            "--db {} requires building with --features duckdb",
            path.display()
        ))
    }
}

/// Write the run's fact snapshot as pretty JSON (`--dump-facts`).
pub(crate) fn write_facts(path: &Path, facts: &[Fact]) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(facts)?;
    write_atomic(path, json.as_bytes())?;
    Ok(())
}

/// Write the run's diagnostic profile as pretty JSON (`--profile`).
pub(crate) fn write_profile(
    path: &Path,
    profile: &DiagnosticProfile,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(profile)?;
    write_atomic(path, json.as_bytes())?;
    Ok(())
}
