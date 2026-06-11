//! # intermed-lab — Phase 8 (operations, not diagnosis)
//!
//! Compatibility Lab — the long-term moat. Fetches a mod corpus, locks it,
//! bootstraps server/client environments, runs smoke tests, classifies
//! failures, and emits a compatibility matrix + static site. Future commands:
//! `intermed lab discover`, `intermed lab run corpus.lock`,
//! `intermed lab report ./runs/latest`.
//!
//! **Donors:** `ModrinthClient` (corpus selection: 50% downloads / 25% follows
//! / 25% updated, dedupe by project id), `CorpusLock`, `EnvironmentBootstrap`,
//! `FabricServerInstaller`/`ForgeServerInstaller`/`NeoForgeServerInstaller`,
//! `ServerProcessRunner`, `CompatibilityMatrix`, `HtmlReportWriter`.
//!
//! This is an orchestration crate (network + process management), not a
//! read-only [`Collector`]; it runs under explicit `lab` subcommands.
//!
//! [`Collector`]: intermed_doctor_core::Collector

/// Implementation status for the CLI's `--list-layers` / help output.
pub const STATUS: &str = "deferred: Phase 8";
