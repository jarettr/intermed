//! # intermed-duckdb — Layer J SQL backend + columnar analytics store
//!
//! Appendix B.2 realization: facts materialize into DuckDB relations, core rules
//! run as vectorized SQL JOINs, and full runs persist for cross-run analytics.
//!
//! Embedded DuckDB is **feature-gated** (`duckdb` feature, off by default) so
//! default workspace builds never compile the bundled C++ engine.

pub mod schema;
pub use schema::EVAL_RUN_ID;
pub mod sql;

#[cfg(feature = "duckdb")]
pub mod analytics;

#[cfg(feature = "duckdb")]
pub mod store;

pub mod rules;

pub use rules::{duckdb_available, DuckdbRulePack};

#[cfg(feature = "duckdb")]
pub use analytics::{
    parse_since, AnalyticsError, AnalyticsStore, HistoryDiffReport, HistoryDiffSummary,
    MixinOverlapRank, MixinRiskTrendPoint, RecurringConflict, RunDeltaKind, RunFindingDelta,
    RunSummary,
};

#[cfg(feature = "duckdb")]
pub use store::{DuckError, DuckStore, QueryResult};

/// Core SQL rule ids evaluated by [`DuckdbRulePack`] (see `sql::CORE_RULES`).
pub const CORE_SQL_RULES: &[&str] = sql::CORE_RULES;

/// Implementation status for help text.
pub const STATUS: &str =
    "active: SQL rule backend (11 core rules) + analytics store + history/trends (feature `duckdb`, off by default)";