//! Columnar (Apache Arrow) fact projection + relational query engine.
//!
//! This is the in-process query engine behind `--logic columnar`, the default rule
//! backend. It reads a `&[Fact]` snapshot and projects it into Arrow
//! [`RecordBatch`]es, then runs the declarative rule IR over them (optimizing
//! logical/physical planner, hash join / aggregate, FastRow and Vectorized
//! strategies). Collectors still emit the row-oriented `Fact` model; this crate
//! projects from it read-only, and the round-trip is exact, so the columnar form is
//! verifiably lossless.
//!
//! - [`schema`] — Arrow schemas mirroring the DuckDB `facts` / `fact_attributes`
//!   relational layout (flat foreign-key design, not nested JSON).
//! - [`convert`] — `&[Fact]` ⇄ [`RecordBatch`] projection. The inverse is exact, so a
//!   round-trip is the regression check that the columnar form is lossless.
//! - [`ffi`] — Arrow C Data Interface export/import: the ABI-stable, zero-copy
//!   hand-off vehicle for DuckDB (C API) and Souffle (generated C++).
//! - [`ir`] — the relational query IR ([`RelExpr`]) and the capability analyzer that
//!   tags a plan with the engines it requires (in-process Datalog / DuckDB / Souffle
//!   / WASM) for the query router.
//!
//! Not yet built: collectors emitting Arrow builders directly, live DuckDB
//! `arrow_scan` ingestion, and the `ascent`/`wasmtime` engines (additive backends
//! behind their own features). The DuckDB and Souffle backends already run over the
//! same IR, via `intermed-duckdb` and `intermed-rules`.
//!
//! [`RecordBatch`]: arrow::record_batch::RecordBatch
//! [`RelExpr`]: ir::RelExpr

pub mod arrow_rows;
pub mod backend;
pub mod convert;
pub mod cost;
pub mod datalog;
pub mod engine;
pub mod error;
pub mod executor;
pub mod explain;
pub mod external;
pub mod fast_row;
pub mod ffi;
pub mod frontend;
pub mod incremental;
pub mod ir;
pub mod optimizer;
pub mod physical;
pub mod regression;
pub mod router;
pub mod schema;
pub mod sql;
pub mod strategy;
pub mod value;

#[cfg(feature = "wasm")]
pub mod wasm;
#[cfg(feature = "wasm")]
pub use wasm::WasmFunction;

#[cfg(feature = "datafusion-backend")]
pub mod datafusion_backend;
#[cfg(feature = "datafusion-backend")]
pub use datafusion_backend::DataFusionBackend;

#[cfg(feature = "polars-backend")]
pub mod polars_backend;
#[cfg(feature = "polars-backend")]
pub use polars_backend::PolarsBackend;

#[cfg(feature = "ascent-backend")]
pub mod ascent_backend;
#[cfg(feature = "ascent-backend")]
pub use ascent_backend::AscentClosureBackend;

pub use arrow_rows::record_batch_to_rows;
pub use backend::{InProcessBackend, QueryBackend};
pub use convert::{FactBatches, batches_to_facts, facts_to_batches};
pub use cost::{Cost, CostModel, HeuristicCostModel, Statistics, cardinality};
pub use datalog::{FACT_SCHEMA, to_datalog};
pub use engine::QueryEngine;
pub use error::ColumnarError;
pub use executor::{
    ColumnarStore, count_physical, execute, execute_physical, execute_strategy, execute_with,
};
pub use explain::{explain, explain_analyze};
pub use external::{ExternalFunction, FunctionRegistry};
pub use ffi::{export_batch, import_batch};
pub use frontend::QuerySpec;
pub use incremental::{execute_incremental, is_incrementally_maintainable};
pub use ir::{Capabilities, Engine, RelExpr, analyze};
pub use optimizer::optimize;
pub use physical::{BuildSide, PhysicalPlan, plan as plan_physical};
pub use regression::{Divergence, assert_lossless, round_trip_divergences};
pub use router::{ExecutionPlan, Stage, plan};
pub use schema::{fact_attributes_schema, facts_schema};
pub use sql::to_sql;
pub use strategy::{ExecutionStrategy, is_fast_row_eligible, select_strategy};
pub use value::{Relation, Row, Value};
