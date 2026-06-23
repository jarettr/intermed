//! Error type for the columnar layer.

/// Failures projecting facts to/from the columnar form.
#[derive(Debug, thiserror::Error)]
pub enum ColumnarError {
    /// An Arrow-level error (array construction, batch shape, FFI).
    #[error("arrow: {0}")]
    Arrow(#[from] arrow::error::ArrowError),
    /// A schema/column shape mismatch while reading a batch back.
    #[error("schema: {0}")]
    Schema(String),
    /// An internal invariant was violated — e.g. the physical plan lowered an
    /// aggregate/window node into a state the executor's dispatch considers
    /// impossible. Returned instead of panicking so a planner bug surfaces as a
    /// query error rather than taking down the process.
    #[error("internal: {0}")]
    Internal(String),
}
