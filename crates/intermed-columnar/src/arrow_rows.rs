//! Reading an Arrow [`RecordBatch`] back into the engine's row form.
//!
//! Both accelerated backends that return Arrow results — DuckDB (`intermed-duckdb`'s
//! `DuckIrEngine`) and DataFusion ([`crate::datafusion_backend`]) — need to turn a
//! result batch into `Vec<`[`Row`]`>`. This is the single shared implementation so the
//! conversion is defined in exactly one place (no per-backend copies to drift). It
//! covers the Arrow types those engines emit for our queries: strings (`Utf8`,
//! `Utf8View`, `LargeUtf8`), the integer/float widths, and booleans.
//!
//! [`RecordBatch`]: arrow::record_batch::RecordBatch

use arrow::array::{
    Array, BooleanArray, Float32Array, Float64Array, Int32Array, Int64Array, LargeStringArray,
    StringArray, StringViewArray, UInt32Array, UInt64Array,
};
use arrow::record_batch::RecordBatch;

use crate::value::{Row, Value};

/// Read one Arrow cell at row `r` as a [`Value`]. Unmodeled types fall back to their
/// debug form rather than dropping data.
pub fn cell(col: &dyn Array, r: usize) -> Value {
    if col.is_null(r) {
        return Value::Null;
    }
    if let Some(a) = col.as_any().downcast_ref::<StringArray>() {
        Value::Str(a.value(r).to_string())
    } else if let Some(a) = col.as_any().downcast_ref::<StringViewArray>() {
        Value::Str(a.value(r).to_string())
    } else if let Some(a) = col.as_any().downcast_ref::<LargeStringArray>() {
        Value::Str(a.value(r).to_string())
    } else if let Some(a) = col.as_any().downcast_ref::<Int64Array>() {
        Value::Int(a.value(r))
    } else if let Some(a) = col.as_any().downcast_ref::<UInt64Array>() {
        Value::Int(a.value(r) as i64)
    } else if let Some(a) = col.as_any().downcast_ref::<Int32Array>() {
        Value::Int(a.value(r) as i64)
    } else if let Some(a) = col.as_any().downcast_ref::<UInt32Array>() {
        Value::Int(a.value(r) as i64)
    } else if let Some(a) = col.as_any().downcast_ref::<Float64Array>() {
        Value::Float(a.value(r))
    } else if let Some(a) = col.as_any().downcast_ref::<Float32Array>() {
        Value::Float(a.value(r) as f64)
    } else if let Some(a) = col.as_any().downcast_ref::<BooleanArray>() {
        Value::Bool(a.value(r))
    } else {
        Value::Str(format!("{:?}", col.data_type()))
    }
}

/// Convert a whole [`RecordBatch`] into rows keyed by column name.
pub fn record_batch_to_rows(batch: &RecordBatch) -> Vec<Row> {
    let schema = batch.schema();
    let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
    (0..batch.num_rows())
        .map(|r| {
            names
                .iter()
                .enumerate()
                .map(|(c, name)| (name.to_string(), cell(batch.column(c).as_ref(), r)))
                .collect::<Row>()
        })
        .collect()
}
