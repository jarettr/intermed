//! Arrow schemas for the columnar fact projection.
//!
//! These mirror the existing DuckDB relational schema (`facts` + `fact_attributes`,
//! a flat foreign-key design keyed on `fact_id`), so a [`RecordBatch`] produced here
//! maps 1:1 onto the DuckDB tables and can later be handed over zero-copy via the
//! Arrow C Data Interface — no separate INSERT generation. Nested attribute maps are
//! flattened into the `fact_attributes` side table rather than encoded as nested
//! JSON, exactly as the plan calls for.
//!
//! [`RecordBatch`]: arrow::record_batch::RecordBatch

use std::sync::Arc;

use arrow::datatypes::{DataType, Field, Schema};

/// The `facts` columnar schema (one row per fact). Column order and nullability
/// match the DuckDB `facts` table.
pub fn facts_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("run_id", DataType::Utf8, false),
        Field::new("fact_id", DataType::UInt64, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("subject", DataType::Utf8, false),
        Field::new("confidence", DataType::Float32, false),
        Field::new("extractor", DataType::Utf8, false),
        Field::new("source_locator", DataType::Utf8, false),
        Field::new("source_line", DataType::Int32, true),
        Field::new("source_inner", DataType::Utf8, true),
    ]))
}

/// The `fact_attributes` columnar schema (one row per `(fact, key)`). A typed
/// attribute is stored in exactly one of the `val_*` columns; the rest are null,
/// and `val_type` records which one is populated.
pub fn fact_attributes_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("run_id", DataType::Utf8, false),
        Field::new("fact_id", DataType::UInt64, false),
        Field::new("key", DataType::Utf8, false),
        Field::new("val_type", DataType::Utf8, false),
        Field::new("val_str", DataType::Utf8, true),
        Field::new("val_int", DataType::Int64, true),
        Field::new("val_float", DataType::Float64, true),
        Field::new("val_bool", DataType::Boolean, true),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemas_match_duckdb_column_layout() {
        let f = facts_schema();
        assert_eq!(
            f.fields()
                .iter()
                .map(|x| x.name().as_str())
                .collect::<Vec<_>>(),
            vec![
                "run_id",
                "fact_id",
                "kind",
                "subject",
                "confidence",
                "extractor",
                "source_locator",
                "source_line",
                "source_inner",
            ]
        );
        // Nullability matches the DuckDB DDL (only source_line/source_inner null).
        assert!(!f.field(0).is_nullable());
        assert!(f.field(7).is_nullable());
        assert!(f.field(8).is_nullable());

        let a = fact_attributes_schema();
        assert_eq!(a.fields().len(), 8);
        assert!(a.field(4).is_nullable()); // val_str
        assert!(!a.field(2).is_nullable()); // key
    }
}
