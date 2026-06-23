//! Arrow C Data Interface bridge (plan Phase 1, "C-Data Interface (FFI)").
//!
//! The whole point of the columnar projection is zero-copy hand-off to engines in
//! other languages — DuckDB's C API and Souffle's generated C++. The Arrow C Data
//! Interface is the ABI-stable vehicle: a `RecordBatch` is exported as
//! `(FFI_ArrowArray, FFI_ArrowSchema)` C structs whose pointers any Arrow-aware
//! consumer can import without copying the buffers.
//!
//! Here we wrap the round-trip through the C structs so it can be exercised in pure
//! Rust (proving the buffers survive an FFI boundary); the host-function plumbing
//! into DuckDB/Souffle is the (deferred) integration step that consumes these.

use arrow::array::{Array, ArrayRef, StructArray};
use arrow::ffi::{FFI_ArrowArray, FFI_ArrowSchema, from_ffi, to_ffi};
use arrow::record_batch::RecordBatch;

use crate::error::ColumnarError;

/// Export a [`RecordBatch`] as the Arrow C Data Interface pair. The returned C
/// structs own the (reference-counted) buffers; passing their addresses to a C/C++
/// consumer is the zero-copy hand-off.
pub fn export_batch(
    batch: &RecordBatch,
) -> Result<(FFI_ArrowArray, FFI_ArrowSchema), ColumnarError> {
    let array: ArrayRef = std::sync::Arc::new(StructArray::from(batch.clone()));
    let data = array.to_data();
    Ok(to_ffi(&data)?)
}

/// Import a [`RecordBatch`] back from an Arrow C Data Interface pair — the inverse of
/// [`export_batch`], used to prove the buffers cross the FFI boundary intact.
pub fn import_batch(
    array: FFI_ArrowArray,
    schema: &FFI_ArrowSchema,
) -> Result<RecordBatch, ColumnarError> {
    // SAFETY: `array` and `schema` form a valid C Data Interface pair produced by
    // `export_batch` (or any conformant Arrow producer). `from_ffi` takes ownership
    // of `array` and reads `schema` by reference, per the Arrow contract.
    let data = unsafe { from_ffi(array, schema)? };
    let struct_array = StructArray::from(data);
    Ok(RecordBatch::from(struct_array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::{batches_to_facts, facts_to_batches};
    use intermed_facts::{FactStore, SourceRef};

    #[test]
    fn record_batch_survives_the_c_data_interface() {
        let mut store = FactStore::new();
        store
            .fact("c", "mod")
            .subject("create")
            .attr("k", "v")
            .attr("n", 7i64)
            .source(SourceRef::file("create.jar"))
            .emit();
        let batches = facts_to_batches(store.all(), "run-x").unwrap();

        // Export → import the facts batch across the FFI boundary.
        let (array, schema) = export_batch(&batches.facts).unwrap();
        let restored = import_batch(array, &schema).unwrap();
        assert_eq!(restored.num_rows(), batches.facts.num_rows());

        // And the attributes batch, then reconstruct the facts to prove fidelity.
        let (aarray, aschema) = export_batch(&batches.attributes).unwrap();
        let attrs = import_batch(aarray, &aschema).unwrap();
        let facts = batches_to_facts(&restored, &attrs).unwrap();
        assert_eq!(facts, store.all());
    }
}
