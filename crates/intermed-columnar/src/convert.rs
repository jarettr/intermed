//! Conversion between the row-oriented [`Fact`] model and the columnar Arrow form.
//!
//! This is a *projection*: it reads an existing `&[Fact]` snapshot read-only
//! (collectors still own the row model) and produces two [`RecordBatch`]es.
//! [`facts_to_batches`] is the export; [`batches_to_facts`] is the inverse, used by
//! the regression harness to prove the columnar form is lossless.

use std::collections::BTreeMap;
use std::sync::Arc;

use arrow::array::{
    Array, BooleanArray, BooleanBuilder, Float32Array, Float32Builder, Float64Array,
    Float64Builder, Int32Array, Int32Builder, Int64Array, Int64Builder, StringArray, StringBuilder,
    UInt64Array, UInt64Builder,
};
use arrow::record_batch::RecordBatch;
use intermed_facts::{AttrValue, Fact, FactId, SourceRef};

use crate::error::ColumnarError;
use crate::schema::{fact_attributes_schema, facts_schema};

/// The two columnar tables a set of facts projects to.
pub struct FactBatches {
    /// One row per fact (`facts` schema).
    pub facts: RecordBatch,
    /// One row per `(fact, attribute)` (`fact_attributes` schema).
    pub attributes: RecordBatch,
}

/// The `val_type` discriminator stored in `fact_attributes`.
fn attr_type_str(v: &AttrValue) -> &'static str {
    match v {
        AttrValue::Str(_) => "str",
        AttrValue::Int(_) => "int",
        AttrValue::Float(_) => "float",
        AttrValue::Bool(_) => "bool",
    }
}

/// Project a slice of facts into the columnar [`FactBatches`].
pub fn facts_to_batches(facts: &[Fact], run_id: &str) -> Result<FactBatches, ColumnarError> {
    // ── facts table ────────────────────────────────────────────────────────
    let mut run = StringBuilder::new();
    let mut id = UInt64Builder::new();
    let mut kind = StringBuilder::new();
    let mut subject = StringBuilder::new();
    let mut confidence = Float32Builder::new();
    let mut extractor = StringBuilder::new();
    let mut locator = StringBuilder::new();
    let mut line = Int32Builder::new();
    let mut inner = StringBuilder::new();

    // ── fact_attributes table ──────────────────────────────────────────────
    let mut a_run = StringBuilder::new();
    let mut a_id = UInt64Builder::new();
    let mut a_key = StringBuilder::new();
    let mut a_type = StringBuilder::new();
    let mut a_str = StringBuilder::new();
    let mut a_int = Int64Builder::new();
    let mut a_float = Float64Builder::new();
    let mut a_bool = BooleanBuilder::new();

    for fact in facts {
        run.append_value(run_id);
        id.append_value(fact.id.0);
        kind.append_value(&fact.kind);
        subject.append_value(&fact.subject);
        confidence.append_value(fact.confidence);
        extractor.append_value(&fact.extractor);
        locator.append_value(&fact.source.locator);
        line.append_option(fact.source.line.map(|l| l as i32));
        inner.append_option(fact.source.inner.as_deref());

        // BTreeMap iteration is sorted, so attribute row order is deterministic.
        for (key, val) in &fact.attributes {
            a_run.append_value(run_id);
            a_id.append_value(fact.id.0);
            a_key.append_value(key);
            a_type.append_value(attr_type_str(val));
            match val {
                AttrValue::Str(s) => {
                    a_str.append_value(s);
                    a_int.append_null();
                    a_float.append_null();
                    a_bool.append_null();
                }
                AttrValue::Int(i) => {
                    a_str.append_null();
                    a_int.append_value(*i);
                    a_float.append_null();
                    a_bool.append_null();
                }
                AttrValue::Float(f) => {
                    a_str.append_null();
                    a_int.append_null();
                    a_float.append_value(*f);
                    a_bool.append_null();
                }
                AttrValue::Bool(b) => {
                    a_str.append_null();
                    a_int.append_null();
                    a_float.append_null();
                    a_bool.append_value(*b);
                }
            }
        }
    }

    let facts = RecordBatch::try_new(
        facts_schema(),
        vec![
            Arc::new(run.finish()),
            Arc::new(id.finish()),
            Arc::new(kind.finish()),
            Arc::new(subject.finish()),
            Arc::new(confidence.finish()),
            Arc::new(extractor.finish()),
            Arc::new(locator.finish()),
            Arc::new(line.finish()),
            Arc::new(inner.finish()),
        ],
    )?;
    let attributes = RecordBatch::try_new(
        fact_attributes_schema(),
        vec![
            Arc::new(a_run.finish()),
            Arc::new(a_id.finish()),
            Arc::new(a_key.finish()),
            Arc::new(a_type.finish()),
            Arc::new(a_str.finish()),
            Arc::new(a_int.finish()),
            Arc::new(a_float.finish()),
            Arc::new(a_bool.finish()),
        ],
    )?;

    Ok(FactBatches { facts, attributes })
}

/// Downcast helper returning a typed array column or a schema error.
fn col<'a, T: 'static>(
    batch: &'a RecordBatch,
    idx: usize,
    what: &str,
) -> Result<&'a T, ColumnarError> {
    batch
        .column(idx)
        .as_any()
        .downcast_ref::<T>()
        .ok_or_else(|| ColumnarError::Schema(format!("column {idx} is not a {what}")))
}

/// Reconstruct the row-oriented facts from the two columnar batches. The inverse of
/// [`facts_to_batches`] — round-tripping a fact set through this must be identity,
/// which is what the regression harness asserts.
pub fn batches_to_facts(
    facts: &RecordBatch,
    attributes: &RecordBatch,
) -> Result<Vec<Fact>, ColumnarError> {
    let id = col::<UInt64Array>(facts, 1, "UInt64Array")?;
    let kind = col::<StringArray>(facts, 2, "StringArray")?;
    let subject = col::<StringArray>(facts, 3, "StringArray")?;
    let confidence = col::<Float32Array>(facts, 4, "Float32Array")?;
    let extractor = col::<StringArray>(facts, 5, "StringArray")?;
    let locator = col::<StringArray>(facts, 6, "StringArray")?;
    let line = col::<Int32Array>(facts, 7, "Int32Array")?;
    let inner = col::<StringArray>(facts, 8, "StringArray")?;

    // First pass: collect attributes keyed by fact id.
    let a_id = col::<UInt64Array>(attributes, 1, "UInt64Array")?;
    let a_key = col::<StringArray>(attributes, 2, "StringArray")?;
    let a_type = col::<StringArray>(attributes, 3, "StringArray")?;
    let a_str = col::<StringArray>(attributes, 4, "StringArray")?;
    let a_int = col::<Int64Array>(attributes, 5, "Int64Array")?;
    let a_float = col::<Float64Array>(attributes, 6, "Float64Array")?;
    let a_bool = col::<BooleanArray>(attributes, 7, "BooleanArray")?;

    let mut attrs_by_fact: BTreeMap<u64, BTreeMap<String, AttrValue>> = BTreeMap::new();
    for r in 0..attributes.num_rows() {
        let val = match a_type.value(r) {
            "str" => AttrValue::Str(a_str.value(r).to_string()),
            "int" => AttrValue::Int(a_int.value(r)),
            "float" => AttrValue::Float(a_float.value(r)),
            "bool" => AttrValue::Bool(a_bool.value(r)),
            other => return Err(ColumnarError::Schema(format!("unknown val_type `{other}`"))),
        };
        attrs_by_fact
            .entry(a_id.value(r))
            .or_default()
            .insert(a_key.value(r).to_string(), val);
    }

    let mut out = Vec::with_capacity(facts.num_rows());
    for r in 0..facts.num_rows() {
        let fid = id.value(r);
        out.push(Fact {
            id: FactId(fid),
            kind: kind.value(r).to_string(),
            subject: subject.value(r).to_string(),
            attributes: attrs_by_fact.remove(&fid).unwrap_or_default(),
            source: SourceRef {
                locator: locator.value(r).to_string(),
                line: if line.is_null(r) {
                    None
                } else {
                    Some(line.value(r) as u32)
                },
                inner: if inner.is_null(r) {
                    None
                } else {
                    Some(inner.value(r).to_string())
                },
            },
            confidence: confidence.value(r),
            extractor: extractor.value(r).to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_facts::FactStore;

    fn sample_facts() -> Vec<Fact> {
        let mut store = FactStore::new();
        store
            .fact("collector-a", "mod")
            .subject("sodium")
            .attr("version", "0.5.13")
            .attr("priority", 1000i64)
            .attr("client", true)
            .attr("cpu", 12.5f64)
            .source(SourceRef::inside("sodium.jar", "fabric.mod.json"))
            .emit();
        store
            .fact("collector-b", "environment")
            .subject("")
            .source(SourceRef::at_line("latest.log", 42))
            .emit();
        // A fact with no attributes and a bare file source.
        store
            .fact("collector-c", "mixin_overlap")
            .subject("net.minecraft.Foo")
            .emit();
        store.all().to_vec()
    }

    #[test]
    fn round_trip_is_lossless() {
        let original = sample_facts();
        let batches = facts_to_batches(&original, "run-1").unwrap();
        assert_eq!(batches.facts.num_rows(), original.len());
        // 4 attributes on fact 0, 0 on the others.
        assert_eq!(batches.attributes.num_rows(), 4);

        let restored = batches_to_facts(&batches.facts, &batches.attributes).unwrap();
        assert_eq!(restored, original, "columnar round-trip must be identity");
    }

    #[test]
    fn typed_attributes_land_in_the_right_column() {
        let facts = sample_facts();
        let b = facts_to_batches(&facts, "run-1").unwrap();
        let types = col::<StringArray>(&b.attributes, 3, "StringArray").unwrap();
        let seen: std::collections::BTreeSet<&str> = (0..b.attributes.num_rows())
            .map(|r| types.value(r))
            .collect();
        assert_eq!(seen, ["bool", "float", "int", "str"].into_iter().collect());
    }

    #[test]
    fn empty_fact_set_produces_empty_batches() {
        let b = facts_to_batches(&[], "run-1").unwrap();
        assert_eq!(b.facts.num_rows(), 0);
        assert_eq!(b.attributes.num_rows(), 0);
        assert!(
            batches_to_facts(&b.facts, &b.attributes)
                .unwrap()
                .is_empty()
        );
    }
}
