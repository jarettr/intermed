//! In-process executor for the relational IR over the columnar fact store.
//!
//! This is the "in-process Datalog / base predicates" engine of the plan: it
//! evaluates a [`RelExpr`] against the Arrow [`FactBatches`] columns and returns a
//! materialized [`Relation`]. It is dependency-free (no DuckDB/Souffle), so it runs
//! everywhere and is the correctness reference the accelerated backends are validated
//! against.
//!
//! **Execution model (plan Phase 1).** A logical [`RelExpr`] is lowered to a
//! [`PhysicalPlan`](crate::physical::PhysicalPlan) of concrete operators, then run by
//! a streaming (Volcano) engine.
//!
//! - *Positional tuples (Phase 1.3).* Internally a row is a positional
//!   [`Tuple`] (`Vec<Value>`) addressed by a shared column [`Schema`], not a
//!   string-keyed `BTreeMap`. A scan row is one allocation instead of a tree of
//!   nodes + key strings; a join merge is a positional concat instead of per-key map
//!   inserts. The public [`Row`]/[`Relation`] (a `BTreeMap`) is reconstructed only
//!   when the final result is materialized, so the widely-consumed public API is
//!   unchanged.
//! - *Streaming.* `Scan → Filter → Project` chains flow tuple-by-tuple without
//!   materializing every stage.
//! - *Hashing.* Joins use a **hash join** (build a hash table from the smaller side,
//!   stream + probe the other), aggregation a **hash aggregate** — `O(n+m)` rather
//!   than the old nested-loop / row-at-a-time `O(n·m)`.
//!
//! Recursion ([`RelExpr::TransitiveClosure`]) is an in-process fixpoint — a correct
//! fallback for the construct the router would route to Souffle.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use arrow::array::{
    Array, BooleanArray, Float32Array, Float64Array, Int32Array, Int64Array, StringArray,
    UInt64Array,
};

use intermed_facts::Fact;

use crate::convert::FactBatches;
use crate::cost::Statistics;
use crate::error::ColumnarError;
use crate::external::FunctionRegistry;
use crate::ir::{
    AggFunc, Aggregate, CmpOp, Condition, Predicate, RelExpr, ScalarValue, WindowFn, WindowFunction,
};
use crate::physical::{self, BuildSide, PhysicalPlan};
use crate::strategy::ExecutionStrategy;
use crate::value::{Relation, Row, Value};

/// The base (non-attribute) columns every fact row carries, in fixed schema order.
const BASE_COLS: [&str; 8] = [
    "fact_id",
    "kind",
    "subject",
    "confidence",
    "extractor",
    "source_locator",
    "source_line",
    "source_inner",
];

/// A positional row: values aligned to a [`Schema`]. One allocation per row (vs the
/// public `BTreeMap` `Row`, which the executor reconstructs only at the boundary).
pub(crate) type Tuple = Vec<Value>;

/// A column schema for a batch of [`Tuple`]s: position → name plus a name → position
/// index for column lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Schema {
    names: Vec<String>,
    index: AHashMap<String, usize>,
}

impl Schema {
    fn new(names: Vec<String>) -> Self {
        // First occurrence of a name wins (duplicate names can only arise from an
        // adversarial column literally named like a join-collision alias).
        let mut index = AHashMap::with_capacity(names.len());
        for (i, n) in names.iter().enumerate() {
            index.entry(n.clone()).or_insert(i);
        }
        Schema { names, index }
    }

    fn pos(&self, name: &str) -> Option<usize> {
        self.index.get(name).copied()
    }
}

/// A materialized batch held by the store: a shared schema + its positional rows.
pub(crate) struct Batch {
    schema: Arc<Schema>,
    rows: Vec<Tuple>,
}

/// A fact pending placement into its kind's batch: base values + its attributes
/// (attribute keys that collide with a base column are dropped — base wins). Shared by
/// the Arrow (`from_batches`) and direct (`from_facts`) store builders.
struct Pending {
    base: [Value; 8],
    attrs: AHashMap<String, Value>,
}

impl Batch {
    /// Position of a column in this batch's schema, if present.
    pub(crate) fn pos(&self, name: &str) -> Option<usize> {
        self.schema.pos(name)
    }
    /// All column names (base + attribute) in schema order.
    pub(crate) fn names(&self) -> &[String] {
        &self.schema.names
    }
    /// The batch's positional rows.
    pub(crate) fn rows(&self) -> &[Tuple] {
        &self.rows
    }
}

/// A queryable, in-memory view built once from the columnar [`FactBatches`]: facts
/// grouped by kind, each kind a [`Batch`] with a fixed schema (base columns + the
/// union of attribute keys seen in that kind) and positional rows.
pub struct ColumnarStore {
    by_kind: BTreeMap<String, Batch>,
}

impl ColumnarStore {
    /// Build the queryable view from the Arrow batches (reads the columnar buffers).
    pub fn from_batches(batches: &FactBatches) -> Result<Self, ColumnarError> {
        let facts = &batches.facts;
        let attrs = &batches.attributes;

        // Resolve attributes per fact id first.
        let a_id = downcast::<UInt64Array>(attrs, 1)?;
        let a_key = downcast::<StringArray>(attrs, 2)?;
        let a_type = downcast::<StringArray>(attrs, 3)?;
        let a_str = downcast::<StringArray>(attrs, 4)?;
        let a_int = downcast::<Int64Array>(attrs, 5)?;
        let a_float = downcast::<Float64Array>(attrs, 6)?;
        let a_bool = downcast::<BooleanArray>(attrs, 7)?;
        let mut attrs_by_fact: AHashMap<u64, Vec<(String, Value)>> = AHashMap::new();
        for r in 0..attrs.num_rows() {
            let v = match a_type.value(r) {
                "str" => Value::Str(a_str.value(r).to_string()),
                "int" => Value::Int(a_int.value(r)),
                "float" => Value::Float(a_float.value(r)),
                "bool" => Value::Bool(a_bool.value(r)),
                other => return Err(ColumnarError::Schema(format!("unknown val_type `{other}`"))),
            };
            attrs_by_fact
                .entry(a_id.value(r))
                .or_default()
                .push((a_key.value(r).to_string(), v));
        }

        let id = downcast::<UInt64Array>(facts, 1)?;
        let kind = downcast::<StringArray>(facts, 2)?;
        let subject = downcast::<StringArray>(facts, 3)?;
        let confidence = downcast::<Float32Array>(facts, 4)?;
        let extractor = downcast::<StringArray>(facts, 5)?;
        let locator = downcast::<StringArray>(facts, 6)?;
        let line = downcast::<Int32Array>(facts, 7)?;
        let inner = downcast::<StringArray>(facts, 8)?;

        let base_set: AHashSet<&str> = BASE_COLS.into_iter().collect();
        let mut kind_facts: BTreeMap<String, Vec<Pending>> = BTreeMap::new();
        let mut kind_attr_keys: BTreeMap<String, AHashSet<String>> = BTreeMap::new();

        for r in 0..facts.num_rows() {
            let fid = id.value(r);
            let base = [
                Value::Int(fid as i64),
                Value::Str(kind.value(r).to_string()),
                Value::Str(subject.value(r).to_string()),
                Value::Float(confidence.value(r) as f64),
                Value::Str(extractor.value(r).to_string()),
                Value::Str(locator.value(r).to_string()),
                if line.is_null(r) {
                    Value::Null
                } else {
                    Value::Int(line.value(r) as i64)
                },
                if inner.is_null(r) {
                    Value::Null
                } else {
                    Value::Str(inner.value(r).to_string())
                },
            ];
            let mut attrs: AHashMap<String, Value> = AHashMap::new();
            if let Some(list) = attrs_by_fact.get(&fid) {
                for (k, v) in list {
                    if base_set.contains(k.as_str()) {
                        continue;
                    }
                    attrs.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
            let k = kind.value(r).to_string();
            let keyset = kind_attr_keys.entry(k.clone()).or_default();
            for key in attrs.keys() {
                keyset.insert(key.clone());
            }
            kind_facts
                .entry(k)
                .or_default()
                .push(Pending { base, attrs });
        }

        Ok(ColumnarStore::assemble(kind_facts, kind_attr_keys))
    }

    /// Build the queryable view **directly** from `&[Fact]`, skipping the Arrow
    /// projection entirely (plan Phase 1). `from_batches` round-trips
    /// `Fact → RecordBatch → rows`, which is pure overhead for the in-process engine —
    /// the Arrow form is only needed by the DuckDB / DataFusion backends. This builds
    /// the identical store (same per-kind schemas + positional rows) reading facts once.
    pub fn from_facts(facts: &[Fact]) -> Self {
        Self::from_facts_for_kinds(facts, None)
    }

    /// Like [`from_facts`](Self::from_facts), but only materializes facts whose kind is
    /// in `kinds` (plan Phase 2: demand-driven build). The engine passes the set of
    /// kinds the rule plans actually scan, so high-volume kinds nothing queries (e.g.
    /// `resource_reference`) are skipped entirely — the dominant build-cost win. A kind
    /// absent from the store scans as empty, which is exactly correct for an unscanned
    /// kind. `None` for `kinds` builds everything (same as `from_facts`).
    pub fn from_facts_for_kinds(facts: &[Fact], kinds: Option<&BTreeSet<String>>) -> Self {
        let base_set: AHashSet<&str> = BASE_COLS.into_iter().collect();
        let mut kind_facts: BTreeMap<String, Vec<Pending>> = BTreeMap::new();
        let mut kind_attr_keys: BTreeMap<String, AHashSet<String>> = BTreeMap::new();

        for f in facts {
            if let Some(keep) = kinds
                && !keep.contains(f.kind.as_str())
            {
                continue;
            }
            let base = [
                Value::Int(f.id.0 as i64),
                Value::Str(f.kind.to_string()),
                Value::Str(f.subject.to_string()),
                Value::Float(f.confidence as f64),
                Value::Str(f.extractor.to_string()),
                Value::Str(f.source.locator.to_string()),
                match f.source.line {
                    Some(l) => Value::Int(l as i64),
                    None => Value::Null,
                },
                match &f.source.inner {
                    Some(s) => Value::Str(s.clone()),
                    None => Value::Null,
                },
            ];
            let mut attrs: AHashMap<String, Value> = AHashMap::with_capacity(f.attributes.len());
            for (k, v) in &f.attributes {
                if base_set.contains(k.as_str()) {
                    continue;
                }
                attrs.insert(k.to_string(), Value::from_attr(v));
            }
            let keyset = kind_attr_keys.entry(f.kind.to_string()).or_default();
            for key in attrs.keys() {
                keyset.insert(key.clone());
            }
            kind_facts
                .entry(f.kind.to_string())
                .or_default()
                .push(Pending { base, attrs });
        }

        ColumnarStore::assemble(kind_facts, kind_attr_keys)
    }

    /// Assemble per-kind [`Batch`]es from pending facts: schema = base columns + the
    /// sorted union of attribute keys seen in that kind; rows = positional tuples
    /// (missing attributes become `Null`). Shared by [`from_batches`] (Arrow path) and
    /// [`from_facts`] (direct path) so both produce a byte-identical store.
    fn assemble(
        kind_facts: BTreeMap<String, Vec<Pending>>,
        mut kind_attr_keys: BTreeMap<String, AHashSet<String>>,
    ) -> Self {
        let mut by_kind: BTreeMap<String, Batch> = BTreeMap::new();
        for (kind_name, pending) in kind_facts {
            let mut attr_names: Vec<String> = kind_attr_keys
                .remove(&kind_name)
                .unwrap_or_default()
                .into_iter()
                .collect();
            attr_names.sort();

            let mut names: Vec<String> = BASE_COLS.iter().map(|s| s.to_string()).collect();
            names.extend(attr_names.iter().cloned());
            let schema = Arc::new(Schema::new(names));

            let rows = pending
                .into_iter()
                .map(|p| {
                    let mut tuple: Tuple = p.base.into();
                    for name in &attr_names {
                        tuple.push(p.attrs.get(name).cloned().unwrap_or(Value::Null));
                    }
                    tuple
                })
                .collect();
            by_kind.insert(kind_name, Batch { schema, rows });
        }
        ColumnarStore { by_kind }
    }

    /// The materialized batch for a kind, if any facts of that kind were projected.
    /// The FastRow strategy reads this directly (positional indexing, no streaming).
    pub(crate) fn batch(&self, kind: &str) -> Option<&Batch> {
        self.by_kind.get(kind)
    }

    /// Catalog statistics for the optimizer: per-kind row counts and column schemas.
    pub fn statistics(&self) -> Statistics {
        let mut rows = HashMap::new();
        let mut cols = HashMap::new();
        for (kind, batch) in &self.by_kind {
            rows.insert(kind.clone(), batch.rows.len() as f64);
            cols.insert(kind.clone(), batch.schema.names.iter().cloned().collect());
        }
        Statistics::new(rows, cols)
    }
}

fn downcast<T: 'static>(
    batch: &arrow::record_batch::RecordBatch,
    idx: usize,
) -> Result<&T, ColumnarError> {
    use arrow::array::Array;
    batch
        .column(idx)
        .as_any()
        .downcast_ref::<T>()
        .ok_or_else(|| ColumnarError::Schema(format!("column {idx} has unexpected array type")))
}

/// A streaming operator's output: its schema plus a Volcano iterator over tuples.
struct RowStream<'a> {
    schema: Arc<Schema>,
    iter: Box<dyn Iterator<Item = Tuple> + 'a>,
}

mod aggregate;
mod closure;
mod join;
mod run;

use aggregate::{compute_window, hash_aggregate};
pub(crate) use aggregate::{eval_cmp, scalar_to_value};
use closure::transitive_closure;
use join::{
    HashKey, concat, group_count_distinct, hash_join, join_filter, join_schema, relation_to_stream,
};
use run::stream;
pub use run::{
    count_physical, execute, execute_physical, execute_strategy, execute_strategy_with_stats,
    execute_with, execute_with_stats,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert::facts_to_batches;
    use crate::ir::{CmpOp, Predicate, ScalarValue};
    use intermed_facts::FactStore;
    use std::collections::BTreeSet;

    fn store() -> ColumnarStore {
        let mut s = FactStore::new();
        s.fact("c", "mixin_application_site")
            .subject("a")
            .attr("operation", "redirect")
            .attr("target_class", "net.minecraft.Foo")
            .emit();
        s.fact("c", "mixin_application_site")
            .subject("b")
            .attr("operation", "inject")
            .attr("target_class", "net.minecraft.Foo")
            .emit();
        s.fact("c", "mixin_application_site")
            .subject("d")
            .attr("operation", "redirect")
            .attr("target_class", "net.minecraft.Bar")
            .emit();
        let batches = facts_to_batches(s.all(), "r").unwrap();
        ColumnarStore::from_batches(&batches).unwrap()
    }

    fn eq(col: &str, v: &str) -> Predicate {
        Predicate {
            column: col.into(),
            op: CmpOp::Eq,
            value: ScalarValue::Str(v.into()),
        }
    }

    /// Phase 1: the direct `from_facts` store must be byte-identical to the Arrow
    /// round-trip `from_batches` store — same rows for every kind, including base
    /// columns, attribute padding, `Null`s, and ordering.
    #[test]
    fn from_facts_equals_from_batches() {
        let mut s = FactStore::new();
        s.fact("c", "mod")
            .subject("sodium")
            .attr("loader", "fabric")
            .attr("priority", 5_i64)
            .confidence(0.9)
            .source(intermed_facts::SourceRef::at_line("a.json", 12))
            .emit();
        s.fact("c", "mod")
            .subject("create")
            .attr("loader", "forge")
            .attr("enabled", true)
            .emit();
        s.fact("c", "mixin_application_site")
            .subject("owo")
            .attr("operation", "overwrite")
            .emit();

        let arrow = ColumnarStore::from_batches(&facts_to_batches(s.all(), "r").unwrap()).unwrap();
        let direct = ColumnarStore::from_facts(s.all());

        // Same kinds.
        let arrow_kinds: Vec<&String> = arrow.by_kind.keys().collect();
        let direct_kinds: Vec<&String> = direct.by_kind.keys().collect();
        assert_eq!(arrow_kinds, direct_kinds);
        // Same schema names + same rows per kind.
        for (k, ab) in &arrow.by_kind {
            let db = direct.by_kind.get(k).expect("kind present");
            assert_eq!(ab.schema.names, db.schema.names, "schema differs for {k}");
            assert_eq!(ab.rows, db.rows, "rows differ for {k}");
        }
    }

    #[test]
    fn scan_filter_project() {
        let plan = RelExpr::scan("mixin_application_site")
            .filter(eq("operation", "redirect"))
            .project(vec!["subject".into(), "target_class".into()]);
        let r = execute(&plan, &store()).unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.rows.iter().all(|row| row.contains_key("target_class")));
        assert!(r.rows.iter().all(|row| !row.contains_key("operation")));
    }

    #[test]
    fn aggregate_counts_per_group() {
        let plan = RelExpr::scan("mixin_application_site").aggregate(
            vec!["target_class".into()],
            vec![Aggregate {
                func: AggFunc::Count,
                column: String::new(),
                alias: "n".into(),
            }],
        );
        let r = execute(&plan, &store()).unwrap();
        // Foo (2) and Bar (1).
        let foo = r
            .rows
            .iter()
            .find(|row| {
                row.get("target_class").and_then(Value::as_str) == Some("net.minecraft.Foo")
            })
            .unwrap();
        assert_eq!(foo.get("n"), Some(&Value::Int(2)));
    }

    #[test]
    fn aggregate_composite_key_has_no_delimiter_collision() {
        let mut facts = FactStore::new();
        facts
            .fact("test", "pair")
            .subject("left")
            .attr("a", "x\u{1}y")
            .attr("b", "z")
            .emit();
        facts
            .fact("test", "pair")
            .subject("right")
            .attr("a", "x")
            .attr("b", "y\u{1}z")
            .emit();
        let store = ColumnarStore::from_facts(facts.all());
        let plan = RelExpr::scan("pair").aggregate(
            vec!["a".into(), "b".into()],
            vec![Aggregate {
                func: AggFunc::Count,
                column: String::new(),
                alias: "n".into(),
            }],
        );

        let result = execute(&plan, &store).unwrap();
        assert_eq!(result.len(), 2);
        assert!(
            result
                .rows
                .iter()
                .all(|row| row.get("n") == Some(&Value::Int(1)))
        );
    }

    #[test]
    fn having_via_filter_on_aggregate() {
        // group → count, then keep groups with count >= 2.
        let plan = RelExpr::scan("mixin_application_site")
            .aggregate(
                vec!["target_class".into()],
                vec![Aggregate {
                    func: AggFunc::Count,
                    column: String::new(),
                    alias: "n".into(),
                }],
            )
            .filter(Predicate {
                column: "n".into(),
                op: CmpOp::Ge,
                value: ScalarValue::Int(2),
            });
        let r = execute(&plan, &store()).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.rows[0].get("target_class").and_then(Value::as_str),
            Some("net.minecraft.Foo")
        );
    }

    #[test]
    fn transitive_closure_finds_indirect_reachability() {
        // a→b, b→c ⇒ closure adds a→c.
        let mut s = FactStore::new();
        for (m, dep) in [("a", "b"), ("b", "c"), ("c", "d")] {
            s.fact("deps", "dependency")
                .subject(m)
                .attr("mod", m)
                .attr("requires", dep)
                .emit();
        }
        let batches = facts_to_batches(s.all(), "r").unwrap();
        let store = ColumnarStore::from_batches(&batches).unwrap();
        let plan = RelExpr::scan("dependency").transitive_closure("mod", "requires");
        let r = execute(&plan, &store).unwrap();
        // a reaches b, c, d.
        let from_a: BTreeSet<&str> = r
            .rows
            .iter()
            .filter(|row| row.get("mod").and_then(Value::as_str) == Some("a"))
            .filter_map(|row| row.get("requires").and_then(Value::as_str))
            .collect();
        assert_eq!(from_a, ["b", "c", "d"].into_iter().collect());
    }

    #[test]
    fn join_merges_matching_rows() {
        let plan = RelExpr::scan("mixin_application_site").join(
            RelExpr::scan("mixin_application_site"),
            vec![("target_class".into(), "target_class".into())],
        );
        // Foo×Foo (2×2=4) + Bar×Bar (1) = 5 self-join rows.
        let r = execute(&plan, &store()).unwrap();
        assert_eq!(r.len(), 5);
    }

    #[test]
    fn hash_join_does_not_match_null_keys() {
        let mut s = FactStore::new();
        s.fact("left", "left_rel")
            .subject("left-null")
            .attr("other", "present")
            .emit();
        s.fact("left", "left_rel")
            .subject("left-x")
            .attr("key", "x")
            .emit();
        s.fact("right", "right_rel")
            .subject("right-null")
            .attr("other", "present")
            .emit();
        s.fact("right", "right_rel")
            .subject("right-x")
            .attr("key", "x")
            .emit();
        let store = ColumnarStore::from_facts(s.all());

        let plan = RelExpr::scan("left_rel").join(
            RelExpr::scan("right_rel"),
            vec![("key".into(), "key".into())],
        );
        let r = execute(&plan, &store).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.rows[0].get("subject").and_then(Value::as_str),
            Some("left-x")
        );
        assert_eq!(
            r.rows[0].get("right.subject").and_then(Value::as_str),
            Some("right-x")
        );
    }

    #[test]
    fn ne_filter_does_not_match_null() {
        let mut s = FactStore::new();
        s.fact("meta", "mod")
            .subject("missing-loader")
            .attr("file", "a.jar")
            .emit();
        s.fact("meta", "mod")
            .subject("forge")
            .attr("loader", "forge")
            .emit();
        let store = ColumnarStore::from_facts(s.all());

        let plan = RelExpr::scan("mod")
            .filter(Predicate {
                column: "loader".into(),
                op: CmpOp::Ne,
                value: ScalarValue::Str("fabric".into()),
            })
            .project(vec!["subject".into()]);
        let r = execute(&plan, &store).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.rows[0].get("subject").and_then(Value::as_str),
            Some("forge")
        );
    }

    #[test]
    fn hash_join_output_independent_of_build_side() {
        // The merged column layout must not depend on which side builds the table.
        let s = store();
        let on = vec![("target_class".to_string(), "target_class".to_string())];
        let scan = || PhysicalPlan::Scan {
            kind: "mixin_application_site".into(),
        };
        let build_right = PhysicalPlan::HashJoin {
            left: Box::new(scan()),
            right: Box::new(scan()),
            on: on.clone(),
            build_side: BuildSide::Right,
        };
        let build_left = PhysicalPlan::HashJoin {
            left: Box::new(scan()),
            right: Box::new(scan()),
            on,
            build_side: BuildSide::Left,
        };
        let mut a = execute_physical(&build_right, &s).unwrap().rows;
        let mut b = execute_physical(&build_left, &s).unwrap().rows;
        assert_eq!(a.len(), 5);
        assert_eq!(b.len(), 5);
        a.sort_by_key(row_signature);
        b.sort_by_key(row_signature);
        assert_eq!(a, b);
    }

    fn row_signature(row: &Row) -> String {
        row.iter()
            .map(|(k, v)| format!("{k}={}", v.to_display()))
            .collect::<Vec<_>>()
            .join("|")
    }

    #[test]
    fn window_row_number_and_partition_sum() {
        use crate::ir::{WindowFn, WindowFunction};

        let mut s = FactStore::new();
        // class A: 10, 30, 20 ; class B: 5
        for (c, p) in [("A", 10), ("A", 30), ("A", 20), ("B", 5)] {
            s.fact("spark", "hot_method")
                .subject(format!("{c}{p}"))
                .attr("class", c)
                .attr("percent", p)
                .emit();
        }
        let batches = facts_to_batches(s.all(), "r").unwrap();
        let store = ColumnarStore::from_batches(&batches).unwrap();

        let plan = RelExpr::scan("hot_method").window(
            vec!["class".into()],
            vec!["percent".into()],
            vec![
                WindowFunction {
                    func: WindowFn::RowNumber,
                    column: String::new(),
                    alias: "rn".into(),
                },
                WindowFunction {
                    func: WindowFn::Sum,
                    column: "percent".into(),
                    alias: "class_total".into(),
                },
            ],
        );
        let r = execute(&plan, &store).unwrap();
        assert_eq!(r.len(), 4); // window does not collapse rows

        // In class A, percent=30 is the 3rd row by ascending percent (rn=3); total=60.
        let top_a = r
            .rows
            .iter()
            .find(|row| {
                row.get("class").and_then(Value::as_str) == Some("A")
                    && row.get("percent") == Some(&Value::Int(30))
            })
            .unwrap();
        assert_eq!(top_a.get("rn"), Some(&Value::Int(3)));
        assert_eq!(top_a.get("class_total"), Some(&Value::Float(60.0)));

        // Class B has a single row: rn=1, total=5.
        let b = r
            .rows
            .iter()
            .find(|row| row.get("class").and_then(Value::as_str) == Some("B"))
            .unwrap();
        assert_eq!(b.get("rn"), Some(&Value::Int(1)));
        assert_eq!(b.get("class_total"), Some(&Value::Float(5.0)));
    }

    #[test]
    fn join_filter_runs_in_process() {
        use crate::ir::Condition;
        let mut s = FactStore::new();
        s.fact("meta", "mod")
            .subject("m1")
            .attr("loader", "fabric")
            .emit();
        s.fact("meta", "mod")
            .subject("m2")
            .attr("loader", "forge")
            .emit();
        s.fact("env", "environment")
            .subject("server")
            .attr("loader", "forge")
            .emit();
        let batches = facts_to_batches(s.all(), "r").unwrap();
        let store = ColumnarStore::from_batches(&batches).unwrap();

        // mods whose loader differs from the environment's loader.
        let plan = RelExpr::JoinFilter {
            left_kind: "mod".into(),
            left_alias: "m".into(),
            right_kind: "environment".into(),
            right_alias: "e".into(),
            condition: Condition::ColCmp {
                left: "m.loader".into(),
                op: CmpOp::Ne,
                right: "e.loader".into(),
            },
        };
        let r = execute(&plan, &store).unwrap();
        // Only m1 (fabric ≠ forge) matches; m2 (forge == forge) does not.
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.rows[0].get("left_subject").and_then(Value::as_str),
            Some("m1")
        );
        assert_eq!(
            r.rows[0].get("right_subject").and_then(Value::as_str),
            Some("server")
        );
    }

    #[test]
    fn join_filter_does_not_match_null_equality_or_inequality() {
        use crate::ir::Condition;
        let mut s = FactStore::new();
        s.fact("meta", "mod")
            .subject("missing-loader")
            .attr("file", "a.jar")
            .emit();
        s.fact("meta", "mod")
            .subject("fabric-mod")
            .attr("loader", "fabric")
            .emit();
        s.fact("env", "environment")
            .subject("missing-env-loader")
            .attr("side", "server")
            .emit();
        s.fact("env", "environment")
            .subject("forge-env")
            .attr("loader", "forge")
            .emit();
        let store = ColumnarStore::from_facts(s.all());

        let eq_plan = RelExpr::JoinFilter {
            left_kind: "mod".into(),
            left_alias: "m".into(),
            right_kind: "environment".into(),
            right_alias: "e".into(),
            condition: Condition::ColCmp {
                left: "m.loader".into(),
                op: CmpOp::Eq,
                right: "e.loader".into(),
            },
        };
        assert!(execute(&eq_plan, &store).unwrap().is_empty());

        let ne_plan = RelExpr::JoinFilter {
            left_kind: "mod".into(),
            left_alias: "m".into(),
            right_kind: "environment".into(),
            right_alias: "e".into(),
            condition: Condition::ColCmp {
                left: "m.loader".into(),
                op: CmpOp::Ne,
                right: "e.loader".into(),
            },
        };
        let r = execute(&ne_plan, &store).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.rows[0].get("left_subject").and_then(Value::as_str),
            Some("fabric-mod")
        );
        assert_eq!(
            r.rows[0].get("right_subject").and_then(Value::as_str),
            Some("forge-env")
        );
    }

    #[test]
    fn group_count_distinct_runs_in_process() {
        let mut s = FactStore::new();
        // `foo` ships in two distinct files (duplicate); `bar` in one.
        s.fact("meta", "mod")
            .subject("foo")
            .attr("loader", "fabric")
            .attr("file", "a.jar")
            .emit();
        s.fact("meta", "mod")
            .subject("foo")
            .attr("loader", "fabric")
            .attr("file", "b.jar")
            .emit();
        s.fact("meta", "mod")
            .subject("bar")
            .attr("loader", "forge")
            .attr("file", "c.jar")
            .emit();
        let batches = facts_to_batches(s.all(), "r").unwrap();
        let store = ColumnarStore::from_batches(&batches).unwrap();

        let plan = RelExpr::GroupCountDistinct {
            kinds: vec!["mod".into()],
            group_col: "loader".into(),
            distinct_attr: "file".into(),
            filters: vec![],
            min_count: 2,
        };
        let r = execute(&plan, &store).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.rows[0].get("loader").and_then(Value::as_str),
            Some("fabric")
        );

        let missing_group = RelExpr::GroupCountDistinct {
            kinds: vec!["mod".into()],
            group_col: "not_present".into(),
            distinct_attr: "file".into(),
            filters: vec![],
            min_count: 2,
        };
        assert!(execute(&missing_group, &store).unwrap().is_empty());
    }

    #[test]
    fn call_external_invokes_a_registered_function() {
        use crate::external::{ExternalFunction, FunctionRegistry};

        // A function that keeps only rows whose `operation` is "redirect".
        struct OnlyRedirects;
        impl ExternalFunction for OnlyRedirects {
            fn name(&self) -> &str {
                "only-redirects"
            }
            fn call(&self, input: &Relation) -> Result<Relation, ColumnarError> {
                let rows = input
                    .rows
                    .iter()
                    .filter(|r| r.get("operation").and_then(Value::as_str) == Some("redirect"))
                    .cloned()
                    .collect();
                Ok(Relation::new(rows))
            }
        }

        let mut registry = FunctionRegistry::new();
        registry.register(Box::new(OnlyRedirects));

        let plan = RelExpr::scan("mixin_application_site").call_external("only-redirects");
        let r = execute_with(&plan, &store(), &registry).unwrap();
        // 2 of 3 facts are redirects.
        assert_eq!(r.len(), 2);
        assert!(
            r.rows
                .iter()
                .all(|row| row.get("operation").and_then(Value::as_str) == Some("redirect"))
        );

        // Unregistered module is not the identity transform.
        let err = execute(
            &RelExpr::scan("mixin_application_site").call_external("missing"),
            &store(),
        )
        .unwrap_err();
        assert!(matches!(err, ColumnarError::MissingExternalModule(name) if name == "missing"));
    }
}
