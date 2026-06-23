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
    AggFunc, Aggregate, CmpOp, Condition, RelExpr, ScalarValue, WindowFn, WindowFunction,
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
            if let Some(keep) = kinds {
                if !keep.contains(&f.kind) {
                    continue;
                }
            }
            let base = [
                Value::Int(f.id.0 as i64),
                Value::Str(f.kind.clone()),
                Value::Str(f.subject.clone()),
                Value::Float(f.confidence as f64),
                Value::Str(f.extractor.clone()),
                Value::Str(f.source.locator.clone()),
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
                attrs.insert(k.clone(), Value::from_attr(v));
            }
            let keyset = kind_attr_keys.entry(f.kind.clone()).or_default();
            for key in attrs.keys() {
                keyset.insert(key.clone());
            }
            kind_facts
                .entry(f.kind.clone())
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

/// Evaluate a logical plan against the store, fully materializing the result.
///
/// Optimizes `expr` (Phase 2), lowers it to a [`PhysicalPlan`], runs the streaming
/// engine, and reconstructs the public `BTreeMap`-backed [`Relation`]. The entry
/// point and result type are unchanged — the internals moved to a logical optimizer
/// + physical operators + positional tuples + streaming + hashing.
pub fn execute(expr: &RelExpr, store: &ColumnarStore) -> Result<Relation, ColumnarError> {
    execute_with(expr, store, &FunctionRegistry::empty())
}

/// Like [`execute`], but with external functions available to `CallExternal` nodes.
pub fn execute_with(
    expr: &RelExpr,
    store: &ColumnarStore,
    registry: &FunctionRegistry,
) -> Result<Relation, ColumnarError> {
    let stats = store.statistics();
    let optimized = crate::optimizer::optimize(expr, &stats);
    let phys = physical::plan(&optimized, &stats);
    run_physical(&phys, store, registry, ExecutionStrategy::Auto)
}

/// Execute under an **explicit** [`ExecutionStrategy`](crate::strategy::ExecutionStrategy)
/// — for debugging, benchmarking, or forcing a path. The result is identical to
/// [`execute`] regardless of strategy (the strategies are proven equivalent); only the
/// execution path differs. `FastRow` runs the fast path when the plan is eligible and
/// otherwise safely degrades to the streaming engine.
pub fn execute_strategy(
    expr: &RelExpr,
    store: &ColumnarStore,
    strategy: ExecutionStrategy,
) -> Result<Relation, ColumnarError> {
    let stats = store.statistics();
    let optimized = crate::optimizer::optimize(expr, &stats);
    let phys = physical::plan(&optimized, &stats);
    let registry = FunctionRegistry::empty();
    run_physical(&phys, store, &registry, strategy)
}

/// Run an already-lowered physical plan, resolving `strategy` against it: the
/// **FastRow** path for a linear `Scan → Filter* → Project` pipeline, the **Vectorized**
/// streaming engine for everything else. The two produce identical results (FastRow
/// reuses the same comparison primitives), so this is purely a performance routing
/// decision. `FastRow` that turns out ineligible degrades to streaming.
fn run_physical(
    phys: &PhysicalPlan,
    store: &ColumnarStore,
    registry: &FunctionRegistry,
    strategy: ExecutionStrategy,
) -> Result<Relation, ColumnarError> {
    match strategy.resolve(phys) {
        ExecutionStrategy::FastRow => match crate::fast_row::execute_fast_row(phys, store) {
            Some(rel) => Ok(rel),
            None => Ok(materialize(stream(phys, store, registry)?)),
        },
        ExecutionStrategy::Vectorized | ExecutionStrategy::Auto => {
            Ok(materialize(stream(phys, store, registry)?))
        }
    }
}

/// Run an already-lowered physical plan, materializing its output.
pub fn execute_physical(
    plan: &PhysicalPlan,
    store: &ColumnarStore,
) -> Result<Relation, ColumnarError> {
    let registry = FunctionRegistry::empty();
    let out = stream(plan, store, &registry)?;
    Ok(materialize(out))
}

/// Count the rows a physical (sub)plan produces, without building the public
/// `BTreeMap` rows — used by `EXPLAIN ANALYZE` to report actual per-stage
/// cardinalities cheaply.
pub fn count_physical(plan: &PhysicalPlan, store: &ColumnarStore) -> Result<usize, ColumnarError> {
    let registry = FunctionRegistry::empty();
    let out = stream(plan, store, &registry)?;
    Ok(out.iter.count())
}

/// Reconstruct the public `BTreeMap`-backed [`Relation`] from a tuple stream. All
/// schema columns are emitted (including `Null`), so no data is silently dropped.
fn materialize(out: RowStream<'_>) -> Relation {
    let names = out.schema.names.clone();
    let rows = out
        .iter
        .map(|tuple| names.iter().cloned().zip(tuple).collect::<Row>())
        .collect();
    Relation::new(rows)
}

/// Build the Volcano iterator for a physical operator. The engine is relationally
/// complete (every operator is implemented), so the yielded items are infallible
/// tuples; the `Result` wraps only construction-time store errors.
fn stream<'a>(
    plan: &'a PhysicalPlan,
    store: &'a ColumnarStore,
    registry: &'a FunctionRegistry,
) -> Result<RowStream<'a>, ColumnarError> {
    match plan {
        PhysicalPlan::Scan { kind } => match store.by_kind.get(kind) {
            Some(batch) => Ok(RowStream {
                schema: batch.schema.clone(),
                iter: Box::new(batch.rows.iter().cloned()),
            }),
            None => Ok(RowStream {
                schema: Arc::new(Schema::new(Vec::new())),
                iter: Box::new(std::iter::empty()),
            }),
        },
        PhysicalPlan::Filter { input, predicate } => {
            let inner = stream(input, store, registry)?;
            let pos = inner.schema.pos(&predicate.column);
            let op = predicate.op;
            let rhs = scalar_to_value(&predicate.value);
            let schema = inner.schema.clone();
            let iter = inner.iter.filter(move |tuple| {
                let lhs = pos.and_then(|i| tuple.get(i)).unwrap_or(&Value::Null);
                eval_cmp(lhs, op, &rhs)
            });
            Ok(RowStream {
                schema,
                iter: Box::new(iter),
            })
        }
        PhysicalPlan::Project { input, columns } => {
            let inner = stream(input, store, registry)?;
            let positions: Vec<Option<usize>> =
                columns.iter().map(|c| inner.schema.pos(c)).collect();
            let schema = Arc::new(Schema::new(columns.clone()));
            let iter = inner.iter.map(move |tuple| {
                positions
                    .iter()
                    .map(|p| p.and_then(|i| tuple.get(i).cloned()).unwrap_or(Value::Null))
                    .collect::<Tuple>()
            });
            Ok(RowStream {
                schema,
                iter: Box::new(iter),
            })
        }
        PhysicalPlan::HashJoin {
            left,
            right,
            on,
            build_side,
        } => hash_join(left, right, on, *build_side, store, registry),
        PhysicalPlan::NestedLoopJoin { left, right } => {
            let left_stream = stream(left, store, registry)?;
            let right_stream = stream(right, store, registry)?;
            let schema = join_schema(&left_stream.schema, &right_stream.schema);
            let right_rows: Vec<Tuple> = right_stream.iter.collect();
            let iter = left_stream.iter.flat_map(move |l| {
                right_rows
                    .iter()
                    .map(|r| concat(&l, r))
                    .collect::<Vec<_>>()
                    .into_iter()
            });
            Ok(RowStream {
                schema,
                iter: Box::new(iter),
            })
        }
        PhysicalPlan::HashAggregate {
            input,
            group_by,
            aggregates,
        } => hash_aggregate(input, group_by, aggregates, store, registry),
        PhysicalPlan::Window {
            input,
            partition_by,
            order_by,
            functions,
        } => {
            let inner = stream(input, store, registry)?;
            let ppos: Vec<Option<usize>> =
                partition_by.iter().map(|c| inner.schema.pos(c)).collect();
            let opos: Vec<Option<usize>> = order_by.iter().map(|c| inner.schema.pos(c)).collect();
            let fpos: Vec<Option<usize>> = functions
                .iter()
                .map(|f| inner.schema.pos(&f.column))
                .collect();
            let mut names = inner.schema.names.clone();
            names.extend(functions.iter().map(|f| f.alias.clone()));
            let rows: Vec<Tuple> = inner.iter.collect();
            let out = compute_window(rows, &ppos, &opos, &fpos, functions)?;
            Ok(RowStream {
                schema: Arc::new(Schema::new(names)),
                iter: Box::new(out.into_iter()),
            })
        }
        PhysicalPlan::TransitiveClosure { input, from, to } => {
            let inner = stream(input, store, registry)?;
            let fp = inner.schema.pos(from);
            let tp = inner.schema.pos(to);
            let rows = transitive_closure(inner.iter, fp, tp);
            let schema = Arc::new(Schema::new(vec![from.clone(), to.clone()]));
            Ok(RowStream {
                schema,
                iter: Box::new(rows.into_iter()),
            })
        }
        PhysicalPlan::CallExternal { input, module } => match registry.get(module) {
            // A registered function is a barrier: materialize the input, call the
            // function, and re-stream its result.
            Some(function) => {
                let input_rel = materialize(stream(input, store, registry)?);
                let out_rel = function.call(&input_rel)?;
                Ok(relation_to_stream(out_rel))
            }
            // No such module ⇒ pass tuples through unchanged (historical behavior; the
            // router would dispatch a real call to the WASM backend).
            None => stream(input, store, registry),
        },
        PhysicalPlan::JoinFilter {
            left_kind,
            left_alias,
            right_kind,
            right_alias,
            condition,
        } => Ok(join_filter(
            store,
            left_kind,
            left_alias,
            right_kind,
            right_alias,
            condition,
        )),
        PhysicalPlan::GroupCountDistinct {
            kinds,
            group_col,
            distinct_attr,
            min_count,
        } => Ok(group_count_distinct(
            store,
            kinds,
            group_col,
            distinct_attr,
            *min_count,
        )),
    }
}

/// Evaluate a [`Condition`] over a column resolver (returns `Null` for absent columns).
/// Matches the SQL rendering in `sql::condition_sql` and the engine's `Filter`
/// comparison semantics (stringly `Eq`/`Ne`, typed ranges) by reusing [`eval_cmp`].
fn eval_condition(cond: &Condition, resolve: &impl Fn(&str) -> Value) -> bool {
    match cond {
        Condition::True => true,
        Condition::Cmp { column, op, value } => {
            eval_cmp(&resolve(column), *op, &scalar_to_value(value))
        }
        Condition::ColCmp { left, op, right } => eval_cmp(&resolve(left), *op, &resolve(right)),
        Condition::In { column, values } => {
            let v = resolve(column);
            !v.is_null() && values.iter().any(|s| v.to_display() == *s)
        }
        Condition::NotNull { column } => !resolve(column).is_null(),
        Condition::IsNull { column } => resolve(column).is_null(),
        Condition::And(a, b) => eval_condition(a, resolve) && eval_condition(b, resolve),
        Condition::Or(a, b) => eval_condition(a, resolve) || eval_condition(b, resolve),
        Condition::Not(a) => !eval_condition(a, resolve),
    }
}

/// Declarative-rule join: cross two scanned kinds and keep rows satisfying `condition`
/// (alias-qualified). Output columns mirror the SQL form
/// (`left_fact_id`/`left_subject`/`right_fact_id`/`right_subject`).
fn join_filter<'a>(
    store: &'a ColumnarStore,
    left_kind: &str,
    left_alias: &str,
    right_kind: &str,
    right_alias: &str,
    condition: &Condition,
) -> RowStream<'a> {
    let lb = store.by_kind.get(left_kind);
    let rb = store.by_kind.get(right_kind);
    let empty = Arc::new(Schema::new(Vec::new()));
    let l_schema = lb
        .map(|b| b.schema.clone())
        .unwrap_or_else(|| empty.clone());
    let r_schema = rb.map(|b| b.schema.clone()).unwrap_or(empty);
    let l_rows: &[Tuple] = lb.map(|b| b.rows.as_slice()).unwrap_or(&[]);
    let r_rows: &[Tuple] = rb.map(|b| b.rows.as_slice()).unwrap_or(&[]);

    let pick = |schema: &Schema, t: &Tuple, col: &str| -> Value {
        schema
            .pos(col)
            .and_then(|i| t.get(i).cloned())
            .unwrap_or(Value::Null)
    };

    let mut out: Vec<Tuple> = Vec::new();
    for lt in l_rows {
        for rt in r_rows {
            let resolve = |name: &str| -> Value {
                let (alias, col) = name.split_once('.').unwrap_or(("", name));
                if alias == left_alias {
                    pick(&l_schema, lt, col)
                } else if alias == right_alias {
                    pick(&r_schema, rt, col)
                } else {
                    Value::Null
                }
            };
            if eval_condition(condition, &resolve) {
                out.push(vec![
                    pick(&l_schema, lt, "fact_id"),
                    pick(&l_schema, lt, "subject"),
                    pick(&r_schema, rt, "fact_id"),
                    pick(&r_schema, rt, "subject"),
                ]);
            }
        }
    }
    let schema = Arc::new(Schema::new(vec![
        "left_fact_id".into(),
        "left_subject".into(),
        "right_fact_id".into(),
        "right_subject".into(),
    ]));
    RowStream {
        schema,
        iter: Box::new(out.into_iter()),
    }
}

/// Group facts of any of `kinds` by subject; keep subjects whose distinct count of
/// `distinct_attr` is at least `min_count`. Output column `group_col` (= subject).
fn group_count_distinct<'a>(
    store: &'a ColumnarStore,
    kinds: &[String],
    group_col: &str,
    distinct_attr: &str,
    min_count: usize,
) -> RowStream<'a> {
    let mut index: AHashMap<String, usize> = AHashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut distinct: Vec<AHashSet<String>> = Vec::new();

    for kind in kinds {
        let Some(batch) = store.by_kind.get(kind) else {
            continue;
        };
        let subj_pos = batch.schema.pos("subject");
        let attr_pos = batch.schema.pos(distinct_attr);
        for t in &batch.rows {
            let subject = subj_pos
                .and_then(|i| t.get(i))
                .map(Value::to_display)
                .unwrap_or_default();
            let slot = *index.entry(subject.clone()).or_insert_with(|| {
                order.push(subject.clone());
                distinct.push(AHashSet::new());
                order.len() - 1
            });
            if let Some(v) = attr_pos.and_then(|i| t.get(i)) {
                if !v.is_null() {
                    distinct[slot].insert(v.to_display());
                }
            }
        }
    }

    let schema = Arc::new(Schema::new(vec![group_col.to_string()]));
    let rows: Vec<Tuple> = order
        .into_iter()
        .zip(distinct)
        .filter(|(_, set)| set.len() >= min_count)
        .map(|(subject, _)| vec![Value::Str(subject)])
        .collect();
    RowStream {
        schema,
        iter: Box::new(rows.into_iter()),
    }
}

/// A hashable, type-distinguishing key cell. Mirrors [`Value`] equality exactly
/// (`Int(2) != Float(2.0) != Str("2")`), so hash-join keys partition rows the same
/// way the old nested-loop `==` did. `Float` is keyed by bit pattern so it is `Eq`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum HashKey {
    Str(String),
    Int(i64),
    Bool(bool),
    Float(u64),
    Null,
}

fn hash_key(v: &Value) -> HashKey {
    match v {
        Value::Str(s) => HashKey::Str(s.clone()),
        Value::Int(i) => HashKey::Int(*i),
        Value::Bool(b) => HashKey::Bool(*b),
        Value::Float(f) => HashKey::Float(f.to_bits()),
        Value::Null => HashKey::Null,
    }
}

/// Compose the join key of a tuple over the given column positions (absent → `Null`).
fn key_of(tuple: &Tuple, positions: &[Option<usize>]) -> Vec<HashKey> {
    positions
        .iter()
        .map(|p| hash_key(p.and_then(|i| tuple.get(i)).unwrap_or(&Value::Null)))
        .collect()
}

/// The output schema of a join: left columns keep their names, right columns that
/// collide with a left name are prefixed `right.` (so no column is shadowed).
fn join_schema(left: &Schema, right: &Schema) -> Arc<Schema> {
    let left_set: AHashSet<&String> = left.names.iter().collect();
    let mut names = left.names.clone();
    for rn in &right.names {
        if left_set.contains(rn) {
            names.push(format!("right.{rn}"));
        } else {
            names.push(rn.clone());
        }
    }
    Arc::new(Schema::new(names))
}

/// Positional concat of a left tuple and a right tuple — the join's row merge. The
/// output layout matches [`join_schema`] (left values then right values).
fn concat(left: &Tuple, right: &Tuple) -> Tuple {
    let mut t = Vec::with_capacity(left.len() + right.len());
    t.extend_from_slice(left);
    t.extend_from_slice(right);
    t
}

/// Convert a public [`Relation`] back into a positional tuple stream — the inverse of
/// [`materialize`], used to re-stream an external function's result. The schema is the
/// sorted union of column names across the returned rows.
fn relation_to_stream<'a>(rel: Relation) -> RowStream<'a> {
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for row in &rel.rows {
        names.extend(row.keys().cloned());
    }
    let names: Vec<String> = names.into_iter().collect();
    let schema = Arc::new(Schema::new(names.clone()));
    let rows: Vec<Tuple> = rel
        .rows
        .into_iter()
        .map(|row| {
            names
                .iter()
                .map(|n| row.get(n).cloned().unwrap_or(Value::Null))
                .collect::<Tuple>()
        })
        .collect();
    RowStream {
        schema,
        iter: Box::new(rows.into_iter()),
    }
}

/// Hash equi-join. Builds a hash table from the `build_side` input keyed by its join
/// columns, then streams the probe side and emits merged rows for each match. The
/// output column layout is independent of which side is built.
fn hash_join<'a>(
    left: &'a PhysicalPlan,
    right: &'a PhysicalPlan,
    on: &'a [(String, String)],
    build_side: BuildSide,
    store: &'a ColumnarStore,
    registry: &'a FunctionRegistry,
) -> Result<RowStream<'a>, ColumnarError> {
    let left_stream = stream(left, store, registry)?;
    let right_stream = stream(right, store, registry)?;
    let out_schema = join_schema(&left_stream.schema, &right_stream.schema);

    let left_key_pos: Vec<Option<usize>> =
        on.iter().map(|(l, _)| left_stream.schema.pos(l)).collect();
    let right_key_pos: Vec<Option<usize>> =
        on.iter().map(|(_, r)| right_stream.schema.pos(r)).collect();

    let build_is_left = build_side == BuildSide::Left;
    let (build_stream, probe_stream, build_key_pos, probe_key_pos) = if build_is_left {
        (left_stream, right_stream, left_key_pos, right_key_pos)
    } else {
        (right_stream, left_stream, right_key_pos, left_key_pos)
    };

    // Build phase.
    let mut table: AHashMap<Vec<HashKey>, Vec<Tuple>> = AHashMap::new();
    for tuple in build_stream.iter {
        table
            .entry(key_of(&tuple, &build_key_pos))
            .or_default()
            .push(tuple);
    }

    // Probe phase: stream the probe side, merge respecting the logical left/right
    // relations (not the physical build/probe roles).
    let iter = probe_stream.iter.flat_map(move |ptuple| {
        let key = key_of(&ptuple, &probe_key_pos);
        match table.get(&key) {
            Some(bucket) => bucket
                .iter()
                .map(|btuple| {
                    if build_is_left {
                        concat(btuple, &ptuple)
                    } else {
                        concat(&ptuple, btuple)
                    }
                })
                .collect::<Vec<_>>()
                .into_iter(),
            None => Vec::new().into_iter(),
        }
    });

    Ok(RowStream {
        schema: out_schema,
        iter: Box::new(iter),
    })
}

pub(crate) fn scalar_to_value(s: &ScalarValue) -> Value {
    match s {
        ScalarValue::Str(s) => Value::Str(s.clone()),
        ScalarValue::Int(i) => Value::Int(*i),
        ScalarValue::Float(f) => Value::Float(*f),
        ScalarValue::Bool(b) => Value::Bool(*b),
    }
}

/// Equality with the declarative engine's stringly semantics: a `Null` (absent
/// attribute) never equals a literal, otherwise values compare by their display
/// string (matching `term_value` / `attr_value_string` in the rules interpreter), so
/// the IR engine selects exactly the facts the interpreter's `where_all`/`where_not`
/// would. Numeric comparisons (below) stay typed.
fn value_eq(lhs: &Value, rhs: &Value) -> bool {
    if lhs.is_null() {
        return false;
    }
    lhs == rhs || lhs.to_display() == rhs.to_display()
}

pub(crate) fn eval_cmp(lhs: &Value, op: CmpOp, rhs: &Value) -> bool {
    match op {
        CmpOp::Eq => value_eq(lhs, rhs),
        CmpOp::Ne => !value_eq(lhs, rhs),
        CmpOp::Lt => matches!(lhs.partial_cmp_value(rhs), Some(Ordering::Less)),
        CmpOp::Le => matches!(
            lhs.partial_cmp_value(rhs),
            Some(Ordering::Less | Ordering::Equal)
        ),
        CmpOp::Gt => matches!(lhs.partial_cmp_value(rhs), Some(Ordering::Greater)),
        CmpOp::Ge => matches!(
            lhs.partial_cmp_value(rhs),
            Some(Ordering::Greater | Ordering::Equal)
        ),
    }
}

/// Group key for aggregation. Uses the display string (matching the prior executor),
/// so e.g. numeric/string forms of a group value collapse together as before.
fn group_key(tuple: &Tuple, positions: &[Option<usize>]) -> String {
    positions
        .iter()
        .map(|p| {
            p.and_then(|i| tuple.get(i))
                .map(Value::to_display)
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join("\u{1}")
}

/// Hash aggregation. Groups are accumulated in a hash table keyed by the group
/// columns; first-seen group order is preserved for deterministic output.
fn hash_aggregate<'a>(
    input: &'a PhysicalPlan,
    group_by: &'a [String],
    aggregates: &'a [Aggregate],
    store: &'a ColumnarStore,
    registry: &'a FunctionRegistry,
) -> Result<RowStream<'a>, ColumnarError> {
    let inner = stream(input, store, registry)?;
    let group_pos: Vec<Option<usize>> = group_by.iter().map(|c| inner.schema.pos(c)).collect();
    let agg_pos: Vec<Option<usize>> = aggregates
        .iter()
        .map(|a| inner.schema.pos(&a.column))
        .collect();

    // Group key → slot in `order`, so output is first-seen order.
    let mut index: AHashMap<String, usize> = AHashMap::new();
    let mut order: Vec<Vec<Tuple>> = Vec::new();
    for tuple in inner.iter {
        let key = group_key(&tuple, &group_pos);
        match index.get(&key) {
            Some(&slot) => order[slot].push(tuple),
            None => {
                index.insert(key, order.len());
                order.push(vec![tuple]);
            }
        }
    }

    let out_rows: Vec<Tuple> = order
        .into_iter()
        .map(|members| {
            let first = &members[0];
            let mut tuple: Tuple = group_pos
                .iter()
                .map(|p| p.and_then(|i| first.get(i).cloned()).unwrap_or(Value::Null))
                .collect();
            for (agg, pos) in aggregates.iter().zip(&agg_pos) {
                tuple.push(compute_agg(agg, &members, *pos)?);
            }
            Ok(tuple)
        })
        .collect::<Result<Vec<Tuple>, ColumnarError>>()?;

    let mut names: Vec<String> = group_by.to_vec();
    names.extend(aggregates.iter().map(|a| a.alias.clone()));
    Ok(RowStream {
        schema: Arc::new(Schema::new(names)),
        iter: Box::new(out_rows.into_iter()),
    })
}

fn compute_agg(
    agg: &Aggregate,
    members: &[Tuple],
    pos: Option<usize>,
) -> Result<Value, ColumnarError> {
    match agg.func {
        AggFunc::Count => Ok(Value::Int(members.len() as i64)),
        AggFunc::Sum | AggFunc::Avg | AggFunc::Min | AggFunc::Max => {
            let nums: Vec<f64> = members
                .iter()
                .filter_map(|m| pos.and_then(|i| m.get(i)).and_then(Value::as_f64))
                .collect();
            if nums.is_empty() {
                return Ok(Value::Null);
            }
            let v = match agg.func {
                AggFunc::Sum => nums.iter().sum(),
                AggFunc::Avg => nums.iter().sum::<f64>() / nums.len() as f64,
                AggFunc::Min => nums.iter().cloned().fold(f64::INFINITY, f64::min),
                AggFunc::Max => nums.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
                // Unreachable given the outer arm, but a planner bug should surface
                // as a query error, not a panic.
                AggFunc::Count => {
                    return Err(ColumnarError::Internal(
                        "Count reached numeric aggregate path".into(),
                    ));
                }
            };
            Ok(Value::Float(v))
        }
    }
}

/// Compute window functions per partition. Output = each input tuple with one value
/// appended per [`WindowFunction`] (so the row count is unchanged). Rows are emitted
/// partition-by-partition, each partition ordered by the `order_by` columns.
fn compute_window(
    rows: Vec<Tuple>,
    ppos: &[Option<usize>],
    opos: &[Option<usize>],
    fpos: &[Option<usize>],
    functions: &[WindowFunction],
) -> Result<Vec<Tuple>, ColumnarError> {
    // Partition rows by the partition-by key (first-seen order).
    let mut index: AHashMap<String, usize> = AHashMap::new();
    let mut parts: Vec<Vec<Tuple>> = Vec::new();
    for row in rows {
        let key = group_key(&row, ppos);
        match index.get(&key) {
            Some(&slot) => parts[slot].push(row),
            None => {
                index.insert(key, parts.len());
                parts.push(vec![row]);
            }
        }
    }

    let mut out = Vec::new();
    for mut part in parts {
        part.sort_by(|a, b| cmp_by_positions(a, b, opos));
        // Order keys for rank/dense_rank (ties share a rank).
        let order_keys: Vec<Vec<Value>> = part
            .iter()
            .map(|t| {
                opos.iter()
                    .map(|p| p.and_then(|i| t.get(i)).cloned().unwrap_or(Value::Null))
                    .collect()
            })
            .collect();
        let n = part.len();
        let mut rank = vec![1usize; n];
        let mut dense = vec![1usize; n];
        for i in 1..n {
            if order_keys[i] == order_keys[i - 1] {
                rank[i] = rank[i - 1];
                dense[i] = dense[i - 1];
            } else {
                rank[i] = i + 1;
                dense[i] = dense[i - 1] + 1;
            }
        }
        for (idx, row) in part.iter().enumerate() {
            let mut tuple = row.clone();
            for (f, &fp) in functions.iter().zip(fpos) {
                let v = match f.func {
                    WindowFn::RowNumber => Value::Int((idx + 1) as i64),
                    WindowFn::Rank => Value::Int(rank[idx] as i64),
                    WindowFn::DenseRank => Value::Int(dense[idx] as i64),
                    WindowFn::Count => Value::Int(part.len() as i64),
                    WindowFn::Sum | WindowFn::Avg | WindowFn::Min | WindowFn::Max => {
                        window_agg(f.func, &part, fp)?
                    }
                };
                tuple.push(v);
            }
            out.push(tuple);
        }
    }
    Ok(out)
}

/// Lexicographic comparison of two tuples over the given column positions (numeric
/// values compare numerically; incomparable/absent compare equal so the sort is total
/// and stable).
fn cmp_by_positions(a: &Tuple, b: &Tuple, positions: &[Option<usize>]) -> Ordering {
    for &p in positions {
        if let (Some(x), Some(y)) = (p.and_then(|i| a.get(i)), p.and_then(|i| b.get(i))) {
            match x.partial_cmp_value(y) {
                Some(o) if o != Ordering::Equal => return o,
                _ => {}
            }
        }
    }
    Ordering::Equal
}

/// A whole-partition aggregate window (`Sum`/`Avg`/`Min`/`Max`) over column `fp`.
fn window_agg(func: WindowFn, part: &[Tuple], fp: Option<usize>) -> Result<Value, ColumnarError> {
    let nums: Vec<f64> = part
        .iter()
        .filter_map(|t| fp.and_then(|i| t.get(i)).and_then(Value::as_f64))
        .collect();
    if nums.is_empty() {
        return Ok(Value::Null);
    }
    let v = match func {
        WindowFn::Sum => nums.iter().sum(),
        WindowFn::Avg => nums.iter().sum::<f64>() / nums.len() as f64,
        WindowFn::Min => nums.iter().cloned().fold(f64::INFINITY, f64::min),
        WindowFn::Max => nums.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        // Unreachable given the caller's dispatch, but a planner bug should
        // surface as a query error, not a panic.
        _ => {
            return Err(ColumnarError::Internal(
                "non-aggregate window fn reached window_agg".into(),
            ));
        }
    };
    Ok(Value::Float(v))
}

/// In-process transitive closure over a `(from, to)` edge relation. Semi-naïve
/// fixpoint — correct for the recursive reachability the plan routes to Souffle.
fn transitive_closure<'a>(
    rows: impl Iterator<Item = Tuple> + 'a,
    from: Option<usize>,
    to: Option<usize>,
) -> Vec<Tuple> {
    let mut closure: AHashSet<(String, String)> = AHashSet::new();
    if let (Some(fi), Some(ti)) = (from, to) {
        for tuple in rows {
            let (Some(a), Some(b)) = (
                tuple.get(fi).map(Value::to_display),
                tuple.get(ti).map(Value::to_display),
            ) else {
                continue;
            };
            closure.insert((a, b));
        }
    }
    loop {
        let mut added = Vec::new();
        for (a, b) in &closure {
            for (c, d) in &closure {
                if b == c && !closure.contains(&(a.clone(), d.clone())) {
                    added.push((a.clone(), d.clone()));
                }
            }
        }
        if added.is_empty() {
            break;
        }
        closure.extend(added);
    }
    // Deterministic output order (the set is unordered).
    let mut pairs: Vec<(String, String)> = closure.into_iter().collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(a, b)| vec![Value::Str(a), Value::Str(b)])
        .collect()
}

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
    fn group_count_distinct_runs_in_process() {
        let mut s = FactStore::new();
        // `foo` ships in two distinct files (duplicate); `bar` in one.
        s.fact("meta", "mod")
            .subject("foo")
            .attr("file", "a.jar")
            .emit();
        s.fact("meta", "mod")
            .subject("foo")
            .attr("file", "b.jar")
            .emit();
        s.fact("meta", "mod")
            .subject("bar")
            .attr("file", "c.jar")
            .emit();
        let batches = facts_to_batches(s.all(), "r").unwrap();
        let store = ColumnarStore::from_batches(&batches).unwrap();

        let plan = RelExpr::GroupCountDistinct {
            kinds: vec!["mod".into()],
            group_col: "id".into(),
            distinct_attr: "file".into(),
            min_count: 2,
        };
        let r = execute(&plan, &store).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r.rows[0].get("id").and_then(Value::as_str), Some("foo"));
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

        // Unregistered module ⇒ pass-through (all 3 rows).
        let passthrough = execute(
            &RelExpr::scan("mixin_application_site").call_external("missing"),
            &store(),
        )
        .unwrap();
        assert_eq!(passthrough.len(), 3);
    }
}
