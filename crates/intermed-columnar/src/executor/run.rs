use super::*;

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
    execute_with_stats(expr, store, &stats, registry)
}

/// Like [`execute_with`], but reuses caller-owned catalog statistics. `QueryEngine`
/// builds these once alongside the store and passes them here so a pack with many
/// rules does not re-scan every batch just to optimize each plan.
pub fn execute_with_stats(
    expr: &RelExpr,
    store: &ColumnarStore,
    stats: &Statistics,
    registry: &FunctionRegistry,
) -> Result<Relation, ColumnarError> {
    let optimized = crate::optimizer::optimize(expr, stats);
    let phys = physical::plan(&optimized, stats);
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
    let registry = FunctionRegistry::empty();
    execute_strategy_with_stats(expr, store, &stats, &registry, strategy)
}

/// Execute with an explicit strategy and caller-owned statistics/registry.
pub fn execute_strategy_with_stats(
    expr: &RelExpr,
    store: &ColumnarStore,
    stats: &Statistics,
    registry: &FunctionRegistry,
    strategy: ExecutionStrategy,
) -> Result<Relation, ColumnarError> {
    let optimized = crate::optimizer::optimize(expr, stats);
    let phys = physical::plan(&optimized, stats);
    run_physical(&phys, store, registry, strategy)
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
pub(super) fn stream<'a>(
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
            None => Err(ColumnarError::MissingExternalModule(module.clone())),
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
            filters,
            min_count,
        } => Ok(group_count_distinct(
            store,
            kinds,
            group_col,
            distinct_attr,
            filters,
            *min_count,
        )),
    }
}
