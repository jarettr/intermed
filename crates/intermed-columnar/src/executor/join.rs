use super::*;

/// Evaluate a [`Condition`] over a column resolver (returns `Null` for absent columns).
/// Matches the SQL rendering in `sql::condition_sql` and the engine's `Filter`
/// comparison semantics (stringly `Eq`/`Ne`, typed ranges) by reusing [`eval_cmp`].
pub(super) fn eval_condition(cond: &Condition, resolve: &impl Fn(&str) -> Value) -> bool {
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

pub(super) fn term_for_alias<'a>(term: &'a str, alias: &str) -> Option<&'a str> {
    let (term_alias, col) = term.split_once('.')?;
    (term_alias == alias).then_some(col.strip_prefix("attr:").unwrap_or(col))
}

pub(super) fn mandatory_join_filter_keys(
    cond: &Condition,
    left_alias: &str,
    right_alias: &str,
) -> Vec<(String, String)> {
    match cond {
        Condition::ColCmp {
            left,
            op: CmpOp::Eq,
            right,
        } => {
            if let (Some(l), Some(r)) = (
                term_for_alias(left, left_alias),
                term_for_alias(right, right_alias),
            ) {
                return vec![(l.to_string(), r.to_string())];
            }
            if let (Some(l), Some(r)) = (
                term_for_alias(right, left_alias),
                term_for_alias(left, right_alias),
            ) {
                return vec![(l.to_string(), r.to_string())];
            }
            Vec::new()
        }
        Condition::And(a, b) => {
            let mut out = mandatory_join_filter_keys(a, left_alias, right_alias);
            out.extend(mandatory_join_filter_keys(b, left_alias, right_alias));
            out
        }
        // Keys under OR/NOT are not mandatory: using them for an index would drop
        // pairs that satisfy another branch.
        _ => Vec::new(),
    }
}

pub(super) fn join_filter_pair_matches(
    condition: &Condition,
    left_alias: &str,
    right_alias: &str,
    l_schema: &Schema,
    r_schema: &Schema,
    lt: &Tuple,
    rt: &Tuple,
) -> bool {
    let pick = |schema: &Schema, t: &Tuple, col: &str| -> Value {
        schema
            .pos(col)
            .and_then(|i| t.get(i).cloned())
            .unwrap_or(Value::Null)
    };
    let resolve = |name: &str| -> Value {
        let (alias, col) = name.split_once('.').unwrap_or(("", name));
        let col = col.strip_prefix("attr:").unwrap_or(col);
        if alias == left_alias {
            pick(l_schema, lt, col)
        } else if alias == right_alias {
            pick(r_schema, rt, col)
        } else {
            Value::Null
        }
    };
    eval_condition(condition, &resolve)
}

/// Declarative-rule join: cross two scanned kinds and keep rows satisfying `condition`
/// (alias-qualified). Output columns mirror the SQL form
/// (`left_fact_id`/`left_subject`/`right_fact_id`/`right_subject`).
pub(super) fn join_filter<'a>(
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
    let keys = mandatory_join_filter_keys(condition, left_alias, right_alias);
    if keys.is_empty() {
        for lt in l_rows {
            for rt in r_rows {
                if join_filter_pair_matches(
                    condition,
                    left_alias,
                    right_alias,
                    &l_schema,
                    &r_schema,
                    lt,
                    rt,
                ) {
                    out.push(vec![
                        pick(&l_schema, lt, "fact_id"),
                        pick(&l_schema, lt, "subject"),
                        pick(&r_schema, rt, "fact_id"),
                        pick(&r_schema, rt, "subject"),
                    ]);
                }
            }
        }
    } else {
        let l_key_pos: Vec<Option<usize>> = keys.iter().map(|(l, _)| l_schema.pos(l)).collect();
        let r_key_pos: Vec<Option<usize>> = keys.iter().map(|(_, r)| r_schema.pos(r)).collect();
        if r_rows.len() <= l_rows.len() {
            let mut index: AHashMap<Vec<HashKey>, Vec<&Tuple>> = AHashMap::new();
            for rt in r_rows {
                if let Some(key) = key_of(rt, &r_key_pos) {
                    index.entry(key).or_default().push(rt);
                }
            }
            for lt in l_rows {
                let Some(key) = key_of(lt, &l_key_pos) else {
                    continue;
                };
                let Some(candidates) = index.get(&key) else {
                    continue;
                };
                for rt in candidates {
                    if join_filter_pair_matches(
                        condition,
                        left_alias,
                        right_alias,
                        &l_schema,
                        &r_schema,
                        lt,
                        rt,
                    ) {
                        out.push(vec![
                            pick(&l_schema, lt, "fact_id"),
                            pick(&l_schema, lt, "subject"),
                            pick(&r_schema, rt, "fact_id"),
                            pick(&r_schema, rt, "subject"),
                        ]);
                    }
                }
            }
        } else {
            let mut index: AHashMap<Vec<HashKey>, Vec<&Tuple>> = AHashMap::new();
            for lt in l_rows {
                if let Some(key) = key_of(lt, &l_key_pos) {
                    index.entry(key).or_default().push(lt);
                }
            }
            for rt in r_rows {
                let Some(key) = key_of(rt, &r_key_pos) else {
                    continue;
                };
                let Some(candidates) = index.get(&key) else {
                    continue;
                };
                for lt in candidates {
                    if join_filter_pair_matches(
                        condition,
                        left_alias,
                        right_alias,
                        &l_schema,
                        &r_schema,
                        lt,
                        rt,
                    ) {
                        out.push(vec![
                            pick(&l_schema, lt, "fact_id"),
                            pick(&l_schema, lt, "subject"),
                            pick(&r_schema, rt, "fact_id"),
                            pick(&r_schema, rt, "subject"),
                        ]);
                    }
                }
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

/// Group facts of any of `kinds` by `group_col`; keep non-null groups whose
/// distinct, non-null `distinct_attr` count is at least `min_count`.
pub(super) fn group_count_distinct<'a>(
    store: &'a ColumnarStore,
    kinds: &[String],
    group_col: &str,
    distinct_attr: &str,
    filters: &[Predicate],
    min_count: usize,
) -> RowStream<'a> {
    let mut index: AHashMap<String, usize> = AHashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut distinct: Vec<AHashSet<String>> = Vec::new();

    for kind in kinds {
        let Some(batch) = store.by_kind.get(kind) else {
            continue;
        };
        let group_pos = batch.schema.pos(group_col);
        let attr_pos = batch.schema.pos(distinct_attr);
        for t in &batch.rows {
            let matches_filters = filters.iter().all(|filter| {
                let actual = batch
                    .schema
                    .pos(&filter.column)
                    .and_then(|i| t.get(i))
                    .unwrap_or(&Value::Null);
                eval_cmp(actual, filter.op, &scalar_to_value(&filter.value))
            });
            if !matches_filters {
                continue;
            }
            let Some(group) = group_pos.and_then(|i| t.get(i)).filter(|v| !v.is_null()) else {
                continue;
            };
            let Some(value) = attr_pos.and_then(|i| t.get(i)).filter(|v| !v.is_null()) else {
                continue;
            };
            let group = group.to_display();
            let slot = *index.entry(group.clone()).or_insert_with(|| {
                order.push(group.clone());
                distinct.push(AHashSet::new());
                order.len() - 1
            });
            distinct[slot].insert(value.to_display());
        }
    }

    let schema = Arc::new(Schema::new(vec![group_col.to_string()]));
    let rows: Vec<Tuple> = order
        .into_iter()
        .zip(distinct)
        .filter(|(_, set)| set.len() >= min_count)
        .map(|(group, _)| vec![Value::Str(group)])
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
pub(super) enum HashKey {
    Null,
    Str(String),
    Int(i64),
    Bool(bool),
    Float(u64),
}

pub(super) fn hash_key(v: &Value) -> Option<HashKey> {
    match v {
        Value::Str(s) => Some(HashKey::Str(s.clone())),
        Value::Int(i) => Some(HashKey::Int(*i)),
        Value::Bool(b) => Some(HashKey::Bool(*b)),
        Value::Float(f) => Some(HashKey::Float(f.to_bits())),
        Value::Null => None,
    }
}

/// Compose the join key of a tuple over the given column positions.
///
/// SQL/DuckDB semantics: an absent/`NULL` key term does not join, even against
/// another `NULL`. Returning `None` keeps those rows out of the hash table and
/// out of probe candidates.
pub(super) fn key_of(tuple: &Tuple, positions: &[Option<usize>]) -> Option<Vec<HashKey>> {
    positions
        .iter()
        .map(|p| {
            let value = p.and_then(|i| tuple.get(i))?;
            hash_key(value)
        })
        .collect()
}

/// The output schema of a join: left columns keep their names, right columns that
/// collide with a left name are prefixed `right.` (so no column is shadowed).
pub(super) fn join_schema(left: &Schema, right: &Schema) -> Arc<Schema> {
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
pub(super) fn concat(left: &Tuple, right: &Tuple) -> Tuple {
    let mut t = Vec::with_capacity(left.len() + right.len());
    t.extend_from_slice(left);
    t.extend_from_slice(right);
    t
}

/// Convert a public [`Relation`] back into a positional tuple stream — the inverse of
/// [`materialize`], used to re-stream an external function's result. The schema is the
/// sorted union of column names across the returned rows.
pub(super) fn relation_to_stream<'a>(rel: Relation) -> RowStream<'a> {
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
pub(super) fn hash_join<'a>(
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
        if let Some(key) = key_of(&tuple, &build_key_pos) {
            table.entry(key).or_default().push(tuple);
        }
    }

    // Probe phase: stream the probe side, merge respecting the logical left/right
    // relations (not the physical build/probe roles).
    let iter = probe_stream.iter.flat_map(move |ptuple| {
        let Some(key) = key_of(&ptuple, &probe_key_pos) else {
            return Vec::new().into_iter();
        };
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
