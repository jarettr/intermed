//! Executable semantic specification for the production relational IR.
//!
//! Random small relations are checked against direct, deliberately boring Rust
//! oracles. This catches operator drift independently of the optimizer and SQL
//! renderer; backend-specific suites consume the same IR shapes.

use std::collections::{BTreeMap, BTreeSet};

use intermed_columnar::ir::{AggFunc, Aggregate, CmpOp, Predicate, RelExpr, ScalarValue};
use intermed_columnar::{ColumnarError, ColumnarStore, Value, execute, facts_to_batches};
use intermed_facts::FactStore;
use proptest::prelude::*;

fn columnar(store: &FactStore) -> ColumnarStore {
    let batches = facts_to_batches(store.all(), "oracle").expect("project facts");
    ColumnarStore::from_batches(&batches).expect("columnar store")
}

proptest! {
    #[test]
    fn relational_ops_match_reference_semantics(
        rows in prop::collection::vec((0u8..4, 0u8..6, any::<bool>()), 0..40)
    ) {
        let mut facts = FactStore::new();
        for (ordinal, (group, value, enabled)) in rows.iter().copied().enumerate() {
            facts.fact("oracle", "left")
                .subject(format!("l{ordinal}"))
                .attr("group", i64::from(group))
                .attr("value", i64::from(value))
                .attr("enabled", enabled)
                .emit();
        }
        for group in 0u8..4 {
            facts.fact("oracle", "right")
                .subject(format!("r{group}"))
                .attr("group", i64::from(group))
                .emit();
        }
        let store = columnar(&facts);

        // Scan / Filter / Project.
        let filtered = RelExpr::scan("left")
            .filter(Predicate {
                column: "enabled".into(),
                op: CmpOp::Eq,
                value: ScalarValue::Bool(true),
            })
            .project(vec!["subject".into(), "group".into()]);
        let actual = execute(&filtered, &store).unwrap();
        let expected_enabled = rows.iter().filter(|(_, _, enabled)| *enabled).count();
        prop_assert_eq!(actual.len(), expected_enabled);
        prop_assert!(actual.rows.iter().all(|row| row.len() == 2));

        // Aggregate.
        let aggregate = RelExpr::scan("left").aggregate(
            vec!["group".into()],
            vec![Aggregate { func: AggFunc::Count, column: String::new(), alias: "n".into() }],
        );
        let actual_counts = execute(&aggregate, &store).unwrap().rows.into_iter()
            .map(|row| {
                let group = row["group"].to_display().parse::<u8>().unwrap();
                let count = match row["n"] { Value::Int(n) => n as usize, _ => 0 };
                (group, count)
            })
            .collect::<BTreeMap<_, _>>();
        let mut expected_counts = BTreeMap::new();
        for (group, _, _) in &rows { *expected_counts.entry(*group).or_insert(0usize) += 1; }
        prop_assert_eq!(actual_counts, expected_counts);

        // Generic relational join.
        let equi_join = RelExpr::scan("left").join(
            RelExpr::scan("right"),
            vec![("group".into(), "group".into())],
        );
        prop_assert_eq!(execute(&equi_join, &store).unwrap().len(), rows.len());

        // Declarative JoinFilter.
        let join = RelExpr::JoinFilter {
            left_kind: "left".into(), left_alias: "l".into(),
            right_kind: "right".into(), right_alias: "r".into(),
            condition: intermed_columnar::ir::Condition::ColCmp {
                left: "l.attr:group".into(), op: CmpOp::Eq, right: "r.attr:group".into(),
            },
        };
        prop_assert_eq!(execute(&join, &store).unwrap().len(), rows.len());

        // GroupDistinct (typed numeric values use display equality by contract).
        let grouped = RelExpr::GroupCountDistinct {
            kinds: vec!["left".into()],
            group_col: "group".into(),
            distinct_attr: "value".into(),
            filters: vec![],
            min_count: 2,
        };
        let actual_groups = execute(&grouped, &store).unwrap().rows.into_iter()
            .map(|row| row["group"].to_display().parse::<u8>().unwrap())
            .collect::<BTreeSet<_>>();
        let mut values = BTreeMap::<u8, BTreeSet<u8>>::new();
        for (group, value, _) in &rows { values.entry(*group).or_default().insert(*value); }
        let expected_groups = values.into_iter().filter_map(|(g, values)| (values.len() >= 2).then_some(g))
            .collect::<BTreeSet<_>>();
        prop_assert_eq!(actual_groups, expected_groups);
    }
}

#[test]
fn closure_and_external_have_explicit_oracle_semantics() {
    let mut facts = FactStore::new();
    for (from, to) in [("a", "b"), ("b", "c"), ("c", "d")] {
        facts
            .fact("oracle", "edge")
            .subject(from)
            .attr("from", from)
            .attr("to", to)
            .emit();
    }
    let store = columnar(&facts);
    let closure = execute(
        &RelExpr::scan("edge").transitive_closure("from", "to"),
        &store,
    )
    .unwrap();
    let pairs = closure
        .rows
        .iter()
        .map(|row| (row["from"].to_display(), row["to"].to_display()))
        .collect::<BTreeSet<_>>();
    assert!(pairs.contains(&("a".into(), "d".into())));

    let error = execute(
        &RelExpr::scan("edge").call_external("not-registered"),
        &store,
    )
    .unwrap_err();
    assert!(
        matches!(error, ColumnarError::MissingExternalModule(module) if module == "not-registered")
    );
}
