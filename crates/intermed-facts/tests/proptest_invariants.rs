//! Property tests for [`FactStore`] invariants.

use intermed_facts::{kind, AttrValue, FactStore, SourceRef};
use proptest::prelude::*;

fn kind_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just(kind::MOD),
        Just(kind::HOT_METHOD),
        Just(kind::MIXIN_TARGET),
        Just(kind::TICK_SPIKE),
        Just(kind::LOG_SIGNAL),
        Just(kind::MOD_METADATA),
        Just(kind::ENTRYPOINT_DETAIL),
        Just(kind::MOD_RELATIONSHIP),
        Just(kind::MOD_CAPABILITY),
        Just(kind::LOG_CRASH),
        Just(kind::LOG_MOD_ERROR),
    ]
}

fn attr_strategy() -> impl Strategy<Value = (String, AttrValue)> {
    prop_oneof![
        any::<i64>().prop_map(|v| ("ms".to_string(), AttrValue::Int(v))),
        any::<f64>().prop_map(|v| ("percent".to_string(), AttrValue::Float(v))),
        any::<bool>().prop_map(|v| ("flag".to_string(), AttrValue::Bool(v))),
        "[a-z]{1,8}".prop_map(|v| ("label".to_string(), AttrValue::Str(v))),
    ]
}

proptest! {
    #[test]
    fn fact_ids_are_unique_and_monotonic(
        count in 1usize..64,
        subjects in prop::collection::vec("[a-z]{1,12}", 1..64),
    ) {
        let mut store = FactStore::new();
        let mut ids = Vec::new();
        for i in 0..count {
            let kind = match i % 3 {
                0 => kind::MOD,
                1 => kind::HOT_METHOD,
                _ => kind::TICK_SPIKE,
            };
            let subject = &subjects[i % subjects.len()];
            let id = store
                .fact("prop-test", kind)
                .subject(subject)
                .source(SourceRef::file("fixture"))
                .emit();
            ids.push(id);
        }

        let unique: std::collections::BTreeSet<_> = ids.iter().copied().collect();
        prop_assert_eq!(unique.len(), ids.len(), "fact ids must be unique");

        for window in ids.windows(2) {
            prop_assert!(window[0] < window[1], "fact ids must be strictly increasing");
        }
    }

    #[test]
    fn by_kind_returns_only_matching_facts(
        entries in prop::collection::vec((kind_strategy(), "[a-z]{1,10}", attr_strategy()), 0..48),
    ) {
        let mut store = FactStore::new();
        let mut expected: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

        for (kind, subject, (key, value)) in entries {
            store
                .fact("prop-test", kind)
                .subject(subject)
                .attr(&key, value)
                .emit();
            *expected.entry(kind.to_string()).or_default() += 1;
        }

        for (kind_name, count) in expected {
            let actual = store.by_kind(&kind_name).count();
            prop_assert_eq!(
                actual,
                count,
                "by_kind({}) must return every emitted fact",
                kind_name
            );
        }
    }

    #[test]
    fn get_roundtrips_emitted_facts(
        entries in prop::collection::vec((kind_strategy(), "[a-z]{1,10}"), 1..32),
    ) {
        let mut store = FactStore::new();
        let mut emitted = Vec::new();
        for (kind, subject) in entries {
            let id = store
                .fact("prop-test", kind)
                .subject(&subject)
                .attr("version", "1")
                .emit();
            emitted.push((id, kind, subject));
        }

        for (id, kind, subject) in emitted {
            let fact = store.get(id).expect("get must resolve emitted id");
            prop_assert_eq!(fact.id, id);
            prop_assert_eq!(&fact.kind, kind);
            prop_assert_eq!(&fact.subject, &subject);
            prop_assert_eq!(fact.attr("version"), Some("1"));
        }
    }

    #[test]
    fn stats_counts_match_store_len(
        entries in prop::collection::vec(kind_strategy(), 0..40),
    ) {
        let mut store = FactStore::new();
        for kind in entries {
            store.fact("prop-test", kind).subject("x").emit();
        }
        let stats = store.stats();
        let sum: usize = stats.values().sum();
        prop_assert_eq!(sum, store.len());
    }

    #[test]
    fn attr_f64_reads_native_float_attrs(
        value in 0.0f64..1000.0,
    ) {
        let mut store = FactStore::new();
        let id = store
            .fact("prop-test", kind::HOT_METHOD)
            .subject("c")
            .attr("percent", value)
            .emit();
        let read = store.get(id).unwrap().attr_f64("percent").unwrap();
        prop_assert!((read - value).abs() < 0.01);
    }

    #[test]
    fn attr_f64_rejects_string_encoded_numbers(
        value in 0.0f64..1000.0,
    ) {
        let mut store = FactStore::new();
        let id = store
            .fact("prop-test", kind::HOT_METHOD)
            .subject("c")
            .attr("percent", format!("{value:.2}"))
            .emit();
        prop_assert_eq!(store.get(id).unwrap().attr_f64("percent"), None);
    }

    #[test]
    fn attr_f64_reads_integer_attrs_as_whole_numbers(
        value in 0i64..10_000,
    ) {
        let mut store = FactStore::new();
        let id = store
            .fact("prop-test", kind::TICK_SPIKE)
            .subject("tick")
            .attr("ms", value)
            .emit();
        prop_assert_eq!(store.get(id).unwrap().attr_f64("ms"), Some(value as f64));
    }

    #[test]
    fn confidence_is_always_clamped(value in -10.0f32..10.0f32) {
        let mut store = FactStore::new();
        let id = store.fact("prop-test", kind::MOD).confidence(value).emit();
        let fact = store.get(id).unwrap();
        prop_assert!(fact.confidence >= 0.0 && fact.confidence <= 1.0);
    }

    #[test]
    fn new_metadata_fact_subjects_and_attributes_roundtrip(
        subject in "[a-z][a-z0-9_]{1,20}",
        related in "[a-z][a-z0-9_]{1,20}",
        confidence in 0.0f32..1.0f32,
    ) {
        let mut store = FactStore::new();
        let id = store
            .fact("prop-test", kind::MOD_RELATIONSHIP)
            .subject(&subject)
            .attr("related", related.clone())
            .attr("type", "recommended_together")
            .confidence(confidence)
            .emit();
        let fact = store.get(id).unwrap();
        prop_assert_eq!(&fact.subject, &subject);
        prop_assert_eq!(fact.attr("related"), Some(related.as_str()));
        prop_assert_eq!(fact.attr("type"), Some("recommended_together"));
    }
}
