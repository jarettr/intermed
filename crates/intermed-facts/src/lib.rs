//! # intermed-facts
//!
//! The **ground truth** layer. Collectors observe a target (a server, an
//! instance, a mods directory, a log file) and emit [`Fact`]s into a
//! [`FactStore`]. Everything downstream — rules, findings, reports — is derived
//! only from facts, never from re-scanning the target.
//!
//! ## Why facts are modelled as predicate + named terms
//!
//! A fact is a Datalog-style predicate: a `kind` (the predicate name, e.g.
//! `mod`, `dependency`, `log_signal`) plus a set of named terms ([`AttrValue`]).
//! This shape is deliberately chosen so that:
//!
//! * Phase 1 imperative rules can match on `kind` + read terms by name.
//! * Phase 5 can lower the same facts into a Datalog IR / SQL rows (DuckDB)
//!   with **no model change** — `kind` becomes the relation, terms become
//!   columns. See `docs/reference/facts.md`.
//!
//! Keep facts as plain data: no behaviour, no references to findings.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub mod schema;
pub mod schema_contract;

/// Catalog of well-known fact predicates.
///
/// Collectors *should* use these constants rather than ad-hoc strings so rules
/// and the eventual Datalog schema stay in sync. New predicates are added here
/// as layers come online; the type is intentionally a `&str` newtype rather
/// than a closed enum so that out-of-tree rule packs (Phase 5) can introduce
/// their own predicates without recompiling this crate.
pub mod kind;
mod store;
mod value;

pub use store::{
    FactBuilder, FactRead, FactRetentionPolicy, FactStore, FactWrite, FilteredFactView,
};
pub use value::{AttrValue, Attributes, Fact, FactId, InternedString, SourceRef};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_and_queries_by_kind() {
        let mut store = FactStore::new();
        store
            .fact("test", kind::MOD)
            .subject("sodium")
            .attr("version", "0.5.3")
            .attr("loader", "fabric")
            .source(SourceRef::inside("sodium.jar", "fabric.mod.json"))
            .emit();
        store.fact("test", kind::MOD).subject("iris").emit();

        assert_eq!(store.len(), 2);
        let mods: Vec<_> = store.by_kind(kind::MOD).collect();
        assert_eq!(mods.len(), 2);
        assert_eq!(mods[0].attr("version"), Some("0.5.3"));
        assert_eq!(store.stats().get(kind::MOD), Some(&2));
    }

    #[test]
    fn repeated_schema_strings_and_subjects_share_the_store_pool() {
        let mut store = FactStore::new();
        for _ in 0..2 {
            store
                .fact("test", kind::MOD)
                .subject("same-mod")
                .attr("version", "1.0")
                .source(SourceRef::file("same.jar"))
                .emit();
        }

        // empty subject, extractor, kind, explicit subject, attribute key,
        // and source locator; the second fact adds no interned allocation.
        assert_eq!(store.interned_len(), 6);
    }

    #[test]
    fn filtered_view_is_zero_copy_and_hides_undeclared_predicates() {
        let mut store = FactStore::new();
        store.fact("meta", kind::MOD).subject("alpha").emit();
        store.fact("meta", kind::PLUGIN).subject("beta").emit();
        let allowed = BTreeSet::from([kind::MOD.to_string()]);
        let view = FilteredFactView::new(&store, &allowed);
        let visible = FactRead::by_kind(&view, kind::MOD).next().unwrap();
        assert!(std::ptr::eq(visible, &store.all()[0]));
        assert_eq!(FactRead::by_kind(&view, kind::PLUGIN).count(), 0);
        assert!(FactRead::get(&view, store.all()[1].id).is_none());
    }

    #[test]
    fn staged_append_preserves_global_ids_and_indexes() {
        let mut store = FactStore::new();
        let first = store.fact("a", kind::MOD).subject("alpha").emit();
        let mut staged = store.staging_after();
        let second = staged.fact("b", kind::PLUGIN).subject("beta").emit();
        assert!(second > first);
        store.append_staged(staged);
        assert_eq!(store.get(first).unwrap().subject.as_str(), "alpha");
        assert_eq!(store.get(second).unwrap().subject.as_str(), "beta");
        assert_eq!(store.by_kind(kind::PLUGIN).count(), 1);
    }

    #[test]
    fn compact_fact_storage_preserves_wire_json_and_sorted_attributes() {
        let mut store = FactStore::new();
        store
            .fact("test", kind::MOD)
            .subject("example")
            .attr("version", "1.0")
            .attr("loader", "fabric")
            .source(SourceRef::inside("example.jar", "fabric.mod.json"))
            .emit();

        let value = serde_json::to_value(&store.all()[0]).unwrap();
        assert_eq!(value["kind"], kind::MOD);
        assert_eq!(value["subject"], "example");
        assert_eq!(value["extractor"], "test");
        assert_eq!(value["source"]["locator"], "example.jar");
        assert_eq!(value["source"]["inner"], "fabric.mod.json");
        assert_eq!(value["attributes"]["loader"], "fabric");
        assert_eq!(value["attributes"]["version"], "1.0");

        let encoded = serde_json::to_string(&store.all()[0].attributes).unwrap();
        assert_eq!(encoded, r#"{"loader":"fabric","version":"1.0"}"#);

        let decoded: Fact = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, store.all()[0]);
    }

    #[test]
    fn confidence_is_clamped() {
        let mut store = FactStore::new();
        let id = store.fact("t", kind::MOD).confidence(5.0).emit();
        assert_eq!(store.all()[0].id, id);
        assert_eq!(store.all()[0].confidence, 1.0);
    }

    #[test]
    fn kind_index_matches_linear_scan() {
        let mut store = FactStore::new();
        store.fact("t", kind::MOD).subject("a").emit();
        store.fact("t", kind::MOD).subject("b").emit();
        store.fact("t", kind::PLUGIN).subject("c").emit();
        let indexed: Vec<_> = store
            .by_kind(kind::MOD)
            .map(|f| f.subject.as_str())
            .collect();
        assert_eq!(indexed, vec!["a", "b"]);
    }

    #[test]
    fn subject_and_kind_subject_indexes_match_linear_scan() {
        let mut store = FactStore::new();
        store
            .fact("t", kind::RESOURCE_COLLISION)
            .subject("p.json")
            .emit();
        store
            .fact("t", kind::RESOURCE_SEMANTIC_DIFF)
            .subject("p.json")
            .emit();
        store
            .fact("t", kind::RESOURCE_COLLISION)
            .subject("other.json")
            .emit();

        // by_subject returns every fact on that subject regardless of kind.
        let on_path: Vec<_> = store
            .by_subject("p.json")
            .map(|f| f.kind.as_str())
            .collect();
        assert_eq!(on_path.len(), 2);
        assert!(on_path.contains(&kind::RESOURCE_COLLISION));
        assert!(on_path.contains(&kind::RESOURCE_SEMANTIC_DIFF));

        // by_kind_subject intersects both axes.
        let coll: Vec<_> = store
            .by_kind_subject(kind::RESOURCE_COLLISION, "p.json")
            .map(|f| f.subject.as_str())
            .collect();
        assert_eq!(coll, vec!["p.json"]);
        assert_eq!(
            store
                .by_kind_subject(kind::RESOURCE_COLLISION, "missing")
                .count(),
            0
        );
        assert_eq!(store.by_subject("missing").count(), 0);
    }

    #[test]
    fn subject_index_survives_compaction() {
        let mut store = FactStore::new();
        for i in 0..100 {
            store
                .fact("mixin", kind::MIXIN_HANDLER_BODY)
                .subject(format!("m{i}"))
                .emit();
        }
        store.fact("meta", kind::MOD).subject("alpha").emit();
        let policy = FactRetentionPolicy {
            max_facts: 10,
            ..FactRetentionPolicy::default()
        };
        store.compact(&policy);
        // Subject index was rebuilt: the surviving fact is still reachable.
        assert_eq!(store.by_subject("alpha").count(), 1);
    }

    #[test]
    fn compact_drops_verbose_mixin_facts() {
        let mut store = FactStore::new();
        for i in 0..100 {
            store
                .fact("mixin", kind::MIXIN_HANDLER_BODY)
                .subject(format!("m{i}"))
                .emit();
        }
        store.fact("meta", kind::MOD).subject("alpha").emit();
        let policy = FactRetentionPolicy {
            max_facts: 10,
            ..FactRetentionPolicy::default()
        };
        let dropped = store.compact(&policy);
        assert!(dropped > 0);
        assert_eq!(store.by_kind(kind::MOD).count(), 1);
        assert_eq!(store.by_kind(kind::MIXIN_HANDLER_BODY).count(), 0);
    }

    #[test]
    fn live_retention_bounds_bulk_detail_and_preserves_causal_facts() {
        let policy = FactRetentionPolicy {
            max_facts: 32,
            ..FactRetentionPolicy::default()
        };
        let mut store = FactStore::with_live_retention(policy);
        for i in 0..600 {
            store
                .fact("mixin", kind::MIXIN_HANDLER_BODY)
                .subject(format!("m{i}"))
                .emit();
        }
        let protected = store
            .fact("runtime", kind::CRASH_ANCHOR)
            .subject("fatal-event")
            .emit();

        assert!(store.live_dropped() > 0);
        assert!(store.len() <= 32 + 256);
        assert_eq!(store.get(protected).unwrap().subject, "fatal-event");
        assert_eq!(store.emitted_stats()[kind::MIXIN_HANDLER_BODY], 600);
        assert!(store.live_dropped_stats()[kind::MIXIN_HANDLER_BODY] > 0);
    }

    #[test]
    fn live_retention_backs_off_when_protected_facts_dominate() {
        let policy = FactRetentionPolicy {
            max_facts: 1,
            ..FactRetentionPolicy::default()
        };
        let mut store = FactStore::with_live_retention(policy);
        for index in 0..300 {
            store
                .fact("runtime", kind::CRASH_ANCHOR)
                .subject(format!("event-{index}"))
                .emit();
        }
        assert_eq!(store.live_dropped(), 0);
        let retry_at = store.live_next_compaction_at;
        assert!(retry_at > store.len());
        for index in 300..400 {
            store
                .fact("runtime", kind::CRASH_ANCHOR)
                .subject(format!("event-{index}"))
                .emit();
        }
        assert_eq!(store.live_next_compaction_at, retry_at);
    }

    #[test]
    fn compact_preserving_keeps_cited_facts() {
        let mut store = FactStore::new();
        let mut cited = std::collections::BTreeSet::new();
        for i in 0..100 {
            let id = store
                .fact("mixin", kind::MIXIN_HANDLER_BODY)
                .subject(format!("m{i}"))
                .emit();
            // Cite a verbose fact whose kind would otherwise be dropped.
            if i == 7 {
                cited.insert(id);
            }
        }
        let policy = FactRetentionPolicy {
            max_facts: 10,
            ..FactRetentionPolicy::default()
        };
        let dropped = store.compact_preserving(&policy, &cited);
        assert!(dropped > 0);
        // The cited verbose fact survives even though its kind is not retained.
        let cited_id = *cited.iter().next().unwrap();
        let f = store.get(cited_id).expect("cited fact preserved");
        assert_eq!(f.subject, "m7");
    }

    #[test]
    fn get_still_works_after_compaction() {
        let mut store = FactStore::new();
        for i in 0..100 {
            store
                .fact("mixin", kind::MIXIN_HANDLER_BODY)
                .subject(format!("m{i}"))
                .emit();
        }
        let kept = store.fact("meta", kind::MOD).subject("alpha").emit();

        let policy = FactRetentionPolicy {
            max_facts: 10,
            ..FactRetentionPolicy::default()
        };
        let dropped = store.compact(&policy);
        assert!(dropped > 0);

        // The kept fact has a high FactId but now lives at a low slot index.
        // The slot-index bug returned None here; id_index resolves it.
        let f = store
            .get(kept)
            .expect("kept fact resolvable after compaction");
        assert_eq!(f.subject, "alpha");
        assert_eq!(f.id, kept);

        // Dropped ids resolve to None, not to some unrelated fact.
        assert!(store.get(FactId(0)).is_none());
    }

    #[test]
    fn get_resolves_correct_fact_before_compaction() {
        let mut store = FactStore::new();
        let a = store.fact("t", kind::MOD).subject("a").emit();
        let b = store.fact("t", kind::MOD).subject("b").emit();
        assert_eq!(store.get(a).unwrap().subject, "a");
        assert_eq!(store.get(b).unwrap().subject, "b");
    }

    #[test]
    fn attr_f64_reads_float_and_int_only() {
        let mut store = FactStore::new();
        store
            .fact("t", kind::HOT_METHOD)
            .subject("c")
            .attr("native", 42.5_f64)
            .attr("as_int", 7_i64)
            .attr("as_str", "12.25")
            .attr("not_num", "abc")
            .emit();
        let f = &store.all()[0];
        assert_eq!(f.attr_f64("native"), Some(42.5));
        assert_eq!(f.attr_f64("as_int"), Some(7.0));
        assert_eq!(f.attr_f64("as_str"), None);
        assert_eq!(f.attr_f64("not_num"), None);
        assert_eq!(f.attr_f64("missing"), None);
    }
}
