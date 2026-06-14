//! Join-key extraction and hash-index planning for the in-process rule interpreter.
//!
//! Declarative `on` / `match_on` clauses are usually equalities between two
//! fact terms (`m.subject = related.attr:path`). When such keys exist we build a
//! hash index on the smaller relation instead of evaluating a nested loop.

use std::collections::{BTreeMap, HashMap};

use intermed_doctor_core::facts::Fact;

use crate::expr::{extract_equijoin_keys, resolve_term, ExprCtx};

/// Broadcast threshold: when one side has at most this many facts and `on` is
/// `TRUE`, reuse bindings for the small side instead of a Cartesian product loop.
pub const BROADCAST_SIDE_MAX: usize = 8;

/// A resolved equijoin between a left-hand and right-hand term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquijoinKey {
    pub left_term: String,
    pub right_term: String,
}

/// Build a hash index mapping join-key values to fact references.
///
/// `key_term` is resolved using `alias` as the sole binding for each fact.
pub fn index_facts_by_term<'a>(
    facts: &[&'a Fact],
    alias: &str,
    key_term: &str,
    settings: &BTreeMap<String, String>,
) -> HashMap<String, Vec<&'a Fact>> {
    let mut map: HashMap<String, Vec<&'a Fact>> = HashMap::new();
    for fact in facts {
        let bindings = single_binding(alias, fact);
        let ctx = ExprCtx {
            bindings: &bindings,
            settings,
            vars: None,
        };
        if let Some(key) = resolve_term(key_term, &ctx) {
            map.entry(key).or_default().push(fact);
        }
    }
    map
}

/// Parse equijoin keys from an `on` / `match_on` expression.
#[must_use]
pub fn plan_equijoins(expr: &str, left_alias: &str, right_alias: &str) -> Vec<EquijoinKey> {
    extract_equijoin_keys(expr)
        .into_iter()
        .filter_map(|(left, right)| classify_equijoin(left, right, left_alias, right_alias))
        .collect()
}

fn classify_equijoin(
    left: String,
    right: String,
    left_alias: &str,
    right_alias: &str,
) -> Option<EquijoinKey> {
    let left_is_left = term_belongs_to_alias(&left, left_alias);
    let right_is_right = term_belongs_to_alias(&right, right_alias);
    let left_is_right = term_belongs_to_alias(&left, right_alias);
    let right_is_left = term_belongs_to_alias(&right, left_alias);

    if left_is_left && right_is_right {
        return Some(EquijoinKey {
            left_term: left,
            right_term: right,
        });
    }
    if left_is_right && right_is_left {
        return Some(EquijoinKey {
            left_term: right,
            right_term: left,
        });
    }
    None
}

fn term_belongs_to_alias(term: &str, alias: &str) -> bool {
    if term == "subject" || term.starts_with("attr:") {
        return true;
    }
    term.starts_with(&format!("{alias}."))
}

fn single_binding<'a>(alias: &str, fact: &'a Fact) -> BTreeMap<String, &'a Fact> {
    let mut map = BTreeMap::new();
    map.insert(alias.to_string(), fact);
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::{kind, FactStore};

    #[test]
    fn extracts_subject_archive_equijoin() {
        let keys = plan_equijoins("s.subject = related.attr:archive", "s", "related");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].left_term, "s.subject");
        assert_eq!(keys[0].right_term, "related.attr:archive");
    }

    #[test]
    fn builds_index_for_archive_attr() {
        let mut store = FactStore::new();
        store
            .fact("t", kind::USES_PROCESS_SPAWN)
            .subject("a")
            .attr("archive", "foo.jar")
            .emit();
        store
            .fact("t", kind::USES_PROCESS_SPAWN)
            .subject("b")
            .attr("archive", "bar.jar")
            .emit();
        let facts: Vec<_> = store.by_kind(kind::USES_PROCESS_SPAWN).collect();
        let settings = BTreeMap::new();
        let index = index_facts_by_term(&facts, "related", "related.attr:archive", &settings);
        assert_eq!(index.get("foo.jar").map(|v| v.len()), Some(1));
        assert_eq!(index.get("bar.jar").map(|v| v.len()), Some(1));
    }
}