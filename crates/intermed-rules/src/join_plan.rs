//! Join-key extraction and hash-index planning for the in-process rule interpreter.
//!
//! Declarative `on` / `match_on` clauses are usually equalities between two
//! fact terms (`m.subject = related.attr:path`). When such keys exist we build a
//! hash index on the smaller relation instead of evaluating a nested loop.

use std::collections::{BTreeMap, HashMap};

use intermed_doctor_core::facts::Fact;

use crate::expr::{extract_equijoin_keys, term_value};

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
    _settings: &BTreeMap<String, String>,
) -> HashMap<String, Vec<&'a Fact>> {
    // Precompile the key-term resolver once, instead of building a `BTreeMap` binding +
    // `ExprCtx` and re-parsing `key_term` for every fact (this index is built over tens
    // of thousands of facts). Mirrors `resolve_term`'s single-binding semantics exactly.
    let resolve = compile_key_resolver(alias, key_term);
    let mut map: HashMap<String, Vec<&'a Fact>> = HashMap::new();
    for fact in facts {
        if let Some(key) = resolve(fact) {
            map.entry(key).or_default().push(fact);
        }
    }
    map
}

/// A precompiled per-fact join-key extractor.
type KeyResolver = Box<dyn Fn(&Fact) -> Option<String>>;

/// Compile a join-key `term` into a per-fact extractor for a single bound `alias`.
/// Matches [`resolve_term`] with a one-alias binding and `vars: None` exactly.
fn compile_key_resolver(alias: &str, term: &str) -> KeyResolver {
    if term == "subject" {
        return Box::new(|f| Some(f.subject.clone()));
    }
    if let Some(attr) = term.strip_prefix("attr:") {
        let attr = attr.to_string();
        return Box::new(move |f| term_value(f, &attr));
    }
    if let Some((a, rest)) = term.split_once('.') {
        if a != alias {
            // Only the bound alias is in scope; any other alias resolves to nothing.
            return Box::new(|_| None);
        }
        let rest = rest.to_string();
        return Box::new(move |f| {
            if let Some(attr) = rest.strip_prefix("attr:") {
                term_value(f, attr)
            } else if rest == "subject" {
                Some(f.subject.clone())
            } else if rest == "kind" {
                Some(f.kind.clone())
            } else {
                term_value(f, &rest)
            }
        });
    }
    // A bare identifier resolves only against `vars`, which this path never supplies.
    Box::new(|_| None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::{FactStore, kind};

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
