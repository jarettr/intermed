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
//!   columns. See `docs/SCHEMA.md`.
//!
//! Keep facts as plain data: no behaviour, no references to findings.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Catalog of well-known fact predicates.
///
/// Collectors *should* use these constants rather than ad-hoc strings so rules
/// and the eventual Datalog schema stay in sync. New predicates are added here
/// as layers come online; the type is intentionally a `&str` newtype rather
/// than a closed enum so that out-of-tree rule packs (Phase 5) can introduce
/// their own predicates without recompiling this crate.
pub mod kind {
    // Layer A — environment / target detection
    pub const ENVIRONMENT: &str = "environment";
    pub const JAVA_RUNTIME: &str = "java_runtime";
    pub const TARGET: &str = "target";
    // Layer B — metadata
    pub const MOD: &str = "mod";
    pub const PLUGIN: &str = "plugin";
    pub const DEPENDENCY: &str = "dependency";
    pub const PROVIDED_DEPENDENCY: &str = "provided_dependency";
    pub const MOD_SIDE: &str = "mod_side";
    pub const ENTRYPOINT: &str = "entrypoint";
    pub const NESTED_JAR: &str = "nested_jar";
    pub const UNPARSEABLE_ARCHIVE: &str = "unparseable_archive";
    // Layer D — log / crash signals
    pub const LOG_SIGNAL: &str = "log_signal";
    pub const LOG_MENTIONS_MOD: &str = "log_mentions_mod";
    // Layer E — VFS / resources
    pub const RESOURCE_WRITER: &str = "resource_writer";
    pub const RESOURCE_COLLISION: &str = "resource_collision";
    pub const JSON_MERGE_CANDIDATE: &str = "json_merge_candidate";
    pub const SAFE_CRDT_MERGE: &str = "safe_crdt_merge";
    pub const UNSAFE_REPLACE_CONFLICT: &str = "unsafe_replace_conflict";
    // Layer F — mixin intelligence
    pub const MIXIN_CONFIG: &str = "mixin_config";
    pub const MIXIN_CLASS: &str = "mixin_class";
    pub const MIXIN_TARGET: &str = "mixin_target";
    pub const MIXIN_OPERATION: &str = "mixin_operation";
    pub const MIXIN_HOTSPOT: &str = "mixin_hotspot";
    pub const MIXIN_OVERLAP: &str = "mixin_overlap";
    pub const HIGH_RISK_OVERWRITE: &str = "high_risk_overwrite";
    pub const LOG_MIXIN_CORRELATION: &str = "log_mixin_correlation";
    // Cross-layer
    pub const DEFERRED_LAYER: &str = "deferred_layer";
}

/// A single typed term value attached to a [`Fact`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttrValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl AttrValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttrValue::Str(s) => Some(s),
            _ => None,
        }
    }
}

impl From<&str> for AttrValue {
    fn from(v: &str) -> Self {
        AttrValue::Str(v.to_string())
    }
}
impl From<String> for AttrValue {
    fn from(v: String) -> Self {
        AttrValue::Str(v)
    }
}
impl From<i64> for AttrValue {
    fn from(v: i64) -> Self {
        AttrValue::Int(v)
    }
}
impl From<bool> for AttrValue {
    fn from(v: bool) -> Self {
        AttrValue::Bool(v)
    }
}

/// Where a fact came from, for provenance / `--explain` (Phase 2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceRef {
    /// File or archive the fact was observed in (relative to the target root
    /// where possible).
    pub locator: String,
    /// Optional 1-based line number (for log/text sources).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Optional inner path (e.g. `fabric.mod.json` inside a jar).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner: Option<String>,
}

impl SourceRef {
    pub fn file(locator: impl Into<String>) -> Self {
        Self {
            locator: locator.into(),
            line: None,
            inner: None,
        }
    }
    pub fn at_line(locator: impl Into<String>, line: u32) -> Self {
        Self {
            locator: locator.into(),
            line: Some(line),
            inner: None,
        }
    }
    pub fn inside(locator: impl Into<String>, inner: impl Into<String>) -> Self {
        Self {
            locator: locator.into(),
            line: None,
            inner: Some(inner.into()),
        }
    }
}

/// A monotonically assigned identifier, unique within a [`FactStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FactId(pub u64);

impl std::fmt::Display for FactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "f{}", self.0)
    }
}

/// An observed, atomic statement about the target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fact {
    pub id: FactId,
    /// Predicate name; see [`kind`].
    pub kind: String,
    /// Primary subject of the statement (e.g. a mod id). May be empty for
    /// environment-level facts.
    pub subject: String,
    /// Named terms.
    pub attributes: BTreeMap<String, AttrValue>,
    /// Provenance.
    pub source: SourceRef,
    /// 0.0..=1.0 — how certain the extractor is.
    pub confidence: f32,
    /// Id of the collector that produced this fact.
    pub extractor: String,
    pub observed_at: DateTime<Utc>,
}

impl Fact {
    /// Read a string-valued attribute.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(AttrValue::as_str)
    }

    /// Read a bool-valued attribute.
    pub fn attr_bool(&self, key: &str) -> Option<bool> {
        match self.attributes.get(key)? {
            AttrValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Read an int-valued attribute.
    pub fn attr_int(&self, key: &str) -> Option<i64> {
        match self.attributes.get(key)? {
            AttrValue::Int(i) => Some(*i),
            _ => None,
        }
    }
}

/// A fact under construction. Obtained from [`FactStore::fact`]; the id is
/// assigned on [`FactBuilder::emit`].
#[must_use = "call .emit() to record the fact"]
pub struct FactBuilder<'s> {
    store: &'s mut FactStore,
    kind: String,
    subject: String,
    attributes: BTreeMap<String, AttrValue>,
    source: SourceRef,
    confidence: f32,
    extractor: String,
}

impl<'s> FactBuilder<'s> {
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }
    pub fn attr(mut self, key: &str, value: impl Into<AttrValue>) -> Self {
        self.attributes.insert(key.to_string(), value.into());
        self
    }
    pub fn source(mut self, source: SourceRef) -> Self {
        self.source = source;
        self
    }
    pub fn confidence(mut self, c: f32) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }
    /// Record the fact and return its assigned id.
    pub fn emit(self) -> FactId {
        let id = FactId(self.store.next_id);
        self.store.next_id += 1;
        self.store.facts.push(Fact {
            id,
            kind: self.kind,
            subject: self.subject,
            attributes: self.attributes,
            source: self.source,
            confidence: self.confidence,
            extractor: self.extractor,
            observed_at: Utc::now(),
        });
        id
    }
}

/// Append-only store of facts gathered during one diagnosis run.
#[derive(Debug, Default)]
pub struct FactStore {
    facts: Vec<Fact>,
    next_id: u64,
}

impl FactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin building a fact. `extractor` is the producing collector's id.
    pub fn fact(&mut self, extractor: &str, kind: &str) -> FactBuilder<'_> {
        let extractor = extractor.to_string();
        FactBuilder {
            store: self,
            kind: kind.to_string(),
            subject: String::new(),
            attributes: BTreeMap::new(),
            source: SourceRef::file("<unknown>"),
            confidence: 1.0,
            extractor,
        }
    }

    pub fn all(&self) -> &[Fact] {
        &self.facts
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    /// All facts with the given predicate.
    pub fn by_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a Fact> + 'a {
        self.facts.iter().filter(move |f| f.kind == kind)
    }

    /// Per-predicate counts, for report fact-stats.
    pub fn stats(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for f in &self.facts {
            *m.entry(f.kind.clone()).or_insert(0) += 1;
        }
        m
    }

    /// Lookup by fact id, used by `doctor --explain`.
    pub fn get(&self, id: FactId) -> Option<&Fact> {
        self.facts.iter().find(|f| f.id == id)
    }
}

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
    fn confidence_is_clamped() {
        let mut store = FactStore::new();
        let id = store.fact("t", kind::MOD).confidence(5.0).emit();
        assert_eq!(store.all()[0].id, id);
        assert_eq!(store.all()[0].confidence, 1.0);
    }
}
