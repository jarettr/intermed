use super::*;
use serde::de::Deserializer;
use serde::ser::{SerializeMap, Serializer};
use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

/// An immutable string that can share one allocation with other facts in the
/// same store. Its serde representation is exactly the ordinary JSON string
/// used before interning was introduced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InternedString(Arc<str>);

impl InternedString {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for InternedString {
    fn from(value: String) -> Self {
        Self(Arc::from(value))
    }
}

impl From<&str> for InternedString {
    fn from(value: &str) -> Self {
        Self(Arc::from(value))
    }
}

impl From<&String> for InternedString {
    fn from(value: &String) -> Self {
        Self(Arc::from(value.as_str()))
    }
}

impl PartialEq<String> for InternedString {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl From<Arc<str>> for InternedString {
    fn from(value: Arc<str>) -> Self {
        Self(value)
    }
}

impl From<InternedString> for String {
    fn from(value: InternedString) -> Self {
        value.0.to_string()
    }
}

impl From<&InternedString> for String {
    fn from(value: &InternedString) -> Self {
        value.as_str().to_string()
    }
}

impl AsRef<str> for InternedString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for InternedString {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Deref for InternedString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for InternedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<&str> for InternedString {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<str> for InternedString {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

/// A small deterministic attribute map backed by one contiguous allocation.
/// Facts normally carry only a handful of terms; a `BTreeMap` allocated one
/// node per term, which dominated heap overhead for resource-heavy packs.
/// Keys remain sorted, so JSON and rule iteration stay deterministic.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attributes(Vec<(InternedString, AttrValue)>);

impl Attributes {
    pub fn get(&self, key: &str) -> Option<&AttrValue> {
        self.0
            .binary_search_by(|(candidate, _)| candidate.as_str().cmp(key))
            .ok()
            .map(|index| &self.0[index].1)
    }

    pub fn insert(&mut self, key: InternedString, value: AttrValue) -> Option<AttrValue> {
        match self
            .0
            .binary_search_by(|(candidate, _)| candidate.cmp(&key))
        {
            Ok(index) => Some(std::mem::replace(&mut self.0[index].1, value)),
            Err(index) => {
                self.0.insert(index, (key, value));
                None
            }
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &InternedString> {
        self.0.iter().map(|(key, _)| key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&InternedString, &AttrValue)> {
        self.0.iter().map(|(key, value)| (key, value))
    }
}

impl Serialize for Attributes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Attributes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = BTreeMap::<InternedString, AttrValue>::deserialize(deserializer)?;
        Ok(Self(map.into_iter().collect()))
    }
}

impl FromIterator<(InternedString, AttrValue)> for Attributes {
    fn from_iter<T: IntoIterator<Item = (InternedString, AttrValue)>>(iter: T) -> Self {
        let mut attributes = Self::default();
        for (key, value) in iter {
            attributes.insert(key, value);
        }
        attributes
    }
}

impl<'a> IntoIterator for &'a Attributes {
    type Item = (&'a InternedString, &'a AttrValue);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (InternedString, AttrValue)>,
        fn(&(InternedString, AttrValue)) -> (&InternedString, &AttrValue),
    >;

    fn into_iter(self) -> Self::IntoIter {
        fn refs(pair: &(InternedString, AttrValue)) -> (&InternedString, &AttrValue) {
            (&pair.0, &pair.1)
        }
        self.0.iter().map(refs)
    }
}

impl IntoIterator for Attributes {
    type Item = (InternedString, AttrValue);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
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

    /// Read as `f64`. Only native `Float` and `Int` values are accepted; string
    /// attributes (including numeric-looking text) are **not** coerced.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            AttrValue::Float(f) => Some(*f),
            AttrValue::Int(i) => Some(*i as f64),
            AttrValue::Str(_) | AttrValue::Bool(_) => None,
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
impl From<f64> for AttrValue {
    fn from(v: f64) -> Self {
        AttrValue::Float(v)
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
    pub locator: InternedString,
    /// Optional 1-based line number (for log/text sources).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Optional inner path (e.g. `fabric.mod.json` inside a jar).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner: Option<String>,
}

impl SourceRef {
    pub fn file(locator: impl Into<InternedString>) -> Self {
        Self {
            locator: locator.into(),
            line: None,
            inner: None,
        }
    }
    pub fn at_line(locator: impl Into<InternedString>, line: u32) -> Self {
        Self {
            locator: locator.into(),
            line: Some(line),
            inner: None,
        }
    }
    pub fn inside(locator: impl Into<InternedString>, inner: impl Into<String>) -> Self {
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
    pub kind: InternedString,
    /// Primary subject of the statement (e.g. a mod id). May be empty for
    /// environment-level facts.
    pub subject: InternedString,
    /// Named terms.
    pub attributes: Attributes,
    /// Provenance.
    pub source: SourceRef,
    /// 0.0..=1.0 — how certain the extractor is.
    pub confidence: f32,
    /// Id of the collector that produced this fact.
    pub extractor: InternedString,
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

    /// Read a numeric attribute as `f64` (`Float` or `Int` only). Use this for
    /// thresholds that must compare numerically; store values as numbers, not
    /// formatted strings.
    pub fn attr_f64(&self, key: &str) -> Option<f64> {
        self.attributes.get(key).and_then(AttrValue::as_f64)
    }
}
