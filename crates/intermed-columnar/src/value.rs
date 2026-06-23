//! Scalar values and rows for the in-process query executor.

use std::collections::BTreeMap;

use intermed_facts::AttrValue;

/// A scalar cell in a result row. `Null` represents an absent attribute.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null,
}

impl Value {
    pub fn from_attr(v: &AttrValue) -> Value {
        match v {
            AttrValue::Str(s) => Value::Str(s.clone()),
            AttrValue::Int(i) => Value::Int(*i),
            AttrValue::Float(f) => Value::Float(*f),
            AttrValue::Bool(b) => Value::Bool(*b),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Numeric view (`Int`/`Float`) for numeric comparisons and aggregates.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Render for SQL/string contexts and group keys.
    pub fn to_display(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "NULL".to_string(),
        }
    }

    /// Total-ish ordering for comparisons: numeric values compare numerically
    /// (cross Int/Float), strings lexically, bools as ints; mismatched/Null are
    /// incomparable (`None`).
    pub fn partial_cmp_value(&self, other: &Value) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (Value::Null, _) | (_, Value::Null) => None,
            (Value::Str(a), Value::Str(b)) => Some(a.cmp(b)),
            (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
            _ => self.as_f64()?.partial_cmp(&other.as_f64()?),
        }
    }
}

/// A result row: column name → value. Order-independent; columns are addressed by
/// name (matching the relational IR's column references).
pub type Row = BTreeMap<String, Value>;

/// A materialized relation (the executor's working set).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Relation {
    pub rows: Vec<Row>,
}

impl Relation {
    pub fn new(rows: Vec<Row>) -> Self {
        Self { rows }
    }
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}
