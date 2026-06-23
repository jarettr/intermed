//! Lang domain (`assets/<ns>/lang/<locale>.json` and legacy `.lang`).
//!
//! Translation files merge as a flat key→value union. The cross-writer conflict
//! (same key, different value) is computed by the semantic diff layer over these
//! summaries; this parser produces the key→value entries and the format.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::DomainParse;
use crate::model::{ParseStatus, ResourceSummary};

/// Parser version — bump when lang lowering changes (cache-invalidating).
pub const LANG_AST_VERSION: &str = "lang-r2";

/// Compact lang summary. Entries are kept so the diff layer can detect same-key
/// different-value conflicts; the per-jar byte cap bounds size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LangSummary {
    /// `json` or `properties`.
    pub format: String,
    pub key_count: usize,
    /// Sorted `(key, value)` entries.
    pub entries: Vec<(String, String)>,
}

/// Parse a JSON lang file (`{"key":"value", ...}`).
pub fn parse_json(value: &Value) -> DomainParse {
    let Some(obj) = value.as_object() else {
        return DomainParse::invalid(vec![diag("lang root is not a JSON object")]);
    };
    let mut entries = Vec::new();
    let mut status = ParseStatus::Parsed;
    for (k, v) in obj {
        match v.as_str() {
            Some(s) => entries.push((k.clone(), s.to_string())),
            None => status = ParseStatus::PartiallyParsed, // non-string value (rare)
        }
    }
    entries.sort();
    summary(entries, "json", status)
}

/// Parse a legacy `.lang` properties file.
pub fn parse_properties(bytes: &[u8]) -> DomainParse {
    let Some(map) = crate::syntax::properties::parse(bytes) else {
        return DomainParse::invalid(vec![diag("`.lang` file is not UTF-8")]);
    };
    let entries: Vec<(String, String)> = map.into_iter().collect();
    summary(entries, "properties", ParseStatus::Parsed)
}

fn summary(entries: Vec<(String, String)>, format: &str, status: ParseStatus) -> DomainParse {
    DomainParse {
        summary: ResourceSummary::Lang(LangSummary {
            format: format.to_string(),
            key_count: entries.len(),
            entries,
        }),
        references: Vec::new(),
        diagnostics: Vec::new(),
        status,
    }
}

fn diag(message: &str) -> crate::model::ResourceParseDiagnostic {
    crate::model::ResourceParseDiagnostic {
        severity: crate::model::DiagnosticSeverity::Error,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lang_json_parses_entries() {
        let v = serde_json::from_str(r#"{"item.b":"B","item.a":"A"}"#).unwrap();
        let p = parse_json(&v);
        let ResourceSummary::Lang(s) = &p.summary else {
            panic!()
        };
        assert_eq!(s.format, "json");
        assert_eq!(
            s.entries,
            vec![("item.a".into(), "A".into()), ("item.b".into(), "B".into())]
        );
    }

    #[test]
    fn lang_properties_parses_entries() {
        let p = parse_properties(b"item.a=A\nitem.b=B\n");
        let ResourceSummary::Lang(s) = &p.summary else {
            panic!()
        };
        assert_eq!(s.format, "properties");
        assert_eq!(s.key_count, 2);
    }
}
