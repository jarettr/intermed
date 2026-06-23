//! `pack.mcmeta` domain — the pack format descriptor. Multiple packs writing one
//! `pack.mcmeta` is an override; conflicting `pack_format` / `supported_formats`
//! is worth flagging (the rule does that from this summary).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::DomainParse;
use crate::model::{ParseStatus, ResourceSummary};

/// Parser version — bump when pack.mcmeta lowering changes (cache-invalidating).
pub const PACK_MCMETA_AST_VERSION: &str = "pack-mcmeta-r1";

/// Compact pack.mcmeta summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackMcmetaSummary {
    pub pack_format: Option<i64>,
    /// `supported_formats` as an inclusive `[min, max]` range when present.
    pub supported_min: Option<i64>,
    pub supported_max: Option<i64>,
    pub has_description: bool,
}

/// Parse a `pack.mcmeta`.
pub fn parse(value: &Value) -> DomainParse {
    let Some(pack) = value.get("pack").and_then(Value::as_object) else {
        return DomainParse::invalid(vec![diag("pack.mcmeta has no `pack` object")]);
    };
    let pack_format = pack.get("pack_format").and_then(Value::as_i64);
    let (supported_min, supported_max) = parse_supported(pack.get("supported_formats"));
    let has_description = pack.contains_key("description");

    DomainParse {
        summary: ResourceSummary::PackMcmeta(PackMcmetaSummary {
            pack_format,
            supported_min,
            supported_max,
            has_description,
        }),
        references: Vec::new(),
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
    }
}

/// `supported_formats` may be an int, an `[min, max]` array, or a
/// `{"min_inclusive":..,"max_inclusive":..}` object.
fn parse_supported(v: Option<&Value>) -> (Option<i64>, Option<i64>) {
    match v {
        Some(Value::Number(n)) => {
            let x = n.as_i64();
            (x, x)
        }
        Some(Value::Array(arr)) if arr.len() == 2 => (arr[0].as_i64(), arr[1].as_i64()),
        Some(Value::Object(o)) => (
            o.get("min_inclusive").and_then(Value::as_i64),
            o.get("max_inclusive").and_then(Value::as_i64),
        ),
        _ => (None, None),
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
    fn pack_mcmeta_parse() {
        let v = serde_json::from_str(
            r#"{"pack":{"pack_format":15,"description":"x","supported_formats":[15,18]}}"#,
        )
        .unwrap();
        let p = parse(&v);
        let ResourceSummary::PackMcmeta(s) = &p.summary else {
            panic!()
        };
        assert_eq!(s.pack_format, Some(15));
        assert_eq!(s.supported_min, Some(15));
        assert_eq!(s.supported_max, Some(18));
        assert!(s.has_description);
    }

    #[test]
    fn pack_mcmeta_object_supported_formats() {
        let v = serde_json::from_str(
            r#"{"pack":{"pack_format":15,"supported_formats":{"min_inclusive":15,"max_inclusive":21}}}"#,
        )
        .unwrap();
        let ResourceSummary::PackMcmeta(s) = &parse(&v).summary else {
            panic!()
        };
        assert_eq!(s.supported_max, Some(21));
    }

    #[test]
    fn malformed_pack_mcmeta_is_invalid() {
        let v = serde_json::from_str("{}").unwrap();
        assert_eq!(parse(&v).status, ParseStatus::Invalid);
    }
}
