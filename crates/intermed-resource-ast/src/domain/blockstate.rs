//! Blockstate domain (`assets/<ns>/blockstates/<path>.json`): references the
//! models its variants / multipart cases use.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::domain::DomainParse;
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

pub const BLOCKSTATE_AST_VERSION: &str = "blockstate-r4";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockstateSummary {
    pub variant_count: usize,
    pub model_count: usize,
    /// Canonical fingerprint of the variant→model mapping (sorted by key, then by
    /// model, including rotation/uvlock/weight). Two blockstates with the same
    /// model *set* but different variant assignments will have different fingerprints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_fingerprint: Option<String>,
}

/// Parse a blockstate resource.
pub fn parse(value: &Value) -> DomainParse {
    let Some(obj) = value.as_object() else {
        return DomainParse::invalid(vec![diag("blockstate root is not a JSON object")]);
    };
    let mut references = Vec::new();
    let mut variant_count = 0;
    // Canonical mapping lines for fingerprinting: "variant_key|model[|rot|uvlock|weight]"
    let mut fingerprint_lines: Vec<String> = Vec::new();

    if let Some(variants) = obj.get("variants").and_then(Value::as_object) {
        variant_count = variants.len();
        let mut keys: Vec<&str> = variants.keys().map(String::as_str).collect();
        keys.sort();
        for key in keys {
            let v = &variants[key];
            collect_models_fp(v, key, &mut references, &mut fingerprint_lines);
        }
    }
    if let Some(multipart) = obj.get("multipart").and_then(Value::as_array) {
        variant_count += multipart.len();
        for case in multipart {
            // Multipart: fingerprint the `when` condition (a canonical key) instead of
            // the array index, so reordering multipart cases doesn't change the hash.
            let when_key = case
                .get("when")
                .and_then(|w| serde_json::to_string(w).ok())
                .unwrap_or_else(|| "always".to_string());
            // Hash the when condition to keep fingerprint lines bounded.
            let when_hash = format!("{:x}", Sha256::digest(when_key.as_bytes()));
            let when_label = &when_hash[..16]; // 16-char prefix for readability

            if let Some(apply) = case.get("apply") {
                collect_models_fp(apply, when_label, &mut references, &mut fingerprint_lines);
            }
        }
    }

    fingerprint_lines.sort();
    let variant_fingerprint = if fingerprint_lines.is_empty() {
        None
    } else {
        let digest = Sha256::digest(fingerprint_lines.join("\n").as_bytes());
        Some(format!("{digest:x}"))
    };

    let model_count = references.len();
    DomainParse {
        summary: ResourceSummary::Blockstate(BlockstateSummary {
            variant_count,
            model_count,
            variant_fingerprint,
        }),
        references,
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
    }
}

/// A variant value is an object `{"model": "..."}` or an array of such (weighted).
/// Populates both the reference list and the fingerprint lines
/// (`"variant_key|model|rot|uvlock|weight"`).
fn collect_models_fp(
    v: &Value,
    variant_key: &str,
    refs: &mut Vec<ResourceReference>,
    fp_lines: &mut Vec<String>,
) {
    match v {
        Value::Object(o) => {
            if let Some(model) = o.get("model").and_then(Value::as_str) {
                refs.push(ResourceReference {
                    relation: RefRelation::UsesModel,
                    namespace: namespace_of(model),
                    target: model.to_string(),
                    required: true,
                    conditions: Vec::new(),
                    is_tag: false,
                    certainty: crate::model::ReferenceCertainty::ExactSchemaReference,
                });
                let x = o.get("x").and_then(Value::as_i64).unwrap_or(0);
                let y = o.get("y").and_then(Value::as_i64).unwrap_or(0);
                let uvlock = o.get("uvlock").and_then(Value::as_bool).unwrap_or(false);
                let weight = o.get("weight").and_then(Value::as_i64).unwrap_or(1);
                fp_lines.push(format!(
                    "{variant_key}|{model}|x={x}|y={y}|uvlock={uvlock}|weight={weight}"
                ));
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_models_fp(item, variant_key, refs, fp_lines);
            }
        }
        _ => {}
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
    fn blockstate_model_refs() {
        let v = serde_json::from_str(
            r#"{"variants":{"":{"model":"create:block/cogwheel"},"facing=north":[{"model":"create:block/x"}]}}"#,
        )
        .unwrap();
        let p = parse(&v);
        let ResourceSummary::Blockstate(s) = &p.summary else {
            panic!()
        };
        assert_eq!(s.variant_count, 2);
        assert_eq!(s.model_count, 2);
        assert!(
            p.references
                .iter()
                .all(|r| r.relation == RefRelation::UsesModel)
        );
    }

    #[test]
    fn x_and_y_rotations_have_distinct_fingerprints() {
        let x =
            serde_json::from_str(r#"{"variants":{"":{"model":"example:block/x","x":90,"y":0}}}"#)
                .unwrap();
        let y =
            serde_json::from_str(r#"{"variants":{"":{"model":"example:block/x","x":0,"y":90}}}"#)
                .unwrap();
        let ResourceSummary::Blockstate(x) = parse(&x).summary else {
            panic!()
        };
        let ResourceSummary::Blockstate(y) = parse(&y).summary else {
            panic!()
        };
        assert_ne!(x.variant_fingerprint, y.variant_fingerprint);
    }
}
