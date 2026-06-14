//! Blockstate domain (`assets/<ns>/blockstates/<path>.json`): references the
//! models its variants / multipart cases use.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::DomainParse;
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

pub const BLOCKSTATE_AST_VERSION: &str = "blockstate-r1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockstateSummary {
    pub variant_count: usize,
    pub model_count: usize,
}

/// Parse a blockstate resource.
pub fn parse(value: &Value) -> DomainParse {
    let Some(obj) = value.as_object() else {
        return DomainParse::invalid(vec![diag("blockstate root is not a JSON object")]);
    };
    let mut references = Vec::new();
    let mut variant_count = 0;

    if let Some(variants) = obj.get("variants").and_then(Value::as_object) {
        variant_count = variants.len();
        for v in variants.values() {
            collect_models(v, &mut references);
        }
    }
    if let Some(multipart) = obj.get("multipart").and_then(Value::as_array) {
        variant_count += multipart.len();
        for case in multipart {
            if let Some(apply) = case.get("apply") {
                collect_models(apply, &mut references);
            }
        }
    }

    let model_count = references.len();
    DomainParse {
        summary: ResourceSummary::Blockstate(BlockstateSummary {
            variant_count,
            model_count,
        }),
        references,
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
    }
}

/// A variant value is an object `{"model": "..."}` or an array of such (weighted).
fn collect_models(v: &Value, refs: &mut Vec<ResourceReference>) {
    match v {
        Value::Object(o) => {
            if let Some(model) = o.get("model").and_then(Value::as_str) {
                refs.push(ResourceReference {
                    relation: RefRelation::UsesModel,
                    namespace: namespace_of(model),
                    target: model.to_string(),
                    required: true,
                    conditioned: false,
                    is_tag: false,
                });
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_models(item, refs);
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
        let ResourceSummary::Blockstate(s) = &p.summary else { panic!() };
        assert_eq!(s.variant_count, 2);
        assert_eq!(s.model_count, 2);
        assert!(p.references.iter().all(|r| r.relation == RefRelation::UsesModel));
    }
}
