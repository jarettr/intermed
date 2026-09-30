//! Model domain (`assets/<ns>/models/<path>.json`): a parent model + texture
//! references. Drives missing-parent / missing-texture graph rules.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::domain::DomainParse;
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

pub const MODEL_AST_VERSION: &str = "model-r3";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSummary {
    pub parent: Option<String>,
    /// Texture slot → texture id mappings (sorted). Excludes texture variables
    /// (`#name` slots).
    pub textures: BTreeMap<String, String>,
    /// SHA256 fingerprint of the overrides array, when present. Order matters for
    /// overrides (first match wins), so a simple count is lossy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides_fingerprint: Option<String>,
}

/// Parse a model resource.
pub fn parse(value: &Value) -> DomainParse {
    let Some(obj) = value.as_object() else {
        return DomainParse::invalid(vec![diag("model root is not a JSON object")]);
    };
    let mut references = Vec::new();

    let parent = obj
        .get("parent")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(p) = &parent {
        references.push(reference(RefRelation::ParentModel, p));
    }

    let mut textures = BTreeMap::new();
    if let Some(tex_obj) = obj.get("textures").and_then(Value::as_object) {
        for (key, v) in tex_obj {
            if let Some(tex) = v.as_str() {
                // `#name` texture variables reference another key, not an asset.
                if !tex.starts_with('#') {
                    references.push(reference(RefRelation::UsesTexture, tex));
                    textures.insert(key.clone(), tex.to_string());
                }
            }
        }
    }

    // Fingerprint the overrides array (order matters: first match wins).
    let overrides_fingerprint = obj
        .get("overrides")
        .and_then(Value::as_array)
        .and_then(|arr| {
            if arr.is_empty() {
                None
            } else {
                serde_json::to_vec(arr)
                    .ok()
                    .map(|b| format!("{:x}", Sha256::digest(&b)))
            }
        });

    DomainParse {
        summary: ResourceSummary::Model(ModelSummary {
            parent,
            textures,
            overrides_fingerprint,
        }),
        references,
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
    }
}

fn reference(relation: RefRelation, id: &str) -> ResourceReference {
    ResourceReference {
        relation,
        namespace: namespace_of(id),
        target: id.to_string(),
        required: true,
        conditions: Vec::new(),
        is_tag: false,
        certainty: crate::model::ReferenceCertainty::ExactSchemaReference,
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
    fn model_texture_refs() {
        let v = serde_json::from_str(
            r##"{"parent":"minecraft:item/generated","textures":{"layer0":"create:item/wrench","x":"#layer0"}}"##,
        )
        .unwrap();
        let p = parse(&v);
        let ResourceSummary::Model(s) = &p.summary else {
            panic!()
        };
        assert_eq!(s.parent.as_deref(), Some("minecraft:item/generated"));
        assert_eq!(s.textures.len(), 1); // `#layer0` is a variable, not a ref
        assert!(
            p.references
                .iter()
                .any(|r| r.relation == RefRelation::ParentModel)
        );
        assert!(
            p.references
                .iter()
                .any(|r| r.relation == RefRelation::UsesTexture)
        );
    }
}
