//! Model domain (`assets/<ns>/models/<path>.json`): a parent model + texture
//! references. Drives missing-parent / missing-texture graph rules.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::DomainParse;
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

pub const MODEL_AST_VERSION: &str = "model-r1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSummary {
    pub parent: Option<String>,
    pub texture_count: usize,
    pub override_count: usize,
}

/// Parse a model resource.
pub fn parse(value: &Value) -> DomainParse {
    let Some(obj) = value.as_object() else {
        return DomainParse::invalid(vec![diag("model root is not a JSON object")]);
    };
    let mut references = Vec::new();

    let parent = obj.get("parent").and_then(Value::as_str).map(str::to_string);
    if let Some(p) = &parent {
        references.push(reference(RefRelation::ParentModel, p));
    }

    let mut texture_count = 0;
    if let Some(textures) = obj.get("textures").and_then(Value::as_object) {
        for v in textures.values() {
            if let Some(tex) = v.as_str() {
                // `#name` texture variables reference another key, not an asset.
                if !tex.starts_with('#') {
                    references.push(reference(RefRelation::UsesTexture, tex));
                    texture_count += 1;
                }
            }
        }
    }

    let override_count = obj
        .get("overrides")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);

    DomainParse {
        summary: ResourceSummary::Model(ModelSummary {
            parent,
            texture_count,
            override_count,
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
        conditioned: false,
        is_tag: false,
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
        let ResourceSummary::Model(s) = &p.summary else { panic!() };
        assert_eq!(s.parent.as_deref(), Some("minecraft:item/generated"));
        assert_eq!(s.texture_count, 1); // `#layer0` is a variable, not a ref
        assert!(p.references.iter().any(|r| r.relation == RefRelation::ParentModel));
        assert!(p.references.iter().any(|r| r.relation == RefRelation::UsesTexture));
    }
}
