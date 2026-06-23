//! Atlas domain (`assets/<ns>/atlases/<path>.json`): lists texture *sources*.
//! Two packs adding disjoint simple sources merge safely; overlapping or
//! directory sources are order-dependent.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::DomainParse;
use crate::model::{ParseStatus, RefRelation, ResourceReference, ResourceSummary};
use crate::semantic::namespace::namespace_of;

pub const ATLAS_AST_VERSION: &str = "atlas-r2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtlasSummary {
    pub source_count: usize,
    /// Whether any source is a non-`single` type (directory/filter) — these are
    /// not disjoint-mergeable.
    pub has_non_single_source: bool,
    /// Normalized descriptor per source (`single:create:block/x`,
    /// `directory:block`, …), sorted. The discriminator for cross-writer atlas
    /// source diffs — `single` sources also produce a reference edge, but
    /// directory/filter sources do not, so the summary is the source of truth.
    #[serde(default)]
    pub sources: Vec<String>,
}

/// Parse an atlas resource.
pub fn parse(value: &Value) -> DomainParse {
    let Some(sources) = value.get("sources").and_then(Value::as_array) else {
        return DomainParse::invalid(vec![diag("atlas has no `sources` array")]);
    };
    let mut references = Vec::new();
    let mut has_non_single_source = false;
    let mut descriptors = Vec::new();
    for source in sources {
        let Some(obj) = source.as_object() else {
            continue;
        };
        let kind = obj.get("type").and_then(Value::as_str).unwrap_or("");
        if kind.ends_with("single") {
            if let Some(resource) = obj.get("resource").and_then(Value::as_str) {
                descriptors.push(format!("single:{resource}"));
                references.push(ResourceReference {
                    relation: RefRelation::AtlasSource,
                    namespace: namespace_of(resource),
                    target: resource.to_string(),
                    required: true,
                    conditions: Vec::new(),
                    is_tag: false,
                });
            }
        } else {
            has_non_single_source = true;
            // Identify the source by its `source`/`namespace`/`id` payload so two
            // writers' directory/filter sources can be compared.
            let detail = obj
                .get("source")
                .or_else(|| obj.get("namespace"))
                .or_else(|| obj.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let short = kind.rsplit(':').next().unwrap_or(kind);
            descriptors.push(format!("{short}:{detail}"));
        }
    }
    descriptors.sort();
    descriptors.dedup();

    DomainParse {
        summary: ResourceSummary::Atlas(AtlasSummary {
            source_count: sources.len(),
            has_non_single_source,
            sources: descriptors,
        }),
        references,
        diagnostics: Vec::new(),
        status: ParseStatus::Parsed,
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
    fn atlas_single_sources() {
        let v = serde_json::from_str(
            r#"{"sources":[{"type":"minecraft:single","resource":"create:block/x"},{"type":"minecraft:directory","source":"block"}]}"#,
        )
        .unwrap();
        let p = parse(&v);
        let ResourceSummary::Atlas(s) = &p.summary else {
            panic!()
        };
        assert_eq!(s.source_count, 2);
        assert!(s.has_non_single_source);
        assert_eq!(p.references.len(), 1);
    }
}
