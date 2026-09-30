//! Lossless Quilt dependency expressions plus conservative legacy-edge
//! projection. Quilt dependency alternatives are nested arrays, while
//! `versions.any` / `versions.all` form a separate version-expression tree.
//! Flattening either tree (or `unless`) loses satisfiability information.

use serde::{Deserialize, Serialize};

use super::Dep;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operator", rename_all = "snake_case")]
pub(super) enum QuiltDependencyExpr {
    Atom {
        id: String,
        versions: String,
        optional: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        environment: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        unless: Option<Box<QuiltDependencyExpr>>,
    },
    Any {
        terms: Vec<QuiltDependencyExpr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DependencyExpression {
    pub relation: String,
    pub expression: String,
}

pub(super) fn parse_array(
    value: Option<&serde_json::Value>,
    relation: &'static str,
    mandatory: bool,
) -> (Vec<Dep>, Vec<DependencyExpression>) {
    let mut deps = Vec::new();
    let mut expressions = Vec::new();
    let Some(values) = value.and_then(serde_json::Value::as_array) else {
        return (deps, expressions);
    };
    for value in values {
        let Some(expression) = parse_expr(value) else {
            continue;
        };
        lower_legacy_edges(&expression, relation, mandatory, None, &mut deps);
        if needs_group_evaluation(&expression)
            && let Ok(serialized) = serde_json::to_string(&expression)
        {
            expressions.push(DependencyExpression {
                relation: relation.to_string(),
                expression: serialized,
            });
        }
    }
    (deps, expressions)
}

fn needs_group_evaluation(expression: &QuiltDependencyExpr) -> bool {
    match expression {
        QuiltDependencyExpr::Any { .. } => true,
        QuiltDependencyExpr::Atom {
            environment,
            unless,
            ..
        } => environment.is_some() || unless.is_some(),
    }
}

fn parse_expr(value: &serde_json::Value) -> Option<QuiltDependencyExpr> {
    if let Some(id) = value.as_str() {
        return Some(QuiltDependencyExpr::Atom {
            id: id.to_string(),
            versions: "*".to_string(),
            optional: false,
            environment: None,
            unless: None,
        });
    }
    if let Some(terms) = value.as_array() {
        return Some(QuiltDependencyExpr::Any {
            terms: terms.iter().filter_map(parse_expr).collect(),
        });
    }
    let object = value.as_object()?;
    let id = object.get("id").and_then(serde_json::Value::as_str)?;
    let versions = object
        .get("versions")
        .map(version_expr)
        .unwrap_or_else(|| "*".to_string());
    let unless = object.get("unless").and_then(parse_expr).map(Box::new);
    Some(QuiltDependencyExpr::Atom {
        id: id.to_string(),
        versions,
        optional: object
            .get("optional")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        environment: object
            .get("environment")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        unless,
    })
}

fn lower_legacy_edges(
    expression: &QuiltDependencyExpr,
    relation: &'static str,
    mandatory: bool,
    inherited_condition: Option<String>,
    deps: &mut Vec<Dep>,
) {
    match expression {
        QuiltDependencyExpr::Any { terms } => {
            let condition = serde_json::to_string(expression).ok();
            for term in terms {
                lower_legacy_edges(term, relation, false, condition.clone(), deps);
            }
        }
        QuiltDependencyExpr::Atom {
            id,
            versions,
            optional,
            environment,
            unless,
        } => {
            let conditional = environment.is_some() || unless.is_some();
            let condition = if conditional || inherited_condition.is_some() {
                serde_json::to_string(expression)
                    .ok()
                    .or(inherited_condition)
            } else {
                None
            };
            deps.push(Dep {
                id: id.clone(),
                range: versions.clone(),
                mandatory: mandatory && !optional && !conditional,
                relation,
                feature: None,
                lifecycle: None,
                ordering: None,
                join_classpath: None,
                condition,
                side: None,
            });
        }
    }
}

fn version_expr(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| serde_json::to_string(value).unwrap_or_else(|_| "*".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_alternatives_and_unless_round_trip_without_flattening() {
        let input = serde_json::json!([
            [{"id":"a"}, {"id":"b"}],
            {"id":"c", "unless":{"id":"replacement"}}
        ]);
        let (edges, expressions) = parse_array(Some(&input), "depends", true);
        assert_eq!(expressions.len(), 2);
        let decoded: QuiltDependencyExpr =
            serde_json::from_str(&expressions[0].expression).unwrap();
        assert!(matches!(decoded, QuiltDependencyExpr::Any { .. }));
        assert!(!edges.iter().any(|edge| edge.id == "a" && edge.mandatory));
        assert!(!edges.iter().any(|edge| edge.id == "c" && edge.mandatory));
    }

    #[test]
    fn version_any_all_remain_a_range_on_one_dependency() {
        let input = serde_json::json!([{
            "id": "provider",
            "versions": {"all": [">=1.0.0", "<2.0.0"]}
        }]);
        let (edges, expressions) = parse_array(Some(&input), "depends", true);
        assert!(expressions.is_empty());
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].id, "provider");
        assert_eq!(edges[0].range, r#"{"all":[">=1.0.0","<2.0.0"]}"#);
    }
}
