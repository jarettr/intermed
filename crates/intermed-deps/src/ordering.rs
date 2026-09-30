//! Load-order constraint analysis over one normalized `before -> after` graph.

use std::collections::{BTreeMap, BTreeSet};

use intermed_doctor_core::RuleCtx;
use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::FactId;

use crate::model::{ConstraintApplicability, ResolvedDependencyModel};

#[derive(Debug, Clone)]
struct OrderingEdge {
    before: String,
    after: String,
    fact_id: FactId,
}

/// Detect every cyclic strongly connected component across both load-before and
/// load-after declarations. One finding represents one actionable cycle group.
pub fn ordering_findings(ctx: &RuleCtx<'_>, rule_id: &str) -> Vec<Finding> {
    let model = ResolvedDependencyModel::from_store(ctx.store);
    let installed = model
        .confirmed_packages()
        .map(|package| package.id.as_str())
        .collect::<BTreeSet<_>>();
    let edges = model
        .constraints
        .iter()
        .filter(|constraint| constraint.applicability == ConstraintApplicability::Active)
        .filter_map(|constraint| {
            let (before, after) = constraint
                .relation
                .ordering_edge(&constraint.from, &constraint.to)?;
            (installed.contains(before) && installed.contains(after)).then(|| OrderingEdge {
                before: before.to_string(),
                after: after.to_string(),
                fact_id: constraint.fact_id,
            })
        })
        .collect::<Vec<_>>();

    strongly_connected_components(&edges)
        .into_iter()
        .filter(|component| {
            component.len() > 1
                || edges
                    .iter()
                    .any(|edge| edge.before == component[0] && edge.after == component[0])
        })
        .map(|component| cycle_finding(rule_id, &component, &edges))
        .collect()
}

fn cycle_finding(rule_id: &str, component: &[String], edges: &[OrderingEdge]) -> Finding {
    let members = component.iter().cloned().collect::<BTreeSet<_>>();
    let internal_edges = edges
        .iter()
        .filter(|edge| members.contains(&edge.before) && members.contains(&edge.after))
        .collect::<Vec<_>>();
    let chain = component.join(" ↔ ");
    let semantic_key = component.join("+");
    let mut builder = Finding::builder(rule_id, format!("ordering-cycle:{semantic_key}"))
        .severity(Severity::Warn)
        .category(Category::Dependency)
        .title("Circular mod load order".to_string())
        .explanation(format!(
            "Normalized load-before/load-after constraints form a cycle among: {chain}. \
             No ordering can satisfy every declaration."
        ))
        .fix(FixCandidate::advice(
            "Break the cycle by removing or reversing at least one ordering declaration in this group.",
        ))
        .tag("dependency")
        .tag("ordering");
    for member in component {
        builder = builder.affects(member);
    }
    for edge in internal_edges {
        builder = builder.evidence(EvidenceEdge::supports(edge.fact_id));
    }
    builder.build()
}

fn strongly_connected_components(edges: &[OrderingEdge]) -> Vec<Vec<String>> {
    let mut nodes = BTreeSet::new();
    let mut graph = BTreeMap::<String, Vec<String>>::new();
    let mut reverse = BTreeMap::<String, Vec<String>>::new();
    for edge in edges {
        nodes.insert(edge.before.clone());
        nodes.insert(edge.after.clone());
        graph
            .entry(edge.before.clone())
            .or_default()
            .push(edge.after.clone());
        reverse
            .entry(edge.after.clone())
            .or_default()
            .push(edge.before.clone());
    }
    for neighbours in graph.values_mut().chain(reverse.values_mut()) {
        neighbours.sort();
        neighbours.dedup();
    }

    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for node in &nodes {
        finish_order(node, &graph, &mut visited, &mut order);
    }
    visited.clear();
    let mut components = Vec::new();
    for node in order.into_iter().rev() {
        if visited.contains(&node) {
            continue;
        }
        let mut component = Vec::new();
        collect_component(&node, &reverse, &mut visited, &mut component);
        component.sort();
        components.push(component);
    }
    components.sort();
    components
}

fn finish_order(
    node: &str,
    graph: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
    order: &mut Vec<String>,
) {
    if !visited.insert(node.to_string()) {
        return;
    }
    if let Some(next) = graph.get(node) {
        for child in next {
            finish_order(child, graph, visited, order);
        }
    }
    order.push(node.to_string());
}

fn collect_component(
    node: &str,
    graph: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
    component: &mut Vec<String>,
) {
    if !visited.insert(node.to_string()) {
        return;
    }
    component.push(node.to_string());
    if let Some(next) = graph.get(node) {
        for child in next {
            collect_component(child, graph, visited, component);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::{FactStore, kind};
    use intermed_doctor_core::{Target, TargetKind};

    fn run(store: &FactStore) -> Vec<Finding> {
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        ordering_findings(&RuleCtx::for_test(store, &target), "dependency")
    }

    #[test]
    fn mixed_before_after_cycle_is_detected_with_all_evidence() {
        let mut store = FactStore::new();
        for id in ["a", "b", "c"] {
            store.fact("test", kind::MOD).subject(id).emit();
        }
        for (from, to, relation) in [
            ("a", "b", "loadafter"), // b -> a
            ("b", "c", "loadafter"), // c -> b
            ("c", "a", "loadafter"), // a -> c
        ] {
            store
                .fact("test", kind::DEPENDENCY)
                .subject(from)
                .attr("dep", to)
                .attr("relation", relation)
                .emit();
        }
        let findings = run(&store);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.len(), 3);
    }

    #[test]
    fn inactive_descriptor_ordering_is_ignored() {
        let mut store = FactStore::new();
        for id in ["a", "b"] {
            store.fact("test", kind::MOD).subject(id).emit();
        }
        for (from, to) in [("a", "b"), ("b", "a")] {
            store
                .fact("test", kind::DEPENDENCY)
                .subject(from)
                .attr("dep", to)
                .attr("relation", "loadbefore")
                .attr("identity_certainty", "cross-loader-unresolved")
                .emit();
        }
        assert!(run(&store).is_empty());
    }
}
