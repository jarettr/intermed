//! Load-order constraint analysis (`loadbefore` / `loadafter`).

use std::collections::{HashMap, HashSet};

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::{kind, FactId};
use intermed_doctor_core::RuleCtx;

/// Detect contradictory or cyclic Forge/NeoForge / Paper load-order declarations.
pub fn ordering_findings(ctx: &RuleCtx<'_>, rule_id: &str) -> Vec<Finding> {
    let store = ctx.store;
    let installed: HashSet<&str> = store
        .by_kind(kind::MOD)
        .chain(store.by_kind(kind::PLUGIN))
        .map(|f| f.subject.as_str())
        .collect();

    let mut before: Vec<(&str, &str, FactId)> = Vec::new();
    let mut after: Vec<(&str, &str, FactId)> = Vec::new();

    for dep in store.by_kind(kind::DEPENDENCY) {
        let from = dep.subject.as_str();
        let to = dep.attr("dep").unwrap_or("");
        if to.is_empty() || !installed.contains(to) || !installed.contains(from) {
            continue;
        }
        match dep.attr("relation").unwrap_or("depends") {
            "loadbefore" => before.push((from, to, dep.id)),
            "loadafter" => after.push((from, to, dep.id)),
            _ => {}
        }
    }

    let mut out = Vec::new();
    out.extend(mutual_loadbefore_conflicts(&before, rule_id));
    out.extend(loadbefore_cycles(&before, rule_id));
    out.extend(before_after_conflicts(&before, &after, rule_id));
    out
}

fn mutual_loadbefore_conflicts(edges: &[(&str, &str, FactId)], rule_id: &str) -> Vec<Finding> {
    let mut pairs = HashSet::new();
    let mut out = Vec::new();
    for &(a, b, fact_a) in edges {
        if let Some((_, _, fact_b)) = edges.iter().find(|&&(x, y, _)| x == b && y == a) {
            let key = if a < b { (a, b) } else { (b, a) };
            if !pairs.insert(key) {
                continue;
            }
            out.push(
                Finding::builder(rule_id, format!("ordering-conflict:{a}<->{b}"))
                    .severity(Severity::Warn)
                    .category(Category::Dependency)
                    .title(format!("Conflicting load order: `{a}` vs `{b}`"))
                    .explanation(format!(
                        "Both `{a}` and `{b}` declare they must load before the other. \
                         The Forge/NeoForge loader may pick an arbitrary order or fail at runtime."
                    ))
                    .evidence(EvidenceEdge::subject(fact_a))
                    .evidence(EvidenceEdge::supports(*fact_b))
                    .affects(a)
                    .affects(b)
                    .fix(FixCandidate::advice(format!(
                        "Remove one of the opposing loadbefore/loadafter edges between `{a}` and `{b}`."
                    )))
                    .tag("dependency")
                    .tag("ordering")
                    .build(),
            );
        }
    }
    out
}

fn loadbefore_cycles(edges: &[(&str, &str, FactId)], rule_id: &str) -> Vec<Finding> {
    let mut adj: HashMap<&str, Vec<(&str, FactId)>> = HashMap::new();
    for &(from, to, id) in edges {
        adj.entry(from).or_default().push((to, id));
    }

    let mut out = Vec::new();
    if let Some(cycle) = find_loadbefore_cycle(&adj) {
        let chain = cycle.join(" → ");
        let first_fact = edges
            .iter()
            .find(|(a, b, _)| {
                cycle
                    .windows(2)
                    .any(|w| w[0] == *a && w[1] == *b)
            })
            .map(|(_, _, id)| id)
            .copied();
        let mut builder = Finding::builder(rule_id, format!("ordering-cycle:{}", cycle[0]))
            .severity(Severity::Warn)
            .category(Category::Dependency)
            .title("Circular mod load order".to_string())
            .explanation(format!(
                "Load-before constraints form a cycle: {chain}. Cycles are undefined for the mod loader."
            ))
            .affects(cycle[0].to_string())
            .fix(FixCandidate::advice(
                "Break the cycle by removing or reversing one loadbefore/loadafter dependency.",
            ))
            .tag("dependency")
            .tag("ordering");
        if let Some(id) = first_fact {
            builder = builder.evidence(EvidenceEdge::subject(id));
        }
        out.push(builder.build());
    }
    out
}

fn find_loadbefore_cycle<'a>(
    adj: &HashMap<&'a str, Vec<(&'a str, FactId)>>,
) -> Option<Vec<&'a str>> {
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    let mut path = Vec::new();

    for &start in adj.keys() {
        if dfs_cycle(start, adj, &mut visiting, &mut visited, &mut path) {
            return Some(path.clone());
        }
    }
    None
}

fn dfs_cycle<'a>(
    node: &'a str,
    adj: &HashMap<&'a str, Vec<(&'a str, FactId)>>,
    visiting: &mut HashSet<&'a str>,
    visited: &mut HashSet<&'a str>,
    path: &mut Vec<&'a str>,
) -> bool {
    if visiting.contains(node) {
        if let Some(pos) = path.iter().position(|&n| n == node) {
            *path = path[pos..].to_vec();
            path.push(node);
        }
        return true;
    }
    if visited.contains(node) {
        return false;
    }
    visiting.insert(node);
    path.push(node);
    if let Some(nexts) = adj.get(node) {
        for (next, _) in nexts {
            if dfs_cycle(next, adj, visiting, visited, path) {
                return true;
            }
        }
    }
    visiting.remove(node);
    visited.insert(node);
    path.pop();
    false
}

fn before_after_conflicts(
    before: &[(&str, &str, FactId)],
    after: &[(&str, &str, FactId)],
    rule_id: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for &(a, b, fact_a) in before {
        if let Some((_, _, fact_b)) = after.iter().find(|&&(x, y, _)| x == a && y == b) {
            out.push(
                Finding::builder(rule_id, format!("ordering-conflict:{a}->{b}"))
                    .severity(Severity::Warn)
                    .category(Category::Dependency)
                    .title(format!("Contradictory ordering for `{a}` and `{b}`"))
                    .explanation(format!(
                        "`{a}` must load both before and after `{b}` (loadbefore + loadafter)."
                    ))
                    .evidence(EvidenceEdge::subject(fact_a))
                    .evidence(EvidenceEdge::supports(*fact_b))
                    .affects(a)
                    .affects(b)
                    .tag("dependency")
                    .tag("ordering")
                    .build(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::{kind, FactStore};
    use intermed_doctor_core::{RuleCtx, Target, TargetKind};

    fn ctx(store: &FactStore) -> RuleCtx<'_> {
        static TARGET: std::sync::LazyLock<Target> = std::sync::LazyLock::new(|| Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        });
        RuleCtx::for_test(store, &TARGET)
    }

    #[test]
    fn mutual_loadbefore_emits_conflict() {
        let mut store = FactStore::new();
        for id in ["a", "b"] {
            store.fact("m", kind::MOD).subject(id).emit();
        }
        store
            .fact("m", kind::DEPENDENCY)
            .subject("a")
            .attr("dep", "b")
            .attr("relation", "loadbefore")
            .emit();
        store
            .fact("m", kind::DEPENDENCY)
            .subject("b")
            .attr("dep", "a")
            .attr("relation", "loadbefore")
            .emit();

        let findings = ordering_findings(&ctx(&store), "dependency");
        assert!(findings.iter().any(|f| f.id.starts_with("ordering-conflict:")));
    }
}