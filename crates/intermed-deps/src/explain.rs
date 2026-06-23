//! Explainable dependency intelligence: `why`, `why-missing`, `implicit`, `path`.
//!
//! These turn the solver from "found an error" into an answerable model. Each edge
//! in the combined graph is either **declared** (a manifest `depends`/… ) or
//! **implicit** (a structural resource reference into another mod's namespace), and
//! every answer is a list of such edges rendered as a human chain, e.g.
//!
//! ```text
//! waystones -> declared dependency -> balm-fabric >=7.0.0
//! modX      -> recipe serializer   -> create (namespace create)
//! ```

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use intermed_doctor_core::facts::FactStore;
use serde::{Deserialize, Serialize};

use crate::effective::EffectiveModel;

/// How one dependency edge was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeKind {
    Declared,
    Implicit,
}

/// One edge in the combined (declared + implicit) dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    /// Human label: a version range for declared edges, the `via` for implicit ones.
    pub detail: String,
    /// True when this edge expresses a hard requirement (mandatory / unconditioned).
    pub required: bool,
}

impl DepEdge {
    /// Render as one explanation line.
    pub fn render(&self) -> String {
        match self.kind {
            EdgeKind::Declared => format!(
                "{} -> declared dependency -> {} {}",
                self.from, self.to, self.detail
            ),
            EdgeKind::Implicit => format!(
                "{} -> {} -> namespace {} -> provider {}",
                self.from, self.detail, self.to, self.to
            ),
        }
    }
}

/// All combined edges for a pack, with adjacency for path search.
#[derive(Debug, Default)]
pub struct DependencyIndex {
    pub edges: Vec<DepEdge>,
    /// `id → installed?`
    present: BTreeSet<String>,
}

impl DependencyIndex {
    pub fn from_store(store: &FactStore) -> Self {
        let model = EffectiveModel::from_store(store);
        let mut edges = Vec::new();
        for d in &model.declared {
            edges.push(DepEdge {
                from: d.from.clone(),
                to: d.to.clone(),
                kind: EdgeKind::Declared,
                detail: d.range.clone(),
                required: d.mandatory,
            });
        }
        let mut present = model.providers;
        for i in &model.implicit {
            let to = if i.provider_mod.is_empty() {
                i.provider_ns.clone()
            } else {
                i.provider_mod.clone()
            };
            // An implicit edge that resolved as present (directly or via an alias)
            // is evidence the provider exists, even if its literal id is not an
            // installed mod id (e.g. satisfied through a `provides` alias table).
            if i.provider_present() {
                present.insert(to.clone());
            }
            edges.push(DepEdge {
                from: i.from.clone(),
                to,
                kind: EdgeKind::Implicit,
                detail: format!("{} {}", i.via, i.provider_ns),
                required: i.required,
            });
        }
        DependencyIndex { edges, present }
    }

    /// Edges pointing *at* `id` (who depends on it).
    fn dependents_of(&self, id: &str) -> Vec<&DepEdge> {
        self.edges.iter().filter(|e| e.to == id).collect()
    }

    /// Whether `id` is installed / provided in the pack.
    pub fn is_present(&self, id: &str) -> bool {
        self.present.contains(id)
    }
}

/// Answer to `deps why <id>` / `deps why-missing <id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhyReport {
    pub id: String,
    pub present: bool,
    /// Edges that establish `id` as a dependency, declared first then implicit.
    pub reasons: Vec<DepEdge>,
}

impl WhyReport {
    /// Render the report as text lines.
    pub fn render(&self) -> String {
        if self.reasons.is_empty() {
            return format!(
                "{} is {} and nothing in the pack depends on it.",
                self.id,
                if self.present { "installed" } else { "absent" }
            );
        }
        let mut lines = vec![format!(
            "{} is {} — required by:",
            self.id,
            if self.present { "installed" } else { "ABSENT" }
        )];
        for e in &self.reasons {
            lines.push(format!("  {}", e.render()));
        }
        lines.join("\n")
    }
}

/// `deps why <id>`: every declared + implicit reason `id` is depended upon.
pub fn why(store: &FactStore, id: &str) -> WhyReport {
    let index = DependencyIndex::from_store(store);
    let mut reasons: Vec<DepEdge> = index.dependents_of(id).into_iter().cloned().collect();
    reasons.sort_by(|a, b| {
        (a.kind == EdgeKind::Implicit, &a.from).cmp(&(b.kind == EdgeKind::Implicit, &b.from))
    });
    WhyReport {
        id: id.to_string(),
        present: index.is_present(id),
        reasons,
    }
}

/// `deps why-missing <id>`: like `why`, but only the *required* reasons and only
/// meaningful when `id` is absent (the explanation of a missing dependency).
pub fn why_missing(store: &FactStore, id: &str) -> WhyReport {
    let mut report = why(store, id);
    report.reasons.retain(|e| e.required);
    report
}

/// One implicit reference into a namespace, with concrete provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImplicitRef {
    pub consumer: String,
    pub via: String,
    pub required: bool,
    pub ref_count: i64,
    pub sample_path: String,
    pub resolve_state: String,
}

/// `deps implicit <dir> --namespace <ns>`: list implicit references to a namespace.
pub fn implicit_for_namespace(store: &FactStore, ns: &str) -> Vec<ImplicitRef> {
    let model = EffectiveModel::from_store(store);
    let mut out: Vec<ImplicitRef> = model
        .implicit
        .iter()
        .filter(|i| i.provider_ns == ns || i.provider_mod == ns)
        .map(|i| ImplicitRef {
            consumer: i.from.clone(),
            via: i.via.clone(),
            required: i.required,
            ref_count: i.ref_count,
            sample_path: i.sample_path.clone(),
            resolve_state: i.resolve_state.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.consumer.cmp(&b.consumer));
    out
}

/// `deps path <from> <to>`: a dependency chain from `from` to `to`, if one exists.
pub fn path(store: &FactStore, from: &str, to: &str) -> Option<Vec<DepEdge>> {
    let index = DependencyIndex::from_store(store);
    // Adjacency: from → outgoing edges.
    let mut adj: BTreeMap<&str, Vec<&DepEdge>> = BTreeMap::new();
    for e in &index.edges {
        adj.entry(e.from.as_str()).or_default().push(e);
    }
    // BFS, tracking the edge used to reach each node.
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    let mut came_from: BTreeMap<&str, &DepEdge> = BTreeMap::new();
    visited.insert(from);
    queue.push_back(from);
    while let Some(node) = queue.pop_front() {
        if node == to {
            // Reconstruct.
            let mut chain = Vec::new();
            let mut cur = to;
            while cur != from {
                let e = came_from.get(cur)?;
                chain.push((*e).clone());
                cur = e.from.as_str();
            }
            chain.reverse();
            return Some(chain);
        }
        if let Some(edges) = adj.get(node) {
            for e in edges {
                if visited.insert(e.to.as_str()) {
                    came_from.insert(e.to.as_str(), e);
                    queue.push_back(e.to.as_str());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::kind;

    fn mod_fact(store: &mut FactStore, id: &str) {
        store
            .fact("meta", kind::MOD)
            .subject(id)
            .attr("version", "1.0.0")
            .emit();
    }

    fn declared(store: &mut FactStore, from: &str, to: &str, range: &str) {
        store
            .fact("meta", kind::DEPENDENCY)
            .subject(from)
            .attr("dep", to)
            .attr("range", range)
            .attr("mandatory", true)
            .attr("relation", "depends")
            .emit();
    }

    fn implicit(store: &mut FactStore, from: &str, ns: &str) {
        store
            .fact("resource-ast-scanner", kind::IMPLICIT_DEPENDENCY_EDGE)
            .subject(from)
            .attr("provider_namespace", ns)
            .attr("provider_mod", ns)
            .attr("via", "recipe-serializer")
            .attr("required", true)
            .attr("hard", true)
            .attr("ref_count", 2_i64)
            .attr("from_path", format!("data/{from}/recipe/x.json"))
            .attr("resolve_state", "present")
            .emit();
    }

    #[test]
    fn why_lists_declared_and_implicit_reasons() {
        let mut store = FactStore::new();
        mod_fact(&mut store, "create");
        mod_fact(&mut store, "waystones");
        declared(&mut store, "waystones", "create", ">=0.5.0");
        implicit(&mut store, "addon", "create");
        let r = why(&store, "create");
        assert!(r.present);
        assert_eq!(r.reasons.len(), 2);
        assert!(r.render().contains("waystones"));
        assert!(r.render().contains("addon"));
    }

    #[test]
    fn path_finds_transitive_chain() {
        let mut store = FactStore::new();
        declared(&mut store, "a", "b", "*");
        declared(&mut store, "b", "c", "*");
        let chain = path(&store, "a", "c").expect("path");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].from, "a");
        assert_eq!(chain[1].to, "c");
    }

    #[test]
    fn path_absent_when_disconnected() {
        let mut store = FactStore::new();
        declared(&mut store, "a", "b", "*");
        assert!(path(&store, "a", "z").is_none());
    }
}
