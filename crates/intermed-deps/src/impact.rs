//! "Blast radius" analysis: what breaks if a mod is removed or version-bumped.
//!
//! `intermed impact remove <id>` and `intermed impact update <id> <from> -> <to>`
//! are built on the same fact store the doctor collects. Removal impact reads the
//! **reverse resource graph** (every `resource_reference` into the target's
//! namespace, grouped by the referencing resource's domain) plus the declared and
//! implicit dependency edges that point at it. Update impact replays each declared
//! version range against the proposed new version.

use std::collections::BTreeMap;

use intermed_doctor_core::facts::{FactStore, kind};
use serde::{Deserialize, Serialize};

use crate::effective::EffectiveModel;
use crate::semver::version_in_range;

/// Resources that reference the target namespace, broken down by referencing domain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReverseResourceImpact {
    /// `domain → number of resources of that domain referencing the namespace`.
    pub by_domain: BTreeMap<String, usize>,
    /// Total references into the namespace.
    pub total_references: usize,
}

/// One mod that implicitly references the target (with how, and whether disclosed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImplicitDependent {
    pub mod_id: String,
    pub via: String,
    pub required: bool,
    pub ref_count: i64,
}

/// The full removal blast radius for a mod / namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveImpact {
    pub target: String,
    /// Whether the target is actually an installed mod / plugin id.
    pub installed: bool,
    pub resources: ReverseResourceImpact,
    /// Mods whose manifest declares a dependency on the target.
    pub declared_dependents: Vec<String>,
    /// Mods whose resources implicitly reference the target's namespace.
    pub implicit_dependents: Vec<ImplicitDependent>,
    /// Ids the target itself provides (Jar-in-Jar / aliases) — also lost on removal.
    pub provides: Vec<String>,
}

impl RemoveImpact {
    /// True when removing the target would affect nothing observable.
    pub fn is_empty(&self) -> bool {
        self.resources.total_references == 0
            && self.declared_dependents.is_empty()
            && self.implicit_dependents.is_empty()
    }
}

/// Compute the removal blast radius of `target` (a mod id or resource namespace).
pub fn remove_impact(store: &FactStore, target: &str) -> RemoveImpact {
    let model = EffectiveModel::from_store(store);

    // Reverse resource graph: every reference whose namespace is the target, grouped
    // by the referencing resource's domain (recipe / tag / advancement / loot / …).
    let mut path_domain: BTreeMap<&str, &str> = BTreeMap::new();
    for f in store.by_kind(kind::RESOURCE_AST_PARSED) {
        if let Some(d) = f.attr("domain") {
            path_domain.insert(f.subject.as_str(), d);
        }
    }
    let mut by_domain: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = 0usize;
    for f in store.by_kind(kind::RESOURCE_REFERENCE) {
        if f.attr("namespace") == Some(target) {
            let domain = path_domain
                .get(f.subject.as_str())
                .copied()
                .unwrap_or("resource");
            *by_domain.entry(domain.to_string()).or_default() += 1;
            total += 1;
        }
    }

    let declared_dependents: Vec<String> = {
        let mut v: Vec<String> = model
            .declared
            .iter()
            .filter(|d| d.to == target)
            .map(|d| d.from.clone())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };

    let implicit_dependents: Vec<ImplicitDependent> = {
        let mut v: Vec<ImplicitDependent> = model
            .implicit
            .iter()
            .filter(|i| i.provider_mod == target || i.provider_ns == target)
            .map(|i| ImplicitDependent {
                mod_id: i.from.clone(),
                via: i.via.clone(),
                required: i.required,
                ref_count: i.ref_count,
            })
            .collect();
        v.sort_by(|a, b| a.mod_id.cmp(&b.mod_id));
        v.dedup_by(|a, b| a.mod_id == b.mod_id && a.via == b.via);
        v
    };

    let mut provides: Vec<String> = store
        .by_kind(kind::PROVIDED_DEPENDENCY)
        .filter(|f| f.subject == target)
        .filter_map(|f| f.attr("provides").map(str::to_string))
        .collect();
    provides.sort_unstable();
    provides.dedup();

    RemoveImpact {
        target: target.to_string(),
        installed: model.mod_ids.contains(target),
        resources: ReverseResourceImpact {
            by_domain,
            total_references: total,
        },
        declared_dependents,
        implicit_dependents,
        provides,
    }
}

/// One declared dependency whose range no longer accepts the proposed version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakingDep {
    pub mod_id: String,
    pub range: String,
    pub mandatory: bool,
}

/// The result of proposing a version bump of `target` from `from` to `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateImpact {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    pub to: String,
    /// Declared dependents whose range rejects `to` (would break on the bump).
    pub breaks: Vec<BreakingDep>,
    /// Declared dependents that rejected `from` but accept `to` (fixed by the bump).
    pub now_satisfied: Vec<BreakingDep>,
    /// Declared dependents whose range could not be parsed (undecidable).
    pub undecidable: Vec<BreakingDep>,
}

/// Compute the version-bump impact: which declared ranges accept / reject `to`.
pub fn update_impact(
    store: &FactStore,
    target: &str,
    from: Option<&str>,
    to: &str,
) -> UpdateImpact {
    let model = EffectiveModel::from_store(store);
    let mut breaks = Vec::new();
    let mut now_satisfied = Vec::new();
    let mut undecidable = Vec::new();

    for dep in model.declared.iter().filter(|d| d.to == target) {
        let entry = BreakingDep {
            mod_id: dep.from.clone(),
            range: dep.range.clone(),
            mandatory: dep.mandatory,
        };
        match version_in_range(to, &dep.range) {
            Some(true) => {
                // Accepts `to`. If it rejected `from`, the bump fixes it.
                if let Some(from_v) = from {
                    if matches!(version_in_range(from_v, &dep.range), Some(false)) {
                        now_satisfied.push(entry);
                    }
                }
            }
            Some(false) => breaks.push(entry),
            None => undecidable.push(entry),
        }
    }

    breaks.sort_by(|a, b| a.mod_id.cmp(&b.mod_id));
    now_satisfied.sort_by(|a, b| a.mod_id.cmp(&b.mod_id));
    undecidable.sort_by(|a, b| a.mod_id.cmp(&b.mod_id));

    UpdateImpact {
        target: target.to_string(),
        from: from.map(str::to_string),
        to: to.to_string(),
        breaks,
        now_satisfied,
        undecidable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mod_fact(store: &mut FactStore, id: &str, version: &str) {
        store
            .fact("meta", kind::MOD)
            .subject(id)
            .attr("version", version)
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

    fn reference(store: &mut FactStore, path: &str, domain: &str, ns: &str) {
        store
            .fact("resource-ast-scanner", kind::RESOURCE_AST_PARSED)
            .subject(path)
            .attr("domain", domain)
            .emit();
        store
            .fact("resource-ast-scanner", kind::RESOURCE_REFERENCE)
            .subject(path)
            .attr("relation", "uses_recipe_type")
            .attr("to", format!("{ns}:thing"))
            .attr("namespace", ns)
            .emit();
    }

    #[test]
    fn remove_impact_counts_references_by_domain() {
        let mut store = FactStore::new();
        mod_fact(&mut store, "create", "0.5.1");
        mod_fact(&mut store, "addon", "1.0.0");
        reference(&mut store, "data/addon/recipe/a.json", "recipe", "create");
        reference(&mut store, "data/addon/recipe/b.json", "recipe", "create");
        reference(&mut store, "data/addon/tags/items/x.json", "tag", "create");
        declared(&mut store, "addon", "create", ">=0.5.0");

        let impact = remove_impact(&store, "create");
        assert!(impact.installed);
        assert_eq!(impact.resources.total_references, 3);
        assert_eq!(impact.resources.by_domain.get("recipe"), Some(&2));
        assert_eq!(impact.resources.by_domain.get("tag"), Some(&1));
        assert_eq!(impact.declared_dependents, vec!["addon".to_string()]);
    }

    #[test]
    fn update_impact_splits_break_and_fix() {
        let mut store = FactStore::new();
        mod_fact(&mut store, "sodium", "0.5.8");
        declared(&mut store, "iris", "sodium", ">=0.5.0 <0.6.0"); // breaks on 0.6.0
        declared(&mut store, "future", "sodium", ">=0.6.0"); // satisfied by 0.6.0 only

        let impact = update_impact(&store, "sodium", Some("0.5.8"), "0.6.0");
        assert_eq!(impact.breaks.len(), 1);
        assert_eq!(impact.breaks[0].mod_id, "iris");
        assert_eq!(impact.now_satisfied.len(), 1);
        assert_eq!(impact.now_satisfied[0].mod_id, "future");
    }
}
