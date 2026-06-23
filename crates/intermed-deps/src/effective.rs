//! The three-level dependency model and the findings only it can see.
//!
//! Layer C already checks *declared* dependencies pairwise (missing / version) and
//! globally (PubGrub). This module adds the **implicit** and **effective** levels
//! and the cross-level findings the pairwise view cannot reach:
//!
//! - **Declared**  — `depends` / `recommends` / … from the mod manifest, surfaced
//!   as `dependency` facts.
//! - **Implicit**  — a structural resource reference into another mod's namespace
//!   (recipe serializer `type`, registry ref, loot function), attributed per-mod by
//!   Layer M as `implicit_dependency_edge`.
//! - **Effective** — declared ∪ implicit, minus conditionally-disabled references,
//!   plus the conditional ones surfaced as soft requirements.
//!
//! Anti-false-positive governs every finding here, consistent with the rest of the
//! crate: an undisclosed edge is only raised for an *installed* provider reached by
//! an *unconditioned* structural reference, a too-wide range needs a real lower
//! bound (a bare `*` expresses no intent and is never flagged), and the speculative
//! `declared-but-unused` finding is explain-only and low-confidence.

use std::collections::{BTreeMap, BTreeSet};

use intermed_doctor_core::RuleCtx;
use intermed_doctor_core::evidence::{
    Category, EvidenceEdge, Finding, FindingVisibility, FixCandidate, Severity,
};
use intermed_doctor_core::facts::{FactId, FactStore, kind};

use crate::graph::is_platform_dep;

/// A declared dependency edge taken from a `dependency` fact.
#[derive(Debug, Clone)]
pub struct DeclaredDep {
    pub from: String,
    pub to: String,
    pub range: String,
    pub relation: String,
    pub mandatory: bool,
    pub fact_id: FactId,
}

/// A per-mod implicit dependency edge taken from an `implicit_dependency_edge` fact.
#[derive(Debug, Clone)]
pub struct ImplicitDep {
    pub from: String,
    pub provider_ns: String,
    pub provider_mod: String,
    pub via: String,
    pub required: bool,
    pub conditioned: bool,
    pub hard: bool,
    pub ref_count: i64,
    pub sample_path: String,
    pub resolve_state: String,
    pub fact_id: FactId,
}

impl ImplicitDep {
    /// True when the provider is installed (directly, via alias, or namespace owner).
    pub fn provider_present(&self) -> bool {
        matches!(self.resolve_state.as_str(), "present" | "present-via-alias")
    }
}

/// The joined three-level dependency model for one collected pack.
#[derive(Debug, Default)]
pub struct EffectiveModel {
    /// Everything an id reference can resolve against: mod / plugin ids, declared
    /// `provides` aliases, and resource-namespace owners.
    pub providers: BTreeSet<String>,
    /// Real installed mod / plugin ids (the things that can actually be removed).
    pub mod_ids: BTreeSet<String>,
    pub declared: Vec<DeclaredDep>,
    pub implicit: Vec<ImplicitDep>,
}

impl EffectiveModel {
    /// Build the model from a collected [`FactStore`].
    pub fn from_store(store: &FactStore) -> Self {
        let mut model = EffectiveModel::default();

        for f in store.by_kind(kind::MOD).chain(store.by_kind(kind::PLUGIN)) {
            model.providers.insert(f.subject.clone());
            model.mod_ids.insert(f.subject.clone());
        }
        for f in store.by_kind(kind::PROVIDED_DEPENDENCY) {
            if let Some(p) = f.attr("provides") {
                model.providers.insert(p.to_string());
            }
        }
        for f in store.by_kind(kind::NAMESPACE_OWNER) {
            model.providers.insert(f.subject.clone());
        }

        for dep in store.by_kind(kind::DEPENDENCY) {
            let to = dep.attr("dep").unwrap_or("").to_string();
            if to.is_empty() {
                continue;
            }
            model.declared.push(DeclaredDep {
                from: dep.subject.clone(),
                to,
                range: dep.attr("range").unwrap_or("*").to_string(),
                relation: dep.attr("relation").unwrap_or("depends").to_string(),
                mandatory: dep.attr_bool("mandatory").unwrap_or(true),
                fact_id: dep.id,
            });
        }

        for e in store.by_kind(kind::IMPLICIT_DEPENDENCY_EDGE) {
            model.implicit.push(ImplicitDep {
                from: e.subject.clone(),
                provider_ns: e.attr("provider_namespace").unwrap_or("").to_string(),
                provider_mod: e.attr("provider_mod").unwrap_or("").to_string(),
                via: e.attr("via").unwrap_or("reference").to_string(),
                required: e.attr_bool("required").unwrap_or(false),
                conditioned: e.attr_bool("conditioned").unwrap_or(false),
                hard: e.attr_bool("hard").unwrap_or(false),
                ref_count: e.attr_int("ref_count").unwrap_or(1),
                sample_path: e.attr("from_path").unwrap_or("").to_string(),
                resolve_state: e.attr("resolve_state").unwrap_or("").to_string(),
                fact_id: e.id,
            });
        }

        model
    }

    /// The set of ids `from` declares any awareness of (depends / recommends /
    /// suggests / optional / includes / breaks) — used to decide "undisclosed".
    pub fn declared_targets(&self, from: &str) -> BTreeSet<String> {
        self.declared
            .iter()
            .filter(|d| d.from == from)
            .map(|d| d.to.clone())
            .collect()
    }

    /// Whether `from`'s manifest covers a dependency on `provider_mod` / `ns`,
    /// allowing for well-known namespace aliases (ae2 ↔ appliedenergistics2).
    fn declares(&self, from: &str, provider_mod: &str, ns: &str) -> bool {
        let targets = self.declared_targets(from);
        if targets.is_empty() {
            return false;
        }
        targets.contains(provider_mod)
            || targets.contains(ns)
            || intermed_resource_identity::is_satisfied_by(provider_mod, &targets)
            || intermed_resource_identity::is_satisfied_by(ns, &targets)
    }
}

/// The shape of a declared version range, classified from the range string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeShape {
    /// `*` / empty — no constraint at all (never flagged: the author expressed nothing).
    Unconstrained,
    /// A real lower bound but no upper bound (`>=x`, `[x,)`) — a breaking major can slip in.
    UnboundedAbove,
    /// Exactly one version (`=x`, `[x]`, `[x,x]`, bare `x`) — fragile to any other build.
    ExactPin,
    /// Bounded on both sides, or unparseable — left alone.
    Other,
}

fn classify_range(range: &str) -> RangeShape {
    let r = range.trim();
    if r.is_empty() || r == "*" || r == "any" {
        return RangeShape::Unconstrained;
    }
    // Maven-style intervals: `[1.0]`/`[1.0,1.0]` exact, `[1.0,)`/`(1.0,)` open above.
    if r.starts_with('[') || r.starts_with('(') {
        let inner = r.trim_matches(|c| c == '[' || c == ']' || c == '(' || c == ')');
        return match inner.split_once(',') {
            None => RangeShape::ExactPin,
            Some((lo, hi)) => {
                let lo = lo.trim();
                let hi = hi.trim();
                if !lo.is_empty() && lo == hi {
                    RangeShape::ExactPin
                } else if hi.is_empty() && !lo.is_empty() {
                    RangeShape::UnboundedAbove
                } else {
                    RangeShape::Other
                }
            }
        };
    }
    let has_upper = r.contains('<');
    let has_lower = r.contains(">=") || r.contains('>') || r.contains('^') || r.contains('~');
    let has_op = has_upper || has_lower || r.contains('=');
    if !has_op {
        // A bare version string (`1.2.3`) means an exact match in mod metadata.
        return RangeShape::ExactPin;
    }
    if r.starts_with('=') && !has_upper && !r.contains(">=") {
        return RangeShape::ExactPin;
    }
    if has_lower && !has_upper {
        return RangeShape::UnboundedAbove;
    }
    RangeShape::Other
}

/// True for relations the manifest uses to *require* (or strongly want) another mod.
fn is_requiring_relation(relation: &str) -> bool {
    matches!(
        relation,
        "depends" | "requires" | "required" | "embedded" | "include" | "included"
    )
}

/// Findings derived from the joined three-level model.
pub fn effective_findings(ctx: &RuleCtx<'_>, rule_id: &str) -> Vec<Finding> {
    let model = EffectiveModel::from_store(ctx.store);
    if model.implicit.is_empty() && model.declared.is_empty() {
        return Vec::new();
    }

    // Installed versions per id, for the range-shape findings.
    let mut installed_versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in ctx
        .store
        .by_kind(kind::MOD)
        .chain(ctx.store.by_kind(kind::PLUGIN))
    {
        installed_versions
            .entry(f.subject.clone())
            .or_default()
            .push(f.attr("version").unwrap_or("0").to_string());
    }

    let mut out = Vec::new();
    out.extend(undisclosed_and_conditional(&model, rule_id));
    out.extend(range_shape_findings(&model, &installed_versions, rule_id));
    out.extend(declared_but_unused(ctx.store, &model, rule_id));
    out
}

/// `implicit-dependency-undisclosed` + `dependency-conditionally-required`.
fn undisclosed_and_conditional(model: &EffectiveModel, rule_id: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for imp in &model.implicit {
        // Only meaningful when the provider is genuinely a separate installed mod
        // (something that could be removed or reordered). A missing provider is the
        // `implicit-dependency-missing` rule's job, not this one.
        if !imp.provider_present() {
            continue;
        }
        let provider = if imp.provider_mod.is_empty() {
            imp.provider_ns.as_str()
        } else {
            imp.provider_mod.as_str()
        };
        if provider == imp.from || is_platform_dep(provider) {
            continue;
        }
        if model.declares(&imp.from, provider, &imp.provider_ns) {
            continue; // declared — nothing undisclosed.
        }

        if imp.required {
            // The flagship finding: a real, unconditioned cross-mod requirement the
            // manifest never declares. Removing the provider or changing load order
            // can silently break the consumer's content.
            let severity = if imp.hard {
                Severity::Warn
            } else {
                Severity::Note
            };
            out.push(
                Finding::builder(
                    rule_id,
                    format!("implicit-dependency-undisclosed:{}->{}", imp.from, provider),
                )
                .severity(severity)
                .confidence(if imp.hard { 0.8 } else { 0.55 })
                .category(Category::Dependency)
                .title(format!(
                    "{} has an undisclosed dependency on {}",
                    imp.from, provider
                ))
                .explanation(format!(
                    "{from}'s resources reference {provider} as a {via} (e.g. {path}), but \
                     {from} does not declare a dependency on it. {provider} is installed now, so \
                     the pack works — but if {provider} is removed, disabled, or the load order \
                     changes, {from}'s affected content can silently fail to load. This is \
                     inferred from resources, not the manifest.",
                    from = imp.from,
                    via = imp.via,
                    path = imp.sample_path,
                ))
                .evidence(EvidenceEdge::supports(imp.fact_id))
                .affects(imp.from.clone())
                .affects(provider.to_string())
                .fix(FixCandidate::advice(format!(
                    "Declare {provider} as a dependency of {from} (e.g. add it to \
                     `depends`/`recommends` in the mod manifest) so the requirement is explicit.",
                    from = imp.from,
                )))
                .tag("dependency")
                .tag("implicit")
                .tag("undisclosed")
                .build(),
            );
        } else if imp.conditioned {
            // Referenced only behind a load condition: a genuine soft dependency the
            // manifest could document. Note, never an error.
            out.push(
                Finding::builder(
                    rule_id,
                    format!(
                        "dependency-conditionally-required:{}->{}",
                        imp.from, provider
                    ),
                )
                .severity(Severity::Note)
                .confidence(0.5)
                .category(Category::Dependency)
                .title(format!(
                    "{} conditionally depends on {}",
                    imp.from, provider
                ))
                .explanation(format!(
                    "{from} references {provider} only behind a load condition (e.g. a \
                     `modloaded:` gate) via {via} ({path}). It is effectively an optional \
                     dependency — declaring it as `recommends`/`suggests` documents the intent \
                     and helps pack tooling order the mods.",
                    from = imp.from,
                    via = imp.via,
                    path = imp.sample_path,
                ))
                .evidence(EvidenceEdge::supports(imp.fact_id))
                .affects(imp.from.clone())
                .affects(provider.to_string())
                .tag("dependency")
                .tag("implicit")
                .tag("conditional")
                .build(),
            );
        }
    }
    out
}

/// `dependency-version-range-too-wide` + `dependency-version-range-too-narrow`.
fn range_shape_findings(
    model: &EffectiveModel,
    installed_versions: &BTreeMap<String, Vec<String>>,
    rule_id: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for dep in &model.declared {
        if is_platform_dep(&dep.to) || !is_requiring_relation(&dep.relation) {
            continue;
        }
        // Only reason about a provider that is actually installed: an absent one is
        // already covered by missing/version findings, and the shape is moot.
        let Some(versions) = installed_versions.get(&dep.to) else {
            continue;
        };
        match classify_range(&dep.range) {
            RangeShape::UnboundedAbove if dep.mandatory => out.push(
                Finding::builder(
                    rule_id,
                    format!("dependency-version-range-too-wide:{}->{}", dep.from, dep.to),
                )
                .severity(Severity::Note)
                .confidence(0.5)
                .category(Category::Dependency)
                .title(format!("{} accepts any future {}", dep.from, dep.to))
                .explanation(format!(
                    "{from} requires {to} {range}, which has a lower bound but no upper bound. A \
                     breaking major release of {to} would be accepted silently and could break \
                     {from} at runtime. Consider an upper bound (e.g. `<next-major`).",
                    from = dep.from,
                    to = dep.to,
                    range = dep.range,
                ))
                .evidence(EvidenceEdge::subject(dep.fact_id))
                .affects(dep.from.clone())
                .affects(dep.to.clone())
                .tag("dependency")
                .tag("range-too-wide")
                .build(),
            ),
            RangeShape::ExactPin => {
                let installed_desc = versions.join(", ");
                out.push(
                    Finding::builder(
                        rule_id,
                        format!(
                            "dependency-version-range-too-narrow:{}->{}",
                            dep.from, dep.to
                        ),
                    )
                    .severity(Severity::Note)
                    .confidence(0.45)
                    .category(Category::Dependency)
                    .title(format!("{} pins {} to one version", dep.from, dep.to))
                    .explanation(format!(
                        "{from} pins {to} to exactly {range} (installed: {installed_desc}). Any \
                         other build of {to} — even a bug-fix patch — will be reported \
                         incompatible. Widen the range unless the pin is deliberate.",
                        from = dep.from,
                        to = dep.to,
                        range = dep.range,
                    ))
                    .evidence(EvidenceEdge::subject(dep.fact_id))
                    .affects(dep.from.clone())
                    .affects(dep.to.clone())
                    .tag("dependency")
                    .tag("range-too-narrow")
                    .build(),
                );
            }
            _ => {}
        }
    }
    out
}

/// `dependency-declared-but-unused` — deliberately explain-only and low-confidence.
///
/// Without bytecode cross-references we cannot prove a code-only dependency is
/// unused, so this never raises a visible warning. It only flags the *narrow,
/// suggestive* case: a content mod (it ships resources) declares a mandatory
/// dependency on an installed mod that itself owns resource namespaces, yet
/// references none of them — a hint the dependency may be stale or code-only.
fn declared_but_unused(store: &FactStore, model: &EffectiveModel, rule_id: &str) -> Vec<Finding> {
    // Mods that ship at least one resource definition (i.e. content/data mods).
    let mut ships_resources: BTreeSet<&str> = BTreeSet::new();
    for f in store.by_kind(kind::RESOURCE_DEFINITION) {
        if let Some(w) = f.attr("writer") {
            ships_resources.insert(w);
        }
    }
    // Namespace owners: an installed mod that owns resource namespaces is a data mod.
    let mut owns_namespaces: BTreeSet<&str> = BTreeSet::new();
    for f in store.by_kind(kind::NAMESPACE_OWNER) {
        if let Some(w) = f.attr("writer") {
            owns_namespaces.insert(w);
        }
    }

    let mut out = Vec::new();
    for dep in &model.declared {
        if !dep.mandatory || is_platform_dep(&dep.to) || !is_requiring_relation(&dep.relation) {
            continue;
        }
        if !ships_resources.contains(dep.from.as_str()) {
            continue; // not a content mod — nothing to infer from resources.
        }
        if !model.mod_ids.contains(&dep.to) || !owns_namespaces.contains(dep.to.as_str()) {
            continue; // the dependency isn't an installed data mod.
        }
        // Does the consumer implicitly reference the dependency at all?
        let references_it = model.implicit.iter().any(|imp| {
            imp.from == dep.from && (imp.provider_mod == dep.to || imp.provider_ns == dep.to)
        });
        if references_it {
            continue;
        }
        out.push(
            Finding::builder(
                rule_id,
                format!("dependency-declared-but-unused:{}->{}", dep.from, dep.to),
            )
            .severity(Severity::Note)
            .visibility(FindingVisibility::ExplainOnly)
            .confidence(0.25)
            .category(Category::Dependency)
            .title(format!(
                "{} may not use its dependency {}",
                dep.from, dep.to
            ))
            .explanation(format!(
                "{from} declares a mandatory dependency on {to}, and both ship resources, yet \
                 {from}'s resources reference none of {to}'s namespaces. The dependency may be \
                 code-only (which this layer cannot see) or stale. This is a low-confidence hint, \
                 not a defect.",
                from = dep.from,
                to = dep.to,
            ))
            .evidence(EvidenceEdge::subject(dep.fact_id))
            .affects(dep.from.clone())
            .affects(dep.to.clone())
            .tag("dependency")
            .tag("declared-but-unused")
            .build(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::{Target, TargetKind};

    fn target() -> Target {
        Target {
            path: "/tmp".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        }
    }

    fn run(store: &FactStore) -> Vec<Finding> {
        let t = target();
        let ctx = RuleCtx::for_test(store, &t);
        effective_findings(&ctx, "dependency")
    }

    fn mod_fact(store: &mut FactStore, id: &str, version: &str) {
        store
            .fact("meta", kind::MOD)
            .subject(id)
            .attr("version", version)
            .emit();
    }

    fn implicit_edge(
        store: &mut FactStore,
        from: &str,
        ns: &str,
        present: bool,
        required: bool,
        hard: bool,
    ) {
        store
            .fact("resource-ast-scanner", kind::IMPLICIT_DEPENDENCY_EDGE)
            .subject(from)
            .attr("provider_namespace", ns)
            .attr("provider_mod", ns)
            .attr("via", "recipe-serializer")
            .attr("required", required)
            .attr("conditioned", !required)
            .attr("hard", hard)
            .attr("ref_count", 3_i64)
            .attr("from_path", format!("data/{from}/recipe/x.json"))
            .attr(
                "resolve_state",
                if present {
                    "present"
                } else {
                    "required-missing"
                },
            )
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

    #[test]
    fn undisclosed_present_undeclared_serializer_is_warned() {
        let mut store = FactStore::new();
        mod_fact(&mut store, "addon", "1.0.0");
        mod_fact(&mut store, "thermal", "10.0.0");
        implicit_edge(&mut store, "addon", "thermal", true, true, true);
        let f = run(&store);
        let undisclosed: Vec<_> = f
            .iter()
            .filter(|x| x.id.starts_with("implicit-dependency-undisclosed:"))
            .collect();
        assert_eq!(undisclosed.len(), 1);
        assert_eq!(undisclosed[0].severity, Severity::Warn);
        assert_eq!(
            undisclosed[0].id,
            "implicit-dependency-undisclosed:addon->thermal"
        );
    }

    #[test]
    fn undisclosed_suppressed_when_declared() {
        let mut store = FactStore::new();
        mod_fact(&mut store, "addon", "1.0.0");
        mod_fact(&mut store, "thermal", "10.0.0");
        implicit_edge(&mut store, "addon", "thermal", true, true, true);
        declared(&mut store, "addon", "thermal", ">=10.0.0");
        let f = run(&store);
        assert!(
            f.iter()
                .all(|x| !x.id.starts_with("implicit-dependency-undisclosed:"))
        );
    }

    #[test]
    fn undisclosed_not_raised_for_missing_provider() {
        // A missing provider is the implicit-dependency-missing rule's job.
        let mut store = FactStore::new();
        mod_fact(&mut store, "addon", "1.0.0");
        implicit_edge(&mut store, "addon", "thermal", false, true, true);
        let f = run(&store);
        assert!(f.is_empty());
    }

    #[test]
    fn conditional_reference_is_a_note() {
        let mut store = FactStore::new();
        mod_fact(&mut store, "addon", "1.0.0");
        mod_fact(&mut store, "create", "0.5.1");
        implicit_edge(&mut store, "addon", "create", true, false, false);
        let f = run(&store);
        let cond: Vec<_> = f
            .iter()
            .filter(|x| x.id.starts_with("dependency-conditionally-required:"))
            .collect();
        assert_eq!(cond.len(), 1);
        assert_eq!(cond[0].severity, Severity::Note);
    }

    #[test]
    fn unbounded_range_is_flagged_too_wide() {
        let mut store = FactStore::new();
        mod_fact(&mut store, "addon", "1.0.0");
        mod_fact(&mut store, "create", "0.5.1");
        declared(&mut store, "addon", "create", ">=0.5.0");
        let f = run(&store);
        assert!(
            f.iter()
                .any(|x| x.id == "dependency-version-range-too-wide:addon->create")
        );
    }

    #[test]
    fn exact_pin_is_flagged_too_narrow() {
        let mut store = FactStore::new();
        mod_fact(&mut store, "addon", "1.0.0");
        mod_fact(&mut store, "create", "0.5.1");
        declared(&mut store, "addon", "create", "0.5.1");
        let f = run(&store);
        assert!(
            f.iter()
                .any(|x| x.id == "dependency-version-range-too-narrow:addon->create")
        );
    }

    #[test]
    fn bare_wildcard_is_not_flagged_wide() {
        let mut store = FactStore::new();
        mod_fact(&mut store, "addon", "1.0.0");
        mod_fact(&mut store, "create", "0.5.1");
        declared(&mut store, "addon", "create", "*");
        let f = run(&store);
        assert!(
            f.iter()
                .all(|x| !x.id.starts_with("dependency-version-range"))
        );
    }

    #[test]
    fn range_shape_classification() {
        assert_eq!(classify_range("*"), RangeShape::Unconstrained);
        assert_eq!(classify_range(">=1.0"), RangeShape::UnboundedAbove);
        assert_eq!(classify_range("[1.0,)"), RangeShape::UnboundedAbove);
        assert_eq!(classify_range("1.2.3"), RangeShape::ExactPin);
        assert_eq!(classify_range("=1.2.3"), RangeShape::ExactPin);
        assert_eq!(classify_range("[1.0]"), RangeShape::ExactPin);
        assert_eq!(classify_range(">=1.0 <2.0"), RangeShape::Other);
    }
}
