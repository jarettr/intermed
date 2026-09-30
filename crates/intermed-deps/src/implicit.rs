//! Cross-layer resolution of Layer-M implicit-dependency candidates.
//!
//! Layer M observes that a resource references a namespace no installed jar owns
//! (e.g. a recipe whose serializer `type` is `thermal:*`). It does **not** decide
//! whether that is a problem — it cannot see the installed mod set. Layer C does:
//! it cross-references each candidate namespace against the installed mods and the
//! declared `provides` aliases, and concludes.
//!
//! Anti-false-positive is the governing constraint. A namespace is *not* a mod id
//! in general, and Minecraft silently skips a recipe with a missing *ingredient*
//! (intended cross-mod compatibility), so flagging those would be noise. We only
//! conclude "missing" for the one signal that genuinely hard-fails at load and is
//! unconditioned: a recipe **serializer type** whose mod is absent. Everything
//! else is left to the verbose facts for explain, not raised as a finding.

use crate::model::ResolvedDependencyModel;
use intermed_doctor_core::RuleCtx;
use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::kind;

/// Resolve implicit-dependency candidates into findings.
pub fn implicit_findings(ctx: &RuleCtx<'_>, rule_id: &str) -> Vec<Finding> {
    let candidates: Vec<_> = ctx
        .store
        .by_kind(kind::IMPLICIT_DEPENDENCY_CANDIDATE)
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }

    let dependency_model = ResolvedDependencyModel::from_store(ctx.store);
    let installed = dependency_model.confirmed_provider_ids();

    // Keep only candidates that are genuinely actionable, low-FP signals:
    // an unconditioned recipe serializer type whose namespace is neither installed,
    // nor an alias provider, nor a platform namespace.
    // (namespace, sample path, total ref count) for the report's "referenced by" line.
    let mut missing: Vec<(&str, &str, i64)> = Vec::new();
    // Candidates are already non-platform namespaces (Layer M excludes
    // minecraft/forge/fabric/… when emitting them), so we only check installation —
    // allowing for well-known namespace aliases (ae2 ↔ appliedenergistics2) so an
    // installed mod under a different id is not flagged missing.
    for c in &candidates {
        let ns = c.subject.as_str();
        if ns.is_empty() {
            continue;
        }
        // Absence conclusions must never be based solely on a registry heuristic
        // or an arbitrary `id` field from an opaque custom serializer.
        if c.attr("reference_certainty")
            .is_some_and(|certainty| certainty != "exact-schema-reference")
        {
            continue;
        }
        if dependency_model.has_unresolved_provider(ns) {
            continue;
        }
        // Trust the Layer-M resolve model (§18) when present: only a
        // `required-missing` resolve state is actionable (it already folds in
        // alias / platform / conditional awareness). Fall back to a local
        // alias-aware check for candidates from an older Layer-M version.
        let resolved_required_missing = match c.attr("resolve_state") {
            Some(state) => state == "required-missing",
            None => {
                !intermed_resource_identity::is_satisfied_by(ns, &installed)
                    && c.attr_bool("required").unwrap_or(false)
            }
        };
        // Scope to recipe serializers — the lowest-false-positive signal (a missing
        // serializer hard-fails the recipe load).
        if !resolved_required_missing || !c.attr_bool("via_recipe_type").unwrap_or(false) {
            continue;
        }
        let ref_count = c.attr_int("ref_count").unwrap_or(1);
        missing.push((ns, c.attr("from_path").unwrap_or(""), ref_count));
    }
    if missing.is_empty() {
        return Vec::new();
    }
    missing.sort_unstable();
    missing.dedup();

    let names: Vec<&str> = missing.iter().map(|(ns, _, _)| *ns).collect();
    // Per-namespace provenance (roadmap §9.3): "<ns> referenced by <path> as recipe
    // serializer (+N more)" — so the finding points at concrete files, not just names.
    let referenced_by: String = missing
        .iter()
        .map(|(ns, path, count)| {
            let more = if *count > 1 {
                format!(" (+{} more)", count - 1)
            } else {
                String::new()
            };
            format!("{ns} referenced by {path} as recipe serializer{more}")
        })
        .collect::<Vec<_>>()
        .join("; ");
    // Note, not Warn: a recipe referencing an uninstalled mod is most often an
    // *optional* compat add-on the author shipped unconditionally. It produces log
    // errors and dead recipes, worth surfacing — but it is rarely pack-breaking,
    // so it must not be raised at a severity that competes with real unsat deps.
    let mut builder = Finding::builder(rule_id, "implicit-dependency-missing")
        .severity(Severity::Note)
        .category(Category::Dependency)
        .title(format!(
            "{} recipe serializer(s) reference a mod that is not installed",
            names.len()
        ))
        .explanation(format!(
            "These namespaces are used as recipe serializer `type`s but no installed mod \
             provides them. {referenced_by}. A recipe whose serializer mod is absent fails to \
             load (the game logs a data error), so the affected recipes silently do nothing. This \
             is inferred from resources, not a declared dependency — if a namespace here is \
             actually shipped by an installed mod under a different id, it is safe to ignore."
        ))
        .fix(FixCandidate::advice(
            "Install the mod that owns each namespace, or remove the data pack / add-on that \
             ships these recipes.",
        ))
        .tag("dependency")
        .tag("implicit")
        .tag("resource");
    for ns in &names {
        builder = builder.affects((*ns).to_string());
    }
    for c in &candidates {
        if names.contains(&c.subject.as_str()) {
            builder = builder.evidence(EvidenceEdge::supports(c.id));
        }
    }
    vec![builder.confidence(0.7).build()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::FactStore;
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

    fn candidate(store: &mut FactStore, ns: &str, required: bool, via_recipe_type: bool) {
        store
            .fact("resource-ast-scanner", kind::IMPLICIT_DEPENDENCY_CANDIDATE)
            .subject(ns)
            .attr("from_path", format!("data/x/recipe/{ns}.json"))
            .attr("required", required)
            .attr("via_recipe_type", via_recipe_type)
            .attr("reference_certainty", "exact-schema-reference")
            .emit();
    }

    fn run(store: &FactStore) -> Vec<Finding> {
        let t = target();
        let ctx = RuleCtx::for_test(store, &t);
        implicit_findings(&ctx, "dependency")
    }

    #[test]
    fn missing_recipe_serializer_is_flagged() {
        let mut store = FactStore::new();
        candidate(&mut store, "thermal", true, true);
        let findings = run(&store);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Note);
        assert!(
            findings[0]
                .affected_components
                .iter()
                .any(|c| c == "thermal")
        );
    }

    #[test]
    fn installed_mod_namespace_is_not_flagged() {
        let mut store = FactStore::new();
        store
            .fact("metadata-scanner", kind::MOD)
            .subject("thermal")
            .emit();
        candidate(&mut store, "thermal", true, true);
        assert!(run(&store).is_empty());
    }

    #[test]
    fn namespace_owner_satisfies_candidate() {
        // Mod id differs from namespace, but Layer M saw resources under `thermal`.
        let mut store = FactStore::new();
        store
            .fact("resource-ast-scanner", kind::NAMESPACE_OWNER)
            .subject("thermal")
            .attr("writer", "thermal_foundation")
            .emit();
        candidate(&mut store, "thermal", true, true);
        assert!(run(&store).is_empty());
    }

    #[test]
    fn non_recipe_type_reference_is_not_flagged() {
        // A missing *ingredient* item namespace is intended cross-mod compat noise.
        let mut store = FactStore::new();
        candidate(&mut store, "thermal", true, false);
        assert!(run(&store).is_empty());
    }

    #[test]
    fn conditioned_only_reference_is_not_flagged() {
        let mut store = FactStore::new();
        candidate(&mut store, "thermal", false, true);
        assert!(run(&store).is_empty());
    }

    #[test]
    fn heuristic_reference_cannot_produce_missing_dependency() {
        let mut store = FactStore::new();
        store
            .fact("resource-ast-scanner", kind::IMPLICIT_DEPENDENCY_CANDIDATE)
            .subject("thermal")
            .attr("from_path", "data/x/worldgen/example.json")
            .attr("required", true)
            .attr("via_recipe_type", true)
            .attr("reference_certainty", "heuristic-registry-reference")
            .emit();
        assert!(run(&store).is_empty());
    }
}
