//! Mixin Complexity Score — a transparent, deterministic rollup of measured
//! mixin structure into one 0–100 number per class and per mod.
//!
//! This is **not** a heuristic risk guess: every point is the capped sum of named
//! [`ComplexityComponent`]s, each carrying the raw quantity it was derived from,
//! so a score is always fully explainable ("38 = 24 injection + 8 targets + 6
//! hot-path"). It measures how much a mixin bends its targets — injection surface,
//! operation severity, peak handler-body complexity, target footprint, and member
//! surface — which is what correlates with fragility under refactors and
//! load-order changes. The conflict-edge term on the mod score folds in the
//! cross-mod interactions the analyzer already proves.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    ComplexityComponent, MixinClassComplexity, MixinClassRecord, MixinConflictEdgeRecord,
    MixinModComplexity,
};

/// Per-operation weight for the injection-surface term. Overwrites replace whole
/// methods, redirects rewrite call sites, modifies rewrite values/locals, plain
/// injects only observe — the weights order them by how invasive the weave is.
fn operation_weight(op: &str) -> u32 {
    match op {
        "overwrite" => 12,
        "redirect" | "wrap-operation" => 7,
        "modify-arg" | "modify-variable" | "modify-constant" | "modify-expression-value" => 5,
        "inject" => 3,
        // shadow / accessor / invoker / unknown: structural, low behavioural weight.
        _ => 1,
    }
}

/// Cap a contribution and build its component if non-zero.
fn component(label: &str, raw_points: u32, cap: u32, measure: u32) -> Option<ComplexityComponent> {
    let points = raw_points.min(cap);
    (points > 0).then(|| ComplexityComponent {
        label: label.to_string(),
        points,
        measure,
    })
}

/// Score a single mixin class from its already-collected structure.
fn score_class(class: &MixinClassRecord) -> MixinClassComplexity {
    let mut components = Vec::new();

    // (a) Injection surface, weighted by operation severity. Falls back to the
    //     declared operations when injection points did not resolve (e.g. a pure
    //     accessor/shadow class, or a refmap that failed to bind).
    let (op_weight, surface_measure) = if !class.injected_methods.is_empty() {
        let w = class
            .injected_methods
            .iter()
            .map(|inj| operation_weight(&inj.injection_type))
            .sum();
        (w, class.injected_methods.len() as u32)
    } else {
        let w = class
            .operations
            .iter()
            .map(|op| operation_weight(op.as_str()))
            .sum();
        (w, class.operations.len() as u32)
    };
    components.extend(component("injection surface", op_weight, 40, surface_measure));

    // (b) Peak per-handler bytecode complexity (already 0–100 from dataflow).
    let peak_handler = class
        .effects
        .iter()
        .filter_map(|e| e.handler_effect.as_ref())
        .map(|h| h.complexity_score)
        .max()
        .unwrap_or(0);
    components.extend(component(
        "peak handler complexity",
        u32::from(peak_handler) / 4,
        25,
        u32::from(peak_handler),
    ));

    // (c) Target footprint — weaving N targets from one mixin multiplies blast radius.
    let target_count = class.targets.len() as u32;
    components.extend(component(
        "multi-target weaving",
        target_count.saturating_sub(1) * 6,
        18,
        target_count,
    ));

    // (d) Member surface the mixin couples to the target (shadows + adds + calls).
    let member_surface =
        (class.shadows.len() + class.added_members.len() + class.calls.len()) as u32;
    components.extend(component(
        "target member coupling",
        member_surface,
        12,
        member_surface,
    ));

    // (e) Reflection in any handler body — opaque, hard to reason about.
    if class.handler_bodies.iter().any(|h| h.uses_reflection) {
        components.extend(component("reflective handler", 6, 6, 1));
    }

    // (f) Hot-path target — complexity on a hot method costs more in practice.
    if !class.hot_paths.is_empty() {
        components.extend(component("hot-path target", 6, 6, class.hot_paths.len() as u32));
    }

    let score = components.iter().map(|c| c.points).sum::<u32>().min(100) as u8;

    MixinClassComplexity {
        mod_id: class.mod_id.clone(),
        mixin_class: class.class_name.clone(),
        score,
        injection_sites: class.injected_methods.len() as u32,
        target_count,
        peak_handler_complexity: peak_handler,
        components,
    }
}

/// Compute per-class and per-mod complexity scores for a whole scan.
///
/// `conflict_edges` feeds only the mod-level cross-mod participation term; class
/// scores are intrinsic to each class.
pub fn compute_complexity(
    classes: &[MixinClassRecord],
    conflict_edges: &[MixinConflictEdgeRecord],
) -> (Vec<MixinClassComplexity>, Vec<MixinModComplexity>) {
    let class_complexity: Vec<MixinClassComplexity> = classes.iter().map(score_class).collect();

    // Cross-mod conflict-edge participation per mod (each edge counts for both ends).
    let mut edges_per_mod: BTreeMap<&str, u32> = BTreeMap::new();
    for edge in conflict_edges {
        *edges_per_mod.entry(edge.source_mod.as_str()).or_default() += 1;
        if edge.target_mod != edge.source_mod {
            *edges_per_mod.entry(edge.target_mod.as_str()).or_default() += 1;
        }
    }

    // Group class indices by mod for the aggregate pass.
    let mut by_mod: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, class) in classes.iter().enumerate() {
        by_mod.entry(class.mod_id.as_str()).or_default().push(i);
    }

    let mut mod_complexity = Vec::new();
    for (mod_id, idxs) in by_mod {
        let mut targets: BTreeSet<&str> = BTreeSet::new();
        let mut total_sites = 0u32;
        let mut peak_class_score = 0u8;
        let mut any_hot = false;
        for &i in &idxs {
            let class = &classes[i];
            for t in &class.targets {
                targets.insert(t.as_str());
            }
            total_sites += class.injected_methods.len() as u32;
            peak_class_score = peak_class_score.max(class_complexity[i].score);
            any_hot |= !class.hot_paths.is_empty();
        }
        let class_count = idxs.len() as u32;
        let target_count = targets.len() as u32;
        let conflict_edges = edges_per_mod.get(mod_id).copied().unwrap_or(0);

        let mut components = Vec::new();
        // The most complex single class dominates the mod's risk surface.
        components.extend(component(
            "peak class complexity",
            u32::from(peak_class_score) / 2,
            40,
            u32::from(peak_class_score),
        ));
        components.extend(component("mixin class count", class_count * 2, 16, class_count));
        components.extend(component("distinct targets", target_count, 20, target_count));
        components.extend(component("injection volume", total_sites / 2, 14, total_sites));
        components.extend(component(
            "cross-mod conflicts",
            conflict_edges * 4,
            20,
            conflict_edges,
        ));
        if any_hot {
            components.extend(component("hot-path footprint", 6, 6, 1));
        }

        let score = components.iter().map(|c| c.points).sum::<u32>().min(100) as u8;
        mod_complexity.push(MixinModComplexity {
            mod_id: mod_id.to_string(),
            score,
            class_count,
            target_count,
            total_injection_sites: total_sites,
            conflict_edges,
            peak_class_score,
            components,
        });
    }

    (class_complexity, mod_complexity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MixinConflictEdgeRecord, ConflictEdgeType, ResolvedInjectionPoint};

    fn class(mod_id: &str, name: &str, targets: &[&str], ops: &[&str]) -> MixinClassRecord {
        MixinClassRecord {
            archive: format!("{mod_id}.jar"),
            mod_id: mod_id.into(),
            config: "mixins.json".into(),
            class_name: name.into(),
            class_path: format!("{name}.class"),
            targets: targets.iter().map(|t| t.to_string()).collect(),
            target_namespace: Default::default(),
            operations: Vec::new(),
            injected_methods: ops
                .iter()
                .enumerate()
                .map(|(i, op)| ResolvedInjectionPoint {
                    target: targets.first().copied().unwrap_or("T").into(),
                    original: format!("m{i}()V"),
                    resolved: format!("m{i}()V"),
                    canonical: format!("m{i}()V"),
                    site_key: format!("m{i}()V@HEAD"),
                    namespace: crate::refmap::Namespace::Named,
                    injection_type: (*op).to_string(),
                    resolved_via_refmap: false,
                    handler_method: "h".into(),
                    handler_descriptor: String::new(),
                    mutates_target_local: false,
                    at_target: "HEAD".into(),
                    at_detail: "HEAD".into(),
                    impact: "entry-hook".into(),
                    local_index: None,
                    local_capture: String::new(),
                    meta: Default::default(),
                    at_ordinal: None,
                    at_target_member: String::new(),
                })
                .collect(),
            shadows: Vec::new(),
            added_members: Vec::new(),
            calls: Vec::new(),
            handler_bodies: Vec::new(),
            target_hierarchy: Vec::new(),
            priority: 1000,
            refmap: None,
            hot_paths: Vec::new(),
            effects: Vec::new(),
            plugin_gated: false,
        }
    }

    #[test]
    fn score_is_the_capped_sum_of_its_components() {
        let c = class("a", "a.Mix", &["T1", "T2"], &["overwrite", "inject"]);
        let cc = score_class(&c);
        let sum: u32 = cc.components.iter().map(|x| x.points).sum();
        assert_eq!(cc.score as u32, sum.min(100));
        // Every component must carry its raw measure (transparency invariant).
        assert!(cc.components.iter().all(|x| x.points > 0));
    }

    #[test]
    fn overwrite_multitarget_scores_higher_than_single_inject() {
        let heavy = score_class(&class("a", "a.Heavy", &["T1", "T2", "T3"], &["overwrite", "redirect"]));
        let light = score_class(&class("b", "b.Light", &["T1"], &["inject"]));
        assert!(heavy.score > light.score, "heavy {} vs light {}", heavy.score, light.score);
    }

    #[test]
    fn mod_score_rises_with_conflict_participation() {
        let classes = vec![class("a", "a.Mix", &["T1"], &["inject"])];
        let no_edges = compute_complexity(&classes, &[]).1;
        let edge = MixinConflictEdgeRecord {
            id: "edge-1".into(),
            edge_type: ConflictEdgeType::SameInjectionPoint,
            source_mod: "a".into(),
            target_mod: "b".into(),
            source_mixin: "a.Mix".into(),
            target_mixin: "b.Mix".into(),
            target_class: "T1".into(),
            site: "m0()V".into(),
            strength: 90,
        };
        let with_edges = compute_complexity(&classes, &[edge]).1;
        let a_before = no_edges.iter().find(|m| m.mod_id == "a").unwrap().score;
        let a_after = with_edges.iter().find(|m| m.mod_id == "a").unwrap().score;
        assert!(a_after > a_before, "{a_after} should exceed {a_before}");
        assert_eq!(with_edges.iter().find(|m| m.mod_id == "a").unwrap().conflict_edges, 1);
    }

    #[test]
    fn empty_scan_yields_no_scores() {
        let (cc, mc) = compute_complexity(&[], &[]);
        assert!(cc.is_empty() && mc.is_empty());
    }
}
