//! Post-collection mixin analysis engine.
//!
//! [`MixinInteractionEngine`] consumes all [`MixinClassModel`] records after jar
//! scanning and derives overlaps, interaction edges, priority conflicts, and
//! composite risk scores. Collectors emit raw facts; this engine emits derived
//! intelligence.

use std::collections::{BTreeMap, BTreeSet};

use crate::effect::{effect_for_overwrite, effect_summaries_for_target};
use crate::graph::MixinInteractionGraph;
use crate::handler_effect::handler_effect_for;
use crate::hierarchy::HierarchyIndex;
use crate::hot_path::HotPathRules;
use crate::model::{
    ConflictEdgeType, HighRiskOverwrite, InteractionType, MemberKind, MixinAnalysis,
    MixinClassModel, MixinClassRecord, MixinConflictEdgeRecord, MixinEffect,
    MixinInteractionRecord, MixinOperation, MixinOverlap, MixinPriorityConflictRecord,
    MixinRiskAssessment, MixinShadowMember, ResolvedInjectionPoint,
};
use crate::refmap::Namespace;
use crate::semantics::InjectionImpact;

/// A target-scoped, order-independent key for a pair of mods.
fn ordered_pair(target: &str, a: &str, b: &str) -> (String, String, String) {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    (target.to_string(), lo.to_string(), hi.to_string())
}

/// Analyzes mixin class models and builds interaction / risk artifacts.
#[derive(Debug, Clone, Default)]
pub struct MixinInteractionEngine {
    hot_paths: HotPathRules,
    hierarchy: HierarchyIndex,
}

impl MixinInteractionEngine {
    /// Create an engine with default hot-path rules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an engine with custom hot-path rules.
    pub fn with_hot_paths(hot_paths: HotPathRules) -> Self {
        Self {
            hot_paths,
            ..Self::default()
        }
    }

    /// Attach a class hierarchy index for inherited-target collision detection.
    pub fn with_hierarchy(mut self, hierarchy: HierarchyIndex) -> Self {
        self.hierarchy = hierarchy;
        self
    }

    /// Run full analysis over all mixin classes in a modpack scan.
    pub fn analyze(&self, classes: &[MixinClassRecord]) -> MixinAnalysis {
        let models: Vec<MixinClassModel> = classes.iter().cloned().map(Into::into).collect();
        let mixin_effects: Vec<MixinEffect> = classes
            .iter()
            .flat_map(|c| c.effects.iter().cloned())
            .collect();
        let overlaps = classify_overlaps(&self.hot_paths, classes, &mixin_effects);
        let high_risk_overwrites =
            classify_overwrites(&self.hot_paths, classes, &mixin_effects);
        let (interactions, conflict_edges, priority_conflicts) =
            detect_interactions(&models, &overlaps, &self.hierarchy);
        let risk_assessments = compute_risk_scores(
            classes,
            &overlaps,
            &conflict_edges,
            &priority_conflicts,
            &mixin_effects,
        );
        let (class_complexity, mod_complexity) =
            crate::complexity::compute_complexity(classes, &conflict_edges);
        let bloat = crate::bloat::compute_bloat(classes);
        let graph = MixinInteractionGraph::build(
            classes,
            &interactions,
            &conflict_edges,
            &priority_conflicts,
        );

        MixinAnalysis {
            overlaps,
            high_risk_overwrites,
            interactions,
            conflict_edges,
            priority_conflicts,
            risk_assessments,
            mixin_effects,
            recommendations: Vec::new(),
            class_complexity,
            mod_complexity,
            bloat,
            graph,
        }
    }
}

fn classify_overlaps(
    rules: &HotPathRules,
    classes: &[MixinClassRecord],
    effects: &[MixinEffect],
) -> Vec<MixinOverlap> {
    let mut by_target: BTreeMap<&str, Vec<&MixinClassRecord>> = BTreeMap::new();
    for class in classes {
        for target in &class.targets {
            by_target.entry(target.as_str()).or_default().push(class);
        }
    }

    let mut out = Vec::new();
    for (target, group) in by_target {
        let mods: BTreeSet<String> = group.iter().map(|c| c.mod_id.clone()).collect();
        if mods.len() < 2 {
            continue;
        }
        let classes_set: BTreeSet<String> = group.iter().map(|c| c.class_name.clone()).collect();
        let operations: BTreeSet<MixinOperation> =
            group.iter().flat_map(|c| c.operations.clone()).collect();
        let hot_path = overlap_is_hot(rules, target, &group);
        let (method_conflict, shared_methods) = method_level_conflict(&group, effects);
        let effect_summaries = effect_summaries_for_target(effects, target);
        out.push(MixinOverlap {
            target: target.to_string(),
            mods: mods.into_iter().collect(),
            classes: classes_set.into_iter().collect(),
            operations: operations.into_iter().collect(),
            hot_path,
            method_conflict,
            shared_methods,
            effect_summaries,
        });
    }
    out
}

fn overlap_is_hot(rules: &HotPathRules, target: &str, group: &[&MixinClassRecord]) -> bool {
    if rules.tag_for(target).is_some() {
        return true;
    }
    group.iter().any(|c| {
        !c.hot_paths.is_empty()
            || c.injected_methods.iter().any(|inj| {
                rules
                    .tag_for_injection(&inj.target, &inj.resolved)
                    .is_some()
            })
    })
}

fn classify_overwrites(
    rules: &HotPathRules,
    classes: &[MixinClassRecord],
    effects: &[MixinEffect],
) -> Vec<HighRiskOverwrite> {
    let mut out = Vec::new();
    for class in classes {
        if !class.operations.contains(&MixinOperation::Overwrite) {
            continue;
        }
        let methods: Vec<String> = class
            .injected_methods
            .iter()
            .filter(|i| i.injection_type == MixinOperation::Overwrite.as_str())
            .map(|i| i.resolved.clone())
            .collect();
        for target in &class.targets {
            let hot = rules.tag_for(target).is_some();
            if methods.is_empty() {
                let matched = effect_for_overwrite(
                    effects,
                    &class.mod_id,
                    &class.class_name,
                    target,
                    "",
                );
                out.push(HighRiskOverwrite {
                    mod_id: class.mod_id.clone(),
                    class_name: class.class_name.clone(),
                    target: target.clone(),
                    method: String::new(),
                    site_key: overwrite_site_key(class, target, "", matched),
                    hot_path: hot,
                    effect_description: matched
                        .map(|e| e.effect_description.clone())
                        .unwrap_or_else(|| overwrite_fallback_description(class, target, "")),
                    handler_effect: matched.and_then(|e| e.handler_effect.clone()),
                });
            } else {
                for method in &methods {
                    let matched = effect_for_overwrite(
                        effects,
                        &class.mod_id,
                        &class.class_name,
                        target,
                        method,
                    );
                    let handler_effect = matched
                        .and_then(|e| e.handler_effect.clone())
                        .or_else(|| {
                            class
                                .injected_methods
                                .iter()
                                .find(|i| i.resolved == *method)
                                .map(|i| i.handler_method.as_str())
                                .and_then(|h| handler_effect_for(&class.handler_bodies, h))
                        });
                    out.push(HighRiskOverwrite {
                        mod_id: class.mod_id.clone(),
                        class_name: class.class_name.clone(),
                        target: target.clone(),
                        method: method.clone(),
                        site_key: overwrite_site_key(class, target, method, matched),
                        hot_path: hot,
                        effect_description: matched
                            .map(|e| e.effect_description.clone())
                            .unwrap_or_else(|| {
                                overwrite_fallback_description(class, target, method)
                            }),
                        handler_effect,
                    });
                }
            }
        }
    }
    out
}

/// True when an effect's injection site matches an overlap compare key.
fn effect_matches_compare_key(effect: &MixinEffect, compare_key: &str) -> bool {
    if effect.site_key == compare_key {
        return true;
    }
    if !effect.site_key.is_empty() && !compare_key.contains('@') {
        return effect.site_key.starts_with(&format!("{compare_key}@")) || effect.method == compare_key;
    }
    effect.method == compare_key
}

fn injection_compare_key(inj: &ResolvedInjectionPoint) -> String {
    if !inj.site_key.is_empty() {
        inj.site_key.clone()
    } else if !inj.canonical.is_empty() {
        inj.canonical.clone()
    } else {
        inj.resolved.clone()
    }
}

fn detect_interactions(
    models: &[MixinClassModel],
    overlaps: &[MixinOverlap],
    hierarchy: &HierarchyIndex,
) -> (
    Vec<MixinInteractionRecord>,
    Vec<MixinConflictEdgeRecord>,
    Vec<MixinPriorityConflictRecord>,
) {
    let mut interactions = Vec::new();
    let mut conflict_edges = Vec::new();
    let mut priority_conflicts = Vec::new();
    let mut edge_id = 0u32;
    let mut interaction_id = 0u32;

    // Direct injection point conflicts. Keyed on the *canonical* (namespace-
    // normalized) method key, never the display name: two mods are matched only
    // when their injection points resolve to the same key in the same namespace,
    // so a named-vs-intermediary pair never silently slips past as "different".
    let mut by_site: BTreeMap<(String, String), Vec<&MixinClassRecord>> = BTreeMap::new();
    // Namespaces each mod uses on each target, for the mismatch pass below.
    let mut ns_by_target: BTreeMap<String, BTreeMap<String, BTreeSet<Namespace>>> = BTreeMap::new();
    for model in models {
        let class = &model.record;
        for inj in &class.injected_methods {
            by_site
                .entry((inj.target.clone(), injection_compare_key(inj)))
                .or_default()
                .push(class);
            ns_by_target
                .entry(inj.target.clone())
                .or_default()
                .entry(class.mod_id.clone())
                .or_default()
                .insert(inj.namespace);
        }
    }
    // Mod pairs already confirmed to share an injection point on a target — so
    // the mismatch pass does not double-report them.
    let mut confirmed: BTreeSet<(String, String, String)> = BTreeSet::new();
    for ((target, method), group) in &by_site {
        let mods: BTreeSet<&str> = group.iter().map(|c| c.mod_id.as_str()).collect();
        if mods.len() < 2 {
            continue;
        }
        let mod_list: Vec<&MixinClassRecord> = group.to_vec();
        for i in 0..mod_list.len() {
            for j in (i + 1)..mod_list.len() {
                let a = mod_list[i];
                let b = mod_list[j];
                let cross_mod = a.mod_id != b.mod_id;
                interaction_id += 1;
                interactions.push(MixinInteractionRecord {
                    id: format!("interaction-{interaction_id}"),
                    interaction_type: InteractionType::DirectInjection,
                    mod_a: a.mod_id.clone(),
                    mod_b: b.mod_id.clone(),
                    mixin_a: a.class_name.clone(),
                    mixin_b: b.class_name.clone(),
                    target: target.clone(),
                    detail: if cross_mod {
                        format!("Both inject into site `{method}` on `{target}`")
                    } else {
                        format!(
                            "`{}` injects into site `{method}` on `{target}` from two of its own mixins",
                            a.mod_id
                        )
                    },
                    // Same-mod overlap is internal complexity, not a mod conflict.
                    strength: if cross_mod { 90 } else { 40 },
                    cross_mod,
                });
                // Conflict *edges* model the cross-mod conflict graph only. Two
                // mixins of the same mod sharing a site is intra-mod complexity,
                // not an A↔B conflict, so it gets no edge and is not "confirmed"
                // for the namespace-mismatch pass.
                if cross_mod {
                    confirmed.insert(ordered_pair(target, &a.mod_id, &b.mod_id));
                    edge_id += 1;
                    conflict_edges.push(MixinConflictEdgeRecord {
                        id: format!("edge-{edge_id}"),
                        edge_type: ConflictEdgeType::SameInjectionPoint,
                        source_mod: a.mod_id.clone(),
                        target_mod: b.mod_id.clone(),
                        source_mixin: a.class_name.clone(),
                        target_mixin: b.class_name.clone(),
                        target_class: target.clone(),
                        site: method.clone(),
                        strength: 90,
                    });
                }
            }
        }
    }

    // Namespace-mismatch pass: two mods inject into the same target but in
    // different mapping namespaces with no bridge, so a same-point clash cannot
    // be confirmed *or* ruled out. Surface it (low strength) instead of letting
    // it slip through as a silent miss.
    for (target, by_mod) in &ns_by_target {
        let mods: Vec<(&String, &BTreeSet<Namespace>)> = by_mod.iter().collect();
        for i in 0..mods.len() {
            for j in (i + 1)..mods.len() {
                let (mod_a, ns_a) = mods[i];
                let (mod_b, ns_b) = mods[j];
                if confirmed.contains(&ordered_pair(target, mod_a, mod_b)) {
                    continue;
                }
                // Disjoint namespace sets ⇒ no common ground to compare on.
                if ns_a.is_disjoint(ns_b) {
                    edge_id += 1;
                    conflict_edges.push(MixinConflictEdgeRecord {
                        id: format!("edge-{edge_id}"),
                        edge_type: ConflictEdgeType::NamespaceMismatch,
                        source_mod: mod_a.clone(),
                        target_mod: mod_b.clone(),
                        source_mixin: String::new(),
                        target_mixin: String::new(),
                        target_class: target.clone(),
                        site: String::new(),
                        strength: 40,
                    });
                }
            }
        }
    }

    // Indirect: @Shadow expects a member another mixin added.
    let mut added_by_target: BTreeMap<String, Vec<(String, String, String)>> = BTreeMap::new();
    for model in models {
        let class = &model.record;
        for added in &class.added_members {
            added_by_target
                .entry(added.target.clone())
                .or_default()
                .push((class.mod_id.clone(), class.class_name.clone(), added.name.clone()));
        }
    }
    for model in models {
        let class = &model.record;
        for shadow in &class.shadows {
            if let Some(added) = added_by_target.get(&shadow.target) {
                for (mod_id, mixin, name) in added {
                    if mod_id == &class.mod_id {
                        continue;
                    }
                    if shadow_matches_added(shadow, name) {
                        interaction_id += 1;
                        interactions.push(MixinInteractionRecord {
                            id: format!("interaction-{interaction_id}"),
                            interaction_type: InteractionType::IndirectShadow,
                            mod_a: mod_id.clone(),
                            mod_b: class.mod_id.clone(),
                            mixin_a: mixin.clone(),
                            mixin_b: class.class_name.clone(),
                            target: shadow.target.clone(),
                            detail: format!(
                                "{mod_id} added `{name}`; {} shadows it",
                                class.mod_id
                            ),
                            strength: 70,
                            cross_mod: true,
                        });
                        edge_id += 1;
                        conflict_edges.push(MixinConflictEdgeRecord {
                            id: format!("edge-{edge_id}"),
                            edge_type: ConflictEdgeType::ShadowAddedMember,
                            source_mod: mod_id.clone(),
                            target_mod: class.mod_id.clone(),
                            source_mixin: mixin.clone(),
                            target_mixin: class.class_name.clone(),
                            target_class: shadow.target.clone(),
                            site: name.clone(),
                            strength: 70,
                        });
                    }
                }
            }
        }
    }

    // Overwrite collisions on the same method.
    let mut overwrites: BTreeMap<(String, String), Vec<&MixinClassRecord>> = BTreeMap::new();
    for model in models {
        let class = &model.record;
        for inj in &class.injected_methods {
            if inj.injection_type == MixinOperation::Overwrite.as_str() {
                overwrites
                    .entry((inj.target.clone(), inj.resolved.clone()))
                    .or_default()
                    .push(class);
            }
        }
    }
    for ((target, method), group) in &overwrites {
        if group.len() < 2 {
            continue;
        }
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let a = group[i];
                let b = group[j];
                let cross_mod = a.mod_id != b.mod_id;
                interaction_id += 1;
                interactions.push(MixinInteractionRecord {
                    id: format!("interaction-{interaction_id}"),
                    interaction_type: InteractionType::OverwriteStack,
                    mod_a: a.mod_id.clone(),
                    mod_b: b.mod_id.clone(),
                    mixin_a: a.class_name.clone(),
                    mixin_b: b.class_name.clone(),
                    target: target.clone(),
                    detail: if cross_mod {
                        format!("Multiple @Overwrite on `{method}`")
                    } else {
                        format!("`{}` has multiple @Overwrite on `{method}`", a.mod_id)
                    },
                    strength: if cross_mod { 95 } else { 45 },
                    cross_mod,
                });
                // Two different mods @Overwrite-ing the same method is one of the
                // strongest conflict signals; same-mod is internal, no edge.
                if cross_mod {
                    edge_id += 1;
                    conflict_edges.push(MixinConflictEdgeRecord {
                        id: format!("edge-{edge_id}"),
                        edge_type: ConflictEdgeType::OverwritesSameMethod,
                        source_mod: a.mod_id.clone(),
                        target_mod: b.mod_id.clone(),
                        source_mixin: a.class_name.clone(),
                        target_mixin: b.class_name.clone(),
                        target_class: target.clone(),
                        site: method.clone(),
                        strength: 95,
                    });
                }
            }
        }
    }

    // Inherited target collisions: injections on classes in a super/sub chain.
    let mut inherited_pairs: BTreeSet<(String, String, String, String)> = BTreeSet::new();
    for (i, model_a) in models.iter().enumerate() {
        let class_a = &model_a.record;
        for model_b in models.iter().skip(i + 1) {
            let class_b = &model_b.record;
            if class_a.mod_id == class_b.mod_id {
                continue;
            }
            for inj_a in &class_a.injected_methods {
                for inj_b in &class_b.injected_methods {
                    if inj_a.target == inj_b.target {
                        continue;
                    }
                    let a_slash = inj_a.target.replace('.', "/");
                    let b_slash = inj_b.target.replace('.', "/");
                    if !hierarchy.related(&a_slash, &b_slash) {
                        continue;
                    }
                    let pair_key = (
                        class_a.mod_id.clone(),
                        class_b.mod_id.clone(),
                        inj_a.target.clone(),
                        inj_b.target.clone(),
                    );
                    if !inherited_pairs.insert(pair_key) {
                        continue;
                    }
                    interaction_id += 1;
                    interactions.push(MixinInteractionRecord {
                        id: format!("interaction-{interaction_id}"),
                        interaction_type: InteractionType::SharedMember,
                        mod_a: class_a.mod_id.clone(),
                        mod_b: class_b.mod_id.clone(),
                        mixin_a: class_a.class_name.clone(),
                        mixin_b: class_b.class_name.clone(),
                        target: inj_a.target.clone(),
                        detail: format!(
                            "Injections on related classes `{}` and `{}` (inherited target chain)",
                            inj_a.target, inj_b.target
                        ),
                        strength: 55,
                        cross_mod: true,
                    });
                    edge_id += 1;
                    conflict_edges.push(MixinConflictEdgeRecord {
                        id: format!("edge-{edge_id}"),
                        edge_type: ConflictEdgeType::InheritedTarget,
                        source_mod: class_a.mod_id.clone(),
                        target_mod: class_b.mod_id.clone(),
                        source_mixin: class_a.class_name.clone(),
                        target_mixin: class_b.class_name.clone(),
                        target_class: inj_a.target.clone(),
                        site: inj_b.target.clone(),
                        strength: 55,
                    });
                }
            }
        }
    }

    // Priority conflicts on overlapping targets with injection overlap.
    for overlap in overlaps {
        if overlap.mods.len() < 2 {
            continue;
        }
        let group: Vec<&MixinClassRecord> = models
            .iter()
            .map(|m| &m.record)
            .filter(|c| c.targets.iter().any(|t| t == &overlap.target))
            .collect();
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let a = group[i];
                let b = group[j];
                if a.priority == b.priority {
                    continue;
                }
                if !share_injection_or_overwrite(a, b, &overlap.target) {
                    continue;
                }
                priority_conflicts.push(MixinPriorityConflictRecord {
                    target: overlap.target.clone(),
                    mod_a: a.mod_id.clone(),
                    mod_b: b.mod_id.clone(),
                    mixin_a: a.class_name.clone(),
                    mixin_b: b.class_name.clone(),
                    priority_a: a.priority,
                    priority_b: b.priority,
                    detail: format!(
                        "Mixin config priority {} (`{}`) vs {} (`{}`) on overlapping injections at `{}`",
                        a.priority, a.class_name, b.priority, b.class_name, overlap.target
                    ),
                });
                edge_id += 1;
                conflict_edges.push(MixinConflictEdgeRecord {
                    id: format!("edge-{edge_id}"),
                    edge_type: ConflictEdgeType::PriorityConflict,
                    source_mod: a.mod_id.clone(),
                    target_mod: b.mod_id.clone(),
                    source_mixin: a.class_name.clone(),
                    target_mixin: b.class_name.clone(),
                    target_class: overlap.target.clone(),
                    site: String::new(),
                    strength: 60,
                });
            }
        }
    }

    // Redirect collisions on the same call site.
    let mut redirects: BTreeMap<(String, String, String), Vec<&MixinClassRecord>> = BTreeMap::new();
    for model in models {
        let class = &model.record;
        for inj in &class.injected_methods {
            if inj.injection_type == MixinOperation::Redirect.as_str()
                || inj.injection_type == MixinOperation::WrapOperation.as_str()
            {
                let site = injection_compare_key(inj);
                redirects
                    .entry((inj.target.clone(), inj.resolved.clone(), site))
                    .or_default()
                    .push(class);
            }
        }
    }
    for ((target, method, site), group) in &redirects {
        if group.len() < 2 {
            continue;
        }
        let mods: BTreeSet<&str> = group.iter().map(|c| c.mod_id.as_str()).collect();
        if mods.len() < 2 {
            continue;
        }
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let a = group[i];
                let b = group[j];
                edge_id += 1;
                conflict_edges.push(MixinConflictEdgeRecord {
                    id: format!("edge-{edge_id}"),
                    edge_type: ConflictEdgeType::RedirectsSameCall,
                    source_mod: a.mod_id.clone(),
                    target_mod: b.mod_id.clone(),
                    source_mixin: a.class_name.clone(),
                    target_mixin: b.class_name.clone(),
                    target_class: target.clone(),
                    site: format!("{method}::{site}"),
                    strength: 80,
                });
            }
        }
    }

    // Local / argument mutation collisions on the same slot.
    let mut locals: BTreeMap<(String, String, String), Vec<&MixinClassRecord>> = BTreeMap::new();
    for model in models {
        let class = &model.record;
        for inj in &class.injected_methods {
            if inj.injection_type == MixinOperation::ModifyVariable.as_str()
                || inj.injection_type == MixinOperation::ModifyArg.as_str()
            {
                let local_key = inj
                    .local_index
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| inj.at_detail.clone());
                locals
                    .entry((inj.target.clone(), inj.resolved.clone(), local_key))
                    .or_default()
                    .push(class);
            }
        }
    }
    for ((target, method, local), group) in &locals {
        if group.len() < 2 {
            continue;
        }
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let a = group[i];
                let b = group[j];
                if a.mod_id == b.mod_id {
                    continue;
                }
                edge_id += 1;
                conflict_edges.push(MixinConflictEdgeRecord {
                    id: format!("edge-{edge_id}"),
                    edge_type: ConflictEdgeType::ModifiesSameLocal,
                    source_mod: a.mod_id.clone(),
                    target_mod: b.mod_id.clone(),
                    source_mixin: a.class_name.clone(),
                    target_mixin: b.class_name.clone(),
                    target_class: target.clone(),
                    site: format!("{method}@local:{local}"),
                    strength: 75,
                });
            }
        }
    }

    // Chained injection: HEAD entry hook + INVOKE call-site hook on same method.
    let mut head_sites: BTreeSet<(String, String)> = BTreeSet::new();
    let mut invoke_sites: Vec<(String, String, &MixinClassRecord)> = Vec::new();
    for model in models {
        let class = &model.record;
        for inj in &class.injected_methods {
            if inj.injection_type != MixinOperation::Inject.as_str() {
                continue;
            }
            let key = (inj.target.clone(), inj.resolved.clone());
            if inj.at_target == "HEAD" {
                head_sites.insert(key);
            } else if inj.at_target == "INVOKE" || inj.impact == "call-replace" {
                invoke_sites.push((inj.target.clone(), inj.resolved.clone(), class));
            }
        }
    }
    for (target, method, invoke_class) in &invoke_sites {
        for model in models {
            let head_class = &model.record;
            if head_class.mod_id == invoke_class.mod_id {
                continue;
            }
            if head_sites.contains(&(target.clone(), method.clone()))
                && head_class
                    .injected_methods
                    .iter()
                    .any(|i| {
                        i.target == *target
                            && i.resolved == *method
                            && i.at_target == "HEAD"
                            && i.injection_type == MixinOperation::Inject.as_str()
                    })
            {
                edge_id += 1;
                conflict_edges.push(MixinConflictEdgeRecord {
                    id: format!("edge-{edge_id}"),
                    edge_type: ConflictEdgeType::ChainedInjection,
                    source_mod: head_class.mod_id.clone(),
                    target_mod: invoke_class.mod_id.clone(),
                    source_mixin: head_class.class_name.clone(),
                    target_mixin: invoke_class.class_name.clone(),
                    target_class: target.clone(),
                    site: format!("{method}@HEAD+INVOKE"),
                    strength: 65,
                });
            }
        }
    }

    detect_member_signature_conflicts(models, &mut edge_id, &mut conflict_edges);
    detect_advanced_conflicts(models, &mut edge_id, &mut conflict_edges);

    (interactions, conflict_edges, priority_conflicts)
}

/// Is `injection_type` an injector that produces a site on a target method (i.e.
/// not a structural `@Shadow`/`@Accessor`/`@Invoker`/`@Unique` marker)?
fn is_injector_type(injection_type: &str) -> bool {
    matches!(
        injection_type,
        "inject"
            | "redirect"
            | "modify-arg"
            | "modify-args"
            | "modify-variable"
            | "modify-constant"
            | "wrap-operation"
            | "wrap-with-condition"
            | "modify-expression-value"
            | "modify-return-value"
            | "modify-receiver"
    )
}

/// Precise semantic-conflict taxonomy (5.4): overwrite-vs-injector, cancellable
/// HEAD vs RETURN, redirect vs wrap-operation, wrap-with-condition suppression,
/// `@ModifyArgs` collisions, and `@Unique`-less added-member collisions.
fn detect_advanced_conflicts(
    models: &[MixinClassModel],
    edge_id: &mut u32,
    conflict_edges: &mut Vec<MixinConflictEdgeRecord>,
) {
    let mut push = |edge_id: &mut u32,
                    edge_type: ConflictEdgeType,
                    a: &MixinClassRecord,
                    b: &MixinClassRecord,
                    target: &str,
                    site: String,
                    strength: u8| {
        if a.mod_id == b.mod_id {
            return;
        }
        *edge_id += 1;
        conflict_edges.push(MixinConflictEdgeRecord {
            id: format!("edge-{edge_id}"),
            edge_type,
            source_mod: a.mod_id.clone(),
            target_mod: b.mod_id.clone(),
            source_mixin: a.class_name.clone(),
            target_mixin: b.class_name.clone(),
            target_class: target.to_string(),
            site,
            strength,
        });
    };

    // ── @Overwrite vs any injector on the same target method ──
    for ov in models {
        for ov_inj in &ov.record.injected_methods {
            if ov_inj.injection_type != MixinOperation::Overwrite.as_str() {
                continue;
            }
            for other in models {
                for inj in &other.record.injected_methods {
                    if inj.target == ov_inj.target
                        && inj.resolved == ov_inj.resolved
                        && is_injector_type(&inj.injection_type)
                    {
                        push(
                            edge_id,
                            ConflictEdgeType::OverwriteVsInjector,
                            &ov.record,
                            &other.record,
                            &ov_inj.target,
                            format!("{}::overwrite-vs-{}", ov_inj.resolved, inj.injection_type),
                            90,
                        );
                    }
                }
            }
        }
    }

    // ── cancellable @Inject(HEAD) vs @Inject(RETURN) on the same method ──
    for head in models {
        for h in &head.record.injected_methods {
            if h.injection_type != MixinOperation::Inject.as_str()
                || h.at_target != "HEAD"
                || !h.meta.cancellable
            {
                continue;
            }
            for ret in models {
                for r in &ret.record.injected_methods {
                    if r.injection_type == MixinOperation::Inject.as_str()
                        && r.target == h.target
                        && r.resolved == h.resolved
                        && (r.at_target == "RETURN" || r.at_target == "TAIL")
                    {
                        push(
                            edge_id,
                            ConflictEdgeType::CancellableHeadVsReturn,
                            &head.record,
                            &ret.record,
                            &h.target,
                            format!("{}@HEAD(cancellable)->RETURN", h.resolved),
                            70,
                        );
                    }
                }
            }
        }
    }

    // ── same call site: redirect vs wrap-operation, wrap-with-condition
    //    suppression, and @ModifyArgs collisions ──
    // (target, method, site) → the (class, operation) members touching it.
    type SiteMembers<'a> = Vec<(&'a MixinClassRecord, &'a str)>;
    let mut by_site: BTreeMap<(String, String, String), SiteMembers> = BTreeMap::new();
    for model in models {
        for inj in &model.record.injected_methods {
            let key = (
                inj.target.clone(),
                inj.resolved.clone(),
                injection_compare_key(inj),
            );
            by_site
                .entry(key)
                .or_default()
                .push((&model.record, inj.injection_type.as_str()));
        }
    }
    for ((target, method, site), members) in &by_site {
        for i in 0..members.len() {
            for j in (i + 1)..members.len() {
                let (a, a_op) = members[i];
                let (b, b_op) = members[j];
                let site_label = format!("{method}::{site}");
                let is_redirect = |op: &str| op == "redirect" || op == "wrap-operation";
                // redirect vs wrap-operation (different ops, both seize the call)
                if (a_op == "redirect" && b_op == "wrap-operation")
                    || (a_op == "wrap-operation" && b_op == "redirect")
                {
                    push(edge_id, ConflictEdgeType::RedirectVsWrapOperation, a, b, target, site_label.clone(), 80);
                }
                // wrap-with-condition can suppress a redirect/wrap/call-site hook
                if a_op == "wrap-with-condition" && (is_redirect(b_op) || b_op == "inject") {
                    push(edge_id, ConflictEdgeType::WrapConditionSuppressesCall, a, b, target, site_label.clone(), 75);
                } else if b_op == "wrap-with-condition" && (is_redirect(a_op) || a_op == "inject") {
                    push(edge_id, ConflictEdgeType::WrapConditionSuppressesCall, b, a, target, site_label.clone(), 75);
                }
                // two @ModifyArgs on the same invocation
                if a_op == "modify-args" && b_op == "modify-args" {
                    push(edge_id, ConflictEdgeType::ModifyArgsSameInvocation, a, b, target, site_label.clone(), 70);
                }
            }
        }
    }

    // ── two mods add the same member name without @Unique ──
    let mut members: BTreeMap<(String, String), Vec<(&MixinClassRecord, bool)>> = BTreeMap::new();
    for model in models {
        for m in &model.record.added_members {
            members
                .entry((m.target.clone(), m.name.clone()))
                .or_default()
                .push((&model.record, m.unique));
        }
    }
    for ((target, name), group) in &members {
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let (a, a_unique) = group[i];
                let (b, b_unique) = group[j];
                // `@Unique` is the collision-protection mechanism; only flag when
                // at least one side is NOT unique (a genuine name clash).
                if !a_unique || !b_unique {
                    push(
                        edge_id,
                        ConflictEdgeType::UniqueMemberConflict,
                        a,
                        b,
                        target,
                        format!("added-member:{name}"),
                        60,
                    );
                }
            }
        }
    }
}

/// One mod's reference to a target member, for signature-conflict grouping.
struct MemberRef {
    mod_id: String,
    mixin: String,
    descriptor: String,
}

/// `(target class, member name)` → every mod that references that member, used to
/// spot cross-mod descriptor disagreement.
type MemberSignatureGroups = BTreeMap<(String, String), Vec<MemberRef>>;

/// Cross-mod member-signature conflicts: two mods reference the same target
/// member but disagree on its descriptor.
///
/// Sound by construction (no false positives):
/// * `@Shadow` is restricted to **fields** — a field has exactly one type, so a
///   descriptor disagreement is provable skew. Differing *method* descriptors are
///   legal overloads, not conflicts, so methods are deliberately excluded.
/// * accessors/invokers are keyed by accessor name, which maps 1:1 to a single
///   backing member by Mixin convention; differing descriptors mean the mods
///   disagree on that member's type.
///
/// Either way the disagreement means at least one mod was built against a
/// different mapping/version of the target, so its `@Shadow`/`@Accessor` binding
/// will fail at apply time.
fn detect_member_signature_conflicts(
    models: &[MixinClassModel],
    edge_id: &mut u32,
    conflict_edges: &mut Vec<MixinConflictEdgeRecord>,
) {
    let mut shadow_fields: MemberSignatureGroups = BTreeMap::new();
    let mut accessors: MemberSignatureGroups = BTreeMap::new();

    for model in models {
        let class = &model.record;
        for shadow in &class.shadows {
            if shadow.kind != MemberKind::Field {
                continue;
            }
            shadow_fields
                .entry((shadow.target.clone(), shadow.name.clone()))
                .or_default()
                .push(MemberRef {
                    mod_id: class.mod_id.clone(),
                    mixin: class.class_name.clone(),
                    descriptor: shadow.descriptor.clone(),
                });
        }
        for added in &class.added_members {
            if added.origin != "accessor" && added.origin != "invoker" {
                continue;
            }
            accessors
                .entry((added.target.clone(), added.name.clone()))
                .or_default()
                .push(MemberRef {
                    mod_id: class.mod_id.clone(),
                    mixin: class.class_name.clone(),
                    descriptor: added.descriptor.clone(),
                });
        }
    }

    emit_signature_conflicts(
        &shadow_fields,
        ConflictEdgeType::ShadowDescriptorConflict,
        65,
        edge_id,
        conflict_edges,
    );
    emit_signature_conflicts(
        &accessors,
        ConflictEdgeType::AccessorConflict,
        50,
        edge_id,
        conflict_edges,
    );
}

/// Emit a conflict edge for every cross-mod pair that disagrees on a member's
/// descriptor within a `(target, member-name)` group.
fn emit_signature_conflicts(
    grouped: &MemberSignatureGroups,
    edge_type: ConflictEdgeType,
    strength: u8,
    edge_id: &mut u32,
    conflict_edges: &mut Vec<MixinConflictEdgeRecord>,
) {
    for ((target, member), refs) in grouped {
        for i in 0..refs.len() {
            for j in (i + 1)..refs.len() {
                let (a, b) = (&refs[i], &refs[j]);
                if a.mod_id == b.mod_id || a.descriptor == b.descriptor {
                    continue; // same mod, or compatible expectation — not a conflict
                }
                *edge_id += 1;
                conflict_edges.push(MixinConflictEdgeRecord {
                    id: format!("edge-{edge_id}"),
                    edge_type,
                    source_mod: a.mod_id.clone(),
                    target_mod: b.mod_id.clone(),
                    source_mixin: a.mixin.clone(),
                    target_mixin: b.mixin.clone(),
                    target_class: target.clone(),
                    site: format!("{member}: {} vs {}", a.descriptor, b.descriptor),
                    strength,
                });
            }
        }
    }
}

/// Resolve the injection `site_key` for a high-risk overwrite row.
fn overwrite_site_key(
    class: &MixinClassRecord,
    target: &str,
    method: &str,
    matched: Option<&MixinEffect>,
) -> String {
    if let Some(effect) = matched {
        return effect.site_key.clone();
    }
    class
        .injected_methods
        .iter()
        .find(|inj| {
            inj.injection_type == MixinOperation::Overwrite.as_str()
                && inj.target == target
                && (method.is_empty() || inj.resolved == method)
        })
        .map(|inj| inj.site_key.clone())
        .unwrap_or_default()
}

fn overwrite_fallback_description(
    class: &MixinClassRecord,
    target: &str,
    method: &str,
) -> String {
    if method.is_empty() {
        format!(
            "`{}` @Overwrite on `{target}` replaces target behaviour — high compatibility risk.",
            class.mod_id
        )
    } else {
        format!(
            "`{}` @Overwrite replaces `{target}#{method}` — full method replacement.",
            class.mod_id
        )
    }
}

fn shadow_matches_added(shadow: &MixinShadowMember, added_name: &str) -> bool {
    shadow.name == added_name
        || shadow.name.strip_prefix("field_") == Some(added_name)
        || added_name.strip_prefix("field_") == Some(shadow.name.as_str())
}

fn share_injection_or_overwrite(a: &MixinClassRecord, b: &MixinClassRecord, target: &str) -> bool {
    let a_sites: BTreeSet<String> = a
        .injected_methods
        .iter()
        .filter(|i| i.target == target)
        .map(injection_compare_key)
        .collect();
    let b_sites: BTreeSet<String> = b
        .injected_methods
        .iter()
        .filter(|i| i.target == target)
        .map(injection_compare_key)
        .collect();
    !a_sites.is_disjoint(&b_sites)
        || (a.operations.contains(&MixinOperation::Overwrite)
            && b.operations.contains(&MixinOperation::Overwrite))
}

fn compute_risk_scores(
    classes: &[MixinClassRecord],
    overlaps: &[MixinOverlap],
    conflict_edges: &[MixinConflictEdgeRecord],
    priority_conflicts: &[MixinPriorityConflictRecord],
    effects: &[MixinEffect],
) -> Vec<MixinRiskAssessment> {
    let mut out = Vec::new();
    for overlap in overlaps {
        // Five independent axes (see `MixinRiskAssessment`). Each is accumulated
        // and clamped, then combined multiplicatively so an uncertain finding
        // cannot saturate the scale just by touching many mods.
        let mut impact: i32 = 0;
        let mut fragility: i32 = 0;
        let mut blast: i32 = 0;
        let mut certainty: i32 = 100;
        let mut actionability: i32 = 50;
        let mut reasons = Vec::new();

        // ── impact: how destructive the semantics are (0–40) ──
        let has_overwrite = overlap.operations.contains(&MixinOperation::Overwrite);
        if has_overwrite {
            impact += 40;
            actionability = actionability.max(80);
            reasons.push("@Overwrite involved".to_string());
        } else if overlap.method_conflict {
            impact += 24;
            actionability = actionability.max(55);
            reasons.push("Method-level injection overlap".to_string());
        } else {
            impact += 8;
            reasons.push("Same target class, disjoint methods".to_string());
        }
        let impact_boost = max_impact_weight(classes, &overlap.target);
        if impact_boost > 0 {
            impact += i32::from(impact_boost.min(16));
            reasons.push(format!("Injection semantics weight +{}", impact_boost.min(16)));
        }
        let modifies_return = effects.iter().any(|e| {
            e.target == overlap.target
                && e.handler_effect
                    .as_ref()
                    .is_some_and(|h| h.early_return || h.modifies_return)
        });
        if modifies_return {
            impact += 8;
            reasons.push("Handler may modify return or exit early".to_string());
        }
        let advanced = conflict_edges.iter().any(|e| {
            matches!(
                e.edge_type,
                ConflictEdgeType::RedirectsSameCall
                    | ConflictEdgeType::ChainedInjection
                    | ConflictEdgeType::ModifiesSameLocal
            ) && e.target_class == overlap.target
        });
        if advanced {
            impact += 6;
            reasons.push("Advanced interaction pattern (redirect chain / shared local)".to_string());
        }
        let impact = impact.clamp(0, 40);

        // ── blast_radius: reach across the game / many mods (0–30) ──
        if overlap.hot_path {
            blast += 18;
            reasons.push("Hot-path target".to_string());
            let hot_effects = effects
                .iter()
                .filter(|e| e.target == overlap.target && e.hot_path)
                .count();
            if hot_effects > 0 {
                blast += (hot_effects as i32 * 3).min(6);
            }
        }
        let mod_count = overlap.mods.len();
        if mod_count > 1 {
            blast += ((mod_count as i32 - 1) * 3).min(9);
            reasons.push(format!("{mod_count} mods touch this target"));
        }
        let edge_count = conflict_edges
            .iter()
            .filter(|e| e.target_class == overlap.target)
            .count();
        if edge_count > 0 {
            blast += (edge_count as i32 * 2).min(6);
            reasons.push(format!("{edge_count} interaction edge(s)"));
        }
        let blast = blast.clamp(0, 30);

        // ── fragility: how easily it breaks on a game/mod update (0–30) ──
        let shadow_skew = conflict_edges.iter().any(|e| {
            matches!(
                e.edge_type,
                ConflictEdgeType::ShadowDescriptorConflict | ConflictEdgeType::AccessorConflict
            ) && e.target_class == overlap.target
        });
        if shadow_skew {
            fragility += 14;
            actionability = actionability.max(75);
            reasons.push(
                "Mods disagree on a target member's signature (@Shadow/@Accessor version skew)"
                    .to_string(),
            );
        }
        if classes
            .iter()
            .filter(|c| c.targets.iter().any(|t| t == &overlap.target))
            .any(|c| c.handler_bodies.iter().any(|h| h.uses_reflection))
        {
            fragility += 8;
            reasons.push("Reflective calls in mixin handler bytecode".to_string());
        }
        // Sponge `@Inject(locals = LocalCapture.CAPTURE_FAILHARD)` hard-fails the
        // injection if the target frame diverges — fragile across updates.
        if classes
            .iter()
            .filter(|c| c.targets.iter().any(|t| t == &overlap.target))
            .any(|c| {
                c.injected_methods
                    .iter()
                    .any(|i| i.local_capture == "CAPTURE_FAILHARD")
            })
        {
            fragility += 8;
            reasons.push("CAPTURE_FAILHARD local capture (apply-failure risk on update)".to_string());
        }
        let priority_conflict = priority_conflicts.iter().any(|p| p.target == overlap.target);
        if priority_conflict {
            fragility += 6;
            actionability = actionability.max(70);
            reasons.push("Priority ordering conflict".to_string());
        }
        if conflict_edges.iter().any(|e| {
            e.edge_type == ConflictEdgeType::InheritedTarget && e.target_class == overlap.target
        }) {
            fragility += 5;
            reasons.push("Inherited target chain overlap".to_string());
        }
        if effects.iter().any(|e| {
            e.target == overlap.target
                && e.handler_effect
                    .as_ref()
                    .is_some_and(|h| h.complexity_score >= 60)
        }) {
            fragility += 4;
            reasons.push("High-complexity mixin handler on this target".to_string());
        }
        let fragility = fragility.clamp(0, 30);

        // ── certainty: how sure we are this conflict is real & resolved (0–100) ──
        let unresolved = classes
            .iter()
            .filter(|c| c.targets.iter().any(|t| t == &overlap.target))
            .filter(|c| has_injection_operations(c) && c.injected_methods.is_empty())
            .count();
        if unresolved > 0 {
            certainty -= (unresolved as i32 * 25).min(60);
            actionability = actionability.min(30);
            reasons.push(format!(
                "{unresolved} mixin(s) with unresolved injection points (lowers certainty)"
            ));
        }
        if !overlap.method_conflict && !has_overwrite {
            // Same class, disjoint methods: a real overlap but a weaker signal
            // that the mods actually conflict.
            certainty -= 20;
        }
        // Plugin-gated uncertainty (5.6): a config plugin can disable these mixins
        // at load time, so we cannot confirm they apply — knock certainty down.
        let plugin_gated = classes
            .iter()
            .filter(|c| c.targets.iter().any(|t| t == &overlap.target))
            .any(|c| c.plugin_gated);
        if plugin_gated {
            certainty -= 25;
            reasons.push(
                "Some mixins here are controlled by a config plugin — possible, not confirmed"
                    .to_string(),
            );
        }
        let certainty = certainty.clamp(20, 100);
        let actionability = actionability.clamp(0, 100);

        // ── composite (risk v2): semantic_conflict / blast / fragility, weighted
        //    and gated by certainty. `apply_failure` is folded in afterwards (see
        //    `fold_apply_failures`) and floors the score because a confirmed
        //    apply failure is itself certain. ──
        let semantic_conflict = (impact as f32 * 2.5).round().clamp(0.0, 100.0) as i32;
        let magnitude =
            0.5 * semantic_conflict as f32 + 0.3 * (blast as f32 / 30.0 * 100.0) + 0.2 * (fragility as f32 / 30.0 * 100.0);
        let score = ((certainty as f32 / 100.0) * magnitude)
            .round()
            .clamp(0.0, 100.0) as u8;

        out.push(MixinRiskAssessment {
            subject: overlap.target.clone(),
            score,
            certainty: certainty as u8,
            apply_failure: 0,
            semantic_conflict: semantic_conflict as u8,
            impact: impact as u8,
            fragility: fragility as u8,
            blast_radius: blast as u8,
            actionability: actionability as u8,
            reasons,
            mods: overlap.mods.clone(),
            hot_path: overlap.hot_path,
            unresolved_points: unresolved,
        });
    }
    out
}

/// Fold apply-failure severity into risk assessments (5.7). A confirmed apply
/// failure on a target raises its `apply_failure` axis to 90 and floors the score
/// — the failure is certain, so certainty does not discount it.
pub(crate) fn fold_apply_failures(
    risk: &mut [MixinRiskAssessment],
    apply_failures: &[crate::apply_failure::ApplyFailure],
) {
    use std::collections::BTreeMap;
    let mut by_target: BTreeMap<&str, bool> = BTreeMap::new();
    for af in apply_failures {
        let entry = by_target.entry(af.target.as_str()).or_insert(false);
        *entry |= af.confirmed;
    }
    for r in risk.iter_mut() {
        if let Some(&confirmed) = by_target.get(r.subject.as_str()) {
            let axis = if confirmed { 90 } else { 55 };
            r.apply_failure = axis;
            r.score = r.score.max(axis);
            r.reasons.push(if confirmed {
                "Confirmed apply failure on this target".to_string()
            } else {
                "Possible apply failure on this target".to_string()
            });
        }
    }
}

fn method_level_conflict(
    group: &[&MixinClassRecord],
    effects: &[MixinEffect],
) -> (bool, Vec<String>) {
    if group
        .iter()
        .any(|c| c.operations.contains(&MixinOperation::Overwrite))
    {
        return (true, Vec::new());
    }

    // Two injects at the same site where either handler modifies return or exits early.
    let mut by_site: BTreeMap<String, Vec<&MixinClassRecord>> = BTreeMap::new();
    for c in group {
        for m in &c.injected_methods {
            by_site
                .entry(injection_compare_key(m))
                .or_default()
                .push(c);
        }
    }
    for (site, mods) in &by_site {
        if mods.len() < 2 {
            continue;
        }
        let risky = effects.iter().any(|e| {
            effect_matches_compare_key(e, site)
                && e.handler_effect.as_ref().is_some_and(|h| {
                    // A handler's own local stores are not a target effect, so
                    // they don't make a shared site "risky" on their own.
                    h.modifies_return || h.early_return || h.writes_target_state
                })
        });
        if risky {
            return (true, vec![site.clone()]);
        }
    }

    let any_unresolved = group
        .iter()
        .filter(|c| has_injection_operations(c))
        .any(|c| c.injected_methods.is_empty());

    let mut by_method: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for c in group {
        for m in &c.injected_methods {
            by_method
                .entry(injection_compare_key(m))
                .or_default()
                .insert(c.mod_id.as_str());
        }
    }
    let shared: Vec<String> = by_method
        .into_iter()
        .filter(|(_, mods)| mods.len() >= 2)
        .map(|(m, _)| m)
        .collect();

    let conflict = !shared.is_empty() || any_unresolved;
    (conflict, shared)
}

fn max_impact_weight(classes: &[MixinClassRecord], target: &str) -> u8 {
    classes
        .iter()
        .filter(|c| c.targets.iter().any(|t| t == target))
        .flat_map(|c| c.injected_methods.iter())
        .filter(|i| i.target == target)
        .map(|i| impact_label_weight(&i.impact))
        .max()
        .unwrap_or(0)
}

fn impact_label_weight(label: &str) -> u8 {
    match label {
        "method-replace" => InjectionImpact::MethodReplace.risk_weight(),
        "call-replace" => InjectionImpact::CallReplace.risk_weight(),
        "entry-hook" => InjectionImpact::EntryHook.risk_weight(),
        "exit-hook" => InjectionImpact::ExitHook.risk_weight(),
        "local-mutation" => InjectionImpact::LocalMutation.risk_weight(),
        "data-mutation" => InjectionImpact::DataMutation.risk_weight(),
        "constant-mutation" => InjectionImpact::ConstantMutation.risk_weight(),
        _ => InjectionImpact::Unknown.risk_weight(),
    }
}

fn has_injection_operations(c: &MixinClassRecord) -> bool {
    c.operations.iter().any(|op| {
        matches!(
            op,
            MixinOperation::Inject
                | MixinOperation::Redirect
                | MixinOperation::ModifyArg
                | MixinOperation::ModifyArgs
                | MixinOperation::ModifyVariable
                | MixinOperation::ModifyConstant
                | MixinOperation::WrapOperation
                | MixinOperation::WrapWithCondition
                | MixinOperation::ModifyExpressionValue
                | MixinOperation::ModifyReturnValue
                | MixinOperation::ModifyReceiver
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ResolvedInjectionPoint;

    fn record(
        mod_id: &str,
        methods: &[&str],
        ops: &[MixinOperation],
    ) -> MixinClassRecord {
        MixinClassRecord {
            archive: format!("{mod_id}.jar"),
            mod_id: mod_id.into(),
            config: "mixins.json".into(),
            class_name: format!("{mod_id}.Mixin"),
            class_path: format!("{mod_id}/Mixin.class"),
            targets: vec!["net.minecraft.server.MinecraftServer".into()],
            target_namespace: Default::default(),
            operations: ops.to_vec(),
            injected_methods: methods
                .iter()
                .map(|&m| ResolvedInjectionPoint {
                    target: "net.minecraft.server.MinecraftServer".into(),
                    original: m.to_string(),
                    resolved: m.to_string(),
                    canonical: m.to_string(),
                    site_key: format!("{m}@HEAD"),
                    namespace: crate::refmap::Namespace::Named,
                    injection_type: "inject".to_string(),
                    resolved_via_refmap: false,
                    handler_method: "handler".into(),
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
            hot_paths: vec!["server-tick".into()],
            effects: Vec::new(),
            plugin_gated: false,
        }
    }

    #[test]
    fn overwrite_vs_injector_emits_edge() {
        let mut ov = record("alpha", &["tick()V"], &[MixinOperation::Overwrite]);
        ov.injected_methods[0].injection_type = "overwrite".into();
        let inj = record("beta", &["tick()V"], &[MixinOperation::Inject]);
        let (_, edges, _) = detect_interactions(
            &[ov.into(), inj.into()],
            &[],
            &HierarchyIndex::new(),
        );
        assert!(edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::OverwriteVsInjector));
    }

    #[test]
    fn cancellable_head_vs_return_emits_edge() {
        let mut head = record("alpha", &["tick()V"], &[MixinOperation::Inject]);
        head.injected_methods[0].at_target = "HEAD".into();
        head.injected_methods[0].meta.cancellable = true;
        let mut ret = record("beta", &["tick()V"], &[MixinOperation::Inject]);
        ret.injected_methods[0].at_target = "RETURN".into();
        let (_, edges, _) = detect_interactions(
            &[head.into(), ret.into()],
            &[],
            &HierarchyIndex::new(),
        );
        assert!(edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::CancellableHeadVsReturn));
    }

    #[test]
    fn unique_member_collision_emits_edge_but_unique_pair_does_not() {
        let mut a = record("alpha", &[], &[MixinOperation::Inject]);
        let mut b = record("beta", &[], &[MixinOperation::Inject]);
        let member = |unique: bool| crate::model::MixinAddedMember {
            target: "net.minecraft.server.MinecraftServer".into(),
            name: "intermed$helper".into(),
            descriptor: "()V".into(),
            kind: MemberKind::Method,
            origin: "added".into(),
            unique,
        };
        a.added_members = vec![member(false)];
        b.added_members = vec![member(false)];
        let (_, edges, _) =
            detect_interactions(&[a.clone().into(), b.clone().into()], &[], &HierarchyIndex::new());
        assert!(edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::UniqueMemberConflict));

        // Both @Unique → no collision edge.
        a.added_members = vec![member(true)];
        b.added_members = vec![member(true)];
        let (_, edges, _) =
            detect_interactions(&[a.into(), b.into()], &[], &HierarchyIndex::new());
        assert!(!edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::UniqueMemberConflict));
    }

    #[test]
    fn disjoint_methods_not_conflict() {
        let overlaps = classify_overlaps(
            &HotPathRules::default(),
            &[
                record("alpha", &["tick()V"], &[MixinOperation::Inject]),
                record("beta", &["render()V"], &[MixinOperation::Redirect]),
            ],
            &[],
        );
        assert_eq!(overlaps.len(), 1);
        assert!(!overlaps[0].method_conflict);
    }

    fn record_with_site(
        mod_id: &str,
        display: &str,
        canonical: &str,
        namespace: Namespace,
    ) -> MixinClassRecord {
        let mut rec = record(mod_id, &[], &[MixinOperation::Inject]);
        rec.injected_methods = vec![ResolvedInjectionPoint {
            target: "net.minecraft.server.MinecraftServer".into(),
            original: display.into(),
            resolved: display.into(),
            canonical: canonical.into(),
            site_key: format!("{canonical}@HEAD"),
            namespace,
            injection_type: "inject".into(),
            resolved_via_refmap: true,
            handler_method: "handler".into(),
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
        }];
        rec
    }

    #[test]
    fn same_canonical_across_namespaces_is_detected_not_silently_missed() {
        // Mod A's point displays as named `tick()V`, Mod B's as intermediary
        // `method_1574()V`; both canonicalize to the same intermediary key.
        // Comparing on the display name (the old behaviour) missed this; comparing
        // on the canonical key catches it.
        let classes = vec![
            record_with_site("alpha", "tick()V", "method_1574()V", Namespace::Intermediary),
            record_with_site("beta", "method_1574()V", "method_1574()V", Namespace::Intermediary),
        ];
        let analysis = MixinInteractionEngine::new().analyze(&classes);
        assert!(
            analysis
                .conflict_edges
                .iter()
                .any(|e| e.edge_type == ConflictEdgeType::SameInjectionPoint),
            "same canonical point across namespaces must conflict"
        );
    }

    #[test]
    fn cross_namespace_without_bridge_is_surfaced_not_dropped() {
        // Mod A only has a named key, Mod B only intermediary, no bridge → the
        // clash cannot be confirmed, but must be surfaced as a low-strength
        // namespace mismatch rather than silently missed.
        let classes = vec![
            record_with_site("alpha", "tick()V", "tick()V", Namespace::Named),
            record_with_site("beta", "method_1574()V", "method_1574()V", Namespace::Intermediary),
        ];
        let analysis = MixinInteractionEngine::new().analyze(&classes);
        assert!(analysis
            .conflict_edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::NamespaceMismatch));
        // And it is not falsely reported as a confirmed same-injection conflict.
        assert!(!analysis
            .conflict_edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::SameInjectionPoint));
    }

    #[test]
    fn mixed_group_does_not_make_a_same_mod_self_conflict_edge() {
        // Mod A weaves the site from two of its own mixins AND Mod B weaves it
        // too. The group has two distinct mods, so it's interesting — but the
        // A.mixin1 ↔ A.mixin2 pair is intra-mod complexity, not a conflict edge.
        let mut a1 = record("alpha", &["tick()V"], &[MixinOperation::Inject]);
        a1.class_name = "alpha.Mixin1".into();
        let mut a2 = record("alpha", &["tick()V"], &[MixinOperation::Inject]);
        a2.class_name = "alpha.Mixin2".into();
        let b = record("beta", &["tick()V"], &[MixinOperation::Inject]);
        let analysis = MixinInteractionEngine::new().analyze(&[a1, a2, b]);

        // No conflict edge may connect a mod to itself.
        assert!(
            analysis
                .conflict_edges
                .iter()
                .all(|e| e.source_mod != e.target_mod),
            "no self (same-mod) conflict edge: {:?}",
            analysis.conflict_edges
        );
        // The real cross-mod conflict (alpha↔beta) is still reported.
        assert!(analysis
            .conflict_edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::SameInjectionPoint
                && e.source_mod != e.target_mod));
        // Both an intra-mod (alpha↔alpha) and cross-mod interaction exist.
        assert!(analysis.interactions.iter().any(|i| !i.cross_mod));
        assert!(analysis.interactions.iter().any(|i| i.cross_mod));
    }

    #[test]
    fn two_mods_at_one_site_remain_a_cross_mod_conflict() {
        let a = record("alpha", &["tick()V"], &[MixinOperation::Inject]);
        let b = record("beta", &["tick()V"], &[MixinOperation::Inject]);
        let analysis = MixinInteractionEngine::new().analyze(&[a, b]);
        assert!(analysis
            .conflict_edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::SameInjectionPoint));
        assert!(analysis.interactions.iter().any(|i| i.cross_mod));
    }

    #[test]
    fn head_and_return_on_same_method_are_not_same_site() {
        let mut head = record("alpha", &["tick()V"], &[MixinOperation::Inject]);
        head.injected_methods[0].site_key = "tick()V@HEAD".into();
        head.injected_methods[0].at_target = "HEAD".into();
        let mut ret = record("beta", &["tick()V"], &[MixinOperation::Inject]);
        ret.injected_methods[0].site_key = "tick()V@RETURN".into();
        ret.injected_methods[0].at_target = "RETURN".into();
        let analysis = MixinInteractionEngine::new().analyze(&[head, ret]);
        assert!(!analysis
            .conflict_edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::SameInjectionPoint));
    }

    #[test]
    fn engine_produces_risk_assessment() {
        let classes = vec![
            record("alpha", &["tick()V"], &[MixinOperation::Inject]),
            record("beta", &["tick()V"], &[MixinOperation::Inject]),
        ];
        let analysis = MixinInteractionEngine::new().analyze(&classes);
        assert!(!analysis.risk_assessments.is_empty());
        let a = &analysis.risk_assessments[0];
        // Risk v2: a certain (resolved), hot-path method conflict ranks high but
        // does not saturate, and the structured axes are populated.
        assert!(a.score >= 40 && a.score < 100, "score = {}", a.score);
        assert!(a.semantic_conflict > 0);
        assert!(a.certainty > 0 && a.certainty <= 100);
        assert!(!analysis.interactions.is_empty());
    }

    #[test]
    fn confirmed_apply_failure_floors_score_and_sets_axis() {
        let classes = vec![
            record("alpha", &["tick()V"], &[MixinOperation::Inject]),
            record("beta", &["tick()V"], &[MixinOperation::Inject]),
        ];
        let mut analysis = MixinInteractionEngine::new().analyze(&classes);
        let target = analysis.risk_assessments[0].subject.clone();
        let af = crate::apply_failure::ApplyFailure {
            kind: crate::apply_failure::ApplyFailureKind::RequireUnsatisfied,
            mod_id: "alpha".into(),
            mixin: "alpha.Mixin".into(),
            target: target.clone(),
            member: "tick()V".into(),
            detail: "missing".into(),
            confirmed: true,
        };
        fold_apply_failures(&mut analysis.risk_assessments, &[af]);
        let r = analysis
            .risk_assessments
            .iter()
            .find(|r| r.subject == target)
            .unwrap();
        assert_eq!(r.apply_failure, 90);
        assert!(r.score >= 90);
    }

    #[test]
    fn plugin_gated_target_loses_certainty() {
        let mut a = record("alpha", &["tick()V"], &[MixinOperation::Inject]);
        a.plugin_gated = true;
        let b = record("beta", &["tick()V"], &[MixinOperation::Inject]);
        let plain = MixinInteractionEngine::new()
            .analyze(&[record("alpha", &["tick()V"], &[MixinOperation::Inject]), b.clone()]);
        let gated = MixinInteractionEngine::new().analyze(&[a, b]);
        assert!(
            gated.risk_assessments[0].certainty < plain.risk_assessments[0].certainty,
            "plugin-gated certainty {} should be below plain {}",
            gated.risk_assessments[0].certainty,
            plain.risk_assessments[0].certainty
        );
    }

    #[test]
    fn unresolved_target_has_reduced_certainty_and_does_not_saturate() {
        // Two mixins that declare injections but resolve no injection points:
        // certainty must drop below 100, and the score must not pin at 100 just
        // because both mods touch the same target.
        let mut a = record("alpha", &["tick()V"], &[MixinOperation::Inject]);
        a.injected_methods.clear();
        let mut b = record("beta", &["tick()V"], &[MixinOperation::Inject]);
        b.injected_methods.clear();
        let analysis = MixinInteractionEngine::new().analyze(&[a, b]);
        let assessment = analysis
            .risk_assessments
            .iter()
            .find(|r| r.unresolved_points > 0)
            .expect("an unresolved assessment");
        assert!(
            assessment.certainty < 100,
            "unresolved target should lose certainty, got {}",
            assessment.certainty
        );
        assert!(
            assessment.score < 100,
            "uncertain target must not saturate, got {}",
            assessment.score
        );
    }

    #[test]
    fn duplicate_overwrite_emits_overwrites_same_method_edge() {
        let mut a = record("alpha", &["tick()V"], &[MixinOperation::Overwrite]);
        a.injected_methods[0].injection_type = "overwrite".into();
        let mut b = record("beta", &["tick()V"], &[MixinOperation::Overwrite]);
        b.injected_methods[0].injection_type = "overwrite".into();
        let analysis = MixinInteractionEngine::new().analyze(&[a, b]);
        assert!(analysis.conflict_edges.iter().any(|e| {
            e.edge_type == ConflictEdgeType::OverwritesSameMethod
        }));
    }

    #[test]
    fn duplicate_redirect_emits_redirects_same_call_edge() {
        let mut a = record("alpha", &["tick()V"], &[MixinOperation::Redirect]);
        a.injected_methods[0].injection_type = "redirect".into();
        a.injected_methods[0].impact = "call-replace".into();
        let mut b = record("beta", &["tick()V"], &[MixinOperation::Redirect]);
        b.injected_methods[0].injection_type = "redirect".into();
        b.injected_methods[0].impact = "call-replace".into();
        let analysis = MixinInteractionEngine::new().analyze(&[a, b]);
        assert!(analysis.conflict_edges.iter().any(|e| {
            e.edge_type == ConflictEdgeType::RedirectsSameCall
        }));
    }

    #[test]
    fn duplicate_modify_variable_emits_modifies_same_local_edge() {
        let mut a = record("alpha", &["tick()V"], &[MixinOperation::ModifyVariable]);
        a.injected_methods[0].injection_type = "modify-variable".into();
        a.injected_methods[0].local_index = Some(2);
        let mut b = record("beta", &["tick()V"], &[MixinOperation::ModifyVariable]);
        b.injected_methods[0].injection_type = "modify-variable".into();
        b.injected_methods[0].local_index = Some(2);
        let analysis = MixinInteractionEngine::new().analyze(&[a, b]);
        assert!(analysis.conflict_edges.iter().any(|e| {
            e.edge_type == ConflictEdgeType::ModifiesSameLocal
        }));
    }

    #[test]
    fn head_plus_invoke_across_mods_emits_chained_injection_edge() {
        let mut head = record("alpha", &["tick()V"], &[MixinOperation::Inject]);
        head.injected_methods[0].at_target = "HEAD".into();
        head.injected_methods[0].site_key = "tick()V@HEAD".into();
        let mut invoke = record("beta", &["tick()V"], &[MixinOperation::Inject]);
        invoke.injected_methods[0].at_target = "INVOKE".into();
        invoke.injected_methods[0].at_detail = "INVOKE".into();
        invoke.injected_methods[0].impact = "call-replace".into();
        invoke.injected_methods[0].site_key = "tick()V@INVOKE".into();
        let analysis = MixinInteractionEngine::new().analyze(&[head, invoke]);
        assert!(analysis.conflict_edges.iter().any(|e| {
            e.edge_type == ConflictEdgeType::ChainedInjection
        }));
    }

    #[test]
    fn high_risk_overwrite_carries_effect_site_key() {
        let mut class = record("beta", &["m0()V"], &[MixinOperation::Overwrite]);
        class.injected_methods[0].injection_type = "overwrite".into();
        class.injected_methods[0].site_key = "m0()V@HEAD".into();
        let effects = crate::effect::compute_class_effects(&class);
        let analysis = MixinInteractionEngine::new().analyze(&[class]);
        assert_eq!(analysis.high_risk_overwrites.len(), 1);
        assert_eq!(analysis.high_risk_overwrites[0].site_key, "m0()V@HEAD");
        assert_eq!(effects[0].site_key, "m0()V@HEAD");
    }

    #[test]
    fn overlap_hot_path_uses_rules_when_class_hot_paths_empty() {
        let alpha = record("alpha", &["tick()V"], &[MixinOperation::Inject]);
        let mut beta = record("beta", &["render()V"], &[MixinOperation::Inject]);
        beta.targets = vec!["net.minecraft.server.MinecraftServer".into()];
        beta.hot_paths.clear();
        beta.injected_methods[0].target = "net.minecraft.server.MinecraftServer".into();
        let effects: Vec<MixinEffect> = Vec::new();
        let overlaps = classify_overlaps(
            &HotPathRules::default(),
            &[alpha, beta],
            &effects,
        );
        assert_eq!(overlaps.len(), 1);
        assert!(overlaps[0].hot_path, "server target must be hot via HotPathRules");
    }

    fn shadow_field(mod_id: &str, name: &str, descriptor: &str) -> MixinClassRecord {
        let mut rec = record(mod_id, &[], &[MixinOperation::Shadow]);
        rec.shadows = vec![crate::model::MixinShadowMember {
            target: "net.minecraft.server.MinecraftServer".into(),
            name: name.into(),
            descriptor: descriptor.into(),
            kind: MemberKind::Field,
        }];
        rec
    }

    fn accessor(mod_id: &str, name: &str, descriptor: &str) -> MixinClassRecord {
        let mut rec = record(mod_id, &[], &[MixinOperation::Accessor]);
        rec.added_members = vec![crate::model::MixinAddedMember {
            target: "net.minecraft.server.MinecraftServer".into(),
            name: name.into(),
            descriptor: descriptor.into(),
            kind: MemberKind::Method,
            origin: "accessor".into(),
            unique: false,
        }];
        rec
    }

    #[test]
    fn shadow_field_descriptor_disagreement_emits_conflict() {
        // Two mods @Shadow the same field with different types → provable skew.
        let classes = vec![
            shadow_field("alpha", "playerCount", "I"),
            shadow_field("beta", "playerCount", "J"),
        ];
        let analysis = MixinInteractionEngine::new().analyze(&classes);
        assert!(
            analysis
                .conflict_edges
                .iter()
                .any(|e| e.edge_type == ConflictEdgeType::ShadowDescriptorConflict),
            "differing shadow field descriptors must conflict"
        );
    }

    #[test]
    fn shadow_field_matching_descriptor_is_not_a_conflict() {
        // Same field, same type across mods is a perfectly valid shared expectation.
        let classes = vec![
            shadow_field("alpha", "playerCount", "I"),
            shadow_field("beta", "playerCount", "I"),
        ];
        let analysis = MixinInteractionEngine::new().analyze(&classes);
        assert!(
            !analysis
                .conflict_edges
                .iter()
                .any(|e| e.edge_type == ConflictEdgeType::ShadowDescriptorConflict),
            "matching shadow descriptors must not conflict"
        );
    }

    #[test]
    fn same_mod_shadow_disagreement_is_not_cross_mod_conflict() {
        // A single mod cannot conflict with itself.
        let classes = vec![
            shadow_field("alpha", "playerCount", "I"),
            shadow_field("alpha", "playerCount", "J"),
        ];
        let analysis = MixinInteractionEngine::new().analyze(&classes);
        assert!(!analysis
            .conflict_edges
            .iter()
            .any(|e| e.edge_type == ConflictEdgeType::ShadowDescriptorConflict));
    }

    #[test]
    fn accessor_signature_disagreement_emits_conflict() {
        // Two mods' accessors for the same member disagree on its type.
        let classes = vec![
            accessor("alpha", "getPlayerCount", "()I"),
            accessor("beta", "getPlayerCount", "()J"),
        ];
        let analysis = MixinInteractionEngine::new().analyze(&classes);
        assert!(
            analysis
                .conflict_edges
                .iter()
                .any(|e| e.edge_type == ConflictEdgeType::AccessorConflict),
            "differing accessor descriptors must conflict"
        );
    }

    #[test]
    fn shadow_descriptor_conflict_raises_risk_with_reason() {
        let classes = vec![
            shadow_field("alpha", "playerCount", "I"),
            shadow_field("beta", "playerCount", "J"),
        ];
        let analysis = MixinInteractionEngine::new().analyze(&classes);
        let assessment = analysis
            .risk_assessments
            .iter()
            .find(|r| r.subject == "net.minecraft.server.MinecraftServer")
            .expect("risk assessment for shared target");
        assert!(
            assessment.reasons.iter().any(|r| r.contains("version skew")),
            "skew reason must be present: {:?}",
            assessment.reasons
        );
    }
}