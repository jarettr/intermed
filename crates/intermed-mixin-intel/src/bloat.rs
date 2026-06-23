//! Mixin bloat detection — woven handler bytecode with little observable effect.
//!
//! This is a *measured* yield signal, not a judgement about code quality. An
//! **inert handler** is one with substantial bytecode (≥ [`INERT_MIN_INSTRUCTIONS`])
//! that provably touches nothing observable on its target: it does not modify the
//! return value, does not cancel / use CallbackInfo control flow, does not mutate
//! locals, and reads or writes no target field or method. Such a handler weaves
//! bytecode into the target for no behavioural return the analyzer can see.
//!
//! The detector is deliberately conservative — every one of those guards must
//! hold — so a handler is only ever called inert when it demonstrably affects
//! nothing. A mod accumulating many inert handlers is surfaced (as a Note) for
//! review; the score is the capped sum of named [`ComplexityComponent`]s, so it is
//! always fully explainable.

use std::collections::BTreeMap;

use crate::model::{
    ComplexityComponent, HandlerBodySummary, MixinBloatAssessment, MixinClassRecord,
};

/// Bytecode floor below which a handler is too small to be considered "bloat":
/// a handful of instructions is normal even for a no-op guard.
pub const INERT_MIN_INSTRUCTIONS: u32 = 8;

/// A handler is *inert* when it has real bytecode but no **target-visible**
/// effect. Every guard must hold — conservative by design, because a user may
/// read "inert" as "safe to delete".
///
/// Note: a handler writing to its *own* locals (`handler_local_store`) is **not**
/// an effect — counting it (as the old code did) made nearly every handler look
/// effective and hid genuine bloat. Conversely we stay cautious: reflection can
/// reach non-target state we don't model, so a reflective handler is never inert.
fn is_inert(h: &HandlerBodySummary) -> bool {
    h.instruction_count >= INERT_MIN_INSTRUCTIONS
        && !h.modifies_return_value
        && !h.throws_exception
        && !h.uses_callback_info
        && !h.uses_reflection
        && h.accesses_target_fields.is_empty()
        && h.calls_target_methods.is_empty()
}

/// A handler is *effective* when it provably affects the target in some way (or
/// uses reflection, which may reach state we cannot see). A handler temporary
/// (`handler_local_store`) is deliberately excluded.
fn is_effective(h: &HandlerBodySummary) -> bool {
    h.modifies_return_value
        || h.throws_exception
        || h.uses_callback_info
        || h.uses_reflection
        || !h.accesses_target_fields.is_empty()
        || !h.calls_target_methods.is_empty()
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

/// Compute per-mod bloat assessments. Only mods with at least one inert handler
/// get an assessment (a mod that weaves nothing inert is, by definition, not bloated).
pub fn compute_bloat(classes: &[MixinClassRecord]) -> Vec<MixinBloatAssessment> {
    // Aggregate handler stats per mod across all its mixin classes.
    struct Acc {
        total_handlers: u32,
        inert_handlers: u32,
        effective_handlers: u32,
        inert_instructions: u32,
        total_instructions: u32,
    }
    let mut by_mod: BTreeMap<&str, Acc> = BTreeMap::new();

    for class in classes {
        let acc = by_mod.entry(class.mod_id.as_str()).or_insert(Acc {
            total_handlers: 0,
            inert_handlers: 0,
            effective_handlers: 0,
            inert_instructions: 0,
            total_instructions: 0,
        });
        for h in &class.handler_bodies {
            acc.total_handlers += 1;
            acc.total_instructions += h.instruction_count;
            if is_inert(h) {
                acc.inert_handlers += 1;
                acc.inert_instructions += h.instruction_count;
            } else if is_effective(h) {
                acc.effective_handlers += 1;
            }
        }
    }

    let mut out = Vec::new();
    for (mod_id, acc) in by_mod {
        if acc.inert_handlers == 0 {
            continue;
        }
        let inert_pct = acc.inert_handlers * 100 / acc.total_handlers.max(1);

        let mut components = Vec::new();
        // (a) Share of handlers that do nothing observable — the core signal.
        components.extend(component(
            "inert handler ratio",
            inert_pct / 2,
            50,
            inert_pct,
        ));
        // (b) Absolute count, so a big mod with many inert handlers ranks above a
        //     tiny one at the same ratio.
        components.extend(component(
            "inert handler count",
            acc.inert_handlers * 4,
            30,
            acc.inert_handlers,
        ));
        // (c) Wasted bytecode volume.
        components.extend(component(
            "inert bytecode volume",
            acc.inert_instructions / 40,
            20,
            acc.inert_instructions,
        ));

        let score = components.iter().map(|c| c.points).sum::<u32>().min(100) as u8;
        out.push(MixinBloatAssessment {
            mod_id: mod_id.to_string(),
            score,
            total_handlers: acc.total_handlers,
            inert_handlers: acc.inert_handlers,
            effective_handlers: acc.effective_handlers,
            inert_instructions: acc.inert_instructions,
            total_handler_instructions: acc.total_instructions,
            components,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HandlerBodySummary;

    fn handler(name: &str, instrs: u32, effective: bool) -> HandlerBodySummary {
        HandlerBodySummary {
            handler_method: name.into(),
            handler_descriptor: String::new(),
            instruction_count: instrs,
            branch_count: 0,
            return_count: 1,
            exception_handlers: 0,
            uses_reflection: false,
            reflective_targets: Vec::new(),
            modifies_return_value: effective,
            throws_exception: false,
            accesses_target_fields: Vec::new(),
            calls_target_methods: Vec::new(),
            uses_callback_info: false,
            calls_original_operation: false,
            original_call_count: 0,
            handler_local_store: false,
            dataflow: None,
        }
    }

    fn class(mod_id: &str, handlers: Vec<HandlerBodySummary>) -> MixinClassRecord {
        MixinClassRecord {
            archive: format!("{mod_id}.jar"),
            mod_id: mod_id.into(),
            config: "m.json".into(),
            class_name: format!("{mod_id}.Mix"),
            class_path: "x.class".into(),
            targets: vec!["T".into()],
            target_namespace: Default::default(),
            runtime_namespace: Default::default(),
            operations: Vec::new(),
            injected_methods: Vec::new(),
            shadows: Vec::new(),
            added_members: Vec::new(),
            calls: Vec::new(),
            handler_bodies: handlers,
            target_hierarchy: Vec::new(),
            priority: 1000,
            refmap: None,
            hot_paths: Vec::new(),
            effects: Vec::new(),
            plugin_gated: false,
            side: crate::model::Side::Both,
            activation: crate::model::ActivationStatus::ActiveAssumed,
            activation_reason: String::new(),
        }
    }

    #[test]
    fn all_effective_handlers_are_not_bloat() {
        let c = class("a", vec![handler("h1", 30, true), handler("h2", 20, true)]);
        assert!(compute_bloat(&[c]).is_empty());
    }

    #[test]
    fn small_handlers_below_floor_are_not_inert() {
        // 5 instructions < INERT_MIN_INSTRUCTIONS, so not counted as bloat.
        let c = class("a", vec![handler("h1", 5, false), handler("h2", 5, false)]);
        assert!(compute_bloat(&[c]).is_empty());
    }

    #[test]
    fn many_inert_handlers_score_higher_than_few() {
        let few = class("a", vec![handler("h1", 40, false)]);
        let many = class(
            "b",
            vec![
                handler("h1", 40, false),
                handler("h2", 40, false),
                handler("h3", 40, false),
                handler("h4", 40, false),
            ],
        );
        let a = compute_bloat(&[few]);
        let b = compute_bloat(&[many]);
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert!(b[0].score > a[0].score, "{} vs {}", b[0].score, a[0].score);
        assert_eq!(b[0].inert_handlers, 4);
        assert_eq!(b[0].effective_handlers, 0);
    }

    #[test]
    fn score_is_capped_sum_of_components() {
        let c = class(
            "a",
            vec![handler("h1", 200, false), handler("h2", 200, false)],
        );
        let out = compute_bloat(&[c]);
        let sum: u32 = out[0].components.iter().map(|x| x.points).sum();
        assert_eq!(out[0].score as u32, sum.min(100));
    }
}
