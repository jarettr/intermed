//! Semantic handler effects derived from bytecode summaries.
//!
//! [`derive_handler_effect`] lifts structural [`HandlerBodySummary`] metrics into
//! risk-oriented semantics used by the interaction engine and effect descriptions.

use crate::model::{HandlerBodySummary, HandlerDataflow, HandlerEffect, HandlerSideEffect, ValueSource};

/// Build a semantic [`HandlerEffect`] from a structural handler bytecode summary.
///
/// When a precise [`HandlerDataflow`] is attached (the normal case for parseable
/// bytecode), the control-flow fields are taken from the abstract interpreter:
/// `early_return` then means the handler *provably* calls `cancel()` /
/// `setReturnValue()`, not merely that it touches `CallbackInfo`. When dataflow is
/// absent (e.g. a record deserialized from an older cache), it falls back to the
/// conservative structural heuristic.
pub fn derive_handler_effect(summary: &HandlerBodySummary) -> HandlerEffect {
    let mut side_effects = Vec::new();

    if summary.uses_reflection {
        side_effects.push(HandlerSideEffect::Reflection);
    }
    if !summary.calls_target_methods.is_empty() {
        side_effects.push(HandlerSideEffect::StaticTargetCall);
    }
    if !summary.accesses_target_fields.is_empty() {
        side_effects.push(HandlerSideEffect::TargetFieldAccess);
    }
    if summary.uses_callback_info {
        side_effects.push(HandlerSideEffect::CallbackControl);
    }
    if summary.throws_exception {
        side_effects.push(HandlerSideEffect::ExceptionThrow);
    }

    let df = summary.dataflow.as_ref();
    let writes_target_state = df.is_some_and(|d| !d.target_field_writes.is_empty());
    if writes_target_state {
        side_effects.push(HandlerSideEffect::TargetStateWrite);
    }
    // Deepened dataflow side-effect categories.
    const HEAVY_ALLOC: u32 = 4;
    if let Some(d) = df {
        if d.writes_global_state {
            side_effects.push(HandlerSideEffect::GlobalStateWrite);
        }
        if d.schedules_async {
            side_effects.push(HandlerSideEffect::AsyncScheduling);
        }
        if d.mutates_world {
            side_effects.push(HandlerSideEffect::WorldMutation);
        }
        if d.allocation_count >= HEAVY_ALLOC {
            side_effects.push(HandlerSideEffect::HeavyAllocation);
        }
        if d.logs_only {
            side_effects.push(HandlerSideEffect::LoggingOnly);
        }
    }

    // Prefer proven control flow; fall back to the legacy heuristic only when no
    // dataflow is available.
    let early_return = match df {
        Some(d) => d.cancels || d.sets_return_value,
        None => summary.uses_callback_info && (summary.return_count > 0 || summary.branch_count > 0),
    };

    HandlerEffect {
        handler_method: summary.handler_method.clone(),
        handler_local_store: summary.handler_local_store,
        modifies_return: summary.modifies_return_value,
        early_return,
        side_effects,
        complexity_score: complexity_score(summary, df),
        cancels: df.is_some_and(|d| d.cancels),
        sets_return_value: df.is_some_and(|d| d.sets_return_value),
        conditional_control: df.is_some_and(|d| d.conditional_control),
        return_value_source: df.map_or(ValueSource::Unknown, |d| d.return_value_source),
        writes_target_state,
        original_call_count: summary.original_call_count,
    }
}

fn complexity_score(summary: &HandlerBodySummary, df: Option<&HandlerDataflow>) -> u8 {
    let mut score = 0u32;
    score = score.saturating_add(summary.instruction_count / 8);
    score = score.saturating_add(summary.branch_count.saturating_mul(4));
    if summary.uses_reflection {
        score = score.saturating_add(20);
    }
    if summary.uses_callback_info {
        score = score.saturating_add(8);
    }
    score = score.saturating_add((summary.calls_target_methods.len().min(5) as u32) * 3);
    score = score.saturating_add((summary.accesses_target_fields.len().min(5) as u32) * 2);
    if summary.throws_exception {
        score = score.saturating_add(10);
    }
    // Dataflow-proven behavioural changes weigh more than raw size: an
    // unconditional short-circuit or a write into target state is a far stronger
    // signal of incompatibility than a long but read-only handler.
    if let Some(d) = df {
        if (d.cancels || d.sets_return_value) && !d.conditional_control {
            score = score.saturating_add(15);
        }
        if !d.target_field_writes.is_empty() {
            score = score.saturating_add(10);
        }
        // High-impact side effects in a woven method weigh heavily.
        if d.mutates_world {
            score = score.saturating_add(12);
        }
        if d.schedules_async {
            score = score.saturating_add(10);
        }
        if d.writes_global_state {
            score = score.saturating_add(8);
        }
    }
    score.min(100) as u8
}

/// Lookup handler effect by handler method name on a class record.
pub fn handler_effect_for(
    summaries: &[HandlerBodySummary],
    handler_method: &str,
) -> Option<HandlerEffect> {
    summaries
        .iter()
        .find(|s| s.handler_method == handler_method)
        .map(derive_handler_effect)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> HandlerBodySummary {
        HandlerBodySummary {
            handler_method: "handler".into(),
            handler_descriptor: String::new(),
            instruction_count: 40,
            branch_count: 3,
            return_count: 1,
            exception_handlers: 0,
            uses_reflection: false,
            string_literals: Vec::new(),
            modifies_return_value: true,
            throws_exception: false,
            accesses_target_fields: vec!["tickCount".into()],
            calls_target_methods: vec!["doTick()V".into()],
            uses_callback_info: true,
            calls_original_operation: false,
            original_call_count: 0,
            handler_local_store: true,
            dataflow: None,
        }
    }

    #[test]
    fn complexity_score_caps_at_100() {
        let mut summary = summary();
        summary.instruction_count = 800;
        summary.branch_count = 20;
        summary.uses_reflection = true;
        summary.uses_callback_info = true;
        summary.calls_target_methods = vec!["a".into(); 10];
        summary.accesses_target_fields = vec!["f".into(); 10];
        summary.throws_exception = true;
        let effect = derive_handler_effect(&summary);
        assert_eq!(effect.complexity_score, 100);
    }

    #[test]
    fn falls_back_to_heuristic_early_return_without_dataflow() {
        let effect = derive_handler_effect(&summary());
        assert!(effect.modifies_return);
        assert!(effect.handler_local_store);
        assert!(effect.early_return); // heuristic: CallbackInfo + branches/returns
        assert!(!effect.cancels); // but nothing was *proven*
        assert!(effect.complexity_score > 0);
        assert!(effect
            .side_effects
            .contains(&HandlerSideEffect::CallbackControl));
    }

    #[test]
    fn dataflow_proves_unconditional_cancel_and_outranks_heuristic() {
        // A handler that references CallbackInfo but, per dataflow, never actually
        // cancels: early_return must be false (the old heuristic over-flagged it).
        let mut quiet = summary();
        quiet.dataflow = Some(HandlerDataflow {
            cancels: false,
            sets_return_value: false,
            ..Default::default()
        });
        assert!(!derive_handler_effect(&quiet).early_return);

        // A handler that provably sets a constant return value, unconditionally.
        let mut decisive = summary();
        decisive.dataflow = Some(HandlerDataflow {
            sets_return_value: true,
            conditional_control: false,
            return_value_source: ValueSource::Constant,
            ..Default::default()
        });
        let effect = derive_handler_effect(&decisive);
        assert!(effect.early_return);
        assert!(effect.sets_return_value);
        assert!(!effect.conditional_control);
        assert_eq!(effect.return_value_source, ValueSource::Constant);
    }

    #[test]
    fn target_field_write_becomes_side_effect_and_raises_score() {
        let mut writer = summary();
        writer.dataflow = Some(HandlerDataflow {
            target_field_writes: vec![crate::model::TargetFieldWrite {
                field: "tickCount".into(),
                source: ValueSource::Constant,
            }],
            ..Default::default()
        });
        let effect = derive_handler_effect(&writer);
        assert!(effect.writes_target_state);
        assert!(effect
            .side_effects
            .contains(&HandlerSideEffect::TargetStateWrite));
    }
}