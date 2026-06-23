//! Effective mixin effect modelling — answers "what changes in the target method?"
//!
//! Combines injection operation, `@At` site, handler bytecode semantics, and hot-path
//! context into [`MixinEffect`] records consumed by findings, mixin-map, and rules.

use crate::handler_effect::derive_handler_effect;
use crate::model::{
    EffectiveEffectKind, HandlerBodySummary, HandlerEffect, MixinClassRecord, MixinEffect,
    MixinOperation, ResolvedInjectionPoint,
};

/// Compute all effective effects for one mixin class record.
pub fn compute_class_effects(class: &MixinClassRecord) -> Vec<MixinEffect> {
    let hot = !class.hot_paths.is_empty();
    class
        .injected_methods
        .iter()
        .map(|inj| compute_injection_effect(class, inj, hot))
        .collect()
}

/// Compute effective effect for a single resolved injection point.
pub fn compute_injection_effect(
    class: &MixinClassRecord,
    inj: &ResolvedInjectionPoint,
    hot_path: bool,
) -> MixinEffect {
    // JVM method identity is name + descriptor. Prefer an exact (name, descriptor)
    // match so overloaded handlers bind to the right body; fall back to name-only
    // when the descriptor is unknown on either side (older caches / overwrite path).
    let handler_summary = class
        .handler_bodies
        .iter()
        .find(|h| {
            h.handler_method == inj.handler_method
                && !h.handler_descriptor.is_empty()
                && !inj.handler_descriptor.is_empty()
                && h.handler_descriptor == inj.handler_descriptor
        })
        .or_else(|| {
            class
                .handler_bodies
                .iter()
                .find(|h| h.handler_method == inj.handler_method)
        });
    let handler_effect = handler_summary.map(derive_handler_effect);
    let operation = operation_from_injection_type(&inj.injection_type);
    let kinds = classify_effect_kinds(&operation, inj, handler_summary, handler_effect.as_ref());
    let effect_description =
        describe_effect(class, inj, &operation, &kinds, handler_effect.as_ref());

    MixinEffect {
        mod_id: class.mod_id.clone(),
        mixin_class: class.class_name.clone(),
        target: inj.target.clone(),
        method: inj.resolved.clone(),
        handler_method: inj.handler_method.clone(),
        operation,
        effect_kinds: kinds,
        effect_description,
        handler_effect,
        hot_path,
        site_key: inj.site_key.clone(),
        at_target: inj.at_target.clone(),
    }
}

fn operation_from_injection_type(injection_type: &str) -> MixinOperation {
    match injection_type {
        "inject" => MixinOperation::Inject,
        "redirect" => MixinOperation::Redirect,
        "overwrite" => MixinOperation::Overwrite,
        "modify-arg" => MixinOperation::ModifyArg,
        "modify-args" => MixinOperation::ModifyArgs,
        "modify-variable" => MixinOperation::ModifyVariable,
        "modify-constant" => MixinOperation::ModifyConstant,
        "wrap-operation" => MixinOperation::WrapOperation,
        "wrap-with-condition" => MixinOperation::WrapWithCondition,
        "modify-expression-value" => MixinOperation::ModifyExpressionValue,
        "modify-return-value" => MixinOperation::ModifyReturnValue,
        "modify-receiver" => MixinOperation::ModifyReceiver,
        _ => MixinOperation::Unknown,
    }
}

fn classify_effect_kinds(
    operation: &MixinOperation,
    inj: &ResolvedInjectionPoint,
    summary: Option<&HandlerBodySummary>,
    handler_effect: Option<&HandlerEffect>,
) -> Vec<EffectiveEffectKind> {
    let mut kinds = Vec::new();
    match *operation {
        MixinOperation::Overwrite => kinds.push(EffectiveEffectKind::FullMethodReplacement),
        MixinOperation::Redirect => {
            kinds.push(EffectiveEffectKind::CallSiteReplacement);
            if summary.is_some_and(|s| s.modifies_return_value)
                || handler_effect.is_some_and(|h| h.modifies_return)
            {
                kinds.push(EffectiveEffectKind::ExitModification);
            }
        }
        MixinOperation::WrapOperation => {
            // A `@WrapOperation` that delegates to the original (calls
            // `Operation.call`) is a *composable* wrapper — it observes/augments,
            // it does not seize the call site. Only when it never calls the
            // original does it behave like a full `@Redirect` replacement.
            let wraps = summary.is_some_and(|s| s.calls_original_operation);
            if wraps {
                kinds.push(EffectiveEffectKind::EntryModification);
            } else {
                kinds.push(EffectiveEffectKind::CallSiteReplacement);
            }
            if summary.is_some_and(|s| s.modifies_return_value)
                || handler_effect.is_some_and(|h| h.modifies_return)
            {
                kinds.push(EffectiveEffectKind::ExitModification);
            }
        }
        MixinOperation::ModifyArg => kinds.push(EffectiveEffectKind::ArgumentMutation),
        // `@ModifyArgs` rewrites the whole argument list of the call at once.
        MixinOperation::ModifyArgs => kinds.push(EffectiveEffectKind::ArgumentMutation),
        // `@ModifyVariable` is the one operation that genuinely rewrites a
        // *target-method* local.
        MixinOperation::ModifyVariable => kinds.push(EffectiveEffectKind::LocalMutation),
        MixinOperation::Inject => classify_inject_kinds(inj, summary, handler_effect, &mut kinds),
        // These transform a value, not a target local. Distinguish them so the
        // report says "return value modified" / "expression value modified"
        // instead of the misleading "local mutation".
        MixinOperation::ModifyReturnValue => {
            kinds.push(EffectiveEffectKind::ReturnValueMutation);
            kinds.push(EffectiveEffectKind::ExitModification);
        }
        MixinOperation::ModifyExpressionValue => {
            kinds.push(EffectiveEffectKind::ExpressionValueMutation);
            kinds.push(EffectiveEffectKind::ExitModification);
        }
        MixinOperation::ModifyConstant => {
            kinds.push(EffectiveEffectKind::ExpressionValueMutation);
        }
        MixinOperation::ModifyReceiver => kinds.push(EffectiveEffectKind::ArgumentMutation),
        // `@WrapWithCondition` can skip the wrapped call entirely — semantically a
        // call-site seizure, like a conditional `@Redirect`.
        MixinOperation::WrapWithCondition => kinds.push(EffectiveEffectKind::CallSiteReplacement),
        MixinOperation::Shadow
        | MixinOperation::Accessor
        | MixinOperation::Invoker
        | MixinOperation::Unique
        | MixinOperation::Definition
        | MixinOperation::Expression
        | MixinOperation::Share
        | MixinOperation::Unknown => kinds.push(EffectiveEffectKind::Unknown),
    }
    if handler_effect.is_some_and(|h| h.early_return) {
        kinds.push(EffectiveEffectKind::PossibleEarlyReturn);
    }
    kinds.sort();
    kinds.dedup();
    kinds
}

fn classify_inject_kinds(
    inj: &ResolvedInjectionPoint,
    summary: Option<&HandlerBodySummary>,
    handler_effect: Option<&HandlerEffect>,
    kinds: &mut Vec<EffectiveEffectKind>,
) {
    let at = inj.at_target.as_str();
    match at {
        "RETURN" | "TAIL" => {
            kinds.push(EffectiveEffectKind::ExitModification);
            if summary.is_some_and(|s| s.modifies_return_value)
                || handler_effect.is_some_and(|h| h.modifies_return)
            {
                kinds.push(EffectiveEffectKind::PossibleEarlyReturn);
            }
        }
        "HEAD" | "INVOKE_ASSIGN" | "INVOKE_STRING" => {
            kinds.push(EffectiveEffectKind::EntryModification);
            // NB: a handler storing into its own temporaries (`handler_local_store`)
            // is NOT a target-local mutation. An `@Inject` only *writes* a target
            // local through a writable MixinExtras `@Local LocalRef` (captured in
            // `mutates_target_local`); a read-only `@Local` capture still sets
            // `local_index` but is not a mutation.
            if inj.mutates_target_local {
                kinds.push(EffectiveEffectKind::LocalMutation);
            }
        }
        "INVOKE" | "FIELD" | "NEW" | "CONSTANT" => {
            kinds.push(EffectiveEffectKind::CallSiteReplacement);
        }
        "LOAD" | "STORE" => kinds.push(EffectiveEffectKind::LocalMutation),
        _ if inj.mutates_target_local => kinds.push(EffectiveEffectKind::LocalMutation),
        _ => kinds.push(EffectiveEffectKind::EntryModification),
    }
}

/// Produce a human-readable explanation of the effective mixin change.
pub fn describe_effect(
    class: &MixinClassRecord,
    inj: &ResolvedInjectionPoint,
    operation: &MixinOperation,
    kinds: &[EffectiveEffectKind],
    handler_effect: Option<&HandlerEffect>,
) -> String {
    let mut parts = Vec::new();
    let site = if inj.site_key.is_empty() {
        inj.resolved.clone()
    } else {
        inj.site_key.clone()
    };

    match *operation {
        MixinOperation::Overwrite => {
            parts.push(format!(
                "`{}` fully replaces `{}#{}` via @Overwrite.",
                class.mod_id, inj.target, inj.resolved
            ));
        }
        MixinOperation::Redirect => {
            parts.push(format!(
                "`{}` replaces a call site in `{}#{}` via @Redirect.",
                class.mod_id, inj.target, inj.resolved
            ));
        }
        MixinOperation::WrapOperation => {
            // Disposition by how many times the wrapped original is invoked —
            // the distinction Mak flags as "huge for compatibility".
            let disposition = match handler_effect.map(|h| h.original_call_count) {
                Some(0) => {
                    " It never calls the original — behaves like a full @Redirect replacement."
                }
                Some(1) => " It calls the original exactly once (composable wrapper).",
                Some(n) if n >= 2 => {
                    " It calls the original more than once — may duplicate side effects."
                }
                _ => "",
            };
            parts.push(format!(
                "`{}` wraps an operation in `{}#{}` via @WrapOperation.{disposition}",
                class.mod_id, inj.target, inj.resolved
            ));
        }
        MixinOperation::WrapWithCondition => {
            parts.push(format!(
                "`{}` conditionally suppresses a call site in `{}#{}` via MixinExtras @WrapWithCondition.",
                class.mod_id, inj.target, inj.resolved
            ));
        }
        MixinOperation::ModifyArgs => {
            parts.push(format!(
                "`{}` rewrites the whole argument list of a call in `{}#{}` via @ModifyArgs.",
                class.mod_id, inj.target, inj.resolved
            ));
        }
        MixinOperation::ModifyArg => {
            parts.push(format!(
                "`{}` mutates arguments passed into `{}#{}`.",
                class.mod_id, inj.target, inj.resolved
            ));
        }
        MixinOperation::ModifyVariable => {
            parts.push(format!(
                "`{}` mutates locals in `{}#{}`.",
                class.mod_id, inj.target, inj.resolved
            ));
        }
        MixinOperation::ModifyReturnValue => {
            // Distinguish passthrough / constant / transformed by the dataflow
            // provenance of the returned value.
            let disposition = match handler_effect.map(|h| h.return_value_source) {
                Some(crate::model::ValueSource::Argument) => {
                    " The handler returns the original value unchanged (passthrough)."
                }
                Some(crate::model::ValueSource::Constant) => {
                    " The handler returns a constant, ignoring the original."
                }
                Some(crate::model::ValueSource::Computed)
                | Some(crate::model::ValueSource::TargetCallResult)
                | Some(crate::model::ValueSource::TargetField) => {
                    " The handler returns a transformed value derived from the original/target."
                }
                _ => "",
            };
            parts.push(format!(
                "`{}` rewrites the return value of `{}#{}` via MixinExtras @ModifyReturnValue.{disposition}",
                class.mod_id, inj.target, inj.resolved
            ));
        }
        MixinOperation::ModifyReceiver => {
            parts.push(format!(
                "`{}` mutates the receiver of a call in `{}#{}` via MixinExtras @ModifyReceiver.",
                class.mod_id, inj.target, inj.resolved
            ));
        }
        MixinOperation::Inject => {
            parts.push(format!(
                "`{}` injects into `{}` at site `{}` (@{}).",
                class.mod_id, inj.target, site, inj.at_target
            ));
        }
        _ => {
            parts.push(format!(
                "`{}` applies `{}` to `{}#{}`.",
                class.mod_id,
                operation.as_str(),
                inj.target,
                inj.resolved
            ));
        }
    }

    // Prefer the dataflow-proven control flow over the heuristic phrasing.
    if let Some(precise) = handler_effect.and_then(describe_control_flow) {
        parts.push(precise);
    } else if kinds.contains(&EffectiveEffectKind::PossibleEarlyReturn) {
        parts.push("The handler may cancel execution or return early via CallbackInfo.".into());
    } else if handler_effect.is_some_and(|h| h.modifies_return) {
        parts.push("The handler may modify the method's return value.".into());
    }
    // A handler's own local stores are not a woven-method mutation, so they get
    // no sentence here. Real target-local mutation surfaces via the
    // `LocalMutation` effect kind (from `@ModifyVariable` / `LocalRef`).
    if kinds.contains(&EffectiveEffectKind::LocalMutation) {
        parts.push("The handler modifies a local variable in the woven (target) method.".into());
    }
    if handler_effect.is_some_and(|h| {
        h.side_effects
            .iter()
            .any(|s| matches!(s, crate::model::HandlerSideEffect::Reflection))
    }) {
        parts.push("The handler uses reflection — behaviour may vary across game versions.".into());
    }
    if handler_effect.is_some_and(|h| h.complexity_score >= 60) {
        parts.push(format!(
            "Handler complexity is high (score {}/100) — debugging woven code will be harder.",
            handler_effect.map(|h| h.complexity_score).unwrap_or(0)
        ));
    }

    parts.join(" ")
}

/// A precise control-flow sentence built from dataflow-proven [`HandlerEffect`]
/// fields, or `None` when nothing concrete was proven (the caller then falls back
/// to the heuristic phrasing). This is what turns "may cancel … via CallbackInfo"
/// into "unconditionally overrides the return value with a constant".
fn describe_control_flow(h: &HandlerEffect) -> Option<String> {
    use crate::model::ValueSource;

    let guard = if h.conditional_control {
        "conditionally"
    } else {
        "unconditionally"
    };
    let mut parts = Vec::new();
    if h.cancels {
        parts.push(format!(
            "The handler {guard} cancels the target method via CallbackInfo."
        ));
    }
    if h.sets_return_value {
        let source = match h.return_value_source {
            ValueSource::Constant => " with a constant value",
            ValueSource::Argument => " with one of its arguments",
            ValueSource::TargetField => " with a value read from a target field",
            ValueSource::TargetCallResult => " with the result of a target call",
            ValueSource::ThisRef => " with the target instance",
            ValueSource::NewObject => " with a newly allocated object",
            ValueSource::Computed | ValueSource::Unknown => "",
        };
        parts.push(format!(
            "The handler {guard} overrides the return value{source}."
        ));
    }
    if h.writes_target_state {
        parts.push("The handler writes into target-class fields, mutating target state.".into());
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// Attach computed effects to every class record (mutates in place).
pub fn enrich_classes_with_effects(classes: &mut [MixinClassRecord]) -> Vec<MixinEffect> {
    let mut all = Vec::new();
    for class in classes.iter_mut() {
        let effects = compute_class_effects(class);
        all.extend(effects.clone());
        class.effects = effects;
    }
    all
}

/// Find the best matching effect for a high-risk overwrite row.
pub fn effect_for_overwrite<'a>(
    effects: &'a [MixinEffect],
    mod_id: &str,
    class_name: &str,
    target: &str,
    method: &str,
) -> Option<&'a MixinEffect> {
    effects.iter().find(|e| {
        e.mod_id == mod_id
            && e.mixin_class == class_name
            && e.target == target
            && (method.is_empty()
                || e.method == method
                || (!e.site_key.is_empty() && e.site_key.starts_with(&format!("{method}@"))))
            && e.operation == MixinOperation::Overwrite
    })
}

/// Collect effect summaries for mixins touching a target class.
pub fn effect_summaries_for_target(effects: &[MixinEffect], target: &str) -> Vec<String> {
    let mut out = Vec::new();
    for effect in effects.iter().filter(|e| e.target == target) {
        if !effect.effect_description.is_empty() {
            out.push(effect.effect_description.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HandlerEffect, MixinClassRecord, ValueSource};

    fn handler_effect() -> HandlerEffect {
        HandlerEffect {
            handler_method: "h".into(),
            handler_local_store: false,
            modifies_return: true,
            early_return: true,
            side_effects: Vec::new(),
            complexity_score: 10,
            cancels: false,
            sets_return_value: false,
            conditional_control: false,
            return_value_source: ValueSource::Unknown,
            writes_target_state: false,
            original_call_count: 0,
        }
    }

    #[test]
    fn control_flow_description_is_precise_from_dataflow() {
        let mut he = handler_effect();
        he.sets_return_value = true;
        he.return_value_source = ValueSource::Constant;
        let s = describe_control_flow(&he).expect("proven");
        assert!(
            s.contains("unconditionally overrides the return value with a constant"),
            "got: {s}"
        );

        he.cancels = true;
        he.conditional_control = true;
        let s = describe_control_flow(&he).unwrap();
        assert!(
            s.contains("conditionally cancels the target method"),
            "got: {s}"
        );

        // Nothing proven → fall back to the heuristic (None).
        let quiet = handler_effect();
        assert!(describe_control_flow(&quiet).is_none());
    }

    fn inject_record(at: &str, modifies_return: bool) -> MixinClassRecord {
        MixinClassRecord {
            archive: "a.jar".into(),
            mod_id: "alpha".into(),
            config: "mixins.json".into(),
            class_name: "alpha.Mixin".into(),
            class_path: "alpha/Mixin.class".into(),
            targets: vec!["net.minecraft.server.MinecraftServer".into()],
            target_namespace: Default::default(),
            runtime_namespace: Default::default(),
            operations: vec![MixinOperation::Inject],
            injected_methods: vec![ResolvedInjectionPoint {
                target: "net.minecraft.server.MinecraftServer".into(),
                original: "tick()V".into(),
                resolved: "tick()V".into(),
                canonical: "tick()V".into(),
                site_key: format!("tick()V@{at}"),
                namespace: crate::refmap::Namespace::Named,
                injection_type: "inject".into(),
                resolved_via_refmap: false,
                handler_method: "handler".into(),
                handler_descriptor: String::new(),
                mutates_target_local: false,
                at_target: at.into(),
                at_detail: at.into(),
                impact: "entry-hook".into(),
                local_index: None,
                local_capture: String::new(),
                meta: Default::default(),
                at_ordinal: None,
                at_target_member: String::new(),
            }],
            shadows: Vec::new(),
            added_members: Vec::new(),
            calls: Vec::new(),
            handler_bodies: vec![HandlerBodySummary {
                handler_method: "handler".into(),
                handler_descriptor: String::new(),
                instruction_count: 12,
                branch_count: 1,
                return_count: 1,
                exception_handlers: 0,
                uses_reflection: false,
                reflective_targets: Vec::new(),
                modifies_return_value: modifies_return,
                throws_exception: false,
                accesses_target_fields: Vec::new(),
                calls_target_methods: Vec::new(),
                uses_callback_info: modifies_return,
                calls_original_operation: false,
                original_call_count: 0,
                handler_local_store: false,
                dataflow: None,
            }],
            target_hierarchy: Vec::new(),
            priority: 1000,
            refmap: None,
            hot_paths: vec!["server-tick".into()],
            effects: Vec::new(),
            plugin_gated: false,
            side: crate::model::Side::Both,
            activation: crate::model::ActivationStatus::ActiveAssumed,
            activation_reason: String::new(),
        }
    }

    #[test]
    fn head_inject_with_writable_local_ref_is_local_mutation() {
        // A MixinExtras `@Local LocalRef` write → mutates_target_local = true.
        let mut record = inject_record("HEAD", false);
        record.injected_methods[0].mutates_target_local = true;
        let effects = compute_class_effects(&record);
        assert!(
            effects[0]
                .effect_kinds
                .contains(&EffectiveEffectKind::LocalMutation)
        );
    }

    #[test]
    fn head_inject_with_readonly_local_capture_is_not_mutation() {
        // Read-only `@Local` capture: local_index set but no write.
        let mut record = inject_record("HEAD", false);
        record.injected_methods[0].local_index = Some(3);
        record.injected_methods[0].mutates_target_local = false;
        let effects = compute_class_effects(&record);
        assert!(
            !effects[0]
                .effect_kinds
                .contains(&EffectiveEffectKind::LocalMutation)
        );
    }

    #[test]
    fn wrap_operation_calling_original_is_not_call_site_replacement() {
        let mut record = inject_record("HEAD", false);
        record.operations = vec![MixinOperation::WrapOperation];
        record.injected_methods[0].injection_type = "wrap-operation".into();
        // Calls Operation.call → composable wrapper.
        record.handler_bodies[0].calls_original_operation = true;
        let effects = compute_class_effects(&record);
        assert!(
            !effects[0]
                .effect_kinds
                .contains(&EffectiveEffectKind::CallSiteReplacement)
        );
        assert!(
            effects[0]
                .effect_kinds
                .contains(&EffectiveEffectKind::EntryModification)
        );
    }

    #[test]
    fn wrap_operation_disposition_surfaces_call_count() {
        let mut record = inject_record("HEAD", false);
        record.operations = vec![MixinOperation::WrapOperation];
        record.injected_methods[0].injection_type = "wrap-operation".into();
        record.handler_bodies[0].calls_original_operation = true;
        record.handler_bodies[0].original_call_count = 2;
        let effects = compute_class_effects(&record);
        assert!(
            effects[0].effect_description.contains("more than once"),
            "expected duplicate-original wording, got: {}",
            effects[0].effect_description
        );

        // Zero calls → behaves like a @Redirect replacement.
        record.handler_bodies[0].calls_original_operation = false;
        record.handler_bodies[0].original_call_count = 0;
        let effects = compute_class_effects(&record);
        assert!(
            effects[0]
                .effect_description
                .contains("never calls the original")
        );
    }

    #[test]
    fn wrap_operation_not_calling_original_is_call_site_replacement() {
        let mut record = inject_record("HEAD", false);
        record.operations = vec![MixinOperation::WrapOperation];
        record.injected_methods[0].injection_type = "wrap-operation".into();
        record.handler_bodies[0].calls_original_operation = false;
        let effects = compute_class_effects(&record);
        assert!(
            effects[0]
                .effect_kinds
                .contains(&EffectiveEffectKind::CallSiteReplacement)
        );
    }

    #[test]
    fn effect_binds_to_handler_overload_by_descriptor() {
        // Two handlers share the name "handler" but differ in descriptor; the two
        // injection points must each bind to their matching body (one modifies the
        // return value, the other does not) — name-only matching bound both to the
        // first body.
        let mut record = inject_record("HEAD", false);
        record.injected_methods = vec![
            ResolvedInjectionPoint {
                handler_descriptor: "(Lp/CallbackInfo;)V".into(),
                site_key: "tick()V@HEAD#a".into(),
                ..record.injected_methods[0].clone()
            },
            ResolvedInjectionPoint {
                handler_descriptor: "(ILp/CallbackInfo;)V".into(),
                site_key: "tick()V@HEAD#b".into(),
                ..record.injected_methods[0].clone()
            },
        ];
        record.handler_bodies = vec![
            HandlerBodySummary {
                handler_descriptor: "(Lp/CallbackInfo;)V".into(),
                modifies_return_value: false,
                ..record.handler_bodies[0].clone()
            },
            HandlerBodySummary {
                handler_descriptor: "(ILp/CallbackInfo;)V".into(),
                modifies_return_value: true,
                ..record.handler_bodies[0].clone()
            },
        ];
        let effects = compute_class_effects(&record);
        // The second injection (descriptor (I…)V) binds the modifies_return body.
        let second = effects
            .iter()
            .find(|e| e.site_key == "tick()V@HEAD#b")
            .unwrap();
        assert!(
            second
                .handler_effect
                .as_ref()
                .is_some_and(|h| h.modifies_return)
        );
        let first = effects
            .iter()
            .find(|e| e.site_key == "tick()V@HEAD#a")
            .unwrap();
        assert!(
            first
                .handler_effect
                .as_ref()
                .is_some_and(|h| !h.modifies_return)
        );
    }

    #[test]
    fn inject_return_with_return_modify_is_exit_effect() {
        let record = inject_record("RETURN", true);
        let effects = compute_class_effects(&record);
        let effect = &effects[0];
        assert!(
            effect
                .effect_kinds
                .contains(&EffectiveEffectKind::ExitModification)
        );
        assert!(
            effect.effect_description.contains("return value")
                || effect.effect_description.contains("CallbackInfo")
                || effect.effect_description.contains("RETURN")
        );
    }

    #[test]
    fn head_inject_with_only_handler_temporaries_is_not_local_mutation() {
        // Handler stores into its own temporaries but does not capture a target
        // local (local_index = None). This must NOT be reported as a target
        // local mutation — the previous code did exactly that and over-reported.
        let mut record = inject_record("HEAD", false);
        record.handler_bodies[0].handler_local_store = true;
        record.injected_methods[0].local_index = None;
        let effects = compute_class_effects(&record);
        assert!(
            !effects[0]
                .effect_kinds
                .contains(&EffectiveEffectKind::LocalMutation),
            "handler temporaries must not be a target LocalMutation"
        );
    }

    #[test]
    fn head_inject_with_captured_writable_local_is_local_mutation() {
        // A captured local that is *written* (writable @Local ref) is a mutation;
        // a captured-but-read local (local_index only) is not — see the readonly test.
        let mut record = inject_record("HEAD", false);
        record.injected_methods[0].local_index = Some(2);
        record.injected_methods[0].mutates_target_local = true;
        let effects = compute_class_effects(&record);
        assert!(
            effects[0]
                .effect_kinds
                .contains(&EffectiveEffectKind::LocalMutation)
        );
    }

    #[test]
    fn modify_return_value_is_return_value_mutation_not_local() {
        let mut record = inject_record("HEAD", false);
        record.operations = vec![MixinOperation::ModifyReturnValue];
        record.injected_methods[0].injection_type = "modify-return-value".into();
        let effects = compute_class_effects(&record);
        let kinds = &effects[0].effect_kinds;
        assert!(kinds.contains(&EffectiveEffectKind::ReturnValueMutation));
        assert!(!kinds.contains(&EffectiveEffectKind::LocalMutation));
    }

    #[test]
    fn effect_for_overwrite_matches_by_site_key_fragment() {
        let mut record = inject_record("HEAD", false);
        record.operations = vec![MixinOperation::Overwrite];
        record.injected_methods[0].injection_type = "overwrite".into();
        record.injected_methods[0].site_key = "tick()V@HEAD".into();
        let effects = compute_class_effects(&record);
        let matched = effect_for_overwrite(
            &effects,
            "alpha",
            "alpha.Mixin",
            "net.minecraft.server.MinecraftServer",
            "tick()V",
        );
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().site_key, "tick()V@HEAD");
    }

    #[test]
    fn overwrite_is_full_replacement() {
        let mut record = inject_record("HEAD", false);
        record.operations = vec![MixinOperation::Overwrite];
        record.injected_methods[0].injection_type = "overwrite".into();
        let effects = compute_class_effects(&record);
        let effect = &effects[0];
        assert!(
            effect
                .effect_kinds
                .contains(&EffectiveEffectKind::FullMethodReplacement)
        );
    }
}
