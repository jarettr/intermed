//! Injection semantics — what a mixin operation is likely to break.
//!
//! Static analysis cannot prove runtime behaviour, but the combination of mixin
//! operation kind and `@At` target is a strong prior for compatibility risk. The
//! analyzer uses these labels in risk scoring and fact emission.

use crate::injection_point::AtDescriptor;
use crate::model::MixinOperation;

/// High-level impact classification for one injection site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InjectionImpact {
    /// `@Overwrite` or full method body replacement.
    MethodReplace,
    /// `@Redirect` / `@WrapOperation` — replaces or wraps a call site.
    CallReplace,
    /// `@Inject` at `HEAD` / `INVOKE_ASSIGN` entry points.
    EntryHook,
    /// `@Inject` at `RETURN` / tail — affects outgoing values.
    ExitHook,
    /// `@ModifyArg` / `@ModifyVariable` — mutates data in flight.
    DataMutation,
    /// `@ModifyConstant` / `@ModifyExpressionValue`.
    ConstantMutation,
    /// `@ModifyVariable` with explicit local index.
    LocalMutation,
    /// Could not classify from available metadata.
    Unknown,
}

impl InjectionImpact {
    /// Stable kebab-case label for facts and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            InjectionImpact::MethodReplace => "method-replace",
            InjectionImpact::CallReplace => "call-replace",
            InjectionImpact::EntryHook => "entry-hook",
            InjectionImpact::ExitHook => "exit-hook",
            InjectionImpact::DataMutation => "data-mutation",
            InjectionImpact::ConstantMutation => "constant-mutation",
            InjectionImpact::LocalMutation => "local-mutation",
            InjectionImpact::Unknown => "unknown",
        }
    }

    /// Relative severity weight used by composite risk scoring (0–25).
    pub fn risk_weight(self) -> u8 {
        match self {
            InjectionImpact::MethodReplace => 25,
            InjectionImpact::CallReplace => 20,
            InjectionImpact::EntryHook => 15,
            InjectionImpact::ExitHook => 12,
            InjectionImpact::LocalMutation => 10,
            InjectionImpact::DataMutation => 10,
            InjectionImpact::ConstantMutation => 8,
            InjectionImpact::Unknown => 5,
        }
    }
}

/// Classify likely breakage semantics from operation + primary `@At` descriptor.
pub fn classify_impact(operation: &MixinOperation, at: Option<&AtDescriptor>) -> InjectionImpact {
    match operation {
        MixinOperation::Overwrite => InjectionImpact::MethodReplace,
        // `@WrapWithCondition` can suppress the call entirely, like a `@Redirect`.
        MixinOperation::Redirect
        | MixinOperation::WrapOperation
        | MixinOperation::WrapWithCondition => InjectionImpact::CallReplace,
        MixinOperation::ModifyArg | MixinOperation::ModifyArgs | MixinOperation::ModifyVariable => {
            if at.is_some_and(|a| a.by.is_some()) {
                InjectionImpact::LocalMutation
            } else {
                InjectionImpact::DataMutation
            }
        }
        MixinOperation::ModifyConstant
        | MixinOperation::ModifyExpressionValue
        | MixinOperation::ModifyReturnValue
        | MixinOperation::ModifyReceiver => InjectionImpact::ConstantMutation,
        MixinOperation::Inject => classify_inject_at(at),
        MixinOperation::Shadow
        | MixinOperation::Accessor
        | MixinOperation::Invoker
        | MixinOperation::Unique
        | MixinOperation::Definition
        | MixinOperation::Expression
        | MixinOperation::Share
        | MixinOperation::Unknown => InjectionImpact::Unknown,
    }
}

fn classify_inject_at(at: Option<&AtDescriptor>) -> InjectionImpact {
    let Some(at) = at else {
        return InjectionImpact::EntryHook;
    };
    match at.value.as_str() {
        "RETURN" | "TAIL" => InjectionImpact::ExitHook,
        "HEAD" | "INVOKE_ASSIGN" | "INVOKE_STRING" => InjectionImpact::EntryHook,
        "INVOKE" | "FIELD" | "NEW" | "CONSTANT" | "MIXINEXTRAS_THROWABLE" => {
            InjectionImpact::CallReplace
        }
        "LOAD" | "STORE" => InjectionImpact::LocalMutation,
        _ if at.by.is_some() => InjectionImpact::LocalMutation,
        _ => InjectionImpact::EntryHook,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrite_is_method_replace() {
        assert_eq!(
            classify_impact(&MixinOperation::Overwrite, None),
            InjectionImpact::MethodReplace
        );
    }

    #[test]
    fn inject_return_is_exit_hook() {
        let at = AtDescriptor {
            value: "RETURN".into(),
            ..Default::default()
        };
        assert_eq!(
            classify_impact(&MixinOperation::Inject, Some(&at)),
            InjectionImpact::ExitHook
        );
    }
}
