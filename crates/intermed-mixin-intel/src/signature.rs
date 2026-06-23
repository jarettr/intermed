//! Handler signature checker (plan Phase 7).
//!
//! Even when a target method and an injection point both resolve, a mixin can still
//! fail to apply because the *handler* has the wrong shape for its operation: an
//! `@Inject` with no `CallbackInfo` parameter, a `@ModifyReturnValue` that returns
//! `void`, a `@WrapOperation` missing its `Operation` parameter. These are sound,
//! descriptor-only checks — they fire only on unambiguous violations, never on a
//! merely-unusual signature, so a flagged handler is a real load-time error.

use serde::{Deserialize, Serialize};

/// Outcome of checking a handler's signature against its operation's contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureCheck {
    /// The signature is consistent with the operation's requirements.
    Valid,
    /// An `@Inject` handler with no `CallbackInfo`/`CallbackInfoReturnable` parameter.
    MissingCallbackInfo,
    /// The handler's return type is wrong for the operation (e.g. a value-modifying
    /// injector returning `void`, or an `@Inject` returning non-`void`).
    WrongReturnType,
    /// A MixinExtras wrapper (`@WrapOperation`) missing its `Operation` parameter.
    MissingOperationParam,
    /// A selector kind / operation whose signature we do not statically check.
    Unsupported,
    /// No handler descriptor was available to check.
    #[default]
    Unchecked,
}

impl SignatureCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureCheck::Valid => "valid",
            SignatureCheck::MissingCallbackInfo => "missing-callback-info",
            SignatureCheck::WrongReturnType => "wrong-return-type",
            SignatureCheck::MissingOperationParam => "missing-operation-param",
            SignatureCheck::Unsupported => "unsupported",
            SignatureCheck::Unchecked => "unchecked",
        }
    }

    /// `true` when the check is a conclusive signature error (a load failure).
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            SignatureCheck::MissingCallbackInfo
                | SignatureCheck::WrongReturnType
                | SignatureCheck::MissingOperationParam
        )
    }
}

/// Parse a JVM method descriptor `(params)ret` into its parameter type list and
/// return type (each in descriptor form). Returns `None` if malformed.
pub fn parse_descriptor(desc: &str) -> Option<(Vec<String>, String)> {
    let bytes = desc.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let close = desc.find(')')?;
    let mut params = Vec::new();
    let mut i = 1;
    while i < close {
        let (ty, next) = parse_one_type(desc, i)?;
        if next > close {
            return None;
        }
        params.push(ty);
        i = next;
    }
    let (ret, end) = parse_one_type(desc, close + 1)?;
    if end != desc.len() {
        return None;
    }
    Some((params, ret))
}

/// Parse one field-descriptor type starting at byte `start`; return the type and
/// the index just past it.
fn parse_one_type(desc: &str, start: usize) -> Option<(String, usize)> {
    let bytes = desc.as_bytes();
    let mut i = start;
    // Array dimensions.
    while bytes.get(i) == Some(&b'[') {
        i += 1;
    }
    match bytes.get(i)? {
        b'L' => {
            let semi = desc[i..].find(';')? + i;
            Some((desc[start..=semi].to_string(), semi + 1))
        }
        b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' | b'V' => {
            Some((desc[start..=i].to_string(), i + 1))
        }
        _ => None,
    }
}

/// `true` when a parameter type is a SpongePowered callback (`CallbackInfo` or
/// `CallbackInfoReturnable`).
fn is_callback_info(ty: &str) -> bool {
    ty.ends_with("CallbackInfo;") || ty.ends_with("CallbackInfoReturnable;")
}

/// `true` when a parameter type is a MixinExtras `Operation`.
fn is_operation_param(ty: &str) -> bool {
    ty.ends_with("/Operation;") || ty.ends_with(";Operation;") || ty.ends_with("Operation;")
}

/// Check a handler's signature for its operation. `operation` is the kebab-case
/// operation string (`inject`, `modify-return-value`, …); `handler_descriptor` is
/// the JVM descriptor of the handler method.
pub fn check_handler_signature(
    operation: &str,
    handler_descriptor: &str,
) -> (SignatureCheck, String) {
    if handler_descriptor.is_empty() {
        return (SignatureCheck::Unchecked, String::new());
    }
    let Some((params, ret)) = parse_descriptor(handler_descriptor) else {
        return (
            SignatureCheck::Unchecked,
            "handler descriptor could not be parsed".to_string(),
        );
    };

    match operation {
        "inject" => {
            if ret != "V" {
                return (
                    SignatureCheck::WrongReturnType,
                    format!("@Inject handler must return void, got `{ret}`"),
                );
            }
            if !params.iter().any(|p| is_callback_info(p)) {
                return (
                    SignatureCheck::MissingCallbackInfo,
                    "@Inject handler has no CallbackInfo/CallbackInfoReturnable parameter"
                        .to_string(),
                );
            }
            (SignatureCheck::Valid, String::new())
        }
        "modify-return-value"
        | "modify-arg"
        | "modify-variable"
        | "modify-constant"
        | "modify-expression-value" => {
            if ret == "V" {
                return (
                    SignatureCheck::WrongReturnType,
                    format!("@{operation} handler must return the modified value, not void"),
                );
            }
            (SignatureCheck::Valid, String::new())
        }
        "wrap-operation" => {
            if !params.iter().any(|p| is_operation_param(p)) {
                return (
                    SignatureCheck::MissingOperationParam,
                    "@WrapOperation handler has no Operation<T> parameter".to_string(),
                );
            }
            (SignatureCheck::Valid, String::new())
        }
        "wrap-with-condition" => {
            if ret != "Z" {
                return (
                    SignatureCheck::WrongReturnType,
                    format!("@WrapWithCondition handler must return boolean, got `{ret}`"),
                );
            }
            (SignatureCheck::Valid, String::new())
        }
        // Redirect / modify-args / accessor / invoker / overwrite etc. need the
        // call/target signature to check soundly — left unsupported here.
        _ => (SignatureCheck::Unsupported, String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CI: &str = "Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfo;";

    #[test]
    fn parses_descriptors() {
        assert_eq!(
            parse_descriptor("(IJ)V"),
            Some((vec!["I".into(), "J".into()], "V".into()))
        );
        assert_eq!(
            parse_descriptor("(Lfoo/Bar;[I)Z"),
            Some((vec!["Lfoo/Bar;".into(), "[I".into()], "Z".into()))
        );
        assert_eq!(parse_descriptor("garbage"), None);
    }

    #[test]
    fn inject_needs_callback_info_and_void() {
        let (ok, _) = check_handler_signature("inject", &format!("({CI})V"));
        assert_eq!(ok, SignatureCheck::Valid);

        let (missing, _) = check_handler_signature("inject", "(I)V");
        assert_eq!(missing, SignatureCheck::MissingCallbackInfo);

        let (badret, _) = check_handler_signature("inject", &format!("({CI})I"));
        assert_eq!(badret, SignatureCheck::WrongReturnType);
    }

    #[test]
    fn value_modifiers_must_not_return_void() {
        let (bad, _) = check_handler_signature("modify-return-value", "(I)V");
        assert_eq!(bad, SignatureCheck::WrongReturnType);
        let (ok, _) = check_handler_signature("modify-return-value", "(I)I");
        assert_eq!(ok, SignatureCheck::Valid);
    }

    #[test]
    fn wrap_operation_needs_operation_param() {
        let op = "Lcom/llamalad7/mixinextras/injector/wrapoperation/Operation;";
        let (ok, _) =
            check_handler_signature("wrap-operation", &format!("(I{op})Ljava/lang/Object;"));
        assert_eq!(ok, SignatureCheck::Valid);
        let (bad, _) = check_handler_signature("wrap-operation", "(I)Ljava/lang/Object;");
        assert_eq!(bad, SignatureCheck::MissingOperationParam);
    }

    #[test]
    fn unknown_operation_is_unsupported_and_empty_is_unchecked() {
        assert_eq!(
            check_handler_signature("redirect", "(I)I").0,
            SignatureCheck::Unsupported
        );
        assert_eq!(
            check_handler_signature("inject", "").0,
            SignatureCheck::Unchecked
        );
    }
}
