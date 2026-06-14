//! Mixin handler bytecode analysis.
//!
//! Handler methods carry the woven logic. Parsing their `Code` attributes yields
//! invocation edges, control-flow complexity, and reflective dispatch that never
//! appears as bare constant-pool references in the mixin class shell.

use std::collections::BTreeSet;

use cafebabe::attributes::{AttributeData, CodeData};
use cafebabe::bytecode::Opcode;
use cafebabe::constant_pool::{ConstantPoolItem, LiteralConstant, MemberRef};
use cafebabe::{parse_class_with_options, MethodAccessFlags, ParseOptions};

use crate::annotation::descriptor_to_dotted;
use crate::model::{CallKind, CallProvenance, HandlerBodySummary, MixinCall};

const REFLECTIVE_CLASSES: &[&str] = &[
    "java/lang/Class",
    "java/lang/reflect/Method",
    "java/lang/reflect/Field",
    "java/lang/reflect/Constructor",
    "java/lang/reflect/AccessibleObject",
];

const CALLBACK_INFO_CLASS: &str = "org/spongepowered/asm/mixin/injection/callback/CallbackInfo";
const CALLBACK_INFO_RETURNABLE: &str =
    "org/spongepowered/asm/mixin/injection/callback/CallbackInfoReturnable";

const CALLBACK_INFO_METHODS: &[(&str, &str)] = &[
    (CALLBACK_INFO_CLASS, "cancel"),
    (CALLBACK_INFO_CLASS, "setReturnValue"),
    (CALLBACK_INFO_RETURNABLE, "setReturnValue"),
    (CALLBACK_INFO_RETURNABLE, "getReturnValue"),
    (CALLBACK_INFO_RETURNABLE, "cancel"),
];

const REFLECTIVE_METHODS: &[(&str, &str)] = &[
    ("java/lang/Class", "forName"),
    ("java/lang/Class", "getMethod"),
    ("java/lang/Class", "getDeclaredMethod"),
    ("java/lang/Class", "getConstructor"),
    ("java/lang/Class", "getDeclaredConstructor"),
    ("java/lang/reflect/Method", "invoke"),
    ("java/lang/reflect/Constructor", "newInstance"),
    ("java/lang/reflect/Field", "get"),
    ("java/lang/reflect/Field", "set"),
    ("java/lang/reflect/AccessibleObject", "setAccessible"),
];

/// Summarize every mixin handler method body in `bytes`.
pub fn analyze_handler_bodies(
    bytes: &[u8],
    handler_methods: &BTreeSet<String>,
    mixin_targets: &[String],
    target_owner_slash: &BTreeSet<String>,
) -> (Vec<HandlerBodySummary>, Vec<MixinCall>) {
    if handler_methods.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut opts = ParseOptions::default();
    opts.parse_bytecode(true);
    let Ok(class) = parse_class_with_options(bytes, &opts) else {
        return (Vec::new(), Vec::new());
    };

    let target_slash = target_owner_slash;
    let mut summaries = Vec::new();
    let mut calls = BTreeSet::new();

    for method in &class.methods {
        let name = method.name.as_ref();
        if !handler_methods.contains(name) {
            continue;
        }
        let descriptor = method.descriptor.to_string();
        let Some(code) = method_code(&method.attributes) else {
            summaries.push(HandlerBodySummary {
                handler_method: name.to_string(),
                handler_descriptor: descriptor.clone(),
                instruction_count: 0,
                branch_count: 0,
                return_count: 0,
                exception_handlers: 0,
                uses_reflection: false,
                string_literals: Vec::new(),
                modifies_return_value: false,
                throws_exception: false,
                accesses_target_fields: Vec::new(),
                calls_target_methods: Vec::new(),
                uses_callback_info: false,
                calls_original_operation: false,
                original_call_count: 0,
                handler_local_store: false,
                dataflow: None,
            });
            continue;
        };

        let is_static = method.access_flags.contains(MethodAccessFlags::STATIC);
        let (mut summary, body_calls) =
            summarize_code(name, &descriptor, code, target_slash, mixin_targets);
        summary.dataflow =
            crate::dataflow::analyze_handler_dataflow(code, &method.descriptor, is_static, target_slash);
        summaries.push(summary);
        calls.extend(body_calls);
    }

    for summary in &mut summaries {
        if summary.uses_reflection {
            for s in extract_string_constants(bytes) {
                if !summary.string_literals.iter().any(|lit| lit == &s) {
                    summary.string_literals.push(s);
                }
            }
        }
    }

    (summaries, calls.into_iter().collect())
}

fn method_code<'a>(
    attributes: &'a [cafebabe::attributes::AttributeInfo<'a>],
) -> Option<&'a CodeData<'a>> {
    for attr in attributes {
        if let AttributeData::Code(code) = &attr.data {
            return Some(code);
        }
    }
    None
}

fn summarize_code(
    handler_method: &str,
    handler_descriptor: &str,
    code: &CodeData<'_>,
    target_slash: &BTreeSet<String>,
    mixin_targets: &[String],
) -> (HandlerBodySummary, Vec<MixinCall>) {
    let mut instruction_count = 0u32;
    let mut branch_count = 0u32;
    let mut return_count = 0u32;
    let mut uses_reflection = false;
    let mut modifies_return_value = false;
    let mut throws_exception = false;
    let mut uses_callback_info = false;
    let mut calls_original_operation = false;
    let mut original_call_count = 0u32;
    let mut handler_local_store = false;
    let mut accesses_target_fields = BTreeSet::new();
    let mut calls_target_methods = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut string_literals = BTreeSet::new();

    if let Some(bytecode) = &code.bytecode {
        for (_offset, opcode) in &bytecode.opcodes {
            instruction_count = instruction_count.saturating_add(1);
            if is_branch_opcode(opcode) {
                branch_count = branch_count.saturating_add(1);
            }
            if is_return_opcode(opcode) {
                return_count = return_count.saturating_add(1);
            }
            if is_typed_return_opcode(opcode) {
                modifies_return_value = true;
            }
            if matches!(opcode, Opcode::Athrow) {
                throws_exception = true;
            }
            if is_local_store_opcode(opcode) {
                handler_local_store = true;
            }
            if let Some(member) = opcode_member_ref(opcode) {
                if is_operation_call(&member) {
                    calls_original_operation = true;
                    original_call_count = original_call_count.saturating_add(1);
                }
                if is_reflective_member(&member) {
                    uses_reflection = true;
                }
                if is_callback_member(&member) {
                    uses_callback_info = true;
                }
                let owner = member.class_name.as_ref();
                if target_slash.contains(owner) {
                    let member_label = format!(
                        "{}:{}",
                        member.name_and_type.name.as_ref(),
                        member.name_and_type.descriptor.as_ref()
                    );
                    match opcode {
                        Opcode::Getfield(_) | Opcode::Putfield(_) => {
                            accesses_target_fields.insert(member_label);
                        }
                        Opcode::Invokevirtual(_)
                        | Opcode::Invokespecial(_)
                        | Opcode::Invokestatic(_)
                        | Opcode::Invokeinterface(_, _) => {
                            calls_target_methods.insert(member_label);
                        }
                        _ => {}
                    }
                }
                if let Some(call) = member_to_call(
                    target_slash,
                    mixin_targets,
                    &member,
                    call_kind_for_opcode(opcode),
                    handler_method,
                    CallProvenance::Bytecode,
                ) {
                    calls.insert(call);
                }
            }
            if let Some(loadable) = opcode_ldc_string(opcode) {
                string_literals.insert(loadable);
            }
        }
    }

    // Constant-pool strings reachable from handler code attributes (e.g. bootstrap).
    for item in code_attributes_pool_strings(code) {
        string_literals.insert(item);
    }

    if !uses_reflection && reflection_machinery_present(&calls) {
        // String literals + reflective machinery in the same handler are tracked
        // separately; calls already captured the structural invokes.
        uses_reflection = calls.iter().any(|c| c.provenance == CallProvenance::Reflective);
    }

    let summary = HandlerBodySummary {
        handler_method: handler_method.to_string(),
        handler_descriptor: handler_descriptor.to_string(),
        instruction_count,
        branch_count,
        return_count,
        exception_handlers: u32::from(code.exception_table.len() as u16),
        uses_reflection,
        string_literals: string_literals.into_iter().collect(),
        modifies_return_value,
        throws_exception,
        accesses_target_fields: accesses_target_fields.into_iter().collect(),
        calls_target_methods: calls_target_methods.into_iter().collect(),
        uses_callback_info,
        calls_original_operation,
        original_call_count,
        handler_local_store,
        dataflow: None,
    };
    (summary, calls.into_iter().collect())
}

fn call_kind_for_opcode(opcode: &Opcode<'_>) -> CallKind {
    match opcode {
        Opcode::Getfield(_) | Opcode::Getstatic(_) | Opcode::Putfield(_) | Opcode::Putstatic(_) => {
            CallKind::FieldAccess
        }
        _ => CallKind::MethodInvocation,
    }
}

fn is_typed_return_opcode(opcode: &Opcode<'_>) -> bool {
    matches!(
        opcode,
        Opcode::Ireturn
            | Opcode::Lreturn
            | Opcode::Freturn
            | Opcode::Dreturn
            | Opcode::Areturn
    )
}

fn is_local_store_opcode(opcode: &Opcode<'_>) -> bool {
    matches!(
        opcode,
        Opcode::Istore(_)
            | Opcode::Lstore(_)
            | Opcode::Fstore(_)
            | Opcode::Dstore(_)
            | Opcode::Astore(_)
    )
}

fn is_callback_member(member: &MemberRef<'_>) -> bool {
    let owner = member.class_name.as_ref();
    let name = member.name_and_type.name.as_ref();
    owner == CALLBACK_INFO_CLASS
        || owner == CALLBACK_INFO_RETURNABLE
        || CALLBACK_INFO_METHODS
            .iter()
            .any(|(c, m)| *c == owner && *m == name)
}

/// True for an invocation of the MixinExtras `Operation.call(...)` original — a
/// `@WrapOperation` handler that calls this *delegates to* the wrapped operation
/// (composable, low risk) instead of fully replacing it.
fn is_operation_call(member: &MemberRef<'_>) -> bool {
    member.class_name.as_ref() == "com/llamalad7/mixinextras/injector/wrap/Operation"
        && member.name_and_type.name.as_ref() == "call"
}

fn opcode_member_ref<'a>(opcode: &Opcode<'a>) -> Option<MemberRef<'a>> {
    match opcode {
        Opcode::Invokevirtual(m)
        | Opcode::Invokespecial(m)
        | Opcode::Invokestatic(m)
        | Opcode::Invokeinterface(m, _) => Some(m.clone()),
        Opcode::Getfield(m) | Opcode::Getstatic(m) | Opcode::Putfield(m) | Opcode::Putstatic(m) => {
            Some(m.clone())
        }
        _ => None,
    }
}

fn opcode_ldc_string(opcode: &Opcode<'_>) -> Option<String> {
    use cafebabe::constant_pool::{LiteralConstant, Loadable};
    let loadable = match opcode {
        Opcode::Ldc(l) | Opcode::LdcW(l) => l,
        _ => return None,
    };
    match loadable {
        Loadable::LiteralConstant(LiteralConstant::String(s)) => Some(s.as_ref().to_string()),
        Loadable::LiteralConstant(LiteralConstant::StringBytes(b)) => {
            Some(String::from_utf8_lossy(b).into_owned())
        }
        _ => None,
    }
}

fn is_branch_opcode(opcode: &Opcode<'_>) -> bool {
    matches!(
        opcode,
        Opcode::Ifeq(_)
            | Opcode::Ifne(_)
            | Opcode::Iflt(_)
            | Opcode::Ifge(_)
            | Opcode::Ifgt(_)
            | Opcode::Ifle(_)
            | Opcode::IfIcmpeq(_)
            | Opcode::IfIcmpne(_)
            | Opcode::IfIcmplt(_)
            | Opcode::IfIcmpge(_)
            | Opcode::IfIcmpgt(_)
            | Opcode::IfIcmple(_)
            | Opcode::IfAcmpne(_)
            | Opcode::IfAcmpeq(_)
            | Opcode::Ifnull(_)
            | Opcode::Ifnonnull(_)
            | Opcode::Goto(_)
            | Opcode::Tableswitch(_)
            | Opcode::Lookupswitch(_)
    )
}

fn is_return_opcode(opcode: &Opcode<'_>) -> bool {
    matches!(
        opcode,
        Opcode::Return
            | Opcode::Ireturn
            | Opcode::Lreturn
            | Opcode::Freturn
            | Opcode::Dreturn
            | Opcode::Areturn
    )
}

fn is_reflective_member(member: &MemberRef<'_>) -> bool {
    let owner = member.class_name.as_ref();
    let name = member.name_and_type.name.as_ref();
    REFLECTIVE_CLASSES.contains(&owner)
        || REFLECTIVE_METHODS
            .iter()
            .any(|(c, m)| *c == owner && *m == name)
}

fn reflection_machinery_present(calls: &BTreeSet<MixinCall>) -> bool {
    calls.iter().any(|c| c.provenance == CallProvenance::Reflective)
}

fn code_attributes_pool_strings(code: &CodeData<'_>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for attr in &code.attributes {
        let AttributeData::RuntimeVisibleAnnotations(anns) = &attr.data else {
            continue;
        };
        for ann in anns {
            for el in &ann.elements {
                if let cafebabe::attributes::AnnotationElementValue::StringConstant(s) = &el.value {
                    out.insert(s.as_ref().to_string());
                }
            }
        }
    }
    out.into_iter().collect()
}

fn member_to_call(
    target_slash: &BTreeSet<String>,
    targets: &[String],
    member: &MemberRef<'_>,
    kind: CallKind,
    handler_method: &str,
    provenance: CallProvenance,
) -> Option<MixinCall> {
    let owner = member.class_name.as_ref();
    let provenance = if is_reflective_member(member) {
        CallProvenance::Reflective
    } else {
        provenance
    };

    let target = if target_slash.contains(owner) {
        targets
            .iter()
            .find(|t| t.replace('.', "/") == owner)
            .cloned()
            .unwrap_or_else(|| descriptor_to_dotted(owner))
    } else {
        // Non-target calls are only retained when they are reflective — the
        // dynamic-dispatch path the user asked us to surface beyond constant pool.
        if provenance != CallProvenance::Reflective {
            return None;
        }
        descriptor_to_dotted(owner)
    };

    Some(MixinCall {
        target,
        owner_class: descriptor_to_dotted(owner),
        member_name: member.name_and_type.name.to_string(),
        descriptor: member.name_and_type.descriptor.to_string(),
        kind,
        provenance,
        handler_method: Some(handler_method.to_string()),
    })
}

/// Extract constant-pool calls into mixin targets (structural, whole-class scan).
pub fn extract_constant_pool_calls(
    bytes: &[u8],
    targets: &[String],
    target_owner_slash: &BTreeSet<String>,
) -> Vec<MixinCall> {
    if targets.is_empty() || target_owner_slash.is_empty() {
        return Vec::new();
    }
    let target_slash = target_owner_slash;
    let mut opts = ParseOptions::default();
    opts.parse_bytecode(false);
    let Ok(class) = parse_class_with_options(bytes, &opts) else {
        return Vec::new();
    };

    let mut out = BTreeSet::new();
    for item in class.constantpool_iter() {
        match item {
            ConstantPoolItem::MethodRef(member) | ConstantPoolItem::InterfaceMethodRef(member) => {
                if let Some(call) =
                    pool_member_to_call(target_slash, targets, &member, CallKind::MethodInvocation)
                {
                    out.insert(call);
                }
            }
            ConstantPoolItem::FieldRef(member) => {
                if let Some(call) =
                    pool_member_to_call(target_slash, targets, &member, CallKind::FieldAccess)
                {
                    out.insert(call);
                }
            }
            _ => {}
        }
    }
    out.into_iter().collect()
}

fn pool_member_to_call(
    target_slash: &BTreeSet<String>,
    targets: &[String],
    member: &MemberRef<'_>,
    kind: CallKind,
) -> Option<MixinCall> {
    let owner = member.class_name.as_ref();
    if !target_slash.contains(owner) {
        return None;
    }
    let target = targets
        .iter()
        .find(|t| t.replace('.', "/") == owner)
        .cloned()
        .unwrap_or_else(|| descriptor_to_dotted(owner));
    let provenance = if is_reflective_member(member) {
        CallProvenance::Reflective
    } else {
        CallProvenance::ConstantPool
    };
    Some(MixinCall {
        target,
        owner_class: descriptor_to_dotted(owner),
        member_name: member.name_and_type.name.to_string(),
        descriptor: member.name_and_type.descriptor.to_string(),
        kind,
        provenance,
        handler_method: None,
    })
}

/// Scan class constant pool for string literals (reflective corroboration).
pub fn extract_string_constants(bytes: &[u8]) -> BTreeSet<String> {
    let mut opts = ParseOptions::default();
    opts.parse_bytecode(false);
    let Ok(class) = parse_class_with_options(bytes, &opts) else {
        return BTreeSet::new();
    };
    let mut out = BTreeSet::new();
    for item in class.constantpool_iter() {
        if let ConstantPoolItem::LiteralConstant(LiteralConstant::String(value)) = item {
            out.insert(value.into_owned());
        } else if let ConstantPoolItem::LiteralConstant(LiteralConstant::StringBytes(bytes)) = item {
            out.insert(String::from_utf8_lossy(bytes).into_owned());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use crate::fixtures;
    use crate::refmap::TinyMappings;

    #[test]
    fn handler_bytecode_detects_target_access_and_callback() {
        let bytes = fixtures::mixin_class_with_handler_bytecode(
            "example/mixin/TickMixin",
            "net/minecraft/server/MinecraftServer",
        );
        let mut handlers = BTreeSet::new();
        handlers.insert("handler".to_string());
        let targets = vec!["net.minecraft.server.MinecraftServer".to_string()];
        let owners: BTreeSet<String> = targets.iter().map(|t| t.replace('.', "/")).collect();
        let (summaries, calls) = analyze_handler_bodies(&bytes, &handlers, &targets, &owners);
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert!(summary.handler_local_store);
        assert!(summary.modifies_return_value);
        assert!(summary.uses_callback_info);
        assert!(!summary.throws_exception);
        assert!(summary
            .accesses_target_fields
            .iter()
            .any(|f| f.contains("tickCount")));
        assert!(summary.return_count >= 1);
        assert!(!calls.is_empty() || !summary.accesses_target_fields.is_empty());
    }

    #[test]
    fn intermediary_owner_matches_named_mixin_target() {
        let bytes = fixtures::mixin_class_with_handler_bytecode(
            "example/mixin/TickMixin",
            "net/minecraft/class_3215",
        );
        let mut handlers = BTreeSet::new();
        handlers.insert("handler".to_string());
        let targets = vec!["net.minecraft.server.MinecraftServer".to_string()];
        let tiny = TinyMappings::parse(
            "tiny\t2\t0\tintermediary\tnamed\n\
             c\tnet/minecraft/class_3215\tnet/minecraft/server/MinecraftServer\n",
        )
        .unwrap();
        let owners = tiny.expand_target_owner_slash(&targets);
        let (summaries, _) = analyze_handler_bodies(&bytes, &handlers, &targets, &owners);
        let summary = &summaries[0];
        assert!(
            summary.uses_callback_info || !summary.accesses_target_fields.is_empty(),
            "intermediary bytecode owner must match via Tiny-expanded target set"
        );
    }

    #[test]
    fn dataflow_proves_unconditional_cancel() {
        let bytes = fixtures::mixin_class_with_handler_bytecode(
            "example/mixin/TickMixin",
            "net/minecraft/server/MinecraftServer",
        );
        let mut handlers = BTreeSet::new();
        handlers.insert("handler".to_string());
        let targets = vec!["net.minecraft.server.MinecraftServer".to_string()];
        let owners: BTreeSet<String> = targets.iter().map(|t| t.replace('.', "/")).collect();
        let (summaries, _) = analyze_handler_bodies(&bytes, &handlers, &targets, &owners);
        let df = summaries[0].dataflow.as_ref().expect("dataflow computed");
        assert!(df.cancels, "handler calls CallbackInfo.cancel()");
        assert!(!df.conditional_control, "no branch precedes the cancel");
        assert!(!df.sets_return_value);
    }

    #[test]
    fn dataflow_proves_constant_return_and_target_write() {
        let bytes = fixtures::mixin_class_with_returning_handler(
            "example/mixin/ReturnMixin",
            "net/minecraft/server/MinecraftServer",
        );
        let mut handlers = BTreeSet::new();
        handlers.insert("handler".to_string());
        let targets = vec!["net.minecraft.server.MinecraftServer".to_string()];
        let owners: BTreeSet<String> = targets.iter().map(|t| t.replace('.', "/")).collect();
        let (summaries, _) = analyze_handler_bodies(&bytes, &handlers, &targets, &owners);
        let df = summaries[0].dataflow.as_ref().expect("dataflow computed");
        assert!(df.sets_return_value);
        assert!(!df.conditional_control);
        assert_eq!(df.return_value_source, crate::model::ValueSource::Constant);
        assert_eq!(df.target_field_writes.len(), 1);
        assert_eq!(df.target_field_writes[0].field, "tickCount");
        assert_eq!(
            df.target_field_writes[0].source,
            crate::model::ValueSource::Constant
        );
    }

    #[test]
    fn handler_bytecode_detects_athrow() {
        let bytes = fixtures::mixin_class_with_throwing_handler(
            "example/mixin/ThrowMixin",
            "net/minecraft/server/MinecraftServer",
        );
        let mut handlers = BTreeSet::new();
        handlers.insert("handler".to_string());
        let targets = vec!["net.minecraft.server.MinecraftServer".to_string()];
        let owners: BTreeSet<String> = targets.iter().map(|t| t.replace('.', "/")).collect();
        let (summaries, _) = analyze_handler_bodies(&bytes, &handlers, &targets, &owners);
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].throws_exception);
    }
}