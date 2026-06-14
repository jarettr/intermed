//! Structural mixin class parsing via cafebabe.
//!
//! Extracts targets, operation annotations, `@Shadow` members, added members,
//! deep injection sites (`@At`, locals), handler bytecode, and call edges —
//! the inputs for interaction analysis.

use std::collections::BTreeSet;

use cafebabe::attributes::{Annotation, AttributeInfo};
use cafebabe::descriptors::FieldType;
use cafebabe::{parse_class_with_options, ParseOptions};

use crate::annotation::{
    collect_class_literals, collect_string_values, has_annotation, is_annotation_type,
    runtime_annotations,
};
use crate::bytecode::{analyze_handler_bodies, extract_constant_pool_calls};
use crate::hierarchy::HierarchyIndex;
use crate::injection_point::{
    parse_at_descriptors, parse_injector_meta, parse_local_captures, parse_parameter_locals,
    resolve_injection_sites, AtDescriptor, LocalCaptureDescriptor, ParamLocalDescriptor,
};
use crate::model::{
    HandlerBodySummary, MemberKind, MixinAddedMember, MixinCall, MixinHierarchyEdge,
    MixinOperation, MixinShadowMember, ResolvedInjectionPoint,
};
use crate::refmap::{MappingContext, TinyMappings};

const MIXIN_ANNOTATION: &str = "org/spongepowered/asm/mixin/Mixin";
const SHADOW_ANNOTATION: &str = "org/spongepowered/asm/mixin/Shadow";
const OVERWRITE_ANNOTATION: &str = "org/spongepowered/asm/mixin/Overwrite";
const ACCESSOR_ANNOTATION: &str = "org/spongepowered/asm/mixin/gen/Accessor";
const INVOKER_ANNOTATION: &str = "org/spongepowered/asm/mixin/gen/Invoker";
const UNIQUE_ANNOTATION: &str = "org/spongepowered/asm/mixin/Unique";

/// Raw parse output before refmap resolution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClassParseResult {
    pub targets: Vec<String>,
    pub operations: BTreeSet<MixinOperation>,
    pub raw_injections: Vec<RawInjection>,
    pub shadows: Vec<MixinShadowMember>,
    pub added_members: Vec<MixinAddedMember>,
    pub calls: Vec<MixinCall>,
    pub handler_bodies: Vec<HandlerBodySummary>,
    pub target_hierarchy: Vec<MixinHierarchyEdge>,
    /// Overwrite handler signatures (`name` + JVM descriptor, e.g. `m0()V`).
    pub overwrite_methods: Vec<String>,
    pub handler_methods: BTreeSet<String>,
}

/// One unresolved injection annotation on a handler method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawInjection {
    pub handler_method: String,
    pub handler_descriptor: String,
    pub operation: MixinOperation,
    pub methods: Vec<String>,
    pub at_sites: Vec<AtDescriptor>,
    pub locals: Vec<LocalCaptureDescriptor>,
    pub param_locals: Vec<ParamLocalDescriptor>,
    pub meta: crate::model::InjectorMeta,
}

/// Parse mixin class bytes into structural evidence (no jar hierarchy context).
pub fn parse_mixin_class(bytes: &[u8]) -> ClassParseResult {
    parse_mixin_class_with_hierarchy(bytes, &HierarchyIndex::new(), None)
}

/// Parse mixin class bytes and attach hierarchy edges for known targets.
pub fn parse_mixin_class_with_hierarchy(
    bytes: &[u8],
    hierarchy: &HierarchyIndex,
    tiny: Option<&TinyMappings>,
) -> ClassParseResult {
    let mut opts = ParseOptions::default();
    opts.parse_bytecode(true);
    let Ok(class) = parse_class_with_options(bytes, &opts) else {
        let mut ops = BTreeSet::new();
        ops.insert(MixinOperation::Unknown);
        return ClassParseResult {
            operations: ops,
            ..Default::default()
        };
    };

    let mut targets = BTreeSet::new();
    collect_mixin_targets(&class.attributes, &mut targets);

    let mut operations = BTreeSet::new();
    let mut raw_injections = Vec::new();
    let mut shadows = Vec::new();
    let mut added_members = Vec::new();
    let mut overwrite_methods = Vec::new();
    let mut handler_methods = BTreeSet::new();

    for field in &class.fields {
        collect_mixin_targets(&field.attributes, &mut targets);
        if let Some(shadow) = shadow_from_member(
            &targets,
            field.name.as_ref(),
            &field.descriptor.to_string(),
            MemberKind::Field,
            &field.attributes,
        ) {
            shadows.push(shadow);
        } else if is_added_field(&field.attributes) {
            for target in &targets {
                added_members.push(MixinAddedMember {
                    target: target.clone(),
                    name: field.name.as_ref().to_string(),
                    descriptor: field.descriptor.to_string(),
                    kind: MemberKind::Field,
                    origin: added_origin(&field.attributes),
                    unique: has_annotation(&field.attributes, UNIQUE_ANNOTATION),
                });
            }
        }
    }

    for method in &class.methods {
        collect_mixin_targets(&method.attributes, &mut targets);
        collect_mixin_operations(&method.attributes, &mut operations);
        for raw in collect_raw_injections(
            method.name.as_ref(),
            &method.descriptor,
            &method.attributes,
        ) {
            handler_methods.insert(raw.handler_method.clone());
            raw_injections.push(raw);
        }

        if let Some(shadow) = shadow_from_member(
            &targets,
            method.name.as_ref(),
            &method.descriptor.to_string(),
            MemberKind::Method,
            &method.attributes,
        ) {
            shadows.push(shadow);
        } else if operations_from_attrs(&method.attributes).contains(&MixinOperation::Overwrite) {
            overwrite_methods.push(format!(
                "{}{}",
                method.name.as_ref(),
                method.descriptor
            ));
            handler_methods.insert(method.name.as_ref().to_string());
        } else if is_added_method(&method.attributes, method.name.as_ref()) {
            for target in &targets {
                added_members.push(MixinAddedMember {
                    target: target.clone(),
                    name: method.name.as_ref().to_string(),
                    descriptor: method.descriptor.to_string(),
                    kind: MemberKind::Method,
                    origin: added_origin(&method.attributes),
                    unique: has_annotation(&method.attributes, UNIQUE_ANNOTATION),
                });
            }
        }
    }

    if operations.is_empty() {
        operations.insert(MixinOperation::Unknown);
    }

    let target_vec: Vec<String> = targets.into_iter().collect();
    let target_owner_slash = build_target_owner_slash(&target_vec, tiny);
    let mut hierarchy_edges = Vec::new();
    for target in &target_vec {
        hierarchy_edges.extend(hierarchy.edges_for_target(target));
    }

    let pool_calls = extract_constant_pool_calls(bytes, &target_vec, &target_owner_slash);
    let (handler_bodies, body_calls) =
        analyze_handler_bodies(bytes, &handler_methods, &target_vec, &target_owner_slash);
    let calls = merge_calls(pool_calls, body_calls);

    ClassParseResult {
        targets: target_vec,
        operations,
        raw_injections,
        shadows,
        added_members,
        calls,
        handler_bodies,
        target_hierarchy: hierarchy_edges,
        overwrite_methods,
        handler_methods,
    }
}

/// Apply refmap / mapping resolution to raw parse output.
pub fn resolve_parse(
    parse: &ClassParseResult,
    mapping: &mut MappingContext,
) -> Vec<ResolvedInjectionPoint> {
    let mut out = BTreeSet::new();
    for target in &parse.targets {
        for inj in &parse.raw_injections {
            let methods: Vec<String> = if inj.methods.is_empty() {
                vec![String::new()]
            } else {
                inj.methods.clone()
            };
            let sites = resolve_injection_sites(
                target,
                &inj.handler_method,
                &inj.handler_descriptor,
                &inj.operation,
                &methods,
                &inj.at_sites,
                &inj.locals,
                &inj.param_locals,
                &inj.meta,
                mapping,
            );
            for site in sites {
                out.insert(resolved_from_site(site));
            }
        }
        for method_key in &parse.overwrite_methods {
            let (handler_name, handler_desc) = split_method_signature(method_key);
            let sites = resolve_injection_sites(
                target,
                handler_name,
                handler_desc,
                &MixinOperation::Overwrite,
                std::slice::from_ref(method_key),
                &[],
                &[],
                &[],
                &crate::model::InjectorMeta::default(),
                mapping,
            );
            for site in sites {
                out.insert(resolved_from_site(site));
            }
        }
    }
    out.into_iter().collect()
}

/// Split a JVM method token `name(desc)` into (`name`, `desc`).
fn split_method_signature(method: &str) -> (&str, &str) {
    if let Some(ix) = method.find('(') {
        (&method[..ix], &method[ix..])
    } else {
        (method, "")
    }
}

fn resolved_from_site(site: crate::injection_point::ResolvedInjectionSite) -> ResolvedInjectionPoint {
    let local_index = site
        .param_locals
        .iter()
        .find_map(|p| p.index.or(p.ordinal))
        .or_else(|| site.locals.iter().find_map(|l| l.local_index))
        .or(site.at.by);
    // A target-frame *write* comes from `@ModifyVariable` or a writable
    // MixinExtras `@Local` ref param — not from a read-only `@Local` capture.
    let mutates_target_local = site.operation == MixinOperation::ModifyVariable
        || site.param_locals.iter().any(|p| p.writable);
    // Surface the strongest capture mode declared (fail-hard outranks the rest).
    let local_capture = site
        .locals
        .iter()
        .map(|l| l.capture_mode)
        .filter(|m| m.captures_locals())
        .max_by_key(|m| m.is_fail_hard() as u8)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    let at_detail = site.at.display();
    let at_target = site.at.value;
    ResolvedInjectionPoint {
        target: site.target,
        original: site.original_method,
        resolved: site.resolved_method,
        canonical: site.canonical_method,
        site_key: site.site_key,
        namespace: site.namespace,
        injection_type: site.operation.as_str().to_string(),
        resolved_via_refmap: site.resolved_via_refmap,
        handler_method: site.handler_method,
        handler_descriptor: site.handler_descriptor,
        mutates_target_local,
        at_target,
        at_detail,
        impact: site.impact,
        local_index,
        local_capture,
        at_ordinal: site.at.ordinal,
        at_target_member: site.at.target.clone(),
        meta: site.meta,
    }
}

/// Build the slash-owner set used for bytecode target matching. When Tiny
/// mappings are present, named `@Mixin` targets are expanded to their
/// intermediary JVM owners so handler analysis works on real compiled jars.
fn build_target_owner_slash(targets: &[String], tiny: Option<&TinyMappings>) -> BTreeSet<String> {
    if let Some(map) = tiny {
        return map.expand_target_owner_slash(targets);
    }
    targets.iter().map(|t| t.replace('.', "/")).collect()
}

fn merge_calls(pool: Vec<MixinCall>, body: Vec<MixinCall>) -> Vec<MixinCall> {
    let mut out = BTreeSet::new();
    for call in pool {
        out.insert(call);
    }
    for call in body {
        out.insert(call);
    }
    out.into_iter().collect()
}

fn shadow_from_member(
    targets: &BTreeSet<String>,
    name: &str,
    descriptor: &str,
    kind: MemberKind,
    attributes: &[AttributeInfo<'_>],
) -> Option<MixinShadowMember> {
    if !has_annotation(attributes, SHADOW_ANNOTATION) {
        return None;
    }
    let target = targets.iter().next()?.clone();
    Some(MixinShadowMember {
        target,
        name: name.to_string(),
        descriptor: descriptor.to_string(),
        kind,
    })
}

fn is_added_field(attributes: &[AttributeInfo<'_>]) -> bool {
    !has_annotation(attributes, SHADOW_ANNOTATION)
        && (has_annotation(attributes, ACCESSOR_ANNOTATION)
            || !has_any_mixin_annotation(attributes))
}

fn is_added_method(attributes: &[AttributeInfo<'_>], name: &str) -> bool {
    if name == "<init>" || name == "<clinit>" {
        return false;
    }
    if has_annotation(attributes, SHADOW_ANNOTATION) {
        return false;
    }
    if operations_from_attrs(attributes)
        .iter()
        .any(|op| !matches!(op, MixinOperation::Shadow | MixinOperation::Unknown))
    {
        return false;
    }
    has_annotation(attributes, ACCESSOR_ANNOTATION)
        || has_annotation(attributes, INVOKER_ANNOTATION)
}

fn added_origin(attributes: &[AttributeInfo<'_>]) -> String {
    if has_annotation(attributes, ACCESSOR_ANNOTATION) {
        "accessor".to_string()
    } else if has_annotation(attributes, INVOKER_ANNOTATION) {
        "invoker".to_string()
    } else {
        "added".to_string()
    }
}

fn has_any_mixin_annotation(attributes: &[AttributeInfo<'_>]) -> bool {
    runtime_annotations(attributes).into_iter().any(|annotation| {
        operation_from_annotation(annotation).is_some()
            || is_annotation_type(annotation, SHADOW_ANNOTATION)
            || is_annotation_type(annotation, ACCESSOR_ANNOTATION)
            || is_annotation_type(annotation, INVOKER_ANNOTATION)
    })
}

/// Collect *every* injector annotation on a handler method.
///
/// A single method can legitimately carry more than one injector (e.g. an
/// `@Inject` plus a `@ModifyVariable`, or two `@At` injectors expressed as
/// separate annotations). Returning only the first lost the rest, so advanced
/// mixin handlers were under-reported. We now emit one [`RawInjection`] per
/// injector annotation and let the caller flatten them.
fn collect_raw_injections(
    handler_method: &str,
    descriptor: &cafebabe::descriptors::MethodDescriptor<'_>,
    attributes: &[AttributeInfo<'_>],
) -> Vec<RawInjection> {
    let handler_descriptor = descriptor.to_string();
    let mut out = Vec::new();
    for annotation in runtime_annotations(attributes) {
        let Some(op) = operation_from_annotation(annotation) else {
            continue;
        };
        if matches!(
            op,
            MixinOperation::Shadow
                | MixinOperation::Accessor
                | MixinOperation::Invoker
                | MixinOperation::Overwrite
                | MixinOperation::Unique
                | MixinOperation::Definition
                | MixinOperation::Expression
                | MixinOperation::Share
                | MixinOperation::Unknown
        ) {
            continue;
        }
        let mut methods = BTreeSet::new();
        for element in &annotation.elements {
            if element.name.as_ref() == "method" {
                collect_string_values(&element.value, &mut methods);
            }
        }
        let method_targets: Vec<String> = if methods.is_empty() {
            vec![format!("{handler_method}{handler_descriptor}")]
        } else {
            methods.into_iter().collect()
        };
        out.push(RawInjection {
            handler_method: handler_method.to_string(),
            handler_descriptor: handler_descriptor.clone(),
            operation: op,
            methods: method_targets,
            at_sites: parse_at_descriptors(annotation),
            locals: parse_local_captures(annotation),
            // MixinExtras `@Local` target-local captures live on the handler's
            // *parameter* annotations, not the injector annotation.
            param_locals: parse_parameter_locals(attributes, descriptor),
            meta: parse_injector_meta(annotation),
        });
    }
    out
}

fn operations_from_attrs(attributes: &[AttributeInfo<'_>]) -> BTreeSet<MixinOperation> {
    let mut out = BTreeSet::new();
    collect_mixin_operations(attributes, &mut out);
    out
}

fn collect_mixin_targets(attributes: &[AttributeInfo<'_>], out: &mut BTreeSet<String>) {
    for annotation in runtime_annotations(attributes) {
        if !is_mixin_annotation(annotation) {
            continue;
        }
        for element in &annotation.elements {
            match element.name.as_ref() {
                "value" | "targets" => collect_class_literals(&element.value, out),
                _ => {}
            }
        }
    }
}

fn collect_mixin_operations(attributes: &[AttributeInfo<'_>], out: &mut BTreeSet<MixinOperation>) {
    for annotation in runtime_annotations(attributes) {
        if let Some(op) = operation_from_annotation(annotation) {
            out.insert(op);
        }
    }
}

fn is_mixin_annotation(annotation: &Annotation<'_>) -> bool {
    is_annotation_type(annotation, MIXIN_ANNOTATION)
}

fn operation_from_annotation(annotation: &Annotation<'_>) -> Option<MixinOperation> {
    let FieldType::Object(class) = &annotation.type_descriptor.field_type else {
        return None;
    };
    let name: &str = class;
    if name.starts_with("org/spongepowered/asm/mixin/injection/") {
        match name.rsplit('/').next()? {
            "Inject" => Some(MixinOperation::Inject),
            "Redirect" => Some(MixinOperation::Redirect),
            "ModifyArg" => Some(MixinOperation::ModifyArg),
            "ModifyArgs" => Some(MixinOperation::ModifyArgs),
            "ModifyVariable" => Some(MixinOperation::ModifyVariable),
            "ModifyConstant" => Some(MixinOperation::ModifyConstant),
            _ => None,
        }
    } else if name == OVERWRITE_ANNOTATION {
        Some(MixinOperation::Overwrite)
    } else if name == SHADOW_ANNOTATION {
        Some(MixinOperation::Shadow)
    } else if name == ACCESSOR_ANNOTATION {
        Some(MixinOperation::Accessor)
    } else if name == INVOKER_ANNOTATION {
        Some(MixinOperation::Invoker)
    } else if name == UNIQUE_ANNOTATION {
        Some(MixinOperation::Unique)
    } else if name.starts_with("com/llamalad7/mixinextras/") {
        match name.rsplit('/').next()? {
            "WrapOperation" => Some(MixinOperation::WrapOperation),
            "WrapWithCondition" => Some(MixinOperation::WrapWithCondition),
            "ModifyExpressionValue" => Some(MixinOperation::ModifyExpressionValue),
            "ModifyReturnValue" => Some(MixinOperation::ModifyReturnValue),
            "ModifyReceiver" => Some(MixinOperation::ModifyReceiver),
            // MixinExtras expression matching: `@Definition` binds a symbol and
            // `@Expression` matches an AST pattern. They scope the operation they
            // accompany; tracked for coverage / fragility, not as injection sites.
            "Definition" => Some(MixinOperation::Definition),
            "Expression" => Some(MixinOperation::Expression),
            // `@Share` threads a shared local between handlers (sugar parameter).
            "Share" => Some(MixinOperation::Share),
            _ => None,
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use crate::model::CallProvenance;

    #[test]
    fn parses_shadow_field() {
        let bytes = fixtures::mixin_class_with_shadow(
            "example/mixin/ShadowMixin",
            "net/minecraft/world/entity/Entity",
            "field_1234",
            "I",
        );
        let parsed = parse_mixin_class(&bytes);
        assert_eq!(parsed.shadows.len(), 1);
        assert_eq!(parsed.shadows[0].name, "field_1234");
    }

    #[test]
    fn bare_inject_infers_handler_method_signature() {
        let bytes = fixtures::mixin_class(
            "example/mixin/RenderMixin",
            "net/minecraft/client/render/WorldRenderer",
            &["injection/Inject"],
        );
        let parsed = parse_mixin_class(&bytes);
        assert_eq!(parsed.raw_injections.len(), 1);
        assert_eq!(parsed.raw_injections[0].methods, vec!["m0()V"]);
    }

    #[test]
    fn parses_inject_method_target() {
        let bytes = fixtures::mixin_class_with_inject_method(
            "example/mixin/TickMixin",
            "net/minecraft/server/MinecraftServer",
            "tick()V",
        );
        let parsed = parse_mixin_class(&bytes);
        assert_eq!(parsed.raw_injections.len(), 1);
        assert_eq!(parsed.raw_injections[0].methods, vec!["tick()V"]);
        assert_eq!(parsed.raw_injections[0].at_sites[0].value, "HEAD");
    }

    #[test]
    fn reads_invisible_mixin_annotations() {
        // Real SpongePowered mods retain @Mixin/@Inject as CLASS (invisible).
        // The target and injection must still be extracted — regression for the
        // bug where only RuntimeVisibleAnnotations were read (targets came back
        // empty on every production jar).
        let bytes = fixtures::mixin_class_invisible_annotations(
            "example/mixin/TickMixin",
            "net/minecraft/server/MinecraftServer",
            "tick()V",
        );
        let parsed = parse_mixin_class(&bytes);
        assert_eq!(
            parsed.targets,
            vec!["net.minecraft.server.MinecraftServer".to_string()],
            "class @Mixin target must be read from invisible annotations"
        );
        assert_eq!(parsed.raw_injections.len(), 1);
        assert_eq!(parsed.raw_injections[0].methods, vec!["tick()V"]);
    }

    #[test]
    fn parses_inject_with_explicit_at_return() {
        let bytes = fixtures::mixin_class_with_inject_at(
            "example/mixin/ReturnMixin",
            "net/minecraft/server/MinecraftServer",
            "tick()V",
            "RETURN",
        );
        let parsed = parse_mixin_class(&bytes);
        assert_eq!(parsed.raw_injections[0].at_sites[0].value, "RETURN");
    }

    #[test]
    fn constant_pool_calls_default_provenance() {
        let bytes = fixtures::mixin_class_with_target_method_ref(
            "example/mixin/CallMixin",
            "net/minecraft/world/entity/Entity",
            "getId",
            "()I",
        );
        let parsed = parse_mixin_class(&bytes);
        assert!(!parsed.calls.is_empty());
        assert_eq!(parsed.calls[0].provenance, CallProvenance::ConstantPool);
    }
}