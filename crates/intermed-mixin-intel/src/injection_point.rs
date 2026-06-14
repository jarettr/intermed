//! Deep mixin injection-point resolution.
//!
//! SpongePowered mixins declare *where* bytecode is woven via nested `@At`
//! annotations and optional `@LocalCapture` metadata. This module turns those
//! annotation trees into stable [`InjectionSiteKey`] values so the analyzer can
//! distinguish `HEAD` vs `RETURN` vs `INVOKE` collisions — not just the target
//! method name from `method = "…"`.

use cafebabe::attributes::{Annotation, AttributeData, AttributeInfo};
use cafebabe::descriptors::{FieldDescriptor, FieldType, MethodDescriptor};

use crate::annotation::{
    annotation_bool_element, annotation_enum_element, annotation_int_element,
    annotation_string_array, annotation_string_element, collect_nested_annotations,
    descriptor_to_dotted, is_annotation_type,
};
use crate::model::MixinOperation;
use crate::refmap::{MappingContext, Namespace};

/// MixinExtras `@Local` — captures a single target-frame local as a handler param.
const MIXINEXTRAS_LOCAL_ANNOTATION: &str = "com/llamalad7/mixinextras/sugar/Local";

/// A MixinExtras `@Local`-captured target local, parsed from the handler's
/// *parameter* annotations (not the method-level annotation that `@LocalCapture`
/// uses). The capture is a *write* into the target frame when the parameter type
/// is a mutable `…Ref` (`LocalRef`, `LocalIntRef`, …); otherwise it is a read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParamLocalDescriptor {
    /// `index = N` when present.
    pub index: Option<i32>,
    /// `ordinal = N` when present.
    pub ordinal: Option<i32>,
    /// The parameter type is a MixinExtras mutable ref → the handler can *write*
    /// the captured target local, not just read it.
    pub writable: bool,
}

/// Parse MixinExtras `@Local` parameter annotations off a handler method.
///
/// Locals captured this way are parameter annotations
/// (`RuntimeVisible/InvisibleParameterAnnotations`), which the SpongePowered
/// `@LocalCapture` path never looks at — so without this a `@Local LocalRef<Integer>`
/// target-local write was invisible.
pub fn parse_parameter_locals(
    attributes: &[AttributeInfo<'_>],
    descriptor: &MethodDescriptor<'_>,
) -> Vec<ParamLocalDescriptor> {
    let mut out = Vec::new();
    for attr in attributes {
        let params = match &attr.data {
            AttributeData::RuntimeVisibleParameterAnnotations(p)
            | AttributeData::RuntimeInvisibleParameterAnnotations(p) => p,
            _ => continue,
        };
        for (i, param) in params.iter().enumerate() {
            for ann in &param.annotations {
                if !is_annotation_type(ann, MIXINEXTRAS_LOCAL_ANNOTATION) {
                    continue;
                }
                let writable = descriptor
                    .parameters
                    .get(i)
                    .is_some_and(is_mutable_ref_param);
                out.push(ParamLocalDescriptor {
                    index: annotation_int_element(ann, "index"),
                    ordinal: annotation_int_element(ann, "ordinal"),
                    writable,
                });
            }
        }
    }
    out
}

/// True when a handler parameter type is a MixinExtras mutable local ref
/// (`com/llamalad7/mixinextras/sugar/ref/LocalRef` and the primitive variants),
/// which lets the handler write back into the captured target local.
fn is_mutable_ref_param(param: &FieldDescriptor<'_>) -> bool {
    if param.dimensions != 0 {
        return false;
    }
    matches!(&param.field_type, FieldType::Object(class) if {
        let c: &str = class;
        c.starts_with("com/llamalad7/mixinextras/sugar/ref/") && c.ends_with("Ref")
    })
}

/// Parsed `@At` descriptor from a mixin handler annotation.
///
/// Every field that distinguishes one weave point from another at the *same*
/// target call must be captured, or two genuinely different injection points
/// collapse into one site key and produce a false "same injection point"
/// finding. In particular `shift` and `slice` are not strings (`shift` is an
/// enum constant, `slice` a nested `@Slice`) and were previously dropped.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AtDescriptor {
    /// `HEAD`, `RETURN`, `INVOKE`, `FIELD`, `CONSTANT`, …
    pub value: String,
    /// Opcode target for `INVOKE` / `FIELD` / `CONSTANT` injection points.
    pub target: String,
    /// `ordinal` when multiple sites match the same target pattern.
    pub ordinal: Option<i32>,
    /// Slice discriminator (the `@Slice` `id`, or a key derived from its bounds).
    pub slice: String,
    /// `shift` enum constant when present (`BEFORE`, `AFTER`, `BY`, …).
    pub shift: String,
    /// `by` offset, meaningful with `shift = BY`.
    pub by: Option<i32>,
    /// Explicit JVM `opcode` filter (e.g. for `FIELD` GETFIELD vs PUTFIELD).
    pub opcode: Option<i32>,
    /// `args` strings (injection-point-specific selectors).
    pub args: Vec<String>,
    /// `@At` `id` (named injection point used by `@Slice` references).
    pub id: String,
    /// `remap = false` opts a target out of refmap remapping.
    pub remap: Option<bool>,
}

impl AtDescriptor {
    /// Build a human-readable `@At` summary for reports.
    pub fn display(&self) -> String {
        let mut out = self.value.clone();
        if !self.target.is_empty() {
            out.push(':');
            out.push_str(&self.target);
        }
        if let Some(ord) = self.ordinal {
            out.push_str(&format!("#{ord}"));
        }
        if !self.slice.is_empty() {
            out.push('/');
            out.push_str(&self.slice);
        }
        if !self.shift.is_empty() {
            out.push('@');
            out.push_str(&self.shift);
        }
        if let Some(by) = self.by {
            out.push_str(&format!("+{by}"));
        }
        out
    }

    /// Stable comparison key fragment for this `@At` site.
    ///
    /// Includes every discriminator (shift/opcode/args/slice/id) so two
    /// injections that differ only in, say, `shift = BEFORE` vs `AFTER` produce
    /// distinct keys rather than colliding.
    pub fn key_fragment(&self) -> String {
        let mut parts = vec![self.value.clone()];
        if !self.target.is_empty() {
            parts.push(self.target.clone());
        }
        if let Some(ord) = self.ordinal {
            parts.push(format!("ord{ord}"));
        }
        if !self.slice.is_empty() {
            parts.push(format!("slice{}", self.slice));
        }
        if !self.shift.is_empty() {
            parts.push(format!("shift{}", self.shift));
        }
        if let Some(by) = self.by {
            parts.push(format!("by{by}"));
        }
        if let Some(op) = self.opcode {
            parts.push(format!("op{op}"));
        }
        for arg in &self.args {
            parts.push(format!("arg{arg}"));
        }
        if !self.id.is_empty() {
            parts.push(format!("id{}", self.id));
        }
        parts.join("|")
    }
}

/// The Sponge `LocalCapture` mode declared by `@Inject(locals = ...)`.
///
/// Determines how the injector reacts when the requested locals cannot be
/// captured. `CAPTURE_FAILHARD` throws at apply time if the local frame does not
/// match — the strictest mode and the one most likely to break across game/mod
/// updates — so it raises apply-failure risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocalCaptureMode {
    NoCapture,
    Print,
    CaptureFailsoft,
    CaptureFailhard,
    CaptureFailexception,
    #[default]
    Unknown,
}

impl LocalCaptureMode {
    pub fn from_enum_name(name: &str) -> Self {
        match name {
            "NO_CAPTURE" => LocalCaptureMode::NoCapture,
            "PRINT" => LocalCaptureMode::Print,
            "CAPTURE_FAILSOFT" => LocalCaptureMode::CaptureFailsoft,
            "CAPTURE_FAILHARD" => LocalCaptureMode::CaptureFailhard,
            "CAPTURE_FAILEXCEPTION" => LocalCaptureMode::CaptureFailexception,
            _ => LocalCaptureMode::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LocalCaptureMode::NoCapture => "NO_CAPTURE",
            LocalCaptureMode::Print => "PRINT",
            LocalCaptureMode::CaptureFailsoft => "CAPTURE_FAILSOFT",
            LocalCaptureMode::CaptureFailhard => "CAPTURE_FAILHARD",
            LocalCaptureMode::CaptureFailexception => "CAPTURE_FAILEXCEPTION",
            LocalCaptureMode::Unknown => "unknown",
        }
    }

    /// Whether this mode actually captures locals (so the handler signature must
    /// match the target frame). `NO_CAPTURE`/`PRINT` do not.
    pub fn captures_locals(self) -> bool {
        matches!(
            self,
            LocalCaptureMode::CaptureFailsoft
                | LocalCaptureMode::CaptureFailhard
                | LocalCaptureMode::CaptureFailexception
        )
    }

    /// `CAPTURE_FAILHARD` hard-fails the injection if the frame diverges, so it
    /// is the most fragile across updates.
    pub fn is_fail_hard(self) -> bool {
        matches!(self, LocalCaptureMode::CaptureFailhard)
    }
}

/// Parsed `@LocalCapture` / `@Local` metadata on an injection handler.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalCaptureDescriptor {
    /// Capture mode enum name (`CAPTURE_FAILSOFT`, `CAPTURE_FAILHARD`, …).
    pub capture_type: String,
    /// Parsed capture mode.
    pub capture_mode: LocalCaptureMode,
    /// Raw `args` strings (`index=0`, `name=foo`, …).
    pub args: Vec<String>,
    /// Parsed local index when `args` contains `index=N`.
    pub local_index: Option<i32>,
}

impl LocalCaptureDescriptor {
    /// Build from a `LocalCapture` enum constant name.
    pub fn from_capture_enum(const_name: &str) -> Self {
        Self {
            capture_type: const_name.to_string(),
            capture_mode: LocalCaptureMode::from_enum_name(const_name),
            ..Self::default()
        }
    }
}

/// One fully resolved injection site after refmap / mapping normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInjectionSite {
    pub target: String,
    pub handler_method: String,
    pub handler_descriptor: String,
    pub operation: MixinOperation,
    pub original_method: String,
    pub resolved_method: String,
    pub canonical_method: String,
    pub namespace: Namespace,
    pub resolved_via_refmap: bool,
    pub at: AtDescriptor,
    pub locals: Vec<LocalCaptureDescriptor>,
    pub param_locals: Vec<ParamLocalDescriptor>,
    pub site_key: String,
    pub impact: String,
    pub meta: crate::model::InjectorMeta,
}

/// Parse injector application metadata (`require`/`expect`/`allow`/`cancellable`/
/// `remap`/`priority`/`group`/`constraints`) from an inject-like annotation.
pub fn parse_injector_meta(annotation: &Annotation<'_>) -> crate::model::InjectorMeta {
    use crate::annotation::{
        annotation_bool_element, annotation_int_element, annotation_string_element,
    };
    crate::model::InjectorMeta {
        require: annotation_int_element(annotation, "require"),
        expect: annotation_int_element(annotation, "expect"),
        allow: annotation_int_element(annotation, "allow"),
        cancellable: annotation_bool_element(annotation, "cancellable").unwrap_or(false),
        remap: annotation_bool_element(annotation, "remap"),
        priority: annotation_int_element(annotation, "priority"),
        group: annotation_string_element(annotation, "group"),
        constraints: annotation_string_element(annotation, "constraints"),
    }
}

/// Parse all `@At` descriptors nested under an inject-like annotation.
pub fn parse_at_descriptors(annotation: &Annotation<'_>) -> Vec<AtDescriptor> {
    let mut out = Vec::new();
    // An injector may carry its own `@Slice`(s); fold that into each `@At` whose
    // own `slice` reference is empty, so the slice scope contributes to the key.
    let injector_slice = slice_key_from_injector(annotation);
    for element in &annotation.elements {
        if element.name.as_ref() != "at" {
            continue;
        }
        let mut nested = Vec::new();
        collect_nested_annotations(&element.value, &mut nested);
        for at_ann in nested {
            let mut at = parse_at_annotation(at_ann);
            if at.slice.is_empty() && !injector_slice.is_empty() {
                at.slice = injector_slice.clone();
            }
            out.push(at);
        }
    }
    if out.is_empty() {
        // Mixin defaults to `@At("HEAD")` when `at` is omitted.
        out.push(AtDescriptor {
            value: "HEAD".to_string(),
            slice: injector_slice,
            ..AtDescriptor::default()
        });
    }
    out
}

/// Parse the Sponge `@Inject(locals = LocalCapture.X)` capture mode.
///
/// `locals` is a **`LocalCapture` enum constant**, not a nested annotation:
/// `@Inject(method = "...", at = @At("HEAD"), locals = LocalCapture.CAPTURE_FAILHARD)`.
/// The old implementation looked for nested `@LocalCapture` annotations under
/// `locals`, which never matched, so the capture mode was silently dropped.
/// MixinExtras `@Local` *parameter* annotations are a separate mechanism handled
/// by [`parse_parameter_locals`].
pub fn parse_local_captures(annotation: &Annotation<'_>) -> Vec<LocalCaptureDescriptor> {
    use cafebabe::attributes::AnnotationElementValue;
    let mut out = Vec::new();
    for element in &annotation.elements {
        if element.name.as_ref() != "locals" {
            continue;
        }
        match &element.value {
            AnnotationElementValue::EnumConstant { const_name, .. } => {
                out.push(LocalCaptureDescriptor::from_capture_enum(const_name.as_ref()));
            }
            // Defensive: an array of enum constants.
            AnnotationElementValue::ArrayValue(values) => {
                for v in values {
                    if let AnnotationElementValue::EnumConstant { const_name, .. } = v {
                        out.push(LocalCaptureDescriptor::from_capture_enum(const_name.as_ref()));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn parse_at_annotation(annotation: &Annotation<'_>) -> AtDescriptor {
    let value = annotation_string_element(annotation, "value").unwrap_or_else(|| "HEAD".into());
    let target = annotation_string_element(annotation, "target")
        .map(|t| descriptor_to_dotted(&t))
        .unwrap_or_default();
    AtDescriptor {
        value,
        target,
        ordinal: annotation_int_element(annotation, "ordinal"),
        // `slice` on `@At` is a *string* reference to a named `@Slice` id; the
        // `@Slice` annotation itself lives on the injector (see `slice_key`).
        slice: annotation_string_element(annotation, "slice").unwrap_or_default(),
        // `shift` is an enum constant, not a string.
        shift: annotation_enum_element(annotation, "shift").unwrap_or_default(),
        by: annotation_int_element(annotation, "by"),
        opcode: annotation_int_element(annotation, "opcode"),
        args: annotation_string_array(annotation, "args"),
        id: annotation_string_element(annotation, "id").unwrap_or_default(),
        remap: annotation_bool_element(annotation, "remap"),
    }
}

/// Derive a stable discriminator for an injector's `@Slice` bounds.
///
/// `@Slice(id = "x", from = @At(...), to = @At(...))` narrows where an injection
/// point may match. Two handlers at the same call but in different slices are
/// different sites, so the slice must contribute to the key. We prefer the slice
/// `id`; otherwise we fold its `from`/`to` `@At`s into a key.
pub fn slice_key_from_injector(injector: &Annotation<'_>) -> String {
    let mut nested = Vec::new();
    for element in &injector.elements {
        if element.name.as_ref() == "slice" {
            collect_nested_annotations(&element.value, &mut nested);
        }
    }
    let mut keys = Vec::new();
    for slice in nested {
        if let Some(id) = annotation_string_element(slice, "id") {
            keys.push(id);
            continue;
        }
        let mut bound = Vec::new();
        for el in &slice.elements {
            if el.name.as_ref() == "from" || el.name.as_ref() == "to" {
                let mut ats = Vec::new();
                collect_nested_annotations(&el.value, &mut ats);
                for at in ats {
                    bound.push(format!(
                        "{}={}",
                        el.name.as_ref(),
                        parse_at_annotation(at).key_fragment()
                    ));
                }
            }
        }
        if !bound.is_empty() {
            keys.push(bound.join(","));
        }
    }
    keys.join(";")
}

/// Build stable site keys for every `@At` on a handler, applying refmap context.
#[allow(clippy::too_many_arguments)]
pub fn resolve_injection_sites(
    target: &str,
    handler_method: &str,
    handler_descriptor: &str,
    operation: &MixinOperation,
    method_names: &[String],
    at_sites: &[AtDescriptor],
    locals: &[LocalCaptureDescriptor],
    param_locals: &[ParamLocalDescriptor],
    meta: &crate::model::InjectorMeta,
    mapping: &mut MappingContext,
) -> Vec<ResolvedInjectionSite> {
    let impact = crate::semantics::classify_impact(operation, at_sites.first());
    let at_list = if at_sites.is_empty() {
        vec![AtDescriptor {
            value: "HEAD".to_string(),
            ..AtDescriptor::default()
        }]
    } else {
        at_sites.to_vec()
    };

    let methods: Vec<String> = if method_names.is_empty() {
        vec![String::new()]
    } else {
        method_names.to_vec()
    };

    let mut out = Vec::new();
    for method in methods {
        let site = mapping.resolve_injection(target, &method);
        for at in &at_list {
            let site_key = build_site_key(&site.canonical, at, locals, param_locals);
            out.push(ResolvedInjectionSite {
                target: target.to_string(),
                handler_method: handler_method.to_string(),
                handler_descriptor: handler_descriptor.to_string(),
                operation: operation.clone(),
                original_method: method.clone(),
                resolved_method: site.display.clone(),
                canonical_method: site.canonical.clone(),
                namespace: site.namespace,
                resolved_via_refmap: site.mapped,
                at: at.clone(),
                locals: locals.to_vec(),
                param_locals: param_locals.to_vec(),
                site_key,
                impact: impact.as_str().to_string(),
                meta: meta.clone(),
            });
        }
    }
    out
}

/// Compose a cross-mod comparison key: canonical method + `@At` + locals.
///
/// Local discriminators (whether from `@LocalCapture` `index=`/`@At(by=)` or a
/// MixinExtras `@Local` parameter) are folded in so two handlers touching
/// *different* locals at the same site don't collide.
pub fn build_site_key(
    canonical_method: &str,
    at: &AtDescriptor,
    locals: &[LocalCaptureDescriptor],
    param_locals: &[ParamLocalDescriptor],
) -> String {
    let method_part = if canonical_method.is_empty() {
        "<unknown-method>"
    } else {
        canonical_method
    };
    let mut key = format!("{method_part}@{}", at.key_fragment());
    if let Some(pl) = param_locals
        .iter()
        .find_map(|p| p.index.or(p.ordinal))
    {
        key.push_str(&format!(":plocal{pl}"));
    } else if let Some(local) = locals.iter().find_map(|l| l.local_index) {
        key.push_str(&format!(":local{local}"));
    } else if let Some(by) = at.by {
        key.push_str(&format!(":by{by}"));
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn local_capture_mode_maps_enum_names() {
        assert_eq!(
            LocalCaptureMode::from_enum_name("CAPTURE_FAILHARD"),
            LocalCaptureMode::CaptureFailhard
        );
        assert!(LocalCaptureMode::CaptureFailhard.is_fail_hard());
        assert!(LocalCaptureMode::CaptureFailhard.captures_locals());
        assert!(!LocalCaptureMode::NoCapture.captures_locals());
        assert_eq!(
            LocalCaptureMode::from_enum_name("definitely_not_a_mode"),
            LocalCaptureMode::Unknown
        );
        // A descriptor built from the enum carries the parsed mode.
        let d = LocalCaptureDescriptor::from_capture_enum("CAPTURE_FAILSOFT");
        assert_eq!(d.capture_mode, LocalCaptureMode::CaptureFailsoft);
        assert_eq!(d.capture_type, "CAPTURE_FAILSOFT");
    }

    #[test]
    fn parses_mixinextras_local_param_as_writable_capture() {
        let bytes = fixtures::mixin_class_with_param_local(
            "example/mixin/M",
            "net/minecraft/server/MinecraftServer",
        );
        let class = cafebabe::parse_class(&bytes).expect("parse");
        let method = class
            .methods
            .iter()
            .find(|m| m.name.as_ref() == "handler")
            .expect("handler");
        let locals = parse_parameter_locals(&method.attributes, &method.descriptor);
        assert_eq!(locals.len(), 1, "one @Local param");
        // The parameter type is a MixinExtras LocalRef → a writable target-local.
        assert!(locals[0].writable);
    }

    #[test]
    fn default_at_is_head_when_missing() {
        let bytes = fixtures::mixin_class_with_inject_method(
            "example/mixin/TickMixin",
            "net/minecraft/server/MinecraftServer",
            "tick()V",
        );
        let class = cafebabe::parse_class(&bytes).expect("parse");
        let method = class.methods.first().expect("handler");
        let cafebabe::attributes::AttributeData::RuntimeVisibleAnnotations(anns) =
            &method.attributes[0].data
        else {
            panic!("expected annotations");
        };
        let inject = &anns[0];
        let ats = parse_at_descriptors(inject);
        assert_eq!(ats.len(), 1);
        assert_eq!(ats[0].value, "HEAD");
    }

    #[test]
    fn site_key_distinguishes_head_and_return() {
        let head = AtDescriptor {
            value: "HEAD".into(),
            ..Default::default()
        };
        let ret = AtDescriptor {
            value: "RETURN".into(),
            ..Default::default()
        };
        let method = "method_1574()V";
        assert_ne!(
            build_site_key(method, &head, &[], &[]),
            build_site_key(method, &ret, &[], &[])
        );
    }

    #[test]
    fn site_key_distinguishes_shift_before_and_after() {
        // The classic false positive: "A injects before call X, B injects after
        // call X" must NOT be reported as the same injection point.
        let before = AtDescriptor {
            value: "INVOKE".into(),
            target: "foo/Bar.baz()V".into(),
            shift: "BEFORE".into(),
            ..Default::default()
        };
        let after = AtDescriptor {
            shift: "AFTER".into(),
            ..before.clone()
        };
        assert_ne!(
            build_site_key("m()V", &before, &[], &[]),
            build_site_key("m()V", &after, &[], &[])
        );
    }

    #[test]
    fn site_key_distinguishes_slices() {
        let s1 = AtDescriptor {
            value: "INVOKE".into(),
            target: "foo/Bar.baz()V".into(),
            slice: "sliceA".into(),
            ..Default::default()
        };
        let s2 = AtDescriptor {
            slice: "sliceB".into(),
            ..s1.clone()
        };
        assert_ne!(
            build_site_key("m()V", &s1, &[], &[]),
            build_site_key("m()V", &s2, &[], &[])
        );
    }

    #[test]
    fn key_fragment_includes_opcode_and_args() {
        let a = AtDescriptor {
            value: "FIELD".into(),
            target: "foo/Bar.field:I".into(),
            opcode: Some(180),
            args: vec!["array=length".into()],
            ..Default::default()
        };
        let frag = a.key_fragment();
        assert!(frag.contains("op180"));
        assert!(frag.contains("argarray=length"));
    }
}