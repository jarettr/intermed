//! Shared runtime-annotation parsing helpers for mixin class files.
//!
//! Mixin intelligence reads annotation metadata only; these utilities normalize
//! SpongePowered and MixinExtras annotation element trees into plain Rust values
//! used by [`crate::injection_point`] and [`crate::class_parser`].

use std::collections::BTreeSet;

use cafebabe::attributes::{Annotation, AnnotationElementValue, AttributeData, AttributeInfo};
use cafebabe::descriptors::FieldType;

/// All annotations on a member, from **both** `RuntimeVisibleAnnotations` and
/// `RuntimeInvisibleAnnotations`.
///
/// SpongePowered Mixin annotations are `@Retention(CLASS)` in the spec, so the
/// class-level `@Mixin` (and, depending on the toolchain that compiled the mod,
/// some member annotations) land in the *invisible* attribute. Reading only the
/// visible one silently misses targets and injection points on production jars
/// while passing on synthetic fixtures — so every consumer must look at both.
pub fn runtime_annotations<'a>(attributes: &'a [AttributeInfo<'a>]) -> Vec<&'a Annotation<'a>> {
    let mut out = Vec::new();
    for attr in attributes {
        match &attr.data {
            AttributeData::RuntimeVisibleAnnotations(anns)
            | AttributeData::RuntimeInvisibleAnnotations(anns) => out.extend(anns.iter()),
            _ => {}
        }
    }
    out
}

/// Collect dotted class names from `value` / `targets` mixin annotation elements.
pub fn collect_class_literals(value: &AnnotationElementValue<'_>, out: &mut BTreeSet<String>) {
    match value {
        AnnotationElementValue::ClassLiteral { class_name } => {
            out.insert(descriptor_to_dotted(class_name.as_ref()));
        }
        AnnotationElementValue::StringConstant(target) => {
            let dotted = descriptor_to_dotted(target.as_ref());
            if !dotted.is_empty() {
                out.insert(dotted);
            }
        }
        AnnotationElementValue::ArrayValue(values) => {
            for v in values {
                collect_class_literals(v, out);
            }
        }
        _ => {}
    }
}

/// Collect UTF-8 string annotation element values.
pub fn collect_string_values(value: &AnnotationElementValue<'_>, out: &mut BTreeSet<String>) {
    match value {
        AnnotationElementValue::StringConstant(s) => {
            let s = s.as_ref().trim();
            if !s.is_empty() {
                out.insert(s.to_string());
            }
        }
        AnnotationElementValue::ArrayValue(values) => {
            for v in values {
                collect_string_values(v, out);
            }
        }
        _ => {}
    }
}

/// Collect nested `@` annotation values from an element (single or array).
pub fn collect_nested_annotations<'a>(
    value: &'a AnnotationElementValue<'a>,
    out: &mut Vec<&'a Annotation<'a>>,
) {
    match value {
        AnnotationElementValue::AnnotationValue(ann) => out.push(ann),
        AnnotationElementValue::ArrayValue(values) => {
            for v in values {
                collect_nested_annotations(v, out);
            }
        }
        _ => {}
    }
}

/// Read the first string value for `element_name` on an annotation.
pub fn annotation_string_element(annotation: &Annotation<'_>, element_name: &str) -> Option<String> {
    for element in &annotation.elements {
        if element.name.as_ref() != element_name {
            continue;
        }
        if let AnnotationElementValue::StringConstant(s) = &element.value {
            let trimmed = s.as_ref().trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Read the first integer value for `element_name` on an annotation.
pub fn annotation_int_element(annotation: &Annotation<'_>, element_name: &str) -> Option<i32> {
    for element in &annotation.elements {
        if element.name.as_ref() != element_name {
            continue;
        }
        let v = match &element.value {
            AnnotationElementValue::IntConstant(i) => *i,
            AnnotationElementValue::ShortConstant(i) => *i,
            AnnotationElementValue::ByteConstant(i) => *i,
            _ => continue,
        };
        return Some(v);
    }
    None
}

/// Read the enum *constant name* for `element_name` (e.g. `shift = At.Shift.AFTER`
/// stores the enum constant `AFTER`). `@At` carries several enum-typed elements
/// (`shift`) that are **not** strings, so reading them as strings silently loses
/// them — which would collapse a BEFORE and an AFTER injection at the same call
/// into one site.
pub fn annotation_enum_element(annotation: &Annotation<'_>, element_name: &str) -> Option<String> {
    for element in &annotation.elements {
        if element.name.as_ref() != element_name {
            continue;
        }
        if let AnnotationElementValue::EnumConstant { const_name, .. } = &element.value {
            return Some(const_name.as_ref().to_string());
        }
    }
    None
}

/// Read a boolean element (`remap = false`). JVM encodes booleans as ints.
pub fn annotation_bool_element(annotation: &Annotation<'_>, element_name: &str) -> Option<bool> {
    for element in &annotation.elements {
        if element.name.as_ref() != element_name {
            continue;
        }
        if let AnnotationElementValue::BooleanConstant(b) = &element.value {
            return Some(*b != 0);
        }
    }
    None
}

/// Read a string-array element (`args = {"index=2"}`) into a flat Vec.
pub fn annotation_string_array(annotation: &Annotation<'_>, element_name: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for element in &annotation.elements {
        if element.name.as_ref() == element_name {
            collect_string_values(&element.value, &mut out);
        }
    }
    out.into_iter().collect()
}

/// True when `annotation` is of the given internal JVM type name (`org/.../Type`).
pub fn is_annotation_type(annotation: &Annotation<'_>, type_name: &str) -> bool {
    matches!(
        &annotation.type_descriptor.field_type,
        FieldType::Object(class) if &**class == type_name
    )
}

/// True when any runtime annotation on `attributes` (visible or invisible)
/// matches `type_name`.
pub fn has_annotation(
    attributes: &[cafebabe::attributes::AttributeInfo<'_>],
    type_name: &str,
) -> bool {
    runtime_annotations(attributes)
        .into_iter()
        .any(|annotation| is_annotation_type(annotation, type_name))
}

/// Convert a class literal / descriptor reference to dotted form.
pub fn descriptor_to_dotted(reference: &str) -> String {
    let reference = reference.trim();
    let unwrapped = reference
        .strip_prefix('L')
        .and_then(|inner| inner.strip_suffix(';'))
        .unwrap_or(reference);
    unwrapped.replace('/', ".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn collects_string_targets() {
        let bytes = fixtures::mixin_class_string_target(
            "example/mixin/T",
            "net.minecraft.server.MinecraftServer",
            &[],
        );
        let class = cafebabe::parse_class(&bytes).expect("parse");
        let mut targets = BTreeSet::new();
        for attr in &class.attributes {
            let cafebabe::attributes::AttributeData::RuntimeVisibleAnnotations(anns) = &attr.data
            else {
                continue;
            };
            for ann in anns {
                for el in &ann.elements {
                    if el.name.as_ref() == "targets" {
                        collect_class_literals(&el.value, &mut targets);
                    }
                }
            }
        }
        assert!(targets.contains("net.minecraft.server.MinecraftServer"));
    }
}