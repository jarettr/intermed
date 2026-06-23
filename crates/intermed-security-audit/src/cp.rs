//! Structured constant-pool evidence from Java `.class` files.
//!
//! Primary parser: [`cafebabe`] (bytecode parsing disabled for speed).
//! Fallback parser: [`noak`] when cafebabe rejects a class file — compiled in
//! only under the default `noak-fallback` feature; with it off, cafebabe is the
//! sole parser and a class it rejects yields no evidence.

use std::collections::BTreeSet;

use cafebabe::constant_pool::{ConstantPoolItem, LiteralConstant, MemberRef};
use cafebabe::{ParseOptions, parse_class_with_options};
#[cfg(feature = "noak-fallback")]
use noak::reader::Class as NoakClass;
#[cfg(feature = "noak-fallback")]
use noak::reader::cpool::Item;

/// JVM class-file magic: `0xCAFEBABE`.
pub const CLASS_MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

/// Returns true when `bytes` begin with a valid Java class-file magic header.
#[must_use]
pub fn is_class_file(bytes: &[u8]) -> bool {
    bytes.len() >= CLASS_MAGIC.len() && bytes[..CLASS_MAGIC.len()] == CLASS_MAGIC
}

/// A resolved constant-pool member reference (method, interface method, or field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberReference {
    pub class_name: String,
    pub member_name: String,
    pub descriptor: String,
}

/// Structured evidence extracted from one class file's constant pool.
///
/// This is the *static* analogue of watching a class run: the constant pool
/// names every type, member, and string literal the class can reach, so the
/// detectors in [`crate::detect`] match against it instead of executing
/// anything. The four buckets are deliberately distinct because they carry
/// different evidentiary weight (see [`crate::detect::SignalProvenance`]).
///
/// # Example
///
/// For a class whose source is roughly:
///
/// ```java
/// Runtime.getRuntime().exec(cmd);                 // → method_invocations
/// Class<?> c = Class.forName("java.lang.Runtime"); // ref + "java.lang.Runtime" string
/// ```
///
/// the evidence would contain:
///
/// * `method_invocations`: `Runtime.exec`, `Runtime.getRuntime`, `Class.forName`
/// * `referenced_classes`: `java/lang/Runtime`, `java/lang/Class`, …
/// * `string_constants`: `"java.lang.Runtime"`
/// * `field_accesses`: (empty here)
///
/// `Runtime.exec` as a `method_invocations` entry is *structural* proof the
/// symbol is referenced; the `"java.lang.Runtime"` literal alone is only a
/// corroborating hint (it could be any string), which is why the two live in
/// separate buckets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassEvidence {
    /// `Class` constant-pool entries (type references, not proof of invocation).
    pub referenced_classes: BTreeSet<String>,
    /// `MethodRef` / `InterfaceMethodRef` entries — closest static analogue to `MethodInsn`.
    pub method_invocations: Vec<MemberReference>,
    /// `FieldRef` entries — used for a narrow set of signals (e.g. `Unsafe` static access).
    pub field_accesses: Vec<MemberReference>,
    /// `String` literal constants (`CONSTANT_String`) — i.e. string literals that
    /// appear in source, such as the argument to `Class.forName("...")`.
    ///
    /// These are **never** invocation evidence on their own. They are retained
    /// only as a low-confidence corroborating signal for reflective dispatch
    /// (see `detect::corroborate_with_strings`); plain UTF-8 pool entries
    /// (member names, descriptors) are deliberately excluded.
    pub string_constants: BTreeSet<String>,
}

/// Extract structured constant-pool evidence from class bytes.
///
/// Returns `None` when magic is invalid or the parser(s) fail. With the
/// `noak-fallback` feature on (the default), a class cafebabe rejects is retried
/// with noak; with it off, cafebabe is authoritative.
pub fn extract_class_evidence(class_bytes: &[u8]) -> Option<ClassEvidence> {
    if !is_class_file(class_bytes) {
        return None;
    }
    let primary = extract_with_cafebabe(class_bytes);
    #[cfg(feature = "noak-fallback")]
    {
        primary.or_else(|| extract_with_noak(class_bytes))
    }
    #[cfg(not(feature = "noak-fallback"))]
    {
        primary
    }
}

fn extract_with_cafebabe(class_bytes: &[u8]) -> Option<ClassEvidence> {
    let mut opts = ParseOptions::default();
    opts.parse_bytecode(false);
    let class = parse_class_with_options(class_bytes, &opts).ok()?;
    let mut evidence = ClassEvidence::default();

    for item in class.constantpool_iter() {
        match item {
            ConstantPoolItem::ClassInfo(name) => {
                evidence.referenced_classes.insert(name.into_owned());
            }
            ConstantPoolItem::MethodRef(member) | ConstantPoolItem::InterfaceMethodRef(member) => {
                push_method_invocation(&mut evidence, member);
            }
            ConstantPoolItem::FieldRef(member) => {
                push_field_access(&mut evidence, member);
            }
            ConstantPoolItem::LiteralConstant(LiteralConstant::String(value)) => {
                evidence.string_constants.insert(value.into_owned());
            }
            ConstantPoolItem::LiteralConstant(LiteralConstant::StringBytes(bytes)) => {
                // Non-UTF8 string constant — keep a lossy form so an obfuscated
                // literal is still eligible for corroboration.
                evidence
                    .string_constants
                    .insert(String::from_utf8_lossy(bytes).into_owned());
            }
            _ => {}
        }
    }

    Some(evidence)
}

fn push_method_invocation(evidence: &mut ClassEvidence, member: MemberRef<'_>) {
    let class_name = member.class_name.as_ref().to_string();
    evidence.referenced_classes.insert(class_name.clone());
    evidence.method_invocations.push(MemberReference {
        class_name,
        member_name: member.name_and_type.name.into_owned(),
        descriptor: member.name_and_type.descriptor.into_owned(),
    });
}

fn push_field_access(evidence: &mut ClassEvidence, member: MemberRef<'_>) {
    let class_name = member.class_name.as_ref().to_string();
    evidence.referenced_classes.insert(class_name.clone());
    evidence.field_accesses.push(MemberReference {
        class_name,
        member_name: member.name_and_type.name.into_owned(),
        descriptor: member.name_and_type.descriptor.into_owned(),
    });
}

#[cfg(feature = "noak-fallback")]
fn extract_with_noak(class_bytes: &[u8]) -> Option<ClassEvidence> {
    let class = NoakClass::new(class_bytes).ok()?;
    let pool = class.pool();
    let mut evidence = ClassEvidence::default();

    for item in pool.iter() {
        match item {
            Item::Class(class_ref) => {
                if let Ok(resolved) = pool.retrieve(class_ref.name) {
                    if let Some(name) = mstr_to_string(resolved) {
                        evidence.referenced_classes.insert(name);
                    }
                }
            }
            Item::MethodRef(method_ref) => {
                push_noak_method(
                    pool,
                    &mut evidence,
                    method_ref.class,
                    method_ref.name_and_type,
                );
            }
            Item::InterfaceMethodRef(method_ref) => {
                push_noak_method(
                    pool,
                    &mut evidence,
                    method_ref.class,
                    method_ref.name_and_type,
                );
            }
            Item::FieldRef(field_ref) => {
                push_noak_field(
                    pool,
                    &mut evidence,
                    field_ref.class,
                    field_ref.name_and_type,
                );
            }
            Item::String(string_ref) => {
                if let Ok(resolved) = pool.retrieve(string_ref.string) {
                    if let Some(value) = mstr_to_string(resolved) {
                        evidence.string_constants.insert(value);
                    }
                }
            }
            _ => {}
        }
    }

    Some(evidence)
}

#[cfg(feature = "noak-fallback")]
fn push_noak_method<'input>(
    pool: &noak::reader::cpool::ConstantPool<'input>,
    evidence: &mut ClassEvidence,
    class: noak::reader::cpool::Index<noak::reader::cpool::Class<'input>>,
    name_and_type: noak::reader::cpool::Index<noak::reader::cpool::NameAndType<'input>>,
) {
    let Some(member) = resolve_noak_member(pool, class, name_and_type) else {
        return;
    };
    evidence
        .referenced_classes
        .insert(member.class_name.clone());
    evidence.method_invocations.push(member);
}

#[cfg(feature = "noak-fallback")]
fn push_noak_field<'input>(
    pool: &noak::reader::cpool::ConstantPool<'input>,
    evidence: &mut ClassEvidence,
    class: noak::reader::cpool::Index<noak::reader::cpool::Class<'input>>,
    name_and_type: noak::reader::cpool::Index<noak::reader::cpool::NameAndType<'input>>,
) {
    let Some(member) = resolve_noak_member(pool, class, name_and_type) else {
        return;
    };
    evidence
        .referenced_classes
        .insert(member.class_name.clone());
    evidence.field_accesses.push(member);
}

#[cfg(feature = "noak-fallback")]
fn resolve_noak_member<'input>(
    pool: &noak::reader::cpool::ConstantPool<'input>,
    class: noak::reader::cpool::Index<noak::reader::cpool::Class<'input>>,
    name_and_type: noak::reader::cpool::Index<noak::reader::cpool::NameAndType<'input>>,
) -> Option<MemberReference> {
    let class_val = pool.retrieve(class).ok()?;
    let class_name = mstr_to_string(class_val.name)?;
    let nat = pool.retrieve(name_and_type).ok()?;
    let member_name = mstr_to_string(nat.name)?;
    let descriptor = mstr_to_string(nat.descriptor)?;
    Some(MemberReference {
        class_name,
        member_name,
        descriptor,
    })
}

#[cfg(feature = "noak-fallback")]
fn mstr_to_string(value: &noak::MStr) -> Option<String> {
    Some(value.to_str()?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn rejects_non_class_magic() {
        assert!(!is_class_file(b"\x00\x00\x00\x00"));
        assert!(extract_class_evidence(b"\x00\x00\x00\x00").is_none());
    }

    #[test]
    fn cafebabe_extracts_method_ref() {
        let class = fixtures::class_with_method_ref(
            "java/lang/Runtime",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
        );
        let evidence = extract_class_evidence(&class).expect("parse class");
        assert!(evidence.referenced_classes.contains("java/lang/Runtime"));
        assert!(
            evidence
                .method_invocations
                .iter()
                .any(|r| { r.class_name == "java/lang/Runtime" && r.member_name == "exec" })
        );
        assert!(evidence.field_accesses.is_empty());
    }

    #[cfg(feature = "noak-fallback")]
    #[test]
    fn noak_fallback_parses_minimal_class() {
        let class = fixtures::minimal_class();
        let evidence = extract_with_noak(&class).expect("noak parse");
        assert!(evidence.referenced_classes.contains("demo/Clazz"));
    }

    #[test]
    fn bare_utf8_strings_are_not_invocation_evidence() {
        let class = fixtures::class_with_utf8_only(&["exec", "java/lang/ProcessBuilder"]);
        let evidence = extract_class_evidence(&class).expect("parse class");
        assert!(
            !evidence
                .referenced_classes
                .contains("java/lang/ProcessBuilder")
        );
        assert!(evidence.method_invocations.is_empty());
        // Plain UTF-8 pool entries are not `CONSTANT_String` literals.
        assert!(evidence.string_constants.is_empty());
    }

    #[test]
    fn string_literals_are_captured_as_string_constants() {
        let class = fixtures::class_with_string_constants(&["java.lang.Runtime", "exec"]);
        let evidence = extract_class_evidence(&class).expect("parse class");
        assert!(evidence.string_constants.contains("java.lang.Runtime"));
        assert!(evidence.string_constants.contains("exec"));
        // String literals are not invocation or class-reference evidence.
        assert!(evidence.method_invocations.is_empty());
    }
}
