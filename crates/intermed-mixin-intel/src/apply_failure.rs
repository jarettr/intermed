//! Apply-time failure model (plan 5.3).
//!
//! Distinct from the *semantic* conflict analysis (what two mixins do to each
//! other), this layer asks a narrower, higher-certainty question: **will this
//! mixin even apply?** A mixin whose target class/method does not exist, whose
//! `require` is unsatisfiable, or whose refmap is missing fails at load time —
//! that is an `Error`, not a "might conflict" `Warn`.
//!
//! Precision depends on a [`TargetClassIndex`] of the classes a mixin targets.
//! For mod-targeting mixins (e.g. a Sodium add-on) the targets live in installed
//! jars, so the index is built from the scan. Minecraft classes only enter the
//! index when the user supplies `--minecraft-jar`; without it, class/method
//! presence simply isn't checked (limited precision, never a false positive).

use std::collections::{BTreeMap, BTreeSet};

use cafebabe::attributes::AttributeData;
use cafebabe::bytecode::Opcode;
use cafebabe::{parse_class_with_options, MethodInfo, ParseOptions};
use serde::{Deserialize, Serialize};

use crate::model::{MemberKind, MixinClassRecord};
use crate::refmap::TinyMappings;

/// Build the invoked/accessed-member simple-name histogram for one method body.
fn method_call_sites(method: &MethodInfo<'_>) -> Option<BTreeMap<String, u32>> {
    let code = method.attributes.iter().find_map(|a| match &a.data {
        AttributeData::Code(c) => Some(c),
        _ => None,
    })?;
    let bytecode = code.bytecode.as_ref()?;
    let mut out: BTreeMap<String, u32> = BTreeMap::new();
    for (_, op) in &bytecode.opcodes {
        let member = match op {
            Opcode::Invokevirtual(m)
            | Opcode::Invokespecial(m)
            | Opcode::Invokestatic(m)
            | Opcode::Invokeinterface(m, _)
            | Opcode::Getfield(m)
            | Opcode::Getstatic(m)
            | Opcode::Putfield(m)
            | Opcode::Putstatic(m) => m.name_and_type.name.as_ref().to_string(),
            _ => continue,
        };
        *out.entry(member).or_insert(0) += 1;
    }
    Some(out)
}

/// Members of one indexed class, for presence / descriptor checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ClassMembers {
    /// Method simple names present on the class.
    method_names: BTreeSet<String>,
    /// `(name, descriptor)` method signatures.
    methods: BTreeSet<(String, String)>,
    /// `(name, descriptor)` field signatures.
    fields: BTreeSet<(String, String)>,
    /// Per-method call-site histogram: target-method simple name → invoked/accessed
    /// member simple name → count. Drives the ordinal-out-of-range check: an
    /// `@At(ordinal = N)` is unsatisfiable when N exceeds the number of matching
    /// sites. Keyed by *simple name* to stay robust against named↔intermediary
    /// skew (we only act when ≥1 match is found, never on a zero-match miss).
    #[serde(default)]
    call_sites: BTreeMap<String, BTreeMap<String, u32>>,
}

/// A `slash/internal/Name` → member index of candidate mixin target classes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetClassIndex {
    classes: BTreeMap<String, ClassMembers>,
    /// Whether any indexed class lives in a Minecraft package (so MC-class
    /// absence is meaningful — we have MC coverage, e.g. via `--minecraft-jar`).
    has_minecraft_coverage: bool,
}

impl TargetClassIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a `.class` file (with bytecode) and record its members + per-method
    /// call-site histogram (for ordinal-out-of-range checks).
    pub fn ingest_class(&mut self, bytes: &[u8]) {
        if bytes.len() < 4 || bytes[..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
            return;
        }
        let mut opts = ParseOptions::default();
        opts.parse_bytecode(true);
        let Ok(class) = parse_class_with_options(bytes, &opts) else {
            return;
        };
        let name = class.this_class.to_string();
        let mut members = ClassMembers::default();
        for m in &class.methods {
            let mname = m.name.to_string();
            members.method_names.insert(mname.clone());
            members.methods.insert((mname.clone(), m.descriptor.to_string()));
            if let Some(sites) = method_call_sites(m) {
                members.call_sites.insert(mname, sites);
            }
        }
        for f in &class.fields {
            members
                .fields
                .insert((f.name.to_string(), f.descriptor.to_string()));
        }
        if is_minecraft_class(&name) {
            self.has_minecraft_coverage = true;
        }
        self.classes.insert(name, members);
    }

    /// Count of call sites in `method` matching the simple name `member_simple`.
    /// `None` when the method isn't indexed (no call-site data — never flag).
    fn call_site_count(&self, class_slash: &str, method: &str, member_simple: &str) -> Option<u32> {
        let sites = self.classes.get(class_slash)?.call_sites.get(method)?;
        Some(sites.get(member_simple).copied().unwrap_or(0))
    }

    /// Merge another index into this one (first writer wins per class).
    pub fn merge(&mut self, other: &Self) {
        for (k, v) in &other.classes {
            self.classes.entry(k.clone()).or_insert_with(|| v.clone());
        }
        self.has_minecraft_coverage |= other.has_minecraft_coverage;
    }

    fn contains_class(&self, slash: &str) -> bool {
        self.classes.contains_key(slash)
    }

    fn has_method(&self, slash: &str, name: &str) -> bool {
        self.classes
            .get(slash)
            .is_some_and(|m| m.method_names.contains(name))
    }

    fn field_descriptors(&self, slash: &str, name: &str) -> Vec<String> {
        self.classes
            .get(slash)
            .map(|m| {
                m.fields
                    .iter()
                    .filter(|(n, _)| n == name)
                    .map(|(_, d)| d.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// One detected apply-time failure (or strong risk thereof).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyFailure {
    pub kind: ApplyFailureKind,
    pub mod_id: String,
    pub mixin: String,
    pub target: String,
    /// The member (method/field) the failure is about, when applicable.
    pub member: String,
    pub detail: String,
    /// `true` = a confirmed apply failure (Error); `false` = a strong risk (Warn).
    pub confirmed: bool,
}

/// Apply-failure categories (the `mixin_apply_*` fact family from plan 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApplyFailureKind {
    TargetClassMissing,
    TargetMethodMissing,
    DescriptorMismatch,
    RequireUnsatisfied,
    RefmapMissing,
    RemapFalseSuspicious,
    OrdinalOutOfRange,
}

impl ApplyFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ApplyFailureKind::TargetClassMissing => "mixin_apply_target_class_missing",
            ApplyFailureKind::TargetMethodMissing => "mixin_apply_target_method_missing",
            ApplyFailureKind::DescriptorMismatch => "mixin_apply_descriptor_mismatch",
            ApplyFailureKind::RequireUnsatisfied => "mixin_apply_require_unsatisfied",
            ApplyFailureKind::RefmapMissing => "mixin_apply_refmap_missing",
            ApplyFailureKind::RemapFalseSuspicious => "mixin_apply_remap_false_suspicious",
            ApplyFailureKind::OrdinalOutOfRange => "mixin_apply_ordinal_out_of_range",
        }
    }
}

/// The simple member name from an `@At` target like `Lnet/minecraft/Foo;bar()V`
/// or the dotted form, or a bare `bar`.
fn at_member_simple_name(at_target: &str) -> &str {
    let after_owner = at_target.rsplit(';').next().unwrap_or(at_target);
    after_owner.split(['(', ':', ' ']).next().unwrap_or(after_owner)
}

/// True for an internal class name in a Minecraft package (named or intermediary).
fn is_minecraft_class(slash: &str) -> bool {
    slash.starts_with("net/minecraft/") || slash.starts_with("com/mojang/")
}

/// Any Minecraft target (named or intermediary).
fn is_minecraft_target(dotted: &str) -> bool {
    dotted.starts_with("net.minecraft.") || dotted.starts_with("com.mojang.")
}

/// A *named* (yarn/mojmap) Minecraft target — `net.minecraft.client.Foo`, not the
/// intermediary `net.minecraft.class_310`. Named references are compiled against
/// dev mappings and **need a refmap** to resolve to the runtime (intermediary)
/// namespace; intermediary references are already runtime-correct and do not.
fn is_named_minecraft(dotted: &str) -> bool {
    is_minecraft_target(dotted) && !dotted.contains(".class_")
}

/// The simple method name from a resolved reference like `tick()V` or `tick`.
fn method_simple_name(resolved: &str) -> &str {
    resolved.split(['(', ' ']).next().unwrap_or(resolved)
}

/// Resolve a mixin target to the slash form used by [`TargetClassIndex`].
///
/// When global Yarn/Mojmap mappings are supplied, named Minecraft targets are
/// bridged to their intermediary slash names so they can be matched against an
/// obfuscated Minecraft jar index.
fn resolve_target_slash(target: &str, mappings: Option<&TinyMappings>) -> String {
    if let Some(map) = mappings {
        if is_named_minecraft(target) {
            if let Some(inter) = map.to_intermediary_class(target) {
                return inter;
            }
        }
    }
    target.replace('.', "/")
}

/// Detect apply-time failures across all mixin classes.
///
/// `refmap_loaded` is the set of config paths that successfully loaded a refmap,
/// used to avoid flagging `refmap_missing` when one is actually present.
/// `global_mappings` optionally supplies Yarn/Mojmap Tiny v2 for named targets.
pub fn detect_apply_failures(
    classes: &[MixinClassRecord],
    index: &TargetClassIndex,
    refmap_loaded: &BTreeSet<String>,
    global_mappings: Option<&TinyMappings>,
) -> Vec<ApplyFailure> {
    let mut out = Vec::new();
    for class in classes {
        detect_for_class(class, index, refmap_loaded, global_mappings, &mut out);
    }
    out.sort_by(|a, b| {
        (a.mod_id.as_str(), a.mixin.as_str(), a.target.as_str(), a.member.as_str())
            .cmp(&(&b.mod_id, &b.mixin, &b.target, &b.member))
    });
    out.dedup();
    out
}

fn detect_for_class(
    class: &MixinClassRecord,
    index: &TargetClassIndex,
    refmap_loaded: &BTreeSet<String>,
    global_mappings: Option<&TinyMappings>,
    out: &mut Vec<ApplyFailure>,
) {
    // refmap_missing: a *named* MC target with no refmap declared or loaded.
    // (Intermediary `class_NNN` targets are already runtime-correct, no refmap.)
    let needs_refmap = class.targets.iter().any(|t| is_named_minecraft(t));
    let has_refmap = class.refmap.is_some() || refmap_loaded.contains(&class.config);
    if needs_refmap && !has_refmap {
        out.push(ApplyFailure {
            kind: ApplyFailureKind::RefmapMissing,
            mod_id: class.mod_id.clone(),
            mixin: class.class_name.clone(),
            target: class.targets.first().cloned().unwrap_or_default(),
            member: String::new(),
            detail: "targets obfuscated Minecraft classes but no refmap is present; \
                     injection points may not resolve at load time"
                .to_string(),
            confirmed: false,
        });
    }

    for inj in &class.injected_methods {
        let slash = resolve_target_slash(&inj.target, global_mappings);

        // remap = false on an obfuscated MC target: the reference is taken
        // verbatim, which only works if it is already in the runtime namespace.
        if inj.meta.remap == Some(false) && is_minecraft_target(&inj.target) {
            out.push(ApplyFailure {
                kind: ApplyFailureKind::RemapFalseSuspicious,
                mod_id: class.mod_id.clone(),
                mixin: class.class_name.clone(),
                target: inj.target.clone(),
                member: inj.resolved.clone(),
                detail: "remap = false on a Minecraft target — the reference is used \
                         unmapped and will miss unless already in the runtime namespace"
                    .to_string(),
                confirmed: false,
            });
        }

        // Ordinal-out-of-range: an `@At(ordinal = N)` is unsatisfiable when the
        // target method has fewer than N+1 matching call sites. Only acts when we
        // found ≥1 matching site (a zero-match is a namespace miss, not proof).
        if let (Some(ordinal), false) = (inj.at_ordinal, inj.at_target_member.is_empty()) {
            if ordinal >= 0 {
                let method = method_simple_name(&inj.resolved);
                let member = at_member_simple_name(&inj.at_target_member);
                if let Some(count) = index.call_site_count(&slash, method, member) {
                    if count >= 1 && ordinal as u32 >= count {
                        out.push(ApplyFailure {
                            kind: ApplyFailureKind::OrdinalOutOfRange,
                            mod_id: class.mod_id.clone(),
                            mixin: class.class_name.clone(),
                            target: inj.target.clone(),
                            member: format!("{member}#{ordinal}"),
                            detail: format!(
                                "@At(ordinal = {ordinal}) selects call site {ordinal} of `{member}` \
                                 in `{}`, but only {count} matching site(s) exist",
                                inj.resolved
                            ),
                            confirmed: true,
                        });
                    }
                }
            }
        }

        // Class/method presence — only when we actually indexed the target class.
        if index.contains_class(&slash) {
            let name = method_simple_name(&inj.resolved);
            if !name.is_empty() && !index.has_method(&slash, name) {
                let require = inj.meta.require.unwrap_or(0) >= 1;
                out.push(ApplyFailure {
                    // require >= 1 makes an unmatched target a hard load failure.
                    kind: if require {
                        ApplyFailureKind::RequireUnsatisfied
                    } else {
                        ApplyFailureKind::TargetMethodMissing
                    },
                    mod_id: class.mod_id.clone(),
                    mixin: class.class_name.clone(),
                    target: inj.target.clone(),
                    member: inj.resolved.clone(),
                    detail: format!(
                        "method `{name}` not found on `{}`{}",
                        inj.target,
                        if require {
                            " and require>=1 — the mixin fails to apply"
                        } else {
                            ""
                        }
                    ),
                    confirmed: require,
                });
            }
        } else if is_minecraft_class(&slash) && index.has_minecraft_coverage {
            // We have a Minecraft index (`--minecraft-jar`) yet the class is
            // absent — a real missing target.
            out.push(ApplyFailure {
                kind: ApplyFailureKind::TargetClassMissing,
                mod_id: class.mod_id.clone(),
                mixin: class.class_name.clone(),
                target: inj.target.clone(),
                member: String::new(),
                detail: format!("target class `{}` not found in the Minecraft jar", inj.target),
                confirmed: true,
            });
        }
    }

    // @Shadow / @Accessor descriptor disagreement against the real member.
    for shadow in &class.shadows {
        if shadow.kind != MemberKind::Field {
            continue;
        }
        let slash = resolve_target_slash(&shadow.target, global_mappings);
        if !index.contains_class(&slash) {
            continue;
        }
        let descs = index.field_descriptors(&slash, &shadow.name);
        if !descs.is_empty() && !descs.contains(&shadow.descriptor) {
            out.push(ApplyFailure {
                kind: ApplyFailureKind::DescriptorMismatch,
                mod_id: class.mod_id.clone(),
                mixin: class.class_name.clone(),
                target: shadow.target.clone(),
                member: shadow.name.clone(),
                detail: format!(
                    "@Shadow field `{}` declared as `{}` but the target has `{}`",
                    shadow.name,
                    shadow.descriptor,
                    descs.join(" | ")
                ),
                confirmed: true,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use crate::model::ResolvedInjectionPoint;

    fn record_targeting(mod_id: &str, target: &str, method: &str) -> MixinClassRecord {
        MixinClassRecord {
            archive: format!("{mod_id}.jar"),
            mod_id: mod_id.into(),
            config: "mixins.json".into(),
            class_name: format!("{mod_id}.Mixin"),
            class_path: format!("{mod_id}/Mixin.class"),
            targets: vec![target.into()],
            target_namespace: Default::default(),
            operations: Vec::new(),
            injected_methods: vec![ResolvedInjectionPoint {
                target: target.into(),
                original: method.into(),
                resolved: method.into(),
                canonical: method.into(),
                site_key: format!("{method}@HEAD"),
                namespace: crate::refmap::Namespace::Named,
                injection_type: "inject".into(),
                resolved_via_refmap: false,
                handler_method: "handler".into(),
                handler_descriptor: String::new(),
                mutates_target_local: false,
                at_target: "HEAD".into(),
                at_detail: "HEAD".into(),
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
            handler_bodies: Vec::new(),
            target_hierarchy: Vec::new(),
            priority: 1000,
            refmap: None,
            hot_paths: Vec::new(),
            effects: Vec::new(),
            plugin_gated: false,
        }
    }

    #[test]
    fn at_member_simple_name_extracts_method() {
        assert_eq!(at_member_simple_name("Lnet/minecraft/Foo;bar()V"), "bar");
        assert_eq!(at_member_simple_name("net.minecraft.Foo;baz:I"), "baz");
        assert_eq!(at_member_simple_name("plainName"), "plainName");
    }

    #[test]
    fn ordinal_out_of_range_is_flagged_when_sites_known() {
        // The fixture's `handler` method invokes `cancel` exactly once.
        let bytes = fixtures::mixin_class_with_handler_bytecode("mod/Target", "net/minecraft/Foo");
        let mut index = TargetClassIndex::new();
        index.ingest_class(&bytes);

        // ordinal 1 with only 1 matching site → out of range.
        let mut rec = record_targeting("alpha", "mod.Target", "handler()V");
        rec.injected_methods[0].at_ordinal = Some(1);
        rec.injected_methods[0].at_target_member = "Lx;cancel()V".into();
        let failures = detect_apply_failures(&[rec], &index, &BTreeSet::new(), None);
        assert!(failures
            .iter()
            .any(|f| f.kind == ApplyFailureKind::OrdinalOutOfRange));

        // ordinal 0 is in range → not flagged.
        let mut ok = record_targeting("alpha", "mod.Target", "handler()V");
        ok.injected_methods[0].at_ordinal = Some(0);
        ok.injected_methods[0].at_target_member = "Lx;cancel()V".into();
        let failures = detect_apply_failures(&[ok], &index, &BTreeSet::new(), None);
        assert!(failures
            .iter()
            .all(|f| f.kind != ApplyFailureKind::OrdinalOutOfRange));
    }

    #[test]
    fn ordinal_with_zero_matches_is_not_a_false_positive() {
        let bytes = fixtures::mixin_class_with_handler_bytecode("mod/Target", "net/minecraft/Foo");
        let mut index = TargetClassIndex::new();
        index.ingest_class(&bytes);
        // A member that the target method never calls → 0 matches → no flag.
        let mut rec = record_targeting("alpha", "mod.Target", "handler()V");
        rec.injected_methods[0].at_ordinal = Some(5);
        rec.injected_methods[0].at_target_member = "Lx;neverCalled()V".into();
        let failures = detect_apply_failures(&[rec], &index, &BTreeSet::new(), None);
        assert!(failures
            .iter()
            .all(|f| f.kind != ApplyFailureKind::OrdinalOutOfRange));
    }

    #[test]
    fn method_missing_on_indexed_class_is_flagged() {
        // Index a class that has `present()V` but not `absent()V`.
        let bytes = fixtures::class_with_method("mod/Target", "present", "()V");
        let mut index = TargetClassIndex::new();
        index.ingest_class(&bytes);

        let rec = record_targeting("alpha", "mod.Target", "absent()V");
        let failures = detect_apply_failures(&[rec], &index, &BTreeSet::new(), None);
        assert!(failures
            .iter()
            .any(|f| f.kind == ApplyFailureKind::TargetMethodMissing));
    }

    #[test]
    fn present_method_is_not_flagged() {
        let bytes = fixtures::class_with_method("mod/Target", "present", "()V");
        let mut index = TargetClassIndex::new();
        index.ingest_class(&bytes);
        let rec = record_targeting("alpha", "mod.Target", "present()V");
        let failures = detect_apply_failures(&[rec], &index, &BTreeSet::new(), None);
        assert!(failures.is_empty());
    }

    #[test]
    fn require_makes_missing_method_a_confirmed_failure() {
        let bytes = fixtures::class_with_method("mod/Target", "present", "()V");
        let mut index = TargetClassIndex::new();
        index.ingest_class(&bytes);
        let mut rec = record_targeting("alpha", "mod.Target", "absent()V");
        rec.injected_methods[0].meta.require = Some(1);
        let failures = detect_apply_failures(&[rec], &index, &BTreeSet::new(), None);
        assert!(failures
            .iter()
            .any(|f| f.kind == ApplyFailureKind::RequireUnsatisfied && f.confirmed));
    }

    #[test]
    fn unindexed_mod_class_is_not_a_false_positive() {
        // Empty index → no class/method claims at all.
        let rec = record_targeting("alpha", "some.unindexed.Class", "whatever()V");
        let failures = detect_apply_failures(&[rec], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(failures
            .iter()
            .all(|f| f.kind != ApplyFailureKind::TargetMethodMissing));
    }

    #[test]
    fn remap_false_on_minecraft_target_is_suspicious() {
        let mut rec = record_targeting("alpha", "net.minecraft.class_310", "method_1()V");
        rec.injected_methods[0].meta.remap = Some(false);
        let failures = detect_apply_failures(&[rec], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(failures
            .iter()
            .any(|f| f.kind == ApplyFailureKind::RemapFalseSuspicious));
    }

    #[test]
    fn global_mappings_bridge_named_target_to_intermediary_index() {
        let tiny = "tiny\t2\t0\tintermediary\tnamed\n\
                    c\tnet/minecraft/class_310\tnet/minecraft/client/MinecraftClient\n";
        let mappings = TinyMappings::parse(tiny).unwrap();
        let bytes = fixtures::class_with_method("net/minecraft/class_310", "present", "()V");
        let mut index = TargetClassIndex::new();
        index.ingest_class(&bytes);

        let mut rec = record_targeting("alpha", "net.minecraft.client.MinecraftClient", "present()V");
        rec.refmap = Some("alpha.refmap.json".into());
        let failures = detect_apply_failures(&[rec], &index, &BTreeSet::new(), Some(&mappings));
        assert!(failures.is_empty());

        let mut missing = record_targeting("alpha", "net.minecraft.client.MinecraftClient", "absent()V");
        missing.refmap = Some("alpha.refmap.json".into());
        let failures = detect_apply_failures(&[missing], &index, &BTreeSet::new(), Some(&mappings));
        assert!(failures
            .iter()
            .any(|f| f.kind == ApplyFailureKind::TargetMethodMissing));
    }
}
