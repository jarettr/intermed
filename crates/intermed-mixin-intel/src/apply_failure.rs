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
use cafebabe::{MethodInfo, ParseOptions, parse_class_with_options};
use serde::{Deserialize, Serialize};

use crate::model::{MemberKind, MixinClassRecord};
use crate::refmap::{Namespace, TinyMappings};

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

/// Local-variable frame information for one target method (plan Phase 8): whether a
/// `LocalVariableTable` / `StackMapTable` is present (so locals can be recovered at
/// all) and the multiset of local descriptors / slots the method declares.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodFrame {
    /// A `LocalVariableTable` is present (names + descriptors recoverable).
    pub has_lvt: bool,
    /// A `StackMapTable` is present (Mixin can infer frames without an LVT).
    pub has_stackmap: bool,
    /// Descriptors of all locals declared in the LVT (scope-insensitive).
    pub local_descriptors: BTreeSet<String>,
    /// Slot indices occupied by locals.
    pub local_slots: BTreeSet<u16>,
}

/// Extract the [`MethodFrame`] from a method's `Code` attribute.
fn method_frame(method: &MethodInfo<'_>) -> MethodFrame {
    let mut frame = MethodFrame::default();
    let Some(code) = method.attributes.iter().find_map(|a| match &a.data {
        AttributeData::Code(c) => Some(c),
        _ => None,
    }) else {
        return frame;
    };
    for attr in &code.attributes {
        match &attr.data {
            AttributeData::LocalVariableTable(entries) => {
                if !entries.is_empty() {
                    frame.has_lvt = true;
                }
                for e in entries {
                    frame.local_descriptors.insert(e.descriptor.to_string());
                    frame.local_slots.insert(e.index);
                }
            }
            AttributeData::StackMapTable(_) => frame.has_stackmap = true,
            _ => {}
        }
    }
    frame
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
    /// Per-method local-variable frame info (plan Phase 8), keyed by method simple
    /// name. Drives local-capture verification.
    #[serde(default)]
    frames: BTreeMap<String, MethodFrame>,
    /// Immediate superclass (slash form), `None` for a `java/lang/Object` root.
    /// Lets `method_resolves` walk inherited methods so a mixin into an inherited
    /// method (`Block#use`) is not mis-reported as missing on the subclass.
    #[serde(default)]
    super_class: Option<String>,
    /// Whether the class implements any interface. An interface can carry a
    /// `default` method, so when a method is not found via the superclass chain but
    /// the class implements interfaces, absence is unprovable (GUI mixins inject
    /// into `render` / `mouseClicked` declared on `Renderable` / `GuiEventListener`).
    #[serde(default)]
    has_interfaces: bool,
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
            members
                .methods
                .insert((mname.clone(), m.descriptor.to_string()));
            if let Some(sites) = method_call_sites(m) {
                members.call_sites.insert(mname.clone(), sites);
            }
            members.frames.insert(mname, method_frame(m));
        }
        members.super_class = class
            .super_class
            .as_ref()
            .map(ToString::to_string)
            .filter(|s| s != "java/lang/Object");
        members.has_interfaces = !class.interfaces.is_empty();
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

    /// `true` when a Minecraft index is present (e.g. via `--minecraft-jar`), so
    /// the absence of a Minecraft class is meaningful (plan Phase 4).
    pub fn has_minecraft_coverage(&self) -> bool {
        self.has_minecraft_coverage
    }

    /// `(minecraft_classes, non_minecraft_classes)` indexed — drives the runtime
    /// classpath coverage model (plan Phase 4).
    pub fn class_scope_counts(&self) -> (usize, usize) {
        let mc = self
            .classes
            .keys()
            .filter(|k| is_minecraft_class(k))
            .count();
        (mc, self.classes.len() - mc)
    }

    /// Resolve whether method `name` exists on `slash` **or any superclass**.
    ///
    /// - `Some(true)`  — found on the class or an indexed ancestor.
    /// - `Some(false)` — provably absent: the whole chain is indexed (terminates at
    ///   a `java/lang/Object` root) and no class in it declares the method.
    /// - `None`        — unprovable: an ancestor is not indexed (e.g. a vanilla
    ///   `net.minecraft.*` superclass without `--minecraft-jar`), so the method
    ///   could be inherited from there. Callers must not raise "method missing"
    ///   for `None` — that was the source of false positives on mixins into
    ///   inherited methods (`Block#use`, `Block#neighborChanged`).
    fn method_resolves(&self, slash: &str, name: &str) -> Option<bool> {
        let mut cur = slash.to_string();
        let mut saw_interfaces = false;
        for _ in 0..64 {
            let members = self.classes.get(&cur)?; // not indexed ⇒ unprovable
            if members.method_names.contains(name) {
                return Some(true);
            }
            saw_interfaces |= members.has_interfaces;
            match &members.super_class {
                // Root reached with the whole superclass chain indexed and no match.
                // If any class in the chain implements an interface, a `default`
                // method could still supply it, so absence stays unprovable.
                None => return if saw_interfaces { None } else { Some(false) },
                Some(parent) => cur = parent.clone(),
            }
        }
        None
    }

    /// Descriptor-aware resolution of a target *method* (plan Phase 5). `dotted` is
    /// the target class in dotted form; `name` is the method simple name; `descriptor`
    /// is the expected JVM descriptor when known. Mapping context bridges a named
    /// target to its indexed (intermediary) slash form, exactly as the apply checks do.
    pub fn resolve_method(
        &self,
        dotted: &str,
        name: &str,
        descriptor: Option<&str>,
        mappings: Option<&TinyMappings>,
    ) -> crate::target_res::TargetResolution {
        use crate::target_res::TargetResolution;
        if name.is_empty() {
            return TargetResolution::Unchecked;
        }
        let slash = resolve_target_slash(dotted, mappings);
        let Some(members) = self.classes.get(&slash) else {
            // Class not indexed: only conclusive for a Minecraft class under MC
            // coverage; otherwise the absence is just a coverage gap.
            return if is_minecraft_class(&slash) && self.has_minecraft_coverage {
                TargetResolution::MissingClass
            } else {
                TargetResolution::Unchecked
            };
        };
        if !members.method_names.contains(name) {
            return TargetResolution::MissingMethod;
        }
        let Some(descriptor) = descriptor else {
            return TargetResolution::NameOnlyMatch;
        };
        if members
            .methods
            .contains(&(name.to_string(), descriptor.to_string()))
        {
            return TargetResolution::ExactMatch;
        }
        // Name present, descriptor not: distinguish a lone signature mismatch from an
        // ambiguous overload set (multiple same-named methods, none matching ours).
        let overloads = members.methods.iter().filter(|(n, _)| n == name).count();
        if overloads >= 2 {
            TargetResolution::AmbiguousOverload
        } else {
            TargetResolution::DescriptorMismatch
        }
    }

    /// Verify a site's `@At` selector against the target method body (plan Phase 6).
    ///
    /// `target_method` is the resolved method simple name; `at_target` the `@At`
    /// keyword; `at_member` the dotted member an `INVOKE`/`FIELD` selects (may be
    /// empty); `ordinal` the optional `@At(ordinal = N)`.
    pub fn verify_selector(
        &self,
        dotted: &str,
        target_method: &str,
        at_target: &str,
        at_member: &str,
        ordinal: Option<i32>,
        mappings: Option<&TinyMappings>,
    ) -> crate::selector::SelectorVerification {
        use crate::selector::{SelectorKind, SelectorVerification, classify_selector};
        let slash = resolve_target_slash(dotted, mappings);
        let method = method_simple_name(target_method);
        let Some(members) = self.classes.get(&slash) else {
            return SelectorVerification::Unchecked;
        };
        if !members.method_names.contains(method) {
            return SelectorVerification::TargetMethodMissing;
        }
        match classify_selector(at_target) {
            // HEAD/RETURN/TAIL exist on any present method.
            SelectorKind::Boundary => SelectorVerification::MatchesByConstruction,
            SelectorKind::MemberRef => {
                if at_member.is_empty() {
                    return SelectorVerification::Unsupported;
                }
                let member = at_member_simple_name(at_member);
                match self.call_site_count(&slash, method, member) {
                    // No call-site data for this method body ⇒ cannot verify.
                    None => SelectorVerification::Unchecked,
                    Some(0) => SelectorVerification::NoMatch,
                    Some(count) => match ordinal {
                        Some(n) if n >= 0 && n as u32 >= count => {
                            SelectorVerification::OrdinalOutOfRange
                        }
                        _ => SelectorVerification::Matched,
                    },
                }
            }
            SelectorKind::Other => SelectorVerification::Unsupported,
        }
    }

    /// Local-variable frame for a target method (plan Phase 8), or `None` when the
    /// class/method is not indexed.
    pub fn method_frame_for(
        &self,
        dotted: &str,
        method: &str,
        mappings: Option<&TinyMappings>,
    ) -> Option<&MethodFrame> {
        let slash = resolve_target_slash(dotted, mappings);
        self.classes
            .get(&slash)?
            .frames
            .get(method_simple_name(method))
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
    after_owner
        .split(['(', ':', ' '])
        .next()
        .unwrap_or(after_owner)
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

/// Whether a Minecraft-domain target is subject to Fabric/Quilt **intermediary
/// obfuscation** — its runtime name differs from its dev name.
///
/// This is the single source of truth behind the `remap=false` and
/// `refmap_missing` namespace checks. Fabric's intermediary mappings cover the
/// obfuscated game — `net.minecraft.*` — and nothing else: Mojang's bundled
/// libraries (`com.mojang.*`: blaze3d, datafixers, brigadier) ship with their real
/// names on every loader, so a reference to them resolves verbatim regardless of
/// the runtime namespace (it needs no refmap and is never a `remap=false` miss).
/// Stating the rule positively here — *what is obfuscated* — keeps the two checks
/// from each carrying their own `com.mojang` carve-out.
fn is_intermediary_obfuscated(target: &str) -> bool {
    target.starts_with("net.minecraft.") || target.starts_with("net/minecraft/")
}

/// A named Minecraft target that genuinely needs a refmap to reach intermediary
/// runtime: an obfuscated `net.minecraft.*` class written with a non-intermediary
/// (dev) name. Unobfuscated targets (`com.mojang.*`) keep real names and need none.
fn needs_intermediary_bridge(dotted: &str) -> bool {
    is_intermediary_obfuscated(dotted) && !dotted.contains(".class_")
}

/// The namespace a Minecraft target reference is *written* in: intermediary
/// (`net.minecraft.class_310`) or named/official (`net.minecraft.world.…`). Used
/// to compare against the loader's runtime namespace for `remap=false` targets.
fn minecraft_target_namespace(dotted: &str) -> Namespace {
    if dotted.contains(".class_") {
        Namespace::Intermediary
    } else {
        Namespace::Named
    }
}

/// Whether a `remap=false` Minecraft target resolves verbatim under `runtime`.
///
/// Unobfuscated targets (`com.mojang.*` libraries — see [`is_intermediary_obfuscated`])
/// keep their real names on every loader, so they always resolve. Only obfuscated
/// `net.minecraft.*` is namespace-sensitive: intermediary (`class_NNN`) on
/// Fabric/Quilt, named on Forge/NeoForge. `Unknown` runtime is handled by the
/// caller (never accused).
fn remap_false_resolves(target: &str, runtime: Namespace) -> bool {
    if !is_intermediary_obfuscated(target) {
        return true;
    }
    minecraft_target_namespace(target) == runtime
}

/// The loader family that presents `ns` as its runtime namespace, for messages.
fn runtime_loader_label(ns: Namespace) -> &'static str {
    match ns {
        Namespace::Named => "Forge/NeoForge",
        Namespace::Intermediary => "Fabric/Quilt",
        Namespace::Unknown => "this",
    }
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
        (
            a.mod_id.as_str(),
            a.mixin.as_str(),
            a.target.as_str(),
            a.member.as_str(),
        )
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
    // A refmap bridges named→runtime only when the runtime namespace is
    // intermediary (Fabric/Quilt). On Forge/NeoForge the runtime IS the named
    // namespace, so named targets need no refmap; on an unknown loader we cannot
    // tell, so we do not accuse. (Intermediary `class_NNN` targets are always
    // runtime-correct and never need a refmap; `com.mojang.*` library classes —
    // blaze3d/datafixers/brigadier — keep real names under intermediary too, so a
    // mixin targeting them needs no refmap either.)
    let needs_refmap = class.runtime_namespace == Namespace::Intermediary
        && class.targets.iter().any(|t| needs_intermediary_bridge(t));
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

        // remap = false takes the reference verbatim, so it resolves only when the
        // target is *already* written in the loader's runtime namespace. It is
        // suspicious only when the written namespace differs from the runtime
        // one — named target on Fabric/Quilt (runtime is intermediary), or an
        // intermediary target on Forge/NeoForge (runtime is named). A matching
        // namespace (named on Forge, intermediary on Fabric — both common and
        // correct) is fine, and an unknown loader is not accused.
        if inj.meta.remap == Some(false) && is_minecraft_target(&inj.target) {
            let runtime = class.runtime_namespace;
            let written = minecraft_target_namespace(&inj.target);
            if runtime != Namespace::Unknown && !remap_false_resolves(&inj.target, runtime) {
                out.push(ApplyFailure {
                    kind: ApplyFailureKind::RemapFalseSuspicious,
                    mod_id: class.mod_id.clone(),
                    mixin: class.class_name.clone(),
                    target: inj.target.clone(),
                    member: inj.resolved.clone(),
                    detail: format!(
                        "remap = false targets the {written} name `{}`, but this {loader} \
                         loader runs mixins against the {runtime} namespace — the reference \
                         is used verbatim and will not resolve",
                        inj.target,
                        written = written.as_str(),
                        runtime = runtime.as_str(),
                        loader = runtime_loader_label(runtime),
                    ),
                    confirmed: false,
                });
            }
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

        // Class/method presence — only when we actually indexed the target class
        // AND the method is *provably* absent across the whole indexed superclass
        // chain. A mixin into an inherited method (`Block#use`) lives on a vanilla
        // ancestor we have not indexed; `method_resolves` returns `None` there, so
        // we do not accuse (this was a large false-positive source on cross-mod
        // mixins targeting vanilla-inherited methods).
        if index.contains_class(&slash) {
            let name = method_simple_name(&inj.resolved);
            if !name.is_empty() && index.method_resolves(&slash, name) == Some(false) {
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
                detail: format!(
                    "target class `{}` not found in the Minecraft jar",
                    inj.target
                ),
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
            runtime_namespace: Namespace::Unknown,
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
            side: crate::model::Side::Both,
            activation: crate::model::ActivationStatus::ActiveAssumed,
            activation_reason: String::new(),
        }
    }

    #[test]
    fn selector_verification_distinguishes_outcomes() {
        use crate::selector::SelectorVerification;
        // The fixture's `handler` method invokes `cancel` exactly once.
        let mut index = TargetClassIndex::new();
        index.ingest_class(&fixtures::mixin_class_with_handler_bytecode(
            "mod/Target",
            "net/minecraft/Foo",
        ));

        // HEAD on an existing method always matches.
        assert_eq!(
            index.verify_selector("mod.Target", "handler", "HEAD", "", None, None),
            SelectorVerification::MatchesByConstruction
        );
        // INVOKE on a call site that exists ⇒ matched.
        assert_eq!(
            index.verify_selector(
                "mod.Target",
                "handler",
                "INVOKE",
                "Lx;cancel()V",
                None,
                None
            ),
            SelectorVerification::Matched
        );
        // ordinal past the single match ⇒ out of range.
        assert_eq!(
            index.verify_selector(
                "mod.Target",
                "handler",
                "INVOKE",
                "Lx;cancel()V",
                Some(3),
                None
            ),
            SelectorVerification::OrdinalOutOfRange
        );
        // INVOKE on a member that is never called in the body ⇒ no match.
        assert_eq!(
            index.verify_selector(
                "mod.Target",
                "handler",
                "INVOKE",
                "Lx;neverCalled()V",
                None,
                None
            ),
            SelectorVerification::NoMatch
        );
        // A selector kind we do not verify.
        assert_eq!(
            index.verify_selector("mod.Target", "handler", "CONSTANT", "", None, None),
            SelectorVerification::Unsupported
        );
        // Method absent ⇒ nothing to match.
        assert_eq!(
            index.verify_selector("mod.Target", "missing", "HEAD", "", None, None),
            SelectorVerification::TargetMethodMissing
        );
    }

    #[test]
    fn descriptor_aware_resolution_distinguishes_outcomes() {
        use crate::target_res::TargetResolution;
        let mut index = TargetClassIndex::new();
        index.ingest_class(&fixtures::class_with_method("mod/Target", "present", "()V"));

        // Exact name + descriptor.
        assert_eq!(
            index.resolve_method("mod.Target", "present", Some("()V"), None),
            TargetResolution::ExactMatch
        );
        // Name matches, descriptor unknown.
        assert_eq!(
            index.resolve_method("mod.Target", "present", None, None),
            TargetResolution::NameOnlyMatch
        );
        // Name matches but a different (single) descriptor ⇒ mismatch, not "missing".
        assert_eq!(
            index.resolve_method("mod.Target", "present", Some("(I)V"), None),
            TargetResolution::DescriptorMismatch
        );
        // Name absent on an indexed class ⇒ missing method.
        assert_eq!(
            index.resolve_method("mod.Target", "absent", Some("()V"), None),
            TargetResolution::MissingMethod
        );
        // Un-indexed non-Minecraft class ⇒ unchecked (coverage gap, not a failure).
        assert_eq!(
            index.resolve_method("other.Thing", "present", Some("()V"), None),
            TargetResolution::Unchecked
        );
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
        assert!(
            failures
                .iter()
                .any(|f| f.kind == ApplyFailureKind::OrdinalOutOfRange)
        );

        // ordinal 0 is in range → not flagged.
        let mut ok = record_targeting("alpha", "mod.Target", "handler()V");
        ok.injected_methods[0].at_ordinal = Some(0);
        ok.injected_methods[0].at_target_member = "Lx;cancel()V".into();
        let failures = detect_apply_failures(&[ok], &index, &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .all(|f| f.kind != ApplyFailureKind::OrdinalOutOfRange)
        );
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
        assert!(
            failures
                .iter()
                .all(|f| f.kind != ApplyFailureKind::OrdinalOutOfRange)
        );
    }

    #[test]
    fn intermediary_obfuscation_scope() {
        // The rule both namespace checks derive from: only `net.minecraft.*` is
        // intermediary-obfuscated; `com.mojang.*` libs and everything else are not.
        assert!(is_intermediary_obfuscated(
            "net.minecraft.world.level.block.Block"
        ));
        assert!(is_intermediary_obfuscated("net/minecraft/class_2248"));
        assert!(!is_intermediary_obfuscated(
            "com.mojang.blaze3d.platform.GlStateManager"
        ));
        assert!(!is_intermediary_obfuscated(
            "com.mojang.brigadier.CommandDispatcher"
        ));
        assert!(!is_intermediary_obfuscated(
            "org.spongepowered.asm.mixin.Mixin"
        ));
        // Derived predicates: com.mojang never needs a bridge and always resolves.
        assert!(!needs_intermediary_bridge(
            "com.mojang.blaze3d.platform.GlStateManager"
        ));
        assert!(needs_intermediary_bridge("net.minecraft.client.Minecraft"));
        assert!(remap_false_resolves(
            "com.mojang.blaze3d.platform.GlStateManager",
            Namespace::Intermediary
        ));
    }

    #[test]
    fn method_resolves_contract() {
        let mut index = TargetClassIndex::new();
        index.ingest_class(&fixtures::class_with_method("mod/Target", "present", "()V"));
        // Present on the (Object-rooted, no-interface) class → resolvable.
        assert_eq!(index.method_resolves("mod/Target", "present"), Some(true));
        // Absent on a fully-indexed Object-rooted chain → provably missing.
        assert_eq!(index.method_resolves("mod/Target", "absent"), Some(false));
        // A class we never indexed → unprovable (must not be reported missing).
        assert_eq!(index.method_resolves("other/NotIndexed", "x"), None);
    }

    #[test]
    fn method_missing_on_indexed_class_is_flagged() {
        // Index a class that has `present()V` but not `absent()V`.
        let bytes = fixtures::class_with_method("mod/Target", "present", "()V");
        let mut index = TargetClassIndex::new();
        index.ingest_class(&bytes);

        let rec = record_targeting("alpha", "mod.Target", "absent()V");
        let failures = detect_apply_failures(&[rec], &index, &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .any(|f| f.kind == ApplyFailureKind::TargetMethodMissing)
        );
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
        assert!(
            failures
                .iter()
                .any(|f| f.kind == ApplyFailureKind::RequireUnsatisfied && f.confirmed)
        );
    }

    #[test]
    fn unindexed_mod_class_is_not_a_false_positive() {
        // Empty index → no class/method claims at all.
        let rec = record_targeting("alpha", "some.unindexed.Class", "whatever()V");
        let failures =
            detect_apply_failures(&[rec], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .all(|f| f.kind != ApplyFailureKind::TargetMethodMissing)
        );
    }

    #[test]
    fn remap_false_namespace_mismatch_is_suspicious() {
        // Named target on a Fabric (intermediary-runtime) loader: the verbatim
        // named reference cannot resolve against intermediary runtime classes.
        let mut fabric = record_targeting("alpha", "net.minecraft.client.Foo", "method_1()V");
        fabric.runtime_namespace = Namespace::Intermediary;
        fabric.injected_methods[0].meta.remap = Some(false);
        let failures =
            detect_apply_failures(&[fabric], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .any(|f| f.kind == ApplyFailureKind::RemapFalseSuspicious)
        );

        // Intermediary target on a Forge (named-runtime) loader: the reverse miss.
        let mut forge = record_targeting("beta", "net.minecraft.class_310", "method_1()V");
        forge.runtime_namespace = Namespace::Named;
        forge.injected_methods[0].meta.remap = Some(false);
        let failures =
            detect_apply_failures(&[forge], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .any(|f| f.kind == ApplyFailureKind::RemapFalseSuspicious)
        );
    }

    #[test]
    fn remap_false_matching_namespace_is_not_flagged() {
        // Forge mod with a named target (Apotheosis pattern): named == runtime, fine.
        let mut forge = record_targeting(
            "apotheosis",
            "net.minecraft.world.entity.animal.Sheep",
            "getMaxHealth()F",
        );
        forge.runtime_namespace = Namespace::Named;
        forge.injected_methods[0].meta.remap = Some(false);
        let failures =
            detect_apply_failures(&[forge], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .all(|f| f.kind != ApplyFailureKind::RemapFalseSuspicious),
            "named target on a Forge loader must not be flagged"
        );

        // Fabric mod with an intermediary target (pehkui pattern): intermediary ==
        // runtime, fine.
        let mut fabric = record_targeting("pehkui", "net.minecraft.class_4603", "method_1()V");
        fabric.runtime_namespace = Namespace::Intermediary;
        fabric.injected_methods[0].meta.remap = Some(false);
        let failures =
            detect_apply_failures(&[fabric], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .all(|f| f.kind != ApplyFailureKind::RemapFalseSuspicious),
            "intermediary target on a Fabric loader must not be flagged"
        );

        // `com.mojang.*` library class on Fabric: blaze3d/datafixers/brigadier keep
        // real names under intermediary, so remap=false resolves — must not flag.
        let mut blaze = record_targeting(
            "sodium",
            "com.mojang.blaze3d.platform.GlStateManager",
            "_enableBlend()V",
        );
        blaze.runtime_namespace = Namespace::Intermediary;
        blaze.injected_methods[0].meta.remap = Some(false);
        let failures =
            detect_apply_failures(&[blaze], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .all(|f| f.kind != ApplyFailureKind::RemapFalseSuspicious),
            "com.mojang.* library target must not be flagged on any loader"
        );

        // Unknown loader (e.g. multi-loader jar): not accused either way.
        let mut unknown =
            record_targeting("multi", "net.minecraft.world.entity.animal.Sheep", "m()V");
        unknown.runtime_namespace = Namespace::Unknown;
        unknown.injected_methods[0].meta.remap = Some(false);
        let failures =
            detect_apply_failures(&[unknown], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .all(|f| f.kind != ApplyFailureKind::RemapFalseSuspicious)
        );
    }

    #[test]
    fn refmap_missing_only_on_intermediary_runtime() {
        // Named target, no refmap, Forge runtime → named is runtime-correct, fine.
        let mut forge = record_targeting("beta", "net.minecraft.client.Foo", "m()V");
        forge.runtime_namespace = Namespace::Named;
        let failures =
            detect_apply_failures(&[forge], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .all(|f| f.kind != ApplyFailureKind::RefmapMissing)
        );

        // Same on Fabric runtime → named needs a refmap to reach intermediary.
        let mut fabric = record_targeting("alpha", "net.minecraft.client.Foo", "m()V");
        fabric.runtime_namespace = Namespace::Intermediary;
        let failures =
            detect_apply_failures(&[fabric], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .any(|f| f.kind == ApplyFailureKind::RefmapMissing)
        );

        // `com.mojang.*` target on Fabric, no refmap → real names, no bridge needed
        // (iris/sodium blaze3d mixins): must not flag refmap_missing.
        let mut mojang =
            record_targeting("iris", "com.mojang.blaze3d.platform.GlStateManager", "m()V");
        mojang.runtime_namespace = Namespace::Intermediary;
        let failures =
            detect_apply_failures(&[mojang], &TargetClassIndex::new(), &BTreeSet::new(), None);
        assert!(
            failures
                .iter()
                .all(|f| f.kind != ApplyFailureKind::RefmapMissing),
            "com.mojang.* target must not trigger refmap_missing"
        );
    }

    #[test]
    fn global_mappings_bridge_named_target_to_intermediary_index() {
        let tiny = "tiny\t2\t0\tintermediary\tnamed\n\
                    c\tnet/minecraft/class_310\tnet/minecraft/client/MinecraftClient\n";
        let mappings = TinyMappings::parse(tiny).unwrap();
        let bytes = fixtures::class_with_method("net/minecraft/class_310", "present", "()V");
        let mut index = TargetClassIndex::new();
        index.ingest_class(&bytes);

        let mut rec = record_targeting(
            "alpha",
            "net.minecraft.client.MinecraftClient",
            "present()V",
        );
        rec.refmap = Some("alpha.refmap.json".into());
        let failures = detect_apply_failures(&[rec], &index, &BTreeSet::new(), Some(&mappings));
        assert!(failures.is_empty());

        let mut missing =
            record_targeting("alpha", "net.minecraft.client.MinecraftClient", "absent()V");
        missing.refmap = Some("alpha.refmap.json".into());
        let failures = detect_apply_failures(&[missing], &index, &BTreeSet::new(), Some(&mappings));
        assert!(
            failures
                .iter()
                .any(|f| f.kind == ApplyFailureKind::TargetMethodMissing)
        );
    }
}
