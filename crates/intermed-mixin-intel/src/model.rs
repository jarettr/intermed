//! Rich internal models for mixin intelligence.
//!
//! [`MixinClassRecord`] is the flat scan artifact used for caching and CLI
//! output. [`MixinClassModel`] is the semantic view built from bytecode and
//! refmaps; [`MixinInteractionEngine`](crate::analyzer::MixinInteractionEngine)
//! consumes models after collection to derive graph edges and risk scores.

use serde::{Deserialize, Serialize};

use crate::graph::MixinInteractionGraph;
use crate::refmap::Namespace;

/// Implementation status surfaced in help text.
pub const STATUS: &str = "active: mixin interaction graph + composite risk";

/// The runtime *side* a mixin (or application site) applies to, derived from which
/// config array it was declared in (`mixins` ⇒ [`Side::Both`], `client` ⇒
/// [`Side::Client`], `server` ⇒ [`Side::Server`]) and any Fabric/Quilt object-form
/// `environment` override (plan Phase 1).
///
/// The point of carrying side is that two mixins on opposite strict sides can never
/// co-apply in one process, so a `client`-only vs `server`-only pair is *not* a
/// conflict — see [`Side::compatible_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Side {
    Client,
    Server,
    /// Applies on both sides (a common/`mixins` entry, or `environment = "*"`).
    Both,
    /// Side could not be determined (no array provenance recorded).
    #[default]
    Unknown,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Client => "client",
            Side::Server => "server",
            Side::Both => "both",
            Side::Unknown => "unknown",
        }
    }

    /// Two sides can co-apply in the same runtime unless one is strictly `client`
    /// and the other strictly `server`. `Both`/`Unknown` are compatible with
    /// everything (conservative: never suppress a real conflict on weak evidence).
    pub fn compatible_with(self, other: Side) -> bool {
        !matches!(
            (self, other),
            (Side::Client, Side::Server) | (Side::Server, Side::Client)
        )
    }

    /// Widen two side observations of the *same* mixin into one: agreement keeps the
    /// side, `Unknown` is the identity, and any genuine disagreement widens to
    /// `Both` (the mixin is declared for more than one side).
    pub fn merge(self, other: Side) -> Side {
        match (self, other) {
            (a, b) if a == b => a,
            (Side::Unknown, b) => b,
            (a, Side::Unknown) => a,
            _ => Side::Both,
        }
    }
}

/// Whether a mixin / application site should be considered active in the analyzed
/// environment, and *why* (plan Phase 1). Static analysis can rarely *confirm*
/// activation, so the honest default for a normally-declared mixin is
/// [`ActivationStatus::ActiveAssumed`], not "active".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationStatus {
    /// Positive runtime evidence the mixin applied (reserved for log-join).
    ActiveConfirmed,
    /// Declared in a config with no gating — assumed to apply, not confirmed.
    ActiveAssumed,
    /// Excluded because its side is disjoint from the analyzed environment.
    InactiveBySide,
    /// The owning config declares an `IMixinConfigPlugin` that can toggle it.
    ConditionalByPlugin,
    /// An injector `constraints = …` makes application environment-conditional.
    ConditionalByConstraint,
    /// Activation could not be determined.
    #[default]
    Unknown,
}

impl ActivationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ActivationStatus::ActiveConfirmed => "active-confirmed",
            ActivationStatus::ActiveAssumed => "active-assumed",
            ActivationStatus::InactiveBySide => "inactive-by-side",
            ActivationStatus::ConditionalByPlugin => "conditional-by-plugin",
            ActivationStatus::ConditionalByConstraint => "conditional-by-constraint",
            ActivationStatus::Unknown => "unknown",
        }
    }

    /// `true` when application is gated/uncertain (plugin or constraint) — a
    /// signal that absence-based conclusions about this mixin carry lower certainty.
    pub fn is_conditional(self) -> bool {
        matches!(
            self,
            ActivationStatus::ConditionalByPlugin | ActivationStatus::ConditionalByConstraint
        )
    }
}

/// Named and intermediary forms of one mixin target class when a Tiny bridge exists.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TargetNamespace {
    /// Human/yarn class name (`net.minecraft.server.MinecraftServer`).
    pub named: Option<String>,
    /// Intermediary slash or dotted form (`net.minecraft.class_3215`).
    pub intermediary: Option<String>,
}

/// One mixin config file in a jar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinConfigRecord {
    pub archive: String,
    pub path: String,
    pub mod_id: String,
    pub package: String,
    pub priority: i64,
    pub refmap: Option<String>,
    pub mixins: Vec<String>,
    /// A `plugin` class declared by the config (`IMixinConfigPlugin`). A plugin
    /// can enable/disable mixins dynamically at load time, so static analysis of
    /// this config is necessarily incomplete — absence-based conclusions get
    /// lower confidence.
    #[serde(default)]
    pub plugin: Option<String>,
    /// Per-mixin application [`Side`], keyed by the *short* mixin name as it appears
    /// in the config (`mixins`/`client`/`server` arrays, plus object-form
    /// `environment` overrides). Absent ⇒ side unknown for that mixin.
    #[serde(default)]
    pub mixin_sides: std::collections::BTreeMap<String, Side>,
}

/// Flat scan record for one mixin class (cache-friendly, CLI-facing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinClassRecord {
    pub archive: String,
    pub mod_id: String,
    pub config: String,
    pub class_name: String,
    pub class_path: String,
    pub targets: Vec<String>,
    /// Per-target namespace bridge (populated when the jar ships Tiny mappings).
    #[serde(default)]
    pub target_namespace: std::collections::BTreeMap<String, TargetNamespace>,
    /// The class namespace this mod's **loader** presents to mixins at runtime,
    /// derived from the jar's loader metadata: [`Namespace::Intermediary`] for
    /// Fabric/Quilt, [`Namespace::Named`] for Forge/NeoForge (official Mojang
    /// names since 1.20.1), [`Namespace::Unknown`] when undetermined or a
    /// multi-loader jar ships both manifests. Drives the `remap=false` /
    /// `refmap_missing` apply-failure checks, which only fire when a target's
    /// written namespace cannot resolve in this runtime namespace.
    #[serde(default)]
    pub runtime_namespace: Namespace,
    pub operations: Vec<MixinOperation>,
    /// Resolved injection points after refmap / mapping normalization.
    #[serde(default)]
    pub injected_methods: Vec<ResolvedInjectionPoint>,
    /// Members the mixin expects to exist on the target via `@Shadow`.
    #[serde(default)]
    pub shadows: Vec<MixinShadowMember>,
    /// Fields or methods the mixin adds to the target (non-shadow handlers).
    #[serde(default)]
    pub added_members: Vec<MixinAddedMember>,
    /// Target-class member references from mixin bytecode.
    #[serde(default)]
    pub calls: Vec<MixinCall>,
    /// Per-handler bytecode summaries (instructions, branches, reflection).
    #[serde(default)]
    pub handler_bodies: Vec<HandlerBodySummary>,
    /// Known superclass/interface edges for mixin targets in this jar scan.
    #[serde(default)]
    pub target_hierarchy: Vec<MixinHierarchyEdge>,
    pub priority: i64,
    pub refmap: Option<String>,
    pub hot_paths: Vec<String>,
    /// Per-injection effective behaviour summaries for this mixin class.
    #[serde(default)]
    pub effects: Vec<MixinEffect>,
    /// The owning config declares an `IMixinConfigPlugin`, which can enable or
    /// disable this mixin at load time. Static analysis therefore cannot confirm
    /// the mixin is actually active, so risk involving it is *possible*, not
    /// confirmed — it carries a certainty penalty (see [`crate::analyzer`]).
    #[serde(default)]
    pub plugin_gated: bool,
    /// Application [`Side`] for this mixin class, resolved from its owning config's
    /// array membership / object-form environment (plan Phase 1). `Both`/`Unknown`
    /// are conservative — only a strict `Client`/`Server` pairing suppresses a
    /// cross-mod conflict.
    #[serde(default)]
    pub side: Side,
    /// Activation status (plan Phase 1): whether this mixin is assumed active, or
    /// gated by a plugin / constraint and therefore only *conditionally* applied.
    #[serde(default)]
    pub activation: ActivationStatus,
    /// Human-readable justification for [`MixinClassRecord::activation`] / `side`,
    /// surfaced in `--explain` and the activation fact.
    #[serde(default)]
    pub activation_reason: String,
}

/// Semantic view of one mixin class — superset of [`MixinClassRecord`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinClassModel {
    pub record: MixinClassRecord,
}

impl MixinClassModel {
    /// Borrow the flat record for emission and caching.
    pub fn record(&self) -> &MixinClassRecord {
        &self.record
    }

    /// Consume into the flat record.
    pub fn into_record(self) -> MixinClassRecord {
        self.record
    }
}

impl From<MixinClassRecord> for MixinClassModel {
    fn from(record: MixinClassRecord) -> Self {
        Self { record }
    }
}

/// Injector-annotation metadata that governs how the injection is *applied* (as
/// opposed to what it does semantically). Drives the apply-failure model and the
/// risk axes: `require`/`expect`/`allow` set how many target matches the loader
/// demands, `cancellable` lets a HEAD inject suppress the rest of the method,
/// `remap = false` opts a reference out of refmap remapping (fragile if the
/// namespace is obfuscated), and `group`/`constraints` scope conditional applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, Default)]
pub struct InjectorMeta {
    /// `require = N`: the loader fails to apply if fewer than N targets match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require: Option<i32>,
    /// `expect = N`: a softer expectation (warns rather than fails).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<i32>,
    /// `allow = N`: upper bound on how many matches are tolerated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<i32>,
    /// `cancellable = true`: the handler may cancel the target method (HEAD/RETURN
    /// `CallbackInfo.cancel()`), so it can suppress downstream code.
    #[serde(default)]
    pub cancellable: bool,
    /// `remap = false`: this injector's references are *not* remapped through the
    /// refmap. Legitimate for mod-targeting injectors; suspicious when the target
    /// is an obfuscated Minecraft class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remap: Option<bool>,
    /// `priority = N` on the injector (overrides the mixin's class priority).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    /// `group = "name"`: injectors in a group share require/allow accounting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// `constraints = "expr"`: environment-conditional application (e.g. a version
    /// range), which makes the injection environment-sensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<String>,
}

/// A single injection site with refmap resolution metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct ResolvedInjectionPoint {
    pub target: String,
    pub original: String,
    /// Human-readable resolved name (may be named/yarn). For display only.
    pub resolved: String,
    /// Cross-mod comparison key, canonicalized to the [`Namespace`] below. This
    /// — not `resolved` — is what the analyzer compares, so two mods are only
    /// matched when their keys are in the same namespace.
    #[serde(default)]
    pub canonical: String,
    /// Fine-grained site key: canonical method + `@At` + locals. Preferred for
    /// collision detection when present (distinguishes `HEAD` vs `RETURN`, etc.).
    #[serde(default)]
    pub site_key: String,
    /// Namespace `canonical` is expressed in (intermediary is cross-mod stable).
    #[serde(default = "default_namespace")]
    pub namespace: Namespace,
    /// Operation kind at this site (`inject`, `redirect`, …).
    #[serde(default = "default_injection_type")]
    pub injection_type: String,
    /// `true` when `resolved` differs from `original` via refmap/mappings.
    #[serde(default)]
    pub resolved_via_refmap: bool,
    /// Mixin handler method carrying this injection annotation.
    #[serde(default)]
    pub handler_method: String,
    /// JVM descriptor of the handler method. JVM method identity is name **plus**
    /// descriptor; carrying it lets effect attribution match the exact overload
    /// rather than the first same-named handler.
    #[serde(default)]
    pub handler_descriptor: String,
    /// The injector captures a *target-method* local via a MixinExtras `@Local`
    /// whose parameter is a writable `LocalRef`/`IntRef`/… (so it can mutate the
    /// target frame), or via `@ModifyVariable`. Distinct from `local_index`,
    /// which only records that *some* local was captured (read or write).
    #[serde(default)]
    pub mutates_target_local: bool,
    /// Primary `@At` target (`HEAD`, `RETURN`, `INVOKE`, …).
    #[serde(default)]
    pub at_target: String,
    /// Human-readable `@At` descriptor (includes opcode target / ordinal).
    #[serde(default)]
    pub at_detail: String,
    /// Likely semantic impact (`entry-hook`, `method-replace`, …).
    #[serde(default)]
    pub impact: String,
    /// Captured local index when `@LocalCapture` / `@At(by=…)` present.
    #[serde(default)]
    pub local_index: Option<i32>,
    /// Sponge `@Inject(locals = LocalCapture.X)` mode, when present (`CAPTURE_FAILHARD`,
    /// `CAPTURE_FAILSOFT`, …). Empty when the injector captures no locals. A
    /// `CAPTURE_FAILHARD` injector hard-fails if the target frame diverges, which
    /// raises apply-failure (fragility) risk.
    #[serde(default)]
    pub local_capture: String,
    /// Injector application metadata (`require`/`cancellable`/`remap`/…).
    #[serde(default)]
    pub meta: InjectorMeta,
    /// `@At(ordinal = N)` — which matching call site this injector selects. Used
    /// for the ordinal-out-of-range apply-failure check.
    #[serde(default)]
    pub at_ordinal: Option<i32>,
    /// The `@At` `target` member (INVOKE/FIELD), dotted, when present.
    #[serde(default)]
    pub at_target_member: String,
}

fn default_injection_type() -> String {
    "inject".to_string()
}

fn default_namespace() -> Namespace {
    Namespace::Unknown
}

/// A `@Shadow` field or method the mixin expects on its target class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct MixinShadowMember {
    pub target: String,
    pub name: String,
    pub descriptor: String,
    pub kind: MemberKind,
}

/// A member the mixin adds to the target (accessor, invoker, or plain field/method).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct MixinAddedMember {
    pub target: String,
    pub name: String,
    pub descriptor: String,
    pub kind: MemberKind,
    /// How the member was introduced (`added`, `accessor`, `invoker`, `overwrite`).
    pub origin: String,
    /// `@Unique`: the author marked this added member as collision-protected. Two
    /// mods adding the *same* non-unique member name to a target collide; `@Unique`
    /// is the mechanism meant to prevent that, so its presence lowers conflict risk.
    #[serde(default)]
    pub unique: bool,
}

/// A method or field reference from mixin bytecode that targets a mixin target class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct MixinCall {
    pub target: String,
    pub owner_class: String,
    pub member_name: String,
    pub descriptor: String,
    pub kind: CallKind,
    /// How the reference was discovered (constant pool vs live bytecode).
    #[serde(default = "default_call_provenance")]
    pub provenance: CallProvenance,
    /// Handler method when the call was found inside handler bytecode.
    #[serde(default)]
    pub handler_method: Option<String>,
}

fn default_call_provenance() -> CallProvenance {
    CallProvenance::ConstantPool
}

/// Evidence provenance for a [`MixinCall`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum CallProvenance {
    ConstantPool,
    Bytecode,
    Reflective,
}

impl CallProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            CallProvenance::ConstantPool => "constant-pool",
            CallProvenance::Bytecode => "bytecode",
            CallProvenance::Reflective => "reflective",
        }
    }
}

/// Structural summary of one mixin handler method body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct HandlerBodySummary {
    pub handler_method: String,
    /// JVM descriptor of the handler method (`(Lorg/.../CallbackInfo;)V`).
    ///
    /// JVM method identity is name **plus** descriptor: two handlers can share a
    /// name but differ in signature (overloads, synthetic bridges). Recording the
    /// descriptor lets effect attribution disambiguate them instead of binding to
    /// whichever same-named method happened to be first.
    #[serde(default)]
    pub handler_descriptor: String,
    pub instruction_count: u32,
    pub branch_count: u32,
    pub return_count: u32,
    pub exception_handlers: u32,
    pub uses_reflection: bool,
    /// When the handler uses reflection, the string constants that look like a
    /// reflective dispatch *target* (a qualified class name like `java.lang.Runtime`,
    /// or a dangerous reflective member like `exec` / `defineClass`). Empty for
    /// non-reflective handlers. This is the handler-granular analogue of the
    /// security layer's jar-level "reflection-corroborated" string evidence: it
    /// pinpoints *which* `@Inject`/`@Redirect` handler reflectively reaches an API
    /// that static target analysis cannot see.
    #[serde(default, alias = "string_literals")]
    pub reflective_targets: Vec<String>,
    /// Handler emits a typed return (`ARETURN`, `IRETURN`, …) — may change the target method's result.
    #[serde(default)]
    pub modifies_return_value: bool,
    /// Handler contains `ATHROW` — may abort the target method with an exception.
    #[serde(default)]
    pub throws_exception: bool,
    /// `GETFIELD` / `PUTFIELD` on mixin target class members.
    #[serde(default)]
    pub accesses_target_fields: Vec<String>,
    /// `INVOKE*` on mixin target class members.
    #[serde(default)]
    pub calls_target_methods: Vec<String>,
    /// Uses SpongePowered `CallbackInfo` / `CallbackInfoReturnable` control flow.
    #[serde(default)]
    pub uses_callback_info: bool,
    /// The handler invokes the MixinExtras `Operation.call(...)` original — i.e.
    /// it *wraps* (delegates to) the operation rather than fully replacing it.
    /// A `@WrapOperation` that never calls the original behaves like a `@Redirect`
    /// (full replacement) and is correspondingly riskier.
    #[serde(default)]
    pub calls_original_operation: bool,
    /// How many times the handler invokes `Operation.call(...)`. 0 = full
    /// replacement (riskiest), 1 = composable wrap, ≥2 = the original runs more
    /// than once (may duplicate side effects). Lets the report distinguish the
    /// MixinExtras `@WrapOperation` dispositions Mak calls out.
    #[serde(default)]
    pub original_call_count: u32,
    /// Handler writes to its **own** local variables (`ISTORE`, `ASTORE`, …).
    ///
    /// This is a near-universal implementation detail (almost every method uses a
    /// temporary), **not** evidence that the mixin mutates the *target method's*
    /// locals — that only happens via `@ModifyVariable`, `@ModifyArg(s)`, or a
    /// MixinExtras `LocalRef` write. Treating a handler temp as a target-local
    /// mutation massively over-reports risk; see `effect::classify`.
    #[serde(default, alias = "modifies_locals")]
    pub handler_local_store: bool,
    /// Precise operand-stack/taint result for this handler body. Absent when the
    /// `Code` attribute could not be abstractly interpreted.
    #[serde(default)]
    pub dataflow: Option<HandlerDataflow>,
}

/// Provenance of a value observed flowing into a dataflow sink (the return value
/// passed to `setReturnValue`, a typed `*RETURN`, or a target field write).
///
/// This is the taint lattice's join of the contributing sources, computed by the
/// abstract interpreter in [`crate::dataflow`]. `Unknown` is the conservative top
/// — used whenever control-flow joins or unmodeled stack shapes prevent a precise
/// claim, so a concrete variant is only ever reported when it is actually proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ValueSource {
    /// Could not be determined precisely (conservative top).
    #[default]
    Unknown,
    /// A compile-time constant (`*CONST`, `LDC`, `BIPUSH`, …).
    Constant,
    /// A handler method parameter (the injected arguments / captured locals).
    Argument,
    /// The mixin/target `this` reference.
    ThisRef,
    /// A value read from a field of the target class (`GETFIELD`/`GETSTATIC` on target).
    TargetField,
    /// The result of invoking a method on the target class.
    TargetCallResult,
    /// An arithmetic / combined value (computed from other operands).
    Computed,
    /// A freshly allocated object (`NEW`, array creation).
    NewObject,
}

impl ValueSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ValueSource::Unknown => "unknown",
            ValueSource::Constant => "constant",
            ValueSource::Argument => "argument",
            ValueSource::ThisRef => "this",
            ValueSource::TargetField => "target-field",
            ValueSource::TargetCallResult => "target-call-result",
            ValueSource::Computed => "computed",
            ValueSource::NewObject => "new-object",
        }
    }
}

/// One write into a target instance/static field from handler bytecode, with the
/// provenance of the stored value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct TargetFieldWrite {
    pub field: String,
    pub source: ValueSource,
}

/// How precisely a handler's dataflow was resolved — rises as later refinement
/// passes add information. The report and confidence scoring read this so a claim
/// always carries its own certainty level (plan §0/§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PrecisionLevel {
    /// Only structural opcode facts (a `cancel` *was* invoked) — no value provenance.
    #[default]
    Structural,
    /// Operand/taint provenance resolved by the abstract interpreter.
    Provenance,
    /// Value sources (what is returned / cancelled / written) resolved precisely.
    ValueSource,
    /// Cross-layer refinement (hot-path / complexity) applied on top.
    Full,
}

impl PrecisionLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            PrecisionLevel::Structural => "structural",
            PrecisionLevel::Provenance => "provenance",
            PrecisionLevel::ValueSource => "value-source",
            PrecisionLevel::Full => "full",
        }
    }
    /// Raise to at least `floor` (precision only ever increases through passes).
    pub fn raise_to(&mut self, floor: PrecisionLevel) {
        if floor > *self {
            *self = floor;
        }
    }
}

/// Why a handler's dataflow could not be resolved precisely at some point — the
/// auditable reasons behind [`HandlerDataflow::imprecise`] (plan §0/§1). Soundness
/// is unaffected: an imprecise reason only ever *lowers* a claim to `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum ImpreciseReason {
    /// A loop back-edge whose loop-carried state a single forward pass can't know.
    LoopBackEdge,
    /// A control-flow merge with mismatched operand-stack heights.
    StackHeightMismatch,
    /// A `tableswitch` / `lookupswitch` whose successors aren't enumerated.
    Switch,
    /// A merge point reachable only via an edge the analysis doesn't model.
    UnmodeledMerge,
    /// Exception control flow (`athrow` handler edges) not modeled.
    ExceptionFlow,
    /// The fixpoint hit its iteration cap and widened to conservative.
    WideningCap,
}

impl ImpreciseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            ImpreciseReason::LoopBackEdge => "loop-back-edge",
            ImpreciseReason::StackHeightMismatch => "stack-height-mismatch",
            ImpreciseReason::Switch => "switch",
            ImpreciseReason::UnmodeledMerge => "unmodeled-merge",
            ImpreciseReason::ExceptionFlow => "exception-flow",
            ImpreciseReason::WideningCap => "widening-cap",
        }
    }
}

/// Precise dataflow / taint facts for one handler body, produced by the abstract
/// interpreter in [`crate::dataflow`]. Unlike [`HandlerBodySummary`]'s flat
/// counters, these distinguish *whether* a control-flow effect actually happens
/// and *where its value comes from* — the difference between "references
/// `CallbackInfo`" and "unconditionally cancels the target and returns a constant".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, Default)]
pub struct HandlerDataflow {
    /// The handler actually invokes `CallbackInfo(Returnable).cancel()`.
    pub cancels: bool,
    /// The handler actually invokes `CallbackInfoReturnable.setReturnValue(...)`.
    pub sets_return_value: bool,
    /// A cancel / set-return-value happens only under a preceding conditional
    /// branch (a guarded effect), rather than unconditionally.
    pub conditional_control: bool,
    /// Provenance of the value the target method ends up returning (the
    /// `setReturnValue` argument, else the handler's own typed return).
    #[serde(default)]
    pub return_value_source: ValueSource,
    /// Target field writes with the provenance of each stored value.
    #[serde(default)]
    pub target_field_writes: Vec<TargetFieldWrite>,
    /// A handler parameter / `this` is forwarded into a target method call.
    pub forwards_args_to_target: bool,
    /// The handler writes a `static` field outside the target class — global state
    /// mutation that can leak across reloads / affect other mods.
    #[serde(default)]
    pub writes_global_state: bool,
    /// Number of `new` / `newarray` allocations in the body (heavy on a hot path).
    #[serde(default)]
    pub allocation_count: u32,
    /// Calls an executor / future / background-thread API (async work scheduled
    /// from inside the woven method — ordering and thread-safety hazards).
    #[serde(default)]
    pub schedules_async: bool,
    /// Calls a world/level mutation API (`setBlock*`, `spawn*`, `destroy*`, …).
    #[serde(default)]
    pub mutates_world: bool,
    /// Contains an `athrow` not dominated by a conditional branch — the handler
    /// can abort the target method unconditionally.
    #[serde(default)]
    pub unconditional_throw: bool,
    /// A control-flow guard reads a config value (the effect is config-gated).
    #[serde(default)]
    pub config_guarded: bool,
    /// A control-flow guard tests whether a mod is loaded (`isModLoaded` / `ModList`).
    #[serde(default)]
    pub mod_loaded_guarded: bool,
    /// The only observable side effect is logging (a diagnostic handler).
    #[serde(default)]
    pub logs_only: bool,
    /// Analysis degraded to conservative at a control-flow join or an unmodeled
    /// stack shape: structural booleans stay reliable, value sources may read
    /// `unknown` where precision was lost. Never produces a wrong precise claim.
    pub imprecise: bool,
    /// How precisely this handler was resolved (rises through refinement passes).
    #[serde(default)]
    pub precision: PrecisionLevel,
    /// Confidence in the value-level claims, 0–100. Structural booleans are always
    /// reliable; this scores the *precise* fields (return source, field writes).
    #[serde(default)]
    pub confidence: u8,
    /// The specific reasons precision was lost, for `--debug-mixin-dataflow` and
    /// metrics. Empty ⇔ `!imprecise`.
    #[serde(default)]
    pub imprecise_reasons: Vec<ImpreciseReason>,
}

impl HandlerDataflow {
    /// Record a precision-loss reason and set the (legacy) `imprecise` flag. The
    /// single place degradation is recorded, so reasons and the flag never drift.
    pub fn degrade(&mut self, reason: ImpreciseReason) {
        self.imprecise = true;
        if !self.imprecise_reasons.contains(&reason) {
            self.imprecise_reasons.push(reason);
        }
    }
}

/// Semantic effect of a mixin handler — derived from [`HandlerBodySummary`] and injection context.
///
/// Used by overlap / overwrite classification and human-readable effect explanations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct HandlerEffect {
    pub handler_method: String,
    /// Handler writes to its own locals — an implementation detail, not a
    /// target-frame mutation. See [`HandlerBodySummary::handler_local_store`].
    #[serde(alias = "modifies_locals")]
    pub handler_local_store: bool,
    pub modifies_return: bool,
    /// The handler can short-circuit the target method (`cancel()` /
    /// `setReturnValue()`). When dataflow is available this is *proven*, not
    /// inferred from the mere presence of a `CallbackInfo` reference.
    pub early_return: bool,
    #[serde(default)]
    pub side_effects: Vec<HandlerSideEffect>,
    /// 0–100 heuristic complexity score (branches, reflection, target calls).
    pub complexity_score: u8,
    /// Proven `CallbackInfo(Returnable).cancel()` (dataflow-backed).
    #[serde(default)]
    pub cancels: bool,
    /// Proven `CallbackInfoReturnable.setReturnValue(...)` (dataflow-backed).
    #[serde(default)]
    pub sets_return_value: bool,
    /// The cancel / set-return-value is guarded by a branch rather than unconditional.
    #[serde(default)]
    pub conditional_control: bool,
    /// Provenance of the value the target ends up returning (dataflow-backed).
    #[serde(default)]
    pub return_value_source: ValueSource,
    /// The handler writes into target-class fields (dataflow-backed).
    #[serde(default)]
    pub writes_target_state: bool,
    /// For `@WrapOperation`: how many times the wrapped original is invoked
    /// (`Operation.call`). 0 = full replacement, 1 = composable wrap, ≥2 = the
    /// original runs more than once.
    #[serde(default)]
    pub original_call_count: u32,
}

/// Observable side effect category in handler bytecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum HandlerSideEffect {
    Reflection,
    StaticTargetCall,
    TargetFieldAccess,
    CallbackControl,
    ExceptionThrow,
    /// The handler writes into a target-class field (dataflow-proven mutation of
    /// target state, distinct from merely reading it).
    TargetStateWrite,
    /// Writes a `static` field outside the target — global-state mutation.
    GlobalStateWrite,
    /// Schedules async / background work from inside the woven method.
    AsyncScheduling,
    /// Calls a world/level mutation API (`setBlock*`, `spawn*`, …).
    WorldMutation,
    /// Allocates heavily (many `new`/`newarray`) — costly on a hot path.
    HeavyAllocation,
    /// Only observable effect is logging (a diagnostic handler).
    LoggingOnly,
}

impl HandlerSideEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            HandlerSideEffect::Reflection => "reflection",
            HandlerSideEffect::StaticTargetCall => "static-target-call",
            HandlerSideEffect::TargetFieldAccess => "target-field-access",
            HandlerSideEffect::CallbackControl => "callback-control",
            HandlerSideEffect::ExceptionThrow => "exception-throw",
            HandlerSideEffect::TargetStateWrite => "target-state-write",
            HandlerSideEffect::GlobalStateWrite => "global-state-write",
            HandlerSideEffect::AsyncScheduling => "async-scheduling",
            HandlerSideEffect::WorldMutation => "world-mutation",
            HandlerSideEffect::HeavyAllocation => "heavy-allocation",
            HandlerSideEffect::LoggingOnly => "logging-only",
        }
    }
}

/// Effective behavioural change one mixin injection imposes on a target method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinEffect {
    pub mod_id: String,
    pub mixin_class: String,
    pub target: String,
    pub method: String,
    pub handler_method: String,
    pub operation: MixinOperation,
    #[serde(default)]
    pub effect_kinds: Vec<EffectiveEffectKind>,
    pub effect_description: String,
    #[serde(default)]
    pub handler_effect: Option<HandlerEffect>,
    pub hot_path: bool,
    #[serde(default)]
    pub site_key: String,
    #[serde(default)]
    pub at_target: String,
}

/// High-level classification of what changes in the target method after weaving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum EffectiveEffectKind {
    FullMethodReplacement,
    EntryModification,
    ExitModification,
    PossibleEarlyReturn,
    CallSiteReplacement,
    ArgumentMutation,
    /// Mutation of a *target-method* local (via `@ModifyVariable` / `LocalRef`),
    /// not a handler temporary.
    LocalMutation,
    /// `@ModifyReturnValue` — transforms the value the target returns.
    ReturnValueMutation,
    /// `@ModifyExpressionValue` / `@ModifyConstant` — transforms an intermediate
    /// expression value at a call/constant site.
    ExpressionValueMutation,
    Unknown,
}

impl EffectiveEffectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EffectiveEffectKind::FullMethodReplacement => "full-method-replacement",
            EffectiveEffectKind::EntryModification => "entry-modification",
            EffectiveEffectKind::ExitModification => "exit-modification",
            EffectiveEffectKind::PossibleEarlyReturn => "possible-early-return",
            EffectiveEffectKind::CallSiteReplacement => "call-site-replacement",
            EffectiveEffectKind::ArgumentMutation => "argument-mutation",
            EffectiveEffectKind::LocalMutation => "local-mutation",
            EffectiveEffectKind::ReturnValueMutation => "return-value-mutation",
            EffectiveEffectKind::ExpressionValueMutation => "expression-value-mutation",
            EffectiveEffectKind::Unknown => "unknown",
        }
    }
}

/// Actionable guidance for writing safer mixin code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub title: String,
    pub description: String,
    pub rationale: String,
    pub confidence: f32,
    /// Optional illustrative mixin snippet for `--explain` / mixin-map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    /// Authoritative documentation link (Mixin wiki, MixinExtras, Fabric docs, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<String>,
}

/// A recommendation bound to one mixin injection site in a scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MixinRecommendationRecord {
    pub mod_id: String,
    pub mixin_class: String,
    pub target: String,
    pub site_key: String,
    pub recommendation: Recommendation,
}

/// One known superclass or interface edge for a mixin target class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct MixinHierarchyEdge {
    pub target: String,
    pub ancestor: String,
    pub depth: u8,
    pub relation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum MemberKind {
    Field,
    Method,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum CallKind {
    MethodInvocation,
    FieldAccess,
}

/// A detected mixin operation kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MixinOperation {
    Inject,
    Redirect,
    Overwrite,
    ModifyArg,
    /// Sponge `@ModifyArgs` — rewrites *all* arguments of a call at once (conflicts
    /// at the invocation-args level, distinct from the single-arg `@ModifyArg`).
    ModifyArgs,
    ModifyVariable,
    ModifyConstant,
    Shadow,
    Accessor,
    Invoker,
    /// MixinExtras and other advanced inject-like annotations.
    WrapOperation,
    ModifyExpressionValue,
    /// MixinExtras `@ModifyReturnValue` — composable return rewriting (not plain `@Inject`).
    ModifyReturnValue,
    /// MixinExtras `@ModifyReceiver` — mutates the call receiver before dispatch.
    ModifyReceiver,
    /// MixinExtras `@WrapWithCondition` — can suppress a call site entirely.
    WrapWithCondition,
    /// SpongePowered `@Unique` — marks an added member as collision-protected.
    Unique,
    /// MixinExtras `@Definition` — binds a symbol for expression matching.
    Definition,
    /// MixinExtras `@Expression` — matches an AST pattern (expression matching).
    Expression,
    /// MixinExtras `@Share` — a shared local threaded between handlers.
    Share,
    Unknown,
}

impl MixinOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            MixinOperation::Inject => "inject",
            MixinOperation::Redirect => "redirect",
            MixinOperation::Overwrite => "overwrite",
            MixinOperation::ModifyArg => "modify-arg",
            MixinOperation::ModifyArgs => "modify-args",
            MixinOperation::ModifyVariable => "modify-variable",
            MixinOperation::ModifyConstant => "modify-constant",
            MixinOperation::Shadow => "shadow",
            MixinOperation::Accessor => "accessor",
            MixinOperation::Invoker => "invoker",
            MixinOperation::WrapOperation => "wrap-operation",
            MixinOperation::ModifyExpressionValue => "modify-expression-value",
            MixinOperation::ModifyReturnValue => "modify-return-value",
            MixinOperation::ModifyReceiver => "modify-receiver",
            MixinOperation::WrapWithCondition => "wrap-with-condition",
            MixinOperation::Unique => "unique",
            MixinOperation::Definition => "definition",
            MixinOperation::Expression => "expression",
            MixinOperation::Share => "share",
            MixinOperation::Unknown => "unknown",
        }
    }
}

/// Two or more mods touching the same target class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinOverlap {
    pub target: String,
    pub mods: Vec<String>,
    pub classes: Vec<String>,
    pub operations: Vec<MixinOperation>,
    pub hot_path: bool,
    #[serde(default = "default_method_conflict")]
    pub method_conflict: bool,
    #[serde(default)]
    pub shared_methods: Vec<String>,
    /// Human-readable effect summaries for mixins involved in this overlap.
    #[serde(default)]
    pub effect_summaries: Vec<String>,
}

fn default_method_conflict() -> bool {
    true
}

/// An overwrite against a target class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighRiskOverwrite {
    pub mod_id: String,
    pub class_name: String,
    pub target: String,
    pub method: String,
    /// Injection `site_key` for recommendation / rule lookup (e.g. `tick()V@HEAD`).
    #[serde(default)]
    pub site_key: String,
    pub hot_path: bool,
    #[serde(default)]
    pub effect_description: String,
    #[serde(default)]
    pub handler_effect: Option<HandlerEffect>,
}

/// Recorded interaction between two mixin classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinInteractionRecord {
    pub id: String,
    pub interaction_type: InteractionType,
    pub mod_a: String,
    pub mod_b: String,
    pub mixin_a: String,
    pub mixin_b: String,
    pub target: String,
    pub detail: String,
    pub strength: u8,
    /// `true` when `mod_a != mod_b` (a real cross-mod interaction — what users
    /// care about); `false` for two mixins of the *same* mod at one site, which
    /// is internal complexity, not a mod-vs-mod conflict.
    #[serde(default = "default_true_cross_mod")]
    pub cross_mod: bool,
}

fn default_true_cross_mod() -> bool {
    true
}

/// Edge in the mixin interaction graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinConflictEdgeRecord {
    pub id: String,
    pub edge_type: ConflictEdgeType,
    pub source_mod: String,
    pub target_mod: String,
    pub source_mixin: String,
    pub target_mixin: String,
    pub target_class: String,
    pub site: String,
    pub strength: u8,
}

/// Priority ordering conflict between mixins on the same target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinPriorityConflictRecord {
    pub target: String,
    pub mod_a: String,
    pub mod_b: String,
    pub mixin_a: String,
    pub mixin_b: String,
    pub priority_a: i64,
    pub priority_b: i64,
    pub detail: String,
}

/// One named, point-valued contribution to a complexity score.
///
/// Scores are the capped sum of their components, so every point a mixin class or
/// mod earns is attributable to a concrete, inspectable cause — the metric is a
/// transparent rollup of measured structure, never an opaque heuristic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct ComplexityComponent {
    /// What this contribution measures (e.g. `@Overwrite sites`).
    pub label: String,
    /// Points added to the score (pre-cap).
    pub points: u32,
    /// The raw measured quantity behind `points` (e.g. number of sites).
    pub measure: u32,
}

/// Composite complexity score for one mixin class (0–100), with its breakdown.
///
/// Quantifies how much one mixin class bends its target(s): injection surface,
/// operation severity (overwrites/redirects weigh more than simple injects),
/// peak handler-body complexity, target footprint, and member surface. Higher
/// scores correlate with fragility under refactors and load-order changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinClassComplexity {
    pub mod_id: String,
    pub mixin_class: String,
    pub score: u8,
    pub injection_sites: u32,
    pub target_count: u32,
    /// Peak per-handler complexity (0–100) observed in this class.
    pub peak_handler_complexity: u8,
    pub components: Vec<ComplexityComponent>,
}

/// Aggregate complexity score for one mod's entire mixin footprint (0–100).
///
/// Rolls up the mod's classes (dominated by its most complex class) plus
/// breadth (distinct targets, total injection sites) and the cross-mod conflict
/// edges the mod participates in. A single "Mixin Complexity Score" per mod that
/// the report and CI can rank on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinModComplexity {
    pub mod_id: String,
    pub score: u8,
    pub class_count: u32,
    pub target_count: u32,
    pub total_injection_sites: u32,
    /// Cross-mod conflict edges this mod participates in.
    pub conflict_edges: u32,
    /// Highest single-class score in the mod.
    pub peak_class_score: u8,
    pub components: Vec<ComplexityComponent>,
}

/// Low-yield mixin footprint for one mod — woven handler bytecode that produces
/// little observable effect on its targets.
///
/// "Bloat" here is measured, not judged: an *inert handler* is one with
/// substantial bytecode that provably touches nothing observable on the target
/// (no return change, no cancel/callback control, no local mutation, no target
/// field/method access). A mod weaving many such handlers ships bytecode into hot
/// classes for little behavioural return — worth flagging for review, never an
/// error. The score is the capped sum of its [`ComplexityComponent`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinBloatAssessment {
    pub mod_id: String,
    pub score: u8,
    pub total_handlers: u32,
    pub inert_handlers: u32,
    pub effective_handlers: u32,
    pub inert_instructions: u32,
    pub total_handler_instructions: u32,
    pub components: Vec<ComplexityComponent>,
}

/// Composite risk assessment for one target class or interaction cluster.
///
/// `score` is no longer a flat sum of boosts (which saturated at 100 for almost
/// every busy target). It is a weighted, certainty-gated combination of five
/// axes so the scale keeps ranking targets apart:
///
/// `score = certainty * (impact + fragility + blast_radius)`
///
/// with `impact` (0–40), `fragility` (0–30) and `blast_radius` (0–30) summing to
/// at most 100, scaled by `certainty` (0–1). An unresolved/uncertain target can
/// no longer reach 100 purely because many mods touch it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinRiskAssessment {
    pub subject: String,
    pub score: u8,
    /// How sure we are the conflict is real and correctly resolved (0–100).
    #[serde(default = "default_certainty")]
    pub certainty: u8,
    /// Apply-time failure severity for this target (0–100): a confirmed missing
    /// target / unsatisfied `require` floors the score high regardless of
    /// certainty, because the failure itself is certain.
    #[serde(default)]
    pub apply_failure: u8,
    /// How strong the cross-mod semantic conflict is on this target (0–100).
    #[serde(default)]
    pub semantic_conflict: u8,
    /// How destructive the semantics are (0–40).
    #[serde(default)]
    pub impact: u8,
    /// How easily it breaks across updates (0–30).
    #[serde(default)]
    pub fragility: u8,
    /// Reach: hot path / core class / many mods (0–30).
    #[serde(default)]
    pub blast_radius: u8,
    /// How clear the fix is (0–100). Reported, not folded into `score`.
    #[serde(default)]
    pub actionability: u8,
    pub reasons: Vec<String>,
    pub mods: Vec<String>,
    pub hot_path: bool,
    pub unresolved_points: usize,
}

fn default_certainty() -> u8 {
    100
}

/// Serializable graph export for reports and visualization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinGraphExport {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub mod_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub label: String,
    pub strength: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InteractionType {
    DirectInjection,
    IndirectShadow,
    SharedMember,
    PriorityOrder,
    OverwriteStack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictEdgeType {
    SameInjectionPoint,
    ShadowAddedMember,
    OverwriteCollision,
    PriorityConflict,
    SharedTarget,
    /// Two mods inject into the same target but their injection points are
    /// expressed in different mapping namespaces (e.g. named vs intermediary)
    /// with no bridge to reconcile them — a *possible* same-point conflict that
    /// could not be confirmed. Surfaced (at low strength) rather than dropped, so
    /// a cross-namespace clash is never silently missed.
    NamespaceMismatch,
    /// Overlapping injections on classes in an ancestor/descendant relationship.
    InheritedTarget,
    /// Two mods `@Overwrite` the same target method.
    OverwritesSameMethod,
    /// Two mods `@Redirect` the same call site on a target method.
    RedirectsSameCall,
    /// Two mods `@ModifyVariable` / `@ModifyArg` the same local slot.
    ModifiesSameLocal,
    /// One mixin injects at a call site another mixin already hooks at method entry.
    ChainedInjection,
    /// Two mods `@Shadow` the same target *field* with different descriptors. A
    /// class field has exactly one type, so disagreement proves at least one mod
    /// was built against a different version / mapping of the target — its
    /// `@Shadow` will fail to bind. Restricted to fields because differing method
    /// descriptors are legal overloads, not a conflict.
    ShadowDescriptorConflict,
    /// Two mods declare an `@Accessor` / `@Invoker` for the same target member
    /// (same accessor name) with incompatible descriptors — they disagree on the
    /// accessed member's type/signature, the same version-skew signal as
    /// [`ConflictEdgeType::ShadowDescriptorConflict`] but for accessor mixins.
    AccessorConflict,
    /// One mod `@Overwrite`s a target method that another mod injects into. The
    /// overwrite replaces the whole body, so the other mod's injectors silently
    /// stop applying — one of the most common "mod B's feature vanished" bugs.
    OverwriteVsInjector,
    /// A `cancellable` `@Inject` at `HEAD` on a method another mod injects at
    /// `RETURN`. If the HEAD handler cancels, the RETURN injector never runs.
    CancellableHeadVsReturn,
    /// A `@Redirect` and a `@WrapOperation` seize the **same** call site. Only one
    /// can own the call; the other is dropped or errors.
    RedirectVsWrapOperation,
    /// A `@WrapWithCondition` can suppress a call site that another mod
    /// `@Redirect`s / `@WrapOperation`s / injects around — if the condition is
    /// false the call (and the other mod's hook on it) never happens.
    WrapConditionSuppressesCall,
    /// Two mods `@ModifyArgs` the same invocation — both rewrite the full argument
    /// list, order-dependently.
    ModifyArgsSameInvocation,
    /// Two mods add the same member name to a target without `@Unique`, so the
    /// added members collide (one shadows the other / a duplicate-name error).
    UniqueMemberConflict,
}

/// Tolerated scanner failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinScanFailure {
    pub archive: String,
    pub path: Option<String>,
    pub reason: String,
}

/// Full scan + analysis result for CLI and tests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MixinScan {
    pub target: String,
    pub configs: Vec<MixinConfigRecord>,
    pub classes: Vec<MixinClassRecord>,
    pub overlaps: Vec<MixinOverlap>,
    pub high_risk_overwrites: Vec<HighRiskOverwrite>,
    #[serde(default)]
    pub mixin_effects: Vec<MixinEffect>,
    #[serde(default)]
    pub recommendations: Vec<MixinRecommendationRecord>,
    #[serde(default)]
    pub interactions: Vec<MixinInteractionRecord>,
    #[serde(default)]
    pub conflict_edges: Vec<MixinConflictEdgeRecord>,
    #[serde(default)]
    pub priority_conflicts: Vec<MixinPriorityConflictRecord>,
    #[serde(default)]
    pub risk_assessments: Vec<MixinRiskAssessment>,
    #[serde(default)]
    pub class_complexity: Vec<MixinClassComplexity>,
    #[serde(default)]
    pub mod_complexity: Vec<MixinModComplexity>,
    #[serde(default)]
    pub bloat: Vec<MixinBloatAssessment>,
    #[serde(default)]
    pub graph_export: Option<MixinGraphExport>,
    /// Apply-time failures (target/method missing, require unsatisfied, refmap
    /// missing, remap-false suspicious) — see [`crate::apply_failure`].
    #[serde(default)]
    pub apply_failures: Vec<crate::apply_failure::ApplyFailure>,
    /// Site-level application records — the central Phase-2 entity. One per
    /// handler→target-method→injection-point tuple (plan Phase 2).
    #[serde(default)]
    pub application_sites: Vec<crate::site::ApplicationSite>,
    /// Runtime classpath coverage for this scan (plan Phase 4): how complete the
    /// analyzer's view of available classes was when verifying application.
    #[serde(default)]
    pub classpath_coverage: Option<crate::classpath::ClasspathCoverage>,
    /// Site-level composition groups (plan Phases 9–10): handlers sharing one exact
    /// injection point, ordered by priority and classified by how they compose.
    #[serde(default)]
    pub compositions: Vec<crate::composition::SiteComposition>,
    /// Grouped, actionable risk diagnoses (plan Phase 13): the top-level picture.
    #[serde(default)]
    pub risk_clusters: Vec<crate::clusters::RiskCluster>,
    /// Mixins that hook Minecraft data loaders — runtime resource mutations bridging
    /// Layer F to Layer M (static datapack) and the Dynamics (script) layer.
    #[serde(default)]
    pub resource_mutations: Vec<crate::resource_bridge::RuntimeResourceMutation>,
    /// Behaviour-grounded capabilities a mod earns via its mixin targets (Layer F → B).
    #[serde(default)]
    pub capabilities: Vec<crate::subsystem::MixinCapability>,
    /// Security-sensitive subsystems mixins weave into (Layer F → G).
    #[serde(default)]
    pub security_surfaces: Vec<crate::subsystem::MixinSecuritySurface>,
    pub failures: Vec<MixinScanFailure>,
}

/// Post-collection analysis output consumed by fact emission and rules.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MixinAnalysis {
    pub overlaps: Vec<MixinOverlap>,
    pub high_risk_overwrites: Vec<HighRiskOverwrite>,
    pub interactions: Vec<MixinInteractionRecord>,
    pub conflict_edges: Vec<MixinConflictEdgeRecord>,
    pub priority_conflicts: Vec<MixinPriorityConflictRecord>,
    pub risk_assessments: Vec<MixinRiskAssessment>,
    pub mixin_effects: Vec<MixinEffect>,
    pub recommendations: Vec<MixinRecommendationRecord>,
    pub class_complexity: Vec<MixinClassComplexity>,
    pub mod_complexity: Vec<MixinModComplexity>,
    pub bloat: Vec<MixinBloatAssessment>,
    pub graph: MixinInteractionGraph,
}
