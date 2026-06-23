//! Static API-usage rules over structured constant-pool evidence.
//!
//! # Confidence model
//!
//! Two tiers of evidence are produced, tracked by [`SignalProvenance`]:
//!
//! * **Structural** — a real `MethodRef` / `InterfaceMethodRef` / `FieldRef`
//!   (the static analogue of a `MethodInsn`). High confidence. Bare UTF-8
//!   strings never produce a structural signal.
//!
//! * **Reflection-corroborated** — a *low-confidence* inference. The classic
//!   obfuscation `Class.forName("java.lang.Runtime").getMethod("exec", …)
//!   .invoke(…)` leaves **no** `MethodRef` on `Runtime.exec`, only string
//!   constants — exactly the adversarial case a scanner exists for. We never
//!   trust such a string on its own (that would flood false positives), but
//!   when reflective dispatch *machinery* is already structurally present
//!   (`setAccessible`, `defineClass`, or `Class.forName` / `Method.invoke`),
//!   a suspicious string constant is admitted as a corroborating signal. The
//!   string therefore never fires alone, yet the combination
//!   `setAccessible + defineClass + "exec"` surfaces a finding that pure
//!   structural analysis is blind to.
//!
//! This remains a diagnostic preflight, not an antivirus: a determined attacker
//! who avoids both reflection machinery and recognizable string literals will
//! still pass. The trade-off favours precision; corroboration buys back recall
//! only on the specific reflective-dispatch pattern, without new false floods.

use std::collections::BTreeSet;

use intermed_doctor_core::evidence::Severity;
use serde::{Deserialize, Serialize};

use crate::cp::{ClassEvidence, MemberReference};

/// Minimum number of note-level signals required before emitting a grouped finding
/// when no high-risk signal is present.
pub const MIN_NOTE_SIGNALS_FOR_FINDING: usize = 2;

/// Confidence of corroborated (string-inferred) signals. Deliberately low — it
/// only ever applies on top of a structural reflection signal.
pub const CORROBORATED_CONFIDENCE: f32 = 0.4;

/// A detected security capability in one jar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySignal {
    ProcessSpawn,
    Socket,
    ReflectionSetAccessible,
    Unsafe,
    NativeLibrary,
    DynamicClassDefinition,
    /// `Class.forName` / `Method.invoke` / `Constructor.newInstance` etc. — the
    /// dispatch machinery used to reach APIs without a direct `MethodRef`.
    ReflectiveInvocation,
    /// `javax.script` engine evaluation — arbitrary code execution vector.
    ScriptEngine,
    /// `ObjectInputStream.readObject` — classic deserialization gadget vector.
    Deserialization,
    /// `System.exit` / `Runtime.exit` / `Runtime.halt` — can abort the game.
    SystemExit,
    /// `java.lang.invoke.MethodHandles` / `MethodHandle` — modern reflective dispatch
    /// that can bypass access checks without a classic `Method.invoke` reference.
    MethodHandles,
}

/// How strongly the body of evidence points at a capability actually being used,
/// orthogonal to [`SignalProvenance`] (which records *how* it was detected):
///
/// * **Low** — reflection-corroborated only: a suspicious string constant gated
///   on reflective-dispatch machinery, with no direct member reference.
/// * **Medium** — a lone structural member reference. The symbol is provably
///   referenced, but a static reference is not proof the call path executes.
/// * **High** — a structural member reference *and* an independent corroborating
///   string constant for the same capability (e.g. a `Runtime.exec` `MethodRef`
///   alongside the literals `"java.lang.Runtime"` / `"exec"`). Two independent
///   indicators agreeing is the strongest static evidence this scanner produces.
///
/// `Ord` runs `Low < Medium < High`, so the per-jar collapse can keep the max.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceStrength {
    Low,
    Medium,
    High,
}

impl EvidenceStrength {
    /// Stable wire/label token (also used as a fact attribute value).
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceStrength::Low => "low",
            EvidenceStrength::Medium => "medium",
            EvidenceStrength::High => "high",
        }
    }

    /// Parse the token produced by [`as_str`](Self::as_str); unknown tokens
    /// (including a missing attribute on an older fact) fall back to `Low`.
    pub fn from_token(token: &str) -> Self {
        match token {
            "high" => EvidenceStrength::High,
            "medium" => EvidenceStrength::Medium,
            _ => EvidenceStrength::Low,
        }
    }
}

/// How a signal was established. Carried through to fact confidence so the
/// distinction between proven and inferred evidence survives into reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignalProvenance {
    /// Direct constant-pool member reference (high confidence).
    Structural,
    /// Inferred from a suspicious string constant, gated on reflective dispatch
    /// machinery being structurally present. Never emitted on its own.
    ReflectionCorroborated,
}

impl SignalProvenance {
    /// Confidence to attach to a fact produced from this provenance.
    pub fn confidence(self) -> f32 {
        self.confidence_with(CORROBORATED_CONFIDENCE)
    }

    /// Like [`confidence`](Self::confidence) with a tunable corroborated tier.
    pub fn confidence_with(self, corroborated: f32) -> f32 {
        match self {
            SignalProvenance::Structural => 1.0,
            SignalProvenance::ReflectionCorroborated => corroborated,
        }
    }

    /// Stable wire/label token (also used as a fact attribute value).
    pub fn as_str(self) -> &'static str {
        match self {
            SignalProvenance::Structural => "structural",
            SignalProvenance::ReflectionCorroborated => "reflection-corroborated",
        }
    }
}

/// A signal together with how it was established and how strong the evidence is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DetectedSignal {
    pub signal: SecuritySignal,
    pub provenance: SignalProvenance,
    /// Defaults to [`EvidenceStrength::Low`] when absent in older cached records.
    #[serde(default = "default_strength")]
    pub strength: EvidenceStrength,
}

fn default_strength() -> EvidenceStrength {
    EvidenceStrength::Low
}

impl DetectedSignal {
    /// A lone structural reference: proven symbol, [`Medium`](EvidenceStrength::Medium).
    fn structural(signal: SecuritySignal) -> Self {
        Self {
            signal,
            provenance: SignalProvenance::Structural,
            strength: EvidenceStrength::Medium,
        }
    }

    /// A structural reference corroborated by an independent string constant:
    /// [`High`](EvidenceStrength::High).
    fn structural_corroborated(signal: SecuritySignal) -> Self {
        Self {
            signal,
            provenance: SignalProvenance::Structural,
            strength: EvidenceStrength::High,
        }
    }

    fn corroborated(signal: SecuritySignal) -> Self {
        Self {
            signal,
            provenance: SignalProvenance::ReflectionCorroborated,
            strength: EvidenceStrength::Low,
        }
    }
}

impl SecuritySignal {
    pub fn fact_kind(self) -> &'static str {
        use intermed_doctor_core::facts::kind;
        match self {
            SecuritySignal::ProcessSpawn => kind::USES_PROCESS_SPAWN,
            SecuritySignal::Socket => kind::USES_SOCKET,
            SecuritySignal::ReflectionSetAccessible => kind::USES_REFLECTION_SET_ACCESSIBLE,
            SecuritySignal::Unsafe => kind::USES_UNSAFE,
            SecuritySignal::NativeLibrary => kind::USES_NATIVE_LIBRARY,
            SecuritySignal::DynamicClassDefinition => kind::USES_DYNAMIC_CLASS_DEFINITION,
            SecuritySignal::ReflectiveInvocation => kind::USES_REFLECTIVE_INVOCATION,
            SecuritySignal::ScriptEngine => kind::USES_SCRIPT_ENGINE,
            SecuritySignal::Deserialization => kind::USES_DESERIALIZATION,
            SecuritySignal::SystemExit => kind::USES_SYSTEM_EXIT,
            SecuritySignal::MethodHandles => kind::USES_METHOD_HANDLES,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SecuritySignal::ProcessSpawn => "process spawn",
            SecuritySignal::Socket => "network socket",
            SecuritySignal::ReflectionSetAccessible => "AccessibleObject.setAccessible",
            SecuritySignal::Unsafe => "sun.misc.Unsafe",
            SecuritySignal::NativeLibrary => "native library load",
            SecuritySignal::DynamicClassDefinition => "dynamic class definition",
            SecuritySignal::ReflectiveInvocation => "reflective invocation",
            SecuritySignal::ScriptEngine => "script engine eval",
            SecuritySignal::Deserialization => "object deserialization",
            SecuritySignal::SystemExit => "process exit/halt",
            SecuritySignal::MethodHandles => "MethodHandles / MethodHandle",
        }
    }

    /// High-risk capabilities that warrant `Warn` severity by default.
    pub fn is_high_risk(self) -> bool {
        matches!(
            self,
            SecuritySignal::ProcessSpawn
                | SecuritySignal::Unsafe
                | SecuritySignal::DynamicClassDefinition
                | SecuritySignal::ScriptEngine
        )
    }

    pub fn severity(self) -> Severity {
        if self.is_high_risk() {
            Severity::Warn
        } else {
            Severity::Note
        }
    }
}

/// Whether a grouped finding should be emitted for the given signal set.
pub fn should_emit_finding(signals: &BTreeSet<SecuritySignal>) -> bool {
    should_emit_finding_with(signals, MIN_NOTE_SIGNALS_FOR_FINDING)
}

/// Like [`should_emit_finding`] with an explicit note-level threshold.
pub fn should_emit_finding_with(
    signals: &BTreeSet<SecuritySignal>,
    min_note_signals: usize,
) -> bool {
    if signals.is_empty() {
        return false;
    }
    if signals.iter().any(|s| s.is_high_risk()) {
        return true;
    }
    signals.len() >= min_note_signals
}

/// Maximum severity across a signal set (used for grouped findings).
pub fn combined_severity(signals: &BTreeSet<SecuritySignal>) -> Severity {
    if signals.iter().any(|s| s.is_high_risk()) {
        Severity::Warn
    } else {
        Severity::Note
    }
}

/// Aggregate confidence for a grouped security finding from evidence mix,
/// structural spread, and per-capability strength — replaces the previous
/// implicit 0.9 default on every finding regardless of corroboration quality.
#[must_use]
pub fn security_finding_confidence(
    signals: &BTreeSet<SecuritySignal>,
    structural: &BTreeSet<SecuritySignal>,
    corroborated_only: &BTreeSet<SecuritySignal>,
    strength: &std::collections::BTreeMap<SecuritySignal, EvidenceStrength>,
    dangerous_classes: usize,
    classes_scanned: usize,
) -> f32 {
    if signals.is_empty() {
        return 0.0;
    }

    let mut confidence = 0.55f32;

    let structural_ratio = structural.len() as f32 / signals.len() as f32;
    confidence += 0.14 * structural_ratio;

    if strength.values().any(|s| *s == EvidenceStrength::High) {
        confidence += 0.12;
    } else if strength.values().any(|s| *s == EvidenceStrength::Medium) {
        confidence += 0.06;
    }

    if classes_scanned > 0 && dangerous_classes > 0 {
        let spread = (dangerous_classes as f32 / classes_scanned as f32).min(1.0);
        confidence += 0.12 * spread;
        // A single structural hit in a huge jar is weaker than broad usage.
        if dangerous_classes == 1 && classes_scanned > 64 {
            confidence -= 0.05;
        }
    }

    if !corroborated_only.is_empty() {
        let inferred_ratio = corroborated_only.len() as f32 / signals.len() as f32;
        confidence -= 0.1 * inferred_ratio;
        if structural.is_empty() {
            confidence -= 0.08;
        }
    }

    confidence.clamp(0.35, 0.98)
}

/// Evaluate structured constant-pool evidence and return deduplicated detections.
///
/// Structural signals are derived first; reflection-corroborated signals are
/// then layered on only when the reflective-dispatch gate is satisfied and the
/// capability was not already proven structurally.
pub fn detect_signals(evidence: &ClassEvidence) -> BTreeSet<DetectedSignal> {
    let structural = structural_signals(evidence);

    // A structural signal that *also* has an independent corroborating string
    // constant is the strongest static evidence (two indicators agree); a lone
    // structural reference is Medium.
    let mut out: BTreeSet<DetectedSignal> = structural
        .iter()
        .map(|&s| {
            if has_corroborating_string(evidence, s) {
                DetectedSignal::structural_corroborated(s)
            } else {
                DetectedSignal::structural(s)
            }
        })
        .collect();

    for signal in corroborate_with_strings(evidence, &structural) {
        out.insert(DetectedSignal::corroborated(signal));
    }

    out
}

/// True when any string constant in the corroboration table for `signal` is
/// present — used to lift a proven structural reference to `High` strength.
fn has_corroborating_string(evidence: &ClassEvidence, signal: SecuritySignal) -> bool {
    CORROBORATION_TABLE
        .iter()
        .any(|&(token, s)| s == signal && evidence.string_constants.contains(token))
}

/// Structural signals only — proven by member references, never by strings.
pub fn structural_signals(evidence: &ClassEvidence) -> BTreeSet<SecuritySignal> {
    let mut out = BTreeSet::new();
    if detects_process_spawn(evidence) {
        out.insert(SecuritySignal::ProcessSpawn);
    }
    if detects_socket(evidence) {
        out.insert(SecuritySignal::Socket);
    }
    if detects_reflection_set_accessible(evidence) {
        out.insert(SecuritySignal::ReflectionSetAccessible);
    }
    if detects_unsafe(evidence) {
        out.insert(SecuritySignal::Unsafe);
    }
    if detects_native_library(evidence) {
        out.insert(SecuritySignal::NativeLibrary);
    }
    if detects_dynamic_class_definition(evidence) {
        out.insert(SecuritySignal::DynamicClassDefinition);
    }
    if detects_reflective_invocation(evidence) {
        out.insert(SecuritySignal::ReflectiveInvocation);
    }
    if detects_script_engine(evidence) {
        out.insert(SecuritySignal::ScriptEngine);
    }
    if detects_deserialization(evidence) {
        out.insert(SecuritySignal::Deserialization);
    }
    if detects_system_exit(evidence) {
        out.insert(SecuritySignal::SystemExit);
    }
    if detects_method_handles(evidence) {
        out.insert(SecuritySignal::MethodHandles);
    }
    out
}

/// Reflective dispatch machinery — the precondition for string corroboration.
///
/// All three members are structurally observable: the bug-class hides the
/// *target* API behind reflection, not the reflection primitives themselves.
fn reflection_machinery_present(structural: &BTreeSet<SecuritySignal>) -> bool {
    structural.contains(&SecuritySignal::ReflectionSetAccessible)
        || structural.contains(&SecuritySignal::DynamicClassDefinition)
        || structural.contains(&SecuritySignal::ReflectiveInvocation)
        || structural.contains(&SecuritySignal::MethodHandles)
}

/// Suspicious string constants mapped to the capability they imply. Matched
/// exactly against `CONSTANT_String` literals (e.g. the argument of
/// `Class.forName("…")` or `getMethod("exec", …)`), never against member names.
const CORROBORATION_TABLE: &[(&str, SecuritySignal)] = &[
    ("java.lang.Runtime", SecuritySignal::ProcessSpawn),
    ("java/lang/Runtime", SecuritySignal::ProcessSpawn),
    ("java.lang.ProcessBuilder", SecuritySignal::ProcessSpawn),
    ("java/lang/ProcessBuilder", SecuritySignal::ProcessSpawn),
    ("exec", SecuritySignal::ProcessSpawn),
    ("sun.misc.Unsafe", SecuritySignal::Unsafe),
    ("sun/misc/Unsafe", SecuritySignal::Unsafe),
    ("jdk.internal.misc.Unsafe", SecuritySignal::Unsafe),
    ("jdk/internal/misc/Unsafe", SecuritySignal::Unsafe),
    ("java.net.Socket", SecuritySignal::Socket),
    ("java/net/Socket", SecuritySignal::Socket),
    (
        "javax.script.ScriptEngineManager",
        SecuritySignal::ScriptEngine,
    ),
    (
        "javax/script/ScriptEngineManager",
        SecuritySignal::ScriptEngine,
    ),
    ("getEngineByName", SecuritySignal::ScriptEngine),
    ("loadLibrary", SecuritySignal::NativeLibrary),
    (
        "java.lang.invoke.MethodHandles",
        SecuritySignal::MethodHandles,
    ),
    (
        "java/lang/invoke/MethodHandles",
        SecuritySignal::MethodHandles,
    ),
    (
        "java.net.URLClassLoader",
        SecuritySignal::DynamicClassDefinition,
    ),
    (
        "java/net/URLClassLoader",
        SecuritySignal::DynamicClassDefinition,
    ),
];

/// Low-confidence corroboration: admit a capability implied by a suspicious
/// string constant, but **only** when reflective-dispatch machinery is already
/// structurally present and the capability was not proven structurally.
///
/// Returns an empty set whenever the reflection gate is closed, guaranteeing a
/// string can never produce a finding by itself.
pub fn corroborate_with_strings(
    evidence: &ClassEvidence,
    structural: &BTreeSet<SecuritySignal>,
) -> BTreeSet<SecuritySignal> {
    let mut out = BTreeSet::new();
    if !reflection_machinery_present(structural) {
        return out;
    }
    for &(token, signal) in CORROBORATION_TABLE {
        if structural.contains(&signal) {
            continue; // already proven directly — no need to infer
        }
        if evidence.string_constants.contains(token) {
            out.insert(signal);
        }
    }
    out
}

fn invokes_method(evidence: &ClassEvidence, class_name: &str, member_name: &str) -> bool {
    evidence
        .method_invocations
        .iter()
        .any(|r| r.class_name == class_name && r.member_name == member_name)
}

fn invokes_any_method(evidence: &ClassEvidence, class_name: &str, member_names: &[&str]) -> bool {
    evidence
        .method_invocations
        .iter()
        .any(|r| r.class_name == class_name && member_names.contains(&r.member_name.as_str()))
}

fn invokes_method_on_any(evidence: &ClassEvidence, classes: &[&str], member_name: &str) -> bool {
    classes
        .iter()
        .any(|class| invokes_method(evidence, class, member_name))
}

fn invokes_socket_api(member: &MemberReference) -> bool {
    const SOCKET_CLASSES: &[&str] = &[
        "java/net/Socket",
        "java/net/ServerSocket",
        "java/net/DatagramSocket",
    ];
    const SOCKET_METHODS: &[&str] = &["<init>", "connect", "bind", "accept", "send", "receive"];

    SOCKET_CLASSES.contains(&member.class_name.as_str())
        && SOCKET_METHODS.contains(&member.member_name.as_str())
}

fn is_unsafe_class(class_name: &str) -> bool {
    matches!(class_name, "sun/misc/Unsafe" | "jdk/internal/misc/Unsafe")
}

fn detects_process_spawn(evidence: &ClassEvidence) -> bool {
    invokes_method(evidence, "java/lang/Runtime", "exec")
        || invokes_method(evidence, "java/lang/ProcessBuilder", "start")
}

fn detects_socket(evidence: &ClassEvidence) -> bool {
    evidence.method_invocations.iter().any(invokes_socket_api)
}

fn detects_reflection_set_accessible(evidence: &ClassEvidence) -> bool {
    invokes_method(
        evidence,
        "java/lang/reflect/AccessibleObject",
        "setAccessible",
    )
}

fn detects_unsafe(evidence: &ClassEvidence) -> bool {
    evidence
        .method_invocations
        .iter()
        .any(|m| is_unsafe_class(&m.class_name))
        || evidence
            .field_accesses
            .iter()
            .any(|f| is_unsafe_class(&f.class_name))
}

fn detects_native_library(evidence: &ClassEvidence) -> bool {
    invokes_method_on_any(evidence, &["java/lang/System"], "loadLibrary")
        || invokes_method_on_any(evidence, &["java/lang/System"], "load")
        || invokes_method_on_any(evidence, &["java/lang/Runtime"], "loadLibrary")
        || invokes_method_on_any(evidence, &["java/lang/Runtime"], "load")
        || invokes_method_on_any(evidence, &["java/lang/foreign/NativeLibrary"], "load")
        || invokes_method_on_any(evidence, &["jdk/internal/loader/NativeLibraries"], "load")
}

fn detects_dynamic_class_definition(evidence: &ClassEvidence) -> bool {
    invokes_method(evidence, "java/lang/ClassLoader", "defineClass")
        || invokes_method(evidence, "java/lang/ClassLoader", "defineClass0")
        || invokes_method(evidence, "java/net/URLClassLoader", "<init>")
        || invokes_any_method(
            evidence,
            "java/net/URLClassLoader",
            &["newInstance", "definePackage"],
        )
        || invokes_method(
            evidence,
            "java/lang/instrument/Instrumentation",
            "redefineClasses",
        )
        || invokes_method(
            evidence,
            "java/lang/instrument/Instrumentation",
            "retransformClasses",
        )
}

fn detects_reflective_invocation(evidence: &ClassEvidence) -> bool {
    invokes_any_method(
        evidence,
        "java/lang/Class",
        &[
            "forName",
            "getMethod",
            "getDeclaredMethod",
            "getConstructor",
            "getDeclaredConstructor",
        ],
    ) || invokes_method(evidence, "java/lang/reflect/Method", "invoke")
        || invokes_method(evidence, "java/lang/reflect/Constructor", "newInstance")
        || invokes_any_method(
            evidence,
            "java/lang/reflect/Field",
            &["get", "set", "getInt", "setInt"],
        )
}

fn detects_method_handles(evidence: &ClassEvidence) -> bool {
    invokes_any_method(
        evidence,
        "java/lang/invoke/MethodHandles",
        &["lookup", "publicLookup"],
    ) || invokes_any_method(
        evidence,
        "java/lang/invoke/MethodHandle",
        &["invoke", "invokeExact"],
    ) || invokes_any_method(
        evidence,
        "java/lang/invoke/Lookup",
        &[
            "findVirtual",
            "findStatic",
            "findConstructor",
            "findSpecial",
            "unreflect",
            "defineHiddenClass",
        ],
    )
}

fn detects_script_engine(evidence: &ClassEvidence) -> bool {
    invokes_any_method(
        evidence,
        "javax/script/ScriptEngineManager",
        &[
            "getEngineByName",
            "getEngineByExtension",
            "getEngineByMimeType",
        ],
    ) || invokes_method(evidence, "javax/script/ScriptEngine", "eval")
}

fn detects_deserialization(evidence: &ClassEvidence) -> bool {
    invokes_any_method(
        evidence,
        "java/io/ObjectInputStream",
        &["readObject", "readUnshared"],
    )
}

fn detects_system_exit(evidence: &ClassEvidence) -> bool {
    invokes_method(evidence, "java/lang/System", "exit")
        || invokes_any_method(evidence, "java/lang/Runtime", &["exit", "halt"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    fn signals_of(class: &[u8]) -> BTreeSet<SecuritySignal> {
        let evidence = crate::cp::extract_class_evidence(class).unwrap();
        detect_signals(&evidence)
            .into_iter()
            .map(|d| d.signal)
            .collect()
    }

    #[test]
    fn detects_runtime_exec_method_ref() {
        let class = fixtures::class_with_method_ref(
            "java/lang/Runtime",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
        );
        assert!(signals_of(&class).contains(&SecuritySignal::ProcessSpawn));
    }

    #[test]
    fn ignores_bare_exec_utf8_without_refs() {
        let class = fixtures::class_with_utf8_only(&["exec"]);
        assert!(!signals_of(&class).contains(&SecuritySignal::ProcessSpawn));
    }

    #[test]
    fn class_ref_alone_does_not_trigger_socket() {
        let class = fixtures::class_with_class_ref("java/net/Socket");
        assert!(!signals_of(&class).contains(&SecuritySignal::Socket));
    }

    #[test]
    fn socket_requires_method_invocation() {
        let class = fixtures::class_with_method_ref("java/net/Socket", "connect", "()V");
        assert!(signals_of(&class).contains(&SecuritySignal::Socket));
    }

    #[test]
    fn reflection_requires_accessible_object_set_accessible() {
        let class =
            fixtures::class_with_method_ref("java/lang/reflect/Field", "setAccessible", "(Z)V");
        assert!(!signals_of(&class).contains(&SecuritySignal::ReflectionSetAccessible));

        let class = fixtures::class_with_method_ref(
            "java/lang/reflect/AccessibleObject",
            "setAccessible",
            "(Z)V",
        );
        assert!(signals_of(&class).contains(&SecuritySignal::ReflectionSetAccessible));
    }

    #[test]
    fn detects_expanded_structural_signals() {
        let class = fixtures::class_with_method_ref(
            "java/lang/Class",
            "forName",
            "(Ljava/lang/String;)Ljava/lang/Class;",
        );
        assert!(signals_of(&class).contains(&SecuritySignal::ReflectiveInvocation));

        let class = fixtures::class_with_method_ref("javax/script/ScriptEngine", "eval", "()V");
        let s = signals_of(&class);
        assert!(s.contains(&SecuritySignal::ScriptEngine));
        assert_eq!(SecuritySignal::ScriptEngine.severity(), Severity::Warn);

        let class =
            fixtures::class_with_method_ref("java/io/ObjectInputStream", "readObject", "()V");
        assert!(signals_of(&class).contains(&SecuritySignal::Deserialization));

        let class = fixtures::class_with_method_ref("java/lang/System", "exit", "(I)V");
        assert!(signals_of(&class).contains(&SecuritySignal::SystemExit));

        let class = fixtures::class_with_method_ref(
            "java/lang/invoke/MethodHandles",
            "lookup",
            "()Ljava/lang/invoke/MethodHandles$Lookup;",
        );
        assert!(signals_of(&class).contains(&SecuritySignal::MethodHandles));

        let class = fixtures::class_with_method_ref("java/net/URLClassLoader", "<init>", "()V");
        assert!(signals_of(&class).contains(&SecuritySignal::DynamicClassDefinition));

        let class =
            fixtures::class_with_method_ref("java/lang/foreign/NativeLibrary", "load", "()V");
        assert!(signals_of(&class).contains(&SecuritySignal::NativeLibrary));
    }

    #[test]
    fn string_alone_never_corroborates_without_reflection_machinery() {
        // A plain string literal "exec" with no reflection machinery present.
        let class = fixtures::class_with_string_constants(&["exec", "java.lang.Runtime"]);
        let evidence = crate::cp::extract_class_evidence(&class).unwrap();
        assert!(evidence.string_constants.contains("exec"));
        assert!(detect_signals(&evidence).is_empty());
    }

    #[test]
    fn reflection_machinery_plus_string_corroborates_process_spawn() {
        // setAccessible (structural) + "java.lang.Runtime" / "exec" strings →
        // the obfuscated Class.forName(...).invoke(...) pattern becomes visible.
        let class = fixtures::class_with_refs_and_strings(
            &[(
                "java/lang/reflect/AccessibleObject",
                "setAccessible",
                "(Z)V",
            )],
            &["java.lang.Runtime", "exec"],
        );
        let evidence = crate::cp::extract_class_evidence(&class).unwrap();
        let detections = detect_signals(&evidence);

        let process_spawn = detections
            .iter()
            .find(|d| d.signal == SecuritySignal::ProcessSpawn)
            .expect("process spawn corroborated");
        assert_eq!(
            process_spawn.provenance,
            SignalProvenance::ReflectionCorroborated
        );
        assert_eq!(
            process_spawn.provenance.confidence(),
            CORROBORATED_CONFIDENCE
        );

        // The reflection machinery itself is structural.
        assert!(detections.contains(&DetectedSignal::structural(
            SecuritySignal::ReflectionSetAccessible
        )));
    }

    #[test]
    fn structural_evidence_is_not_downgraded_to_corroborated() {
        // A real Runtime.exec ref plus the matching string must stay structural.
        let class = fixtures::class_with_refs_and_strings(
            &[
                (
                    "java/lang/Runtime",
                    "exec",
                    "(Ljava/lang/String;)Ljava/lang/Process;",
                ),
                (
                    "java/lang/Class",
                    "forName",
                    "(Ljava/lang/String;)Ljava/lang/Class;",
                ),
            ],
            &["java.lang.Runtime", "exec"],
        );
        let evidence = crate::cp::extract_class_evidence(&class).unwrap();
        let detections = detect_signals(&evidence);
        let spawn = detections
            .iter()
            .find(|d| d.signal == SecuritySignal::ProcessSpawn)
            .expect("process spawn present");
        // Stays structural (proven), and the matching string lifts it to High.
        assert_eq!(spawn.provenance, SignalProvenance::Structural);
        assert_eq!(spawn.strength, EvidenceStrength::High);
        // Exactly one entry for the capability — no corroborated duplicate.
        assert_eq!(
            detections
                .iter()
                .filter(|d| d.signal == SecuritySignal::ProcessSpawn)
                .count(),
            1
        );
    }

    #[test]
    fn evidence_strength_tiers_low_medium_high() {
        // Low: corroborated string-only (gated on reflection machinery).
        let class = fixtures::class_with_refs_and_strings(
            &[(
                "java/lang/reflect/AccessibleObject",
                "setAccessible",
                "(Z)V",
            )],
            &["java.lang.Runtime", "exec"],
        );
        let ev = crate::cp::extract_class_evidence(&class).unwrap();
        let spawn = detect_signals(&ev)
            .into_iter()
            .find(|d| d.signal == SecuritySignal::ProcessSpawn)
            .unwrap();
        assert_eq!(spawn.strength, EvidenceStrength::Low);

        // Medium: lone structural reference, no corroborating string.
        let class = fixtures::class_with_method_ref(
            "java/lang/Runtime",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
        );
        let ev = crate::cp::extract_class_evidence(&class).unwrap();
        let spawn = detect_signals(&ev)
            .into_iter()
            .find(|d| d.signal == SecuritySignal::ProcessSpawn)
            .unwrap();
        assert_eq!(spawn.strength, EvidenceStrength::Medium);

        // High: structural reference *and* a corroborating string.
        let class = fixtures::class_with_refs_and_strings(
            &[(
                "java/lang/Runtime",
                "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;",
            )],
            &["java.lang.Runtime"],
        );
        let ev = crate::cp::extract_class_evidence(&class).unwrap();
        let spawn = detect_signals(&ev)
            .into_iter()
            .find(|d| d.signal == SecuritySignal::ProcessSpawn)
            .unwrap();
        assert_eq!(spawn.strength, EvidenceStrength::High);
    }

    #[test]
    fn threshold_requires_two_note_signals_or_one_high_risk() {
        let mut signals = BTreeSet::new();
        signals.insert(SecuritySignal::Socket);
        assert!(!should_emit_finding(&signals));

        signals.insert(SecuritySignal::NativeLibrary);
        assert!(should_emit_finding(&signals));

        let mut high = BTreeSet::new();
        high.insert(SecuritySignal::ProcessSpawn);
        assert!(should_emit_finding(&high));
    }

    #[test]
    fn severity_warn_only_for_high_risk() {
        assert_eq!(SecuritySignal::ProcessSpawn.severity(), Severity::Warn);
        assert_eq!(SecuritySignal::Unsafe.severity(), Severity::Warn);
        assert_eq!(SecuritySignal::ScriptEngine.severity(), Severity::Warn);
        assert_eq!(SecuritySignal::Socket.severity(), Severity::Note);
        assert_eq!(
            SecuritySignal::ReflectionSetAccessible.severity(),
            Severity::Note
        );
        assert_eq!(
            SecuritySignal::ReflectiveInvocation.severity(),
            Severity::Note
        );
    }
}
