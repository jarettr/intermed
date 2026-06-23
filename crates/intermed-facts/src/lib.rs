//! # intermed-facts
//!
//! The **ground truth** layer. Collectors observe a target (a server, an
//! instance, a mods directory, a log file) and emit [`Fact`]s into a
//! [`FactStore`]. Everything downstream — rules, findings, reports — is derived
//! only from facts, never from re-scanning the target.
//!
//! ## Why facts are modelled as predicate + named terms
//!
//! A fact is a Datalog-style predicate: a `kind` (the predicate name, e.g.
//! `mod`, `dependency`, `log_signal`) plus a set of named terms ([`AttrValue`]).
//! This shape is deliberately chosen so that:
//!
//! * Phase 1 imperative rules can match on `kind` + read terms by name.
//! * Phase 5 can lower the same facts into a Datalog IR / SQL rows (DuckDB)
//!   with **no model change** — `kind` becomes the relation, terms become
//!   columns. See `docs/reference/facts.md`.
//!
//! Keep facts as plain data: no behaviour, no references to findings.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub mod schema;

/// Catalog of well-known fact predicates.
///
/// Collectors *should* use these constants rather than ad-hoc strings so rules
/// and the eventual Datalog schema stay in sync. New predicates are added here
/// as layers come online; the type is intentionally a `&str` newtype rather
/// than a closed enum so that out-of-tree rule packs (Phase 5) can introduce
/// their own predicates without recompiling this crate.
pub mod kind {
    // Layer A — environment / target detection
    pub const ENVIRONMENT: &str = "environment";
    pub const JAVA_RUNTIME: &str = "java_runtime";
    pub const TARGET: &str = "target";
    // Layer B — metadata
    pub const MOD: &str = "mod";
    pub const PLUGIN: &str = "plugin";
    /// A jar whose manifest is present but unusable (e.g. no mod id). Recorded
    /// instead of emitting a `mod`/`plugin` fact with a placeholder `?` subject
    /// that would pollute duplicate-id / dependency reasoning.
    pub const INVALID_METADATA: &str = "invalid_metadata";
    /// A second role a jar advertises beyond its primary identity (e.g. a Bukkit
    /// plugin that also ships a `fabric.mod.json` for proxy hooks). Informational
    /// only — no rule consumes it, so it never creates a loader/dep false positive.
    pub const SECONDARY_IDENTITY: &str = "secondary_identity";
    pub const DEPENDENCY: &str = "dependency";
    pub const PROVIDED_DEPENDENCY: &str = "provided_dependency";
    pub const MOD_SIDE: &str = "mod_side";
    pub const ENTRYPOINT: &str = "entrypoint";
    pub const MOD_METADATA: &str = "mod_metadata";
    pub const ENTRYPOINT_DETAIL: &str = "entrypoint_detail";
    /// A class-package root a mod jar owns (`subject` = mod id, `package` = dotted
    /// root like `com.foo.mymod`, `class_count` = classes under it). The
    /// frame-to-jar ownership index: a crash stack frame whose class falls under an
    /// *exclusively*-owned root is attributed to that mod with high confidence.
    pub const PACKAGE_OWNER: &str = "package_owner";
    pub const MOD_RELATIONSHIP: &str = "mod_relationship";
    pub const MOD_CAPABILITY: &str = "mod_capability";
    pub const NESTED_JAR: &str = "nested_jar";
    pub const UNPARSEABLE_ARCHIVE: &str = "unparseable_archive";
    // Modpack manifests (.mrpack / CurseForge export). These describe mods by
    // reference (download url / project id), which may not be materialized on disk.
    pub const MODPACK_MANIFEST: &str = "modpack_manifest";
    pub const MODPACK_FILE_REF: &str = "modpack_file_ref";
    pub const MODPACK_PROJECT_REF: &str = "modpack_project_ref";
    /// Emitted when a manifest references mod jars that are not present on disk,
    /// so dependency/security/SBOM analysis would be incomplete.
    pub const MODPACK_INCOMPLETE: &str = "modpack_incomplete";
    /// A Forge Access Transformer / Fabric-Quilt Access Widener directive that
    /// changes the access of a game (or library) class member.
    pub const ACCESS_TRANSFORM: &str = "access_transform";
    /// A Forge coremod (JS bytecode-manipulation script) declared by a jar.
    pub const COREMOD: &str = "coremod";
    // Layer D — log / crash signals
    pub const LOG_SIGNAL: &str = "log_signal";
    pub const LOG_MENTIONS_MOD: &str = "log_mentions_mod";
    pub const LOG_CRASH: &str = "log_crash";
    pub const LOG_MOD_ERROR: &str = "log_mod_error";
    /// A jar scan was truncated by a per-jar resource limit (entry too large,
    /// total bytes, or entry count) — analysis of that archive is incomplete, so
    /// absence of a finding from it is lower-confidence. Emitted by VFS and
    /// security-audit scanners as a DoS guard against malicious archives.
    pub const SCAN_TRUNCATED: &str = "scan_truncated";
    // Layer E — VFS / resources
    pub const RESOURCE_WRITER: &str = "resource_writer";
    pub const RESOURCE_COLLISION: &str = "resource_collision";
    pub const JSON_MERGE_CANDIDATE: &str = "json_merge_candidate";
    pub const SAFE_CRDT_MERGE: &str = "safe_crdt_merge";
    pub const LANG_JSON_MERGE: &str = "lang_json_merge";
    pub const LANG_PROPERTIES_MERGE: &str = "lang_properties_merge";
    pub const LANG_FORMAT_CONFLICT: &str = "lang_format_conflict";
    pub const UNSAFE_REPLACE_CONFLICT: &str = "unsafe_replace_conflict";
    /// A Minecraft tag JSON collision where at least one writer sets
    /// `"replace": true`. The merged result is order-dependent (a later replace
    /// wipes earlier writers' values), so it is *not* a safe CRDT merge.
    pub const TAG_REPLACE_CONFLICT: &str = "tag_replace_conflict";
    /// A tag JSON collision whose object entries carry `required` flags
    /// (`{"id":..,"required":false}`): set-union is still possible but the
    /// optional/required semantics need review.
    pub const TAG_MIXED_REQUIRED: &str = "tag_mixed_required";
    /// A tag-path JSON collision that does not parse as a valid tag document.
    pub const TAG_INVALID: &str = "tag_invalid";
    /// A domain JSON (recipe / loot table / advancement / blockstate / model /
    /// atlas / pack.mcmeta) written by multiple jars at the same path. These are
    /// single-document files: the runtime keeps one by load order, so this is an
    /// override, not a mergeable union.
    pub const JSON_OVERRIDE_CONFLICT: &str = "json_override_conflict";
    /// A proposed overlay/PackOps action for a resource collision: what an overlay
    /// generator *would* do to resolve it (`action`, `safety`, `writers`,
    /// `requires_manual_review`). Read-only intent — Layer E never writes files.
    pub const RESOURCE_OVERLAY_ACTION: &str = "resource_overlay_action";
    // Layer M — resource / data semantics (typed resource AST). Compact facts
    // lowered from per-resource summaries; rules turn them into findings.
    /// One resource was parsed into its typed AST (`domain`, `parse_status`,
    /// `semantic_hash`, `writer`, `registry`/domain attrs).
    pub const RESOURCE_AST_PARSED: &str = "resource_ast_parsed";
    /// A resource definition a jar provides at a path (`domain`, `namespace`, `writer`).
    pub const RESOURCE_DEFINITION: &str = "resource_definition";
    /// An outgoing semantic reference (`relation`, `to`, `namespace`, `required`,
    /// `conditioned`, `is_tag`) from one resource to a referenced id.
    pub const RESOURCE_REFERENCE: &str = "resource_reference";
    /// A namespace and a mod that owns (defines resources under) it.
    pub const NAMESPACE_OWNER: &str = "namespace_owner";
    /// A dependency implied by a resource reference (e.g. a recipe `type` whose
    /// namespace isn't a definition owner). Layer C decides satisfied/missing.
    pub const IMPLICIT_DEPENDENCY_CANDIDATE: &str = "implicit_dependency_candidate";
    /// A *per-mod* implicit dependency edge: a consumer mod (`subject` = writer)
    /// ships a resource that structurally references a foreign `provider_namespace`
    /// (recipe serializer `type`, worldgen feature, loot function, registry ref…).
    /// Carries `relation`/`via`, `required`, `ref_count`, `sample_path` and the
    /// Layer-M `resolve_state`. Layer C joins these against the *declared* edges to
    /// build the effective-dependency model and surface undisclosed/unused deps.
    pub const IMPLICIT_DEPENDENCY_EDGE: &str = "implicit_dependency_edge";
    /// The resolution of a referenced namespace against the installed world:
    /// `namespace_class` (installed-mod / provided-alias / builtin / … / missing)
    /// and `state` (present / required-missing / optional-missing / …). The
    /// auditable record behind an implicit-dependency conclusion.
    pub const RESOURCE_RESOLVE_RESULT: &str = "resource_resolve_result";
    /// Two writers semantically disagree on the same resource path (`diff_kind`,
    /// `writers`, `detail`) — recipe output override, lang key conflict, etc.
    pub const RESOURCE_SEMANTIC_DIFF: &str = "resource_semantic_diff";
    /// A resource points to another resource that was deleted or overridden.
    pub const RESOURCE_SEMANTIC_CONFLICT: &str = "resource_semantic_conflict";
    /// A per-object parse/validation issue (malformed field, unparseable domain
    /// JSON): the `validate` output of the §4 analyzer contract. Surfaced for
    /// `vfs explain --ast` and a single grouped, explain-only finding — never a
    /// per-file warning (anti-FP).
    pub const RESOURCE_SEMANTIC_ISSUE: &str = "resource_semantic_issue";
    /// Reserved. A model reference with no defining file is *not* emitted as a fact:
    /// mods generate models at runtime (baked / custom loaders) or ship them in
    /// resource packs, so absence is not proof of breakage. Unresolved references
    /// are surfaced only in `vfs explain --ast`, never as a finding. Kept for
    /// schema stability and possible future use with a sound resolver.
    pub const RESOURCE_DANGLING_REFERENCE: &str = "resource_dangling_reference";
    // Layer E — runtime content dynamics (script engines: KubeJS / CraftTweaker).
    // These record what data-pack scripts *removed* at load time, so the evidence
    // graph knows a recipe/item present in a jar is not actually obtainable.
    pub const RUNTIME_REMOVED_RECIPE: &str = "runtime_removed_recipe";
    /// A data-pack script *modifies* (replaces input/output of) a recipe rather
    /// than removing it. Distinct from removal because the recipe still exists but
    /// its static definition is no longer authoritative — enough to caveat a
    /// static recipe finding, not to call it deleted.
    pub const RUNTIME_SCRIPT_MODIFIES_RECIPE: &str = "runtime_script_modifies_recipe";
    pub const RUNTIME_REMOVED_ITEM: &str = "runtime_removed_item";
    pub const RUNTIME_REMOVED_LOOT_TABLE: &str = "runtime_removed_loot_table";
    pub const RUNTIME_REMOVED_TAG: &str = "runtime_removed_tag";
    // Layer F — mixin intelligence
    pub const MIXIN_CONFIG: &str = "mixin_config";
    /// Per-mixin-class activation status and application side (client/server/both),
    /// derived from which config array the mixin came from, any object-form
    /// `environment`, and config plugin gating (plan Phase 1). Lets downstream
    /// analysis stop treating a client-only vs server-only pair as a conflict.
    pub const MIXIN_ACTIVATION: &str = "mixin_activation";
    /// One stable mixin *application site* — the central site-level entity (plan
    /// Phase 2): a single handler→target-method→injection-point tuple with its
    /// side, activation, priority, require/expect/allow and resolution confidence.
    pub const MIXIN_APPLICATION_SITE: &str = "mixin_application_site";
    /// Runtime classpath coverage for one scan (plan Phase 4): which scopes
    /// (Minecraft / mods / libraries / loader) were indexed and at what level, so
    /// absence-based "target class missing" verdicts never exceed their evidence.
    pub const MIXIN_CLASSPATH_COVERAGE: &str = "mixin_classpath_coverage";
    /// Composition of all handlers applied at one exact injection point (plan
    /// Phases 9–10): their application order, roles, and how they compose
    /// (high-conflict / order-sensitive-chain / safe / conditional / impossible).
    pub const MIXIN_COMPOSITION: &str = "mixin_composition";
    /// A grouped, actionable risk diagnosis for one target (plan Phase 13): rolls up
    /// the per-site apply/selector/signature/local/composition evidence into one
    /// verdict with a headline and recommended action.
    pub const MIXIN_RISK_CLUSTER: &str = "mixin_risk_cluster";
    /// A mixin that hooks a Minecraft data loader (`RecipeManager`, `LootManager`,
    /// `TagManagerLoader`, …) and therefore mutates runtime resources — the Layer-F
    /// → Layer-M / Dynamics bridge. Keyed to the same `domain` string Layer M and the
    /// Dynamics layer use, so static datapack analysis can be told it has a runtime
    /// blind spot, and script + mixin mutation of one domain can be correlated.
    pub const MIXIN_RUNTIME_RESOURCE_MUTATION: &str = "mixin_runtime_resource_mutation";
    /// A security-sensitive subsystem a mixin weaves into (Layer F → Layer G):
    /// networking, class loading, (de)serialization, or save IO. Woven code there is
    /// a real audit concern, and compounds with the mod's `uses_*` security facts.
    pub const MIXIN_SECURITY_SURFACE: &str = "mixin_security_surface";
    /// A mixin config declares an `IMixinConfigPlugin`, which can toggle mixins at
    /// load time — static analysis of that config is necessarily incomplete.
    pub const MIXIN_CONFIG_PLUGIN: &str = "mixin_config_plugin";
    /// A mixin config declared a `.refmap.json` (obf↔intermediary↔named name
    /// resolution is available for its injection points).
    pub const MIXIN_REFMAP_LOADED: &str = "mixin_refmap_loaded";
    pub const MIXIN_CLASS: &str = "mixin_class";
    pub const MIXIN_TARGET: &str = "mixin_target";
    pub const MIXIN_OPERATION: &str = "mixin_operation";
    pub const MIXIN_HOTSPOT: &str = "mixin_hotspot";
    pub const MIXIN_OVERLAP: &str = "mixin_overlap";
    pub const HIGH_RISK_OVERWRITE: &str = "high_risk_overwrite";
    pub const LOG_MIXIN_CORRELATION: &str = "log_mixin_correlation";
    // Phase 1-3 new facts
    pub const MIXIN_INJECTION_POINT: &str = "mixin_injection_point";
    pub const MIXIN_SHADOW: &str = "mixin_shadow";
    pub const MIXIN_ADDED_MEMBER: &str = "mixin_added_member";
    pub const MIXIN_CALLS: &str = "mixin_calls";
    pub const MIXIN_INTERACTION: &str = "mixin_interaction";
    pub const MIXIN_CONFLICT_EDGE: &str = "mixin_conflict_edge";
    pub const MIXIN_PRIORITY_CONFLICT: &str = "mixin_priority_conflict";
    pub const MIXIN_RISK_SCORE: &str = "mixin_risk_score";
    pub const MIXIN_HANDLER_BODY: &str = "mixin_handler_body";
    pub const MIXIN_HANDLER_EFFECT: &str = "mixin_handler_effect";
    pub const MIXIN_EFFECT: &str = "mixin_effect";
    pub const MIXIN_RECOMMENDATION: &str = "mixin_recommendation";
    pub const MIXIN_HIERARCHY: &str = "mixin_hierarchy";
    /// Composite complexity score for one mixin class (transparent components).
    pub const MIXIN_CLASS_COMPLEXITY: &str = "mixin_class_complexity";
    /// Aggregate complexity score for one mod's whole mixin footprint.
    pub const MIXIN_MOD_COMPLEXITY: &str = "mixin_mod_complexity";
    /// Low-yield mixin footprint (inert handlers) for one mod.
    pub const MIXIN_BLOAT: &str = "mixin_bloat";
    /// Aggregate dataflow-precision metrics for one scan: how many handlers
    /// resolved precisely vs imprecise, and the breakdown of imprecision reasons.
    /// Measurement signal (plan §0) — never a finding.
    pub const MIXIN_DATAFLOW_METRICS: &str = "mixin_dataflow_metrics";
    // Layer G — security audit
    pub const USES_PROCESS_SPAWN: &str = "uses_process_spawn";
    pub const USES_SOCKET: &str = "uses_socket";
    pub const USES_REFLECTION_SET_ACCESSIBLE: &str = "uses_reflection_set_accessible";
    pub const USES_UNSAFE: &str = "uses_unsafe";
    pub const USES_NATIVE_LIBRARY: &str = "uses_native_library";
    pub const USES_DYNAMIC_CLASS_DEFINITION: &str = "uses_dynamic_class_definition";
    pub const USES_REFLECTIVE_INVOCATION: &str = "uses_reflective_invocation";
    pub const USES_SCRIPT_ENGINE: &str = "uses_script_engine";
    pub const USES_DESERIALIZATION: &str = "uses_deserialization";
    pub const USES_SYSTEM_EXIT: &str = "uses_system_exit";
    pub const USES_METHOD_HANDLES: &str = "uses_method_handles";
    /// Reserved schema kind; Layer G no longer emits this predicate (too noisy for security).
    pub const WRITES_FILES: &str = "writes_files";
    /// A potentially malicious data modification (e.g. wiping core game recipes or tags).
    pub const SECURITY_SUSPECT_MODIFICATION: &str = "security_suspect_modification";
    // Layer H — SBOM / provenance
    pub const CHECKSUM: &str = "checksum";
    pub const ARTIFACT_IDENTITY: &str = "artifact_identity";
    pub const UNKNOWN_SOURCE: &str = "unknown_source";
    pub const SIGNATURE_STATUS: &str = "signature_status";
    pub const SBOM: &str = "sbom";
    pub const TRUST_SCORE: &str = "trust_score";
    // Layer I — performance / spark
    pub const TICK_SPIKE: &str = "tick_spike";
    pub const HOT_METHOD: &str = "hot_method";
    pub const HOT_MOD: &str = "hot_mod";
    pub const GC_PAUSE: &str = "gc_pause";
    pub const HEAP_PRESSURE: &str = "heap_pressure";
    pub const THREAD_HOTSPOT: &str = "thread_hotspot";
    pub const SPARK_IMPORT_FAILURE: &str = "spark_import_failure";
    // Cross-layer
    pub const DEFERRED_LAYER: &str = "deferred_layer";
}

/// A single typed term value attached to a [`Fact`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttrValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl AttrValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttrValue::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Read as `f64`. Only native `Float` and `Int` values are accepted; string
    /// attributes (including numeric-looking text) are **not** coerced.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            AttrValue::Float(f) => Some(*f),
            AttrValue::Int(i) => Some(*i as f64),
            AttrValue::Str(_) | AttrValue::Bool(_) => None,
        }
    }
}

impl From<&str> for AttrValue {
    fn from(v: &str) -> Self {
        AttrValue::Str(v.to_string())
    }
}
impl From<String> for AttrValue {
    fn from(v: String) -> Self {
        AttrValue::Str(v)
    }
}
impl From<i64> for AttrValue {
    fn from(v: i64) -> Self {
        AttrValue::Int(v)
    }
}
impl From<f64> for AttrValue {
    fn from(v: f64) -> Self {
        AttrValue::Float(v)
    }
}
impl From<bool> for AttrValue {
    fn from(v: bool) -> Self {
        AttrValue::Bool(v)
    }
}

/// Where a fact came from, for provenance / `--explain` (Phase 2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceRef {
    /// File or archive the fact was observed in (relative to the target root
    /// where possible).
    pub locator: String,
    /// Optional 1-based line number (for log/text sources).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Optional inner path (e.g. `fabric.mod.json` inside a jar).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner: Option<String>,
}

impl SourceRef {
    pub fn file(locator: impl Into<String>) -> Self {
        Self {
            locator: locator.into(),
            line: None,
            inner: None,
        }
    }
    pub fn at_line(locator: impl Into<String>, line: u32) -> Self {
        Self {
            locator: locator.into(),
            line: Some(line),
            inner: None,
        }
    }
    pub fn inside(locator: impl Into<String>, inner: impl Into<String>) -> Self {
        Self {
            locator: locator.into(),
            line: None,
            inner: Some(inner.into()),
        }
    }
}

/// A monotonically assigned identifier, unique within a [`FactStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FactId(pub u64);

impl std::fmt::Display for FactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "f{}", self.0)
    }
}

/// An observed, atomic statement about the target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fact {
    pub id: FactId,
    /// Predicate name; see [`kind`].
    pub kind: String,
    /// Primary subject of the statement (e.g. a mod id). May be empty for
    /// environment-level facts.
    pub subject: String,
    /// Named terms.
    pub attributes: BTreeMap<String, AttrValue>,
    /// Provenance.
    pub source: SourceRef,
    /// 0.0..=1.0 — how certain the extractor is.
    pub confidence: f32,
    /// Id of the collector that produced this fact.
    pub extractor: String,
}

impl Fact {
    /// Read a string-valued attribute.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(AttrValue::as_str)
    }

    /// Read a bool-valued attribute.
    pub fn attr_bool(&self, key: &str) -> Option<bool> {
        match self.attributes.get(key)? {
            AttrValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Read an int-valued attribute.
    pub fn attr_int(&self, key: &str) -> Option<i64> {
        match self.attributes.get(key)? {
            AttrValue::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Read a numeric attribute as `f64` (`Float` or `Int` only). Use this for
    /// thresholds that must compare numerically; store values as numbers, not
    /// formatted strings.
    pub fn attr_f64(&self, key: &str) -> Option<f64> {
        self.attributes.get(key).and_then(AttrValue::as_f64)
    }
}

/// A fact under construction. Obtained from [`FactStore::fact`]; the id is
/// assigned on [`FactBuilder::emit`].
#[must_use = "call .emit() to record the fact"]
pub struct FactBuilder<'s> {
    store: &'s mut FactStore,
    kind: String,
    subject: String,
    attributes: BTreeMap<String, AttrValue>,
    source: SourceRef,
    confidence: f32,
    extractor: String,
}

impl<'s> FactBuilder<'s> {
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }
    pub fn attr(mut self, key: &str, value: impl Into<AttrValue>) -> Self {
        self.attributes.insert(key.to_string(), value.into());
        self
    }
    pub fn source(mut self, source: SourceRef) -> Self {
        self.source = source;
        self
    }
    pub fn confidence(mut self, c: f32) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }
    /// Record the fact and return its assigned id.
    pub fn emit(self) -> FactId {
        let id = FactId(self.store.next_id);
        self.store.next_id += 1;
        let idx = self.store.facts.len();
        let kind = self.kind.clone();
        self.store.facts.push(Fact {
            id,
            kind,
            subject: self.subject,
            attributes: self.attributes,
            source: self.source,
            confidence: self.confidence,
            extractor: self.extractor,
        });
        self.store
            .kind_index
            .entry(self.store.facts[idx].kind.clone())
            .or_default()
            .push(idx);
        self.store
            .subject_index
            .entry(self.store.facts[idx].subject.clone())
            .or_default()
            .push(idx);
        self.store.id_index.insert(id, idx);
        id
    }
}

/// Policy for dropping verbose low-signal facts when the store grows large.
///
/// Collectors emit many mixin bytecode facts; rules rarely need all of them.
/// Compaction keeps predicates required for findings and drops the rest once
/// `max_facts` is exceeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactRetentionPolicy {
    /// When `facts.len()` exceeds this, [`FactStore::compact`] runs automatically.
    pub max_facts: usize,
    /// Predicates always retained (findings depend on these).
    pub keep_kinds: BTreeSet<String>,
}

impl Default for FactRetentionPolicy {
    fn default() -> Self {
        let mut keep = BTreeSet::new();
        for k in [
            kind::MOD,
            kind::PLUGIN,
            kind::DEPENDENCY,
            kind::PROVIDED_DEPENDENCY,
            kind::MOD_SIDE,
            kind::ENVIRONMENT,
            kind::JAVA_RUNTIME,
            kind::TARGET,
            kind::LOG_SIGNAL,
            kind::LOG_MENTIONS_MOD,
            kind::RESOURCE_COLLISION,
            kind::RESOURCE_WRITER,
            kind::RESOURCE_OVERLAY_ACTION,
            kind::RUNTIME_REMOVED_RECIPE,
            kind::RUNTIME_REMOVED_ITEM,
            kind::RUNTIME_REMOVED_LOOT_TABLE,
            kind::RUNTIME_REMOVED_TAG,
            kind::RUNTIME_SCRIPT_MODIFIES_RECIPE,
            kind::MODPACK_INCOMPLETE,
            kind::MODPACK_MANIFEST,
            kind::MIXIN_OVERLAP,
            kind::MIXIN_DATAFLOW_METRICS,
            kind::MIXIN_EFFECT,
            kind::HIGH_RISK_OVERWRITE,
            // Site-level overhaul (plan Phases 1–14): conclusion-bearing diagnoses.
            // The verbose per-site `mixin_application_site` stays droppable (like
            // `mixin_injection_point`) — preserved only when a finding cites it.
            kind::MIXIN_ACTIVATION,
            kind::MIXIN_CLASSPATH_COVERAGE,
            kind::MIXIN_COMPOSITION,
            kind::MIXIN_RISK_CLUSTER,
            kind::MIXIN_RUNTIME_RESOURCE_MUTATION,
            kind::MIXIN_SECURITY_SURFACE,
            kind::SBOM,
            kind::UNKNOWN_SOURCE,
            kind::SIGNATURE_STATUS,
            kind::TRUST_SCORE,
            kind::USES_PROCESS_SPAWN,
            kind::USES_UNSAFE,
            kind::USES_DYNAMIC_CLASS_DEFINITION,
            kind::USES_SCRIPT_ENGINE,
            kind::USES_SOCKET,
            kind::USES_REFLECTION_SET_ACCESSIBLE,
            kind::USES_NATIVE_LIBRARY,
            kind::USES_DESERIALIZATION,
            kind::USES_SYSTEM_EXIT,
            kind::USES_METHOD_HANDLES,
            kind::SECURITY_SUSPECT_MODIFICATION,
            kind::DEFERRED_LAYER,
            // Layer M — keep the *compact* conclusion-bearing facts; the verbose
            // per-edge `resource_reference` / `resource_definition` are evidence
            // only and remain droppable (preserved when a finding cites them).
            kind::RESOURCE_AST_PARSED,
            kind::RESOURCE_SEMANTIC_DIFF,
            kind::RESOURCE_SEMANTIC_CONFLICT,
            kind::RESOURCE_SEMANTIC_ISSUE,
            kind::IMPLICIT_DEPENDENCY_CANDIDATE,
            kind::RESOURCE_RESOLVE_RESULT,
            kind::NAMESPACE_OWNER,
        ] {
            keep.insert(k.to_string());
        }
        Self {
            max_facts: 50_000,
            keep_kinds: keep,
        }
    }
}

/// Append-only store of facts gathered during one diagnosis run.
#[derive(Debug, Default)]
pub struct FactStore {
    facts: Vec<Fact>,
    next_id: u64,
    /// Per-predicate index into `facts` for O(1) kind lookup.
    kind_index: BTreeMap<String, Vec<usize>>,
    /// Per-subject index into `facts`. Lets cross-fact passes (suppression /
    /// finding merge, Layer-M ↔ Layer-E correlation) join on the shared subject
    /// (usually a resource path or mod id) without an O(n·m) scan.
    subject_index: BTreeMap<String, Vec<usize>>,
    /// FactId → position in `facts`. Required because ids are monotonic and
    /// stable across [`FactStore::compact`], so `id.0` is *not* the slot index
    /// once any fact has been dropped. See `get_still_works_after_compaction`.
    id_index: BTreeMap<FactId, usize>,
}

impl FactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin building a fact. `extractor` is the producing collector's id.
    pub fn fact(&mut self, extractor: &str, kind: &str) -> FactBuilder<'_> {
        let extractor = extractor.to_string();
        FactBuilder {
            store: self,
            kind: kind.to_string(),
            subject: String::new(),
            attributes: BTreeMap::new(),
            source: SourceRef::file("<unknown>"),
            confidence: 1.0,
            extractor,
        }
    }

    pub fn all(&self) -> &[Fact] {
        &self.facts
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    /// All facts with the given predicate (indexed; O(k) not O(n)).
    pub fn by_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a Fact> + 'a {
        let facts = &self.facts;
        self.kind_index
            .get(kind)
            .into_iter()
            .flatten()
            .copied()
            .map(move |i| &facts[i])
    }

    /// All facts with the given subject (indexed; O(k) not O(n)). Used by passes
    /// that correlate facts sharing a subject — e.g. a Layer-M semantic diff and
    /// a Layer-E byte collision on the same resource path.
    pub fn by_subject<'a>(&'a self, subject: &'a str) -> impl Iterator<Item = &'a Fact> + 'a {
        let facts = &self.facts;
        self.subject_index
            .get(subject)
            .into_iter()
            .flatten()
            .copied()
            .map(move |i| &facts[i])
    }

    /// All facts with the given predicate **and** subject. Intersects the kind
    /// and subject indexes, scanning the smaller postings list.
    pub fn by_kind_subject<'a>(
        &'a self,
        kind: &'a str,
        subject: &'a str,
    ) -> impl Iterator<Item = &'a Fact> + 'a {
        let facts = &self.facts;
        let by_kind = self.kind_index.get(kind);
        let by_subject = self.subject_index.get(subject);
        // Walk whichever postings list is shorter, filtering by the other axis.
        let (drive, want_subject) = match (by_kind, by_subject) {
            (Some(k), Some(s)) if k.len() <= s.len() => (Some(k), true),
            (Some(_), Some(s)) => (Some(s), false),
            _ => (None, false),
        };
        drive
            .into_iter()
            .flatten()
            .copied()
            .map(move |i| &facts[i])
            .filter(move |f| {
                if want_subject {
                    f.subject == subject
                } else {
                    f.kind == kind
                }
            })
    }

    /// Drop verbose facts not listed in `policy.keep_kinds` when over `max_facts`.
    ///
    /// Rebuilds ids and the kind index. Returns how many facts were removed.
    pub fn compact(&mut self, policy: &FactRetentionPolicy) -> usize {
        self.compact_preserving(policy, &BTreeSet::new())
    }

    /// Like [`FactStore::compact`], but never drops a fact whose id is in
    /// `keep_ids`. Evidence edges on findings cite facts by id; dropping a cited
    /// fact left the report rendering it as a bare `fact #N` with no kind,
    /// subject, or source. The engine passes every fact id referenced by a
    /// finding's evidence here so provenance always resolves.
    pub fn compact_preserving(
        &mut self,
        policy: &FactRetentionPolicy,
        keep_ids: &BTreeSet<FactId>,
    ) -> usize {
        if self.facts.len() <= policy.max_facts {
            return 0;
        }
        let before = self.facts.len();
        let retained: Vec<Fact> = self
            .facts
            .iter()
            .filter(|f| policy.keep_kinds.contains(&f.kind) || keep_ids.contains(&f.id))
            .cloned()
            .collect();
        if retained.len() >= before {
            return 0;
        }
        self.facts = retained;
        self.rebuild_index();
        before.saturating_sub(self.facts.len())
    }

    fn rebuild_index(&mut self) {
        self.kind_index.clear();
        self.subject_index.clear();
        self.id_index.clear();
        for (idx, fact) in self.facts.iter().enumerate() {
            self.kind_index
                .entry(fact.kind.clone())
                .or_default()
                .push(idx);
            self.subject_index
                .entry(fact.subject.clone())
                .or_default()
                .push(idx);
            self.id_index.insert(fact.id, idx);
        }
        // Ids are *not* renumbered: existing FactIds (e.g. held by findings'
        // evidence edges) must stay valid after compaction. next_id continues
        // monotonically past the largest surviving id.
        self.next_id = self
            .facts
            .iter()
            .map(|f| f.id.0)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);
    }

    /// Per-predicate counts, for report fact-stats.
    pub fn stats(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for f in &self.facts {
            *m.entry(f.kind.clone()).or_insert(0) += 1;
        }
        m
    }

    /// Lookup by fact id, used by `doctor --explain` and evidence resolution.
    ///
    /// Resolves through `id_index` rather than treating `id.0` as a slot index,
    /// so it stays correct after [`FactStore::compact`] has dropped facts.
    pub fn get(&self, id: FactId) -> Option<&Fact> {
        self.id_index.get(&id).and_then(|&idx| self.facts.get(idx))
    }

    /// Rehydrate a store from a prior diagnosis snapshot (`--dump-facts` round-trip).
    pub fn from_snapshot(facts: Vec<Fact>) -> Self {
        let next_id = facts
            .iter()
            .map(|f| f.id.0)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);
        let mut store = Self {
            facts,
            next_id,
            kind_index: BTreeMap::new(),
            subject_index: BTreeMap::new(),
            id_index: BTreeMap::new(),
        };
        store.rebuild_index();
        store
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_and_queries_by_kind() {
        let mut store = FactStore::new();
        store
            .fact("test", kind::MOD)
            .subject("sodium")
            .attr("version", "0.5.3")
            .attr("loader", "fabric")
            .source(SourceRef::inside("sodium.jar", "fabric.mod.json"))
            .emit();
        store.fact("test", kind::MOD).subject("iris").emit();

        assert_eq!(store.len(), 2);
        let mods: Vec<_> = store.by_kind(kind::MOD).collect();
        assert_eq!(mods.len(), 2);
        assert_eq!(mods[0].attr("version"), Some("0.5.3"));
        assert_eq!(store.stats().get(kind::MOD), Some(&2));
    }

    #[test]
    fn confidence_is_clamped() {
        let mut store = FactStore::new();
        let id = store.fact("t", kind::MOD).confidence(5.0).emit();
        assert_eq!(store.all()[0].id, id);
        assert_eq!(store.all()[0].confidence, 1.0);
    }

    #[test]
    fn kind_index_matches_linear_scan() {
        let mut store = FactStore::new();
        store.fact("t", kind::MOD).subject("a").emit();
        store.fact("t", kind::MOD).subject("b").emit();
        store.fact("t", kind::PLUGIN).subject("c").emit();
        let indexed: Vec<_> = store
            .by_kind(kind::MOD)
            .map(|f| f.subject.as_str())
            .collect();
        assert_eq!(indexed, vec!["a", "b"]);
    }

    #[test]
    fn subject_and_kind_subject_indexes_match_linear_scan() {
        let mut store = FactStore::new();
        store
            .fact("t", kind::RESOURCE_COLLISION)
            .subject("p.json")
            .emit();
        store
            .fact("t", kind::RESOURCE_SEMANTIC_DIFF)
            .subject("p.json")
            .emit();
        store
            .fact("t", kind::RESOURCE_COLLISION)
            .subject("other.json")
            .emit();

        // by_subject returns every fact on that subject regardless of kind.
        let on_path: Vec<_> = store
            .by_subject("p.json")
            .map(|f| f.kind.as_str())
            .collect();
        assert_eq!(on_path.len(), 2);
        assert!(on_path.contains(&kind::RESOURCE_COLLISION));
        assert!(on_path.contains(&kind::RESOURCE_SEMANTIC_DIFF));

        // by_kind_subject intersects both axes.
        let coll: Vec<_> = store
            .by_kind_subject(kind::RESOURCE_COLLISION, "p.json")
            .map(|f| f.subject.as_str())
            .collect();
        assert_eq!(coll, vec!["p.json"]);
        assert_eq!(
            store
                .by_kind_subject(kind::RESOURCE_COLLISION, "missing")
                .count(),
            0
        );
        assert_eq!(store.by_subject("missing").count(), 0);
    }

    #[test]
    fn subject_index_survives_compaction() {
        let mut store = FactStore::new();
        for i in 0..100 {
            store
                .fact("mixin", kind::MIXIN_HANDLER_BODY)
                .subject(format!("m{i}"))
                .emit();
        }
        store.fact("meta", kind::MOD).subject("alpha").emit();
        let policy = FactRetentionPolicy {
            max_facts: 10,
            ..FactRetentionPolicy::default()
        };
        store.compact(&policy);
        // Subject index was rebuilt: the surviving fact is still reachable.
        assert_eq!(store.by_subject("alpha").count(), 1);
    }

    #[test]
    fn compact_drops_verbose_mixin_facts() {
        let mut store = FactStore::new();
        for i in 0..100 {
            store
                .fact("mixin", kind::MIXIN_HANDLER_BODY)
                .subject(format!("m{i}"))
                .emit();
        }
        store.fact("meta", kind::MOD).subject("alpha").emit();
        let policy = FactRetentionPolicy {
            max_facts: 10,
            ..FactRetentionPolicy::default()
        };
        let dropped = store.compact(&policy);
        assert!(dropped > 0);
        assert_eq!(store.by_kind(kind::MOD).count(), 1);
        assert_eq!(store.by_kind(kind::MIXIN_HANDLER_BODY).count(), 0);
    }

    #[test]
    fn compact_preserving_keeps_cited_facts() {
        let mut store = FactStore::new();
        let mut cited = std::collections::BTreeSet::new();
        for i in 0..100 {
            let id = store
                .fact("mixin", kind::MIXIN_HANDLER_BODY)
                .subject(format!("m{i}"))
                .emit();
            // Cite a verbose fact whose kind would otherwise be dropped.
            if i == 7 {
                cited.insert(id);
            }
        }
        let policy = FactRetentionPolicy {
            max_facts: 10,
            ..FactRetentionPolicy::default()
        };
        let dropped = store.compact_preserving(&policy, &cited);
        assert!(dropped > 0);
        // The cited verbose fact survives even though its kind is not retained.
        let cited_id = *cited.iter().next().unwrap();
        let f = store.get(cited_id).expect("cited fact preserved");
        assert_eq!(f.subject, "m7");
    }

    #[test]
    fn get_still_works_after_compaction() {
        let mut store = FactStore::new();
        for i in 0..100 {
            store
                .fact("mixin", kind::MIXIN_HANDLER_BODY)
                .subject(format!("m{i}"))
                .emit();
        }
        let kept = store.fact("meta", kind::MOD).subject("alpha").emit();

        let policy = FactRetentionPolicy {
            max_facts: 10,
            ..FactRetentionPolicy::default()
        };
        let dropped = store.compact(&policy);
        assert!(dropped > 0);

        // The kept fact has a high FactId but now lives at a low slot index.
        // The slot-index bug returned None here; id_index resolves it.
        let f = store
            .get(kept)
            .expect("kept fact resolvable after compaction");
        assert_eq!(f.subject, "alpha");
        assert_eq!(f.id, kept);

        // Dropped ids resolve to None, not to some unrelated fact.
        assert!(store.get(FactId(0)).is_none());
    }

    #[test]
    fn get_resolves_correct_fact_before_compaction() {
        let mut store = FactStore::new();
        let a = store.fact("t", kind::MOD).subject("a").emit();
        let b = store.fact("t", kind::MOD).subject("b").emit();
        assert_eq!(store.get(a).unwrap().subject, "a");
        assert_eq!(store.get(b).unwrap().subject, "b");
    }

    #[test]
    fn attr_f64_reads_float_and_int_only() {
        let mut store = FactStore::new();
        store
            .fact("t", kind::HOT_METHOD)
            .subject("c")
            .attr("native", 42.5_f64)
            .attr("as_int", 7_i64)
            .attr("as_str", "12.25")
            .attr("not_num", "abc")
            .emit();
        let f = &store.all()[0];
        assert_eq!(f.attr_f64("native"), Some(42.5));
        assert_eq!(f.attr_f64("as_int"), Some(7.0));
        assert_eq!(f.attr_f64("as_str"), None);
        assert_eq!(f.attr_f64("not_num"), None);
        assert_eq!(f.attr_f64("missing"), None);
    }
}
