//! Well-known fact predicates shared by collectors and rules.

// Layer A — environment / target detection
pub const ENVIRONMENT: &str = "environment";
pub const ANALYSIS_ENVIRONMENT: &str = "analysis_environment";
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
/// One descriptor-declared role of a physical artifact. Unlike `mod`/`plugin`,
/// candidate roles are observations and may be inactive or unresolved for the
/// current target loader.
pub const ARTIFACT_ROLE: &str = "artifact_role";
pub const DEPENDENCY: &str = "dependency";
/// Lossless loader-specific dependency expression (currently Quilt any/all/
/// unless/environment). Layer C evaluates this as a group instead of treating
/// its atoms as independent mandatory edges.
pub const DEPENDENCY_EXPRESSION: &str = "dependency_expression";
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
/// A class symbol referenced by a mod's ordinary bytecode constant pool.
/// This is a bounded structural usage edge, not proof that the call executes.
pub const BYTECODE_REFERENCE: &str = "bytecode_reference";
pub const BYTECODE_CALL_EDGE: &str = "bytecode_call_edge";
pub const CALL_SLICE_COVERAGE: &str = "call_slice_coverage";
pub const SCRIPT_DISCOVERY_COVERAGE: &str = "script_discovery_coverage";
pub const MOD_RELATIONSHIP: &str = "mod_relationship";
pub const MOD_CAPABILITY: &str = "mod_capability";
pub const NESTED_JAR: &str = "nested_jar";
/// A loader-compatibility bridge installed in the target. This is evidence
/// that cross-loader descriptors may be intentional; it does not by itself
/// prove every foreign artifact is supported.
pub const COMPATIBILITY_BRIDGE: &str = "compatibility_bridge";
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
/// A normalized semantic log event (logger record plus continuation lines).
pub const RUNTIME_EVENT: &str = "runtime_event";
/// One throwable in an event's structured exception chain.
pub const THROWABLE_NODE: &str = "throwable_node";
/// One parsed stack frame with platform/framework/mod classification.
pub const STACK_FRAME: &str = "stack_frame";
/// A fatal/uncaught/loader-exit event around which causal ranking is built.
pub const CRASH_ANCHOR: &str = "crash_anchor";
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
/// A neutral, non-interpretive observation that a platform-namespace resource
/// has a structurally notable property (e.g. a `minecraft:` tag with `replace=true`,
/// or a `minecraft:` recipe with `output_count=0`). Carries `observation`,
/// `namespace`, and `writer` attributes. Rules read this fact to decide whether the
/// property constitutes a security concern — the AST never decides for them.
pub const RESOURCE_PLATFORM_OBSERVATION: &str = "resource_platform_observation";
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
/// Canonical typed mutation emitted by static script parsing and runtime log
/// observation. Legacy runtime_* predicates remain compatibility projections.
pub const SCRIPT_MUTATION: &str = "script_mutation";
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
pub const MIXIN_RESOURCE_HOOK: &str = "mixin_resource_hook";
/// A security-sensitive subsystem a mixin weaves into (Layer F → Layer G):
/// networking, class loading, (de)serialization, or save IO. Woven code there is
/// a real audit concern, and compounds with the mod's `uses_*` security facts.
pub const MIXIN_SECURITY_SURFACE: &str = "mixin_security_surface";
/// A mixin config declares an `IMixinConfigPlugin`, which can toggle mixins at
/// load time — static analysis of that config is necessarily incomplete.
pub const MIXIN_CONFIG_PLUGIN: &str = "mixin_config_plugin";
/// A mixin config's declared `.refmap.json` was successfully read and parsed,
/// so obf↔intermediary↔named resolution is available for its injection points.
pub const MIXIN_REFMAP_LOADED: &str = "mixin_refmap_loaded";
pub const MIXIN_REFMAP_STATUS: &str = "mixin_refmap_status";
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

/// Authoritative producer/semantic owner of a fact predicate. Keeping this next
/// to the canonical kind registry prevents policy code from inferring ownership
/// from spelling conventions such as `mixin_*` or `resource_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactLayer {
    TargetDetection,
    Metadata,
    Dependency,
    Log,
    Resource,
    Mixin,
    Security,
    Sbom,
    Performance,
    Rules,
    DataSemantics,
}

#[must_use]
pub fn layer(kind: &str) -> Option<FactLayer> {
    Some(match kind {
        ENVIRONMENT | ANALYSIS_ENVIRONMENT | JAVA_RUNTIME | TARGET | SCAN_TRUNCATED => {
            FactLayer::TargetDetection
        }
        MOD
        | PLUGIN
        | INVALID_METADATA
        | SECONDARY_IDENTITY
        | ARTIFACT_ROLE
        | MOD_SIDE
        | ENTRYPOINT
        | MOD_METADATA
        | ENTRYPOINT_DETAIL
        | PACKAGE_OWNER
        | BYTECODE_REFERENCE
        | BYTECODE_CALL_EDGE
        | CALL_SLICE_COVERAGE
        | SCRIPT_DISCOVERY_COVERAGE
        | MOD_RELATIONSHIP
        | MOD_CAPABILITY
        | NESTED_JAR
        | COMPATIBILITY_BRIDGE
        | UNPARSEABLE_ARCHIVE
        | MODPACK_MANIFEST
        | MODPACK_FILE_REF
        | MODPACK_PROJECT_REF
        | MODPACK_INCOMPLETE
        | ACCESS_TRANSFORM
        | COREMOD => FactLayer::Metadata,
        DEPENDENCY
        | DEPENDENCY_EXPRESSION
        | PROVIDED_DEPENDENCY
        | IMPLICIT_DEPENDENCY_CANDIDATE
        | IMPLICIT_DEPENDENCY_EDGE => FactLayer::Dependency,
        LOG_SIGNAL | LOG_MENTIONS_MOD | LOG_CRASH | LOG_MOD_ERROR | RUNTIME_EVENT
        | THROWABLE_NODE | STACK_FRAME | CRASH_ANCHOR => FactLayer::Log,
        RESOURCE_WRITER
        | RESOURCE_COLLISION
        | JSON_MERGE_CANDIDATE
        | SAFE_CRDT_MERGE
        | LANG_JSON_MERGE
        | LANG_PROPERTIES_MERGE
        | LANG_FORMAT_CONFLICT
        | UNSAFE_REPLACE_CONFLICT
        | TAG_REPLACE_CONFLICT
        | TAG_MIXED_REQUIRED
        | TAG_INVALID
        | JSON_OVERRIDE_CONFLICT
        | RESOURCE_OVERLAY_ACTION => FactLayer::Resource,
        RESOURCE_AST_PARSED
        | RESOURCE_DEFINITION
        | RESOURCE_REFERENCE
        | NAMESPACE_OWNER
        | RESOURCE_RESOLVE_RESULT
        | RESOURCE_SEMANTIC_DIFF
        | RESOURCE_SEMANTIC_CONFLICT
        | RESOURCE_SEMANTIC_ISSUE
        | RESOURCE_PLATFORM_OBSERVATION
        | RESOURCE_DANGLING_REFERENCE
        | RUNTIME_REMOVED_RECIPE
        | RUNTIME_SCRIPT_MODIFIES_RECIPE
        | RUNTIME_REMOVED_ITEM
        | RUNTIME_REMOVED_LOOT_TABLE
        | RUNTIME_REMOVED_TAG
        | SCRIPT_MUTATION => FactLayer::DataSemantics,
        MIXIN_CONFIG
        | MIXIN_ACTIVATION
        | MIXIN_APPLICATION_SITE
        | MIXIN_CLASSPATH_COVERAGE
        | MIXIN_COMPOSITION
        | MIXIN_RISK_CLUSTER
        | MIXIN_RUNTIME_RESOURCE_MUTATION
        | MIXIN_RESOURCE_HOOK
        | MIXIN_SECURITY_SURFACE
        | MIXIN_CONFIG_PLUGIN
        | MIXIN_REFMAP_LOADED
        | MIXIN_REFMAP_STATUS
        | MIXIN_CLASS
        | MIXIN_TARGET
        | MIXIN_OPERATION
        | MIXIN_HOTSPOT
        | MIXIN_OVERLAP
        | HIGH_RISK_OVERWRITE
        | LOG_MIXIN_CORRELATION
        | MIXIN_INJECTION_POINT
        | MIXIN_SHADOW
        | MIXIN_ADDED_MEMBER
        | MIXIN_CALLS
        | MIXIN_INTERACTION
        | MIXIN_CONFLICT_EDGE
        | MIXIN_PRIORITY_CONFLICT
        | MIXIN_RISK_SCORE
        | MIXIN_HANDLER_BODY
        | MIXIN_HANDLER_EFFECT
        | MIXIN_EFFECT
        | MIXIN_RECOMMENDATION
        | MIXIN_HIERARCHY
        | MIXIN_CLASS_COMPLEXITY
        | MIXIN_MOD_COMPLEXITY
        | MIXIN_BLOAT
        | MIXIN_DATAFLOW_METRICS => FactLayer::Mixin,
        USES_PROCESS_SPAWN
        | USES_SOCKET
        | USES_REFLECTION_SET_ACCESSIBLE
        | USES_UNSAFE
        | USES_NATIVE_LIBRARY
        | USES_DYNAMIC_CLASS_DEFINITION
        | USES_REFLECTIVE_INVOCATION
        | USES_SCRIPT_ENGINE
        | USES_DESERIALIZATION
        | USES_SYSTEM_EXIT
        | USES_METHOD_HANDLES
        | WRITES_FILES => FactLayer::Security,
        CHECKSUM | ARTIFACT_IDENTITY | UNKNOWN_SOURCE | SIGNATURE_STATUS | SBOM | TRUST_SCORE => {
            FactLayer::Sbom
        }
        TICK_SPIKE | HOT_METHOD | HOT_MOD | GC_PAUSE | HEAP_PRESSURE | THREAD_HOTSPOT
        | SPARK_IMPORT_FAILURE => FactLayer::Performance,
        DEFERRED_LAYER => FactLayer::Rules,
        _ => return None,
    })
}

/// Every fact-kind predicate declared in this module, in declaration order.
///
/// This is the canonical registry used by the schema-contract gate
/// (`tests/schema_gate.rs`): every kind here must have a `schema.toml` entry,
/// and every emitted kind must appear here. A test parses this file to ensure
/// the registry never drifts from the `pub const` declarations above.
#[must_use]
pub fn all_kinds() -> &'static [&'static str] {
    &[
        ENVIRONMENT,
        ANALYSIS_ENVIRONMENT,
        JAVA_RUNTIME,
        TARGET,
        MOD,
        PLUGIN,
        INVALID_METADATA,
        SECONDARY_IDENTITY,
        ARTIFACT_ROLE,
        DEPENDENCY,
        DEPENDENCY_EXPRESSION,
        PROVIDED_DEPENDENCY,
        MOD_SIDE,
        ENTRYPOINT,
        MOD_METADATA,
        ENTRYPOINT_DETAIL,
        PACKAGE_OWNER,
        BYTECODE_REFERENCE,
        BYTECODE_CALL_EDGE,
        CALL_SLICE_COVERAGE,
        SCRIPT_DISCOVERY_COVERAGE,
        MOD_RELATIONSHIP,
        MOD_CAPABILITY,
        NESTED_JAR,
        COMPATIBILITY_BRIDGE,
        UNPARSEABLE_ARCHIVE,
        MODPACK_MANIFEST,
        MODPACK_FILE_REF,
        MODPACK_PROJECT_REF,
        MODPACK_INCOMPLETE,
        ACCESS_TRANSFORM,
        COREMOD,
        LOG_SIGNAL,
        LOG_MENTIONS_MOD,
        LOG_CRASH,
        LOG_MOD_ERROR,
        RUNTIME_EVENT,
        THROWABLE_NODE,
        STACK_FRAME,
        CRASH_ANCHOR,
        SCAN_TRUNCATED,
        RESOURCE_WRITER,
        RESOURCE_COLLISION,
        JSON_MERGE_CANDIDATE,
        SAFE_CRDT_MERGE,
        LANG_JSON_MERGE,
        LANG_PROPERTIES_MERGE,
        LANG_FORMAT_CONFLICT,
        UNSAFE_REPLACE_CONFLICT,
        TAG_REPLACE_CONFLICT,
        TAG_MIXED_REQUIRED,
        TAG_INVALID,
        JSON_OVERRIDE_CONFLICT,
        RESOURCE_OVERLAY_ACTION,
        RESOURCE_AST_PARSED,
        RESOURCE_DEFINITION,
        RESOURCE_REFERENCE,
        NAMESPACE_OWNER,
        IMPLICIT_DEPENDENCY_CANDIDATE,
        IMPLICIT_DEPENDENCY_EDGE,
        RESOURCE_RESOLVE_RESULT,
        RESOURCE_SEMANTIC_DIFF,
        RESOURCE_SEMANTIC_CONFLICT,
        RESOURCE_SEMANTIC_ISSUE,
        RESOURCE_PLATFORM_OBSERVATION,
        RESOURCE_DANGLING_REFERENCE,
        RUNTIME_REMOVED_RECIPE,
        RUNTIME_SCRIPT_MODIFIES_RECIPE,
        RUNTIME_REMOVED_ITEM,
        RUNTIME_REMOVED_LOOT_TABLE,
        RUNTIME_REMOVED_TAG,
        SCRIPT_MUTATION,
        MIXIN_CONFIG,
        MIXIN_ACTIVATION,
        MIXIN_APPLICATION_SITE,
        MIXIN_CLASSPATH_COVERAGE,
        MIXIN_COMPOSITION,
        MIXIN_RISK_CLUSTER,
        MIXIN_RUNTIME_RESOURCE_MUTATION,
        MIXIN_RESOURCE_HOOK,
        MIXIN_SECURITY_SURFACE,
        MIXIN_CONFIG_PLUGIN,
        MIXIN_REFMAP_LOADED,
        MIXIN_REFMAP_STATUS,
        MIXIN_CLASS,
        MIXIN_TARGET,
        MIXIN_OPERATION,
        MIXIN_HOTSPOT,
        MIXIN_OVERLAP,
        HIGH_RISK_OVERWRITE,
        LOG_MIXIN_CORRELATION,
        MIXIN_INJECTION_POINT,
        MIXIN_SHADOW,
        MIXIN_ADDED_MEMBER,
        MIXIN_CALLS,
        MIXIN_INTERACTION,
        MIXIN_CONFLICT_EDGE,
        MIXIN_PRIORITY_CONFLICT,
        MIXIN_RISK_SCORE,
        MIXIN_HANDLER_BODY,
        MIXIN_HANDLER_EFFECT,
        MIXIN_EFFECT,
        MIXIN_RECOMMENDATION,
        MIXIN_HIERARCHY,
        MIXIN_CLASS_COMPLEXITY,
        MIXIN_MOD_COMPLEXITY,
        MIXIN_BLOAT,
        MIXIN_DATAFLOW_METRICS,
        USES_PROCESS_SPAWN,
        USES_SOCKET,
        USES_REFLECTION_SET_ACCESSIBLE,
        USES_UNSAFE,
        USES_NATIVE_LIBRARY,
        USES_DYNAMIC_CLASS_DEFINITION,
        USES_REFLECTIVE_INVOCATION,
        USES_SCRIPT_ENGINE,
        USES_DESERIALIZATION,
        USES_SYSTEM_EXIT,
        USES_METHOD_HANDLES,
        WRITES_FILES,
        CHECKSUM,
        ARTIFACT_IDENTITY,
        UNKNOWN_SOURCE,
        SIGNATURE_STATUS,
        SBOM,
        TRUST_SCORE,
        TICK_SPIKE,
        HOT_METHOD,
        HOT_MOD,
        GC_PAUSE,
        HEAP_PRESSURE,
        THREAD_HOTSPOT,
        SPARK_IMPORT_FAILURE,
        DEFERRED_LAYER,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_kind_has_an_authoritative_layer() {
        let missing = all_kinds()
            .iter()
            .copied()
            .filter(|kind| layer(kind).is_none())
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "fact kinds without a layer: {missing:?}"
        );
        assert_eq!(layer("mixin_looks_like_a_kind"), None);
    }
}
