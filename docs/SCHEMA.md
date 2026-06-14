# Schema Conventions (Phase 0)

## The three schemas

| Schema | Type | Owner crate | Versioning |
|---|---|---|---|
| Fact | `intermed_facts::Fact` | `intermed-facts` | Datalog-shaped predicate + named terms |
| Finding | `intermed_evidence::Finding` | `intermed-evidence` | with `EvidenceEdge` provenance |
| Report | `intermed-doctor-report-v1` | `intermed-doctor-core` | `schema` string, bump on breaking change |

## Fact = predicate + named terms (deliberate)

A fact is `kind` (predicate name) + `subject` + named `attributes`. This is a
Datalog tuple in disguise:

```
mod(subject="sodium", version="0.5.3", loader="fabric")
dependency(subject="create", dep="fabric-api", range=">=0.90", mandatory=true, relation="depends")
dependency(subject="alpha", dep="beta", range=">=2.0", mandatory=true, relation="breaks")
log_signal(subject="OutOfMemory", line=2, excerpt="...")
resource_writer(subject="modid", path="data/.../tags/items/x.json", archive="mod.jar")
mixin_target(subject="modid", target="net.minecraft.client.render.WorldRenderer", mixin="...")
```

Why this shape:

* **Phase 1** imperative rules match on `kind` and read terms by name.
* **Phase 5** lowers the *same* facts into a Datalog IR / SQL rows with **no
  model change** — `kind` → relation, terms → columns. Per the design doc
  (Appendix Б), the early Datalog backend is DuckDB: facts stream into columnar
  tables and rules become vectorized `JOIN`s.

Predicate names are constants in `intermed_facts::kind`. Add new predicates
there as layers come online; keep collectors and rules referring to the
constants, never raw strings.

## Predicate catalog

Layer A/B/C/D:

* `environment`, `java_runtime`, `target`
* `mod`, `plugin`, `dependency`, `provided_dependency`, `mod_side`,
  `nested_jar` (Jar-in-Jar: `subject` = parent mod, `nested` = bundled id,
  `version` = bundled module's own version; the same module is also emitted as a
  versioned `provided_dependency` with `bundled=true`), `unparseable_archive`
* `entrypoint` (`subject` = mod id, `phase` = lifecycle slot — `main`/`client`/
  `server`/`init`/`client_init`/`mod` for the Forge `@Mod` class — `class` = entry
  class, `loader`)
* `mod_metadata` (append-only enrichment of `mod`/`plugin`: `name`,
  `description`, JSON `authors`, `license`, `environment`, `icon`, `update_json`,
  `version_raw`, `version_normalized`, `loader`)
* `entrypoint_detail` (`subject` = mod id, `phase`, `class`, `entrypoint_type`;
  at metadata level `full`, JSON `events` and numeric `priority`)
* `mod_relationship` (`subject` = mod id, `related`, `type` =
  `recommended_together`|`known_incompatible`|`provides_api`|`consumes_api`,
  `reason`, fact confidence)
* `mod_capability` (`subject` = mod id, `capability`, `reason`, fact confidence)
* `access_transform` (Forge Access Transformer / Fabric-Quilt Access Widener:
  `subject` = mod id, `mechanism` = `access-transformer`|`access-widener`,
  `access`, optional `qualifier`, `target_class`, optional `member`, `target_key`
  = mechanism-independent `class#member` join key)
* `coremod` (`subject` = mod id, `name` = declared Forge coremod, `loader`)
* `log_signal`
* `log_mentions_mod` (`subject` = mod id structurally named by a parsed crash
  stack trace, `via` = `mixin-config`|`message`, `exception` = throwable class,
  `line`; correlated with installed `mod` facts by the log-signal rule)
* `log_crash` (`subject` = root exception, `root_cause_exception`,
  `root_cause_mod`, `phase`, `severity`, `line`)
* `log_mod_error` (`subject` = implicated mod, `root_cause_exception`, `phase`,
  `severity`, numeric `blame_score`, plus Layer-B `version`, `environment`, and
  JSON `capabilities` when available)

Layer E / VFS:

* `resource_writer`
* `resource_collision`
* `json_merge_candidate`
* `safe_crdt_merge`
* `lang_json_merge` — `assets/**/lang/*.json` key-union candidate
* `lang_properties_merge` — `assets/**/lang/*.lang` key-union candidate
* `lang_format_conflict` — same locale as both JSON and `.lang`
* `unsafe_replace_conflict`

Layer M / resource semantics (typed AST) — detail in
[SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md):

* `resource_ast_parsed` — per-resource parse summary (`domain`, `parse_status`,
  `semantic_hash`, domain attrs)
* `resource_definition` — path → defining writer + namespace
* `resource_reference` — outgoing edge (`relation`, `to`, `namespace`,
  `required`, `conditioned`, `is_tag`)
* `namespace_owner` — namespace → writer (incl. binary-only assets)
* `implicit_dependency_candidate` — Layer M observes; Layer C resolves
* `resource_semantic_diff` — cross-writer meaning disagreement (`diff_kind`,
  `writers`, `detail`)
* `resource_dangling_reference` — **reserved**, not emitted (see
  [RESOURCE-GRAPH.md](RESOURCE-GRAPH.md))

Layer E / Dynamics (script engines):

* `runtime_removed_recipe` (subject = recipe id; `engine`, `via`, `line`, `excerpt`)
* `runtime_removed_item` (subject = item id; `engine`, `via`, `line`, `excerpt`)
* `runtime_removed_loot_table` (subject = loot table id)
* `runtime_removed_tag` (subject = tag id)

Layer F / Mixin Intelligence:

* `mixin_config`
* `mixin_class`
* `mixin_target` — optional `target_named`, `target_intermediary` when the jar ships Tiny mappings
* `mixin_operation`
* `mixin_hotspot`
* `mixin_overlap`
* `high_risk_overwrite` — `@Overwrite` risk (`site_key`, `effect_description`, `hot_path`, …)
* `log_mixin_correlation`
* `mixin_injection_point` — `injection_type`, `resolved_method`, `resolved_via_refmap`,
  `canonical_method`, `site_key`, `handler_method`, `at_target`, `at_detail`, `impact`;
  injector metadata `require`/`expect`/`allow`/`cancellable`/`remap`/`group`,
  `at_ordinal`, `at_target_member`, `local_capture`
* `mixin_shadow` — `@Shadow` field/method on target
* `mixin_added_member` — accessor/invoker/added member (`unique` for `@Unique`)
* `mixin_calls` — target reference (`provenance`: constant-pool / bytecode / reflective)
* `mixin_handler_body` — handler bytecode summary (`instruction_count`, `uses_reflection`,
  `modifies_return_value`, `uses_callback_info`, `accesses_target_fields`, `original_call_count`, …)
* `mixin_handler_effect` — semantic handler effect (`complexity_score`, `early_return`,
  `original_call_count`, and `side_effects` incl. `global-state-write`, `async-scheduling`,
  `world-mutation`, `heavy-allocation`, `logging-only`)
* `mixin_effect` — effective target-method change (`effect_description`, `effect_kinds`, …)
* `mixin_recommendation` — safer-mixin advice (`title`, `description`, `rationale`,
  `confidence`, optional `example`, `doc_url`); covers effect, conflict-taxonomy, and
  apply-failure families
* `mixin_hierarchy` — target ancestor edge (`ancestor`, `depth`, `relation`)
* `mixin_interaction` — semantic interaction between two mixins
* `mixin_conflict_edge` — typed graph edge (`edge_type`, `strength`); edge types include
  `overwrite-vs-injector`, `cancellable-head-vs-return`, `redirect-vs-wrap-operation`,
  `wrap-condition-suppresses-call`, `modify-args-same-invocation`, `unique-member-conflict`
* `mixin_priority_conflict` — priority ordering on overlapping injections
* `mixin_risk_score` — composite 0–100 risk (`score`, `reasons`, `mods`) plus axes
  `certainty`, `apply_failure`, `semantic_conflict`, `blast_radius`, `fragility`, `actionability`
* `mixin_apply_target_method_missing` / `mixin_apply_require_unsatisfied` /
  `mixin_apply_target_class_missing` / `mixin_apply_descriptor_mismatch` /
  `mixin_apply_ordinal_out_of_range` / `mixin_apply_refmap_missing` /
  `mixin_apply_remap_false_suspicious` — apply-time failures (`confirmed`, `target`,
  `member`, `detail`); `Error` when confirmed, else `Warn`

Layer G / Security audit (emitted by `security-scanner`):

* `uses_process_spawn`
* `uses_socket`
* `uses_reflection_set_accessible`
* `uses_unsafe`
* `uses_native_library`
* `uses_dynamic_class_definition`
* `uses_reflective_invocation`
* `uses_script_engine`
* `uses_deserialization`
* `uses_system_exit`

Each carries a `provenance` attribute (`structural` | `reflection-corroborated`);
corroborated facts are emitted with confidence `0.4` and only when reflective
dispatch machinery is structurally present (see `docs/LAYER-G-SECURITY.md`).

Reserved (not emitted by Layer G — too noisy for security preflight):

* `writes_files`

Layer H / SBOM:

* `checksum`
* `artifact_identity`
* `unknown_source`
* `signature_status`
* `sbom`
* `trust_score`

Layer I / Performance (Spark import):

* `tick_spike`
* `hot_method` — `percent` must be stored **numerically** (`AttrValue::Float` or
  `Int`); `Fact::attr_f64` does not parse string attributes. The correlation rule
  ignores hot methods below a 5% CPU floor and skips facts with non-numeric
  `percent`.
* `hot_mod`
* `gc_pause`
* `heap_pressure`
* `thread_hotspot`
* `spark_import_failure` — `reason`; surfaced as `spark-import-failure:*` finding when import fails

Layer K / Compatibility Lab (operations, not facts — `intermed lab`):

* `intermed-corpus-candidates-v1` — discovery input
* `intermed-corpus-lock-v1` — content-addressed corpus lock (`lab discover`)
* `intermed-smoke-output-v1` — one captured smoke-test output
* `intermed-lab-run-v1` — classified run (`lab run`); each `SmokeResult` may
  carry `attributions[]` (`category`, `subject`, optional `line_excerpt`) for
  finding-level `lab eval` joins
* `intermed-compatibility-matrix-v1` — aggregated matrix (`lab report`)
* `intermed-rule-accuracy-v2` — Doctor vs lab accuracy (`lab eval`):
  `by_category` (co-occurrence), `by_rule` + `finding_level` (attributed
  per-finding), `suggested_severity` gated on ≥10 predictions

See [LAYER-K-LAB.md](LAYER-K-LAB.md).

Layer J / Rule Packs:

* **Single source of truth:** `rules/core/intermed-core.rules.v2.json`
  (`intermed-rule-pack-v2`). Legacy `intermed-rule-pack-v1` packs remain valid;
  [`upgrade_pack_to_v2`](../../crates/intermed-rules/src/convert.rs) upgrades schema metadata.
* JSON Schema: `rules/intermed-rule-pack-v2.schema.json`.
* Rule kinds: `group-distinct`, `fact-finding`, `join`, `aggregate`, `correlation`.
  Expressions in `on` / `where` / `having` use the small language in
  `crates/intermed-rules/src/expr.rs`; finding templates use `{alias.field}` placeholders.
* **Backends** (all driven from the same pack):
  * `DeclarativeRulePack` — in-process interpreter (`--logic imperative` / `datalog`)
  * `SouffleRulePack` — generated `.dl` (`datalog_codegen`)
  * `DuckdbRulePack` — materializes facts + interpreter; SQL generated via `sql_codegen`
    (`intermed rules generate --backend sql`)
* CLI: `intermed rules check`, `intermed rules generate --backend sql|rust|datalog`.
* Core rules in the v2 pack include duplicate-id, loader/side mismatch (join),
  resource-conflict (fact-finding + related evidence), mixin overlap/overwrite,
  SBOM provenance, and sbom×security correlation.

  Analytics persistence: `doctor --db FILE` writes `runs`, `facts`,
  `fact_attributes`, `findings`, and evidence side tables; query with
  `intermed db query --db FILE "SELECT …"`.

### DuckDB analytics store (`intermed-duckdb`)

DDL and Rust row mapping are bound in `crates/intermed-duckdb/src/schema.rs`
(single source of truth — no hand-maintained parallel schema).

| Table | Role |
|-------|------|
| `runs` | One row per diagnosis (`run_id` = first 16 hex of `sha256(generated_at ‖ target_path ‖ tool_version)`) |
| `facts` | Predicate + subject + provenance columns |
| `fact_attributes` | EAV terms (`val_type` + typed value columns) |
| `findings` | Report findings snapshot |
| `finding_tags` / `finding_affects` / `finding_evidence` | Finding annotations and provenance edges |

Re-persisting the same `run_id` deletes prior rows for that id, then upserts
fresh rows with `INSERT OR REPLACE` (idempotent per run; safe for large
`mixin_effect` batches). Built-in analytics views include `risk_patterns`,
`historical_conflicts`, `mixin_effect_hotpaths`, `security_capabilities`,
`sbom_trust_buckets`, `fact_kind_counts`, `mod_capability_inventory`, and
`log_root_causes`.

## Provenance is mandatory

Every `Fact` carries a `SourceRef` (file / line / inner path) and a
`confidence`. Every `Finding` carries `EvidenceEdge`s pointing back at the facts
that justify it. This is what makes the Phase-2 `--explain <finding>` and
`--dump-facts` possible without re-running anything — and why InterMed never
prints an unsourced verdict.

## Output formats

* **Terminal** — human, ANSI optional, no colour crate (cold-start discipline).
* **JSON** — the `DoctorReport` verbatim (`--json`).
* **SARIF 2.1.0** — findings as results, distinct `rule_id`s as rules (`--sarif`),
  for IDE / CI code-scanning.

## Single source of truth (answers Appendix Б critique #3)

Appendix Б warns that DuckDB table schema, FlatBuffers IPC, and Rust models can
drift and cause segfaults. The discipline that prevents it: **the Rust `serde`
type is the source of truth.** When DuckDB (Phase 5) and any JVM-worker IPC
(Phase 4/6, if ever needed) arrive, their schemas must be *generated from* the
Rust types, never hand-maintained in parallel. Until then there is exactly one
definition per schema, in the owner crate above.
