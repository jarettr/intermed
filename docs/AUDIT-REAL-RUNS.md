# Critical audit — real-run pass (2026-06-12)

Adversarial validation of `intermed doctor` and subcommands against a corpus of
**real, downloaded mods** (Modrinth, Fabric/Forge 1.20.1). Goal: find bugs,
false outputs, and — most importantly — **dishonest docs/tests**. Nothing here is
fixed; this is a findings log. Severity ordered. Each item lists reproduction +
evidence so it can be verified independently.

Corpus (outside the repo): `~/intermed_corpus/` — `fabric_clean` (fabric-api,
sodium, lithium, ferritecore, modmenu, indium, iris), `big_mixin` (Create),
`broken_deps` (iris alone), `duplicate` (two sodium versions), `mixed_loader`
(fabric lithium + forge JEI), `server_scn` (synthesised server + script logs).

Binary under test: `target/debug/intermed` built `--features duckdb`.

> **Measurement caveat (applies to the auditor too).** Two of my first readings
> were *my own* false findings — a Python aggregation compared JSON booleans to
> the string `"true"` and under-counted, and a binary `grep` ran in a reset cwd.
> Both were re-checked before landing here. Where a claim is a hypothesis rather
> than a proven fact, it is labelled **[HYPOTHESIS]**.

---

## CRITICAL

### C1. Jar-in-Jar (nested mods) is never resolved → false "missing dependency" on essentially every Fabric pack
`fabric_clean` *contains* `fabric-api-0.92.9`, which bundles 52 nested modules
(`META-INF/jars/fabric-renderer-api-v1-*.jar`, `…resource-loader-v0…`, etc.). Doctor
reports all of them as missing:

```
$ intermed doctor ~/intermed_corpus/fabric_clean
ERROR Missing dependency: fabric-renderer-api-v1   (affects: indium)
ERROR Missing dependency: fabric-resource-loader-v0
ERROR Missing dependency: fabric-key-binding-api-v1 (affects: modmenu)
… (8 such errors, all provided by fabric-api's nested jars)
ERROR Dependency constraints cannot be satisfied together
      … __intermed_modpack__ { 1.0.0 } is forbidden.
```

Evidence: `unzip -l fabric-api…jar | grep META-INF/jars` lists all the "missing"
modules; `fabric.mod.json` declares `"jars": [52 entries]`. `--dump-facts` shows
**`nested_jar` facts: 0** — the scanner never recurses into `META-INF/jars/`.

Impact: the flagship Layer-C output is wrong on the **single most common
real-world case** (every Fabric pack ships Fabric API). It also poisons the
PubGrub resolver, so `dependency-unsat:global` fires on nearly every real pack.

### C1a. DOC/TEST HONESTY: `nested_jar` and `entrypoint` are phantom predicates
`docs/SCHEMA.md` "Predicate catalog" lists `nested_jar` and `entrypoint` (and
`intermed_facts::kind` defines `NESTED_JAR`, `ENTRYPOINT`). **No collector emits
either, and no rule reads either** (`grep -rn "kind::NESTED_JAR\|kind::ENTRYPOINT"`
→ only the const definitions; the only "entrypoint" hits are unrelated log
regexes). The schema advertises two capabilities that do not exist. This is the
"documentation lies" failure mode directly: a reader/maintainer trusts the
catalog and assumes JIJ + entrypoint facts exist.

---

## HIGH

### H1. Mixin subpackage resolution drops most real mixins (silent false "scan failure")
`crates/intermed-mixin-intel/src/scan.rs::join_class_name`:

```rust
pub(crate) fn join_class_name(package: &str, mixin: &str) -> String {
    if mixin.contains('.') || package.is_empty() {
        mixin.to_string()          // <-- drops the package for dotted entries
    } else {
        format!("{package}.{mixin}")
    }
}
```

Mixin config entries in `mixins`/`client`/`server` are **always relative to
`package`** and routinely use dots for sub-packages (`accessor.FooAccessor`,
`client.BarMixin`). The `mixin.contains('.')` heuristic wrongly treats those as
fully-qualified and strips the package, producing a path that does not exist:

```
$ intermed mixin-map ~/intermed_corpus/big_mixin   # Create
Mixin classes: 17
Scan failures: 64
  reason: mixin class listed in config but not found
  path: accessor/AbstractProjectileDispenseBehaviorAccessor.class
```

But the class **exists** in the jar at
`com/simibubi/create/foundation/mixin/accessor/AbstractProjectileDispenseBehaviorAccessor.class`
(`create.mixins.json` has `package = com.simibubi.create.foundation.mixin` and lists
`accessor.…` under `client`). 64 of ~81 Create mixins (79%) are silently dropped.
Layer F is blind to the majority of real mods' mixins.

### H1a. DOC/TEST HONESTY: the test "validates" the broken function only on the trivial input
`crates/intermed-mixin-intel/src/lib.rs`:

```rust
#[test]
fn join_class_name_respects_package() {
    assert_eq!(join_class_name("alpha.mixin", "RenderMixin"), "alpha.mixin.RenderMixin");
}
```

The name claims it "respects package", but it only exercises the **no-dot** case —
exactly the case that works. The broken case (`join_class_name("a.b", "accessor.X")`
returns `"accessor.X"`, not `"a.b.accessor.X"`) is untested. A green test giving
false confidence over the common real input.

### H2. Mixin target-member taint is inert on real (intermediary-mapped) jars
Across **all 187** handler bodies from the clean set,
`calls_target_methods` and `accesses_target_fields` are empty, and the dataflow
interpreter's `target-field` / `target-call-result` provenance and
`writes_target_state` never fire (only 3 `mixin_calls` facts total, all reflective
`java.lang.Class`). The CallbackInfo half **does** work (cancels: 16,
sets_return_value: 12, early_return: 28 — verified on real bytecode).

[HYPOTHESIS] Root cause is a namespace mismatch: the mixin config's target class
names are matched against the **intermediary** owner names in the compiled handler
bytecode (`net/minecraft/class_…`). `bytecode.rs` builds `target_slash` from the
config targets and only counts members whose owner is in that set; on real jars
the owners never match, so every target read/write/call is missed. Injection-point
*method* names are refmap-resolved, but the bytecode *owner* matching is not.
Net effect: a documented Layer-F capability (target field/method tracking, and the
new dataflow's target-state analysis) is effectively dead on real-world jars while
passing on the synthetic fixtures (which use named targets).

---

## MEDIUM

### M1. Duplicate / overlapping dependency findings + leaked synthetic node
For one missing dependency the user gets two ERRORs:

```
$ intermed doctor ~/intermed_corpus/broken_deps
ERROR Dependency constraints cannot be satisfied together
      Because iris depends on sodium … and __intermed_modpack__ { 1.0.0 } depends
      on iris, __intermed_modpack__ { 1.0.0 } is forbidden.
ERROR Missing dependency: sodium
      iris requires sodium (0.5.x), but it is not installed.
```

The PubGrub `dependency-unsat:global` restates the same root cause as the cleaner
`missing-dependency:iris->sodium`, and leaks the internal synthetic root
`__intermed_modpack__ { 1.0.0 }` into user-facing text ("is forbidden"). Confusing
and redundant; on real packs (amplified by C1) it appears on nearly every run.

### M2. Layer H (SBOM) contradicts Layer B (metadata) on Forge mods
```
$ intermed doctor ~/intermed_corpus/mixed_loader
WARN Unknown mod provenance: jei-1.20.1-forge-15.20.0.130.jar
     This jar has no recognizable Fabric/Quilt/Forge manifest.
```

False: JEI ships a standard `META-INF/mods.toml` (`modLoader="javafml"`), and
Layer B **does** parse it — `--dump-facts` shows a `mod` fact `subject=jei`. So the
two layers disagree: metadata recognises the Forge mod, SBOM provenance claims no
recognizable manifest. The `unknown-source` WARN is a false positive for valid
Forge mods.

### M3. Mixin dataflow intelligence is computed but never surfaced without an overlap
`--mixin-risk` on the clean set emits 187 `mixin_handler_effect` facts (with the
new `cancels` / `sets_return_value` / `return_value_source` / `complexity_score`
attributes), but produces **0 findings** — Layer F only raises findings on
cross-mod overlaps / high-risk overwrites. On a typical single coherent pack the
user sees none of the per-handler intelligence. The data exists in `--dump-facts`
only; there is no report surface for "this handler unconditionally cancels a
hot-path method", which is the actionable part.

---

## LOW / precision / UX

### L1. Layer G "process spawn" on Sodium is unverified / likely imprecise
Reported: `process spawn [medium]`. Constant-pool check of all 511 Sodium classes:
`ProcessBuilder` → 0 classes; `java/lang/Runtime` → 37 (overwhelmingly
`maxMemory`/`availableProcessors` introspection, not `exec`). The `sun.misc.Unsafe`
(1 class) and reflective-invocation (setAccessible, 1 class) signals are **true
positives**. "process spawn" could not be confirmed and may be a misattributed
Runtime reference. **Strength:** the finding text is honestly hedged ("preflight
hints … not proof of malicious runtime behavior"), so this is a precision issue,
not a dishonest claim.

### L2. loader-mismatch is never raised among mods in a bare mods dir
`mixed_loader` (fabric lithium + forge JEI, both recognised as mods) produces no
loader-mismatch finding. The rule only compares mod loaders against a *detected
instance/server loader*; with a bare mods dir there is no baseline, so a
fabric+forge mix is silently accepted. Undocumented limitation.

### L3. `--changed-since` rejects plain dates
`--changed-since 2020-01-01` → `error: invalid RFC3339 timestamp … premature end
of input`. Requires a full `2020-01-01T00:00:00Z`. Other knobs use day counts
(`--cache-max-age-days`); a bare date or relative form would be the natural input.

### L4. `--performance` without `--spark-report` is silently inert
No perf facts, no message that the performance layer had no data. A one-line
"performance layer inactive: no spark report" would avoid the impression that the
pack is perf-clean.

---

## Confirmed strengths (worth keeping)

- **`--explain <id>`** — genuinely excellent: rule, fix candidates, and the
  supporting fact graph with `archive!file` source locators and extractors.
- **Dynamics sensor** (my recent work) — correct on a realistic server: parsed
  both CraftTweaker and KubeJS removal markers into one clear note
  (`Scripts removed 2 recipe(s) and 3 item(s)…`).
- **Honesty of security framing** — every Layer-G finding is hedged as a static
  preflight hint, not a verdict.
- **Working & verified:** duplicate-id (incl. under `--logic duckdb`), the non-JIJ
  missing-dependency path, SARIF 2.1.0 (valid, 7 results), `--html`, `--profile`,
  `--dump-config`, VFS scan.
- **Dataflow on real bytecode** — the CallbackInfo control-flow detection
  (cancels/setReturnValue/early-return) fires correctly on real Sodium/Lithium/etc.

---

## Auditor's unfinished work (mixin-strengthening session, not part of the audit)

Left mid-stream before the audit pivot; documented so it is not mistaken for done:

- The dataflow engine (`dataflow.rs`) is implemented, wired, and tested, but its
  output is **not yet woven into `effect.rs::describe_effect`** (still says "may
  cancel … via CallbackInfo" instead of the now-provable "unconditionally cancels
  / returns a constant") nor into `recommendation.rs`. Started, not finished.
- Weakness items still open from the strengthening brief: richer `@At INVOKE`
  (lambda / `invokedynamic`) recognition, MixinExtras advanced annotations
  (`@WrapWithCondition`, `@WrapMethod`, `@Definition`/`@Expression`), and
  obfuscation robustness — **H2 above is the concrete, high-value instance of the
  obfuscation gap** and should be fixed first.

---

# Round 2 — all loaders + full subcommand/flag sweep (2026-06-12)

Expanded corpus (`~/intermed_corpus/`): `forge_pack` (Create+deps, JEI, Jade,
Architectury, FerriteCore — `mods.toml`), `neoforge_pack` (1.21.1,
`neoforge.mods.toml`), `quilt_pack` (Quilted Fabric API — `quilt.mod.json`),
`paper_plugins` (LuckPerms, WorldEdit, ViaVersion, PlaceholderAPI — `plugin.yml`),
`version_mix` (1.19.2 + 1.21.1). Every subcommand and (nearly) every flag exercised.

> **Methodology honesty (again).** This session I made **three** measurement
> errors of my own — JSON `true` vs the string `"true"`, a `grep` in a reset cwd,
> and reading `d["nodes"]` instead of `d["graph"]["nodes"]` for `deps graph`
> (which made a working feature look broken). All were caught on re-check. Treat
> single-shot observations skeptically; everything below was re-verified.

## CRITICAL (new)

### C2. `db query` is **not** read-only — it executes destructive SQL, contradicting its own help
Help: *"Run a **read-only** SQL query against the analytics store."* Reality:

```
$ intermed db query --db audit.duckdb "DROP TABLE facts"
Success
$ intermed db query --db audit.duckdb "SELECT COUNT(*) FROM facts"
0                                   # was 9240 before the DROP
$ intermed db query --db audit.duckdb "DELETE FROM runs"
Count
3                                   # deleted all three persisted runs
```

`DROP`/`DELETE`/`UPDATE` all run. (`SELECT … FROM facts` returns 0 rather than an
error only because the store's `open()` recreates the empty schema via
`CREATE TABLE IF NOT EXISTS`.) A command advertised as read-only can silently wipe
or corrupt the analytics history. Both a safety bug and a documentation lie.

## HIGH (new / escalated)

### H3. SBOM "unknown provenance" is a false positive for **every** non-Fabric/Quilt mod
Escalation of round-1 M2 — it is systemic, not a one-off:

```
forge_pack:    5/5 mods → "Unknown mod provenance … no recognizable Fabric/Quilt/Forge manifest"
neoforge_pack: 5/5 mods → same
paper_plugins: 3   plugins → same
quilt_pack:    0   (Fabric/Quilt understood)
```

Every one of those was parsed by Layer B (they appear as `mod`/`plugin` facts).
Layer H's provenance classifier only recognises Fabric/Quilt manifests, so it
emits a false `unknown-source` WARN — and the message explicitly claims no
"**Forge**" manifest while a valid `META-INF/mods.toml` / `neoforge.mods.toml` /
`plugin.yml` is present. False supply-chain signal across entire ecosystems.

### H4. `trends mixin-overlaps` is 100% broken (reserved-word SQL)
```
$ intermed trends mixin-overlaps --db audit.duckdb
error: overlap query failed: duckdb: Parser Error: syntax error at or near "overlaps"
LINE 17:  ) overlaps
```
The query aliases a subquery `overlaps`, which is a DuckDB reserved keyword. The
subcommand fails every invocation. (Same family as the round-1 GROUP-BY bug —
the hand-written analytics SQL is under-tested against the real engine.)

### C1 (cross-loader confirmation)
`forge_pack`: `ERROR Missing dependency: flywheel` / `ponder` for Create. Both are
bundled **inside Create** at `META-INF/jarjar/flywheel-forge-….jar` and
`…/Ponder-Forge-….jar` and declared mandatory — i.e. **false positives**, the same
Jar-in-Jar gap as round-1 C1 but via Forge's `META-INF/jarjar/` (Fabric uses
`META-INF/jars/`). The scanner ignores both nested-jar conventions.

## MEDIUM (new)

### M4. Phase-7 hot-method × mixin cross-layer correlation is inert on realistic input
ROADMAP calls this "the first genuine cross-layer join". With a Spark report whose
hot methods are `net.minecraft.server.MinecraftServer.tick` (22.5%) and
`Level.tickBlockEntities` (11%) — both above the 5% floor, both classes Lithium
mixes into — `--performance --mixin-risk` produced **0** correlation findings (only
the 3 `tick-spike` findings fired). Same root as H2: Spark uses named MC classes,
mixin target facts are intermediary, so they never join. The headline cross-layer
capability does not fire on real named-vs-intermediary data.

### M5. `rules check` fails on the project's **own** `rules/` directory
```
$ intermed rules check rules/
Files: 4  Rules: 19  Status: failed
error: rules/community-registry.json: parse json: missing field `id`
```
`rules check` parses every JSON under the path as a rule pack, but
`community-registry.json` is a registry (`schema`/`packs`/`publishers`), not a pack.
The validator does not distinguish them, so the tool cannot cleanly validate its
own shipped `rules/` tree.

## LOW / UX (new)

- **L5. `rules generate` ignores the embedded pack** — defaults to the CWD-relative
  `rules/core/intermed-core.rules.v2.json`; `error: pack not found` unless run from
  the repo root. (`rules registry`, `rules sign`+`verify` roundtrip, `--logic
  datalog`, `--logic souffle` graceful error, `--config` roundtrip all work.)
- **L6. ViaVersion classified as `mod`, not `plugin`** — its universal jar bundles a
  mod manifest alongside `plugin.yml`; the scanner picks the mod manifest. The other
  three plugins (LuckPerms, WorldEdit, PlaceholderAPI) are correctly `plugin`.
- **L7. `doctor --performance` silently swallows Spark import failures** — a malformed
  `--spark-report` yields no perf findings and no error, whereas `spark-map` reports
  `Import failures: 1` with the parse error. Doctor should surface the same.
- **L8. `lab run` gives no signal when no smoke outputs are ingested** — a `--logs`
  dir without valid `intermed-smoke-output-v1` JSON yields `Environments: 0` /
  empty run with no "0 smoke outputs found" notice. (Input format is correctly
  documented in `--help`; this is only the missing-feedback nit.)

## Confirmed working in Round 2 (strengths)

- **All four metadata systems parse**: Forge `mods.toml`, NeoForge
  `neoforge.mods.toml`, Quilt `quilt.mod.json`, Bukkit/Paper `plugin.yml` — every
  mod/plugin in each pack became a `mod`/`plugin` fact.
- `deps resolve` (PubGrub) + `deps graph` (`intermed-modpack-graph-v1`, real
  nodes/edges), `sbom export` (SPDX-2.3 → 5 packages; CycloneDX → 5 components),
  `vfs overlay`, `cache stats|prune|clear`, `db query` (for `SELECT`),
  `history conflicts|diff`, `trends mixin-risk`, `lab discover|report`,
  `spark-map` + `doctor --performance` tick/gc/heap findings, `rules
  sign|verify|registry`, `--logic datalog|souffle`, `--config`, `--html`,
  `--profile`, `--dump-config`, SARIF — all function.

## Net picture after two rounds

The plumbing is broad and mostly works; the **failures cluster in three places**:
1. **Nested-jar (JIJ) blindness** (C1) → false missing-deps on essentially every
   real pack, both loaders.
2. **Namespace (named ↔ intermediary) mismatch** (H2, M4) → mixin target-member
   taint and the perf cross-layer correlation silently produce nothing on real jars.
3. **Layer-coverage gaps that emit confident-but-false text** — SBOM provenance for
   non-Fabric mods (H3), `db query` "read-only" (C2), and the two analytics SQL
   queries that don't run (H4 + round-1). These are the dangerous ones: the output
   *reads* authoritative while being wrong.

---

# Resolution log — audit remediation (2026-06-13)

Systemic fixes for all remaining audit items after the C/H tranche (C1–C2, H1–H3).
Each item lists the architectural change and the in-tree test that guards it.

## CRITICAL / HIGH — resolved

| ID | Fix | Tests |
|----|-----|-------|
| **C1 / C1a** | *(prior session)* Jar-in-Jar recursion + `nested_jar` / `provided_dependency` facts | `intermed-minecraft-scan/tests/metadata.rs::nested_jar_registers_versioned_provider` |
| **C2** | *(prior session)* `DuckStore::open_readonly` for `db query` | `intermed-duckdb/tests/duckdb_backend.rs::readonly_open_rejects_writes_but_allows_select` |
| **H1 / H1a** | *(prior session)* `join_class_name` always prefixes `package`; dotted entries are sub-packages | `intermed-mixin-intel/src/lib.rs::join_class_name_respects_package` |
| **H2** | Tiny v2 **class** bridge (`named_class_to_intermediary`); bytecode owner set expanded per jar; `mixin_target` emits `target_named` / `target_intermediary` | `refmap::tiny_bridges_named_and_intermediary_classes`, `bytecode::intermediary_owner_matches_named_mixin_target` |
| **H3** | SBOM `detect_identity` parses Forge `[[mods]]`, NeoForge, `plugin.yml`, `paper-plugin.yml` | `intermed-sbom/tests/sbom_scan.rs::scan_records_forge_mods_toml_identity` |
| **H4** | DuckDB subquery alias `overlaps` → `overlap_rows` (reserved word) | `intermed-duckdb/tests/duckdb_backend.rs::top_mixin_overlaps_query_runs_against_duckdb` |

## MEDIUM — resolved

| ID | Fix | Tests |
|----|-----|-------|
| **M1** | Suppress `dependency-unsat:global` when pairwise already reports `missing-dependency`; sanitize `__intermed_modpack__` → “the modpack” in PubGrub text | `intermed-deps/tests/dependency_dedup.rs`, `report::unsat_text_hides_synthetic_modpack_root` |
| **M3** | `handler_intelligence_findings` surfaces `mixin_handler_effect` (cancels / return / complexity) without overlap | `intermed-mixin-intel/tests/rule_eval.rs` (extended pipeline) |
| **M4** | `MixinIndex` alias map + `target_named`/`target_intermediary` attrs join Spark named classes to intermediary mixin targets | `intermed-spark-bridge` `named_spark_class_joins_intermediary_mixin_target` |
| **M5** | `rules check` skips `community-registry.json` and `intermed-rule-registry-v1` indexes | `intermed-rules/src/pack.rs::check_skips_registry_index_files` |

## LOW / UX — resolved

| ID | Fix | Tests |
|----|-----|-------|
| **L1** | Removed `getRuntime` from process-spawn string corroboration table (Runtime introspection ≠ spawn) | existing `detects_runtime_exec_method_ref` / reflection corroboration tests |
| **L2** | New `MixedLoaderPackRule` for fabric+forge mixes in bare `mods/` dirs | `intermed-rules::mixed_loader_pack_fires_in_bare_mods_dir` |
| **L3** | `--changed-since` accepts `YYYY-MM-DD` (midnight UTC) | `scan_filter::parse_unix_and_rfc3339` |
| **L4** | `performance-inactive` Note when `--performance` yields no Spark facts | `intermed-spark-bridge::performance_inactive_note_when_no_spark_facts` |
| **L5** | `rules generate` uses embedded core v2 when pack path empty or missing | CLI default `pack=""` + fallback in `run_rules_generate` |
| **L6** | Metadata prefers `plugin.yml` over bundled mod manifest (ViaVersion) | `intermed-minecraft-scan/tests/metadata.rs` plugin ordering |
| **L7** | Spark import failures emit `spark_import_failure` facts + `spark-import-failure:*` findings | `intermed-spark-bridge::spark_import_failure_surfaces_as_finding` |
| **L8** | `lab run` prints a note when zero smoke environments ingested | CLI output in `run_lab` |

## Cache bumps (scan output changed)

* `intermed-mixin-intel` → **`-r19`** (namespace bridge + handler intel facts unchanged schema, bytecode attrs richer)
* `intermed-sbom` → **`-r3`** (Forge/NeoForge/Bukkit/Paper identity)
* `intermed-minecraft-scan` → **`-r3`** (plugin-first manifest dispatch)

## Verification

```bash
cargo test --features duckdb   # full in-tree suite (2026-06-13: all green)
```

Re-run against `~/intermed_corpus/` recommended before closing the audit; the fixes above
are guarded by unit/integration tests on fixtures, not by re-fetching the external corpus.
