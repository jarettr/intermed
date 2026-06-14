# Roadmap — phases → layers → crates

Philosophy carried from the design doc:

> **Doctor and PackOps explain. Runtime enforces.**

Doctor is an *evidence engine*, not an enforcement runtime. The pipeline is
`facts → rules → findings → report`, never a battery of ad-hoc `check()`s.

**Feature-level status (layers A–L, cross-layer joins, deferred items):**
[STATUS.md](STATUS.md). **User-oriented overview:** [CONCEPTS.md](CONCEPTS.md).

## Status

| Phase | Goal | Layers | Crates | State |
|---|---|---|---|---|
| **0** | Extraction discipline: skeleton, donor map, conventions, first schema | — | workspace + `docs/` | ✅ done |
| **1** | `intermed doctor` actually works | A,B,C,D,J | facts, evidence, report, doctor-core, minecraft-scan, log, deps, rules, cli | ✅ done |
| **2** | Fact store + evidence graph: `--dump-facts`, `--explain` | — | doctor-core, cli | ✅ done |
| **3** | PackOps / VFS: resource conflicts, overlays | E | vfs, packops | ✅ done |
| **M** | Resource / data semantics (typed AST) | M | resource-ast | ✅ done |
| **4** | Mixin intelligence (risk map) | F | mixin-intel | ✅ done |
| **5** | Datalog-compatible backend behind the `Rule` trait | J | rules | ✅ done |
| **5b** | DuckDB SQL backend + analytics store (feature-gated) | J | duckdb | ✅ done (off by default) |
| **6** | Security / SBOM | G,H | security-audit, sbom | ✅ done |
| **7** | Spark / observability correlation | I | spark-bridge | ✅ done |
| **8** | Compatibility Lab (offline evidence path) | K | lab | ✅ done |
| 9 | Runtime preflight bridge | L | runtime-preflight | ⏸ deferred ~1 year (until stabilization) |

Remaining stubs are **wired**: each deferred layer is a real `Collector`/operations crate
behind the production contract, registered in the CLI, and surfaced in every
report under "Deferred layers". Filling one in = implementing the trait; no
plumbing changes.

## Phase 1 — Definition of Done (met)

```
intermed doctor ./server          # detects server, scans mods + logs/
intermed doctor ./mods            # bare mods directory
intermed doctor latest.log        # single log/crash file (fast path, no mod scan)
intermed doctor ./server --json   # intermed-doctor-report-v1
intermed doctor ./server --sarif  # SARIF 2.1.0
```

Working findings: missing dependency, version mismatch, wrong Minecraft version,
duplicate id, loader mismatch, client/server side mismatch, and log signals
(OOM, mixin apply error, ClassNotFound/NoClassDef, mod load failure, port in
use, datapack/registry errors, JVM crash, stack overflow).

## Phase 2 — Definition of Done (met)

```
intermed doctor ./instance --dump-facts facts.json
intermed doctor ./instance --explain finding_id
```

The engine now returns a `DiagnosticRun`: compact `DoctorReport` plus the raw
fact snapshot. Findings carry `EvidenceEdge`s to fact ids, and `--explain`
prints the rule, fix candidates, supporting facts, attributes, source locations,
and extractors for a specific finding.

## Phase 3 — Definition of Done (met)

```
intermed vfs scan ./mods
intermed vfs explain ./mods
intermed vfs overlay ./mods --out ./overlay
```

Layer E scans `assets/**`, `data/**`, and `pack.mcmeta` inside jars, emits
`resource_writer`, `resource_collision`, `json_merge_candidate`,
`safe_crdt_merge`, and `unsafe_replace_conflict` facts, and derives resource
findings through the normal rule path. PackOps writes overlay previews into a
new output directory only; source jars and mod directories stay untouched.

## Phase M — Definition of Done (met)

```
intermed doctor ./mods --resource-level semantic
intermed doctor ./mods --resource-level full
intermed vfs explain ./mods --path data/create/recipes/crushing/tuff.json --ast
intermed vfs overlay ./mods --explain-plan
intermed doctor ./mods --dump-facts facts.json   # resource_ast_parsed, …
```

Layer M (`intermed-resource-ast`) parses mod resources into compact typed AST
summaries, emits semantic facts (`resource_reference`, `resource_semantic_diff`,
`implicit_dependency_candidate`, …), and never emits findings directly. Rules
surface recipe output overrides, lang key conflicts, and (via Layer C) missing
recipe serializer mods. The shared jar cache stores per-resource summaries;
`vfs explain --ast` and overlay plan v2 classify safe/review/unsafe merges. See
[LAYER-M-DATA-SEMANTICS.md](LAYER-M-DATA-SEMANTICS.md), [CL-LAYER-M.md](CL-LAYER-M.md).

## Phase 4 — Definition of Done (met)

```
intermed doctor ./instance --mixin-risk
intermed mixin-map ./mods
```

Layer F statically scans mixin configs, annotations, and handler bytecode. It
resolves injection points via refmap/Tiny with **canonical** intermediary keys
and **`site_key`** (`@At` + locals), runs [`MixinInteractionEngine`](../crates/intermed-mixin-intel/src/analyzer.rs)
(overlaps, namespace mismatch, inherited targets, shadow/overwrite/priority
edges), and emits composite `mixin_risk_score` facts plus the full mixin fact
vocabulary in [SCHEMA.md](SCHEMA.md). Risk findings and `mixin-map` correlate
with Spark hot methods. Intelligence only: no bytecode transformation, no auto-heal.
See [LAYER-F-MIXIN.md](LAYER-F-MIXIN.md).

## Phase 5 — Definition of Done (met)

```
intermed doctor ./instance --logic=imperative
intermed doctor ./instance --logic=datalog
intermed doctor ./instance --logic=souffle
cargo build -p intermed-cli --features duckdb
intermed doctor ./mods --logic=duckdb --db history.duckdb
intermed db query --db history.duckdb "SELECT kind, COUNT(*) FROM facts GROUP BY kind"
intermed rules check ./rules
```

Phase 5 adds `intermed-rule-pack-v1`, a declarative Datalog-compatible rule-pack
schema, an in-process rule-pack backend implementing the existing `Rule` trait,
rule-pack validation, and a real optional Souffle backend. `--logic=souffle`
materializes `.facts`, writes a generated `.dl` program, runs `souffle -F ... -D ...`,
and imports output relations back into normal findings. Imperative rules remain
the fallback for checks that have not yet been ported.

Phase 5b adds `intermed-duckdb`: embedded DuckDB (feature `duckdb`, bundled C++
paid only when enabled) as an in-process SQL rule backend and append-only
analytics history (`doctor --db`, `intermed db query`). Six core SQL rules cover
duplicate ids, mixin overlap/overwrite, loader/side mismatch, and resource
conflicts (`crates/intermed-duckdb/src/sql.rs`). Default CI/workspace builds
never compile DuckDB.

## Phase 6 — Definition of Done (met)

```
intermed doctor ./mods --json          # fact_stats includes checksum, sbom, uses_*
intermed doctor ./mods --dump-facts f  # security + sbom predicates present
intermed doctor ./mods --explain security-api-risk:modid
```

Layer G parses class constant pools (cafebabe/noak), collapses signals per
capability, and groups security findings per mod (`security-api-risk:{mod_id}`)
with structural vs reflection-corroborated provenance. Layer H records jar
checksums, graded `source_class`, signing, trust scores, and correlates weak
provenance with high-risk capabilities (`sbom-security-correlation`). Both use
the jar cache. See [LAYER-G-SECURITY.md](LAYER-G-SECURITY.md),
[LAYER-H-SBOM.md](LAYER-H-SBOM.md).

## Phase 7 — Definition of Done (met)

```
intermed doctor ./server --performance
intermed doctor ./server --performance --spark-report ./spark/profile.json
intermed spark-map ./server --spark-report ./spark/profile.json
```

Layer I imports `intermed-spark-report-v1` JSON, emits performance facts, and
correlates hot methods (≥ 5% CPU floor) against mixin **target** facts — the
first genuine cross-layer join.

## Phase 8 — Definition of Done (met)

```
intermed lab discover ./candidates.json --out corpus.lock
intermed lab run corpus.lock --logs ./captured --out ./runs/latest
intermed lab report ./runs/latest --out ./site
```

Layer K (`intermed-lab`) produces reproducible compatibility evidence: a
content-addressed corpus lock, classified smoke-test ingestion, and a
compatibility matrix (JSON + static HTML). The offline evidence path is fully
implemented and tested; live server execution (Modrinth fetch, loader installers,
`ServerProcessRunner`) is a deferred donor behind the `CandidateProvider` /
`SmokeRunner` traits. See [LAYER-K-LAB.md](LAYER-K-LAB.md).

## Phase 9 — Runtime Preflight (deferred ~1 year)

Layer L (`intermed-runtime-preflight`) is **intentionally held deferred** until
the evidence engine stabilizes (on the order of a year). It is registered as a
`DeferredCollector` (visible in reports, emits nothing) and performs **no
enforcement** — *Doctor and PackOps explain; the Runtime enforces.* Promote it
only after Layers A–K are stable.

## Appendix Б (hybrid engine) — explicitly deferred

Rust↔JVM FlatBuffers IPC, DuckDB fact store, Wasmtime plugin microkernel,
transactional shadow VFS, resilient telemetry. None of it is on the Phase 0–3
critical path. Its three self-identified risks (distribution, cold start, schema
sync) are handled by: keeping Phase 1 a single pure-Rust binary; gating heavy
work behind `applies(target)`; and the single-source-of-truth schema rule
(`docs/SCHEMA.md`).

For the item-by-item split of Appendix Б into what serves the current goal versus
what travels with the runtime, see
[APPENDIX-B-BOUNDARY.md](APPENDIX-B-BOUNDARY.md). Both non-runtime extractions are
now **landed**: the **fact-store/rule-engine seam** (`intermed-duckdb`,
`--logic duckdb`) and the script-engine **dynamics sensors**
(`intermed-dynamics`, Layer E — KubeJS/CraftTweaker logs → `runtime_removed_*`
facts → an auditable note; see [LAYER-E-DYNAMICS.md](LAYER-E-DYNAMICS.md)).
Everything still deferred in Appendix Б travels with the runtime.
