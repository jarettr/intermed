# Roadmap — phases → layers → crates

Philosophy carried from the design doc:

> **Doctor and PackOps explain. Runtime enforces.**

Doctor is an *evidence engine*, not an enforcement runtime. The pipeline is
`facts → rules → findings → report`, never a battery of ad-hoc `check()`s.

## Status

| Phase | Goal | Layers | Crates | State |
|---|---|---|---|---|
| **0** | Extraction discipline: skeleton, donor map, conventions, first schema | — | workspace + `docs/` | ✅ done |
| **1** | `intermed doctor` actually works | A,B,C,D,J | facts, evidence, report, doctor-core, minecraft-scan, log, deps, rules, cli | ✅ done |
| **2** | Fact store + evidence graph: `--dump-facts`, `--explain` | — | doctor-core, cli | ✅ done |
| **3** | PackOps / VFS: resource conflicts, overlays | E | vfs, packops | ✅ done |
| **4** | Mixin intelligence (risk map) | F | mixin-intel | ✅ done |
| **5** | Datalog-compatible backend behind the `Rule` trait | J | rules | ✅ done |
| 6 | Security / SBOM | G,H | security-audit, sbom | 🔲 stub |
| 7 | Spark / observability correlation | I | spark-bridge | 🔲 stub |
| 8 | Compatibility Lab | K | lab | 🔲 stub |
| 9 | Runtime preflight bridge | L | runtime-preflight | 🔲 stub |

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

## Phase 4 — Definition of Done (met)

```
intermed doctor ./instance --mixin-risk
intermed mixin-map ./mods
```

Layer F statically scans mixin configs and class-file string/constant-pool
evidence. It emits `mixin_config`, `mixin_class`, `mixin_target`,
`mixin_operation`, `mixin_hotspot`, `mixin_overlap`, and
`high_risk_overwrite` facts. It derives risk findings for target overlaps and
`@Overwrite` usage, with hot-path escalation for renderer/server/chunk/entity
targets. This is intelligence only: no bytecode transformation, no auto-heal.

## Phase 5 — Definition of Done (met)

```
intermed doctor ./instance --logic=imperative
intermed doctor ./instance --logic=datalog
intermed doctor ./instance --logic=souffle
intermed rules check ./rules
```

Phase 5 adds `intermed-rule-pack-v1`, a declarative Datalog-compatible rule-pack
schema, an in-process rule-pack backend implementing the existing `Rule` trait,
rule-pack validation, and a real optional Souffle backend. `--logic=souffle`
materializes `.facts`, writes a generated `.dl` program, runs `souffle -F ... -D ...`,
and imports output relations back into normal findings. Imperative rules remain
the fallback for checks that have not yet been ported.

## Appendix Б (hybrid engine) — explicitly deferred

Rust↔JVM FlatBuffers IPC, DuckDB fact store, Wasmtime plugin microkernel,
transactional shadow VFS, resilient telemetry. None of it is on the Phase 0–3
critical path. Its three self-identified risks (distribution, cold start, schema
sync) are handled by: keeping Phase 1 a single pure-Rust binary; gating heavy
work behind `applies(target)`; and the single-source-of-truth schema rule
(`docs/SCHEMA.md`).
