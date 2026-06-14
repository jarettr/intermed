# InterMed concepts

High-level guide for **using and reasoning about** InterMed without reading the
crate graph. For exact fact kinds and CLI flags see [SCHEMA.md](SCHEMA.md) and
[EXAMPLES.md](EXAMPLES.md). For what is implemented *right now* see
[STATUS.md](STATUS.md).

## What InterMed is

InterMed is a **read-only evidence engine** for Minecraft modpacks and servers.
You point it at a directory or log; it collects **facts**, runs **rules**, and
returns **findings** with provenance — not a mod loader, not a patcher, not an
antivirus.

> **Doctor and PackOps explain. Runtime enforces.**

The Rust rewrite deliberately dropped JVM execution. Static layers read files;
the deferred runtime layer (L) would bridge to enforcement later.

## The pipeline (one picture)

```text
  Target                    Collectors (observe)              Rules (infer)
  ──────                    ────────────────────              ─────────────
  server/                   metadata, deps, logs,    ──▶     missing-dep,
  mods/          ──▶        vfs, resource-ast,              mixin-risk,
  latest.log                mixin, security,                 recipe-output-override,
                            sbom, spark (import),            implicit-dependency-missing,
                            dynamics (script logs)            …
                                      │
                                      ▼
                               FactStore  ──▶  Findings  ──▶  DoctorReport
                               (snapshot)       + evidence      terminal / JSON / SARIF
```

**Collectors never emit findings.** **Rules never read the filesystem.** The CLI
wires concrete collectors and rules at the composition root
([`intermed-cli`](../crates/intermed-cli/)).

## Targets

A **target** is whatever you pass to `intermed doctor`:

| Target kind | Typical path | What runs |
|-------------|--------------|-----------|
| Server / instance | `./server`, Prism instance, `.minecraft` | Mod scan + `logs/` (if present) |
| Modpack archive | `pack.mrpack`, CurseForge `.zip` | Extract → layout resolve → full scan |
| Mods directory | `./mods` | Jar scan only (fast) |
| Log file | `latest.log` | Log layer only (fastest) |

Layer A resolves launcher layouts (Prism/MultiMC `.minecraft`, CurseForge
`overrides/`, Modrinth exports) and classifies `instance_type` as
`server` / `client` / `integrated` before collectors run.

Collectors declare `applies(target)` so cold paths stay cheap — scanning every
mod jar for a single crash log would be wasteful.

## Facts, findings, evidence

| Term | Meaning |
|------|---------|
| **Fact** | One observed predicate, e.g. `mixin_overlap`, `uses_process_spawn`. Open vocabulary (`facts::kind` constants). |
| **Finding** | Rule output: severity, title, explanation, fix hints. |
| **Evidence edge** | Link from finding → supporting fact ids. Powers `intermed doctor --explain ID`. |

Facts are the **shared language** between imperative rules, Datalog packs, Souffle,
and DuckDB — same snapshot, different evaluators (`--logic`).

## Diagnostic layers (A–L)

Layers are organizational, not runtime modules. Each maps to collectors and/or
rules documented in [STATUS.md](STATUS.md).

| Code | You get… |
|------|----------|
| A–D | *Does this pack load?* — target detection, jar metadata, dependency graph, log/crash signals |
| E | *Do mods fight over files?* — resource/data collisions, script-engine removal logs |
| M | *Do mods mean different things on the same path?* — typed AST, recipe/lang semantics, ref graph |
| F | *Will mixins step on each other?* — static mixin risk map, interaction graph |
| G–H | *Is anything suspicious or opaque?* — API usage scan, jar provenance |
| I | *Is the server actually hot here?* — Spark import correlated with mixin targets |
| J | *How are rules expressed?* — engine plumbing (not user-facing diagnosis) |
| K | *Did this combination work in practice?* — offline compatibility lab |
| L | *Runtime enforcement* — deferred |

## Three products in one binary

| Surface | Role | Example |
|---------|------|---------|
| **Doctor** | Diagnose a target; default UX | `intermed doctor ./mods --mixin-risk` |
| **PackOps / VFS** | Resource conflict explain + overlay **preview** + semantic plan | `intermed vfs overlay ./mods --out ./overlay`, `vfs explain --ast` |
| **Deps (Layer C)** | Dependency graph export + PubGrub resolution | `intermed deps resolve ./mods` |
| **Lab** | Reproducible compatibility **evidence** (not doctor) | `intermed lab run corpus.lock --logs ./captured` |

PackOps writes only to `--out`; it never mutates source jars. Lab is
**operations**: it does not register as a doctor collector.

## Static vs dynamic evidence

| Kind | Examples | Limit |
|------|----------|-------|
| **Static** | Constant pool, mixin annotations, jar manifest | Cannot see runtime-only behavior |
| **Import** | Spark JSON | Profiler must run elsewhere |
| **Log-derived** | Crash signatures, KubeJS/CraftTweaker removal lines | Best-effort markers |
| **Live execution** | Lab smoke on real JVM | **Structurally deferred** behind `SmokeRunner` |

InterMed prefers **honest gaps** (namespace mismatch, unresolved injection
points, unidentified jars) over silent certainty.

## Mixin intelligence (Layer F) in one minute

1. **Collect** mixin configs + class annotations (+ handler bytecode).
2. **Resolve** injection names via refmap / Tiny; build **canonical** keys in
   intermediary namespace when possible.
3. **Compare** injection sites via **`site_key`** (method + `@At` + locals) — not
   just method name.
4. **Analyze** with [`MixinInteractionEngine`](../crates/intermed-mixin-intel/src/analyzer.rs):
   overlaps, same-point conflicts, namespace mismatch, inherited targets,
   shadow/overwrite stacks, priority ordering, composite risk 0–100.
5. **Report** via `mixin-map`, `--mixin-risk`, and facts for SQL/Datalog rules.

No bytecode transformation is performed.

## Security + SBOM (G + H) in one minute

- **Security** scans `.class` constant pools for risky **member references**.
  Strings alone never fire; reflection-corroborated signals require visible
  dispatch machinery. One grouped finding per mod.
- **SBOM** fingerprints jars (hash, loader manifest, signing, trust score,
  graded `source_class`). A **correlation rule** warns when a weakly identified
  jar also shows high-risk capabilities.

## Compatibility lab (K) — offline vs live

**Implemented:** pin a corpus (`discover`), ingest captured smoke logs (`run`),
build a matrix (`report`), score doctor accuracy (`eval`).

**Deferred by design:** downloading mods, installing loaders, launching servers.
Those would implement the same `CandidateProvider` / `SmokeRunner` traits as the
in-tree file/captured providers — see
[`intermed-lab`](../crates/intermed-lab/src/lib.rs) module docs.

## Where to go next

- Commands: [EXAMPLES.md](EXAMPLES.md)
- Fact reference: [SCHEMA.md](SCHEMA.md), Layer M: [SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md)
- Implementation checklist: [STATUS.md](STATUS.md)
- Architecture rules for contributors: [CONVENTIONS.md](CONVENTIONS.md)