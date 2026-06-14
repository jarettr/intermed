# InterMed

A **Minecraft modpack / server evidence engine**. Point it at a server, an
instance, a mods directory, or a log, and it builds a fact graph, derives
findings with full provenance, and emits a diagnosis you can read in the
terminal or feed to CI.

> Doctor and PackOps **explain**. Runtime **enforces**.

This is a ground-up Rust reimplementation of the older Java InterMed runtime,
refocused from *enforcement* to *evidence*. Start with [`docs/CONCEPTS.md`](docs/CONCEPTS.md)
for how the engine works, [`docs/STATUS.md`](docs/STATUS.md) for what each layer
does today, and [`docs/ROADMAP.md`](docs/ROADMAP.md) for the phase plan.
[`docs/donor-inventory.md`](docs/donor-inventory.md) maps the Java port.
The current Phase 2/3 changelist is documented in
[`docs/CL-PHASE-2-3.md`](docs/CL-PHASE-2-3.md).
The current Phase 4/5 changelist is documented in
[`docs/CL-PHASE-4-5.md`](docs/CL-PHASE-4-5.md).
Phases 6/7: [`docs/CL-PHASE-6-7.md`](docs/CL-PHASE-6-7.md).
Cache/profile: [`docs/CL-CACHE-PROFILE.md`](docs/CL-CACHE-PROFILE.md).
Layer M (resource AST): [`docs/CL-LAYER-M.md`](docs/CL-LAYER-M.md),
[`docs/LAYER-M-DATA-SEMANTICS.md`](docs/LAYER-M-DATA-SEMANTICS.md).

## Quick start

```bash
cargo build --release

# Diagnose things:
intermed doctor ./server          # a dedicated server (scans mods + logs/)
intermed doctor ./mods            # a bare mods directory
intermed doctor latest.log        # a single log or crash report
intermed doctor ./server --json   # machine-readable intermed-doctor-report-v1
intermed doctor ./server --sarif  # SARIF 2.1.0 for IDE / CI
intermed doctor ./mods --dump-facts facts.json
intermed doctor ./mods --explain finding_id

# Inspect resource/data overrides:
intermed vfs scan ./mods
intermed vfs explain ./mods
intermed vfs overlay ./mods --out ./overlay
intermed vfs explain ./mods --path data/foo/recipes/bar.json --ast
intermed vfs overlay ./mods --explain-plan
intermed doctor ./mods --resource-level semantic

# Inspect Mixin risk and rule packs:
intermed mixin-map ./mods
intermed doctor ./mods --mixin-risk
intermed doctor ./mods --logic=datalog
intermed doctor ./mods --logic=souffle  # requires `souffle` in PATH

# DuckDB SQL backend + analytics (optional, feature-gated)
cargo build -p intermed-cli --features duckdb
intermed doctor ./mods --logic=duckdb --mixin-risk
intermed doctor ./mods --db history.duckdb
intermed db query --db history.duckdb "SELECT kind, COUNT(*) FROM facts GROUP BY kind"

intermed rules check ./rules

# SBOM + security (Phase 6, always on for mods)
intermed doctor ./mods --json

# Spark import (Phase 7, gated)
intermed doctor ./server --performance
intermed spark-map ./server --spark-report ./spark/profile.json

# Compatibility Lab (Phase 8)
intermed lab discover ./candidates.json --out corpus.lock
intermed lab run corpus.lock --logs ./captured --out ./runs/latest
intermed lab report ./runs/latest --out ./site

# Cache + profiling (doctor)
intermed doctor ./mods --profile profile.json
intermed doctor ./mods --no-cache
```

Exit code: `0` healthy, `1` warnings only, `2` errors or worse.

More examples: [`docs/EXAMPLES.md`](docs/EXAMPLES.md). Concepts:
[`docs/CONCEPTS.md`](docs/CONCEPTS.md). Layer status:
[`docs/STATUS.md`](docs/STATUS.md). Jar cache: [`docs/CACHE.md`](docs/CACHE.md).
Profiling: [`docs/PROFILING.md`](docs/PROFILING.md).
Man page: `man -l docs/man/intermed.1` (generated at build time).

## How it works

```
Target ──▶ [Collectors] ──▶ FactStore ──▶ [Rules] ──▶ Findings ──▶ DoctorReport
```

Collectors observe (one per diagnostic layer A–L); rules infer; the report is
the single structured artifact rendered to terminal / JSON / SARIF. The engine
is generic — layers plug in at the CLI. See
[`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) and [`docs/SCHEMA.md`](docs/SCHEMA.md).

## Workspace

Core (Phases 1–8): `intermed-facts`, `intermed-evidence`, `intermed-report`,
`intermed-doctor-core`, `intermed-minecraft-scan`, `intermed-log`,
`intermed-deps`, `intermed-rules`, `intermed-vfs`, `intermed-packops`,
`intermed-resource-ast`, `intermed-dynamics`, `intermed-mixin-intel`,
`intermed-security-audit`,
`intermed-sbom`, `intermed-spark-bridge`, `intermed-lab`, `intermed-cli`.

Optional: `intermed-duckdb` (feature `duckdb`). Deferred: `intermed-runtime-preflight`.

## License

MIT.
