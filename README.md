# InterMed

A **Minecraft modpack / server evidence engine**. Point it at a server, an
instance, a mods directory, or a log, and it builds a fact graph, derives
findings with full provenance, and emits a diagnosis you can read in the
terminal or feed to CI.

> Doctor and PackOps **explain**. Runtime **enforces**.

This is a ground-up Rust reimplementation of the older Java InterMed runtime,
refocused from *enforcement* to *evidence*. See [`docs/ROADMAP.md`](docs/ROADMAP.md)
for the phase plan and [`docs/donor-inventory.md`](docs/donor-inventory.md) for
how the Java codebase is being ported (port-by-behavior, not copy).
The current Phase 2/3 changelist is documented in
[`docs/CL-PHASE-2-3.md`](docs/CL-PHASE-2-3.md).
The current Phase 4/5 changelist is documented in
[`docs/CL-PHASE-4-5.md`](docs/CL-PHASE-4-5.md).

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

# Inspect Mixin risk and rule packs:
intermed mixin-map ./mods
intermed doctor ./mods --mixin-risk
intermed doctor ./mods --logic=datalog
intermed doctor ./mods --logic=souffle  # requires `souffle` in PATH
intermed rules check ./rules
```

Exit code: `0` healthy, `1` warnings only, `2` errors or worse.

## How it works

```
Target ──▶ [Collectors] ──▶ FactStore ──▶ [Rules] ──▶ Findings ──▶ DoctorReport
```

Collectors observe (one per diagnostic layer A–L); rules infer; the report is
the single structured artifact rendered to terminal / JSON / SARIF. The engine
is generic — layers plug in at the CLI. See
[`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) and [`docs/SCHEMA.md`](docs/SCHEMA.md).

## Workspace

Working (Phases 1-5): `intermed-facts`, `intermed-evidence`, `intermed-report`,
`intermed-doctor-core`, `intermed-minecraft-scan`, `intermed-log`,
`intermed-deps`, `intermed-rules`, `intermed-vfs`, `intermed-packops`,
`intermed-mixin-intel`, `intermed-cli`.

Wired stubs (later phases): `intermed-security-audit`, `intermed-sbom`,
`intermed-spark-bridge`, `intermed-lab`, `intermed-runtime-preflight`.

## License

MIT.
