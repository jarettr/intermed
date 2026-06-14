# CL: Phase 6/7 Production Implementation

## Scope

Phases 6 and 7 ship inside the single-binary Rust architecture:

- no bytecode transformation;
- no JVM worker;
- no code execution from jars;
- Spark import reads JSON only (no forked profiler).

## User-visible commands

```bash
# Layer G/H — always on for mods targets
intermed doctor ./mods --json
intermed doctor ./mods --dump-facts facts.json
intermed doctor ./mods --explain security-api-risk:risky

# Layer I — gated like mixin-risk
intermed doctor ./server --performance
intermed doctor ./server --performance --spark-report ./spark/profile.json
intermed spark-map ./server --spark-report ./spark/profile.json
```

## Phase 6 Behavior (Layers G + H)

### Layer H — SBOM (`intermed-sbom`)

- SHA-256 checksum per jar.
- Identity from `fabric.mod.json` / `quilt.mod.json` / Forge `mods.toml`.
- JAR signing detection via `META-INF/*.SF`.
- Trust score heuristic (manifest + version + loader + signing).
- Emits: `checksum`, `artifact_identity`, `unknown_source`, `signature_status`, `sbom`, `trust_score`.
- Rule `sbom-provenance`: Warn on `unknown_source`, Note on unsigned jars.
- Jar cache partial: `sbom-generator`.

### Layer G — Security (`intermed-security-audit`)

- Walks `.class` entries; verifies `0xCAFEBABE` magic before parsing.
- Parses constant pools via cafebabe + noak fallback.
- Detects risky API evidence from **method references** (not bare UTF-8 strings).
- Emits per-mod `uses_*` facts (six signal kinds; no `writes_files`).
- Rule `security-api-risk`: **one grouped finding per mod**; Warn for process spawn / Unsafe / defineClass; Note for socket / reflection / native load; threshold suppresses single Note signals.
- Jar cache partial: `security-scanner`.

## Phase 7 Behavior (Layer I)

- Import format: `intermed-spark-report-v1` JSON.
- Discovery: `--spark-report`, `spark/*.json`, `profiler/*.json`.
- Emits: `tick_spike`, `hot_method`, `hot_mod`, `gc_pause`, `heap_pressure`, `thread_hotspot`.
- Rule `performance-correlation` (cross-layer): joins `hot_method` / `hot_mod`
  against mixin **target** facts (`mixin_target` / `mixin_operation` /
  `mixin_overlap` / `high_risk_overwrite`); `@Overwrite`, multi-mod, or ≥ 50% CPU
  escalate to Error. Tick spikes ≥ 50 ms still emit standalone. See
  [LAYER-I-SPARK.md](LAYER-I-SPARK.md).
- `spark-map` subcommand for standalone inspection.

## Test Matrix

```bash
cargo test -p intermed-sbom
cargo test -p intermed-security-audit
cargo test -p intermed-spark-bridge
cargo test -p intermed-cli --test e2e
```

E2E covers:

- `checksum` / `sbom` / `uses_process_spawn` in `--dump-facts`;
- grouped `security-api-risk` finding for process spawn;
- `--explain security-api-risk:{mod}` golden output;
- `--performance` + `--spark-report` fact_stats;
- `spark-map` stdout;
- cache/profile quirks (`--no-cache --json` omits profile; `--profile` always writes).

## Verification

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
cargo build
```