# CL: Phase 4/5 Production Implementation

## Scope

Phase 4 and Phase 5 are implemented inside the current single-binary Rust
architecture:

- no mixin transformation;
- no JVM worker;
- no code execution from jars;
- no mandatory external Datalog runtime for default operation;
- Souffle is a real optional backend gated on a local `souffle` binary.

## User-visible commands

```bash
intermed doctor ./mods --mixin-risk
intermed mixin-map ./mods

intermed doctor ./mods --logic=imperative
intermed doctor ./mods --logic=datalog
intermed doctor ./mods --logic=souffle
intermed rules check ./rules
```

## Phase 4 Behavior

- Scans mixin config JSON files inside jars.
- Resolves config package + `mixins`/`client`/`server` entries to class paths.
- Reads class-file constant-pool UTF-8 entries when the class has a valid
  `CAFEBABE` header; falls back to printable string extraction for tolerant
  fixtures or partial class evidence.
- Detects Mixin operation evidence:
  - `@Inject`;
  - `@Redirect`;
  - `@Overwrite`;
  - `@ModifyArg`;
  - `@ModifyVariable`;
  - `@ModifyConstant`.
- Detects target class descriptors and normalizes them to dotted names.
- Emits facts:
  - `mixin_config`;
  - `mixin_class`;
  - `mixin_target`;
  - `mixin_operation`;
  - `mixin_hotspot`;
  - `mixin_overlap`;
  - `high_risk_overwrite`.
- Derives findings for target overlap and overwrite risk.
- Escalates hot-path overlaps/overwrites for renderer, server tick, chunk,
  entity, network, and registry targets.
- Tolerates missing listed classes and records scan failures instead of failing
  the whole pack.

## Phase 5 Behavior

- Adds `intermed-rule-pack-v1`.
- Adds an in-process Datalog-compatible evaluator implementing the existing
  `Rule` trait.
- Adds a committed default rule pack at
  `rules/core/intermed-core.rules.json`.
- Adds `intermed rules check` for JSON/YAML rule-pack validation.
- Adds `doctor --logic=imperative|datalog|souffle`.
- `--logic=souffle` materializes selected facts as `.facts`, writes a generated
  `.dl` program, runs `souffle -F ... -D ...`, and maps output relations back to
  normal findings.
- Keeps imperative rules as fallback for rules not yet ported to declarative
  packs.

## Test Matrix

Default `cargo test` covers:

- mixin unit tests for operation/target extraction and overlap classification;
- mixin integration tests for:
  - cross-mod target overlap;
  - high-risk overwrite detection;
  - missing mixin class tolerance;
- rule-pack unit tests for:
  - default pack validation;
  - duplicate-id finding emission;
  - invalid rule shape rejection;
- CLI e2e tests for:
  - `mixin-map` golden output;
  - `doctor --logic=datalog`;
  - `doctor --logic=souffle` real optional backend behavior;
  - `rules check ./rules`;
  - invalid rule-pack negative path.

Optional real-mod smoke:

```bash
INTERMED_REAL_MODS_DIR=/path/to/real/mods \
  cargo test -- --ignored real_mods
```

This runs VFS, Mixin Map, and `doctor --json` against a real mods directory.

## Verification

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
INTERMED_REAL_MODS_DIR=/home/mak/.minecraft/mods cargo test -- --ignored real_mods
```
