# CL: Phase 2/3 Production Hardening

## Scope

Phase 2 and Phase 3 are now treated as production behavior inside their current
architecture boundary:

- no DuckDB/Souffle yet;
- no JVM bytecode worker;
- no mutation during `doctor`;
- PackOps writes only explicit overlay previews into a new output directory.

## User-visible commands

```bash
intermed doctor ./mods --dump-facts facts.json
intermed doctor ./mods --explain resource-conflict:data/minecraft/tags/items/test.json

intermed vfs scan ./mods
intermed vfs explain ./mods
intermed vfs overlay ./mods --out ./overlay
```

## Behavior

- `DiagnosticRun` preserves the report plus the raw fact snapshot from the same
  pipeline execution.
- `--dump-facts` writes the Phase-2 fact stream without re-running collectors.
- `--explain` expands a finding into rule id, fix candidates, evidence edges,
  source locations, attributes, and extractor ids.
- VFS scans `assets/**`, `data/**`, and `pack.mcmeta` inside jars.
- VFS emits `resource_writer`, `resource_collision`,
  `json_merge_candidate`, `safe_crdt_merge`, and
  `unsafe_replace_conflict` facts.
- One corrupt jar no longer fails the whole scan; it is reported as a scan
  failure and an `unparseable_archive` fact.
- Unsafe archive paths (`..`, absolute paths, empty path segments) are ignored
  before facts or overlay writes.
- PackOps stages overlay output in a temporary sibling directory and atomically
  renames it into place.
- PackOps refuses existing output directories and does not remove pre-existing
  temp directories it did not create.

## Test Matrix

Default `cargo test` covers:

- unit tests for fact/evidence/report/log/deps/VFS primitives;
- VFS integration tests for:
  - `safe-crdt-merge`;
  - `json-merge-candidate`;
  - `unsafe-replace`;
  - `identical`;
  - deterministic scan output;
  - corrupt jar tolerance;
  - unsafe archive path filtering;
- PackOps integration tests for:
  - merged tag overlay output;
  - manifest output;
  - existing output refusal;
  - temp directory ownership;
  - cleanup after stage errors;
- CLI e2e tests for:
  - `vfs explain` golden output;
  - `doctor --explain` golden output;
  - `doctor --dump-facts`;
  - `vfs overlay`;
  - missing-target negative path.

Optional real-mod smoke:

```bash
INTERMED_REAL_MODS_DIR=/path/to/real/mods \
  cargo test -- --ignored real_mods
```

This runs the VFS scanner and full `doctor --json` against a real mods
directory without making the default test suite depend on network or third-party
availability.

## Verification

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```
