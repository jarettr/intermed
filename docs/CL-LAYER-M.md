# CL: Layer M — resource / data semantics (typed AST)

## Scope

Layer M ships inside the single-binary Rust architecture:

- no bytecode transformation;
- no JVM worker;
- AST collectors emit **facts only** — rules produce findings;
- full syntax trees are transient; only compact summaries enter cache and
  `FactStore`;
- reuses the shared [`JarCache`](CACHE.md) (collector id `resource-ast-scanner`).

Crate: [`intermed-resource-ast`](../crates/intermed-resource-ast/).

## User-visible commands

```bash
# Layer M on doctor (default: semantic level)
intermed doctor ./mods --resource-level semantic
intermed doctor ./mods --resource-level full
intermed doctor ./mods --resource-level basic   # AST off — Layer E only

# Per-resource AST explain
intermed vfs explain ./mods --path data/create/recipes/crushing/tuff.json --ast

# Semantic overlay plan (read-only JSON)
intermed vfs overlay ./mods --explain-plan

# Facts / explain
intermed doctor ./mods --dump-facts facts.json   # resource_ast_parsed, …
intermed doctor ./mods --explain recipe-output-override:data/.../x.json
```

Config (`intermed-config-v1`):

```toml
[resource]
level = "semantic"              # basic | semantic | full
max_json_bytes = 1048576
max_ast_facts_per_resource = 256
```

Env: `INTERMED_RESOURCE_LEVEL`.

## Depth levels

| Level | Domains parsed |
|-------|----------------|
| `basic` | Layer M disabled |
| `semantic` (default) | tag, recipe, lang, pack.mcmeta, namespace/ref graph |
| `full` | + model, blockstate, loot table, atlas |

## Pipeline

```text
resource bytes → syntax AST → typed domain AST → semantic summary → facts → rules → findings
```

Collectors: `ResourceAstCollector` (parallel per jar via `--jobs` / `INTERMED_JOBS`).

Facts emitted: `resource_ast_parsed`, `resource_definition`, `resource_reference`,
`namespace_owner`, `implicit_dependency_candidate`, `resource_semantic_diff`.

Rules:

| Rule | Findings |
|------|----------|
| `resource-semantics` (Layer M) | `recipe-output-override:*` (`Warn`), `lang-key-conflict` (`Note`) |
| `dependency` (Layer C) | `implicit-dependency-missing` (`Note`, recipe serializer only) |

Cross-layer: Layer M emits `implicit_dependency_candidate`; Layer C resolves against
installed mods, `provides` aliases, and `namespace_owner`.

## Overlay plan v2

`intermed vfs overlay --explain-plan` emits `intermed-overlay-plan-v2` with
`safe_items` / `review_items` / `unsafe_items`. Layer-M semantic diffs escalate
collisions into `review_items`. See [OVERLAY-V2.md](OVERLAY-V2.md).

## Anti-false-positive decisions

- No finding for dangling model/texture refs (runtime-generated models).
- No semantic-diff finding for tags (union is benign unless `replace: true` —
  already Layer E).
- Implicit deps: only unconditioned `via_recipe_type` + `required` candidates.

## Test matrix

```bash
cargo test -p intermed-resource-ast
cargo test -p intermed-resource-ast --test golden
cargo test -p intermed-resource-ast --test properties
cargo test -p intermed-cli --test e2e
```

Coverage:

- domain parser unit tests (tag, recipe, lang, model, …);
- golden AST summaries (`tests/fixtures/resource_ast/`, regenerate with
  `UPDATE_GOLDEN=1 cargo test -p intermed-resource-ast --test golden`);
- property tests (order-independent semantic hash, tag canonical set);
- proptest fuzz (`parse_never_panics_*`);
- rule unit tests (`recipe_override_warns_per_recipe`, implicit deps in
  `intermed-deps`);
- CLI e2e (VFS explain, doctor resource findings).

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p intermed-resource-ast
```

## Documentation

| Doc | Topic |
|-----|-------|
| [LAYER-M-DATA-SEMANTICS.md](LAYER-M-DATA-SEMANTICS.md) | Layer overview |
| [RESOURCE-AST.md](RESOURCE-AST.md) | Domain parsers |
| [RESOURCE-GRAPH.md](RESOURCE-GRAPH.md) | Reference graph |
| [SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md) | Fact vocabulary |
| [IMPLICIT-DEPS.md](IMPLICIT-DEPS.md) | M → C cross-layer |
| [OVERLAY-V2.md](OVERLAY-V2.md) | Semantic overlay plan |