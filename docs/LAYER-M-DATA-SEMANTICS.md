# Layer M — resource / data semantics (typed resource AST)

Layer M adds a **typed-AST view** over the Layer-E VFS. Where Layer E sees bytes
and byte-level collisions, Layer M sees *meaning*: a recipe's serializer type and
outputs, a tag's entries and replace mode, a model's parent and textures, and the
reference graph that ties them together.

It is implemented in `crates/intermed-resource-ast` and reuses the existing
shared infrastructure — the per-jar [`JarCache`](CACHE.md), the `--jobs` thread
pool, and the `facts → rules → findings → report` pipeline.

## The contract: the AST never emits findings

Layer M keeps InterMed's philosophy exactly. Collectors observe and emit facts;
rules draw conclusions; the report shows them. The pipeline is:

```
resource bytes
  → syntax AST            (serde_json::Value / key=value)
  → typed domain AST      (TagAst, RecipeSummary, …)
  → semantic summary      (compact, order-independent)
  → facts                 (resource_ast_parsed, resource_semantic_diff, …)
  → rules produce findings (recipe-output-override, implicit-dependency-missing, …)
```

The collector never produces a `Finding`. See [RESOURCE-AST.md](RESOURCE-AST.md)
for the per-domain parsers and [SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md)
for the emitted facts.

## Depth levels

Controlled by `--resource-level` (CLI), `[resource] level` (config), or
`INTERMED_RESOURCE_LEVEL` (env):

| Level | What runs |
|-------|-----------|
| `basic` | Layer M off — only the Layer-E raw VFS (writers, collisions, rough tag/lang merge). |
| `semantic` (default) | Tags, recipes, lang, `pack.mcmeta`, namespace / reference graph. |
| `full` | Adds models, blockstates, loot tables, atlases. |

```toml
[resource]
level = "semantic"          # basic | semantic | full
max_json_bytes = 1048576    # per-resource JSON cap (DoS guard)
max_ast_facts_per_resource = 256
```

## What Layer M adds that Layer E cannot

- **Recipe output overrides** — two mods define the same recipe path producing
  *different items*. Layer E sees "json-override, pick a winner"; Layer M proves
  the *result changes* (e.g. `create:crushed_raw_gold` vs
  `createaddition:electrum_nugget` for `crushing/ochrum`). A `Warn`.
- **Lang key conflicts** — the same locale key bound to different text. A `Note`.
- **Implicit dependencies** — a recipe whose serializer `type` namespace is not
  installed (resolved by Layer C, see [IMPLICIT-DEPS.md](IMPLICIT-DEPS.md)).
- **The reference graph** — definitions, references and namespace ownership across
  the pack (see [RESOURCE-GRAPH.md](RESOURCE-GRAPH.md)).
- **A semantic overlay plan** — safe / review / unsafe buckets
  (see [OVERLAY-V2.md](OVERLAY-V2.md)).

## Anti-false-positive stance

False positives are the cardinal sin here, so Layer M is deliberately narrow:

- It reports a cross-writer diff **only** for recipe-output-override and
  lang-key-conflict. Tags *union* (differing content is benign) and single-document
  overrides are already classified by Layer E — re-flagging either would be noise.
- It does **not** raise "dangling model reference" findings. Mods generate models
  at runtime (AE2 formed multiblocks, custom model loaders) or ship them in
  resource packs, so an absent file is not proof of breakage. Unresolved
  references are shown only in `vfs explain --ast`, clearly labelled
  "may be runtime-generated".
- Implicit-dependency conclusions are limited to the lowest-FP signal — an
  unconditioned recipe serializer type whose mod is absent.

## CLI

```sh
intermed doctor ./mods --resource-level full
intermed vfs explain ./mods --path data/create/recipes/crushing/tuff.json --ast
intermed vfs overlay ./mods --out ./overlay --explain-plan
```

## Status

```
Layer M status:      active experimental
resource-ast cache:  r1 (intermed-resource-ast-cache-v1)
tag parser:          tag-r1
recipe parser:       recipe-r1
lang parser:         lang-r2
overlay plan:        v2
```

## See also

- [CL-LAYER-M.md](CL-LAYER-M.md) — implementation changelog and test matrix
- [RESOURCE-AST.md](RESOURCE-AST.md) — domain parsers
- [SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md) — fact vocabulary
- [RESOURCE-GRAPH.md](RESOURCE-GRAPH.md) — reference graph
- [IMPLICIT-DEPS.md](IMPLICIT-DEPS.md) — M → C cross-layer
- [OVERLAY-V2.md](OVERLAY-V2.md) — semantic overlay plan
- [CONFIG.md](CONFIG.md) — `[resource]` section
