# Schema — Layer M resource facts

Compact facts lowered from per-resource AST summaries. The AST collector
(`resource-ast-scanner`) emits these; rules read them. **No finding is emitted
from the collector.**

Canonical predicate names live in [`intermed_facts::kind`](../crates/intermed-facts/src/lib.rs).
This document is the Layer-M vocabulary reference. General fact conventions:
[SCHEMA.md](SCHEMA.md).

## Emitted predicates

### `resource_ast_parsed`

One row per parsed resource per writer.

| Attribute | Type | Meaning |
|-----------|------|---------|
| `domain` | string | `tag`, `recipe`, `lang`, `model`, … |
| `parse_status` | string | `parsed`, `partially-parsed`, `invalid`, `skipped` |
| `semantic_hash` | string | Order-independent summary hash |
| `writer` | string | Mod id that wrote this resource |
| `archive` | string | Source jar file name |
| `ref_count` | int | Outgoing reference count (may be truncated) |
| `diagnostic_count` | int | Parse diagnostics on this resource |

Domain-specific summary attrs (on the same fact):

| Domain | Extra attrs |
|--------|-------------|
| `tag` | `registry`, `replace`, `entry_count`, `has_required_flag` |
| `recipe` | `recipe_type`, `ingredient_count`, `output_count`, `has_conditions` |
| `lang` | `format` (`json` \| `properties`), `key_count` |
| `pack-mcmeta` | `pack_format`, `has_description` |
| `model` | `parent`, `texture_count`, `override_count` |
| `blockstate` | `variant_count`, `model_count` |
| `loot-table` | `pool_count`, `entry_count` |
| `atlas` | `source_count`, `has_non_single_source` |

Example:

```text
resource_ast_parsed(
  subject="data/create/recipes/crushing/tuff.json",
  domain="recipe",
  parse_status="parsed",
  recipe_type="create:crushing",
  output_count=1,
  writer="create",
  archive="create-fabric-1.20.1.jar"
)
```

### `resource_definition`

Maps a resource path to a defining writer and namespace.

| Attribute | Meaning |
|-----------|---------|
| `domain` | Resource domain |
| `namespace` | Path namespace (`create`, `minecraft`, …) |
| `writer` | Mod id |

### `resource_reference`

One outgoing semantic edge from a resource.

| Attribute | Meaning |
|-----------|---------|
| `relation` | `uses_item`, `uses_tag`, `uses_recipe_type`, `produces_item`, `parent_model`, `uses_texture`, `uses_model`, `loot_entry`, `atlas_source`, … |
| `to` | Referenced id (`create:crushing`, `minecraft:tuff`, `#minecraft:logs`) |
| `namespace` | Namespace component of `to` |
| `required` | bool — absence would break the resource |
| `conditioned` | bool — gated behind load conditions |
| `is_tag` | bool — `to` is a tag reference |

Fan-out is bounded by `max_ast_facts_per_resource` (default 256).

Example:

```text
resource_reference(
  subject="data/foo/recipes/bar.json",
  relation="uses_recipe_type",
  to="create:crushing",
  namespace="create",
  required=true,
  conditioned=false
)
```

### `namespace_owner`

A jar ships resources under a namespace (including binary-only assets).

| Attribute | Meaning |
|-----------|---------|
| `writer` | Mod id |

Subject = namespace string.

### `implicit_dependency_candidate`

Layer M observes; Layer C resolves. One row per **namespace** (aggregated).

| Attribute | Meaning |
|-----------|---------|
| `from_path` | Sample resource path |
| `target` | Sample referenced id |
| `ref_count` | References into this namespace |
| `required` | At least one unconditioned reference |
| `via_recipe_type` | Referenced as a recipe serializer `type` |

See [IMPLICIT-DEPS.md](IMPLICIT-DEPS.md).

### `resource_semantic_diff`

Cross-writer semantic disagreement on the same resource path.

| Attribute | Meaning |
|-----------|---------|
| `diff_kind` | `recipe-output-override`, `lang-key-conflict` |
| `writers` | Comma-separated mod ids |
| `writer_count` | int |
| `detail` | Human-readable diff summary |

Rules:

| `diff_kind` | Finding |
|-------------|---------|
| `recipe-output-override` | `recipe-output-override:{path}` (`Warn`) |
| `lang-key-conflict` | `lang-key-conflict` grouped (`Note`) |

## Reserved (not emitted today)

### `resource_dangling_reference`

Reserved for a future sound resolver (MC jar + resource packs indexed). Unresolved
model references are surfaced in `vfs explain --ast` only — not as facts or
findings. See [RESOURCE-GRAPH.md](RESOURCE-GRAPH.md).

## Cache payload (not facts)

Per-jar cache records (`intermed-resource-ast-cache-v1`) store
[`CachedResourceAst`](../crates/intermed-resource-ast/src/model.rs) summaries —
not the fact stream. Cache key version folds crate version, schema, combined
`parser_version`, and `resource_level`. See [CACHE.md](CACHE.md) and
[RESOURCE-AST.md](RESOURCE-AST.md).

## Parser versions (cache invalidation)

| Domain | Version constant |
|--------|------------------|
| tag | `tag-r1` |
| recipe | `recipe-r1` |
| lang | `lang-r2` |
| pack.mcmeta | `pack-mcmeta-r1` |
| model | `model-r1` |
| blockstate | `blockstate-r1` |
| loot table | `loot-table-r1` |
| atlas | `atlas-r1` |

Bump a domain's `*_AST_VERSION` when its summary or references change.

## Findings produced from these facts

| Rule id | Layer | Finding |
|---------|-------|---------|
| `resource-semantics` | M | `recipe-output-override:*`, `lang-key-conflict` |
| `dependency` | C | `implicit-dependency-missing` |

## See also

- [LAYER-M-DATA-SEMANTICS.md](LAYER-M-DATA-SEMANTICS.md)
- [RESOURCE-AST.md](RESOURCE-AST.md)
- [RESOURCE-GRAPH.md](RESOURCE-GRAPH.md)