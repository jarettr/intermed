# Resource AST — domain parsers

Each Layer-M domain parser lowers one resource's syntax tree into a compact,
serialisable [`ResourceSummary`] plus outgoing [`ResourceReference`]s. The full
syntax tree is transient (parsed, summarised, dropped — backpressure); only the
compact summary is cached and lowered to facts.

Common rules for every parser:

- **Never panics.** Malformed input becomes `ParseStatus::Invalid` (or
  `PartiallyParsed`) with a diagnostic — never a crash. Guaranteed by the
  `parse_never_panics_*` property tests.
- **Order-independent.** Summaries are canonical (sets sorted + de-duplicated), so
  the `semantic_hash` is stable under key/entry reordering. Guaranteed by the
  `*_order_independent` / `*_canonical_set` property tests.
- **Generic over schema.** Modded schemas are open-ended, so parsers favour
  generic traversal over per-type schemas.

Parser versions (`*_AST_VERSION`) are folded into the cache key; bump one to
invalidate just that domain.

---

## tag (`tag-r1`)

- **Supported paths:** `data/<ns>/tags/<registry...>/<path>.json`
- **Parsed fields:** `replace`, `values` (string ids, `#tag` refs, and
  `{ "id", "required" }` objects), derived `registry` (nested registries like
  `worldgen/biome` supported).
- **Ignored:** anything outside `values`/`replace`.
- **Summary:** `registry`, `replace`, `entry_count` (de-duplicated),
  `has_required_flag`, sorted `entries`.
- **References:** one per entry — `uses_tag` for `#` refs, `uses_item` otherwise.
- **Limitations:** does not resolve nested tag membership (that needs the whole
  registry); `required` semantics are recorded, not interpreted here.
- **Safety:** tag merge is a set union and order-independent **unless** a writer
  sets `replace: true`. Layer M never treats differing tags as a conflict.

## recipe (`recipe-r1`)

- **Supported paths:** `data/<ns>/recipe[s]/<path>.json`
- **Parsed fields:** `type`; outputs from `result`/`results`/`output`/`outputs`;
  ingredients from every other `item`/`tag`/bare resource `id`; load `conditions`
  (`conditions`, `fabric:load_conditions`, `neoforge:conditions`).
- **Ignored:** type-specific fields (pattern keys, processing time, etc.) beyond
  item/tag extraction.
- **Summary:** `recipe_type`, `ingredient_count`, `output_count`,
  `has_conditions`, sorted `outputs`, sorted `ingredients`.
- **References:** `uses_recipe_type` (the serializer), `produces_item`,
  `uses_item`, `uses_tag`. Conditioned recipes mark their refs `conditioned` and
  non-`required`.
- **Limitations:** generic traversal may miss exotic custom result schemas; it
  errs toward fewer refs, not false ones.
- **Safety:** recipes are single-document — multiple writers = a load-order
  override. The valuable signal is when the **outputs differ** (see diff layer).

## lang (`lang-r2`)

- **Supported paths:** `assets/<ns>/lang/<locale>.json` and legacy `.lang`.
- **Parsed fields:** flat `key → value` map (`format` = `json` | `properties`).
- **Summary:** `format`, `key_count`, `entries` (kept so the diff layer can detect
  same-key/different-value conflicts; bounded by `max_json_bytes`).
- **Safety:** disjoint keys union safely; a shared key with different text is a
  load-order-dependent display change (`Note`).

## pack.mcmeta (`pack-mcmeta-r1`)

- **Supported paths:** `pack.mcmeta`
- **Parsed fields:** `pack.pack_format`, `pack.supported_formats`
  (min/max, scalar/array/object forms), presence of `description`.
- **Summary:** `pack_format`, `supported_min`, `supported_max`, `has_description`.

## model (`model-r1`) — *full* level

- **Supported paths:** `assets/<ns>/models/<path>.json`
- **Parsed fields:** `parent`; `textures` (real asset refs only — `#var`
  references are texture variables, not assets, and are excluded); `overrides`
  count.
- **References:** `parent_model`, `uses_texture`.
- **Limitations:** does not resolve runtime/baked models (see RESOURCE-GRAPH.md).

## blockstate (`blockstate-r1`) — *full* level

- **Supported paths:** `assets/<ns>/blockstates/<path>.json`
- **Parsed fields:** `variants` / `multipart` model references.
- **References:** `uses_model`.

## loot_table (`loot-table-r1`) — *full* level

- **Supported paths:** `data/<ns>/loot_table[s]/<path>.json`
- **Parsed fields:** pools and entries (recursively into children).
- **References:** `loot_entry` (item/tag drops).

## atlas (`atlas-r1`) — *full* level

- **Supported paths:** `assets/<ns>/atlases/<path>.json`
- **Parsed fields:** `sources` count, whether any non-`single` source is present.

---

## Cache

The per-resource [`CachedResourceAst`] is the shared-`JarCache` payload. See
[CACHE.md](CACHE.md) for tiers; Layer M only adds its own cache-key version
(crate version + folded `parser_version` + level), so a parser or level change
invalidates entries without touching unrelated jars.

## See also

- [LAYER-M-DATA-SEMANTICS.md](LAYER-M-DATA-SEMANTICS.md)
- [SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md)
- [CACHE.md](CACHE.md)
- [CL-LAYER-M.md](CL-LAYER-M.md)
