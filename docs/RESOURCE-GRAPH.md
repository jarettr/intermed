# Resource reference graph

The `ResourceGraph` (`semantic/refs.rs`) is the aggregated, pack-wide view built
from every parsed resource. It is **pure data with no opinions** — rules and
`explain` read it; it never emits findings.

```rust
struct ResourceGraph {
    definitions:      BTreeMap<String, BTreeSet<String>>, // resource_path → writers
    references:       Vec<RefEdge>,                        // outgoing edges
    namespace_owners: BTreeMap<String, BTreeSet<String>>, // namespace → writers
}
```

## Edges

| Relation | From → To | Source domain |
|----------|-----------|---------------|
| `uses_recipe_type` | recipe → serializer id | recipe |
| `produces_item` | recipe → item | recipe |
| `uses_item` | recipe/tag → item | recipe, tag |
| `uses_tag` | recipe/tag → tag | recipe, tag |
| `parent_model` | model → parent model | model |
| `uses_texture` | model → texture | model |
| `uses_model` | blockstate → model | blockstate |
| `loot_entry` | loot table → item/tag | loot_table |
| `atlas_source` | atlas → texture source | atlas |

## Namespace ownership

A namespace is *owned* when a jar ships any resource under `assets/<ns>/` or
`data/<ns>/`. Ownership is collected from **all** resources (including binary
assets, which contribute ownership without a per-file fact — backpressure). It is
the proxy for "this namespace exists in the pack", used by implicit-dependency
resolution (see [IMPLICIT-DEPS.md](IMPLICIT-DEPS.md)).

## What the graph powers

- **Implicit dependency candidates** — references into a non-platform namespace
  that no jar owns (`implicit_dependency_candidates()`).
- **Unresolved model references** (`unresolved_model_references()`) — model/
  blockstate references whose target file is absent from an installed, non-platform
  namespace.

### Why unresolved references are NOT a finding

This is the most important safety decision in the graph. An absent model file is
**not** proof of a broken reference:

- Mods generate models at runtime (AE2 formed multiblocks, Create connected
  blocks), via custom model loaders, or as baked models — no JSON file exists.
- Models can be supplied by a resource pack outside `mods/`.
- Vanilla `minecraft:` parents live in the Minecraft jar, not in mods.

Flagging these produced confirmed false positives on real packs (e.g.
`ae2:block/crafting/monitor_formed`). So the graph exposes unresolved references
**for `vfs explain --ast` only**, labelled "may be runtime-generated", and never
raises a finding. The `resource_dangling_reference` fact kind is reserved for a
future sound resolver (one that also indexes the MC jar and resource packs).

## Inspecting the graph

```sh
intermed vfs explain ./mods --path data/create/recipes/crushing/tuff.json --ast
```

shows the domain, every writer, the semantic diff, and the outgoing references for
one resource.

## See also

- [LAYER-M-DATA-SEMANTICS.md](LAYER-M-DATA-SEMANTICS.md)
- [SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md)
- [IMPLICIT-DEPS.md](IMPLICIT-DEPS.md)
- [OVERLAY-V2.md](OVERLAY-V2.md)
