# Resources and overlays

When two mods (or a datapack) ship the same file — `data/minecraft/recipes/stick.json`,
`assets/minecraft/atlases/blocks.json`, a tag — the game keeps one or merges them
by load order. InterMed reads every such file, groups them by path, and reports
what happens at each collision.

There are two views: the byte-level view (who writes what, who wins) and the
semantic view (what the file *means* — a recipe's output, a tag's entries).

## Who writes which file

```bash
intermed vfs scan ./mods
```

This lists every resource path written by more than one source and classifies the
collision:

- **Safe merge** — pure-append tags, compatible sound-event definitions, and
  language files whose shared keys agree. Both sources' entries survive under
  the domain's actual semantics. Benign; reported as a note.
- **Override** — a single-document file (a recipe, a model, a loot table) where
  only one copy survives by load order. The others are dropped.
- **Order-dependent** — an atlas or similar file where merging is not a plain
  union: source order decides which textures win, so the result depends on load
  order.

## What a file means

With the semantic layer on, InterMed parses the file and compares meaning, not
just bytes:

```bash
intermed doctor ./mods --resource-level semantic   # recipes, tags, lang, pack.mcmeta
intermed doctor ./mods --resource-level full        # + models, blockstates, loot, atlases, advancements
```

It reports, for example:

- **Recipe output override** — two mods define the same recipe id with different
  outputs or quantities; only one definition survives.
- **Loot/model/blockstate semantic override** — item ids may agree while rolls,
  weights, texture mappings, predicates, rotations, or shaped layout differ.
- **Platform-resource observation** — operations such as `"replace": true` on a
  vanilla tag remain available in JSON/`--explain`, but are not called failures or
  security findings by themselves.

Physical presence is tracked separately from AST validity. A resource that is too
large to parse, malformed, or only seen in the ZIP directory is not mistaken for
an absent file. Reference extraction is bounded per resource; truncation marks the
collector incomplete and prevents definitive absence conclusions. Tag membership
is unioned only when order-independent; `replace:true` remains unresolved until an
authoritative resource priority is available.

Script-driven changes are accounted for: if a KubeJS or CraftTweaker script
selects a recipe, the static conclusion is caveated according to selector,
script phase, evidence origin, and runtime-session provenance. A static script
declaration is not treated as proof that the mutation executed.

## Inspecting one file

```bash
intermed vfs explain ./mods --path data/foo/recipes/bar.json --ast
```

This shows every writer of that path, the parsed AST, and how the writers differ.

## Previewing the merged result

```bash
intermed vfs overlay ./mods --out ./overlay
```

This writes only domain-specific, order-independent merges that InterMed can
materialize safely. It is not a reconstruction of the game's full resource
stack: launcher packs, server datapacks, runtime generators, and loader order
may still change the effective result. Unsafe winner previews require explicit
opt-in. Source jars are never touched. Add `--explain-plan` to print the plan
without writing files.

For the full flag list, see
[the command reference](../reference/commands.md#vfs). For the resource model in
detail, see [What each analysis examines](../reference/analysis.md#resources).
