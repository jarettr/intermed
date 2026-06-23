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

- **Safe merge** — tags, language files, and other documents the game unions.
  Both mods' entries survive. Benign; reported as a note.
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

- **Recipe output override** — two mods produce the same item from different
  recipes; only one survives.
- **A mod replaces a platform tag** — a mod's tag uses `"replace": true` against a
  vanilla or convention tag, discarding other mods' entries.
- **A mod disables a platform recipe** — a mod ships an empty recipe at a
  vanilla recipe's path, removing it.

Script-driven changes are accounted for: if a KubeJS or CraftTweaker script
removes a recipe, an override of that recipe is not reported as a conflict,
because the script deletes it anyway.

## Inspecting one file

```bash
intermed vfs explain ./mods --path data/foo/recipes/bar.json --ast
```

This shows every writer of that path, the parsed AST, and how the writers differ.

## Previewing the merged result

```bash
intermed vfs overlay ./mods --out ./overlay
```

This writes the merged copy of each resource — exactly what the game would load —
into the `--out` directory. It reads the jars and writes only to `--out`; the
source jars are never touched. Add `--explain-plan` to print the merge plan
without writing files.

For the full flag list, see
[the command reference](../reference/commands.md#vfs). For the resource model in
detail, see [What each analysis examines](../reference/analysis.md#resources).
