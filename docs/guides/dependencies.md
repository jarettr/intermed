# Dependencies

A mod declares what it needs in its metadata (`fabric.mod.json`, `mods.toml`).
InterMed reads those declarations across every mod in the pack and answers four
kinds of question.

## In the doctor report

Dependency findings appear in a normal `doctor` run:

- **Missing dependency** (`error`) — a mod requires another that is not
  installed. Loader and runtime pseudo-dependencies (`minecraft`, `java`, the
  loader itself) are never reported; they are always present.
- **Version range too narrow** (`note`) — a pin so tight that a bug-fix release
  of the dependency would be rejected.
- **Version range too wide** (`note`) — a lower bound with no upper bound, so a
  breaking major release would be accepted silently.
- **Undisclosed dependency** (`warn`) — a mod uses another mod's content (a
  recipe type, a registry object) without declaring a dependency on it. See
  *implicit dependencies* below.

A bundled (Jar-in-Jar) library counts as installed: if a mod ships its dependency
inside itself, that dependency is satisfied and not reported missing.

## Implicit dependencies

Some dependencies are never declared but are visible in a mod's data. A recipe
whose type is `alloy_forgery:forging` needs Alloy Forgery, whether or not the mod
says so. InterMed derives these from the resource graph.

It distinguishes hard from soft. A reference is only a *required* implicit
dependency when it is unconditioned: a tag entry marked `"required": false`, or a
recipe gated by `fabric:load_conditions` / `neoforge:conditions`, is optional —
the game silently drops it when the other mod is absent — so it is reported as
optional, not missing.

```bash
intermed deps implicit alloy_forgery ./mods   # what references this namespace
```

## Asking direct questions

```bash
intermed deps why kubejs ./mods          # every reason kubejs is depended upon
intermed deps why-missing cloth-config ./mods  # which mods require this absent one
intermed deps path create ae2 ./mods     # a dependency chain from create to ae2
intermed deps resolve ./mods             # full resolution (PubGrub), as JSON
intermed deps graph ./mods               # the whole graph, as JSON
```

`why` and `why-missing` print both declared and implicit reasons, each with its
source.

## Blast radius

Before removing or bumping a mod, ask what it takes with it:

```bash
intermed impact remove create ./mods       # what depends on create, directly and through data
intermed impact update sodium 0.6.0 ./mods # which declared ranges reject 0.6.0
```

`impact remove` walks both the declared dependents and the resource references
into the mod's namespace. `impact update` checks the proposed version against
every range that mentions the mod.

For the exact flags of each subcommand, see
[the command reference](../reference/commands.md#deps).
