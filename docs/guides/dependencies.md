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
- **Undisclosed dependency** (`note`) — a mod uses another mod's content (a
  recipe type, a registry object) without declaring a dependency on it. See
  *implicit dependencies* below.

A bundled (Jar-in-Jar) library counts as installed only when loader metadata and
active-descriptor evidence establish that the nested provider joins the runtime
classpath. A merely present or unresolved nested archive prevents a definitive
absence claim but does not satisfy a hard dependency as fact.

## Version languages

Ranges are interpreted in the language selected by the declaring loader, not as
one universal SemVer dialect:

- Fabric dependencies use Fabric Loader extended SemVer. Build metadata does not
  affect ordering, and prereleases are compared directly. For example,
  `1.0.2-rc1+1.20` satisfies `>=1.0.0` because the `1.0.2` release tuple is newer.
- Forge and NeoForge dependencies use Maven interval syntax such as `[47,)` and
  `[1.0,2.0)`.
- Quilt uses its own constraints: a bare version means `^version`, and `^^`/`~~`
  implement same-major and same-major-and-minor matching.
- Generic and opaque metadata stays conservative: an unsupported comparison is
  undecidable, not an incompatible-version error.

The same decision is reused by doctor findings, `impact update`, and the PubGrub
whole-pack resolver. PubGrub receives stable surrogate tokens for every raw
installed version; loader-specific evaluators decide which finite-catalog tokens
each predicate permits. An undecidable provider blocks a definitive contradiction,
preventing uncertainty from becoming a false `dependency-unsat:global` error.

Dependency applicability is evaluated before either pairwise or global reasoning.
Forge/NeoForge `side=CLIENT|SERVER|BOTH` constraints are matched against the
resolved target side; a constraint for the opposite side is inactive. Feature-
gated or otherwise conditional constraints remain undecidable until authoritative
target configuration establishes that they are enabled.

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

`why` can explain positive, negative, and ordering declarations with their real
relation. `why-missing` and ordinary dependency paths use only positive
presence-requiring edges, so `breaks` and `loadbefore` can never be presented as
reasons that an absent mod is required.

## Blast radius

Before removing or bumping a mod, ask what it takes with it:

```bash
intermed impact remove create ./mods       # what depends on create, directly and through data
intermed impact update sodium 0.6.0 ./mods # which declared ranges reject 0.6.0
```

`impact remove` walks positive declared dependents and resource references into
the mod's namespace. `impact update` respects relation polarity: leaving a
`breaks`/`conflicts` range is a resolved incompatibility, not a new breakage.

For the exact flags of each subcommand, see
[the command reference](../reference/commands.md#deps).
