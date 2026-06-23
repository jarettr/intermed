# What each analysis examines

InterMed runs a set of analyses over a target. Each one reads specific files,
produces facts, and has limits it does not cross. This page states, for each,
what it reads, what it concludes, and where it stops.

All of them share one rule: a finding is only raised from evidence on disk, and
absence of evidence is never treated as proof. Where an analysis cannot be sure,
it says less rather than guessing.

- [Metadata](#metadata)
- [Modpack manifests](#modpack-manifests)
- [Dependencies](#dependencies)
- [Resources](#resources)
- [Mixins](#mixins)
- [Scripts](#scripts)
- [Security & SBOM](#security--sbom)
- [Logs](#logs)
- [Performance](#performance)
- [Compatibility Lab](#compatibility-lab)

---

## Metadata

**Reads:** `fabric.mod.json`, `quilt.mod.json`, `META-INF/mods.toml` /
`neoforge.mods.toml`, `plugin.yml` / `paper-plugin.yml`, and the JAR manifest.
For jars with no readable metadata, it reads the `@Mod` annotation and entrypoint
classes from bytecode.

**Concludes:** the mod id, version, loader, and side of each mod; the
dependencies it declares; capability fingerprints (does it register content, add
keybindings, ship a config, use custom networking) from symbolic references in
the constant pool.

**Stops at:** capabilities are *which frameworks a class references*, not what it
does with them. "Registers content" does not enumerate the registered ids.

It also detects a mods directory that mixes loaders (Fabric and Forge jars side by
side with no instance to say which is meant) and reports it, since the other
analyses cannot assume a single loader there.

---

## Modpack manifests

**Reads:** a Modrinth `.mrpack` or a CurseForge export. These describe their mods
*by reference* — a download URL and hash, or a `(projectID, fileID)` pair — and
ship only an `overrides/` tree; the actual jars are not in the archive.

**Concludes:** the pack's declared mod set, and whether those jars are present on
disk. When they are not, it raises a clear "analysis is incomplete" finding —
otherwise the metadata, dependency, security, and SBOM analyses would scan an
empty `mods/` tree and report a misleadingly clean pack.

**Stops at:** it parses the manifest and checks what is materialized. It never
downloads the referenced jars; to analyze them, install the pack first and point
`doctor` at the resulting instance.

---

## Dependencies

**Reads:** the declared dependencies from metadata, the bundled (Jar-in-Jar)
libraries each mod provides, and the implicit references derived from the resource
graph.

**Concludes:** missing dependencies; version ranges too narrow or too wide;
undisclosed dependencies a mod uses without declaring; the resolution of the whole
graph. Pairwise semver checks give the precise per-edge findings
(`missing-dependency`, `wrong-version`, `wrong-mc-version`); a PubGrub global
resolver adds joint satisfiability — when the installed catalog is inconsistent in
a way no single pair shows, it raises `dependency-unsat:global` with a
human-readable derivation tree. A bundled library satisfies the dependency it
provides. Loader and runtime pseudo-dependencies (`minecraft`, `java`, the loader)
are never reported missing.

An implicit dependency is only *required* when its reference is unconditioned: a
tag entry with `"required": false`, or a recipe gated on a mod being loaded, is
optional. Client-asset references (a model parent, a texture) are excluded from
the dependency view — they are too often runtime-generated or resource-pack
supplied to call a missing mod.

**Stops at:** it reasons about declared and data-visible dependencies. It does not
prove that a mod will function — only that its stated and structural needs are met.

See the [Dependencies guide](../guides/dependencies.md).

---

## Resources

**Reads:** every file under `data/` and `assets/` across the jars — recipes, tags,
loot tables, advancements, models, blockstates, atlases, language files,
`pack.mcmeta`. Which domains are parsed depends on `--resource-level`.

**Concludes:** for each path written by more than one source, whether the result
is a safe merge (tags, lang — unioned), an override (single-document — one wins by
load order), or order-dependent (atlases — source order decides). With the
semantic level, it compares meaning: recipe output overrides, tag replacements,
disabled recipes, registry-object overrides. It also derives the
namespace-reference graph that feeds implicit dependencies.

Paths are classified by their registry directory (the segment after the
namespace), so a recipe-unlock advancement under `advancements/recipes/` is an
advancement, not a recipe. Recipe results in every form — `{item}`, `{id}`, a bare
string, or an array — are read as outputs.

A typed AST (Layer M) backs the semantic level. It parses recipes, tags, loot
tables, models, blockstates, atlases, advancements, predicates, item modifiers,
and `pack.mcmeta` into typed summaries, and pulls reference edges from worldgen
(biomes, features, dimensions, noise/density, structures) and the newer small
datapack registries (damage types, trim/banner patterns, …) via a declarative
spec table rather than a parser per registry. Two layers of conflict come out of
this: byte-level collisions (identical / override / safe union) from the VFS, and
*semantic* diffs the bytes cannot express — two writers crafting different outputs
at the same recipe path, or mapping the same lang key to different text. Severity
for a semantic diff is derived centrally from the kind of impact it declares plus
confidence, not hand-assigned per domain. Worldgen and small-registry edges are
emitted as *soft* (`required: false`): they feed the implicit-dependency model but
never the dangling-file check, because such an id often resolves to an inline
sibling, a datapack-merged entry, or a runtime registration.

**Stops at:** it resolves references at the namespace level, not the individual id
level. A recipe that uses a non-existent item within an *installed* mod's
namespace is not flagged; only references to a whole missing namespace are.
Validating individual ids would need the set of registered ids, which is not built
(see the project's roadmap note).

See the [Resources guide](../guides/resources.md).

---

## Mixins

**Reads:** mixin configs (Fabric `fabric.mod.json:mixins`, Forge/NeoForge
`mods.toml` and the manifest), the compiled handler bytecode, refmaps, and any
Tiny mappings shipped in the jar. Off unless `--mixin-risk` is set.

**Concludes:** the analysis works at the *application site* (one `handler →
target method → injection point`), not the mixin class. It reports: what each
mixin targets; overlaps where two mods inject into the same method; `@Overwrite`s
that fully replace a method; mixins that may not apply (target/method missing,
wrong handler signature shape, or an unrecoverable local-capture frame);
composition and order at a shared site, with per-handler roles (two `@Redirect`s
conflict, two `@WrapOperation`s chain); a bytecode dataflow read of whether a
handler unconditionally cancels and what it makes the target return; the subsystem
a target belongs to (yielding a capability and a security-sensitivity flag); and
per-target risk, per-mod complexity, and handler bloat. Apply checks resolve a
target method through the class hierarchy, so a mixin into an inherited method is
not reported missing. Side/activation is modelled, so a `client`-only and a
`server`-only mixin into one method are not counted as a conflict.

Every verdict is graded by a confirmation ladder (runtime log → … → mod-level
heuristic) and severity is derived from that grade plus impact and coverage, so a
finding never over-states its evidence. A supplied game log can upgrade a static
hypothesis to a confirmed finding; a Spark profile lets a hot method be correlated
to a specific site by match quality. `--explain` lists what was and was not
actually checked.

Whether a `remap = false` or no-refmap reference resolves depends on the loader's
runtime namespace: Fabric/Quilt run mixins against intermediary names,
Forge/NeoForge against official names, and `com.mojang.*` library classes keep
their real names everywhere. A reference is only flagged when it cannot resolve in
the loader it actually runs under.

**Stops at:** Minecraft's own classes are only indexed when you pass
`--minecraft-jar`. Without it, vanilla-target presence is not checked, and never
produces a false positive — the analysis stays within the mod classes it has.

See the [Mixins guide](../guides/mixins.md).

---

## Scripts

**Reads:** KubeJS (`.js`) and CraftTweaker (`.zs`) script source on disk.

**Concludes:** recipe removals and replacements that name a concrete id, with a
confidence label. This feeds the resource analysis: a recipe override that a
script deletes is not reported as a conflict.

**Stops at:** it is a keyword-and-literal read, not a script interpreter. A removal
whose id is computed at runtime produces no fact rather than a guess.

---

## Security & SBOM

**Reads:** the JAR signature manifest, the constant pool of each class (for
sensitive-API references), Forge coremod declarations, and the metadata that
identifies each artifact.

**Concludes:** signature status per jar; a trust score from how well an artifact
is identified; the dangerous-API surface — counts of classes referencing process
spawning, sockets, reflection, `Unsafe`, `System.exit`, method handles; shipped
coremods; and an SBOM (SPDX or CycloneDX). A grouped security finding is raised
only once a jar crosses a signal threshold.

**Stops at:** this is preflight, from the constant pool. It reports that a class
*references* an API, not that it calls it, and never that a jar is malicious. It
tells you where to spend manual review.

See the [Security guide](../guides/security.md).

---

## Logs

**Reads:** crash reports and `latest.log` (or a single log file passed as the
target).

**Concludes:** known error signatures, the mods a log mentions, and — when a log
accompanies a mods scan — correlations between logged errors and the mods present.

**Stops at:** it matches known signatures and references. It does not replay the
run.

---

## Performance

**Reads:** a Spark sampler profile, supplied with `--spark-report` and enabled by
`--performance`.

**Concludes:** hot methods and hot mods, tick spikes, and a correlation between
hot methods and the mods (and mixins) that own them, against configurable
thresholds.

**Stops at:** it reads a profile you captured; it does not profile the game
itself.

---

## Compatibility Lab

**Reads:** a candidate list and captured smoke-test logs.

**Concludes:** a content-addressed corpus lock, a classified ingestion of the
captured logs, and a compatibility matrix as JSON and static HTML.

**Stops at:** the offline evidence path is complete. Fetching and launching
candidates live is behind a trait and not built in this release.

See [the command reference](commands.md#lab).
