# Layer B — Mod / plugin metadata

For every jar under a target's mods (and `plugins/`) directory, Layer B opens the
archive and parses whatever manifest it carries — **Tier-1, JVM-free**: it reads
`fabric.mod.json`, `quilt.mod.json`, `mods.toml` / `neoforge.mods.toml`,
`plugin.yml` / `paper-plugin.yml`, never bytecode (annotation-driven `@Mod`
discovery is a thin fallback). Deep class analysis is Layer F.

**Crate:** [`intermed-minecraft-scan`](../crates/intermed-minecraft-scan/) ·
**Live status:** [STATUS.md](STATUS.md)

Roadmap and measurement criteria: [LAYER-B-METADATA-ROADMAP.md](LAYER-B-METADATA-ROADMAP.md).

`--metadata-level=basic|enriched|full` controls the append-only intelligence
facts. `basic` emits the legacy contract; `enriched` (default) adds
`mod_metadata`, `entrypoint_detail`, `mod_relationship`, and `mod_capability`;
`full` also emits events/priority detected from declared entrypoint classes.

## Loader matrix

| Loader | Manifest | Facts |
|--------|----------|-------|
| Fabric | `fabric.mod.json` | `mod`, deps, `mod_side`, entrypoints, access widener |
| Quilt | `quilt.mod.json` (`quilt_loader`) | as Fabric (deps as arrays/objects) |
| Forge / NeoForge | `META-INF/(neoforge.)mods.toml` | `mod`, deps (incl. NeoForge `type`), `mixin_config`, AT/AW, coremods |
| Forge (annotation) | `@Mod` class (fallback when no TOML) | `mod`, entrypoint (`phase=mod`) |
| Bukkit / Paper | `plugin.yml` / `paper-plugin.yml` | `plugin`, deps, `load_order` |

Jar-in-Jar modules (`META-INF/jars/`, `META-INF/jarjar/`) are recursively
registered as versioned `provided_dependency` (with `bundled=true`) + `nested_jar`,
so a dependency satisfied by a bundled library is not falsely reported missing.

## Entrypoints (`entrypoint`)

The class(es) a loader loads at each lifecycle phase, extracted from:

- **Fabric** `entrypoints` map — `{ "main": ["pkg.Mod"], "client": [{ "value": … }] }`;
- **Quilt** `quilt_loader.entrypoints` — scalar, array, or object form per phase;
- **Forge / NeoForge** the `@Mod`-annotated class (`phase = mod`). The `mods.toml`
  names the mod but not its entry class, so the `@Mod` class scan runs *even when a
  TOML is present* (and as the sole manifest when none is) to fill the entrypoint.

Fact: `entrypoint` (`subject` = mod id, `phase`, `class`, `loader`).

## Entrypoint intelligence (`entrypoint_detail`, `full` level)

At the `full` metadata level, [`entrypoint_analysis`](../crates/intermed-minecraft-scan/src/entrypoint_analysis.rs)
reads each entrypoint **class's bytecode** ([`cafebabe`]) — real structural
analysis, not constant-pool substring guessing:

- **Forge / NeoForge** — the class-level `@Mod$EventBusSubscriber` /
  `@EventBusSubscriber` annotation, and every `@SubscribeEvent` method, whose
  subscribed event is its **first parameter type** (parsed from the method
  descriptor). `EventPriority` is read from the annotation when present.
- **Fabric / Quilt** — listener registration in method bodies: a
  `SomethingEvents.FIELD.register(…)` shape (`getstatic` of a `*Events` field
  feeding a `register` invoke) yields the actual event family + field.

Fact `entrypoint_detail` carries `entrypoint_type`, `events` (the real subscribed
event simple-names), and `priority`.

Beyond the declared entrypoint classes, a **whole-jar pass** (`analyze_jar`, capped
at 6000 classes) scans *every* class for `@SubscribeEvent` handlers and listener
registrations — real mods spread event handlers across many classes, so this is
where the bulk of the event coverage comes from. The aggregated events feed
capability inference.

## Capabilities (`mod_capability`)

[`infer_capabilities`](../crates/intermed-minecraft-scan/src/metadata.rs) derives
high-level capabilities from **structural evidence only** — never from the mod id:

| Capability | Evidence |
|------------|----------|
| `has_worldgen` / `adds_custom_dimension` | `data/<ns>/worldgen/` · `dimension[_type]/` files in the jar (strong, 0.9) |
| `modifies_rendering` | subscribes to a render/HUD event · AT on a render class · render entrypoint class path |
| `hooks_game_tick` / `hooks_server_lifecycle` / `hooks_world_events` | the real subscribed event type |
| `modifies_game_code` / `deep_runtime_integration` | declares mixins / access transforms / coremods |
| `registers_content` / `custom_networking` / `registers_commands` / `has_config` / `adds_keybindings` / `adds_creative_tab` / `adds_block_entities` / `uses_data_attachments` / `uses_forge_capabilities` | a **constant-pool reference** to the distinctive framework type (`DeferredRegister`, `SimpleChannel`, `RegisterCommandsEvent`, `ForgeConfigSpec`, `KeyMapping`, …) anywhere in the jar — honest structural evidence, not a name |
| `performance_oriented` | transforms game code but registers **no content** — a behavioural mod, by evidence (0.55) |

Confidence tracks signal strength; the data-pack scan + the whole-jar framework
reference scan (`CAPABILITY_REFS`) together distinguish content mods from
behavioural mods without ever consulting the mod's name.

## Relationships (`mod_relationship`)

Emitted from the manifest (`depends` → `consumes_api`, `breaks` →
`known_incompatible`, `recommends`/`suggests` → `recommended_together`, `provides`
→ `provides_api`) **and** from a curated knowledge base
([`knowledge.rs`](../crates/intermed-minecraft-scan/src/knowledge.rs)) of
well-established facts no manifest declares — Sodium ⊥ OptiFine, Iris → Sodium,
etc. The core rule `known-incompatible-mods` turns a `known_incompatible` pair that
is **both installed** into an `Error` finding.

## Access transformers & wideners (`access_transform`)

Both Forge **Access Transformers** (`META-INF/accesstransformer.cfg`) and
Fabric/Quilt **Access Wideners** (the `.accesswidener` file named by the manifest)
relax the JVM access of *game* members so a mod can touch internals. They are a
frequent, quiet source of cross-mod conflict (two mods widening the same member
differently; a `@Shadow` assuming a visibility another mod's transform changed).

[`access.rs`](crates/intermed-minecraft-scan/src/access.rs) parses both into a
normalized `AccessDirective` and emits `access_transform` facts:
`mechanism` (`access-transformer` | `access-widener`), `access`
(`public`/`accessible`/`mutable`/`extendable`/…), optional `qualifier`
(`-f` / `transitive`), `target_class`, optional `member`, and a **mechanism-
independent `target_key`** (`class#member`) so a Forge AT and a Fabric AW on the
same member produce the same join key for correlation.

## Coremods (`coremod`)

Forge `META-INF/coremods.json` declares JavaScript bytecode-manipulation scripts
that rewrite classes at load time, *outside* the mixin/compatibility machinery.
Each declared coremod becomes a `coremod` fact (`subject` = mod id, `name`,
`loader`), and the declarative `forge-coremod-present` rule raises a `Note` — a
coremod bypasses conflict detection and breaks often across updates, so it is a
"review this mod first" signal.

## NeoForge / Forge `mods.toml` dependency semantics

`[[dependencies.<mod>]]` rows map to Layer-C `dependency` facts:

| `type` / legacy | `mandatory` | `relation` | Layer-C behavior |
|-----------------|-------------|------------|------------------|
| `required` | `true` | `depends` | missing / version checks |
| `optional` | `false` | `recommends` | silent when absent |
| `incompatible` | `false` | `breaks` | **Error** when present |
| `discouraged` | `false` | `discouraged` | **Warn** when present |
| legacy `mandatory=false` | `false` | `suggests` | silent when absent |

`ordering = "BEFORE"` / `"AFTER"` maps to `loadbefore` / `loadafter` (see
[LAYER-C-DEPENDENCIES](LAYER-C-DEPENDENCIES.md)). Feature-gated rows
(`feature = "mod:flag"`) emit `feature` on the fact and are treated as
non-mandatory until the feature is known enabled.

## Modern Forge tables

* `[[mixins]] config = "…"` → `mixin_config` facts (Layer F also discovers these).
* `[[accessTransformers]] file = "…"` → parsed `access_transform` directives
  (in addition to legacy `META-INF/accesstransformer.cfg`).

## Cache

`CACHE_VERSION` trailing revision bumps when scan/parse logic changes within a
release (`-r7` at time of writing — NeoForge `type`, ordering, mixins/AT tables).
The per-jar parsed payload is cached; analysis is not.
