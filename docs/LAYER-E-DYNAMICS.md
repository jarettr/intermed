# Layer E — Script-engine dynamics sensors

Static collectors see what a jar **contains**; they cannot see what a pack's
data-pack scripts **remove** at load time. A modpack routinely deletes hundreds
of recipes and hides items through [KubeJS] and [CraftTweaker]. An item that
exists in a jar but whose only recipe was scripted away is, in practice,
unobtainable — and the static graph would never know.

This is the *«сенсоры динамики»* extraction from the design doc's **Appendix B**
(*"Транзакционная VFS и учет динамики"*): **pure evidence**, no runtime
enforcement. *Doctor explains; runtime enforces.*

[KubeJS]: https://kubejs.com/
[CraftTweaker]: https://docs.blamejared.com/

## Method

1. Only applies to a `Server` / `Instance` directory (the script logs live there).
2. Read the script engines' own load logs, in a stable order:
   - `crafttweaker.log`, `logs/crafttweaker.log`
   - `logs/kubejs/{startup,server,client}.log`
   - `logs/groovyscript.log`, `logs/groovyscript/{server,client}.log`
   - `logs/rhino.log`, `logs/script/rhino.log`
3. Match each line against the marker table (`patterns()`, first match wins per
   line). Each pattern captures the affected **registry id** as capture group 1.
4. Emit one fact per marker:
   - `runtime_removed_recipe` — subject = recipe id
   - `runtime_removed_item` — subject = item id
   - `runtime_removed_loot_table` — subject = loot table id
   - `runtime_removed_tag` — subject = tag id (`#minecraft:planks` or `minecraft:logs`)
   Attributes: `engine` (`crafttweaker` / `kubejs` / `groovyscript` / `rhino`),
   `via` (`recipe-removed` / `recipe-output-removed` / `item-removed` /
   `loot-table-removed` / `tag-removed`), `line`, `excerpt`; `source` points at
   the exact log line.

`ScriptDynamicsRule` folds all such facts into **one** auditable note (severity
`Note`, category `Resource`) summarising counts per engine with a capped sample
of ids and an evidence edge to every fact. One note, never a wall of findings —
a kitchen-sink pack removes thousands of recipes.

## Supported engines

| Engine | Typical log paths | Notes |
|--------|-------------------|-------|
| CraftTweaker | `crafttweaker.log` | Bracket syntax `<recipe:…>`, `<item:…>`, `<tag:…>`, `<loot_table:…>` |
| KubeJS | `logs/kubejs/*.log` | Quoted ids: `Removed recipe 'mod:id'` |
| GroovyScript | `logs/groovyscript*.log` | `[GroovyScript]`-tagged lines take priority over generic KubeJS-shaped markers |
| Rhino | `logs/rhino.log` | Bare `Removing recipe "mod:id"` (CraftTweaker JS backend) |

## Confidence and honesty

Script engines do not emit a stable, machine-readable removal manifest; their
human logs vary by engine and version. The marker table is therefore
**best-effort** (the same posture as `intermed-log`'s crash-signature table).
Facts are stamped at confidence `0.6` and always retain the source line +
excerpt so a human can audit every claim. The table is the single point of
extension when new log formats appear.

## Seam left open

The natural next step is **correlation**: join a `runtime_removed_recipe` whose
output item is provided by a mod in the pack against the metadata/SBOM graph to
flag *"item X from mod Y is unobtainable — its only recipe was scripted away"*.
That requires an item-registry fact source the engine does not yet collect, so
the facts are produced now and the correlation rule is deferred until a registry
collector exists. No infrastructure is required for it — it is one more `Rule`.

## Related: static VFS (`intermed-vfs`)

Jar resource collision scanning (Layer E static half) lives in
[`intermed-vfs`](../crates/intermed-vfs/). It classifies:

| Class | Meaning |
|-------|---------|
| `identical` | byte-identical duplicates |
| `safe-crdt-merge` | Minecraft tag JSON (`data/**/tags/**`) — union merge; honours `replace: true` |
| `lang-json-merge` | `assets/**/lang/*.json` — key union |
| `lang-properties-merge` | `assets/**/lang/*.lang` — key union |
| `lang-format-mismatch` | same locale shipped as both `.json` and `.lang` |
| `json-merge-candidate` / `unsafe-replace` | other JSON / binary conflicts |

[`merge_tag_values`](../crates/intermed-vfs/src/lib.rs) clears prior tag values
when a writer sets `"replace": true` before applying its own `values` (vanilla
tag merge semantics). [`intermed-packops`](../crates/intermed-packops/) uses
these merge helpers for overlay previews.