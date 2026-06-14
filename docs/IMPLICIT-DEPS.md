# Implicit dependencies

A modpack's declared dependencies (Layer B/C) are not the whole story: a mod's
*resources* can depend on another mod without ever declaring it — most clearly a
recipe whose serializer `type` belongs to a mod you may not have installed.

Layer M observes these; **Layer C decides**. This keeps the layering honest: Layer
M cannot see the installed mod set, so it only emits candidates; the dependency
rule resolves them.

## Layer M: emit candidates

For every reference into a non-platform namespace that no jar owns, Layer M
aggregates **one candidate per namespace** (`implicit_dependency_candidate`,
subject = namespace) with:

- `required` — at least one reference is unconditioned (absence would break it);
- `via_recipe_type` — referenced as a recipe serializer `type` (the strongest,
  lowest-false-positive signal — a missing serializer hard-fails the recipe load);
- `ref_count`, `from_path`, `target` — sample provenance.

Platform namespaces (`minecraft`, `forge`, `neoforge`, `fabric`, `c`, `common`)
are excluded at the source.

## Layer C: resolve (`intermed-deps/src/implicit.rs`)

A candidate namespace is considered **provided** if it matches any installed mod /
plugin id, a declared `provides` alias, or a `namespace_owner` (a jar shipping
resources under it — this catches mod-id ≠ namespace cases).

The dependency rule raises `implicit-dependency-missing` (a grouped **`Note`**)
only for candidates that are **all** of:

- not provided, **and**
- `via_recipe_type` (a missing recipe serializer, not a missing ingredient), **and**
- `required` (not gated behind a load condition).

Everything else is left as evidence, not a finding.

### Why so conservative

This is governed by the anti-false-positive rule:

- A namespace is **not** a mod id in general, so a bare "namespace not installed"
  is unreliable — hence the `namespace_owner` / alias checks.
- Minecraft silently **skips** a recipe with a missing *ingredient* (intended
  cross-mod compatibility), so flagging missing ingredient namespaces is noise.
  Only a missing *serializer* is a genuine load error.
- Mods often ship optional compat recipes unconditionally (e.g.
  `createaddition` ships `recipes/compat/immersiveengineering/...`). These produce
  real log errors but are rarely pack-breaking, so the finding is a `Note`, not a
  `Warn`.

## Example

On a 64-mod Fabric pack, this surfaces exactly two true positives:

```
NOTE 2 recipe serializer(s) reference a mod that is not installed
     … not provided by any installed mod: immersiveengineering, jeed.
```

both confirmed: `createaddition` and `supplementaries` ship compat recipes whose
serializer mods are absent.

## Future (Stage 6)

Richer cross-layer resolution — `dependency_satisfied` / `wrong_version` /
`optional_gated` interpreted facts, version/range analysis — is planned but
intentionally out of the current sound MVP.

## See also

- [LAYER-M-DATA-SEMANTICS.md](LAYER-M-DATA-SEMANTICS.md)
- [LAYER-C-DEPENDENCIES.md](LAYER-C-DEPENDENCIES.md)
- [SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md)
- [CL-LAYER-M.md](CL-LAYER-M.md)
