# Layer C — Dependencies

Layer C answers: *can this modpack's declared dependency constraints be satisfied
together?* It runs in [`intermed-deps`](../crates/intermed-deps/) as a doctor rule
and as standalone CLI commands.

## Two evaluation paths

| Path | Purpose | Finding ids |
|------|---------|-------------|
| **Pairwise semver** | Fast direct checks per `dependency` fact | `missing-dependency`, `wrong-version`, `wrong-mc-version`, `incompatible-mod`, `discouraged-dependency` |
| **Load order** | `loadbefore` / `loadafter` edges among installed mods | `ordering-conflict`, `ordering-cycle` |
| **PubGrub global** | Joint satisfiability + derivation-tree explanations + actionable bullet summary | `dependency-unsat:global` |

Pairwise checks remain conservative: unparsable versions or ranges emit nothing.
`breaks` / `discouraged` / `recommends` relations from Layer B are honored
(optional and incompatible deps do not produce false `missing-dependency`
findings). PubGrub uses the same semver bridge
([`creeper-semver-pubgrub`](https://crates.io/crates/creeper-semver-pubgrub))
and skips edges it cannot express.

`dependency-unsat:global` explanations append an **Actionable summary** listing
mod↔mod conflicts extracted from the PubGrub derivation (e.g. which package has
no satisfying version, which mod requires which).

## Pipeline

```text
FactStore
   ├─▶ pairwise_findings()          ──▶ direct findings
   └─▶ ModpackGraph
         └─▶ ModpackProvider (pubgrub OfflineDependencyProvider)
               └─▶ resolve(root = __intermed_modpack__)
                     ├─ Satisfied
                     └─ Unsatisfiable → DefaultStringReporter explanation
```

The synthetic root depends on every installed mod at a pinned singleton version.
`provides` aliases register additional package versions when the alias id is not
already installed.

## Version range semantics

See [VERSION-RANGES.md](VERSION-RANGES.md) for Fabric `||` / space-AND ranges,
Minecraft two-component padding, and snapshot undecidability.

## CLI

```bash
# Export graph JSON (schema intermed-modpack-graph-v1)
intermed deps graph ./mods

# Run PubGrub (schema intermed-deps-resolution-v1; exit 1 when unsat)
intermed deps resolve ./mods
```

`intermed doctor` always registers [`DependencyRule`](../crates/intermed-deps/src/rule.rs)
(pairwise + global unsat + implicit resource deps).

## Implicit dependencies (Layer M → C)

Layer M emits `implicit_dependency_candidate` when a resource references a
non-platform namespace no jar owns (e.g. a recipe `type` from an absent mod).
Layer C resolves each candidate against installed mod ids, `provides` aliases,
and `namespace_owner` facts — then raises `implicit-dependency-missing` as a
grouped **`Note`** only for unconditioned recipe-serializer references.

See [IMPLICIT-DEPS.md](IMPLICIT-DEPS.md).

## Public API

- [`build_graph`](../crates/intermed-deps/src/graph.rs) — facts → graph
- [`resolve_store` / `resolve_graph`](../crates/intermed-deps/src/resolver.rs) — PubGrub outcome
- [`build_provider`](../crates/intermed-deps/src/provider.rs) — graph → `OfflineDependencyProvider`

PackOps and future version-selection tooling can reuse these without running the
full doctor pipeline.