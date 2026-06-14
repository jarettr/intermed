# Version range semantics (Layer C)

`intermed-deps` evaluates dependency ranges conservatively: when a version or range
cannot be parsed as semver, **no finding is emitted** (avoids false positives).

Pairwise checks and the PubGrub global resolver share the same normalization
logic in [`semver.rs`](../crates/intermed-deps/src/semver.rs) and
[`ranges.rs`](../crates/intermed-deps/src/ranges.rs). See
[LAYER-C-DEPENDENCIES.md](LAYER-C-DEPENDENCIES.md).

## Minecraft release versions

Two-component MC versions are padded before comparison:

| Written | Parsed as |
|---------|-----------|
| `1.20` | `1.20.0` |
| `1.21.1` | `1.21.1` (unchanged) |

So instance `1.20` satisfies `>=1.20` and `>=1.20.0`.

## Snapshots

Snapshot ids such as `23w31a` are **undecidable** — dependency checks against
`minecraft` are skipped rather than guessed.

## Fabric ranges

Fabric mod metadata often uses space-separated AND comparators:

```
>=0.11.6 <0.12.0
```

These normalize to semver comma syntax (`>=0.11.6, <0.12.0`) before parsing.

OR alternatives use `||` in both Fabric metadata and semver:

```
>=1.20 || <1.21
```

JSON array ranges in `fabric.mod.json` / `quilt.mod.json` are joined with ` || `.

## Build metadata

Mod versions with build suffixes (`0.5.3+1.20.1`) compare on the leading semver
segment (`0.5.3`).