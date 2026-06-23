# Quickstart

## Install

```bash
cargo build --release
```

The binary is `target/release/intermed`. Put it on your `PATH`, or call it by
path. Everything below assumes `intermed` is on the `PATH`.

The build also writes a man page (`docs/man/intermed.1`) and shell completions
(`docs/completions/`).

## First run

Point `doctor` at a mods directory, a server, an instance, or a single log:

```bash
intermed doctor ./mods            # a bare mods directory
intermed doctor ./server          # a dedicated server (scans mods + logs/)
intermed doctor ~/.minecraft      # a launcher instance
intermed doctor latest.log        # a single log or crash report
intermed doctor pack.mrpack       # a Modrinth / CurseForge modpack manifest
```

It auto-detects the target kind, the loader, and the Minecraft version, then
prints a report. The last line is the verdict and the counts:

```
WARNINGS  1 actionable, 10 informational  (0 fatal, 1 error, 0 warn, 10 note · 1073 facts)
```

The process exit code follows the lint convention: `0` healthy, `1` warnings,
`2` errors or worse. See [Reading a report](reading-a-report.md).

## Going deeper on one run

```bash
intermed doctor ./mods --mixin-risk          # add the mixin analysis
intermed doctor ./mods --resource-level full # parse every resource domain
intermed doctor ./mods --explain <finding-id># show the evidence behind one finding
intermed doctor ./mods --json > report.json  # machine-readable
intermed doctor ./mods --html report.html    # a self-contained HTML report
```

## One recipe per command

```bash
# doctor — the main diagnosis
intermed doctor ./mods
intermed doctor ./server --mixin-risk --performance --json

# vfs — resource/data overrides
intermed vfs scan ./mods                      # who writes which file
intermed vfs explain ./mods --path data/foo/recipes/bar.json --ast
intermed vfs overlay ./mods --out ./overlay   # write the merged result to disk

# deps — the dependency graph
intermed deps why kubejs ./mods               # why is kubejs depended upon
intermed deps why-missing cloth-config ./mods # who needs the missing mod
intermed deps path create ae2 ./mods          # a dependency chain between two mods
intermed deps graph ./mods                    # export the whole graph as JSON

# impact — blast radius of a change
intermed impact remove create ./mods          # what breaks if create is removed
intermed impact update sodium 0.6.0 ./mods    # which ranges reject the new version

# mixin-map — static mixin targets and overlaps
intermed mixin-map ./mods

# spark-map — import a Spark performance profile
intermed spark-map ./server --spark-report ./spark/profile.json

# sbom — software bill of materials
intermed sbom export ./mods --format spdx > sbom.spdx.json

# rules — validate a declarative rule pack
intermed rules check ./rules
intermed rules explain --rule duplicate-id

# lab — reproducible compatibility evidence
intermed lab discover ./candidates.json --out corpus.lock
intermed lab run corpus.lock --logs ./captured --out ./runs/latest
intermed lab report ./runs/latest --out ./site

# cache — jar scan cache maintenance
intermed cache stats
intermed cache prune
intermed cache clear

# history / trends — across persisted runs (needs --db on doctor)
intermed doctor ./mods --db history.duckdb
intermed history conflicts --db history.duckdb
intermed trends mixin-risk --db history.duckdb

# db — raw SQL over the analytics store (build with --features duckdb)
intermed db query --db history.duckdb "SELECT kind, COUNT(*) FROM facts GROUP BY kind"
```

Full flag lists for every command are in
[the command reference](../reference/commands.md).

## What a run never does

- It does not edit, move, or delete anything in your pack.
- It does not download mods or contact the network. (The Compatibility Lab's live
  server runner is the one opt-in exception, and it is not built in this release.)
- It does not start the game.

The one command that writes files, `vfs overlay`, writes only to the `--out`
directory you name, and only the merged copies of resources — never the source
jars.
