# Commands and flags

Every command, subcommand, and option. For the live version run
`intermed <command> --help`, or read `docs/man/intermed.1`.

Global options (accepted before any subcommand):

| Option | Effect |
|--------|--------|
| `--config <FILE>` | Use this config file instead of discovery. See [Configuration](configuration.md). |
| `--dump-config` | Print the effective config as TOML and exit. |
| `--quiet` | Suppress progress messages on stderr. Errors still print. |
| `-v`, `-vv` | More informational detail (repeatable). |
| `-V`, `--version` | Print the version. |

Commands:
[doctor](#doctor) ·
[vfs](#vfs) ·
[deps](#deps) ·
[impact](#impact) ·
[mixin-map](#mixin-map) ·
[spark-map](#spark-map) ·
[sbom](#sbom) ·
[rules](#rules) ·
[lab](#lab) ·
[cache](#cache) ·
[db](#db) ·
[history](#history) ·
[trends](#trends) ·
[demo](#demo)

---

## doctor

```
intermed doctor [OPTIONS] [TARGET]
```

Diagnose a server, instance, mods directory, or a single log/crash file. `TARGET`
defaults to the current directory. The target kind is auto-detected.

**Target & detection**

| Flag | Effect |
|------|--------|
| `--mods-dir <DIR>` | Override the detected mods directory. |
| `--minecraft-jar <JAR>` | Index a Minecraft client/server jar, so mixin apply checks and `minecraft:` references resolve against real vanilla classes and data. |
| `--minecraft-mappings <FILE>` | Yarn/Mojmap Tiny v2 mappings, to bridge named ↔ intermediary for the jar above. |

**Analysis depth**

| Flag | Effect |
|------|--------|
| `--metadata-level <basic\|enriched\|full>` | Metadata detail. Default `enriched`. |
| `--resource-level <basic\|semantic\|full>` | Resource/data semantics depth. `basic` off, `semantic` core domains, `full` all domains. Default `semantic`. |
| `--mixin-risk` | Enable the mixin analysis. |
| `--mixin-level <normal\|detailed\|full>` | Mixin depth. Default `detailed`. |
| `--mixin-handler-effects` / `--no-mixin-handler-effects` | Toggle per-handler effect facts. |
| `--mixin-recommendations` / `--no-mixin-recommendations` | Toggle mixin fix recommendations. |
| `--performance` | Import a Spark profile (see `--spark-report`). |

**Output**

| Flag | Effect |
|------|--------|
| `--json [FILE]` | `intermed-doctor-report-v1` JSON, to stdout or a file. |
| `--sarif [FILE]` | SARIF 2.1.0. |
| `--html <FILE>` | A self-contained HTML report. |
| `--explain <FINDING_ID>` | Print one finding with its full evidence chain, and exit. |
| `--dump-facts <FILE>` | Write the raw fact snapshot to JSON. |
| `--profile <FILE>` | Write a wall-clock phase profile. |
| `--no-color` | Disable ANSI colour. |
| `--exit-zero` | Always exit `0` on completion; a non-zero exit then means an operational error, not a finding. |

**Cache** (see [Caching](caching.md))

| Flag | Effect |
|------|--------|
| `--no-cache` | Disable the jar scan cache. |
| `--cache-dir <DIR>` | Override the cache root. |
| `--cache-remote-dir <DIR>` | Shared cache tier (network mount / CI cache). |
| `--cache-max-size <MIB>` | Soft size cap. Default 512. |
| `--cache-max-age-days <DAYS>` | Max entry age. Default 180. |
| `--changed-since <TIME>` | Scan only jars modified at or after this RFC3339 / unix time. |

**Rule packs** (see [rules](#rules))

| Flag | Effect |
|------|--------|
| `--rule-pack <PATH\|ID>` | Load an extra rule pack. |
| `--rule-pack-dir <DIR>` | Load every pack in a directory. |
| `--core-rule-pack-only` | Use only the built-in core rules. |
| `--rule-pack-trusted-keys <KEYS>` | Trusted signing keys for packs. |
| `--rule-pack-registry <FILE\|URL>` | A pack registry to resolve from. |
| `--allow-insecure-registry`, `--allow-unsigned-rules` | Relax pack trust checks. |

**Engine & tuning**

| Flag | Effect |
|------|--------|
| `--logic <columnar\|souffle\|duckdb>` | Rule backend. Default `columnar` (in-process). The others are external engines over the same IR. |
| `--jobs <N>` | Worker thread cap. `0` = all cores. |
| `--db <FILE>` | Persist this run into a DuckDB analytics store. |
| `--db-best-effort` | Do not fail the run if the DB write fails. |
| `--security-min-note-signals <N>` | Signals needed before a grouped security finding. Default 2. |
| `--security-corroborated-confidence <S>` | Confidence for reflection-corroborated security facts. |
| `--sbom-well-identified-trust <S>` | Trust score for well-identified jars. Default 60. |
| `--log-parallel-line-threshold <N>` | Log size above which scanning parallelizes. |
| `--perf-tick-spike-ms`, `--perf-tick-spike-warn-ms`, `--perf-high-cpu-percent`, `--perf-hot-method-floor` | Spark thresholds (see [Configuration](configuration.md#performance)). |

---

## vfs

Inspect resource/data overrides. See the [Resources guide](../guides/resources.md).

```
intermed vfs scan    [OPTIONS] [TARGET]      # classify every resource collision
intermed vfs explain [OPTIONS] [TARGET]      # explain one path; --path <P>, --ast
intermed vfs overlay [OPTIONS] --out <OUT> [TARGET]  # write the merged result
```

`vfs overlay` reads jars and writes only under `--out`. `--explain-plan` prints
the merge plan without writing. `--include-unsafe-winners` includes
override-collision winners in the overlay.

---

## deps

The dependency graph and resolution. See the
[Dependencies guide](../guides/dependencies.md).

```
intermed deps graph       [TARGET]   # export the graph (intermed-modpack-graph-v1 JSON)
intermed deps resolve     [TARGET]   # PubGrub resolution (intermed-deps-resolution-v1 JSON)
intermed deps why         <ID> [TARGET]   # why a mod/namespace is depended upon
intermed deps why-missing <ID> [TARGET]   # why an absent dependency is required
intermed deps implicit    <ID> [TARGET]   # resource-derived references into a namespace
intermed deps path        <FROM> <TO> [TARGET]  # a dependency chain between two mods
```

---

## impact

Blast radius of a change. See the
[Dependencies guide](../guides/dependencies.md#blast-radius).

```
intermed impact remove <MOD> [TARGET]            # what breaks if the mod is removed
intermed impact update <MOD> <VERSION> [TARGET]  # which ranges reject the new version
```

---

## mixin-map

The static mixin view on its own. See the [Mixins guide](../guides/mixins.md).

```
intermed mixin-map [OPTIONS] [TARGET]
```

Accepts `--minecraft-jar` / `--minecraft-mappings` to extend apply checks to
vanilla, and `--json` for machine output.

---

## spark-map

```
intermed spark-map [OPTIONS] [TARGET] --spark-report <FILE>
```

Import a Spark sampler profile and summarize hot methods and mods, correlating
hot methods with the mods (and mixins) that own them.

---

## sbom

```
intermed sbom export [OPTIONS] [TARGET] --format <spdx|cyclonedx>
```

Export a software bill of materials. See the
[Security guide](../guides/security.md#exporting-an-sbom).

---

## rules

Declarative rule packs.

```
intermed rules check   [PATH]    # validate a pack's structure and schema
intermed rules explain [PACK]    # static EXPLAIN of the rules; --rule <ID>, --facts <FILE>
```

`rules explain --rule <id>` shows what a rule matches; with `--facts` from a
`--dump-facts` run it shows the rule against real data.

---

## lab

The Compatibility Lab: reproducible compatibility evidence from captured runs.

```
intermed lab discover <CANDIDATES> --out <LOCK>     # content-addressed corpus lock
intermed lab run      <LOCK> --logs <LOGS> --out <RUN>  # ingest captured smoke-test logs
intermed lab report   <RUN> --out <SITE>            # JSON + static HTML matrix
```

The offline evidence path is complete. A live server runner (fetching and
launching candidates) is behind a trait and not built in this release.

---

## cache

Jar scan cache maintenance. See [Caching](caching.md).

```
intermed cache stats   # hit/miss counters and on-disk size
intermed cache prune   # force an age + size prune pass
intermed cache clear   # delete all cached payloads
```

---

## db

```
intermed db query --db <FILE> "<SQL>"
```

Run a read-only SQL query against the DuckDB analytics store. Requires a build
with `--features duckdb`. The store is populated by `doctor --db`.

---

## history

Recurring findings across persisted runs. Requires `--db` and the `duckdb`
feature.

```
intermed history conflicts --db <FILE>   # findings that recur within a time window
intermed history patterns  --db <FILE>   # recurring kinds of risk (rule + category)
intermed history diff      --db <FILE> <A> <B>  # findings changed between two runs
intermed history prune     --db <FILE>   # delete runs older than a retention window
```

---

## trends

Time-series analytics over persisted runs. Requires `--db` and the `duckdb`
feature.

```
intermed trends mixin-risk     --db <FILE>   # mixin-category counts per run
intermed trends mixin-overlaps --db <FILE>   # most frequent mixin overlaps
```

---

## demo

```
intermed demo report [OPTIONS]
```

Render markdown, HTML, and JSON presentation artifacts from a demo run directory.
A presentation helper, not part of a normal diagnosis.
