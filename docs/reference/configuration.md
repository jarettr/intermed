# Configuration

InterMed reads its settings from a TOML file (`intermed-config-v1`). Every key
has a built-in default, so a config file is optional — it exists to change a
default without typing a flag every run.

## Precedence

Lowest to highest; later wins, merged key by key:

1. Built-in defaults.
2. Home config: `$XDG_CONFIG_HOME/intermed/config.toml` (or `~/.config/...`).
3. Project config: the first found in the current directory.
4. `INTERMED_*` environment variables.
5. Command-line flags.

`--config <FILE>` replaces discovery with one explicit file. `--dump-config`
prints the effective config — the result of the merge — and exits:

```bash
intermed --dump-config
```

## Keys

The defaults below are the effective values.

### `[cache]`

| Key | Default | Meaning |
|-----|---------|---------|
| `max_size_mib` | 512 | Soft cap on cache size; oldest entries pruned first. |
| `max_age_days` | 180 | Maximum age of a cache entry. |
| `prune_interval_days` | 1 | How often a prune pass runs. |
| `fingerprint_reverify_days` | 30 | How often a cached jar's fingerprint is re-checked. |

See [Caching](caching.md). Flags: `--cache-dir`, `--cache-max-size`,
`--cache-max-age-days`, `--cache-remote-dir`, `--no-cache`.

### `[performance]`

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `false` | Import a Spark profile during `doctor`. |
| `tick_spike_ms` | 50 | Minimum tick spike duration to report. |
| `tick_spike_warn_ms` | 100 | Spike duration that bumps severity. |
| `high_cpu_percent` | 50.0 | CPU% at or above which a hot method/mod is severe. |
| `hot_method_floor_percent` | 5.0 | Minimum CPU% for hot-method ↔ mixin correlation. |

Flags: `--performance`, `--spark-report`, `--perf-tick-spike-ms`,
`--perf-tick-spike-warn-ms`, `--perf-high-cpu-percent`, `--perf-hot-method-floor`.

### `[security]`

| Key | Default | Meaning |
|-----|---------|---------|
| `min_note_signals` | 2 | Distinct security signals before a grouped finding is raised. |
| `corroborated_confidence` | 0.4 | Confidence for reflection-corroborated security facts. |

Flags: `--security-min-note-signals`, `--security-corroborated-confidence`.

### `[sbom]`

| Key | Default | Meaning |
|-----|---------|---------|
| `well_identified_trust` | 60 | Trust score for a well-identified jar. |

Flag: `--sbom-well-identified-trust`.

### `[log]`

| Key | Default | Meaning |
|-----|---------|---------|
| `parallel_line_threshold` | 4096 | Log line count above which scanning parallelizes. |

Flag: `--log-parallel-line-threshold`.

### `[lab]`

| Key | Default | Meaning |
|-----|---------|---------|
| `excerpt_max` | 280 | Maximum characters of a log excerpt kept in a Lab run. |

### `[runtime]`

| Key | Default | Meaning |
|-----|---------|---------|
| `jobs` | 0 | Worker threads; `0` means all cores. |

Flag: `--jobs`.

### `[rules]`

| Key | Default | Meaning |
|-----|---------|---------|
| `packs` | `[]` | Extra rule packs to load. |
| `core_only` | `false` | Use only the built-in core rules. |

Flags: `--rule-pack`, `--rule-pack-dir`, `--core-rule-pack-only`.

### `[metadata]`

| Key | Default | Meaning |
|-----|---------|---------|
| `level` | `enriched` | `basic`, `enriched`, or `full`. |

Flag: `--metadata-level`.

### `[mixin]`

| Key | Default | Meaning |
|-----|---------|---------|
| `level` | `detailed` | `normal`, `detailed`, or `full`. Mixin analysis is still gated by `--mixin-risk`. |

Flags: `--mixin-level`, `--mixin-handler-effects`, `--mixin-recommendations`.

### `[resource]`

| Key | Default | Meaning |
|-----|---------|---------|
| `level` | `semantic` | `basic`, `semantic`, or `full`. |
| `max_json_bytes` | 1048576 | Largest JSON resource parsed (1 MiB). |
| `max_ast_facts_per_resource` | 256 | Cap on facts emitted per resource. |

Flag: `--resource-level`.
