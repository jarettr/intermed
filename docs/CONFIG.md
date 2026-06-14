# Configuration

InterMed loads settings from (lowest → highest precedence):

1. Built-in defaults
2. Config file (`--config`, `INTERMED_CONFIG`, or discovery paths)
3. `INTERMED_*` environment variables
4. CLI flags on `intermed doctor`

Print defaults:

```bash
intermed --dump-config
```

## Config file

Schema: `intermed-config-v1` (TOML).

Discovery order when `--config` is omitted:

- `./.intermed.toml`
- `./intermed.toml`
- `~/.config/intermed/config.toml` (or `$XDG_CONFIG_HOME/intermed/config.toml`)

Example:

```toml
schema = "intermed-config-v1"

[cache]
max_size_mib = 512
max_age_days = 180

[performance]
enabled = false
tick_spike_ms = 50
tick_spike_warn_ms = 100
high_cpu_percent = 50.0
hot_method_floor_percent = 5.0

[security]
min_note_signals = 2
corroborated_confidence = 0.4

[sbom]
well_identified_trust = 60

[log]
parallel_line_threshold = 4096

[lab]
excerpt_max = 280

[runtime]
jobs = 0

[metadata]
# basic | enriched | full
level = "enriched"

[mixin]
# normal | detailed | full — see LAYER-F-MIXIN.md
level = "detailed"
# handler_effects = true
# recommendations = true

[resource]
# basic (AST off) | semantic | full — see LAYER-M-DATA-SEMANTICS.md
level = "semantic"
max_json_bytes = 1048576
max_ast_facts_per_resource = 256
```

## Environment variables

| Variable | Section | Default |
|----------|---------|---------|
| `INTERMED_CONFIG` | — | Config file path |
| `INTERMED_CACHE_MAX_MIB` | cache | 512 |
| `INTERMED_CACHE_MAX_AGE_DAYS` | cache | 180 |
| `INTERMED_CACHE_PRUNE_INTERVAL_DAYS` | cache | 1 |
| `INTERMED_CACHE_FINGERPRINT_REVERIFY_DAYS` | cache | 30 |
| `INTERMED_PERF_TICK_SPIKE_MS` | performance | 50 |
| `INTERMED_PERF_TICK_SPIKE_WARN_MS` | performance | 100 |
| `INTERMED_PERF_HIGH_CPU_PERCENT` | performance | 50.0 |
| `INTERMED_PERF_HOT_METHOD_FLOOR` | performance | 5.0 |
| `INTERMED_SECURITY_MIN_NOTE_SIGNALS` | security | 2 |
| `INTERMED_SECURITY_CORROBORATED_CONFIDENCE` | security | 0.4 |
| `INTERMED_SBOM_WELL_IDENTIFIED_TRUST` | sbom | 60 |
| `INTERMED_LOG_PARALLEL_LINE_THRESHOLD` | log | 4096 |
| `INTERMED_LAB_EXCERPT_MAX` | lab | 280 |
| `INTERMED_JOBS` | runtime | 0 (all cores) |
| `INTERMED_METADATA_LEVEL` | metadata | `enriched` |
| `INTERMED_MIXIN_LEVEL` | mixin | `detailed` |
| `INTERMED_MIXIN_HANDLER_EFFECTS` | mixin | (derived from `level`) |
| `INTERMED_MIXIN_RECOMMENDATIONS` | mixin | (derived from `level`) |
| `INTERMED_RESOURCE_LEVEL` | resource | `semantic` |

## CLI flags (`intermed doctor`)

| Flag | Config key |
|------|------------|
| `--config FILE` | (file path) |
| `--no-cache` | disables cache |
| `--cache-dir`, `--cache-max-size`, `--cache-max-age-days` | `[cache]` |
| `--performance`, `--spark-report` | `[performance]` |
| `--perf-tick-spike-ms`, `--perf-tick-spike-warn-ms`, `--perf-high-cpu-percent`, `--perf-hot-method-floor` | `[performance]` |
| `--security-min-note-signals` | `[security].min_note_signals` |
| `--security-corroborated-confidence` | `[security].corroborated_confidence` |
| `--sbom-well-identified-trust` | `[sbom].well_identified_trust` |
| `--log-parallel-line-threshold` | `[log].parallel_line_threshold` |
| `--jobs` | `[runtime].jobs` |
| `--metadata-level basic\|enriched\|full` | `[metadata].level` |
| `--mixin-level normal\|detailed\|full` | `[mixin].level` |
| `--no-mixin-handler-effects` / `--mixin-handler-effects` | `[mixin].handler_effects` |
| `--no-mixin-recommendations` / `--mixin-recommendations` | `[mixin].recommendations` |
| `--resource-level basic\|semantic\|full` | `[resource].level` |
| `--html FILE` | HTML report output |

### Resource semantics presets (Layer M)

| Preset | Parsed domains | Typical use |
|--------|----------------|-------------|
| `basic` | none (Layer E VFS only) | Fast scan, no AST cost |
| `semantic` (default) | tag, recipe, lang, pack.mcmeta, ref graph | Doctor on most packs |
| `full` | + model, blockstate, loot table, atlas | `vfs explain --ast`, overlay plan |

`max_json_bytes` skips oversized per-resource JSON (DoS guard).
`max_ast_facts_per_resource` caps `resource_reference` fan-out.

## CLI flags (`intermed vfs`)

| Flag | Config key |
|------|------------|
| `--resource-level` | `[resource].level` (explain `--ast`) |
| `--ast` | (explain only — per-path semantic view) |
| `--explain-plan` | (overlay — semantic plan v2, read-only) |
| `--include-unsafe-winners` | (overlay v1 — stage lexical winners) |

### Mixin analysis presets

| Preset | Handler effect facts | Recommendations | Per-handler findings (`mixin-handler-intel:*`) |
|--------|---------------------|-----------------|------------------------------------------------|
| `normal` | off | off | off |
| `detailed` (default) | on | on | off |
| `full` | on | on | on |

Use `normal` on large packs (`fabric_mega`) when you only need overlaps and risk
scores without hundreds of per-handler notes. `--mixin-risk` on `doctor` still
enables the mixin collector; presets control **depth and noise**, not whether
Layer F runs.

## CLI flags (`intermed lab run`)

| Flag | Config key |
|------|------------|
| `--lab-excerpt-max` | `[lab].excerpt_max` |
