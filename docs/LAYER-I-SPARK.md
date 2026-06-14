# Layer I — Spark / performance bridge

Imports existing Spark-style profiler output as facts. Does **not** run Spark or attach to a live JVM.

## Import format (`intermed-spark-report-v1`)

```json
{
  "schema": "intermed-spark-report-v1",
  "source": "spark-profiler",
  "tick_spikes_ms": [120, 95],
  "gc_pauses_ms": [50],
  "heap_pressure_bytes": 1073741824,
  "hot_methods": [
    {"class": "net.minecraft.server.MinecraftServer", "method": "tick", "percent": 42.5}
  ],
  "hot_mods": [{"mod": "sodium", "percent": 15.0}],
  "thread_hotspots": [{"thread": "Server thread", "percent": 80.0}]
}
```

Export or hand-author this JSON from Spark sessions. All arrays are optional.

## Discovery order

1. `doctor --spark-report PATH` (explicit file)
2. `{target}/spark/*.json`
3. `{target}/profiler/*.json`

## Facts emitted

| Kind | Subject | Attrs |
|------|---------|-------|
| `tick_spike` | `tick-{ms}ms` | `ms` |
| `gc_pause` | `gc-{ms}ms` | `ms` |
| `heap_pressure` | `heap` | `bytes` |
| `hot_method` | class | `method`, `percent` (numeric) |
| `hot_mod` | mod | `percent` (numeric) |
| `thread_hotspot` | thread | `percent` (numeric) |

`percent` must be stored as a number (`AttrValue::Float` or `Int`), not a
formatted string. Threshold rules read it with `Fact::attr_f64`, which accepts
only native numeric attribute values — string-encoded numbers are ignored.

## Findings (`performance-correlation`)

This rule is the project's first genuine **cross-layer** join: it links Layer-I
performance evidence to Layer-F mixin intelligence. It builds an index of mixin
work keyed by the **target class** (`mixin_target`), the operations applied
(`mixin_operation`), overlaps (`mixin_overlap`), and `@Overwrite`s
(`high_risk_overwrite`), then joins it against Spark facts.

> Note: the join is on `mixin_target.target` (the class a mixin modifies), **not**
> on `mixin_hotspot`. `mixin_hotspot` facts are keyed by a hot-path *tag*
> (`server-tick`, `entity`, …) and carry no `target` attribute; the previous
> implementation read that non-existent attribute and so never correlated.

| Finding id | Trigger | Severity |
|------------|---------|----------|
| `perf-mixin:{class}:{method}` | A `hot_method` at **≥ 5% CPU** (floor) whose class is modified by a mixin (exact FQN, else simple-name match) | **Error** if an `@Overwrite`, ≥ 2 mods, or CPU ≥ 50% is involved; otherwise **Warn** |
| `perf-hot-mod:{mod}` | A `hot_mod` that also performs mixin work | **Error** if it `@Overwrite`s a class or CPU ≥ 50%; otherwise **Warn** |
| `tick-spike:{ms}` | `tick_spike` with `ms ≥ 50` | **Warn** if `ms ≥ 100` or mixin correlations exist; otherwise **Note** |
| `perf-log-suspect:{mod}` | `hot_mod` + `log_mentions_mod` — slow *and* failing | **Warn** |
| `perf-tick-log-suspect:{mod}` | `tick_spike` + `log_mentions_mod` (installed mod) — lag *and* crash trace (D3) | **Warn** |
| `perf-tick-mixin-hotpath:{mod}` | `tick_spike` + mixin hot-path / `@Overwrite` targets for that mod | **Warn** / **Note** |
| `perf-hot-mod-resource:{mod}` | `hot_mod` + `resource_collision` where mod is among writers | **Warn** |
| `perf-hot-method-log:{class}:{method}` | `hot_method` + `log_signal` excerpt mentions class/method | **Warn** |
| `performance-heuristic-fallback` | No Spark facts, but mixin/VFS/log layers provide partial lag hints | **Note** |

Correlation findings carry cross-layer **evidence edges**: the Spark fact as the
`Subject` plus every supporting Layer-F mixin fact (or Layer-D `log_mentions_mod`
fact) as `Supports`, so the evidence graph spans both layers.

Matching prefers an exact dotted-FQN match between the Spark class and the mixin
target, falling back to the simple class name when Spark reports a class under a
different qualification.

Category: `Performance`.

## CLI

```bash
intermed doctor ./server --performance
intermed doctor ./server --performance --mixin-risk --json
intermed spark-map ./server --spark-report ./spark/profile.json
```

Layer I is gated by `--performance` (like Layer F and `--mixin-risk`). No jar cache involvement; report files are parsed in parallel (rayon) with order preserved.