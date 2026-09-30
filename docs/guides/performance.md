# Performance

InterMed does not profile the game. It *imports* a profile you captured and turns
it into evidence: which methods and mods are hot, where ticks spiked, and — when the
mixin analysis is on — which mixin actually owns a hot method.

## What it reads

A Spark sampler profile, as `intermed-spark-report-v1` JSON. InterMed reads that
schema (exported from Spark, or hand-authored as a fixture); it never forks or runs
the Spark profiler itself. The shape it expects carries `hot_methods` (each with a
`class` and `method`), `hot_mods`, `tick_spikes_ms`, `gc_pauses_ms`,
`thread_hotspots`, and an optional `heap_pressure_bytes`. A report may also provide
`session_fingerprint`; only evidence with the same non-empty fingerprint is treated
as same-run evidence. A `hot_mod` may carry a `phase` such as `worldgen` or
`resource-reload` for phase-aware resource correlation.

Percentages must be finite values in `0..=100`, and duration/byte counters must fit
the signed 64-bit fact representation. Invalid values make that report incomplete
instead of wrapping into negative evidence. Findings cite the concrete report path,
not a discovery-order index.

This is the honest boundary: if you have a profile in that shape, InterMed reasons
over it; producing the profile is out of scope for this release.

## Running it

```bash
# fold performance into a normal diagnosis
intermed doctor ./server --performance --spark-report profile.json

# or the performance view on its own
intermed spark-map ./server --spark-report profile.json
```

## What it concludes

- **Hot methods and hot mods** — the methods taking the most sampled time, and the
  mods that own them.
- **Tick spikes** — measured ticks over the configured note/warn thresholds.
- **GC, heap, and thread observations** — repeated long pauses, heap pressure, and
  classified server/render/GC/worker hotspots remain direct observations until
  stronger evidence attributes them.
- **Mod (and mixin) attribution** — a hot method is tied back to the mod it belongs
  to. With `--mixin-risk`, it goes one level deeper: the hot method is correlated to
  the specific mixin **application site** that owns it, graded by how precisely they
  match. Class-only and ambiguous simple-name matches remain context; an exact
  owner/method/site match is a correlation, not automatic proof that weaving caused
  the CPU cost. See [Mixins](mixins.md#how-sure-it-is) and
  [How the analyses connect](../reference/analysis.md#how-the-analyses-connect).

## Tuning the thresholds

The spike, CPU, and hot-method-floor thresholds are configurable, both as flags and
in the config file:

```bash
intermed doctor ./server --performance --spark-report profile.json \
  --perf-tick-spike-ms 60 --perf-hot-method-floor 5
```

See [Configuration](../reference/configuration.md#performance) for every key and its
default.

## Limits

It reasons over the profile you give it; it does not measure the game, and a method
below the hot-method floor produces no correlation rather than a guess. The
attribution is as precise as the symbol names in the profile — a method with no
resolvable owner, an ambiguous simple class name, or an ambiguous overload is left
unattributed rather than blamed on the nearest mod. Free-text log excerpts are not
used for method correlation; Layer I joins structured stack-frame owner/method data.

For the exact flags, see [the command reference](../reference/commands.md#spark-map)
and [what each analysis examines](../reference/analysis.md#performance).
