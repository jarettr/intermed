# Profiling doctor runs

## Built-in wall-clock profile

Every `doctor` run records per-collector and per-rule timings plus jar-cache
statistics. When the jar cache is enabled, the same profile (including
`collectors[]`, `rules[]`, and `cache`) is embedded automatically in
`doctor --json` output.

Write the profile to a separate file:

```bash
intermed doctor ./mods --profile profile.json
```

With `--json`, the same data is embedded in the report under `profile`:

```json
{
  "schema": "intermed-doctor-profile-v1",
  "total_ms": 842,
  "collectors": [{ "id": "metadata-scanner", "duration_ms": 120 }],
  "rules": [{ "id": "dependency", "duration_ms": 3 }],
  "cache": { "hits": 40, "misses": 2, "writes": 2, "fast_hits": 38 }
}
```

### Interpreting fields

| Field | Meaning |
|-------|---------|
| `total_ms` | Wall time for the full pipeline |
| `collectors[].duration_ms` | Time inside one `Collector::collect` |
| `rules[].duration_ms` | Time inside one `Rule::evaluate` |
| `cache.hits` | Jar payloads served from disk cache |
| `cache.misses` | Jars rescanned (cache miss or disabled) |
| `cache.writes` | New or refreshed cache files written |
| `cache.fast_hits` | Lookups that skipped full-jar SHA-256 via fingerprint |

Phase timings sum to ≤ `total_ms` (overhead for report assembly is not itemized).

### Parallel jar scanning

Collectors that scan a directory of jars (metadata, mixin, VFS, SBOM, security)
parse the jars in parallel with [`rayon`]; the spark bridge parses report files in
parallel too. Work is distributed across the global rayon thread pool, so a single
`collectors[].duration_ms` is wall time across cores, not summed CPU time. Parsing
is data-parallel and order-preserving (`par_iter().map().collect()`), so output —
and the evidence/finding set — is identical to a sequential run. Fact emission
into the single-threaded store always happens serially after the parallel scan.

[`rayon`]: https://docs.rs/rayon

**Note:** `--json` embeds `profile` only when the jar cache is enabled (default).
Use `--profile FILE` to always write timings to disk, including with `--no-cache`.

## Flamegraph (development)

The built-in profile uses coarse `Instant` timers — no sampling overhead in release
builds. For hotspot analysis during development:

```bash
cargo install flamegraph
cargo flamegraph --bin intermed -- doctor ./mods --mixin-risk
```

This requires a debug-oriented build environment and is **not** bundled into the
release binary. Use it locally to find slow jar parsers or rule hot spots.