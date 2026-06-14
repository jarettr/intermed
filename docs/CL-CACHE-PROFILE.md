# CL: Jar cache & profiling hardening

## Jar cache

- **Fingerprint fast path** — sidecar `fp/{digest}.json` maps jar path + mtime/size → SHA-256; skips full-jar hashing on repeat runs (`fast_hits` counter).
- **Per-collector logic versioning** — the cache key and record carry a `cache_version` (`{collector_id}/{cache_version}/…`) derived from the collector crate version. A collector whose scan logic changed misses the cache even when jar bytes (and SHA-256) are unchanged, so a tool upgrade never serves payloads from the previous parser. See [CACHE.md](CACHE.md#logic-versioning-collector-upgrades).
- **Automatic pruning** — on cache init, at most once per 24 h: delete entries older than 180 days; cap total size at 512 MiB (oldest first).
- **Per-shard write locks** — 256 shards by SHA-256 prefix instead of a global mutex.
- **`JarCache::new` → `io::Result`** — CLI reports a clear error when the cache root cannot be created.

## Profiling

- Per-collector and per-rule wall-clock timings in `DiagnosticProfile` (unchanged schema).
- **`--json` embeds `profile` automatically when jar cache is enabled** (includes `cache` stats + phase breakdown).
- **`--profile FILE` always writes** the full profile, even with `--no-cache`.

## CLI structure

`DoctorArgs` flattened into:

- `DoctorOutputArgs` — `--json`, `--sarif`, `--no-color`, `--profile`
- `DoctorCacheArgs` — `--no-cache`, `--cache-dir`
- `DoctorProvenanceArgs` — `--dump-facts`, `--explain`
- `DoctorPerformanceArgs` — `--performance`, `--spark-report` (Phase 7)

## Build artifacts

- `docs/man/intermed.1` via `clap_mangen`
- Shell completions in `docs/completions/` via `clap_complete`

## Tests added

- `jar_cache`: fingerprint, prune, blocked root, fast_hits, logic-version invalidation
- E2E: cache hits, profile file, `--no-cache --json` omits profile
- Cache collectors: `metadata-scanner`, `vfs-scanner`, `resource-ast-scanner`, `mixin-analyzer`, `sbom-generator`, `security-scanner`