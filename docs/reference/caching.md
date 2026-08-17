# Caching

Scanning a jar — reading its classes, mixins, and resources — is the slow part of
a run. InterMed caches the result of each jar scan on disk so an unchanged jar is
scanned once and reused after.

The cache only ever speeds up a run. It never changes a finding: a cached result
is byte-for-byte what a fresh scan would produce.

## Where it lives

Default `$XDG_CACHE_HOME/intermed`, or `~/.cache/intermed`. Override with
`--cache-dir <DIR>`, or disable entirely with `--no-cache`.

## How an entry is keyed

A cache entry is keyed by the jar's SHA-256 content identity together with the
collector logic version and settings fingerprint. File size, modification time,
and the short-lived fingerprint table are lookup hints only: InterMed verifies
the current content hash before it trusts a persistent payload. Replacing a JAR
with different bytes while preserving its size and mtime therefore cannot reuse
the old result.

The version string is what keeps a cache honest across upgrades. Each analyzer
(mixins, resources, metadata) carries its own version; when its logic changes, the
version changes, and every entry it produced is treated as stale and regenerated.
You never need to clear the cache after an upgrade — the keying does it.

Cache payload compatibility also includes the emitted-fact/schema version. A
collector that depends on mappings incorporates the mapping source/hash,
Minecraft version, source namespace, target namespace, and parser version into
its settings identity. Any incompatible change invalidates the payload rather
than attempting a best-effort migration.

## Pruning

The cache prunes itself, by age and by size:

| Setting | Default | Flag |
|---------|---------|------|
| Max size | 512 MiB, oldest first | `--cache-max-size <MIB>` |
| Max age | 180 days | `--cache-max-age-days <DAYS>` |
| Prune interval | every 1 day | (config `cache.prune_interval_days`) |
| Fingerprint hint age | 30 days | (config `cache.fingerprint_reverify_days`; content is still hashed on every lookup) |

Force maintenance by hand:

```bash
intermed cache stats   # hit/miss counters and on-disk size
intermed cache prune   # run an age + size prune now
intermed cache clear   # delete everything
```

## Incremental runs

`--changed-since <TIME>` (RFC3339 or unix seconds) scans only jars modified at or
after that time, leaving the rest cached. Useful when a pack changes a little
between runs.

## Sharing a cache

`--cache-remote-dir <DIR>` adds a second cache tier: a scan written by one machine
is reused by any other pointed at the same directory — a network mount, or a CI
cache restored between jobs. The local cache is checked first, then the remote.

In CI, persisting the cache directory between runs is usually enough to make
repeated checks fast. See [Using InterMed in CI](../guides/ci.md#keeping-runs-fast).
