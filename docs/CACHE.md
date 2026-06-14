# Jar scan cache

InterMed caches per-jar collector payloads on disk to speed up repeated `doctor`
runs against the same modpack.

## Default behavior

Caching is **enabled by default**. Disable with:

```bash
intermed doctor ./mods --no-cache
```

Override the root directory:

```bash
intermed doctor ./mods --cache-dir /tmp/intermed-cache
```

## Cache tiers (memory → disk → remote)

The cache is **content-addressable** (keyed by the jar's SHA-256, folded together
with the collector id and its logic version) and read-through across three tiers,
fastest first:

1. **Memory** — an in-process map of the cache-record text, so the *same content*
   looked up again within one run (identical bundled libs, a library duplicated
   across packs) skips disk I/O entirely. Bounded; the disk tier is the source of
   truth, so eviction only costs a re-read. Counter: `mem_hits` (⊆ `hits`).
   *Only the trusted-sha path consults memory* — the fingerprint fast-path (whose
   sha may be stale) does not, preserving the "evicted payload forces a rehash"
   safety.
2. **Disk** — the on-disk store described below (the durable tier).
3. **Remote** *(optional)* — a shared store so a payload computed by one machine is
   reused by others. Enable with a directory (network mount / CI cache):

   ```bash
   intermed doctor ./mods --cache-remote-dir /mnt/shared/intermed-cache
   ```

   This is the reference `LocalDirRemoteTier`; a real S3/HTTP backend implements the
   same two-method `RemoteCacheTier` trait (`get`/`put`) and attaches via
   `JarCache::with_remote(...)` with no other code changes. Remote bytes are
   validated (schema + sha + logic version) before they may populate the local
   disk tier, so a corrupt/foreign remote cannot poison local state. A remote hit
   warms disk + memory. Counter: `remote_hits` (⊆ `hits`).

## On-disk layout

```
$XDG_CACHE_HOME/intermed/jars/{collector_id}/{cache_version}/{sha[0:2]}/{sha256}.json
$XDG_CACHE_HOME/intermed/jars/{collector_id}/fp/{digest[0:2]}/{digest}.json
```

Fallback when `XDG_CACHE_HOME` is unset: `~/.cache/intermed/jars/…`

Fingerprints map a jar path + `mtime`/`size` to the last known SHA-256 so repeat
runs can skip hashing unchanged jars.

## Record schema (`intermed-jar-cache-v1`)

Each file stores jar metadata plus the serialized collector payload:

- `cache_version` — the producing collector's logic version (see below)
- `mtime_secs` / `mtime_nanos` / `size_bytes` — fast invalidation
- `sha256` — full content hash when mtime/size change but bytes are identical
- `payload` — collector-specific JSON (metadata, vfs, resource-ast, mixin, sbom,
  security partials)

## Logic versioning (collector upgrades)

A jar's bytes — and therefore its SHA-256 — can be **identical** across two
releases of InterMed, yet a collector that improved its parser between those
releases must not keep serving the payload computed by the *old* parser. (Classic
stale-scanner bug: `sodium.jar` unchanged, but `mixin-analyzer` learned to read
string-form `@Mixin(targets = …)` — the new logic must recompute.)

To prevent this, every cache entry is keyed and validated by a per-collector
`cache_version`:

- It is **part of the cache key** (`{collector_id}/{cache_version}/…`), so a new
  logic version structurally cannot collide with an old payload file.
- It is **re-validated** when a record is read, as defense in depth.
- Collectors derive it from their crate version
  (`concat!(env!("CARGO_PKG_VERSION"), "-rN")`), so **every release invalidates
  automatically** — no manual global-schema bump. The trailing `-rN` revision
  lets an author force invalidation for a logic change within one release.

Old version directories are reclaimed by the normal age/size prune. Rolling back
to an earlier build transparently re-hits that build's entries.

## Invalidation

1. **Fingerprint fast path:** if the sidecar `mtime + size` match the jar on disk,
   reuse the cached SHA-256 and skip reading the full jar (counter: `fast_hits`).
2. **Logic-version miss:** the record's `cache_version` ≠ the running collector's
   version → rescan and rewrite (different key, so the old entry is left intact).
3. **Metadata miss:** current jar `mtime + size` ≠ cached payload values → rescan
   unless SHA-256 still matches.
4. **Content miss:** SHA-256 of jar bytes ≠ cached hash → rescan and rewrite.

If mtime/size change but SHA-256 matches, the entry is reused **without** rewriting
the payload: the (small) fingerprint sidecar tracks the new mtime instead, so a
launcher that touches every jar on startup no longer rewrites the whole cache each
run. `fast_hits` counts a fingerprint shortcut only when it actually yields a
usable payload — a stale fingerprint or logic-version miss is not counted as fast.

## Durability & safety

- **Atomic writes:** every cache file (payload and fingerprint) is written to a
  unique temp sibling and `rename`d into place. A concurrent reader or a crash
  mid-write never observes a truncated record (a partial read is simply rejected
  and rescanned, never served).
- **No world-writable fallback:** when neither `XDG_CACHE_HOME` nor `HOME` is set,
  the cache is **disabled** rather than falling back to a predictable shared path
  like `/tmp/intermed` (a cache-poisoning vector). An explicit `--cache-dir` is
  always honoured.

## Automatic cleanup

On startup (at most once per 24 hours), InterMed prunes the cache:

- deletes entries older than **180 days**
- if total size exceeds **512 MiB**, removes oldest files until under the cap

**Priority (LRU) eviction — hot mods kept longer.** Eviction is oldest-`mtime`-first,
and a cache hit *promotes* the entry by bumping its `mtime` (debounced to once per
hour, so a run of repeat hits does not rewrite metadata). Frequently-used ("hot")
mods therefore keep recent mtimes and survive size-cap pruning, while cold,
never-re-scanned entries are evicted first.

Manual wipe still works: `rm -rf ~/.cache/intermed`.

## Privacy

Cache files contain parsed metadata and scan summaries derived from jar contents.
They do not execute mod code. Remove `~/.cache/intermed` to clear all cached data.

## Reporting

`doctor --json` embeds cache counters under `profile.cache` when the jar cache is
enabled (no extra flags required):

```json
{ "hits": 12, "misses": 2, "writes": 2, "fast_hits": 10, "mem_hits": 4, "remote_hits": 1 }
```

`mem_hits` and `remote_hits` are subsets of `hits` showing which tier served them.

See [PROFILING.md](PROFILING.md) for phase timings.

## Layer M (`resource-ast-scanner`)

Layer M does not implement a separate cache. Per-jar AST summaries
(`JarAstPartial`) are stored through the same `JarCache` machinery as VFS and
mixin. The cache key version folds:

- crate version (`CARGO_PKG_VERSION`);
- `intermed-resource-ast-cache-v1`;
- combined domain `parser_version` (e.g. `tag-r1`, `recipe-r1`);
- active `--resource-level` (`semantic` vs `full` never share entries).

See [RESOURCE-AST.md](RESOURCE-AST.md) and [CL-LAYER-M.md](CL-LAYER-M.md).