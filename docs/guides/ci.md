# Using InterMed in CI

InterMed is built to run unattended. It reads only the files you point it at,
writes machine-readable output, and sets its exit code by the worst finding.

## Gating a build

The exit code is the gate: `0` healthy, `1` warnings, `2` errors or worse. To
fail a build only on errors, treat exit `1` as a pass:

```bash
intermed doctor ./mods --json --html report.html
code=$?
[ "$code" -ge 2 ] && exit 1 || exit 0
```

To fail on any warning, gate on `code -ge 1`. To never let findings fail the step
— for example when you only want the report artifact — add `--exit-zero`, and a
non-zero exit then means a genuine operational error instead:

```bash
intermed doctor ./mods --json report.json --exit-zero
```

## Machine output

| Flag | Output |
|------|--------|
| `--json [FILE]`  | The full `intermed-doctor-report-v1` report. |
| `--sarif [FILE]` | SARIF 2.1.0, for code-scanning UIs. |
| `--html FILE`    | A self-contained HTML report (no network, inlined assets). |

`--json` and `--sarif` write to stdout when given no path, or to the file you
name. They can be combined with `--html` in one run.

GitHub code scanning consumes SARIF directly:

```yaml
- run: intermed doctor ./mods --sarif results.sarif --exit-zero
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

## Keeping runs fast

InterMed caches each jar scan on disk, keyed by the jar's content. The first run
populates the cache; later runs reuse it for any jar that has not changed.

- Persist the cache directory between CI runs (default
  `$XDG_CACHE_HOME/intermed`, or set `--cache-dir`).
- `--changed-since <time>` scans only jars modified at or after a timestamp
  (RFC3339 or unix seconds), for incremental checks.
- `--jobs N` caps worker threads on shared runners.

A shared cache tier — one machine's scan reused by another — is available with
`--cache-remote-dir <dir>` pointed at a network mount or restored CI cache. See
[Caching](../reference/caching.md).

## Tracking findings over time

Pass `--db history.duckdb` to persist each run into an analytics store (requires a
build with `--features duckdb`). Then:

```bash
intermed history conflicts --db history.duckdb   # findings that recur across runs
intermed history diff --db history.duckdb A B     # what changed between two runs
intermed trends mixin-risk --db history.duckdb    # mixin risk over time
```

## A note on determinism

Given the same inputs, a run produces the same facts and findings. Finding ids
are stable, so a diff between two runs is meaningful. Order of jars on disk does
not change the result.
