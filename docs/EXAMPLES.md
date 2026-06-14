# InterMed command examples

Copy-paste recipes for every subcommand. For mental model see
[CONCEPTS.md](CONCEPTS.md); for per-layer implementation status see
[STATUS.md](STATUS.md).

## doctor

```bash
# Diagnose a mods directory (default target: current directory)
intermed doctor ./mods

# Full JSON report with embedded profile/cache stats
intermed doctor ./server --json

# Mixin overlap + overwrite risk (Layer F)
intermed doctor ./mods --mixin-risk

# Declarative rule backends
intermed doctor ./mods --logic=datalog
intermed doctor ./mods --logic=souffle   # requires `souffle` in PATH

# DuckDB SQL backend (build with --features duckdb)
cargo build -p intermed-cli --features duckdb
intermed doctor ./mods --logic=duckdb --mixin-risk --json
intermed doctor ./mods --logic=duckdb --db history.duckdb
intermed db query --db history.duckdb "SELECT rule_id, severity, COUNT(*) FROM findings GROUP BY 1, 2"

# Provenance tooling
intermed doctor ./mods --dump-facts facts.json
intermed doctor ./mods --explain duplicate-id:some-mod --no-color

# --explain is fuzzy: a partial / typo'd id auto-resolves on a unique match, else
# prints ranked "did you mean" suggestions, else the top findings by severity.
intermed doctor ./mods --explain dupmod          # → resolves to duplicate-id:dupmod
intermed doctor ./mods --explain duplcate-id      # → "did you mean: …"

# Exit-code control: by default the exit code follows findings (0 healthy / 1 warn
# / 2 error), so writing a --json/--sarif/--html/--profile artifact still "fails" a
# CI step. --exit-zero makes findings stop affecting the exit code; a non-zero exit
# then means only a genuine operational error (bad target, unwritable output).
intermed doctor ./mods --json --exit-zero > report.json

# Output verbosity (global flags, work on every subcommand)
intermed doctor ./mods --quiet            # suppress progress messages
intermed doctor ./mods -v                 # per-scan detail (fact/finding counts)

# --logic non-imperative backends print which rules ran declaratively vs as an
# imperative fallback; note Layer-F mixin-risk only runs under --logic imperative.
intermed doctor ./mods --logic=datalog    # see the provenance line on stderr

# Phase 6 — SBOM + security (always on for mods targets)
intermed doctor ./mods --json
intermed doctor ./mods --explain security-api-risk:some-mod
intermed doctor ./mods --explain unknown-source:mystery.jar

# Phase 7 — Spark import (gated). --performance without a --spark-report prints a
# friendly hint on how to capture one (there is no runtime profile to correlate).
intermed doctor ./server --performance
intermed doctor ./server --performance --mixin-risk --json
intermed doctor ./server --spark-report ./spark/profile.json --performance

# Performance / cache
intermed doctor ./mods --profile profile.json
intermed doctor ./mods --no-cache
intermed doctor ./mods --cache-dir /tmp/intermed-cache
intermed doctor ./mods --cache-remote-dir /mnt/shared/intermed-cache  # shared Tier-3

# CI / IDE output
intermed doctor ./mods --sarif > report.sarif

# Interactive HTML report — one self-contained file (inline CSS/JS, no network).
# Tabs: Summary · Findings · Mixin · Facts · Performance. The Findings tab filters
# by severity & category and expands each finding to its provenance (the evidence
# facts it cites); the Mixin tab shows a risk heatmap + complexity/bloat tables.
intermed doctor ./mods --mixin-risk --html report.html
```

Exit codes: `0` healthy, `1` warnings only, `2` errors or worse.

## vfs

```bash
intermed vfs scan ./mods
intermed vfs explain ./mods
intermed vfs overlay ./mods --out ./overlay-preview

# Layer M — per-resource semantic view
intermed vfs explain ./mods --path data/create/recipes/crushing/tuff.json --ast

# Semantic overlay plan (safe / review / unsafe buckets, read-only JSON)
intermed vfs overlay ./mods --explain-plan
```

Layer M on doctor (default `semantic` level):

```bash
intermed doctor ./mods --resource-level full
intermed doctor ./mods --explain recipe-output-override:data/foo/recipes/bar.json
intermed doctor ./mods --explain implicit-dependency-missing
```

See [LAYER-M-DATA-SEMANTICS.md](LAYER-M-DATA-SEMANTICS.md).

## mixin-map

Prints overlaps, effective effects, recommendations, risk scores, the **Mixin
Complexity Score (per mod)**, **Mixin bloat**, interactions, and conflict edges.

```bash
intermed mixin-map ./mods

# Self-contained interactive graph (no CDN — opens offline): nodes by type, edges
# by conflict type, drag / search / per-edge-type filters.
intermed mixin-map ./mods --graph-format html --graph-out mixins.html
intermed mixin-map ./mods --graph-format dot  --graph-out mixins.dot   # Graphviz
```

## spark-map

```bash
intermed spark-map ./server
intermed spark-map ./server --spark-report ./spark/profile.json
```

## lab

Reproducible compatibility evidence (Layer K). See [LAYER-K-LAB.md](LAYER-K-LAB.md).

```bash
intermed lab discover ./candidates.json --out corpus.lock
intermed lab run corpus.lock --logs ./captured --out ./runs/latest
intermed lab report ./runs/latest --out ./site
```

## db

DuckDB analytics store (`--features duckdb`). Persists full runs for cross-target history.

```bash
# Persist every doctor run
intermed doctor ./mods --db ./history.duckdb

# Ad-hoc SQL (read-only)
intermed db query --db ./history.duckdb "SELECT kind, COUNT(*) AS n FROM facts GROUP BY kind ORDER BY n DESC"
intermed db query --db ./history.duckdb "SELECT target_path, generated_at, error_count FROM runs ORDER BY generated_at DESC LIMIT 10"

# Built-in analytics views (queryable directly)
intermed db query --db ./history.duckdb "SELECT * FROM risk_patterns ORDER BY severity_rank DESC LIMIT 10"
intermed db query --db ./history.duckdb "SELECT * FROM historical_conflicts WHERE run_count >= 3"
```

Re-running doctor on the same target replaces the prior row for that `run_id` (idempotent).

## history / trends

```bash
# Findings that recur across runs in a window (now with first_seen + distinct targets)
intermed history conflicts --db ./history.duckdb --since 30d

# Recurring *kinds* of risk (rule × category) rolled up across all history
intermed history patterns --db ./history.duckdb --limit 20

# Compare two runs; prune old runs
intermed history diff --db ./history.duckdb --run-a <id> --run-b <id>
intermed history prune --db ./history.duckdb --keep 90d

# Time series
intermed trends mixin-risk --db ./history.duckdb
```

## rules

```bash
intermed rules check ./rules
intermed rules check ./rules/core/intermed-core.rules.json
```

## Man pages

After building, view generated roff:

```bash
man -l docs/man/intermed.1
```