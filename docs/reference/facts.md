# Facts and schema

Everything InterMed reports is built from facts. Understanding the fact model
explains why a finding says what it says, and what `--explain` is showing you.

## The pipeline

```
files on disk → collectors → facts → rules → findings → report
```

- **Collectors** read the target — a jar's metadata, its mixins, its resources, a
  log — and emit **facts**.
- **Rules** read facts and emit **findings**. A rule never reads a file; it only
  reasons over facts. This is why every finding can be traced back to facts, and
  every fact back to a file.
- The **report** is the findings plus the context (environment, counts, which
  collectors ran).

The fact graph is the single source of truth. Two findings about the same jar
cite the same facts; a diff between runs is a diff over stable finding ids.

## A fact

Each fact has:

| Field | Meaning |
|-------|---------|
| `kind` | The predicate — `dependency`, `mixin_overlap`, `resource_collision`, `trust_score`, … |
| `subject` | What the fact is about — a mod id, a resource path, a target class. |
| `attributes` | Typed key/values carrying the detail. |
| `source` | Where it was read: a locator (the jar), an optional inner path (the file inside it), and an optional line. |
| `extractor` | Which collector produced it. |
| `confidence` | How certain the extractor is that the observed fact is correct. |

`doctor --dump-facts <FILE>` writes the whole fact snapshot, before any rule runs.
The predicate histogram (in the report's `fact_stats`, and the HTML Facts tab)
lists every kind and its count.

## A finding's evidence

A finding cites the facts behind it as **evidence edges**. Each edge names a fact, a
weight, and the **relation** the fact plays:

| Relation | Meaning |
|----------|---------|
| `Subject` | The fact is the thing being complained about. |
| `Supports` | The fact directly backs the finding. |
| `Mentions` | The fact references another (a name, a path). |
| `Violates` | The fact contradicts an expectation. |
| `ConflictsWith` | Two facts conflict with each other. |
| `CorrelatesWith` | A heuristic link — the edge that ties one layer's fact to another's. |

`--explain <id>` resolves those edges back to the facts and prints them with their
source. A finding whose evidence is derived rather than read from one file says so,
rather than printing an empty source.

`CorrelatesWith` is how the analyses connect: a finding from one analysis can cite a
fact from another — a mixin site that owns a hot Spark method, a low-trust jar that
also references a dangerous API. See
[How the analyses connect](analysis.md#how-the-analyses-connect).

See [Reading a report](../guides/reading-a-report.md#explaining-one-finding).

## The report schema

The JSON report is schema `intermed-doctor-report-v1`. Its fields are listed in
[Output formats](output-formats.md#json). Other stable schema names you may see:

| Schema | Produced by |
|--------|-------------|
| `intermed-doctor-report-v1` | `doctor --json` |
| `intermed-doctor-profile-v1` | `doctor --profile` |
| `intermed-telemetry-event-v1` | explicit `doctor --telemetry-out` / `--telemetry-endpoint` |
| `intermed-modpack-graph-v1` | `deps graph` |
| `intermed-deps-resolution-v1` | `deps resolve` |
| `intermed-config-v1` | the config file and `--dump-config` |

The predicate catalog is also lifecycle-checked in CI. Every built-in `kind::`
predicate must be referenced by production code or marked `reserved = true` in
`crates/intermed-facts/schema.toml`; a reserved predicate that becomes active
must have that marker removed. `complete = false` instead describes an active
predicate whose row may legitimately omit some terms.

## Rule backends

Rules run on an in-process engine by default (`--logic columnar`). The same rules
can run on external backends over the same fact IR — Soufflé (`--logic souffle`,
needs the `souffle` binary) or DuckDB (`--logic duckdb`, needs a `--features
duckdb` build). The backend changes where the reasoning runs, not the result.
