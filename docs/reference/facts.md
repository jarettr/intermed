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
| `weight` | How strongly it supports a finding it is cited by. |

`doctor --dump-facts <FILE>` writes the whole fact snapshot, before any rule runs.
The predicate histogram (in the report's `fact_stats`, and the HTML Facts tab)
lists every kind and its count.

## A finding's evidence

A finding cites the facts behind it as **evidence edges** — each naming a fact, the
relation it plays (subject, supporting), and a weight. `--explain <id>` resolves
those edges back to the facts and prints them with their source. A finding whose
evidence is derived rather than read from one file says so, rather than printing an
empty source.

See [Reading a report](../guides/reading-a-report.md#explaining-one-finding).

## The report schema

The JSON report is schema `intermed-doctor-report-v1`. Its fields are listed in
[Output formats](output-formats.md#json). Other stable schema names you may see:

| Schema | Produced by |
|--------|-------------|
| `intermed-doctor-report-v1` | `doctor --json` |
| `intermed-doctor-profile-v1` | `doctor --profile` |
| `intermed-modpack-graph-v1` | `deps graph` |
| `intermed-deps-resolution-v1` | `deps resolve` |
| `intermed-config-v1` | the config file and `--dump-config` |

## Rule backends

Rules run on an in-process engine by default (`--logic columnar`). The same rules
can run on external backends over the same fact IR — Soufflé (`--logic souffle`,
needs the `souffle` binary) or DuckDB (`--logic duckdb`, needs a `--features
duckdb` build). The backend changes where the reasoning runs, not the result.
