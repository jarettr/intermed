# Output formats

`doctor` produces one of four outputs. The terminal report is the default; the
others are written when you ask for them, and can be combined in one run.

## Terminal

The default. A header, grouped findings, and a summary line. Colour is on for a
TTY; turn it off with `--no-color`. Covered in
[Reading a report](../guides/reading-a-report.md).

## JSON

```bash
intermed doctor ./mods --json            # to stdout
intermed doctor ./mods --json report.json
```

Schema `intermed-doctor-report-v1`. Top-level keys:

| Key | Contents |
|-----|----------|
| `schema`, `tool_version`, `generated_at` | Identity of the report. |
| `target` | The path and detected kind. |
| `environment` | Loader, Minecraft version, side, OS, Java — detected or inferred. |
| `summary` | Counts: `fatal`, `error`, `warn`, `note`, `info`, `total`, and `worst`. |
| `findings` | The flat list (see below). Not grouped — group them as you like. |
| `fix_plan` | Suggested fixes, aggregated across findings. |
| `fact_stats` | A histogram of fact kinds the run produced. |
| `collectors` | Which analysis collectors ran, their layer, status, and fact count. |
| `rules` | Which rules fired and how many findings each produced. |
| `deferred_layers` | Analyses that did not run (e.g. mixin without `--mixin-risk`). |
| `profile` | Phase timings, when `--profile` is set. |

Each finding:

| Field | Contents |
|-------|----------|
| `id` | Stable, unique within a report. The argument to `--explain`. |
| `rule_id` | The rule that produced it. |
| `severity` | `fatal` / `error` / `warn` / `note` / `info`. |
| `category` | The analysis area (dependency, resource, mixin, security, …). |
| `title`, `explanation` | The human text. |
| `evidence` | Edges to the facts behind the finding (fact id, relation, weight). |
| `evidence_summary` | A flattened, inline view of the key evidence. |
| `confidence` | 0–1, how certain the finding is. |
| `affected_components` | The mods / paths the finding is about. |
| `fix_candidates` | Suggested fixes. |
| `machine_tags` | Stable tags for filtering. |
| `visibility` | Whether the finding is shown by default. |

## SARIF

```bash
intermed doctor ./mods --sarif results.sarif
```

SARIF 2.1.0, for IDE and CI code-scanning UIs (including GitHub code scanning).
Severities map to SARIF levels; each result carries its source location.

## HTML

```bash
intermed doctor ./mods --html report.html
```

A single self-contained file — inline CSS and JS, no network. Tabs:

- **Summary** — the counts (actionable / informational), environment, and which
  collectors ran.
- **Findings** — grouped, filterable by severity and category, each expandable to
  its evidence and provenance.
- **Dependencies** — declared, implicit, and bundled dependencies.
- **Resources** — namespaces, collisions by kind, semantic overrides, unresolved
  references.
- **Mixin** — the risk heatmap, per-mod complexity, overlaps.
- **Security** — the dangerous-API surface, trust scores, signatures, coremods.
- **Facts** — the predicate histogram and a sample of raw facts.
- **Performance** — hot mods and methods, and phase timings.

The depth of the Mixin and Resource tabs follows `--mixin-risk` and
`--resource-level`.

## Other artifacts

| Flag | Output |
|------|--------|
| `--dump-facts <FILE>` | The raw fact snapshot, before rules. Pair with `rules explain --facts`. |
| `--profile <FILE>` | An `intermed-doctor-profile-v1` wall-clock phase profile. |

For the fact model itself, see [Facts and schema](facts.md).
