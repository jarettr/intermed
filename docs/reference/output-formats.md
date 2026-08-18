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

The canonical schema is `intermed-doctor-report-v2`. Use
`--report-schema v1` only for a consumer that has not migrated yet; that
compatibility representation omits the trust-contract detail described below.

Top-level keys:

| Key | Contents |
|-----|----------|
| `schema`, `tool_version`, `generated_at` | Identity of the report. |
| `target` | The path and detected kind. |
| `environment` | Loader, Minecraft version, side, OS, Java — detected or inferred. |
| `analysis_environment` | Host process information, kept separate from the analyzed runtime. |
| `target_capabilities` | Coverage of the manifest, artifacts, classpaths, mappings, logs, configs, scripts, datapacks, and runtime profile. |
| `summary` | Counts: `fatal`, `error`, `warn`, `note`, `info`, `total`, and `worst`. |
| `findings` | The flat list (see below). Not grouped — group them as you like. |
| `evidence_graph` | Canonical artifacts, mod instances, classes, methods, resources and runtime events plus typed links between them. |
| `incidents` | Runtime occurrences grouped by semantic failure without merging their physical provenance. |
| `recommendations` | Deduplicated actions referenced by one or more findings. |
| `fix_plan` | Suggested fixes, aggregated across findings. |
| `fact_stats` | A histogram of fact kinds the run produced. |
| `collectors` | Which analysis collectors ran, their layer, status, and fact count. |
| `rules` | Which rules fired and how many findings each produced. |
| `deferred_layers` | Analyses that are not implemented for the selected target. Disabled, skipped, active, and incomplete collectors are recorded separately in `analysis_configuration`. |
| `profile` | Phase timings, when `--profile` is set. |

Each finding:

| Field | Contents |
|-------|----------|
| `id` | Presentation/compatibility identifier, unique within a report. The argument to `--explain`. |
| `semantic_id`, `occurrence_id` | Stable conclusion identity and, when applicable, the physical occurrence identity. |
| `family`, `channel` | Typed conclusion family and report channel. |
| `rule_id` | The rule that produced it. |
| `severity` | `fatal` / `error` / `warn` / `note` / `info`. |
| `category` | The analysis area (dependency, resource, mixin, security, …). |
| `title`, `explanation` | The human text. |
| `evidence` | Edges to the facts behind the finding (fact id, relation, weight). |
| `evidence_path` | Typed cross-layer links connecting the conclusion to canonical entities. |
| `recommendation_ids` | References to shared recommendation objects. |
| `evidence_summary` | A flattened, inline view of the key evidence. |
| `confidence` | 0–1, how certain the finding is. |
| `affected_components` | The mods / paths the finding is about. |
| `fix_candidates` | Suggested fixes. |
| `machine_tags` | Stable tags for filtering. |
| `visibility` | Whether the finding is shown by default. |
| `assessment` | Final disposition, impact, certainty, proof kind, provenance, required coverage, evaluated prerequisites, blockers, and severity adjustments. |

`assessment.disposition` is `asserted`, `downgraded`, or `abstained`. An
`abstained` record preserves the candidate conclusion and evidence but is not a
hard claim. Its `blockers` explain exactly which prerequisite was missing; for
example an incomplete provider universe or incompatible mappings. Error and
Fatal conclusions are permitted only when their declared contract is satisfied.

## Schema compatibility

- `intermed-doctor-report-v2` is canonical from 0.1.6.
- The v1 reader remains supported.
- `doctor --report-schema v1` is a temporary, lossy writer through 0.1.7. It
  removes assessment and target-capability detail that v1 consumers cannot
  represent.
- Additive optional fields do not change the schema identifier. Removing a
  field, changing its meaning/type, or making an optional field mandatory
  requires a new schema identifier.

Rule packs follow the same explicit policy. `intermed-rule-pack-v3` requires an
assessment contract, including a typed `conclusion_kind`, for Error/Fatal rules.
Legacy v1/v2 packs still load, but
their hard findings are capped at Warn and carry the
`legacy-rule-pack-has-no-proof-contract` blocker.

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

The depth of the Mixin and Resource tabs follows `--mixin-level` and
`--resource-level`.

## Other artifacts

| Flag | Output |
|------|--------|
| `--dump-facts <FILE>` | The raw fact snapshot, before rules. Pair with `rules explain --facts`. |
| `--profile <FILE>` | An `intermed-doctor-profile-v1` wall-clock phase profile. |
| `--telemetry-out <FILE>` | An explicitly requested, privacy-filtered `intermed-telemetry-event-v1`; see [Telemetry and privacy](../guides/telemetry.md). |

For the fact model itself, see [Facts and schema](facts.md).
