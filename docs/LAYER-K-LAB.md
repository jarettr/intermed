# Layer K — Compatibility Lab (Phase 8)

Reproducible compatibility **evidence**: pin a mod corpus, run smoke tests
against bootstrapped environments, classify the failures, and emit a
compatibility matrix + static HTML site.

**Live status:** [STATUS.md](STATUS.md) · **Crate:**
[`intermed-lab`](../crates/intermed-lab/) · **STATUS string in code:**
`active: Phase 8 (offline evidence path; live runner deferred)`

Unlike the diagnostic layers, the lab is **operations, not a `Collector`** — it
runs under explicit `intermed lab` subcommands, never the doctor pipeline.

## Structurally deferred: live runner

The lab is **split by trait boundary**, not by “unfinished stub”:

| Component | In-tree today | Deferred donor |
|-----------|---------------|----------------|
| Candidate sourcing | [`FileCandidateProvider`](crates/intermed-lab/src/corpus.rs) (JSON on disk) | Networked `ModrinthClient` → [`CandidateProvider`](crates/intermed-lab/src/corpus.rs) |
| Smoke execution | [`CapturedLogRunner`](crates/intermed-lab/src/run.rs) (`intermed-smoke-output-v1` files) | `ServerProcessRunner`, loader installers, `VanillaServerFetcher` → [`SmokeRunner`](crates/intermed-lab/src/run.rs) |

**Live server execution is intentionally out of the deterministic core** so
`lab discover` / `run` / `report` / `eval` stay offline-testable without network
or a JVM. Promoting a live runner means implementing the same traits — no doctor
pipeline changes. See module docs in
[`intermed-lab/src/lib.rs`](../crates/intermed-lab/src/lib.rs).

## What is implemented (the offline evidence path)

Everything that turns **captured** runs into reproducible evidence is implemented
and tested. Following the Spark bridge's *import, don't execute* discipline,
the in-tree path ingests smoke outputs from disk; it does not launch Minecraft.

```
candidates.json ──(discover)──▶ corpus.lock ──(run)──▶ lab-run.json ──(report)──▶ matrix.json + index.html
                   dedup+pin+digest        classify failures       aggregate matrix
```

## Commands

```bash
intermed lab discover ./candidates.json --out corpus.lock
intermed lab run corpus.lock --logs ./captured --out ./runs/latest
intermed lab report ./runs/latest --out ./site
```

### `lab discover` — corpus lock

Builds a deterministic, content-addressed lock from a candidate pool
(`intermed-corpus-candidates-v1`):

- duplicate `project_id`s collapse to one entry, keeping the higher `downloads`
  (ties → lexicographically smaller `version_id`) — the rewritten Modrinth
  weighting;
- entries are sorted by `project_id`;
- a SHA-256 `digest` is computed over the canonical pinned set. Two locks with the
  same digest pin the exact same corpus for the exact same environment. Loading a
  hand-edited lock whose digest no longer matches is rejected.

### `lab run` — smoke-test ingestion + classification

Reads captured smoke outputs (`intermed-smoke-output-v1`, one JSON per
environment) and classifies each into a `SmokeResult`:

| Status | Meaning |
|--------|---------|
| `pass` | clean exit |
| `fail` | non-zero exit, recoverable failure category |
| `crash` | OOM / StackOverflow / JVM hard crash |
| `timeout` | exceeded the run time budget |

Failure categories are aligned with Layer D log signals (`mixin-apply-error`,
`missing-dependency`, `mod-loading-failure`, `class-not-found`,
`registry-freeze-error`, `datapack-validation-error`, `port-in-use`,
`out-of-memory`, `stack-overflow`, `jvm-crash`, `unknown`).

To run smoke tests today, produce `intermed-smoke-output-v1` JSON (or plain logs
the classifier understands) under `--logs` and pass them to `lab run`. A future
live runner would emit the same schema from a real JVM process.

### `lab report` — compatibility matrix

Aggregates a run into `intermed-compatibility-matrix-v1` (totals, pass rate,
failure-by-category histogram, per-environment cells) and renders a
self-contained, HTML-escaped `index.html`.

## Schemas

| Schema | Produced by |
|--------|-------------|
| `intermed-corpus-candidates-v1` | discovery input (hand-authored or fetched) |
| `intermed-corpus-lock-v1` | `lab discover` |
| `intermed-smoke-output-v1` | a smoke runner (captured or live) |
| `intermed-lab-run-v1` | `lab run` |
| `intermed-compatibility-matrix-v1` | `lab report` |

All artifacts are written with a temp-then-rename atomic discipline.

## Smoke taxonomy extensions

Beyond crash/OOM, classification now covers:

| Category | Smoke status | Example log signal |
|----------|--------------|-------------------|
| `performance-regression` | `degraded` (clean exit) or `fail` | `Can't keep up`, `Running Nms behind`, `MSPT` |
| `mixin-apply-error` | `fail` | `InvalidMixinException`, `MixinTransformerError` |

`SmokeStatus::Degraded` marks a server that exited cleanly but failed the tick
budget — the shape of perf regressions Spark/Doctor correlate against.

Live execution contracts (`ServerProcessRunner`, `EnvironmentRunner`) live in
`crates/intermed-lab/src/execution.rs` (interfaces only; JVM path deferred).

## Deferred donors (rewrite-hard: network / process)

`ModrinthClient` (50% downloads / 25% follows / 25% updated, dedupe by project
id) → a networked `CandidateProvider`; `EnvironmentBootstrap`, the loader
installers, `VanillaServerFetcher`, `ServerProcessRunner` → a live `SmokeRunner`.
These stay out of the deterministic core so the evidence path never depends on
the network or a JVM.

## `lab eval` — precision loop

Score Doctor predictions against lab ground truth:

```bash
intermed lab eval --report report.json --run runs/latest/lab-run.json --out accuracy.json
intermed lab eval --manifest dataset.json --min-severity warn --out accuracy.json
```

Emits `intermed-rule-accuracy-v3` with **three** evaluation granularities:

| Mode | Field | Unit | What it measures |
|------|-------|------|------------------|
| Category co-occurrence | `by_category` | one tp/fp/fn per (mod-set, category) | Did category C appear in predictions **and** observations? First-order framework; collapses intra-case multiplicity. |
| Attributed finding-level | `by_rule`, `finding_level` | one tp/fp per **finding** | Joins each qualifying finding against lab `attributions` (subjects extracted from crash logs). |
| Per-finding audit trail | `by_finding` | one row per finding id | Same join as above with `matched_subject` on true positives (CI/debug friendly). |

**Category co-occurrence limitations** (documented honestly):

- Five `mixin-overlap` findings + one mixin crash → **one** tp, not 1 tp + 4 fp.
- `loader`, `side`, and `duplicate` rules share the `mod-loading-failure` bucket.
- Linkage is co-occurrence, not causal attribution.

**Finding-level mode** closes the noise gap: each flagged finding is scored
individually against attributed subjects (`mod id`, JVM class, jar stem). Lab
`attributions` on each `SmokeResult` are populated
automatically by `lab run` from captured logs.

**Severity calibration** (`suggested_severity` in `by_category` / `by_rule`):
grounded in observed precision but stays at `note` until at least
`SEVERITY_CALIBRATION_MIN_SUPPORT` (10) predictions exist — so tp=2, fp=0
cannot force `error` in CI.

Only *predictive* findings participate (mixin, dependency, loader/side/duplicate).
Reactive findings (security, SBOM, log-signal) are excluded.

## Tests

```bash
cargo test -p intermed-lab
cargo test -p intermed-cli --test e2e lab_discover_run_report_pipeline
cargo test -p intermed-cli --test e2e lab_eval_scores_doctor_predictions_against_ground_truth
```
