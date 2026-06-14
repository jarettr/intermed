# Layer D — Log / crash analysis

The cheapest, most direct evidence of a broken pack is its own logs. Layer D is a
**pure, JVM-free** port of the old `LogAnalyzer`: it scans `latest.log`,
`debug.log`, and the newest crash report, classifies failure signatures, and —
since this work — reconstructs structured stack traces and correlates them with the
installed mod set. *Doctor explains; runtime enforces.*

**Crate:** [`intermed-log`](../crates/intermed-log/) · **Live status:**
[STATUS.md](STATUS.md)

## What it reads

`log_files(target)` collects, in order:

- a single file when the target *is* a log/crash file;
- otherwise `logs/latest.log`, `logs/debug.log`, and the most recent
  `crash-reports/*.txt`.

Large `debug.log`s (hundreds of thousands of lines) are scanned in parallel
(`par_iter().enumerate()` above `parallel_line_threshold`, default 4096); emission
stays sequential and in line order, so the fact set is worker-count-independent.

## 1. Signal classification (`log_signal`)

Each line is matched against the signature table (`patterns()`, first match wins
per line). Signals and severities:

| Signal | Severity | Matches |
|--------|----------|---------|
| `MixinApplyError` | Error | `InvalidMixinException`, `Mixin apply failed`, … |
| `NoClassDefFound` / `ClassNotFound` | Error | runtime class resolution failures |
| `MissingDependency` / `ModLoadingFailure` | Error | loader resolution errors |
| `OutOfMemory` / `JvmCrash` | Fatal | `OutOfMemoryError`, `SIGSEGV`, hs_err |
| `StackOverflow` | Error | `StackOverflowError` |
| `PortInUse` | Error | `Address already in use` |
| `DatapackValidationError` | Warn | datapack load failures |
| `RegistryFreezeError` | Error | registry mutated after freeze |

`signal_severity` / `signal_title` / `signal_fix` are shared with the declarative
(DuckDB / Datalog) backends so findings stay identical across rule engines.
`LogSignalRule` turns each `log_signal` into a finding with a per-signal fix hint.

## 2. Structured stack traces (`stacktrace.rs`)

The line scan classifies *individual* lines; a Java crash is a multi-line
structure. [`parse_stacktraces`](crates/intermed-log/src/stacktrace.rs) reconstructs
it, tolerant of a logger prefix (`[12:00:00] [Render/ERROR]: `) or none (crash
reports). For each trace it captures:

- the thrown **exception** (class + message) and its `at …` **frames**;
- the **`Caused by:`** chain, with each link's frames routed to *that* link (frames
  after a `Caused by` belong to it, not the top exception);
- `... N more` elisions are consumed.

## 3. Mod correlation (`log_mentions_mod`)

From each trace, mods are extracted **structurally** (no guessing from package
names):

- a `*.mixins.json` / `mixins.*.json` reference → that mod id (`via=mixin-config`,
  confidence 0.9);
- explicit loader phrases `mod 'x'`, `Failed to load mod x`, `for mod x`
  (`via=message`, confidence 0.7).

References are de-duplicated and emitted as `log_mentions_mod` facts
(`subject` = mod id; `via`, `exception`, `line`, numeric `blame_score`). When
Layer B metadata exists, version, environment, and capabilities are attached.

Each reconstructed trace also emits `log_crash` using the deepest `Caused by`
exception as root cause, plus one weighted `log_mod_error` per structurally
named mod. These facts power the DuckDB `log_root_causes` view.

`LogSignalRule` then **cross-references** mentions with installed Layer-B `mod`
facts:

- a mod named in a crash trace that is **also installed** → `Warn` *"crash trace
  implicates installed mod X"* — the strongest triage lead ("look here first");
- a name with **no matching install** → `Note` (often a missing dependency or a
  renamed jar).

## Confidence and honesty

The signature table and phrase patterns are **best-effort** (logs vary by loader
and version), so every `log_signal` keeps its source line + excerpt and is stamped
at confidence 0.85; mentions carry the exception and line. A human can audit every
claim. The tables are the single point of extension when new formats appear.

## Modern mod crash patterns

Additional regex signals (see `intermed-log` `patterns()`):

| Signal | Typical cause |
|--------|----------------|
| `SodiumConflict` | Duplicate Sodium / Rubidium / Embeddium |
| `IrisShaderError` | Iris without Sodium or bad shader pack |
| `LithiumConflict` | Lithium / Radium / CaffeineConfig mixin clash |
| `CreateError` | Create / Flywheel / Registrate init failure |
| `NeoForgeLoadError` | `ModLoadingException` / mod instance creation |

## Cross-layer: performance × logs (D3)

D3 is implemented at **mod granularity** in Layer I (no per-line wall-clock join):

| Finding | Join | Severity |
|---------|------|----------|
| `perf-log-suspect:{mod}` | `hot_mod` + `log_mentions_mod` | Warn |
| `perf-tick-log-suspect:{mod}` | `tick_spike` + `log_mentions_mod` (installed) | Warn |

Evidence edges link Spark facts to every supporting `log_mentions_mod` fact. See
[LAYER-I-SPARK.md](LAYER-I-SPARK.md).

> Wall-clock alignment of individual tick spikes to individual log lines is *not*
> attempted: Spark durations and log line numbers do not share a timeline in the
> fact model. Mod-level joins are the sound, evidence-backed correlation.
