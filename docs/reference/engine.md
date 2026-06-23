# The query engine

Detection logic in InterMed is declarative. A rule pack describes *what* facts a
finding is made of; an engine decides *how* to find them. This page describes that
engine: the pipeline a rule runs through, the backends that can run it, and — in
equal measure — what the engine does not yet do.

It matters mostly to people writing rules or reading `EXPLAIN` output. Nothing
here changes the findings you get: the backends are proven to produce identical
findings on real packs (see [Equivalence](#equivalence-and-limits)).

## Where it sits

Rules and their backends are Layer J. The engine reads facts and selects rows; it
never mutates the fact store, downloads anything, or runs mod code. It operates on
a read-only Arrow projection of the facts a run has already collected.

```text
RuleSpec (declarative pack)
   │  frontend: QuerySpec (JSON/YAML) → typed relational IR (RelExpr)
   ▼
RelExpr ──▶ logical optimizer ──▶ physical planner ──▶ strategy selection ──▶ execute
            (pushdown rewrites)    (cost model)         (FastRow | Vectorized)
```

The frontend pipeline order is fixed and predictable:

```text
scan → [join] → filters → [transitive-closure] → [aggregate + having]
     → [call-external] → [project]
```

## Backends

Select with `--logic`. All three run the *same* IR; they differ only in the
machine underneath.

| `--logic` | Engine | Availability |
| --- | --- | --- |
| `columnar` *(default)* | In-process columnar engine, pure Rust | Always |
| `souffle` | Datalog via the external `souffle` binary | Needs `souffle` in `PATH` |
| `duckdb` | Vectorized SQL over DuckDB relations | Needs a build with `--features duckdb` |

The in-process columnar backend is the default precisely because it needs no
external tool and no extra build feature. Souffle and DuckDB are alternative
executors over the identical lowered plan; `--logic duckdb` additionally routes the
log, security, and SBOM analyses through their declarative SQL forms. A backend
that is requested but unavailable fails the run with a clear message rather than
silently falling back.

Rust `ascent` (in-process Datalog), DataFusion, and Polars backends are designed
against the same pluggable `QueryBackend` seam but are **not** built in by default
— they carry heavy dependencies and are additive, not required. WASM external
functions (`CallExternal`) are similarly feature-gated.

## The in-process engine

### Two execution strategies

The engine keeps **one** logical IR and **one** physical plan; what it picks per
plan is *how* to run it.

- **Vectorized** — the full Arrow/columnar streaming engine: hash join, aggregate,
  window, transitive closure, external calls. It is relationally complete and is
  the correctness reference.
- **FastRow** — a specialized low-overhead path for the linear `Scan → Filter* →
  Project` shape that dominates real rule packs (a `FactFinding` rule is almost
  always "scan a kind, keep rows matching a conjunction of equalities, project
  `fact_id`"). It reads the columnar batch directly, pre-resolves every filter and
  projection column position once (not per row), evaluates the conjunction in place
  with short-circuiting, and materializes only the surviving projected columns — no
  boxed per-stage iterator, no intermediate tuple clones.

The planner chooses per top-level plan. FastRow is correct by construction: it
reuses the executor's own comparison and value-conversion functions, so its filter
semantics and output row order are identical to Vectorized. The two are asserted
equal on real packs.

### Optimizer and cost

Before lowering, a rule-based **logical optimizer** rewrites the plan into an
equivalent but cheaper one:

- **Predicate pushdown** — a `Filter` moves below a `Join` to the input that owns
  its column, and below a `Project` when the column survives, so fewer rows reach
  the expensive operator.
- **Projection pushdown** — a `Project`/`Aggregate`/`TransitiveClosure` tells its
  input which columns it needs, so a `Scan` is pruned to those columns. Pruning
  never crosses a join (collision-prefixing makes that unsound), so join inputs
  keep their full width.

The rewrites are equivalence-preserving for the inner-join/inner-filter semantics
the engine uses. They lean on catalog **statistics** (per-kind fact counts) to
decide column origin and the hash-join build side; with empty statistics the
provenance-dependent rewrites are skipped — a safe no-op, so the optimizer never
changes results, only ever does less work. The cost model estimates each
operator's output cardinality, CPU, and peak memory bottom-up to compare plan
alternatives.

### Inspecting a plan

```bash
intermed rules generate --backend explain <pack>   # logical + optimized + physical plan, per rule
```

`EXPLAIN` is static: it shows the logical plan, the optimized logical plan, the
chosen physical plan, and which engines the plan's constructs require — so you can
see *why* a rule routes where it does. `EXPLAIN ANALYZE` additionally runs the
plan and annotates each operator with its real output cardinality and wall-clock
time.

### Incremental maintenance

For the row-local (monotonic) fragment of the IR — `Scan` / `Filter` / `Project` —
each output row depends on exactly one input fact, so appending a delta of facts
adds exactly the result rows of running the query over just the delta:
`q(base ∪ delta) ≡ q(base) ∪ q(delta)`. The engine can therefore maintain such a
query against new facts without re-touching the base.

This is bounded on purpose: joins are monotonic but need both sides, and
aggregation and transitive closure are not row-additive, so they are reported as
not incrementally maintainable and the caller does a full re-run. The incremental
path is the sound "at least Filter and Project" slice, not a general view
maintainer.

## Equivalence and limits

The columnar engine replaced the original row interpreter as the in-process
backend; there is no longer an interpreter to select. What remains of the old code
is reused, not parallel: the engine hands its matched rows to the same finding
builder the interpreter used, so emission is shared. A test-time guard
(`intermed-query-bridge`) compares the engine's fact selection against that
builder's matching on real packs and fails on any divergence. Consequences worth
stating plainly:

- **Findings are identical across backends by construction.** Each backend selects
  matched rows and hands them to one shared finding builder, so the columnar
  default, Souffle, and DuckDB produce the same findings — validated byte-identical
  on the test corpus.
- **One residual is not relational.** `Correlation` and `Aggregate` rules cannot be
  expressed in the relational IR (e.g. `sbom-security-correlation`); their *matching*
  still runs on the original interpreter code over only those rules. It is shared
  emission, not a second engine, and removing it needs new engine operators.
- **It is a query engine over facts, not a fact source.** It cannot find anything
  the collectors did not record; its precision is the facts' precision.
- The Arrow projection round-trips losslessly (a regression harness fails if the
  columnar form differs from the source facts by one fact), and the projection is
  read-only — it reads the collected facts without mutating them or the collectors.

See [What each analysis examines](analysis.md) for the analyses that feed facts in,
and [Facts and schema](facts.md) for the fact model the engine queries.
