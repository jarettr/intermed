# InterMed Roadmap

> **Status: working draft (v0).** This is a direction, not a schedule. It lists
> *horizons* (Now / Near / Far), not dates, because effort is shared across a
> small team and the further out a line is, the less it is a promise. The
> **principles** below constrain every horizon; the **open decisions** at the end
> are still ours to settle.

---

## How to read this

A roadmap here answers three questions, in order: what makes InterMed's output
**trustworthy**, what makes it **useful**, and what makes it **adopted** — and
only as a parallel background, what makes the internals **elegant**. The analysis
*depth* is already built; depth is no longer the binding constraint. Every line
below is placed by that order of leverage, not by how interesting it is to build.

---

## Principles (the spine)

These are invariants. A feature that violates one is wrong no matter how valuable
it looks.

1. **The evidence engine is the source of truth. Everything else interprets it.**
   Facts come from disk; rules reason over facts; findings cite facts. Nothing
   downstream — including any model — may invent a fact or override the engine.
2. **Measure before you optimize.** "Heuristics to the ideal" is undefined without
   a measured distance to that ideal. The measurement loop is therefore a
   *precondition* for deepening heuristics, not a separate nicety.
3. **AI interprets; it never decides.** Learned models prioritize, cluster, and
   explain over the engine's features. Probability never pretends to be proof. A
   verdict ("safe", "will break") must rest on the deterministic engine.
4. **Safety and verification stay deterministic.** Security and mod verification
   are the highest-stakes domains; they are answered by proof, never by a model's
   confidence.
5. **Parity is how a team stays coherent.** Differential gates (identical findings
   across changes), the single declarative rule source, and the fact schema are
   not just author discipline now — they are the contract that stops contributors
   from breaking each other's invariants. They are load-bearing.
6. **Absence of evidence is never proof.** Each analysis states what it *cannot*
   conclude. (Already enforced in the docs via the per-analysis "Stops at".)
7. **No data without consent.** All telemetry and log collection is opt-in,
   explicit, and documented before any byte is gathered.

---

## Horizons

### Now — Hardening · *currency: correctness & hygiene*

Goal: ship a 0.1.x worth trusting, and quietly start the clock on the one thing
that compounds with time (data).

- **Close the remaining correctness items.** (The three latent parser panics from
  the bug hunt are already fixed and fuzz-guarded.) Remaining: canonicalize/reject
  nullable join keys at lowering, so the in-process engine (Null = Null) and the
  DuckDB backend (SQL Null ≠ Null) can never silently diverge on a future rule.
- **Project Status / maturity statement** in the docs: this is an alpha, validated
  against the packs we ran, not yet widely exercised; here is what is deferred.
- **Schema honesty as a CI gate**: a test asserting every `kind::` predicate is
  either emitted/read or explicitly reserved — phantom predicates become
  impossible by construction.
- **Perf micro-levers (optional, low-risk):** ancestor-set cache in `related()`
  (the last few percent of mixin time); `group_key` via the type-safe `HashKey`;
  zip central-directory CRC32 in VFS pass 1 (the remaining ~47% of VFS, if
  revisited).
- **Begin consented telemetry**: opt-in collection of run outcomes and logs. This
  is time-sensitive — every un-logged run is a training example lost forever — and
  it is the dependency that makes the Far/AI horizon possible at all.
- **Release 0.1.x publicly.**

### Near — Trust, product, and a gradual engine restructure · *currency: usefulness*

These tracks can run partly in parallel (team capacity permitting). Track A gates
the heuristic-deepening work in Far.

- **Track A — Measurement (precondition for "heuristics to the ideal").** Close the
  calibrate / lab feedback loop: per-finding attribution against real outcomes,
  precision/recall *per rule*, and data-grounded severity. This is what turns
  "the mixin rule's false-positive rate is ~30%" from a guess into a number — and
  what makes "deepen the heuristics" a measurable target instead of a vibe.
- **Track B — Triage.** Surface the actionable few from the informational many so
  the depth never drowns the user. Rule-based ranking first (ships value with zero
  ML); learned ranking later, once Track A and telemetry support it.
- **Track C — Evidence → action.** Move from "here is the conflict" to "here is the
  line that resolves it" — a concrete mixin blacklist/priority entry, a fix plan —
  without ever editing the user's pack. This is also the conceptual precursor to
  imod.
- **Track D — imod v0.** A verifiable, signed, mod-level manifest. The standards
  play: shift InterMed from *analyzing arbitrary mods* (recall-bound, after the
  fact) toward being *the thing mods are built against*. (Requires a reason for the
  first authors to adopt before an ecosystem exists — see Open decisions.)
- **Track E — Engine restructure (incremental, behind shadow gates).** The gradual
  rework deferred earlier: FactStore compaction (flat representation + key/kind
  interning) and finishing the columnar-migration tail (collectors emitting
  columnar directly). These converge on one end-state — no row store, everything
  flat from emission, conflict edges derived rather than materialized — which cuts
  both peak memory (the scaling lever for the largest packs) and store-build time.
  Done in small parity-gated steps, never a big-bang cutover.

### Far — Depth, learned interpretation, and the ecosystem · *currency: research & bets*

The bets. Each is gated on a Near deliverable; none should start before its gate.

- **Learned micro-models**, trained on the telemetry gathered since Now, acting as
  *interpreters* over the engine's measured features (false-positive estimation,
  root-cause hints, ranking). Never a source of verdicts. Gated on: consented data
  (Now) + measurement loop (Near A).
- **Heuristics deepened toward the now-measurable ideal.** Gated on: Near A.
- **Micro-LLM coverage across the engine** — broader interpretation, same rule:
  interpret, never decide.
- **[research track] Unified interference contour** — modelling mixin conflict,
  resource override, and dependency cycle as instances of one abstract
  interference. Kept explicitly exploratory and gated on a concrete payoff: does
  the unified contour find conflicts no single-layer rule can? If not, it is
  elegance without shipping value.
- **Deterministic mod verification + full security audit** — on the proof side of
  the line, never the learned side.
- **impack** — verifiable pack composition and ecosystem standardization. Gated on:
  imod adoption (Near D).

---

## Cross-cutting dependencies

The non-obvious wiring that the horizons hide:

- **consented telemetry (Now) → learned models (Far).** Start collecting now or
  arrive at the AI horizon with an empty dataset.
- **measurement loop (Near A) → heuristic deepening (Far).** You cannot optimize to
  an ideal you cannot measure.
- **imod (Near D) → impack / standard (Far).** The ecosystem play is a chain, not a
  jump.
- **parity gates → team coherence (always).** The contract scales the team without
  scaling the breakage.

---

## Non-goals (this cycle)

A roadmap is also a list of refusals.

- **AI as a source of verdicts.** Ever.
- **A runtime / auto-resolving loader.** Held privately as a long-term north star;
  deliberately *not* promised here, possibly not even reachable.
- **The unified contour as a committed feature.** It is a research track, not a
  deliverable.
- **[OPEN] Live Compatibility-Lab runner** (fetching + launching candidates) —
  stays deferred, or cut from scope entirely?
- **[OPEN] Trimming the engine backends** toward in-process + a single oracle
  (DuckDB), retiring the speculative ones?
- **[OPEN] Minimum supported Minecraft / loader versions.**

---

## Open decisions (ours to settle)

1. **Primary user for the Near horizon.** Pack authors/admins (→ weight Track C +
   imod), CI/hosting/professional builds (→ weight SARIF, gating, memory scale), or
   the technical/portfolio audience (→ weight depth + demos)? Near cannot optimize
   for all three at once.
2. **Team capacity** — how parallel can the Near tracks actually run, and which is
   the single most important to finish first?
3. **The first-adopter problem for imod.** What gives the *first* mod authors a
   reason to publish a manifest before the ecosystem that rewards it exists?
4. **The three `[OPEN]` non-goals above.**
