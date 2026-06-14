# Appendix B boundary — hybrid engine vs. the current goal

The spec's *Приложение Б: Архитектура гибридного движка InterMed Core* describes
an ambitious hybrid engine (ephemeral JVM workers, DuckDB, Wasmtime, a
transactional shadow VFS, resilient telemetry). Its own critique already names
three structural risks: **distribution hell** (Rust + JVM + DuckDB + Wasmtime in
one binary), **cold-start cost** (standing up that infrastructure to check a
single log), and **schema-sync fragility** (FlatBuffers ↔ DuckDB ↔ Rust models
must move in lockstep or segfault on obfuscated input).

The project's **current goal** is narrow and clear:

> A static Minecraft modpack/server **evidence engine** — collectors → facts →
> rules → findings → reports. *Doctor and PackOps explain. Runtime enforces.*

This document extracts, item by item, what from Appendix B serves that goal now,
and consigns the rest to the deferred **runtime** track (~1 year out, until the
engine stabilizes — see `intermed-runtime-preflight`).

## Decision table

| Appendix B item | Keep now (current goal) | Defer to runtime / later |
|-----------------|-------------------------|--------------------------|
| **B.1 Hybrid IPC (Rust ↔ ephemeral JVM, FlatBuffers/UDS, zero-copy)** | Nothing concrete: Layers F/G already parse bytecode in **pure Rust** (`cafebabe`/`noak`) with per-jar error isolation. The *discipline* (bytecode parsing is an isolated, failure-contained step) is already realized. | The JVM worker, FlatBuffers transport, and JNI/GraalVM polyglot — added only if a deep-AST need outgrows pure Rust. Pure distribution + schema-sync risk. |
| **B.2 Columnar fact store (DuckDB) + Datalog-as-SQL** | The **seam** (unchanged): `FactStore` + pluggable Layer-J backends. **Landed (feature-gated):** `intermed-duckdb` — embedded SQL rule backend (`--logic duckdb`, six core rules in `sql.rs`), append-only analytics (`doctor --db FILE`, `intermed db query`). Schema ↔ Rust mapping: `schema.rs` (DDL + rows), `sql.rs` (rule programs). | Full auto-codegen of DDL from serde; dependency/log/security rules as SQL; Wasmtime/JVM hybrid IPC; server-tick log volume at columnar scale without an explicit ops need. Default builds/CI stay DuckDB-free. |
| **B.3 WASM plugin microkernel (Wasmtime, capability security, fuel)** | The **declarative rule-pack** model (`intermed-rules`, JSON/YAML, validated by `rules check`). Community rules that are *data, not code* are capability-safe by construction — no sandbox needed. | Executing arbitrary community code (Python/JS → WASM). A real extension/runtime concern and a distribution burden; the declarative model covers the near-term need. |
| **B.4 Transactional VFS / Shadow Engine (WAL, atomic commit, CoW)** | **Atomicity discipline is already in use**: PackOps writes overlay *previews* via temp-dir + atomic rename, and the jar cache now writes records the same way. Doctor/PackOps **explain** (previews), they don't mutate in place. | Full WAL + copy-on-write **in-place** mutation of a live pack. In-place enforcement belongs to the runtime, not the evidence engine. |
| **B.4 (sensors) Dynamics from script-engine logs (KubeJS/CraftTweaker)** | **Done — `intermed-dynamics` (Layer E).** Parses `crafttweaker.log` / `logs/kubejs/*.log` for removed-recipe / removed-item markers and injects `runtime_removed_recipe` / `runtime_removed_item` facts; `ScriptDynamicsRule` folds them into one auditable note. Pure evidence, no new infrastructure. See `docs/LAYER-E-DYNAMICS.md`. | The item→mod **correlation** rule (flag an unobtainable item) waits on an item-registry fact source; it is one more `Rule`, no infrastructure. |
| **B.5 Telemetry & resilient routing (multiplexed tunnel, socks5/split-tunnel)** | Local artifact generation for the Compatibility Lab (`matrix.json` + static HTML) — **shipped in Phase 8** (`intermed-lab`). | Network exfiltration of reports/dumps from end-user machines, block-evasion tunneling. Operational + privacy-sensitive + distribution burden; out of scope for a local CLI. |

## Principle

Appendix B is a research north star, not a build plan. Each heavy component is
admitted only when a concrete, current-goal need outgrows the simple pure-Rust
path — never preemptively. The two clean extractions worth tracking as **current-goal** backlog were:

1. **Script-engine dynamics sensors** (B.4): KubeJS/CraftTweaker log → facts.
   **Done** — `intermed-dynamics`, see `docs/LAYER-E-DYNAMICS.md`.
2. **Fact-store/rule-engine seam** (B.2): keep storage and logic behind contracts
   so a columnar backend *could* slot in later without touching collectors/rules.
   **Done** — `intermed-duckdb` (`--logic duckdb`) evaluates the relational, log
   and security rules as SQL. Dependency resolution stays **imperative by design**
   (semver range satisfaction is arithmetic, not a relational JOIN) and runs in
   *every* logic mode, so the columnar backend is at functional parity without
   duplicating semver in SQL.

Everything else in Appendix B travels with the runtime, deferred until the
evidence engine is stable.
