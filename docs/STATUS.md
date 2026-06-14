# InterMed — live implementation status

This is the **authoritative feature map** for what the codebase does *today*.
Phase milestones live in [ROADMAP.md](ROADMAP.md); per-layer deep dives in
`LAYER-*.md`. When code and docs disagree, **code wins** — update this file when
behavior changes.

Last aligned with: mixin-intel `CACHE_VERSION` **`-r22`**, vfs **`-r2`**, minecraft-scan
**`-r11`**, sbom `CACHE_VERSION` **`-r3`**, security `CACHE_VERSION` **`-r2`**.
Audit remediation (2026-06-13): see [AUDIT-REAL-RUNS.md § Resolution log](AUDIT-REAL-RUNS.md#resolution-log--audit-remediation-2026-06-13).

## How to read the table

| Column | Meaning |
|--------|---------|
| **Capabilities** | Shipped and tested in-tree |
| **Missing / deferred** | Not implemented, stubbed, or intentionally out of scope |
| **Docs** | Layer design note (if any) |
| **Code** | Primary crate / entry points |

---

## Layer status

| Layer | Name | State | Capabilities | Missing / deferred | Docs | Code |
|-------|------|-------|--------------|-------------------|------|------|
| **A** | Target detection | ✅ active | Prism/MultiMC/`.minecraft`/CurseForge/Modrinth layouts; BFS `mods/` discovery; `instance_type` (server/client/integrated); loader + host launcher metadata | Remote launcher DB sync | — | [`intermed-doctor-core`](../crates/intermed-doctor-core/src/instance_layout.rs), [`intermed-minecraft-scan`](../crates/intermed-minecraft-scan/src/env.rs) |
| **B** | Metadata | ✅ active | Rich `mod_metadata`; entrypoint details/events; capabilities; relationships; Fabric / Quilt / Forge / NeoForge manifests; Forge multi-mod + `@Mod`; AT/AW; coremods; `--metadata-level` | Exact method-level entrypoint semantics and calibrated capability corpus | [LAYER-B-METADATA](LAYER-B-METADATA.md) | [`intermed-minecraft-scan`](../crates/intermed-minecraft-scan/) |
| **C** | Dependencies | ✅ active | Pairwise semver (`breaks`/`discouraged`/`recommends`); **load-order cycle/conflict** rules; **PubGrub** global unsat + **actionable summaries**; `intermed deps graph/resolve`; `provides` aliases | Version *selection* from remote catalogs (PackOps solver) | [LAYER-C-DEPENDENCIES](LAYER-C-DEPENDENCIES.md) | [`intermed-deps`](../crates/intermed-deps/) |
| **D** | Log / crash | ✅ active | Semantic stack traces; root-cause exception; weighted `log_mod_error`; metadata-enriched `log_mentions_mod`; modern mod patterns; D3 Spark correlation | Frame-to-jar ownership and calibrated blame corpus | [LAYER-D-LOG](LAYER-D-LOG.md) | [`intermed-log`](../crates/intermed-log/) |
| **E** | Resource / VFS | ✅ active | `assets/**`, `data/**`, `pack.mcmeta` scan; **lang JSON/`.lang` merge + format-mismatch**; tag merge with **`replace: true`**; script dynamics (**KubeJS/CT/GroovyScript/Rhino**; recipe/item/**loot/tag** removal facts); overlay preview | Live transactional VFS (Appendix B runtime) | [LAYER-E-DYNAMICS](LAYER-E-DYNAMICS.md) | [`intermed-vfs`](../crates/intermed-vfs/), [`intermed-packops`](../crates/intermed-packops/), [`intermed-dynamics`](../crates/intermed-dynamics/) |
| **M** | Data semantics (AST) | 🧪 experimental | Typed resource AST over Layer E; **`--resource-level`** (`basic`/`semantic`/`full`); parallel jar scan via shared cache; **recipe output override** + **lang key conflict** findings; **implicit dependency candidates** → Layer C; **`vfs explain --ast`**; overlay plan v2 (`--explain-plan`) | Dangling-ref findings (reserved); Stage-6 interpreted dependency facts; advancements/predicates/worldgen parsers | [LAYER-M-DATA-SEMANTICS](LAYER-M-DATA-SEMANTICS.md) | [`intermed-resource-ast`](../crates/intermed-resource-ast/) |
| **F** | Mixin intelligence | ✅ active | **Unified config discovery**; **MixinExtras** (`ModifyReturnValue`, `ModifyReceiver`, …); refmap + Tiny v2; flow-sensitive dataflow; **`--mixin-level`** noise control; composite risk (**hot-path + Spark boost**); recommendations with **code examples + doc links**; Complexity + Bloat; `mixin-map` HTML graph | Runtime mixin apply simulation; MC class hierarchy when targets absent | [LAYER-F-MIXIN](LAYER-F-MIXIN.md) | [`intermed-mixin-intel`](../crates/intermed-mixin-intel/) |
| **G** | Security audit | ✅ active | **MethodHandles** + expanded native/dynamic APIs; per-signal **`affected_classes`**; graded finding **`confidence`**; structural + reflection-corroborated collapse | Runtime enforcement / hooks; `writes_files` (too noisy) | [LAYER-G-SECURITY](LAYER-G-SECURITY.md) | [`intermed-security-audit`](../crates/intermed-security-audit/) |
| **H** | SBOM / provenance | ✅ active | **`platform-listed`** source class (Modrinth/CurseForge); **certified** JAR signing; **`corpus.lock`** boost; expanded trust score; cross-layer correlation with G | Ed25519 `.imod` packaging verify; live Modrinth download stats | [LAYER-H-SBOM](LAYER-H-SBOM.md) | [`intermed-sbom`](../crates/intermed-sbom/) |
| **I** | Performance (Spark) | ✅ active | **`perf-tick-mixin-hotpath`**; **`perf-hot-mod-resource`**; **`perf-hot-method-log`**; **`performance-heuristic-fallback`** when Spark absent | Live JVM attach / Spark execution | [LAYER-I-SPARK](LAYER-I-SPARK.md) | [`intermed-spark-bridge`](../crates/intermed-spark-bridge/) |
| **J** | Rules engine | ✅ active | Imperative rules; Datalog rule-pack; optional Souffle; optional DuckDB; **doctor merges installed/community packs**; `rules update` over `https://` | WASM plugin microkernel | [RULE-PACKS](RULE-PACKS.md), [ROADMAP](ROADMAP.md) § Phase 5 | [`intermed-rules`](../crates/intermed-rules/), [`intermed-duckdb`](../crates/intermed-duckdb/) |
| **K** | Compatibility lab | ✅ offline path | `lab discover` / `run` / `report` / `eval`; corpus lock digest; captured-log `SmokeRunner`; matrix + HTML; rule accuracy v2 | **Live runner structurally deferred**: `ServerProcessRunner`, loader installers, networked `CandidateProvider` | [LAYER-K-LAB](LAYER-K-LAB.md) | [`intermed-lab`](../crates/intermed-lab/) |
| **L** | Runtime preflight | ⏸ deferred | Registered `DeferredCollector`; visible in reports | Enforcement bridge (~1 year hold) | [ROADMAP](ROADMAP.md) § Phase 9 | [`intermed-runtime-preflight`](../crates/intermed-runtime-preflight/) |

---

## Cross-cutting infrastructure

| Feature | Status | Code |
|---------|--------|------|
| Fact store + `--dump-facts` / `--explain` | ✅ | [`intermed-doctor-core`](../crates/intermed-doctor-core/) |
| Jar scan cache — content-addressable (SHA-256), 3-tier (memory → disk → remote `RemoteCacheTier`/`--cache-remote-dir`), LRU-promote prune (hot mods kept longer), per-collector `CACHE_VERSION` | ✅ | [`jar_cache`](../crates/intermed-doctor-core/src/jar_cache/) |
| Evidence graph on findings | ✅ | [`intermed-evidence`](../crates/intermed-evidence/) |
| Report v1 / SARIF | ✅ | [`intermed-report`](../crates/intermed-report/) |
| Interactive HTML report (tabs, severity/category filters, clickable provenance, mixin heatmap; self-contained) | ✅ | [`intermed-report`](../crates/intermed-report/src/html.rs) |
| Output UX: `--exit-zero`, fuzzy `--explain`, `--quiet`/`-v`, `--logic` rule provenance | ✅ | [`intermed-cli`](../crates/intermed-cli/) |
| DuckDB analytics: `risk_patterns` / `historical_conflicts` views, `history conflicts`/`patterns`, `trends` | ✅ (`--features duckdb`) | [`intermed-duckdb`](../crates/intermed-duckdb/) |
| Fact vocabulary | ✅ | [`intermed-facts`](../crates/intermed-facts/), [SCHEMA](SCHEMA.md) |

---

## Notable cross-layer joins (implemented)

| Join | Layers | Rule / surface |
|------|--------|----------------|
| Spark hot method ↔ mixin **target** class | I + F | `performance-correlation` |
| Mixin risk ↔ Spark CPU boost | I + F | `mixin-risk` |
| Low trust jar ↔ high-risk API usage | H + G | `sbom-security-correlation` |
| Crash-trace mod mention ↔ installed mod | D + B | `log-signal` (`log-mentions-mod:*`) |
| CPU hotspot mod ↔ crash-trace mention | I + D | `performance` (`perf-log-suspect:*`) |
| Mod capabilities ↔ mixin risk on a target | B + F | `mixin-risk` (capability context + evidence) |
| Lab ground truth ↔ Doctor predictions | K + * | `lab eval` → `intermed-rule-accuracy-v2` |
| Recipe serializer namespace ↔ installed mod | M + C | `implicit-dependency-missing` |
| Recipe output override ↔ overlay review bucket | M + E | `vfs overlay --explain-plan` |

---

## Documentation map

| Audience | Start here |
|----------|------------|
| New users | [CONCEPTS.md](CONCEPTS.md) → [EXAMPLES.md](EXAMPLES.md) |
| Contributors | [CONVENTIONS.md](CONVENTIONS.md) → [SCHEMA.md](SCHEMA.md) → this file |
| Phase history | [ROADMAP.md](ROADMAP.md), `CL-PHASE-*.md`, [CL-LAYER-M.md](CL-LAYER-M.md) |
| Resource semantics | [LAYER-M-DATA-SEMANTICS.md](LAYER-M-DATA-SEMANTICS.md) → [RESOURCE-AST.md](RESOURCE-AST.md), [SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md) |
| Java port reference | [donor-inventory.md](donor-inventory.md) |

---

## Maintenance rule

When you ship a layer feature:

1. Bump the collector's `CACHE_VERSION` if scan output changes.
2. Update [SCHEMA.md](SCHEMA.md) if fact kinds or attrs change.
3. Update the matching `LAYER-*.md` (and [SCHEMA-RESOURCE-FACTS.md](SCHEMA-RESOURCE-FACTS.md) for Layer M) and **this file**.
4. Add or refresh a golden / integration test where CLI output is stable.
