# Schema Conventions (Phase 0)

## The three schemas

| Schema | Type | Owner crate | Versioning |
|---|---|---|---|
| Fact | `intermed_facts::Fact` | `intermed-facts` | Datalog-shaped predicate + named terms |
| Finding | `intermed_evidence::Finding` | `intermed-evidence` | with `EvidenceEdge` provenance |
| Report | `intermed-doctor-report-v1` | `intermed-doctor-core` | `schema` string, bump on breaking change |

## Fact = predicate + named terms (deliberate)

A fact is `kind` (predicate name) + `subject` + named `attributes`. This is a
Datalog tuple in disguise:

```
mod(subject="sodium", version="0.5.3", loader="fabric")
dependency(subject="create", dep="fabric-api", range=">=0.90", mandatory=true)
log_signal(subject="OutOfMemory", line=2, excerpt="...")
resource_writer(subject="modid", path="data/.../tags/items/x.json", archive="mod.jar")
mixin_target(subject="modid", target="net.minecraft.client.render.WorldRenderer", mixin="...")
```

Why this shape:

* **Phase 1** imperative rules match on `kind` and read terms by name.
* **Phase 5** lowers the *same* facts into a Datalog IR / SQL rows with **no
  model change** — `kind` → relation, terms → columns. Per the design doc
  (Appendix Б), the early Datalog backend is DuckDB: facts stream into columnar
  tables and rules become vectorized `JOIN`s.

Predicate names are constants in `intermed_facts::kind`. Add new predicates
there as layers come online; keep collectors and rules referring to the
constants, never raw strings.

## Predicate catalog

Layer A/B/C/D:

* `environment`, `java_runtime`, `target`
* `mod`, `plugin`, `dependency`, `provided_dependency`, `mod_side`,
  `entrypoint`, `nested_jar`, `unparseable_archive`
* `log_signal`, `log_mentions_mod`

Layer E / VFS:

* `resource_writer`
* `resource_collision`
* `json_merge_candidate`
* `safe_crdt_merge`
* `unsafe_replace_conflict`

Layer F / Mixin Intelligence:

* `mixin_config`
* `mixin_class`
* `mixin_target`
* `mixin_operation`
* `mixin_hotspot`
* `mixin_overlap`
* `high_risk_overwrite`
* `log_mixin_correlation`

Layer J / Rule Packs:

* Rule packs use `intermed-rule-pack-v1`.
* The in-process Datalog-compatible backend reads the same `Fact` stream as
  imperative rules.
* The optional Souffle backend materializes selected facts as `.facts`, executes
  a generated `.dl` program with `souffle -F ... -D ...`, and maps output
  relations back to normal `Finding`s.

## Provenance is mandatory

Every `Fact` carries a `SourceRef` (file / line / inner path) and a
`confidence`. Every `Finding` carries `EvidenceEdge`s pointing back at the facts
that justify it. This is what makes the Phase-2 `--explain <finding>` and
`--dump-facts` possible without re-running anything — and why InterMed never
prints an unsourced verdict.

## Output formats

* **Terminal** — human, ANSI optional, no colour crate (cold-start discipline).
* **JSON** — the `DoctorReport` verbatim (`--json`).
* **SARIF 2.1.0** — findings as results, distinct `rule_id`s as rules (`--sarif`),
  for IDE / CI code-scanning.

## Single source of truth (answers Appendix Б critique #3)

Appendix Б warns that DuckDB table schema, FlatBuffers IPC, and Rust models can
drift and cause segfaults. The discipline that prevents it: **the Rust `serde`
type is the source of truth.** When DuckDB (Phase 5) and any JVM-worker IPC
(Phase 4/6, if ever needed) arrive, their schemas must be *generated from* the
Rust types, never hand-maintained in parallel. Until then there is exactly one
definition per schema, in the owner crate above.
