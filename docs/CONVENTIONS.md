# Coding Conventions (Phase 0)

These exist to stop the one failure mode that kills a Java→Rust port:
**transliterating OOP**. The legacy code is class hierarchies, `null`, and
exceptions. Rust wants data, enums, and `Result`. Port the *behavior*, not the
shape.

## Architecture seam (do not break)

```
Target ──▶ [Collectors] ──▶ FactStore ──▶ [Rules] ──▶ Findings ──▶ DoctorReport
```

* **Collectors observe, rules infer.** A `Collector` only writes facts; it never
  produces findings and never reads another collector's output. A `Rule` only
  reads facts and emits findings. Keeping these pure is what makes a new layer a
  drop-in (one `Collector` impl + one registration line in the CLI).
* **The engine knows nothing concrete.** `intermed-doctor-core` has no idea what
  Minecraft, a log, or a dependency is. The CLI (composition root) is the only
  place that wires concrete collectors/rules in.
* **Read-only on the target.** Diagnosis never mutates the thing it inspects.
  Mutation lives in `intermed-packops` behind explicit subcommands.

## Crate layering (acyclic)

```
facts ◀ evidence ◀ doctor-core ◀ {collector & rule crates} ◀ cli
                        ▲
                     report (renders core's DoctorReport)
```

Collector/rule crates depend only on `intermed-doctor-core` (which re-exports
`facts` and `evidence`). Never add an edge that points back toward the leaves.

## Rust style

* **Errors:** `Result` + `thiserror` for libraries, `anyhow` only in the binary.
  Never `panic!`/`unwrap()` on input-derived data. Collectors degrade to fewer
  facts; they do not abort the run.
* **No inheritance ports.** A Java base class becomes either a `trait` (behavior)
  or a plain `struct`/`enum` (data) — decide per case, never both.
* **Data is data.** `Fact`, `Finding`, `DoctorReport` are plain `serde` types
  with no logic beyond builders/accessors.
* **`Option`, not null.** Every uncertain attribute is `Option<_>`; absence is
  normal (Phase 1 fills what it can detect).
* **No `&'static str` enums where vocabulary must be open.** Fact `kind`s are
  strings (with constants in `facts::kind`) so out-of-tree rule packs can add
  predicates without recompiling core.
* **Keep cold start cheap.** `doctor latest.log` must not pay for mod scanning.
  Collectors gate on `applies(target)`; don't pull heavy deps into the hot path.

## Quality gates (must pass before commit)

```
cargo fmt --all
cargo clippy --all-targets   # zero warnings
cargo test
```
