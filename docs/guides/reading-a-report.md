# Reading a report

A `doctor` report has three parts: a header, the findings, and a summary line.

```
InterMed Doctor v0.1.2-alpha
Target: ./mods (mods directory)
Env:    loader=fabric  mc=1.20.1  java=21

ERROR Missing dependency: cloth-config
      bewitchment requires cloth-config (*), but it is not installed.
      → Install cloth-config, or remove bewitchment.

NOTE  iris pins sodium to one version
      iris requires sodium 0.5.x exactly. Any other build is reported incompatible.
      affects: iris, sodium

WARNINGS  1 actionable, 10 informational  (0 fatal, 1 error, 0 warn, 10 note · 1073 facts)
```

## The header

`Env:` is what InterMed detected. For a server or instance it reads the loader
and Minecraft version from the installation. For a bare mods directory there is
no installation to read, so it infers them from the mods themselves and marks
them `(inferred)`. Inference takes the loader the mods agree on and the Minecraft
version their dependency ranges point to.

## Severities

Every finding has one of five severities.

| Severity | Meaning |
|----------|---------|
| `fatal`  | The pack cannot load as-is. |
| `error`  | A real problem: a missing dependency, a hard mixin apply failure. |
| `warn`   | Worth attention: an `@Overwrite`, an order-dependent merge, a version pin. |
| `note`   | Context, usually benign: a safe tag merge, a mod-gated optional reference. |
| `info`   | Background detail, shown only when you ask for it. |

The first three — `fatal`, `error`, `warn` — are **actionable**. `note` and
`info` are **informational**.

## The summary line

```
WARNINGS  1 actionable, 10 informational  (0 fatal, 1 error, 0 warn, 10 note · 1073 facts)
```

- The verdict word: `HEALTHY`, `WARNINGS`, or `PROBLEMS`.
- `actionable` vs. `informational` — the signal/noise split. A large `total`
  usually means many safe merges or per-handler notes, not many problems; the
  `actionable` count is what needs a decision.
- The per-severity breakdown and the number of facts the run produced.

## Finding groups

Findings of the same kind are grouped. A pack with two hundred safe tag merges
prints one line — `Resource can be merged safely · 200 findings` — not two
hundred. The terminal and HTML reports both group; the JSON keeps the flat list
so tools can group their own way.

## Explaining one finding

Every finding has an `id` (visible in JSON, or with `-v`). Pass it to `--explain`
to see exactly where the finding came from:

```bash
intermed doctor ./mods --explain "missing-dependency:bewitchment->cloth-config"
```

```
ERROR Missing dependency: cloth-config
id: missing-dependency:bewitchment->cloth-config
rule: dependency

bewitchment requires cloth-config (*), but it is not installed.

Fix candidates:
- Install cloth-config matching *.

Evidence:
- f7 Subject weight=1.00: dependency subject=bewitchment
  attrs: {"dep":"cloth-config","mandatory":true,"range":"*","relation":"depends"}
  source: bewitchment-1.20-10.jar!fabric.mod.json  extractor=metadata-scanner
```

The `Evidence` block is the chain of facts behind the finding. Each line names
the fact, its attributes, and its `source` — the jar and the file inside it that
the fact was read from. For mixin and some other findings, `--explain` also
prints fix recommendations with code examples.

If the id does not match, `--explain` lists the closest ids it does have.

## Partial and deferred analysis

Not every analysis runs on every command. Opt-in ones — mixins (`--mixin-risk`),
performance (`--performance --spark-report`) — are listed under `deferred_layers` in
the JSON report when they did not run, so a clean-looking report is never mistaken
for a complete one.

A run can also be *partial* for a reason it could not control — a jar it could not
read, a modpack manifest whose jars are not on disk. When that happens the report
adds a caveat and is conservative about its verdict rather than presenting an
incomplete scan as healthy. The fix is usually to point `doctor` at a fully
materialized target (install the pack first).

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Healthy — no warnings or errors. |
| `1`  | Warnings only. |
| `2`  | Errors or worse. |

Use `--exit-zero` to always exit `0` when the run completes — handy when you only
want the side effect of writing a `--json` / `--sarif` / `--html` artifact and a
non-zero exit would otherwise fail the step. With it, a non-zero exit means a real
operational failure (a bad target, an unwritable output path), not a finding.

For gating a CI build on this, see [Using InterMed in CI](ci.md).
