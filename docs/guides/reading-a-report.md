# Reading a report

A `doctor` report has three parts: a header, the findings, and a summary line.

```
InterMed Doctor v0.1.7-alpha · intermed-doctor-report-v2
Target: ./mods (mods directory)
Env:    loader=fabric  mc=1.20.1  java=21

WARN  Missing dependency could not be confirmed: cloth-config
      Provider coverage is partial, so InterMed abstained from an absence claim.
      trust: disposition=Abstained certainty=Undecidable

NOTE  iris pins sodium to one version
      iris requires sodium 0.5.x exactly. Any other build is reported incompatible.
      affects: iris, sodium

Status: 0 confirmed · 1 review · 1 incomplete · 10 context
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
| `fatal`  | A terminal runtime/startup failure backed by terminality evidence. |
| `error`  | A strong problem whose declared proof and coverage prerequisites are satisfied. |
| `warn`   | Worth attention: an `@Overwrite`, an order-dependent merge, a version pin. |
| `note`   | Context, usually benign: a safe tag merge, a mod-gated optional reference. |
| `info`   | Background detail, shown only when you ask for it. |

Severity describes impact and presentation. Trust is a separate contract:
`assessment.disposition` says whether the candidate was asserted, downgraded,
or abstained; `certainty`, `proof_kind`, `coverage`, and `blockers` explain why.
An unmet prerequisite cannot remain Error/Fatal.

## The summary line

```
Status: 0 confirmed · 1 review · 1 incomplete · 10 context
```

- `confirmed` counts asserted Error/Fatal conclusions with confirmed certainty.
- `review` counts default-surface warnings needing a decision.
- `incomplete` counts findings or collectors whose prerequisites/coverage were
  partial or unavailable.
- `context` counts default-surface Note/Info records. Raw verbose and explain-only
  detail is reported separately.

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

Trust: asserted · startup-blocking · confirmed
Proof: deterministic-derivation
Prerequisites: complete-pack ✓, complete-provider-universe ✓,
               active-descriptor ✓

Fix candidates:
- Install cloth-config matching *.

Evidence:
- f7 Subject weight=1.00: dependency subject=bewitchment
  attrs: {"dep":"cloth-config","mandatory":true,"range":"*","relation":"depends"}
  source: bewitchment-1.20-10.jar!fabric.mod.json  extractor=metadata-scanner
```

The trust block appears before the evidence and lists the proposed impact, proof
kind, evaluated prerequisites, and any `why_not_error` blockers. The `Evidence`
block is the chain of facts behind the finding. Each line names
the fact, its attributes, and its `source` — the jar and the file inside it that
the fact was read from. For mixin and some other findings, `--explain` also
prints fix recommendations with code examples.

If the id does not match, `--explain` lists the closest ids it does have.

## Partial and deferred analysis

Not every analysis runs on every command. Opt-in ones — mixins (`--mixin-level basic|standard|full`, with `--mixin-risk` as a standard-level alias),
performance (`--performance --spark-report`) — are recorded in
the collector list and `target_capabilities` as `disabled`, `skipped`, `active`,
`incomplete`, `complete`, `partial`, or `unavailable`, with a reason.
`deferred_layers` is reserved for genuinely
unimplemented analysis, so a clean-looking report is never mistaken for a complete one.

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
