# Project status

InterMed 0.1.6-alpha is an alpha static analyzer. Its CLI, schemas, rules, and
reports are usable, but compatibility is not yet promised across every Minecraft
or loader release and machine-facing formats may change before 1.0.

## What has been validated

A fresh 0.1.6 trust-contract pass on 2026-08-17 covered five materialized
Modrinth packs: 1,166 mod archives and 3.01 GiB of JAR content across Minecraft 1.19.2,
1.20.1, and 1.21.1 with Fabric, Forge, and NeoForge. Every run used its original
`.mrpack` as authoritative environment evidence. BMC4 additionally used
`--mixin-level full`, a Minecraft 1.20.1 client jar, and Tiny mappings. All runs
used `--jobs 4`, completed without an operational error, and used the canonical
`intermed-doctor-report-v2` schema. The optional embedded DuckDB backend was not
enabled for this gate. Timings below are warm-cache validation timings; fact and
finding counts are independent of that cache state.

The optional DuckDB build was validated separately with its full crate suite,
CLI persistence E2E tests, and Clippy. A Pixelmon DuckDB smoke run persisted 834
retained facts and 209 findings to a 3.3 MiB database; its semantic findings,
severities, and assessments matched the default columnar report exactly.

| Pack | Target | Archives | Generated / retained / snapshot-dropped facts | Findings (Error / Warn) | Confirmed problems / abstentions | Time | Peak RSS |
|---|---|---:|---:|---:|---:|---:|---:|
| Prominence II | Fabric 1.20.1 | 436 | 1,194,571 / 52,151 / 1,142,420 | 10,755 (1 / 378) | 1 / 63 | 14.4 s | 3,132 MiB |
| Create+ | Forge 1.19.2 | 286 | 407,069 / 22,945 / 384,124 | 5,402 (3 / 309) | 3 / 34 | 3.7 s | 1,645 MiB |
| FOM | NeoForge 1.21.1 | 101 | 163,372 / 12,665 / 150,707 | 3,501 (0 / 268) | 0 / 193 | 5.8 s | 1,271 MiB |
| Pixelmon | NeoForge 1.21.1 | 13 | 150,939 / 834 / 150,105 | 209 (0 / 14) | 0 / 26 | 2.8 s | 640 MiB |
| Better MC Forge BMC4, full Mixin | Forge 1.20.1 | 330 | 808,508 / 29,902 / 778,606 | 7,798 (2 / 475) | 2 / 83 | 8.6 s | 2,533 MiB |

All five reports had zero Error/Fatal findings that violated the typed assessment
contract: every retained hard conclusion was asserted, confirmed, blocker-free,
and backed by its declared coverage prerequisites. Abstentions are visible
findings whose prerequisites were not met; they are not silently discarded
errors. A cached and uncached Pixelmon run also produced the same 209 semantic
finding records, including severity and assessment disposition.

“Snapshot-dropped” means facts removed only after every registered rule finished;
it is not collection-time truncation. Tiny-limit regression fixtures verify that
bounded and unbounded snapshots produce identical finding identities for runtime-
confirmed Mixin failures, performance/Mixin correlation, reflective handler
security correlation, and an external rule consuming a droppable predicate.

This is validation of execution, retention correctness, report integrity, and
known fixtures. It is not a claim that every emitted informational record was
independently confirmed by launching Minecraft.
Precision and recall per rule still require the Compatibility Lab measurement
loop described in the roadmap.

## Supported use

- Static inspection of local servers, launcher instances, mods directories,
  `.mrpack`/zip packs, logs, and crash reports.
- Metadata, dependency, resource, mixin, script, security-preflight, SBOM, and
  imported Spark analysis at the documented depth.
- Terminal, JSON, SARIF, and self-contained HTML reports, with operational
  failures kept separate from domain findings.
- Bounded archive reads, a persistent scan cache, and a configurable worker cap
  for large packs. On a 16 GiB machine, use `--jobs 2` or `--jobs 1` when running
  the deepest analysis of a very large pack.

## Not promised by this alpha

- No pack is launched and no runtime compatibility verdict is proved by a static
  scan alone. Live Compatibility Lab execution remains deferred.
- Security output is a preflight of signatures, identity, and sensitive API
  references; it is not malware certification or full behavioral analysis.
- Mixin apply absence is conclusive only when the relevant complete classpath is
  indexed. Partial coverage is reported as partial rather than promoted to proof.
- No minimum Minecraft or loader version has been declared. Older and unusual
  metadata dialects remain an explicit compatibility frontier.
- InterMed never edits the analyzed pack. Overlay and fix operations are previews
  or writes to a separately requested output location.
- Telemetry is disabled by default. There is no background sender, default
  endpoint, stable installation identifier, or implicit log upload.

The [analysis reference](reference/analysis.md) gives the exact stopping point of
each analyzer. The [roadmap](ROADMAP.md) tracks measurement, triage, evidence-to-
action work, and the remaining product decisions.
