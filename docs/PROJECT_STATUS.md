# Project status

InterMed 0.1.5-alpha is an alpha static analyzer. Its CLI, schemas, rules, and
reports are usable, but compatibility is not yet promised across every Minecraft
or loader release and machine-facing formats may change before 1.0.

## What has been validated

A fresh 0.1.5 release-candidate pass on 2026-08-14 covered five materialized
Modrinth packs: 1,166 mod archives and 4.01 GiB on disk across Minecraft 1.19.2,
1.20.1, and 1.21.1 with Fabric, Forge, and NeoForge. Every run used its original
`.mrpack` as authoritative environment evidence. BMC4 additionally used
`--mixin-level full`, a Minecraft 1.20.1 client jar, Tiny mappings, and `--jobs 2`.
The other runs used `--jobs 4`. All five completed without an operational error.

| Pack | Target | Archives | Generated / retained / snapshot-dropped facts | Findings (Error / Warn) | Time | Peak RSS |
|---|---|---:|---:|---:|---:|---:|
| Prominence II | Fabric 1.20.1 | 436 | 520,613 / 13,848 / 506,765 | 1,925 (1 / 65) | 37 s | 1,311 MiB |
| Create+ | Forge 1.19.2 | 286 | 166,477 / 7,330 / 159,147 | 861 (5 / 44) | 19 s | 566 MiB |
| FOM | NeoForge 1.21.1 | 101 | 62,496 / 2,239 / 60,257 | 277 (0 / 28) | 16 s | 394 MiB |
| Pixelmon | NeoForge 1.21.1 | 13 | 83,691 / 296 / 83,395 | 34 (0 / 9) | 33 s | 332 MiB |
| Better MC Forge BMC4, full Mixin | Forge 1.20.1 | 330 | 383,613 / 29,486 / 354,127 | 7,865 (8 / 493) | 43 s | 1,801 MiB |

“Snapshot-dropped” means facts removed only after every registered rule finished;
it is not collection-time truncation. Tiny-limit regression fixtures verify that
bounded and unbounded snapshots produce identical finding identities for runtime-
confirmed Mixin failures, performance/Mixin correlation, reflective handler
security correlation, and an external rule consuming a droppable predicate.

This is validation of execution, retention correctness, report integrity, and
known fixtures. It is not a claim that every one of the 10,962 findings was
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
