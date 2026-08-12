# Project status

InterMed 0.1.4-alpha is an alpha static analyzer. Its CLI, schemas, rules, and
reports are usable, but compatibility is not yet promised across every Minecraft
or loader release and machine-facing formats may change before 1.0.

## What has been validated

The August 2026 corpus run covered 12 complete Modrinth packs: 2,289 declared
artifacts (5.6 GB materialized), Minecraft 1.12.2, 1.19.2, 1.20.1, and 1.21.1,
and Fabric, Forge, and NeoForge packs. The bounded static analysis completed for
all 12 packs without an operational error; the largest observed peak was about
3.2 GiB RSS with a restricted worker count. Unit, integration, backend-parity,
negative-fixture, archive-boundary, and CLI end-to-end tests cover the contracts
used by that run.

This is validation of execution, resource bounds, report integrity, and known
fixtures. It is not a claim that every one of the 60,690 corpus findings was
independently confirmed by launching Minecraft. Precision and recall per rule
still require the Compatibility Lab measurement loop described in the roadmap.

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
