# Project status

InterMed 0.1.7-alpha is an alpha static analyzer. Its CLI, schemas, rules, and
reports are usable, but compatibility is not yet promised across every Minecraft
or loader release and machine-facing formats may change before 1.0.

## What has been validated

A fresh 0.1.7 coherent-evidence pass on 2026-08-18 covered five materially
different real targets across Forge and NeoForge 1.20.1/1.21.1. Pixelmon and
Cobblemon exercise pack identity and compatibility bridges; Better MC Forge
BMC4 exercises a large full-Mixin corpus; Cave Horror exercises KubeJS discovery
and resource-mutator completeness; Spaceholecraft combines 397 canonical
artifacts with a real terminal runtime incident. BMC4 and Spaceholecraft were
supplied Minecraft client jars and Tiny mappings. Their client jars were
official-obfuscated while the available Tiny files described intermediary to
Yarn named symbols, so absence verification correctly remained unavailable
instead of comparing incompatible namespaces.

Every report used `intermed-doctor-report-v2`, had unique finding IDs, and
completed with zero operational errors. Runs used `--jobs 2`; DuckDB support was
not enabled or compiled as part of this gate. The final Pixelmon audit used full
metadata and resource depth and was repeated with and without the cache: finding
IDs, semantic IDs, assessments, fact counts, and graph cardinalities were
identical. Timings include cold or partially warm cache work and are therefore
measurements of these invocations, not cross-machine benchmarks.

| Pack | Target evidence | Canonical artifacts | Generated / retained / snapshot-dropped facts | Findings (Error / Warn) | Abstentions | Time | Peak RSS |
|---|---|---:|---:|---:|---:|---:|---:|
| Pixelmon, full metadata/resources | authoritative NeoForge 1.21.1 manifest | 15 | 158,842 / 10,378 / 148,464 | 35 (0 / 11) | 26 | 36.9 s | 346 MiB |
| Cobblemon | authoritative NeoForge 1.21.1 manifest + Connector evidence | 137 | 61,994 / 11,708 / 50,286 | 116 (0 / 19) | 84 | 48.1 s | 356 MiB |
| Spaceholecraft | NeoForge 1.21.1 runtime log | 397 | 676,661 / 90,285 / 586,376 | 11,839 (191 / 556) | 68 | 246.7 s | 2,705 MiB |
| Better MC Forge BMC4 | authoritative Forge 1.20.1 manifest, full Mixin | 536 | 412,100 / 46,458 / 365,642 | 9,112 (2 / 498) | 53 | 211.0 s | 2,250 MiB |
| Cave Horror | authoritative Forge 1.20.1 manifest + KubeJS | 181 | 189,203 / 23,497 / 165,706 | 3,336 (1 / 147) | 3 | 76.3 s | 1,206 MiB |

Spaceholecraft's primary terminal incident resolves to the deepest
`IllegalStateException` (`GL error off-thread`, GLFW 65539), not its outer
`ReportedException`. The evidence path records
`createdieselgenerators.EntityFilterItem.appendHoverText` calling
`create.AllKeys.isKeyDown`; target Java is taken from the log as
`21.0.7+6-LTS`, not from the analyzer host. Cave Horror's KubeJS tree is reported
as a runtime mutator, so affected static resource conclusions carry mutator
coverage rather than claiming final runtime state.

All retained Error/Fatal findings in these reports satisfy the typed assessment
contract: each is asserted, confirmed, blocker-free, and backed by its declared
coverage prerequisites. Abstentions remain visible structured conclusions; they
are not silently discarded errors. Evidence paths are bounded to 256 links per
finding while the normalized evidence graph retains the complete relationship
set within its declared graph budgets.

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
