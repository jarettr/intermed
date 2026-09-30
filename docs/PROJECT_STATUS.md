# Project status

InterMed 0.2.0-alpha is an alpha static analyzer with a typed trust contract,
canonical cross-layer entity identities, and an operational Compatibility Lab.
Every strong conclusion declares its evidence and coverage prerequisites. When
those prerequisites are unavailable or contradictory, the report downgrades or
abstains instead of presenting an unsupported Error/Fatal conclusion.

The CLI, report schemas, corpus locks, resumable campaigns, bounded runtime-log
normalization, and static-analysis pipeline are usable. Compatibility is not
promised for every Minecraft or loader release, and machine-facing formats may
still change before 1.0.

## 0.2.0 real-pack measurement gate

The 0.2.0 gate reran the exact 101-pack corpus used for 0.1.9: 77 Fabric,
18 Forge, 4 NeoForge, and 2 Quilt instances spanning Minecraft 1.7.10 through
26.2. The authoritative case-list SHA-256 is
`453620d2343c0bd69eb48b510e86b9c07d19be3a2e688f4676d0d1a3640f73eb`.

Layer K verified all 56,448 locked files (23,844,535,832 bytes) before Doctor
ran. No required or optional file was absent. All reports were produced by one
0.2.0-alpha executable (SHA-256
`3f7fa37ac0235fe77572af6e6d4497ba140ac1009d7fdfff09285f9dd644c2d6`)
and one effective rule pack (SHA-256
`a20b7bb8b5d18f28604340ae65015037e21430ee5ba6bf5151fbfea9a1831899`).

| Measurement | Result |
|---|---:|
| Materialized packs / reports | 101 / 101 |
| Infrastructure / harness / operational failures | 0 / 0 / 0 |
| Locked files verified | 56,448 |
| Bytes re-hashed before analysis | 23,844,535,832 |
| Raw findings | 66,632 |
| Confirmed problems | 18 |
| Needs review | 712 |
| Incomplete analysis | 85 |
| Context / hidden detail | 4,500 / 61,343 |
| Facts generated / retained / compacted | 7,339,415 / 1,797,160 / 5,542,255 |
| Aggregate Doctor time | 727.546 s |
| Maximum per-run peak RSS | 3,317,592,064 bytes (3.09 GiB) |
| Final cache logical bytes / files | 435,583,084 / 40,985 |

The 18 hard conclusions were manually checked against descriptor, artifact, and
runtime evidence. They comprise seven duplicate active mod IDs, six exact
version/incompatibility conclusions, two absent required providers, and three
terminal Forge mod-loading incidents from a supplied crash report. Every hard
conclusion is `asserted` and `confirmed`, with no assessment blocker. The sorted
hard-finding IDs are unchanged from the final 0.1.9 corpus run.

The 85 incomplete items are explicit rather than inferred from global scan
state: 59 conclusions carry typed blockers or partial coverage, 24 packs reached
a relevant Resource AST bound, one metadata descriptor declares a missing
access-transformer file, and one VFS scan reached its resource-entry limit.
Unrelated oversized media does not make metadata analysis incomplete.

Mixin analysis was active at `basic` depth in all 101 packs. No Minecraft jar or
compatible mappings were supplied. Target/method absence therefore cannot
become a hard conclusion. Undecidable site-level apply hypotheses remain in
JSON/Explain and the coverage passport, but do not flood the default surface.
The final visibility-only triage changed 8,124 records without changing any of
the 66,632 semantic finding payloads.

The table and methodology above are the committed, release-facing numerical
summary. The raw packs and per-case reports are intentionally not committed:
they are large third-party artifacts. Reproduction is anchored by the case-list,
binary, rule-pack, and input hashes recorded here rather than by a machine-local
filesystem path.

## Coherent evidence graph

The 0.2 line uses shared identities for artifacts, mod instances, classes,
methods, resources, runtime events, throwable nodes, dependencies, and Mixin
sites. Physical artifact identity is content-addressed; paths are locators, not
join keys. Method identities include descriptors so overloads cannot silently
merge.

Before report assembly, the coherence pass can refine or contradict a proposed
conclusion. Examples include a runtime frame refuting static class absence, an
exact code/runtime use refuting `declared-but-unused`, a nested active provider
refuting dependency absence, and runtime loader evidence refining an otherwise
unknown static environment. Adjustments are retained in the assessment rather
than silently rewriting severity.

Runtime logs are normalized into structured events, throwable chains, stack
frames, crash anchors, and physical occurrence IDs. Semantic fingerprints group
equivalent failures without merging separate occurrences or their source
locations. Host Java remains in `analysis_environment`; compatibility verdicts
use only target-derived runtime evidence.

## Supported use

- Static inspection of local servers, launcher instances, mods directories,
  `.mrpack`/zip packs, logs, and crash reports.
- Metadata, dependency, resource, Mixin, script, security-preflight, SBOM, and
  imported Spark analysis at the documented depth.
- Loader-specific dependency dialects for Fabric/Quilt and Forge/NeoForge,
  conservative unknown-version handling, nested providers, and typed bridge
  capabilities.
- Terminal, JSON, SARIF, and self-contained HTML reports with typed assessment,
  evidence paths, target capabilities, collector completeness, and analyzer
  fingerprinting.
- Content-addressed corpus locks and materialization, target verification,
  resumable bounded-parallel campaigns, captured runtime observations, explicit
  sandbox plans, accuracy reports, and mismatch clustering.
- Bounded archive/log reads, content-verified persistent scan caches, and
  post-rule semantics-preserving fact compaction.

## Not promised by this alpha

- `doctor` never launches Minecraft. Layer-K execution requires an explicit
  command and sandbox policy; loader installation and network acquisition are
  separate inputs.
- A static-only campaign does not produce runtime precision/recall. A zero
  runtime false-positive counter without runtime labels is not an accuracy
  measurement.
- Security output is structural preflight evidence, not malware certification
  or full behavioral analysis.
- Mixin apply absence is conclusive only with the relevant complete classpath,
  compatible namespace/mappings, active side, and exact selector/signature
  coverage.
- Static resource state may be changed by scripts, Mixins, or custom loaders;
  conclusions are gated when mutator coverage is partial.
- No minimum Minecraft or loader version has been declared. Older and unusual
  metadata dialects remain a compatibility frontier.
- InterMed never edits the analyzed pack. Overlay and fix operations write only
  to an explicitly requested separate output.
- Telemetry is disabled by default. There is no background sender, default
  endpoint, stable installation identifier, or implicit log upload.
- A clean report means only that no supported problem was found in inspected
  evidence; it is not a guarantee that the pack will start or remain stable.

The [analysis reference](reference/analysis.md) defines the exact stopping point
of each analyzer. The [roadmap](ROADMAP.md) tracks remaining acquisition,
runtime-coverage, measurement, evidence-to-action, and product work.
