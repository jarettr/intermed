# Schema and migration policy

InterMed's machine-facing formats are versioned independently. A schema name is
part of the data, not an implied property of the executable version.

## Doctor reports

`intermed-doctor-report-v2` is the canonical output from 0.1.6. In 0.1.7 it gains
additive evidence-graph, incident, shared-recommendation, semantic identity, and
evidence-path fields. It already permits unknown optional fields, so these do
not require a v3 schema name. The v1 reader remains supported,
and `doctor --report-schema v1` remains a temporary lossy compatibility writer
during the alpha series. V1 cannot preserve assessment prerequisites, blockers, adjustments, or
target-capability coverage.

An additive optional field is compatible within one schema. Removing a field,
changing its type or meaning, changing enum semantics, or making an optional
field mandatory is breaking and requires a new schema name. Readers must ignore
unknown optional fields and must not infer a strong conclusion from an absent v2
assessment.

## Rule packs

`intermed-rule-pack-v3` is canonical from 0.1.6. From 0.1.7 every rule proposing
Error or Fatal must also declare a typed `conclusion_kind`, in addition to its
impact, proof kind, coverage prerequisites, and behavior
when a prerequisite is missing. V1 loading has been removed. V2 remains a
migration-read-only format; its Error/Fatal output is capped at Warn with a structured
`legacy-rule-pack-has-no-proof-contract` blocker. Local, remote, signed, and
unsigned packs all pass through this policy; a signature authenticates bytes but
does not grant permission to bypass the trust contract.

## Analyzer cache

A persistent collector payload is valid only when all of these identities match:

- input SHA-256 content identity;
- collector logic version;
- effective settings fingerprint;
- emitted fact/schema version;
- mapping identity, when the collector consumes mappings.

Filesystem metadata may accelerate lookup, but never proves content identity.
There is no best-effort migration of an incompatible collector payload: it is
invalidated and regenerated.

Mapping-derived payload identity includes the mapping source, mapping-file hash,
Minecraft version, source namespace, target namespace, and parser version.

## Compatibility Lab

0.1.8 introduces independently versioned Layer-K artifacts:

- `intermed-lab-campaign-v1` — immutable campaign plan;
- `intermed-lab-campaign-state-v1` — resumable case state;
- `intermed-execution-observation-v1` — structured runtime evidence;
- `intermed-lab-materialization-v1` — content-addressed instance manifest;
- `intermed-lab-campaign-report-v1` — campaign metrics and triage summary;
- `intermed-lab-triage-v1` — semantic mismatch clusters.

Campaign identity includes its expected corpus digests, one common analyzer
fingerprint, case-local Doctor fingerprint expectations, and execution/static
plans. The analyzer fingerprint covers the executable SHA-256, InterMed version,
Git/build state, Cargo features, and rule-pack identity. A case-local expectation
separately pins the effective configuration and target-manifest digests because
those legitimately differ between pack instances. Changing any of these fields
produces a different campaign digest; an existing state file refuses to resume
against the changed plan. `analyzer_fingerprint = "auto"` is an explicit
discovery mode: generated reports are still checked for internal consistency,
but an attestation/replay campaign should replace it with the measured digest.
Runtime observations are not silently migrated across incompatible schemas.

`intermed-corpus-lock-v3` separates `content_digest`, `lock_manifest_digest`, and
`acquisition_digest`. Changing a CDN URL no longer changes content identity.
Locks also declare `verification_completeness` and `unhashed_files`; an unhashed
lock remains usable but is never described as fully content-addressed. The v1
and v2 readers remain migration-readable.

`intermed-lab-run-v2` adds explicit inconclusive, harness, infrastructure, and
skipped statuses. `intermed-compatibility-matrix-v2` counts these separately.
`intermed-rule-accuracy-v4` represents undefined ratios as `null`, records
eligible/excluded cases, and includes Wilson precision lower bounds. The v1 Lab
run reader remains available; accuracy reports are regenerated rather than
migrated.

From 0.1.9, SBOM provenance can also consume the exact artifact SHA-256 values
from `intermed-lab-materialization-v1`. This is an additive interpretation of an
existing manifest: cached artifact metadata remains content-addressed, while the
pack-specific provenance credit is recomputed for every target. Corpus-lock v1,
v2, and v3 remain readable.

Artifact materialization is atomic and no-clobber under concurrent workers. An
existing destination is verified rather than opened for writing, so a losing
worker cannot truncate a hard-linked content-store blob. This changes execution
semantics but not the materialization schema.

0.1.9 also tightens additive report semantics without changing the v2 shape:
canonical finding identity includes the typed condition family, so different
resource conclusions about the same entity cannot share a semantic ID. Runtime
incident detail remains present but may move to `explain-only` visibility once a
primary incident owns the default surface. Consumers must continue to use
`semantic_id` for condition continuity and `occurrence_id` for one physical
report occurrence rather than treating presentation title or severity as an ID.

Cache budget enforcement now runs during writes and counts both payload and
fingerprint files. This changes eviction timing, not cache schema; content hash,
collector version, settings, fact schema, and mapping identity remain the
validity boundary.

## Compatibility promise

These formats remain alpha. InterMed preserves the explicitly documented legacy
reader/writer paths, but any other breaking change advances the schema name and
is called out in the release notes.
