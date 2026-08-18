# Schema and migration policy

InterMed's machine-facing formats are versioned independently. A schema name is
part of the data, not an implied property of the executable version.

## Doctor reports

`intermed-doctor-report-v2` is the canonical output from 0.1.6. In 0.1.7 it gains
additive evidence-graph, incident, shared-recommendation, semantic identity, and
evidence-path fields. It already permits unknown optional fields, so these do
not require a v3 schema name. The v1 reader remains supported,
and `doctor --report-schema v1` provides a lossy compatibility writer through
0.1.7. V1 cannot preserve assessment prerequisites, blockers, adjustments, or
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
when a prerequisite is missing. V1 and v2 packs remain loadable, but their
Error/Fatal output is capped at Warn with a structured
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

## Compatibility promise

These formats remain alpha. InterMed preserves the explicitly documented legacy
reader/writer paths, but any other breaking change advances the schema name and
is called out in the release notes.
