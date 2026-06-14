# Layer B Metadata Roadmap

## Vision (6-9 months)

Make Layer B a first-class intelligence layer: manifests describe identity,
entrypoints describe behavior, capabilities and relationships feed Layers C/F/I/J,
and Layer D uses that context for root-cause-oriented crash triage.

All additions are append-only. Existing `mod`, `plugin`, `entrypoint`,
`dependency`, and `log_mentions_mod` facts remain valid.

## Delivered foundation and vertical slice

- Reserved predicates: `mod_metadata`, `entrypoint_detail`, `mod_relationship`,
  `mod_capability`, `log_crash`, and `log_mod_error`.
- `--metadata-level basic|enriched|full`, `[metadata].level`, and
  `INTERMED_METADATA_LEVEL`.
- Rich Fabric, Quilt, Forge/NeoForge, Bukkit, and Paper manifest metadata.
- Raw and normalized versions; broader non-strict semver parsing in Layer C.
- Entrypoint classification and bounded class-symbol analysis for common event
  bus/loader/event markers.
- Manifest-backed incompatibility, recommendation, and provided-API relationships.
- Initial high-level capabilities from entrypoints, events, mixins, access
  transforms, coremods, and known performance/render naming.
- Root-cause exception facts, weighted mod blame, and Layer-B-enriched log facts.
- DuckDB `mod_capability_inventory` and `log_root_causes` views.

## Metadata levels

| Level | Contract | Cost |
|---|---|---|
| `basic` | Legacy facts only | Lowest |
| `enriched` (default) | Rich manifest metadata, entrypoint types, relationships, capabilities | Low |
| `full` | Adds detected events and priority from entrypoint class symbols | Moderate |

## Phase plan

### Phase 0: Foundation (1 week)

Exit criteria: predicates and levels documented; property tests pass; old fact
contracts unchanged.

### Phase 1: Manifest enrichment (3-4 weeks)

Harden loader-specific parsing against a 100+ mod corpus. Measure metadata
coverage by loader and reduce Layer-C skipped/undecidable versions.

Targets:

- authors and environment on at least 80% of corpus mods where loaders expose it;
- 15-25% fewer version-related Layer-C skips;
- no measurable regression in warm-cache scan time.

### Phase 2: Entrypoint intelligence (5-7 weeks)

The current implementation uses bounded class-symbol evidence. The next step is
structured cafebabe method/annotation analysis:

- exact `@EventBusSubscriber` and event registration method extraction;
- Fabric/Quilt callback registration with owner, method, and lifecycle phase;
- confidence calibration against Create, Sodium, Lithium, Iris, and a labeled
  community corpus;
- capability evidence that points to exact entrypoint facts.

Exit criteria: at least three correctly supported capabilities for each labeled
popular mod, under 10% false-positive rate on the corpus.

### Phase 3: Relationships and deep integration (4-6 weeks)

- infer `consumes_api` from structured class references;
- maintain a versioned incompatibility knowledge pack instead of hard-coding it;
- add capability-aware Layer-F and Layer-I rules;
- publish Rule Pack v3 examples using the new predicates;
- add capability/root-cause trend views and HTML report sections.

Exit criteria: community rule packs consume the predicates; capability-backed
findings retain evidence edges; real-pack reports show actionable relationship
and root-cause sections.

## Parallel Layer D track

The delivered parser reconstructs caused-by chains, emits the deepest exception
as root cause, and weights structurally named mods. Remaining work:

- map stack frames to installed mods using jar class indexes;
- account for wrapper/library frames and loader internals;
- group repeated crashes by stable root-cause fingerprint;
- calibrate blame scores on labeled crashes;
- correlate runtime phase and thread from log prefixes.

## Risks and controls

| Risk | Control |
|---|---|
| Entrypoint inference false positives | Evidence, confidence, labeled corpus, exact analyzers before raising severity |
| Fact volume | Metadata levels, append-only predicates, DuckDB volume monitoring |
| Scan cost | Jar cache, declared-entrypoint-only scan, Rayon, warm/cold benchmarks |
| Rule-pack churn | Existing predicates remain unchanged; new predicates are optional |

## Measurement

Track per corpus run: metadata coverage, normalized-version rate, entrypoint and
capability precision/recall, Layer-C undecidable count, fact counts by kind,
cold/warm scan duration, and root-cause top-1 accuracy.
