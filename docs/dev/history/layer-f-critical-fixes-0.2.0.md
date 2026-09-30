# Layer F critical fixes — 0.2.0 implementation record

This document archives the Layer F hardening plan that previously lived at the
repository root. It is a completed implementation record, not an active backlog.

## Completed work

- [x] **Canonical environment resolution.** The Mixin collector resolves loader,
  Minecraft version, and target side through Layer A's
  `resolve_environment_field()` authority/conflict model. It no longer selects
  the first `environment` fact.
- [x] **Typed mapping compatibility.** `MappingCompatibility` distinguishes
  `Compatible`, `Incompatible`, and `VersionUnverified`. Unknown mapping/target
  versions cannot prove class or method absence.
- [x] **Explicit refmap lifecycle.** `RefmapStatus` separates not declared,
  loaded, missing, unreadable, too large, and invalid refmaps. Apply verification
  consumes the actual per-config status and facts expose the same state.
- [x] **Bounded read outcomes.** Mixin config, refmap, and class reads retain
  absent/too-large/unreadable distinctions through `BoundedReadError`; coverage
  gaps are not rewritten as ordinary missing entries.
- [x] **Descriptor-aware method-body identity.** Call sites, instruction offsets,
  and frame state are keyed by owner, method name, and descriptor. Overloaded
  methods cannot overwrite one another.
- [x] **Instruction-point selector and locals verification.** Selector matching
  retains opcode/member/offset information. Locals are checked at every selected
  instruction offset and aggregated conservatively.
- [x] **Effect-derived composition.** `HandlerEffect` and bytecode dataflow drive
  cancel/replacement/wrapper/multiplier semantics. `@WrapOperation` is classified
  by its observed original-call count, and a replacement is not counted as the
  independent non-observer required by the old false-positive condition.
- [x] **Unique-site cluster accounting.** Apply failures and failed site verdicts
  are deduplicated by stable site identity before cluster counts are computed.

## Additional hardening completed with the plan

- Canonical Layer B artifact/mod identities replace filename/stem joins; fallback
  names are explicit unresolved display identities.
- Activation includes the target side, config plugins, descriptor authority, and
  conditional/impossible co-application states.
- Apply-failure families declare typed proof/coverage prerequisites rather than
  sharing one universal classpath requirement.
- Runtime confirmation prefers config, full class, handler, target, and site
  identity; a class-only match is correlation unless it identifies one unique
  candidate site.
- Cross-layer security and resource-mutation joins use site/handler evidence,
  not a mod-wide boolean.
- Mixin site provenance points back to config/class/application-site facts.
- Precision is represented by identity, activation, verification, and effect
  evidence rather than one value serving all four meanings.

## Regression coverage

The implementation is covered by Layer F unit/integration tests for:

- equal-authority environment conflicts and target-side activation;
- compatible, incompatible, and version-unverified mappings;
- every refmap status and bounded-read failure class;
- overload-safe method lookup;
- descriptor-bearing production selector wiring;
- opcode, ordinal, shift, slice, and instruction-offset matching;
- multi-offset local capture aggregation;
- runtime correlation versus exact site confirmation;
- cancellation and `@WrapOperation` effect classes;
- one-site cluster deduplication;
- measured target/selector/signature/runtime/composition fixtures.

The active roadmap and release status live in `docs/ROADMAP.md` and
`docs/PROJECT_STATUS.md`.
