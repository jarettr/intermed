# Security and SBOM

InterMed reports supply-chain and capability facts about the jars in a pack. It
is a static, preflight view: it reports what a jar *references*, not what it does
at runtime. The framing matters — a reference to a process-spawning API is a
reason to look, not proof of anything.

## In the doctor report

For a mods directory these run as part of a normal `doctor` run:

- **Signature status** — whether each jar carries a `META-INF/*.SF` signature.
  Most Fabric and Forge mods ship unsigned; this is reported as informational
  context, not a problem.
- **Trust score** — a 0–100 score per artifact from how well it is identified
  (known id, version, signature). Lower is less certain.
- **Coremods** — Forge bytecode transformers a mod ships, which run before mixins
  and outside their model.
- **Dangerous-API surface** — a count of classes in a jar that reference
  sensitive APIs: process spawning, sockets, reflection, `sun.misc.Unsafe`,
  `System.exit`, method handles. This is read from the constant pool — a symbolic
  reference, not a call trace. A grouped finding is only raised once a jar crosses
  a signal threshold (configurable; default two distinct signals).

The HTML report's **Security** tab collects all of this in one place.

## Exporting an SBOM

```bash
intermed sbom export ./mods --format spdx       > sbom.spdx.json
intermed sbom export ./mods --format cyclonedx  > sbom.cdx.json
```

The SBOM lists each jar with its mod id, version, loader, SHA-256, and signature
state. Use it as a supply-chain artifact in CI or a release.

## Reading the API surface honestly

The dangerous-API surface answers "which jars touch sensitive APIs, and how
much". It does not answer "is this jar malicious". A large content mod legitimately
uses reflection; an obfuscated jar with a single `ProcessBuilder` reference may be
worth a closer look. Use it to decide where to spend manual review, and pair it
with `--explain` to see which classes carry the references.

## Low provenance meets a dangerous capability

The trust score and the dangerous-API surface are weak on their own — most mods are
unsigned, and large mods legitimately use reflection. They are far more telling
*together*. InterMed correlates the two: when a jar that could **not** be
confidently identified (trust below the `well_identified_trust` threshold) also
statically references a high-risk capability — process spawning, `Unsafe` / native
class definition, or a script engine — it raises a single
`low-trust-capability:<jar>` finding (`warn`, security).

The reasoning is explicit in the finding: unknown provenance combined with a
dangerous capability is a stronger supply-chain signal than either alone. The fix it
suggests is to establish the jar's provenance (a known platform, a signature or a
real manifest) before trusting a jar that spawns processes, loads native code, or
evaluates scripts. `--explain` shows both sides of the link — the SBOM trust fact
and the capability fact — so you can judge it yourself.

This is one correlation in a wider set; see
[How the analyses connect](../reference/analysis.md#how-the-analyses-connect).

## Where the numbers come from

For the thresholds and confidence values, see
[Configuration](../reference/configuration.md#security) and
[What each analysis examines](../reference/analysis.md#security--sbom).
