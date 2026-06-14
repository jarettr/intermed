# Layer H — SBOM / provenance

Read-only jar provenance scan. No bytecode execution, no network calls.

**Live status:** [STATUS.md](STATUS.md) · **Crate:**
[`intermed-sbom`](../crates/intermed-sbom/)

## Per-jar analysis

1. **SHA-256** of the full jar bytes.
2. **Manifest identity** — first match wins:
   - `fabric.mod.json` → loader `fabric`
   - `quilt.mod.json` → loader `quilt`
   - `META-INF/mods.toml` → loader `forge`
   - `META-INF/neoforge.mods.toml` → loader `neoforge`
3. **Graded source class** ([`SourceClass`](../crates/intermed-sbom/src/lib.rs)):
   - `platform-listed` — mod id **and** Modrinth/CurseForge metadata or homepage
   - `identified` — recognized loader manifest **with** mod id
   - `partially-identified` — manifest present but id missing (library jar, incomplete metadata)
   - `unidentified` — no recognizable loader manifest
4. **JAR signing depth** ([`SignatureStrength`](../crates/intermed-sbom/src/lib.rs)):
   - `unsigned` — no `META-INF/*.SF`
   - `manifest-only` — `.SF` without PKCS block (`.RSA` / `.DSA` / `.EC`)
   - `certified` — `.SF` plus certificate block (full JAR signature structure)
5. **Trust score** (0–100 heuristic, identifiability — **not** a safety verdict):
   - base 20 + mod id +40 + version +20 + loader +10
   - +8 platform listed, +5 contact/homepage, +7 present in sibling `corpus.lock`
   - +5 manifest-only sign, +5 additional when certified (capped at 100).

The old binary `unknown_source` flag is replaced by `source_class` on facts and
scan records — only `unidentified` jars trigger the standalone provenance finding.

## Facts emitted

| Kind | Subject | Key attrs |
|------|---------|-----------|
| `checksum` | archive | `algorithm`, `hex` |
| `artifact_identity` | mod_id | `version`, `archive`, `sha256` |
| `unknown_source` | archive | `reason` (legacy finding path for `unidentified`) |
| `signature_status` | archive | `status` |
| `trust_score` | archive | `score` |
| `sbom` | archive | `mod_id`, `version`, `loader`, `sha256`, `signed`, `signature_strength`, `platform`, `in_corpus_lock`, `source_class`, `trust_score` |

## Findings

### `sbom-provenance`

| Condition | Severity |
|-----------|----------|
| `source_class=unidentified` | Warn |
| `signature_status=unsigned` | Note |

### `sbom-security-correlation` (cross-layer with G)

Warn when a jar has **low trust** (below configurable
`well_identified_trust`, default 70) **and** Layer G reports a high-risk
capability (`uses_process_spawn`, `uses_unsafe`, `uses_dynamic_class_definition`,
`uses_script_engine`). Well-identified jars with dangerous APIs are already
covered by `security-api-risk` alone.

## CLI

```bash
intermed doctor ./mods --json
intermed doctor ./mods --explain unknown-source:mystery.jar
intermed doctor ./mods --explain low-trust-capability:mystery.jar
```

Jar cache collector id: `sbom-generator` (`CACHE_VERSION` `-r2`).

## Not in scope (legacy donor)

Ed25519 `.imod` / `.impack` packaging verification from the Java
`ModSbomGenerator` — see [donor-inventory.md](donor-inventory.md).