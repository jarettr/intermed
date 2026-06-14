# Donor Inventory (Phase 0+)

The new project is **Rust**; the legacy project is **100% Java** (~840 `.java`
files). "Extraction" between languages is therefore **port-by-behavior, not
copy** — the Java is a read-only *specification and reference implementation*,
never source to be moved.

**Current Rust implementation map:** [STATUS.md](STATUS.md)

## Legacy warehouse

* Location (read-only reference): `~/Загрузки/InterMed-8.0.0-alpha.1/`
* Rule: never edited in place. Each extraction is a deliberate re-implementation
  under a new crate, re-using the **old tests as behavioral fixtures**.

## The real dividing line: `org.objectweb.asm`

The Java codebase ran on the JVM because the *runtime executed mods*. Doctor
executes nothing — it reads files — so the language boundary is not "Java vs
Rust" but **bytecode vs not**. Anything importing `org.objectweb.asm` is the
JVM frontier; everything else is plain data/text and ports cleanly.

## Tiers

| Tier | Meaning | Action |
|---|---|---|
| **1** | Pure data / text / JSON / TOML / YAML / zip | Port to Rust, often onto a ready crate |
| **2** | Reads Java `.class` bytecode (ASM) | Rust class-file parser (`cafebabe`/`noak`) **or** optional JVM worker |
| **3** | Mutation / execution / monolith-entangled | Research-only; not in product path |

## Tier 1 — ported

| Donor (legacy path) | Does | New home | Status |
|---|---|---|---|
| `test-harness/.../LogAnalyzer.java` | regex log classification | `intermed-log` | ✅ Phase 1 |
| `app/.../resolver/SemVerConstraint.java` | version parse/compare | `intermed-deps` | ✅ Phase 1 |
| `app/.../resolver/PubGrubResolver.java` | dependency resolution | `intermed-deps` | ✅ `pubgrub` + `creeper-semver-pubgrub` |
| `intermed-runtime-core/.../metadata/ModMetadataParser.java` (**JSON path**) | fabric/quilt/forge manifests | `intermed-minecraft-scan` | ✅ Phase 1 |
| `app/.../vfs/CrdtJsonMergeEngine.java`, `VirtualFileSystemRouter.java` | JSON merge + fs routing | `intermed-vfs`, `intermed-packops` | ✅ Phase 3 |
| `app/.../doctor/DoctorReport.java` etc. | report-DNA (ANSI/JSON/SARIF) | `intermed-report` | ✅ redesigned |

## Tier 1 — partial / later

| Donor | Does | New home | Status |
|---|---|---|---|
| `intermed-packaging/.../ModSbomGenerator.java` | checksums, `.imod`/`.impack`, Ed25519 | `intermed-sbom` | ✅ jar scan; ⏳ signed pack verify |
| `ModrinthClient`, loader installers (lab) | networked corpus + live smoke | `intermed-lab` traits | ⏳ deferred behind `CandidateProvider` / `SmokeRunner` |

## External backend adopted in Phase 5

| Source | Does | New home | Note |
|---|---|---|---|
| Souffle Datalog | offline rule evaluation | `intermed-rules` `--logic=souffle` | optional external binary |
| DuckDB | SQL rules + analytics | `intermed-duckdb` | feature-gated |

## Tier 2 — JVM frontier (ported deeper than early notes)

| Donor | Does | New home | Rust depth (today) |
|---|---|---|---|
| `app/.../mixin/MixinASTAnalyzer.java` | mixin targets via ASM | `intermed-mixin-intel` | ✅ configs + annotations + **handler bytecode**; refmap/Tiny **canonical** keys; `@At` **`site_key`**; `MixinInteractionEngine`; hierarchy index; semantics heuristics — see [LAYER-F-MIXIN](LAYER-F-MIXIN.md) |
| `intermed-runtime-core/.../metadata/ModMetadataParser.java` (**annotation path**) | Forge `@Mod` via ASM | `intermed-minecraft-scan` | ⏳ annotation-only mods |
| `intermed-security-agent/.../SecurityHookTransformer.java` | API scan via ASM | `intermed-security-audit` | ✅ constant-pool structural + reflection-corroborated + per-capability collapse + grouped findings — see [LAYER-G-SECURITY](LAYER-G-SECURITY.md) |

## Tier 3 — research-only (never product path yet)

`ResolutionEngine`, `MixinTransmogrifier`, ClassLoader DAG, Graal/WASM execution,
`SemanticBus` enforcement, `Minecraft1201Backend`, Prism native adapter. Kept as
references for the eventual (optional) runtime — Layer L, Phase 9.

## Tests as fixtures (highest-leverage trick)

The old Java tests are language-independent once reduced to input → expected
output. Where a donor has tests (`SecurityHookTransformerTest`, resolver tests,
`LogAnalyzer` cases), capture their cases as Rust test vectors when porting the
donor. This is how behavior survives the language change without trusting a
transliteration.