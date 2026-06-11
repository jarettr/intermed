# Donor Inventory (Phase 0)

The new project is **Rust**; the legacy project is **100% Java** (~840 `.java`
files). "Extraction" between languages is therefore **port-by-behavior, not
copy** — the Java is a read-only *specification and reference implementation*,
never source to be moved.

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

## Tier 1 — port cleanly (Phase 1–3, 5–6)

| Donor (legacy path) | Does | New home | Crate to use |
|---|---|---|---|
| `test-harness/.../analysis/LogAnalyzer.java` | regex log classification (zero non-stdlib imports) | `intermed-log` ✅ done | `regex` |
| `app/.../resolver/SemVerConstraint.java` | version parse/compare | `intermed-deps` ✅ done | `semver` |
| `app/.../resolver/PubGrubResolver.java` | dependency resolution | `intermed-deps` (later) | adopt **`pubgrub`** crate |
| `intermed-runtime-core/.../metadata/ModMetadataParser.java` (**JSON path**) | fabric/quilt/forge/paper manifests | `intermed-minecraft-scan` ✅ done | `serde_json`+`toml`+`serde_yaml`+`zip` |
| `app/.../vfs/CrdtJsonMergeEngine.java`, `VirtualFileSystemRouter.java` | JSON merge + fs routing | `intermed-vfs` ✅ extracted | `serde_json`+`zip` |
| `intermed-packaging/.../ModSbomGenerator.java`, `PackagingService` | checksums, `.imod`/`.impack`, Ed25519 verify | `intermed-sbom` (Phase 6) | — |
| `app/.../doctor/DoctorReport.java` etc. | report-DNA (ANSI/JSON/SARIF) | `intermed-report` ✅ ported & redesigned | — |

## External backend adopted in Phase 5

| Source | Does | New home | Note |
|---|---|---|---|
| Souffle Datalog | high-performance offline rule evaluation | `intermed-rules` optional `--logic=souffle` | real `.facts` + generated `.dl` execution; not required for default CLI |

## Tier 2 — the JVM frontier (Phase 4, 6)

| Donor | Does | New home | Note |
|---|---|---|---|
| `app/.../mixin/MixinASTAnalyzer.java` | mixin targets via ASM annotations | `intermed-mixin-intel` ✅ extracted as static intelligence | currently constant-pool/string evidence; structural parser remains the next fidelity step |
| `intermed-runtime-core/.../metadata/ModMetadataParser.java` (**annotation path**) | Forge `@Mod` discovery via ASM | `intermed-minecraft-scan` (later) | only needed for annotation-only mods |
| `intermed-security-agent/.../SecurityHookTransformer.java` | API-usage scan via ASM | `intermed-security-audit` (Phase 6) | port the *detection*, drop the *transformation* |

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
