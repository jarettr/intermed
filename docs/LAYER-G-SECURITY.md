# Layer G — Security audit

Static API-usage evidence from mod jar class files. **Detection only** — no hooks,
no enforcement, no mod code execution.

**Live status:** [STATUS.md](STATUS.md) · **Crate:**
[`intermed-security-audit`](../crates/intermed-security-audit/)

## Pipeline

```text
  jar .class entries
       │
       ▼
  ClassEvidence (per class)     ← cafebabe primary, noak fallback
       │
       ▼
  detect_signals (structural) + corroborate_with_strings (gated)
       │
       ▼
  collapse_per_capability (jar-wide, one entry per capability)
       │
       ▼
  uses_* facts (provenance + confidence)  ──▶  security-api-risk (one finding / mod)
```

## Method

1. List zip entries ending in `.class` (skip directories, `..` paths, non-`CAFEBABE` magic).
2. Parse constant pools with **cafebabe** (primary) and **noak** (fallback feature).
3. Extract structured evidence per class ([`ClassEvidence`](crates/intermed-security-audit/src/cp.rs)):
   - `MethodRef` / `InterfaceMethodRef` → invocation evidence
   - `FieldRef` → field access (narrow: `Unsafe` static access)
   - `Class` entries → type references only
   - `CONSTANT_String` literals → **only** for reflection corroboration
4. Match references against risky API rules → **structural** signals.
5. Layer reflection-corroborated signals when dispatch machinery is present.
6. **Collapse** to one [`DetectedSignal`](crates/intermed-security-audit/src/detect.rs) per
   capability per mod (structural provenance wins over corroborated; strength = max seen).
7. Emit one `uses_*` fact per `(mod_id, signal)`; rule groups into **one finding per mod**.

A bare UTF-8 string in the constant pool never produces a signal on its own.

## Confidence model

| Provenance | Fact confidence | Source |
|------------|----------------:|--------|
| `structural` | 1.0 | real `MethodRef` / `InterfaceMethodRef` / `FieldRef` |
| `reflection-corroborated` | 0.4 (configurable) | suspicious `CONSTANT_String`, **gated** on reflective machinery |

Each fact carries a `provenance` attribute. Findings tag `reflection-corroborated`
when any contributing signal used that path.

### Evidence strength

Within a capability, detections carry **strength** (`low` / `medium` / `high`) used
during collapse — e.g. structural `Medium` in one class and corroborated `High` in
another collapses to structural + `High`.

### Why corroboration

Obfuscated `Class.forName(…).getMethod(…).invoke(…)` leaves no `Runtime.exec`
method reference. Corroboration recovers targeted recall:

- Reflective **machinery** must be structurally visible first.
- Suspicious strings (`"java.lang.Runtime"`, `"exec"`, …) add low-confidence
  capability hints only when machinery is present and the capability is not
  already structural.

This is diagnostic preflight, **not** antivirus.

## Signals

| Fact kind | Detection rule (method/field ref required unless corroborated) |
|-----------|------------------------------------------------------------------|
| `uses_process_spawn` | `Runtime.exec`, `ProcessBuilder.start` |
| `uses_socket` | `Socket` / `ServerSocket` / `DatagramSocket` + network ops |
| `uses_reflection_set_accessible` | `AccessibleObject.setAccessible` |
| `uses_unsafe` | `sun/misc/Unsafe` or `jdk/internal/misc/Unsafe` |
| `uses_native_library` | `System` / `Runtime` `.load` / `.loadLibrary` |
| `uses_dynamic_class_definition` | `ClassLoader.defineClass` |
| `uses_reflective_invocation` | `Class.forName`, `getMethod`, `Method.invoke`, … |
| `uses_script_engine` | `ScriptEngineManager`, `ScriptEngine.eval` |
| `uses_deserialization` | `ObjectInputStream.readObject` / `readUnshared` |
| `uses_system_exit` | `System.exit`, `Runtime.exit` / `halt` |
| `uses_method_handles` | `MethodHandles.lookup`, `MethodHandle.invoke`, `Lookup.unreflect`, … |

Expanded detection (same fact kinds where noted):

- **Native library** — also `java.lang.foreign.NativeLibrary.load`, `jdk.internal.loader.NativeLibraries`
- **Dynamic class definition** — also `URLClassLoader`, `Instrumentation.redefineClasses` / `retransformClasses`
- **Reflective invocation** — also reflective `Field.get` / `set` accessors

`writes_files` is **not emitted** — too noisy for security preflight.

Collector record tracks `classes_scanned`, `dangerous_classes`, and per-signal
`affected_classes` (how many classes structurally hit each capability). Grouped
findings expose this in titles/labels and carry graded `confidence` (not a flat
0.9 for every mod).

Subject is the mod id from `fabric.mod.json` / `quilt.mod.json` when present.

## Findings (`security-api-risk`)

One grouped finding per mod: `security-api-risk:{mod_id}`.

| Severity | Signals |
|----------|---------|
| **Warn** | `uses_process_spawn`, `uses_unsafe`, `uses_dynamic_class_definition`, `uses_script_engine` |
| **Note** | `uses_socket`, `uses_reflection_set_accessible`, `uses_native_library`, `uses_reflective_invocation`, `uses_deserialization`, `uses_system_exit` |

Reflection-corroborated **high-risk** capabilities still drive **Warn**, with
explanation labeled *inferred (low confidence)*.

**Threshold:** a single Note-level signal does **not** emit a finding. Emit when:

- any Warn-level signal is present, **or**
- two or more Note-level signals are present.

Category: `Security`.

## Cross-layer note

Layer H's [`sbom-security-correlation`](../crates/intermed-sbom/src/lib.rs) rule
joins **low trust / weak `source_class`** jars with high-risk Layer G facts.
Security findings stand alone; correlation adds supply-chain context.

## CLI

```bash
intermed doctor ./mods --json
intermed doctor ./mods --dump-facts facts.json
intermed doctor ./mods --explain security-api-risk:modid
```

Jar cache collector id: `security-scanner` (`CACHE_VERSION` `-r2`).

## Tests

```bash
cargo test -p intermed-security-audit
```