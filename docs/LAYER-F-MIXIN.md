# Layer F — Mixin intelligence

Static mixin risk map with refmap resolution, deep injection sites, handler
bytecode, interaction graphs, and composite risk scoring. InterMed **does not**
transform classes or execute mod code; it reads mixin JSON configs and class-file
evidence only.

**Live status:** [STATUS.md](STATUS.md) · **Crate:**
[`intermed-mixin-intel`](../crates/intermed-mixin-intel/)

## Architecture

```text
  [MixinCollector] ──▶ raw facts (configs, classes, shadows, injection points, …)
         │
         ▼
  [MixinInteractionEngine] ──▶ overlaps, graph edges, risk scores
         │
         ▼
  [MixinRiskRule] ──▶ findings with 0–100 risk + Spark correlation
```

Collectors emit **raw** facts. [`MixinInteractionEngine`](crates/intermed-mixin-intel/src/analyzer.rs)
builds the interaction graph and composite risk scores **after** all jars are
scanned — separating collection from analysis.

## Config discovery

All loaders are discovered in a **single unified pass**
([`discover_mixin_configs`](crates/intermed-mixin-intel/src/scan.rs)):

1. **Fabric** — `fabric.mod.json` → `mixins` array
2. **Quilt** — `quilt.mod.json` → `quilt_loader.mixins` and top-level `mixins`
3. **Forge / NeoForge** — `META-INF/MANIFEST.MF` → `MixinConfigs:` comma list
   **and** `META-INF/mods.toml` / `neoforge.mods.toml` → `[[mixins]] config = …`
   (modern Forge declares configs in the TOML, not the manifest)
4. **Fallback** — if a jar declares none but still ships `*.mixins.json` /
   `mixins.*.json` files, those are globbed in (shaded / coremod-era jars)

Client/server mixin lists in config JSON are included.

## Refmap + canonical resolution

When a mixin config declares `"refmap": "…refmap.json"`, the scanner:

1. Parses the SpongePowered `.refmap.json` (`mappings` + `data` environments).
2. Optionally parses Tiny v2 mappings from `mappings/mappings.tiny` (intermediary /
   yarn / mojmap) when present in the same jar.
3. Resolves `method = "…"` injection targets into a **display** name and a
   **canonical** comparison key.

[`MappingContext::resolve_injection`](crates/intermed-mixin-intel/src/refmap.rs)
expresses `canonical` in the **intermediary** namespace when a bridge exists
(refmap token, Tiny named→intermediary reverse map). Each point also records
`namespace` (`intermediary` | `named` | `unknown`).

**Cross-mod matching** uses `canonical` / `site_key`, never display names alone —
so `tick()V` and `method_1574()V` can match when both bridge to the same
intermediary key.

Unresolved injection points remain **conservative** (overlap flagged as conflict).

## Structural class model

Per mixin class, cafebabe parses annotations and — for injection handlers —
bytecode (`parse_bytecode(true)`):

| Evidence | Source |
|----------|--------|
| `@Shadow` fields/methods | `mixin_shadow` facts |
| Added members (accessor/invoker/plain) | `mixin_added_member` facts |
| Target-class calls (constant pool + handler bytecode) | `mixin_calls` facts (`provenance`) |
| Reflective dispatch in handlers | `mixin_calls` with `provenance=reflective` |
| Handler body shape (branches, returns, reflection, target field/method access, CallbackInfo) | `mixin_handler_body` facts |
| Semantic handler effect (locals/return/early-exit/complexity) | `mixin_handler_effect` facts |
| Effective change on target method after weaving | `mixin_effect` facts |
| Safer-mixin guidance per injection site | `mixin_recommendation` facts |
| Deep injection sites (`@At`, locals, `site_key`) | `mixin_injection_point` facts |
| Injection semantics (`impact`) | `mixin_injection_point.impact` |
| Target superclass/interface edges (when class present in jars) | `mixin_hierarchy` facts |

Every Sponge + MixinExtras annotation is classified **explicitly** (not collapsed
into plain `@Inject`):

| Annotation | `mixin_operation` |
|------------|-------------------|
| `@Inject` / `@Redirect` | `inject` / `redirect` |
| `@ModifyArg` / `@ModifyArgs` | `modify-arg` / `modify-args` |
| `@ModifyVariable` / `@ModifyConstant` | `modify-variable` / `modify-constant` |
| `@Overwrite` / `@Shadow` / `@Accessor` / `@Invoker` | `overwrite` / `shadow` / `accessor` / `invoker` |
| `@Unique` | `unique` (also sets `mixin_added_member.unique`) |
| `@WrapOperation` | `wrap-operation` |
| `@WrapWithCondition` | `wrap-with-condition` (can suppress a call site entirely) |
| `@ModifyExpressionValue` | `modify-expression-value` |
| `@ModifyReturnValue` | `modify-return-value` |
| `@ModifyReceiver` | `modify-receiver` |
| `@Definition` / `@Expression` | `definition` / `expression` (MixinExtras expression matching) |
| `@Share` | `share` (shared local between handlers) |
| `@Local` (parameter) | tracked as a writable/read-only target-local capture |

### Injector metadata

Each injector annotation's application controls are parsed into `InjectorMeta` and
carried on every resolved injection point: `require`, `expect`, `allow`,
`cancellable`, `remap`, `priority`, `group`, `constraints`. These drive the
apply-failure model (`require` ≥ 1 + unmatched target = hard failure;
`remap = false` on a Minecraft target = suspicious) and the conflict taxonomy
(`cancellable` HEAD vs RETURN). The Sponge `@Inject(locals = LocalCapture.X)` mode
(`CAPTURE_FAILHARD` raises apply-failure risk) is parsed as the enum constant it
is — not as a (non-existent) nested annotation.

### Deep injection resolution

Beyond `method = "…"` + refmap, the scanner parses nested `@At` annotations
(`HEAD`, `RETURN`, `INVOKE`, ordinals, slices, `by`) and `@LocalCapture` args.
Cross-mod collision detection prefers **`site_key`** (canonical method + `@At` +
locals) so `HEAD` and `RETURN` on the same method are **not** falsely merged.

### Hierarchy + semantics

[`HierarchyIndex`](crates/intermed-mixin-intel/src/hierarchy.rs) is built from all
`.class` files in scanned jars. When mixin targets appear in that index, the
analyzer emits `inherited-target` conflict edges for injections on related
super/sub classes. Minecraft core classes are usually absent from mod jars —
hierarchy facts are opportunistic, not guaranteed.

[`InjectionImpact`](crates/intermed-mixin-intel/src/semantics.rs) labels
(`entry-hook`, `method-replace`, `call-replace`, …) feed composite risk scoring.

## Interaction graph

[`MixinInteractionGraph`](crates/intermed-mixin-intel/src/graph.rs) connects mixins,
targets, and conflict edges:

| Edge / interaction | Meaning |
|--------------------|---------|
| **Direct injection** | Same `site_key` / canonical point, multiple mods |
| **Namespace mismatch** | Same target, disjoint mapping namespaces — clash cannot be confirmed *or* ruled out (low strength) |
| **Indirect shadow** | Mod A added a member mod B shadows |
| **Overwrite stack** | Multiple `@Overwrite` on one method |
| **Overwrites same method** | Graph edge when two mods overwrite the same method |
| **Redirects same call** | Multiple `@Redirect` / `@WrapOperation` on one call site |
| **Modifies same local** | `@ModifyVariable` / `@ModifyArg` on the same slot |
| **Chained injection** | `HEAD` entry hook plus `INVOKE` hook on the same method across mods |
| **Priority conflict** | Different mixin priorities on overlapping injections |
| **Inherited target** | Injections on classes in a known super/sub chain |
| **Shadow descriptor conflict** | Two mods `@Shadow` the same target **field** with different descriptors — a class field has one type, so this is provable version/mapping skew (fields only; differing *method* descriptors are legal overloads) |
| **Accessor conflict** | Two mods declare an `@Accessor`/`@Invoker` for the same member with incompatible signatures |
| **Overwrite vs injector** | One mod `@Overwrite`s a method another mod injects into — the overwrite replaces the body, so the other mod's hooks silently stop applying |
| **Cancellable HEAD vs RETURN** | A `cancellable` `@Inject(HEAD)` on a method another mod injects at `RETURN`; if the HEAD cancels, the RETURN handler never runs |
| **Redirect vs WrapOperation** | A `@Redirect` and a `@WrapOperation` seize the same call site — only one can own it |
| **WrapWithCondition suppresses call** | A `@WrapWithCondition` can skip a call another mod redirects/injects around |
| **ModifyArgs same invocation** | Two mods `@ModifyArgs` the same call, order-dependently |
| **Unique member conflict** | Two mods add the same member name to a target without `@Unique` |

Facts: `mixin_interaction`, `mixin_conflict_edge`, `mixin_priority_conflict`.

Export (all on `MixinInteractionGraph`):

- `graph_to_dot(scan)` — Graphviz DOT
- `graph_to_graphml(scan)` — GraphML for Gephi/yEd
- `graph_to_json(scan)` — `MixinGraphExport` JSON
- `graph_to_html(scan, title)` — a **self-contained, dependency-free** interactive
  page: an inline vanilla-JS force-directed canvas graph with node drag, hover
  tooltips, per-edge-type filter checkboxes, node/mod search highlight, and a
  legend. No CDN or network access — safe offline and as a committed artifact.

## Analysis depth (`--mixin-level`)

Mixin scan depth is controlled by [`MixinSettings`](../crates/intermed-doctor-core/src/settings.rs)
(config `[mixin]`, `INTERMED_MIXIN_*` env, CLI):

| Preset | `mixin_handler_effect` facts | `mixin_recommendation` facts | `mixin-handler-intel:*` findings |
|--------|------------------------------|------------------------------|----------------------------------|
| `normal` | off | off | off |
| `detailed` (default) | on | on | off |
| `full` | on | on | on |

CLI: `--mixin-level=normal|detailed|full`, `--no-mixin-handler-effects`,
`--no-mixin-recommendations` (and positive overrides). Use **`normal`** on large
performance stacks when you want overlaps + risk only.

## Composite risk (v2) + Spark

`mixin_risk_score` facts carry a 0–100 score per overlapped target **plus the five
axes it is built from**, so the score is explainable, not a flat saturated sum:

| Axis | Meaning |
|------|---------|
| `certainty` | How sure the conflict is real & resolved (unresolved points, disjoint methods, and **plugin-gated** mixins all lower it) |
| `apply_failure` | Apply-time failure severity on this target (a *confirmed* failure floors the score — see below) |
| `semantic_conflict` | Strength of the cross-mod semantic clash (operation severity, overwrite, advanced patterns) |
| `blast_radius` | Reach: hot path, core class, number of mods |
| `fragility` | Breakage risk on update: shadow/accessor skew, reflection, `CAPTURE_FAILHARD`, priority conflict |

The composite is `certainty · (0.5·semantic + 0.3·blast + 0.2·fragility)`, then a
**confirmed apply failure floors** the score to its `apply_failure` axis — a failure
is itself certain, so `certainty` does not discount it. An uncertain target can no
longer reach 100 just because many mods touch it. `actionability` (how clear the
fix is) is reported alongside but not folded into the score.

**Plugin-gated uncertainty:** when a mixin's config declares an
`IMixinConfigPlugin` (which can enable/disable mixins at load time), the affected
target's `certainty` drops by 25 — the conflict is *possible*, not *confirmed*.

### Apply-failure model

A separate, higher-certainty layer ([`apply_failure.rs`](crates/intermed-mixin-intel/src/apply_failure.rs))
asks **will this mixin even apply?** rather than "might it conflict?". It builds a
`TargetClassIndex` (member + per-method call-site histogram) from the class files in
scanned jars, plus the Minecraft jar when `--minecraft-jar` is supplied. Facts
(`Error` when *confirmed*, else `Warn`):

| Fact | Fires when |
|------|-----------|
| `mixin_apply_target_method_missing` | Target class indexed, method absent |
| `mixin_apply_require_unsatisfied` | …and `require ≥ 1` (a hard load failure) |
| `mixin_apply_target_class_missing` | Minecraft jar indexed, target class absent |
| `mixin_apply_descriptor_mismatch` | `@Shadow` field type ≠ the real member |
| `mixin_apply_ordinal_out_of_range` | `@At(ordinal = N)` exceeds the matching call-site count (only when ≥ 1 site is found, so a namespace miss never false-positives) |
| `mixin_apply_refmap_missing` | A *named* Minecraft target with no refmap (intermediary `class_NNN` targets are exempt — they need none) |
| `mixin_apply_remap_false_suspicious` | `remap = false` on a Minecraft target |

Every presence check is gated on the target actually being indexed; absent
coverage means **no claim**, never a false positive. Without `--minecraft-jar`,
vanilla-targeting mixins simply aren't apply-checked (mod-targeting ones still are).

[`MixinRiskRule`](crates/intermed-mixin-intel/src/rule.rs) reads risk scores and
boosts severity when Layer-I `hot_method` facts correlate with the same class
(simple-name or FQN match, same join strategy as `intermed-spark-bridge`; up to
**+28** at rule time). [`historical_severity_boost`](crates/intermed-mixin-intel/src/recommendation.rs)
also considers Spark hot methods when elevating effect-summary severity.

Hot-path tags are extensible via [`HotPathRules`](crates/intermed-mixin-intel/src/hot_path.rs):
simple class name, package-prefix rules, and injected method-name heuristics.

### Layer B capability context

A mixin-risk finding also folds in the Layer-B `mod_capability` facts of the mods
involved (`capability_context`): a risk on a render class reads very differently
when the mod is known to `modifies_rendering` and is `performance_oriented`. The
capabilities are appended to the explanation ("Involved mod capabilities: sodium →
modifies_rendering, performance_oriented") and each backing `mod_capability` fact
is attached as `CorrelatesWith` evidence — turning "this mod weaves code" into
"this *rendering/performance* mod weaves code on a hot render class".

## Handler dataflow (taint analysis)

[`dataflow.rs`](crates/intermed-mixin-intel/src/dataflow.rs) is a **flow-sensitive
forward abstract interpreter** over a handler's `Code`. It models the JVM operand
stack (slot-accurate, including category-2 longs/doubles) and locals, propagating
an [`AbstractValue`] taint lattice from sources (parameters, `this`, target fields,
target-call results, constants) to sinks (`setReturnValue`, `cancel`, `PUTFIELD` on
the target, typed returns).

At a control-flow merge it computes the **lattice join** of the predecessor states
(the state saved on each branch plus the fall-through), so a value both paths agree
on survives with its provenance — only genuine disagreement rises to `Unknown`.
This is what lets `if (c) return 0; else return 0;` still report a *constant*
return. It degrades conservatively (clears to `Unknown`, sets `imprecise`) only
where flow is truly irreducible on a single pass: a **loop header** (back-edge
state unknown), a height-mismatched merge, or a switch. A separate `guarded` flag —
set once execution is control-dependent on a conditional branch — marks a
cancel / `setReturnValue` as **conditional** rather than unconditional, independent
of value precision.

Beyond control flow, the interpreter classifies **semantic side effects** by the
provenance of values and the APIs a handler invokes:

| Signal | How it's detected |
|--------|-------------------|
| `writes_global_state` | `PUTSTATIC` to a class outside the target |
| `schedules_async` | call to an executor / future / `*Async` API |
| `mutates_world` | call to `setBlock*` / `spawn*` / `destroyBlock` / `explode` / … |
| `allocation_count` | `new` / `newarray` count (heavy on a hot path) |
| `unconditional_throw` | `athrow` not dominated by a conditional branch |
| `config_guarded` | a branch tests a `*Config*`/`*Option*` getter result |
| `mod_loaded_guarded` | a branch tests `isModLoaded` / `ModList.isLoaded` |
| `logs_only` | the only observable effect is a logger call |

The guard classification is precise: a config / mod-loaded check pushes a tagged
abstract value (`ConfigCheck` / `ModLoadedCheck`) onto the operand stack, and a
conditional branch that consumes it sets the corresponding guard flag — so the
analysis *proves* the effect is gated rather than guessing.

Results feed `mixin_handler_effect` (`cancels`, `sets_return_value`,
`conditional_control`, `return_value_source`, `writes_target_state`,
`original_call_count`, and the `side_effects` list above), turning "references
CallbackInfo" into "*unconditionally* cancels and returns a constant" or
"config-gated world mutation that schedules async work". `original_call_count`
distinguishes the `@WrapOperation` dispositions: 0 = full replacement, 1 =
composable wrap, ≥ 2 = the original runs more than once.

## Complexity & bloat (per class / per mod)

Two transparent, **measured** scores (each the capped sum of named components, every
point attributable to a concrete cause — never an opaque heuristic):

- **Mixin Complexity Score** ([`complexity.rs`](crates/intermed-mixin-intel/src/complexity.rs)) —
  0–100 per class and per mod, measuring *how much* a mixin bends its targets:
  injection surface weighted by operation severity (overwrite > redirect > inject),
  peak handler complexity, target footprint, member coupling, reflection, hot-path.
  Facts `mixin_class_complexity` / `mixin_mod_complexity`; a `Note` finding fires
  for mods scoring ≥ 80.
- **Mixin Bloat** ([`bloat.rs`](crates/intermed-mixin-intel/src/bloat.rs)) — measures
  *low yield*: an **inert handler** has real bytecode (≥ 8 instructions) but
  provably changes nothing observable on its target (no return change, no
  cancel/CallbackInfo, no local mutation, no target field/method access — every
  guard must hold, so it is conservative). A mod with many inert handlers ships
  bytecode into hot classes for no measurable effect. Fact `mixin_bloat`; a `Note`
  fires at score ≥ 50 with ≥ 3 inert handlers.

Both surface in `mixin-map` ("Mixin Complexity Score (per mod)" / "Mixin bloat").

## Findings severity

| Condition | Severity |
|-----------|----------|
| Risk score ≤ 60 | Note |
| Risk score 61–80 | Warn |
| Risk score > 80 or Spark hot-method boost | Warn (elevated confidence) |
| Disjoint `site_key`s on same class | Note (via `method_conflict: false`) |

High-strength `mixin_interaction` facts (≥ 70) also surface as interaction findings.

### Effective effect + recommendations

[`effect.rs`](crates/intermed-mixin-intel/src/effect.rs) models the **effective behavioural
change** each injection imposes (`full-method-replacement`, `entry-modification`,
`exit-modification`, …) with a human `effect_description`.

[`recommendation.rs`](crates/intermed-mixin-intel/src/recommendation.rs) derives actionable
guidance with **concrete code snippets** and **documentation links** (Mixin wiki,
MixinExtras wiki). Three families:

- **Effect-level** — prefer `@Inject` / `@ModifyReturnValue` over **any** `@Overwrite`
  (confidence raised on hot paths), consolidate `@Redirect` storms into
  `@WrapOperation`, MixinExtras return/receiver guidance, and dataflow-backed advice:
  unconditional cancel shuts out stacked mixins, constant return value, target-state
  writes, **hot-path world mutation**, **async scheduled from a woven method**,
  **global static writes**, **allocation-heavy hot handlers**.
- **Conflict-taxonomy** — per edge type: convert an `@Overwrite` that locks out
  another mod's injectors, guard a `cancellable` HEAD that starves a RETURN injector,
  reconcile `@Redirect` vs `@WrapOperation`, and add `@Unique` to colliding members.
- **Apply-failure** — how to make a non-applying mixin apply: ship a refmap, drop a
  suspicious `remap = false`, rebuild against the right version, lower an out-of-range
  ordinal.

Facts carry optional `example` and `doc_url` attributes; `mixin-map` and
`intermed doctor --explain` print them inline.

Historical `log_mixin_correlation` facts optionally elevate severity when runtime logs
show similar mixin patterns on the same target.

## Facts emitted

| Kind | Meaning |
|------|---------|
| `mixin_config` | One config file in a jar |
| `mixin_class` | One mixin class with operations |
| `mixin_target` | Mod → target class edge |
| `mixin_operation` | Mod operation on a target |
| `mixin_hotspot` | Hot-path tag for a mixin |
| `mixin_injection_point` | Resolved site (`site_key`, `at_target`, `impact`, …) |
| `mixin_shadow` | `@Shadow` member expectation |
| `mixin_added_member` | Member added to target |
| `mixin_calls` | Reference into target (`provenance`) |
| `mixin_handler_body` | Handler bytecode summary (incl. `modifies_return_value`, `uses_callback_info`, …) |
| `mixin_handler_effect` | Semantic handler effect (`complexity_score`, `early_return`, …) |
| `mixin_effect` | Effective target-method change per injection site |
| `mixin_recommendation` | Safer-mixin advice bound to `site_key` |
| `mixin_hierarchy` | Known superclass/interface edge |
| `mixin_overlap` | Multiple mods share a target |
| `high_risk_overwrite` | `@Overwrite` against a target |
| `mixin_interaction` | Semantic interaction between two mixins |
| `mixin_conflict_edge` | Typed edge in the interaction graph |
| `mixin_priority_conflict` | Priority ordering conflict |
| `mixin_risk_score` | Composite 0–100 risk per target |
| `mixin_class_complexity` | Per-class complexity score + component breakdown |
| `mixin_mod_complexity` | Per-mod aggregate complexity score |
| `mixin_bloat` | Per-mod low-yield (inert-handler) footprint |
| `mixin_apply_target_method_missing` | Target method not found on the indexed class |
| `mixin_apply_require_unsatisfied` | …with `require ≥ 1` (confirmed load failure) |
| `mixin_apply_target_class_missing` | Target class absent (Minecraft jar indexed) |
| `mixin_apply_descriptor_mismatch` | `@Shadow` field type ≠ the real member |
| `mixin_apply_ordinal_out_of_range` | `@At(ordinal)` exceeds the call-site count |
| `mixin_apply_refmap_missing` | Named Minecraft target with no refmap |
| `mixin_apply_remap_false_suspicious` | `remap = false` on a Minecraft target |

`mixin_risk_score` carries `score` plus the axes `certainty`, `apply_failure`,
`semantic_conflict`, `blast_radius`, `fragility`, `actionability`.

## CLI

```bash
intermed doctor ./mods --mixin-risk
intermed doctor ./mods --mixin-risk --minecraft-jar ~/.cache/intermed/mc/1.20.1/client.jar
intermed mixin-map ./mods
```

`--minecraft-jar` broadens the apply-failure target index to vanilla classes so
mixins targeting Minecraft (not just other mods) are apply-checked.

`mixin-map` is **cluster-first**: it leads with **Top Mixin Clusters** (per target:
mods, risk + axis breakdown, top reasons, derived triage actions), then the detailed
overlaps, effects, recommendations, conflict edges, and apply failures below.

Datalog / Souffle / DuckDB backends reuse mixin facts; see [SCHEMA.md](SCHEMA.md).

## Cache

`CACHE_VERSION` trailing revision is bumped when parse or analysis logic changes
within a release (`-r22` at time of writing). The cache stores the per-jar parse
*partial* (now including the `TargetClassIndex` member + call-site data and the
deepened dataflow fields); interaction/risk/recommendation analysis is recomputed
each run.

## Not in scope

- Runtime mixin application or priority simulation
- Guaranteed Minecraft class hierarchy without target stubs in scanned jars
- Proving semantic equivalence of injection handlers (impact labels are heuristics)