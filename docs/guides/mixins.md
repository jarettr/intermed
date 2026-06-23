# Mixins

A mixin patches a class at load time. Two mods that patch the same method can
interact; a mixin that fully replaces a method locks others out; a mixin can
target something that is not there, or capture a local that has moved. InterMed
reads the mixin configs and the compiled handler bytecode and reports these
statically — without loading the game, and without ever running mod code.

## Turning it on

The mixin analysis is opt-in, because it reads bytecode and produces detail a
quick dependency check does not need:

```bash
intermed doctor ./mods --mixin-risk
intermed mixin-map ./mods            # the mixin view on its own
```

Depth is controlled by `--mixin-level`:

- `normal` — overlaps and risk only.
- `detailed` — adds recommendations (the default for the dedicated config).
- `full` — adds a per-handler effect summary for every injection point.

## The unit of analysis: the application site

Deep mixin analysis is not about the *mixin class* — it is about the **application
site**: one `handler → target method → injection point` tuple. A single mixin
class can host dozens of sites, and real failures live at the site level ("this
handler, on this target method, at this injection point"), not at the mod level.
Each site carries its side, activation, priority, and `require`/`expect`/`allow`
constraints, and a resolution confidence with the reasons behind it.

## What it checks: will the mixin apply?

These are load-time questions, answered from the classes InterMed has indexed:

- **Target present** — the target class and method exist. Method presence is
  resolved through the class hierarchy, so a mixin into an inherited method is not
  reported missing just because the method lives on a superclass.
- **Handler shape** — even when target and injection point resolve, a handler can
  still fail to apply because it has the wrong shape: an `@Inject` with no
  `CallbackInfo`, a `@ModifyReturnValue` returning `void`, a `@WrapOperation`
  missing its `Operation` parameter. These are descriptor-only checks that fire
  only on unambiguous violations — a flagged handler is a real load-time error,
  not a merely-unusual signature.
- **Local capture** — injectors that capture target-method locals
  (`@Inject(locals = …)`, `@ModifyVariable`, MixinExtras `@Local`) are among the
  most version-fragile mixins. The analysis asks whether the target method's frame
  is even recoverable (is the `LocalVariableTable` / `StackMapTable` present) and
  whether the captured type is declared. It flags the real hazard — an
  unrecoverable frame, which makes a `CAPTURE_FAILHARD` injector hard-crash —
  rather than guessing at an exact match.
- **Activation and side** — which config array a mixin came from (`mixins` /
  `client` / `server`), any Fabric/Quilt `environment`, and config-level plugin
  gating become a first-class side and activation status. A `client`-only and a
  `server`-only mixin into the same method are *not* counted as a conflict, and a
  plugin-gated mixin carries honest, lower certainty.
- **Refmap / namespace resolution** — whether a `remap = false` or no-refmap
  reference resolves depends on the loader's runtime namespace: Fabric/Quilt run
  against intermediary names, Forge/NeoForge against official names, and
  `com.mojang.*` library classes keep their real names everywhere. A reference is
  only flagged when it cannot resolve in the loader it actually runs under.

## What it reasons about: how the mixins interact

- **Overlap** — two mods inject into the same target method. Not necessarily a
  bug, but the place where order and composition matter.
- **`@Overwrite` effect** — a mixin fully replaces a method. Any other mod
  injecting there is locked out, and the overwrite breaks when the method changes
  upstream. `--explain` suggests a narrower `@Inject` / `@ModifyReturnValue` form,
  with a code example.
- **Composition and order** — pairwise overlap is not enough; what matters is the
  *order* handlers apply in and *how their roles compose*. The analysis groups the
  participants at one injection point, orders them by effective priority, assigns
  each a role, and classifies the group: two `@Redirect`s on one call are a
  near-certain conflict, two `@WrapOperation`s that each call the original once are
  a legal chain, and an unconditional cancel suppresses everything downstream.
- **Handler dataflow** — a small forward abstract interpreter models the operand
  stack and locals over a handler's bytecode to answer the questions that actually
  decide risk: does the handler *unconditionally* cancel the target, and what does
  it make the target return — a constant, an argument, or a value derived from the
  target's own state? A cancel or `setReturnValue` that is control-dependent on a
  branch is marked *conditional* rather than unconditional.
- **Subsystem reach** — a mod's mixin *targets* are the most honest statement of
  what it touches. A jar that calls itself a "tweak" but `@Overwrite`s
  `WorldRenderer` is a rendering mod; one woven into the network packet path is a
  network mod. Targets are classified into a subsystem, which yields a
  behaviour-grounded capability and a security-sensitivity flag when the subsystem
  is one where woven code is a real audit concern (networking, class loading,
  (de)serialization, save IO).
- **Risk cluster / complexity / bloat** — aggregate views: which target classes
  attract the most patches, which mods carry the heaviest mixin footprint, and
  which mods ship handlers that never do anything.

## How sure it is

Different checks have very different evidence behind them, and the report says so
rather than sounding equally certain everywhere:

- **Confirmation ladder** — every claim is graded by *how* it is backed, from a
  runtime log at the top down to a mod-level heuristic. Severity is derived from
  that grade plus impact and coverage: a missing method under a full classpath is
  an error; the same claim on an unresolved mapping is at most a warning.
- **Coverage trace** — `--explain` on a mixin finding lists what was actually
  checked and what was not — the difference between "confidence 0.55 because the
  target bytecode wasn't visible" and "confidence 0.95, fully verified".
- **Runtime-log confirmation** — if you pass a game log in which the same mixin
  actually failed to apply, a static *hypothesis* is upgraded to a *confirmed*
  finding. The log parser is deliberately conservative: a field it cannot extract
  is left empty rather than guessed.
- **Performance correlation** — with a Spark profile, a hot method is matched to a
  site by quality of fit; only a high-quality match on a destructive handler is
  allowed to drive a high-severity performance finding, so "this mod is slow"
  never masquerades as "this handler is the cause".

## Precision and its limits

The whole analysis stays within the classes it has indexed — the other mods in the
pack. Minecraft's own classes are only indexed when you supply them, so
vanilla-target checks are off by default and never produce a false positive:

```bash
intermed doctor ./mods --mixin-risk --minecraft-jar /path/to/minecraft.jar
intermed doctor ./mods --mixin-risk --minecraft-jar mc.jar --minecraft-mappings mappings.tiny
```

With the jar (and, for named targets, Yarn/Mojmap mappings), apply checks extend
to vanilla classes too.

Two limits are worth stating directly. First, this is static analysis: the
dataflow interpreter degrades to "unknown" at loops, mismatched stack merges, and
switches rather than guessing, so it never reports a concrete value it has not
proven — precision is sacrificed before soundness, every time. Second, it does not
load the game; a runtime log raises certainty when you supply one, but absent that,
every apply verdict is a well-evidenced hypothesis, not an execution result.

For the full flag list, see
[the command reference](../reference/commands.md#mixin-map). For how risk is
scored, see [What each analysis examines](../reference/analysis.md#mixins).
