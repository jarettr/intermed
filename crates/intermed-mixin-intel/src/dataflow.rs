//! Operand-stack / taint abstract interpretation for mixin handler bodies.
//!
//! [`crate::bytecode`] produces flat structural counters (how many branches, does
//! it reference `CallbackInfo`). That cannot answer the questions that actually
//! decide compatibility risk: does the handler *unconditionally* cancel the
//! target, and what does it make the target return — a constant, an argument, or
//! a value derived from the target's own state?
//!
//! This module answers them with a small **forward abstract interpreter**. It
//! models the JVM operand stack (slot-accurate, including category-2 longs and
//! doubles) and the local variable array over a handler's `Code`, propagating an
//! [`AbstractValue`] taint lattice from sources (parameters, `this`, target
//! fields, target call results, constants) to sinks (`setReturnValue`, `cancel`,
//! `PUTFIELD` on the target, typed returns).
//!
//! ## Control flow and soundness
//!
//! The pass walks instructions in order but is **flow-sensitive**: at a forward
//! control-flow merge it computes the *lattice join* of the predecessor states
//! (the state saved at each branch plus the fall-through), so a value both paths
//! agree on survives the merge with its provenance — only genuine disagreement
//! rises to [`AbstractValue::Unknown`]. This is what lets an `if (…) return 0;
//! else return 0;` still report a constant return.
//!
//! It **degrades conservatively** — clears the stack/locals to `Unknown` and sets
//! [`HandlerDataflow::imprecise`] — only where it truly cannot reconcile flow: a
//! loop header (the back-edge's state is unknown on a single forward pass), a
//! merge with mismatched operand-stack heights, or a switch. Structural booleans
//! (a `cancel` *was* invoked) come straight from the opcode and stay reliable
//! regardless. The interpreter therefore never reports a concrete [`ValueSource`]
//! it has not actually proven — precision is sacrificed before soundness, every
//! time. A separate `guarded` flag (set once execution is control-dependent on a
//! conditional branch) marks a cancel / `setReturnValue` as *conditional* rather
//! than unconditional, independent of value precision.

use std::collections::{BTreeMap, BTreeSet};

use cafebabe::attributes::CodeData;
use cafebabe::bytecode::Opcode;
use cafebabe::constant_pool::MemberRef;
use cafebabe::descriptors::{FieldType, MethodDescriptor};

use crate::model::{
    HandlerDataflow, ImpreciseReason, PrecisionLevel, TargetFieldWrite, ValueSource,
};

const CALLBACK_INFO: &str = "org/spongepowered/asm/mixin/injection/callback/CallbackInfo";
const CALLBACK_INFO_RETURNABLE: &str =
    "org/spongepowered/asm/mixin/injection/callback/CallbackInfoReturnable";

/// One word of abstract state on the operand stack or in a local slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbstractValue {
    /// Conservative top — provenance unknown.
    Unknown,
    /// Upper word of a category-2 (long/double) value.
    Top,
    /// A compile-time constant.
    Constant,
    /// A handler parameter (an injected argument or captured local).
    Argument,
    /// The `this` reference (slot 0 of an instance method).
    This,
    /// The injected `CallbackInfo` / `CallbackInfoReturnable` parameter.
    CallbackInfo,
    /// A value read from a target-class field.
    TargetField,
    /// The result of a call on the target class.
    TargetCall,
    /// An arithmetic / combined value.
    Computed,
    /// A freshly allocated object or array.
    NewObject,
    /// The boolean result of a config lookup (`*Config*.getBoolean(...)` etc.) —
    /// tracked so a branch on it marks the effect `config_guarded`.
    ConfigCheck,
    /// The boolean result of a mod-loaded check (`FabricLoader.isModLoaded`,
    /// `ModList.isLoaded`) — a branch on it marks the effect `mod_loaded_guarded`.
    ModLoadedCheck,
}

impl AbstractValue {
    /// Lattice join (least upper bound): equal values are preserved, disagreement
    /// rises to the conservative top `Unknown`. This is what lets a value that both
    /// predecessors of a control-flow merge agree on survive the join with its
    /// provenance intact, instead of every merge resetting to `Unknown`.
    fn join(self, other: AbstractValue) -> AbstractValue {
        use AbstractValue::*;
        if self == other {
            return self;
        }
        // Refined lattice (still sound — the join is the *least upper bound*):
        // a compile-time constant is a degenerate computed value, so
        // `Constant ⊔ Computed = Computed` instead of collapsing to `Unknown`.
        // This keeps `if (c) return 5; else return x+1;` resolving to a
        // (non-tainted, non-target) `Computed` source rather than `Unknown`.
        match (self, other) {
            (Constant, Computed) | (Computed, Constant) => Computed,
            _ => Unknown,
        }
    }

    fn to_source(self) -> ValueSource {
        match self {
            AbstractValue::Constant => ValueSource::Constant,
            AbstractValue::Argument => ValueSource::Argument,
            AbstractValue::This => ValueSource::ThisRef,
            AbstractValue::TargetField => ValueSource::TargetField,
            AbstractValue::TargetCall => ValueSource::TargetCallResult,
            AbstractValue::Computed
            | AbstractValue::ConfigCheck
            | AbstractValue::ModLoadedCheck => ValueSource::Computed,
            AbstractValue::NewObject => ValueSource::NewObject,
            AbstractValue::Unknown | AbstractValue::Top | AbstractValue::CallbackInfo => {
                ValueSource::Unknown
            }
        }
    }

    /// Whether this value is handler-controlled data flowing in from outside the
    /// target (used to decide if a target call is fed tainted arguments).
    fn is_handler_controlled(self) -> bool {
        matches!(self, AbstractValue::Argument | AbstractValue::This)
    }
}

/// Slot-accurate abstract operand stack. Category-2 values occupy two words: the
/// value in the lower slot and an [`AbstractValue::Top`] filler above it.
#[derive(Clone, PartialEq)]
struct Stack {
    words: Vec<AbstractValue>,
}

impl Stack {
    fn new() -> Self {
        Self { words: Vec::new() }
    }
    fn push1(&mut self, v: AbstractValue) {
        self.words.push(v);
    }
    /// Push a value of the given width (2 = category-2 long/double).
    fn push_value(&mut self, v: AbstractValue, width: u8) {
        self.words.push(v);
        if width == 2 {
            self.words.push(AbstractValue::Top);
        }
    }
    fn pop1(&mut self) -> AbstractValue {
        self.words.pop().unwrap_or(AbstractValue::Unknown)
    }
    /// Pop one logical value, transparently consuming a category-2 `Top` filler.
    fn pop_value(&mut self) -> AbstractValue {
        match self.words.pop() {
            Some(AbstractValue::Top) => self.words.pop().unwrap_or(AbstractValue::Unknown),
            Some(v) => v,
            None => AbstractValue::Unknown,
        }
    }
    /// Element-wise lattice join with another stack. `None` when the operand-stack
    /// heights differ — an irreducible merge the linear model cannot reconcile, so
    /// the caller degrades conservatively.
    fn join(&self, other: &Stack) -> Option<Stack> {
        if self.words.len() != other.words.len() {
            return None;
        }
        Some(Stack {
            words: self
                .words
                .iter()
                .zip(&other.words)
                .map(|(a, b)| a.join(*b))
                .collect(),
        })
    }
}

/// Local variable array. Category-2 values set the lower slot to the value and
/// the upper slot to `Top`.
#[derive(Clone, PartialEq)]
struct Locals {
    slots: Vec<AbstractValue>,
}

impl Locals {
    fn get(&self, index: usize) -> AbstractValue {
        self.slots
            .get(index)
            .copied()
            .unwrap_or(AbstractValue::Unknown)
    }
    fn set(&mut self, index: usize, v: AbstractValue, width: u8) {
        if index >= self.slots.len() {
            self.slots
                .resize(index + width as usize, AbstractValue::Unknown);
        }
        self.slots[index] = v;
        if width == 2 && index + 1 < self.slots.len() {
            self.slots[index + 1] = AbstractValue::Top;
        }
    }
    /// Element-wise lattice join with another local array, padding the shorter
    /// with `Unknown` (a slot live on only one path is unknown after the merge).
    fn join(&self, other: &Locals) -> Locals {
        let len = self.slots.len().max(other.slots.len());
        let slots = (0..len)
            .map(|i| {
                let a = self.slots.get(i).copied().unwrap_or(AbstractValue::Unknown);
                let b = other
                    .slots
                    .get(i)
                    .copied()
                    .unwrap_or(AbstractValue::Unknown);
                a.join(b)
            })
            .collect();
        Locals { slots }
    }
}

/// Abstract machine state (operand stack + locals + control-dependence) at one
/// program point, carried along control-flow edges and merged at join points.
#[derive(Clone, PartialEq)]
struct State {
    stack: Stack,
    locals: Locals,
    /// Control-dependent on a conditional branch: any cancel / `setReturnValue`
    /// reached here is *conditional*, not unconditional. Joined with OR — a point
    /// is unguarded only if *every* path to it is unguarded (sound: we never claim
    /// "unconditional" unless it provably always executes).
    guarded: bool,
}

impl State {
    /// Lattice join of two states. Returns `None` when operand-stack heights differ
    /// (an irreducible merge — should not occur in verifier-valid bytecode, but is
    /// handled conservatively if it does).
    fn join(&self, other: &State) -> Option<State> {
        Some(State {
            stack: self.stack.join(&other.stack)?,
            locals: self.locals.join(&other.locals),
            guarded: self.guarded || other.guarded,
        })
    }

    /// Widen to the conservative top: every word/local becomes `Unknown` (keeping
    /// category-2 `Top` fillers and stack height). Forces fixpoint convergence as a
    /// backstop when a point is revisited too many times.
    fn widen(&self) -> State {
        State {
            stack: Stack {
                words: self
                    .stack
                    .words
                    .iter()
                    .map(|w| {
                        if *w == AbstractValue::Top {
                            AbstractValue::Top
                        } else {
                            AbstractValue::Unknown
                        }
                    })
                    .collect(),
            },
            locals: Locals {
                slots: self
                    .locals
                    .slots
                    .iter()
                    .map(|s| {
                        if *s == AbstractValue::Top {
                            AbstractValue::Top
                        } else {
                            AbstractValue::Unknown
                        }
                    })
                    .collect(),
            },
            guarded: self.guarded,
        }
    }
}

/// Abstractly interpret one handler body and summarise its taint behaviour.
///
/// `target_internal_names` are the mixin's target classes in internal (slash)
/// form, used to recognise reads/writes/calls that touch target state.
pub fn analyze_handler_dataflow(
    code: &CodeData<'_>,
    descriptor: &MethodDescriptor<'_>,
    is_static: bool,
    target_internal_names: &BTreeSet<String>,
) -> Option<HandlerDataflow> {
    let bytecode = code.bytecode.as_ref()?;

    let mut df = HandlerDataflow::default();
    let opcodes = &bytecode.opcodes;
    if opcodes.is_empty() {
        return Some(df);
    }

    // Phase 2: a proper **worklist fixpoint**. We compute the abstract state
    // *entering* each instruction by iterating control-flow edges (including loop
    // back-edges and switch successors) to a fixpoint, then extract effects in a
    // single pass using those converged states. Loops and switches therefore
    // converge instead of degrading; the small finite-height lattice guarantees
    // termination, and a per-offset visit cap widens to conservative as a backstop.
    let entry = State {
        stack: Stack::new(),
        locals: Locals {
            slots: init_locals(descriptor, is_static),
        },
        guarded: false,
    };
    let in_states = run_fixpoint(opcodes, entry, code, target_internal_names, &mut df);

    // Extraction pass: apply each reachable instruction once, in its converged
    // entry state, accumulating the handler's effects.
    let mut branch_seen = false;
    let mut cir_return: Option<ValueSource> = None;
    let mut typed_return: Option<ValueSource> = None;
    let mut writes: BTreeMap<String, ValueSource> = BTreeMap::new();
    for (offset, opcode) in opcodes.iter() {
        let Some(state) = in_states.get(offset) else {
            continue; // unreachable instruction — no effect
        };
        let mut stack = state.stack.clone();
        let mut locals = state.locals.clone();
        apply_opcode(
            opcode,
            &mut stack,
            &mut locals,
            target_internal_names,
            &mut df,
            &mut branch_seen,
            &mut cir_return,
            &mut typed_return,
            &mut writes,
            state.guarded,
        );
    }

    df.return_value_source = cir_return.or(typed_return).unwrap_or(ValueSource::Unknown);
    df.target_field_writes = writes
        .into_iter()
        .map(|(field, source)| TargetFieldWrite { field, source })
        .collect();

    // `logs_only`: the handler invokes a logger and has no other observable
    // effect — a pure diagnostic injection, the lowest-risk shape.
    let calls_logger = opcodes.iter().any(|(_, op)| match op {
        Opcode::Invokevirtual(m)
        | Opcode::Invokeinterface(m, _)
        | Opcode::Invokespecial(m)
        | Opcode::Invokestatic(m) => is_logging_call(m.class_name.as_ref()),
        _ => false,
    });
    df.logs_only = calls_logger
        && !df.cancels
        && !df.sets_return_value
        && df.target_field_writes.is_empty()
        && !df.mutates_world
        && !df.schedules_async
        && !df.writes_global_state
        && !df.forwards_args_to_target
        && !df.unconditional_throw;

    // The abstract interpreter ran, so provenance is resolved; value sources are
    // trustworthy only where the analysis did not degrade. Later passes (pattern
    // matching, cross-layer) raise this further.
    df.precision = if df.imprecise {
        PrecisionLevel::Provenance
    } else {
        PrecisionLevel::ValueSource
    };
    df.confidence = if df.imprecise { 55 } else { 85 };

    // Pass 4 — pattern refinement: recognise high-reliability handler shapes and
    // raise confidence (precision only ever increases). Sound: it never adds a
    // precise claim, only scores how well-understood the resolved shape is.
    refine_with_patterns(&mut df);

    Some(df)
}

/// Lightweight post-pass over the resolved dataflow. Bumps confidence for handler
/// shapes whose behaviour is well-understood, so the report can rank "we are sure
/// this is benign/decisive" above a merely-resolved result (plan §1 Pass 4).
fn refine_with_patterns(df: &mut HandlerDataflow) {
    // A pure diagnostic injection: nothing observable but a log call. The safest
    // shape there is — high confidence regardless of branch structure.
    if df.logs_only {
        df.confidence = df.confidence.max(95);
        return;
    }
    // A guard read from config / mod-loaded is a recognised, intentional gate;
    // the conditional effect is exactly what the author meant.
    if (df.config_guarded || df.mod_loaded_guarded) && df.conditional_control {
        df.confidence = df.confidence.max(90);
    }
    // A fully-resolved decisive short-circuit (cancel / set-return with a concrete
    // value source, no degradation) is a high-certainty behavioural claim.
    if !df.imprecise
        && (df.cancels || df.sets_return_value)
        && df.return_value_source != ValueSource::Unknown
    {
        df.confidence = df.confidence.max(92);
    }
}

/// Maximum times a single program point is re-entered before its incoming state
/// is widened to conservative — a termination backstop. The lattice is already
/// finite-height (`Constant ⊑ Computed ⊑ Unknown`, fixed stack height), so
/// well-behaved methods converge in 1–3 visits; this only guards pathological CFGs.
const MAX_VISITS_PER_OFFSET: u32 = 24;

/// Worklist fixpoint: compute the abstract state *entering* each reachable
/// instruction, iterating control-flow edges (forward, back, and switch) until
/// nothing changes. Exception-handler entries are seeded conservatively so their
/// bodies are analysed soundly rather than dropped as unreachable.
fn run_fixpoint(
    opcodes: &[(usize, Opcode<'_>)],
    entry: State,
    code: &CodeData<'_>,
    targets: &BTreeSet<String>,
    df: &mut HandlerDataflow,
) -> BTreeMap<usize, State> {
    use std::collections::VecDeque;

    let offset_to_idx: BTreeMap<usize, usize> = opcodes
        .iter()
        .enumerate()
        .map(|(i, (o, _))| (*o, i))
        .collect();

    let mut in_states: BTreeMap<usize, State> = BTreeMap::new();
    let mut visits: BTreeMap<usize, u32> = BTreeMap::new();
    let mut worklist: VecDeque<usize> = VecDeque::new();

    let seed = |off: usize,
                st: State,
                in_states: &mut BTreeMap<usize, State>,
                worklist: &mut VecDeque<usize>| {
        if !offset_to_idx.contains_key(&off) {
            return;
        }
        let merged = match in_states.get(&off) {
            Some(existing) => existing.join(&st).unwrap_or_else(|| st.clone()),
            None => st,
        };
        if in_states.get(&off) != Some(&merged) {
            in_states.insert(off, merged);
            if !worklist.contains(&off) {
                worklist.push_back(off);
            }
        }
    };

    seed(opcodes[0].0, entry, &mut in_states, &mut worklist);

    // Conservative seeds for exception-handler entries (basic exception handling).
    let local_count = code.max_locals as usize;
    for h in &code.exception_table {
        let handler = State {
            stack: Stack {
                words: vec![AbstractValue::Unknown], // the caught throwable
            },
            locals: Locals {
                slots: vec![AbstractValue::Unknown; local_count],
            },
            guarded: true, // a handler runs only on the exceptional path
        };
        seed(
            h.handler_pc as usize,
            handler,
            &mut in_states,
            &mut worklist,
        );
    }

    while let Some(off) = worklist.pop_front() {
        let Some(&idx) = offset_to_idx.get(&off) else {
            continue;
        };
        let (_, opcode) = &opcodes[idx];
        // Transfer: apply the opcode to the entering state to get the out-state.
        // A scratch `df` discards effects here — they are extracted later, once.
        let mut state = in_states[&off].clone();
        let mut scratch = HandlerDataflow::default();
        apply_opcode(
            opcode,
            &mut state.stack,
            &mut state.locals,
            targets,
            &mut scratch,
            &mut false,
            &mut None,
            &mut None,
            &mut BTreeMap::new(),
            state.guarded,
        );
        let branch = is_conditional_branch(opcode);
        for succ in successors(idx, off, opcode, opcodes) {
            let mut succ_state = state.clone();
            if branch {
                succ_state.guarded = true;
            }
            let v = visits.entry(succ).or_insert(0);
            *v += 1;
            if *v > MAX_VISITS_PER_OFFSET {
                df.degrade(ImpreciseReason::WideningCap);
                succ_state = succ_state.widen();
            }
            seed(succ, succ_state, &mut in_states, &mut worklist);
        }
    }

    in_states
}

/// The successor program-point offsets of an instruction: branch / switch targets
/// and (unless control cannot fall through) the next instruction.
fn successors(
    idx: usize,
    offset: usize,
    opcode: &Opcode<'_>,
    opcodes: &[(usize, Opcode<'_>)],
) -> Vec<usize> {
    let mut out = Vec::new();
    match opcode {
        Opcode::Tableswitch(_) | Opcode::Lookupswitch(_) => {
            out.extend(switch_targets(offset, opcode));
        }
        _ => {
            if let Some(rel) = branch_offset(opcode) {
                let dest = offset as i64 + rel as i64;
                if dest >= 0 {
                    out.push(dest as usize);
                }
            }
        }
    }
    if falls_through(opcode) {
        if let Some((next_off, _)) = opcodes.get(idx + 1) {
            out.push(*next_off);
        }
    }
    out
}

/// Absolute offsets of every arm of a `tableswitch` / `lookupswitch` (default +
/// cases), so the fixpoint reaches switch successors instead of degrading.
fn switch_targets(offset: usize, opcode: &Opcode<'_>) -> Vec<usize> {
    let rels: Vec<i32> = match opcode {
        Opcode::Lookupswitch(t) => std::iter::once(t.default)
            .chain(t.match_offsets.iter().map(|(_, o)| *o))
            .collect(),
        Opcode::Tableswitch(t) => std::iter::once(t.default)
            .chain(t.jumps.iter().copied())
            .collect(),
        _ => Vec::new(),
    };
    rels.into_iter()
        .filter_map(|rel| {
            let dest = offset as i64 + rel as i64;
            (dest >= 0).then_some(dest as usize)
        })
        .collect()
}

/// Seed the local array with parameter provenance: slot 0 is `this` for instance
/// methods, then each parameter (category-2 types span two slots).
fn init_locals(descriptor: &MethodDescriptor<'_>, is_static: bool) -> Vec<AbstractValue> {
    let mut slots = Vec::new();
    if !is_static {
        slots.push(AbstractValue::This);
    }
    for param in &descriptor.parameters {
        let value = if param.dimensions == 0 && is_callback_info_type(&param.field_type) {
            AbstractValue::CallbackInfo
        } else {
            AbstractValue::Argument
        };
        slots.push(value);
        if param.dimensions == 0 && is_category_two(&param.field_type) {
            slots.push(AbstractValue::Top);
        }
    }
    slots
}

fn is_callback_info_type(ty: &FieldType<'_>) -> bool {
    if let FieldType::Object(_) = ty {
        let rendered = format!("{ty}");
        rendered.contains("CallbackInfo")
    } else {
        false
    }
}

fn is_category_two(ty: &FieldType<'_>) -> bool {
    matches!(ty, FieldType::Long | FieldType::Double)
}

/// Whether an opcode lets control fall through to the next instruction. `goto`,
/// `return`/`athrow`, switches and `ret` do not.
fn falls_through(opcode: &Opcode<'_>) -> bool {
    !matches!(
        opcode,
        Opcode::Goto(_)
            | Opcode::Jsr(_)
            | Opcode::Ret(_)
            | Opcode::Ireturn
            | Opcode::Lreturn
            | Opcode::Freturn
            | Opcode::Dreturn
            | Opcode::Areturn
            | Opcode::Return
            | Opcode::Athrow
            | Opcode::Tableswitch(_)
            | Opcode::Lookupswitch(_)
    )
}

/// Lattice join of return-value provenance across multiple return sites: agreeing
/// sources are preserved, disagreement rises to `Unknown`.
fn join_source(acc: Option<ValueSource>, v: ValueSource) -> Option<ValueSource> {
    use ValueSource::{Computed, Constant};
    Some(match acc {
        None => v,
        Some(a) if a == v => a,
        // Mirror the operand lattice: a constant is a degenerate computed value.
        Some(Constant) if v == Computed => Computed,
        Some(Computed) if v == Constant => Computed,
        Some(_) => ValueSource::Unknown,
    })
}

fn branch_offset(opcode: &Opcode<'_>) -> Option<i32> {
    match opcode {
        Opcode::Ifeq(o)
        | Opcode::Ifne(o)
        | Opcode::Iflt(o)
        | Opcode::Ifge(o)
        | Opcode::Ifgt(o)
        | Opcode::Ifle(o)
        | Opcode::IfIcmpeq(o)
        | Opcode::IfIcmpne(o)
        | Opcode::IfIcmplt(o)
        | Opcode::IfIcmpge(o)
        | Opcode::IfIcmpgt(o)
        | Opcode::IfIcmple(o)
        | Opcode::IfAcmpeq(o)
        | Opcode::IfAcmpne(o)
        | Opcode::Ifnull(o)
        | Opcode::Ifnonnull(o)
        | Opcode::Goto(o)
        | Opcode::Jsr(o) => Some(*o),
        _ => None,
    }
}

fn is_conditional_branch(opcode: &Opcode<'_>) -> bool {
    matches!(
        opcode,
        Opcode::Ifeq(_)
            | Opcode::Ifne(_)
            | Opcode::Iflt(_)
            | Opcode::Ifge(_)
            | Opcode::Ifgt(_)
            | Opcode::Ifle(_)
            | Opcode::IfIcmpeq(_)
            | Opcode::IfIcmpne(_)
            | Opcode::IfIcmplt(_)
            | Opcode::IfIcmpge(_)
            | Opcode::IfIcmpgt(_)
            | Opcode::IfIcmple(_)
            | Opcode::IfAcmpeq(_)
            | Opcode::IfAcmpne(_)
            | Opcode::Ifnull(_)
            | Opcode::Ifnonnull(_)
            | Opcode::Tableswitch(_)
            | Opcode::Lookupswitch(_)
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_opcode(
    opcode: &Opcode<'_>,
    stack: &mut Stack,
    locals: &mut Locals,
    targets: &BTreeSet<String>,
    df: &mut HandlerDataflow,
    branch_seen: &mut bool,
    cir_return: &mut Option<ValueSource>,
    typed_return: &mut Option<ValueSource>,
    writes: &mut BTreeMap<String, ValueSource>,
    guarded: bool,
) {
    use AbstractValue as V;

    if is_conditional_branch(opcode) {
        *branch_seen = true;
    }

    match opcode {
        // ── constants ──────────────────────────────────────────────────────
        Opcode::AconstNull
        | Opcode::IconstM1
        | Opcode::Iconst0
        | Opcode::Iconst1
        | Opcode::Iconst2
        | Opcode::Iconst3
        | Opcode::Iconst4
        | Opcode::Iconst5
        | Opcode::Fconst0
        | Opcode::Fconst1
        | Opcode::Fconst2
        | Opcode::Bipush(_)
        | Opcode::Sipush(_) => stack.push_value(V::Constant, 1),
        Opcode::Lconst0 | Opcode::Lconst1 | Opcode::Dconst0 | Opcode::Dconst1 => {
            stack.push_value(V::Constant, 2)
        }
        Opcode::Ldc(_) | Opcode::LdcW(_) => stack.push_value(V::Constant, 1),
        Opcode::Ldc2W(_) => stack.push_value(V::Constant, 2),

        // ── loads ──────────────────────────────────────────────────────────
        Opcode::Iload(i) | Opcode::Fload(i) | Opcode::Aload(i) => {
            stack.push_value(locals.get(*i as usize), 1)
        }
        Opcode::Lload(i) | Opcode::Dload(i) => stack.push_value(locals.get(*i as usize), 2),
        Opcode::Iaload
        | Opcode::Faload
        | Opcode::Aaload
        | Opcode::Baload
        | Opcode::Caload
        | Opcode::Saload => {
            stack.pop_value(); // index
            stack.pop_value(); // arrayref
            stack.push_value(V::Computed, 1);
        }
        Opcode::Laload | Opcode::Daload => {
            stack.pop_value();
            stack.pop_value();
            stack.push_value(V::Computed, 2);
        }

        // ── stores ─────────────────────────────────────────────────────────
        Opcode::Istore(i) | Opcode::Fstore(i) | Opcode::Astore(i) => {
            let v = stack.pop_value();
            locals.set(*i as usize, v, 1);
        }
        Opcode::Lstore(i) | Opcode::Dstore(i) => {
            let v = stack.pop_value();
            locals.set(*i as usize, v, 2);
        }
        Opcode::Iastore
        | Opcode::Fastore
        | Opcode::Aastore
        | Opcode::Bastore
        | Opcode::Castore
        | Opcode::Sastore => {
            stack.pop_value();
            stack.pop_value();
            stack.pop_value();
        }
        Opcode::Lastore | Opcode::Dastore => {
            stack.pop_value();
            stack.pop_value();
            stack.pop_value();
        }
        Opcode::Iinc(i, _) => locals.set(*i as usize, V::Computed, 1),

        // ── stack manipulation (word-accurate) ─────────────────────────────
        Opcode::Pop => {
            stack.pop1();
        }
        Opcode::Pop2 => {
            stack.pop1();
            stack.pop1();
        }
        Opcode::Dup => {
            let t = stack.pop1();
            stack.push1(t);
            stack.push1(t);
        }
        Opcode::DupX1 => {
            let a = stack.pop1();
            let b = stack.pop1();
            stack.push1(a);
            stack.push1(b);
            stack.push1(a);
        }
        Opcode::DupX2 => {
            let a = stack.pop1();
            let b = stack.pop1();
            let c = stack.pop1();
            stack.push1(a);
            stack.push1(c);
            stack.push1(b);
            stack.push1(a);
        }
        Opcode::Dup2 => {
            let a = stack.pop1();
            let b = stack.pop1();
            stack.push1(b);
            stack.push1(a);
            stack.push1(b);
            stack.push1(a);
        }
        Opcode::Dup2X1 => {
            let a = stack.pop1();
            let b = stack.pop1();
            let c = stack.pop1();
            stack.push1(b);
            stack.push1(a);
            stack.push1(c);
            stack.push1(b);
            stack.push1(a);
        }
        Opcode::Dup2X2 => {
            let a = stack.pop1();
            let b = stack.pop1();
            let c = stack.pop1();
            let d = stack.pop1();
            stack.push1(b);
            stack.push1(a);
            stack.push1(d);
            stack.push1(c);
            stack.push1(b);
            stack.push1(a);
        }
        Opcode::Swap => {
            let a = stack.pop1();
            let b = stack.pop1();
            stack.push1(a);
            stack.push1(b);
        }

        // ── arithmetic / logic (narrow) ────────────────────────────────────
        Opcode::Iadd
        | Opcode::Isub
        | Opcode::Imul
        | Opcode::Idiv
        | Opcode::Irem
        | Opcode::Iand
        | Opcode::Ior
        | Opcode::Ixor
        | Opcode::Ishl
        | Opcode::Ishr
        | Opcode::Iushr
        | Opcode::Fadd
        | Opcode::Fsub
        | Opcode::Fmul
        | Opcode::Fdiv
        | Opcode::Frem => {
            stack.pop_value();
            stack.pop_value();
            stack.push_value(V::Computed, 1);
        }
        Opcode::Ineg | Opcode::Fneg => {
            stack.pop_value();
            stack.push_value(V::Computed, 1);
        }
        // ── arithmetic / logic (wide) ──────────────────────────────────────
        Opcode::Ladd
        | Opcode::Lsub
        | Opcode::Lmul
        | Opcode::Ldiv
        | Opcode::Lrem
        | Opcode::Land
        | Opcode::Lor
        | Opcode::Lxor
        | Opcode::Dadd
        | Opcode::Dsub
        | Opcode::Dmul
        | Opcode::Ddiv
        | Opcode::Drem => {
            stack.pop_value();
            stack.pop_value();
            stack.push_value(V::Computed, 2);
        }
        Opcode::Lshl | Opcode::Lshr | Opcode::Lushr => {
            stack.pop_value(); // int shift amount
            stack.pop_value(); // long value
            stack.push_value(V::Computed, 2);
        }
        Opcode::Lneg | Opcode::Dneg => {
            stack.pop_value();
            stack.push_value(V::Computed, 2);
        }

        // ── conversions ────────────────────────────────────────────────────
        Opcode::I2l | Opcode::I2d | Opcode::F2l | Opcode::F2d => {
            stack.pop_value();
            stack.push_value(V::Computed, 2);
        }
        Opcode::L2i | Opcode::L2f | Opcode::D2i | Opcode::D2f => {
            stack.pop_value();
            stack.push_value(V::Computed, 1);
        }
        Opcode::I2f | Opcode::I2b | Opcode::I2c | Opcode::I2s | Opcode::F2i => {
            stack.pop_value();
            stack.push_value(V::Computed, 1);
        }
        Opcode::L2d | Opcode::D2l => {
            stack.pop_value();
            stack.push_value(V::Computed, 2);
        }

        // ── comparisons ────────────────────────────────────────────────────
        Opcode::Lcmp | Opcode::Dcmpg | Opcode::Dcmpl => {
            stack.pop_value();
            stack.pop_value();
            stack.push_value(V::Computed, 1);
        }
        Opcode::Fcmpg | Opcode::Fcmpl => {
            stack.pop_value();
            stack.pop_value();
            stack.push_value(V::Computed, 1);
        }

        // ── branches ───────────────────────────────────────────────────────
        Opcode::Ifeq(_)
        | Opcode::Ifne(_)
        | Opcode::Iflt(_)
        | Opcode::Ifge(_)
        | Opcode::Ifgt(_)
        | Opcode::Ifle(_)
        | Opcode::Ifnull(_)
        | Opcode::Ifnonnull(_) => {
            // Classify the guard by the provenance of the tested value, so the
            // effect can be reported as config- / mod-loaded-gated.
            match stack.pop_value() {
                V::ConfigCheck => df.config_guarded = true,
                V::ModLoadedCheck => df.mod_loaded_guarded = true,
                _ => {}
            }
        }
        Opcode::IfIcmpeq(_)
        | Opcode::IfIcmpne(_)
        | Opcode::IfIcmplt(_)
        | Opcode::IfIcmpge(_)
        | Opcode::IfIcmpgt(_)
        | Opcode::IfIcmple(_)
        | Opcode::IfAcmpeq(_)
        | Opcode::IfAcmpne(_) => {
            stack.pop_value();
            stack.pop_value();
        }
        Opcode::Tableswitch(_) | Opcode::Lookupswitch(_) => {
            // The fixpoint enumerates switch successors via the CFG, so the body of
            // every arm is analysed — no conservative degradation needed here.
            stack.pop_value();
        }
        Opcode::Goto(_)
        | Opcode::Jsr(_)
        | Opcode::Ret(_)
        | Opcode::Nop
        | Opcode::Breakpoint
        | Opcode::Impdep1
        | Opcode::Impdep2 => {}

        // ── returns ────────────────────────────────────────────────────────
        Opcode::Ireturn | Opcode::Freturn | Opcode::Areturn | Opcode::Lreturn | Opcode::Dreturn => {
            let v = stack.pop_value();
            *typed_return = join_source(*typed_return, v.to_source());
        }
        Opcode::Return => {}
        Opcode::Athrow => {
            // An unguarded throw aborts the target method unconditionally.
            if !guarded {
                df.unconditional_throw = true;
            }
            stack.pop_value();
        }

        // ── fields ─────────────────────────────────────────────────────────
        Opcode::Getstatic(m) => {
            let source = if targets.contains(m.class_name.as_ref()) {
                V::TargetField
            } else {
                V::Computed
            };
            stack.push_value(source, field_width(member_descriptor(m)));
        }
        Opcode::Getfield(m) => {
            stack.pop_value(); // objectref
            let source = if targets.contains(m.class_name.as_ref()) {
                V::TargetField
            } else {
                V::Computed
            };
            stack.push_value(source, field_width(member_descriptor(m)));
        }
        Opcode::Putstatic(m) => {
            let v = stack.pop_value();
            record_field_write(m, v, targets, writes);
            // A static write outside the target class is global-state mutation.
            if !targets.contains(m.class_name.as_ref()) {
                df.writes_global_state = true;
            }
        }
        Opcode::Putfield(m) => {
            let v = stack.pop_value();
            stack.pop_value(); // objectref
            record_field_write(m, v, targets, writes);
        }

        // ── invocations ────────────────────────────────────────────────────
        Opcode::Invokevirtual(m) | Opcode::Invokeinterface(m, _) | Opcode::Invokespecial(m) => {
            apply_invoke(m, false, stack, targets, df, cir_return, guarded);
        }
        Opcode::Invokestatic(m) => {
            apply_invoke(m, true, stack, targets, df, cir_return, guarded);
        }
        Opcode::Invokedynamic(indy) => {
            let (param_count, ret) = parse_descriptor(indy.name_and_type.descriptor.as_ref());
            for _ in 0..param_count {
                stack.pop_value();
            }
            push_return(stack, ret, V::NewObject);
        }

        // ── object / array creation ────────────────────────────────────────
        Opcode::New(_) => {
            df.allocation_count = df.allocation_count.saturating_add(1);
            stack.push_value(V::NewObject, 1);
        }
        Opcode::Newarray(_) | Opcode::Anewarray(_) => {
            df.allocation_count = df.allocation_count.saturating_add(1);
            stack.pop_value();
            stack.push_value(V::NewObject, 1);
        }
        Opcode::Multianewarray(_, dims) => {
            df.allocation_count = df.allocation_count.saturating_add(1);
            for _ in 0..*dims {
                stack.pop_value();
            }
            stack.push_value(V::NewObject, 1);
        }
        Opcode::Arraylength | Opcode::Instanceof(_) => {
            stack.pop_value();
            stack.push_value(V::Computed, 1);
        }
        Opcode::Checkcast(_) => { /* type-only: leaves the operand unchanged */ }
        Opcode::Monitorenter | Opcode::Monitorexit => {
            stack.pop_value();
        }
    }
}

/// Apply an `invoke*`: pop arguments + receiver, recognise `CallbackInfo` sinks
/// and target-call taint, and push the typed result.
fn apply_invoke(
    member: &MemberRef<'_>,
    is_static: bool,
    stack: &mut Stack,
    targets: &BTreeSet<String>,
    df: &mut HandlerDataflow,
    cir_return: &mut Option<ValueSource>,
    guarded: bool,
) {
    use AbstractValue as V;

    let owner = member.class_name.as_ref();
    let name = member.name_and_type.name.as_ref();
    let (param_count, ret) = parse_descriptor(member.name_and_type.descriptor.as_ref());

    // Arguments are popped innermost-last; collect in declaration order.
    let mut args: Vec<AbstractValue> = (0..param_count).map(|_| stack.pop_value()).collect();
    args.reverse();
    let receiver = if is_static {
        None
    } else {
        Some(stack.pop_value())
    };

    let is_callback_owner = owner == CALLBACK_INFO || owner == CALLBACK_INFO_RETURNABLE;
    if is_callback_owner {
        match name {
            "cancel" => {
                df.cancels = true;
                df.conditional_control |= guarded;
            }
            "setReturnValue" => {
                df.sets_return_value = true;
                df.conditional_control |= guarded;
                let source = args.first().map_or(ValueSource::Unknown, |v| v.to_source());
                *cir_return = join_source(*cir_return, source);
            }
            // `getReturnValue()` reads the value the target method would have
            // returned — provenance is the *target's own result*. Modeling it lets
            // `setReturnValue(getReturnValue() + …)` resolve to a target-derived
            // value instead of `Unknown`.
            "getReturnValue" => {
                push_return(stack, ret, V::TargetCall);
                return;
            }
            _ => {}
        }
    }

    let into_target = targets.contains(owner);
    if into_target {
        let receiver_tainted = receiver.is_some_and(AbstractValue::is_handler_controlled);
        if receiver_tainted || args.iter().any(|a| a.is_handler_controlled()) {
            df.forwards_args_to_target = true;
        }
    }

    // Semantic side-effect classification (deepened analysis): recognise async
    // scheduling, world mutation, and config / mod-loaded guards by their API.
    let category = classify_invoke(owner, name);
    match category {
        InvokeCategory::Async => df.schedules_async = true,
        InvokeCategory::WorldMutation => df.mutates_world = true,
        InvokeCategory::ConfigCheck => {
            push_return(stack, ret, V::ConfigCheck);
            return;
        }
        InvokeCategory::ModLoadedCheck => {
            push_return(stack, ret, V::ModLoadedCheck);
            return;
        }
        InvokeCategory::Logging | InvokeCategory::Other => {}
    }

    let result = if into_target {
        V::TargetCall
    } else {
        V::Computed
    };
    push_return(stack, ret, result);
}

/// Coarse semantic category of an invoked method, by owner + name patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvokeCategory {
    Async,
    WorldMutation,
    ConfigCheck,
    ModLoadedCheck,
    Logging,
    Other,
}

/// True for a logger call (used for the `logs_only` end-of-body classification).
fn is_logging_call(owner: &str) -> bool {
    owner.starts_with("org/slf4j/")
        || owner.starts_with("org/apache/logging/log4j/")
        || owner.ends_with("/Logger")
        || owner == "java/io/PrintStream"
}

fn classify_invoke(owner: &str, name: &str) -> InvokeCategory {
    // Mod-loaded checks (Fabric `isModLoaded`, Forge/NeoForge `ModList.isLoaded`).
    if name == "isModLoaded"
        || (owner.ends_with("/ModList") && name == "isLoaded")
        || (owner.ends_with("/LoadingModList") && name.contains("getModFileById"))
    {
        return InvokeCategory::ModLoadedCheck;
    }
    // Config lookups: a getter on a config-shaped owner returning a value used in a
    // guard. Conservative — only obvious `*Config*`/`*Option*` owners.
    if (owner.contains("Config") || owner.contains("Option") || owner.contains("Settings"))
        && (name.starts_with("get") || name.starts_with("is") || name.starts_with("as"))
    {
        return InvokeCategory::ConfigCheck;
    }
    // Async scheduling / background work.
    if owner.starts_with("java/util/concurrent/")
        || owner == "java/util/concurrent/CompletableFuture"
        || (owner.ends_with("/Util")
            && (name.contains("ExecutorService")
                || name.contains("backgroundExecutor")
                || name.contains("ioPool")))
        || matches!(
            name,
            "submit" | "execute" | "scheduleAtFixedRate" | "schedule"
        ) && owner.contains("Executor")
        || name == "supplyAsync"
        || name == "runAsync"
        || name == "thenRunAsync"
        || name == "thenApplyAsync"
    {
        return InvokeCategory::Async;
    }
    // World / level mutation.
    if matches!(
        name,
        "setBlock"
            | "setBlockState"
            | "destroyBlock"
            | "removeBlock"
            | "spawnEntity"
            | "addFreshEntity"
            | "addEntity"
            | "setBlockAndUpdate"
            | "explode"
            | "playSound"
    ) {
        return InvokeCategory::WorldMutation;
    }
    if is_logging_call(owner) {
        return InvokeCategory::Logging;
    }
    InvokeCategory::Other
}

fn record_field_write(
    member: &MemberRef<'_>,
    value: AbstractValue,
    targets: &BTreeSet<String>,
    writes: &mut BTreeMap<String, ValueSource>,
) {
    if !targets.contains(member.class_name.as_ref()) {
        return;
    }
    let field = member.name_and_type.name.to_string();
    // The stored value's provenance is already correct: after a degraded merge the
    // operand is `Unknown`, so no flag is needed to force conservatism here.
    let source = value.to_source();
    writes.entry(field).or_insert(source);
}

/// Push an invocation/indy result of the parsed return shape, or nothing for void.
fn push_return(stack: &mut Stack, ret: ReturnShape, result: AbstractValue) {
    match ret {
        ReturnShape::Void => {}
        ReturnShape::Narrow => stack.push_value(result, 1),
        ReturnShape::Wide => stack.push_value(result, 2),
    }
}

/// Width in operand-stack words of a field/return type descriptor.
fn field_width(descriptor: &str) -> u8 {
    match descriptor.chars().next() {
        Some('J' | 'D') => 2,
        _ => 1,
    }
}

fn member_descriptor<'a>(member: &'a MemberRef<'a>) -> &'a str {
    member.name_and_type.descriptor.as_ref()
}

/// The operand-stack shape of a method return type.
enum ReturnShape {
    Void,
    Narrow,
    Wide,
}

/// Parse a method descriptor into (argument count, return shape). Counts logical
/// arguments (one per parameter, regardless of width — [`Stack::pop_value`]
/// consumes category-2 fillers on its own).
fn parse_descriptor(descriptor: &str) -> (usize, ReturnShape) {
    let bytes = descriptor.as_bytes();
    let Some(open) = descriptor.find('(') else {
        return (0, ReturnShape::Void);
    };
    let Some(close) = descriptor.find(')') else {
        return (0, ReturnShape::Void);
    };

    let mut count = 0usize;
    let mut i = open + 1;
    while i < close {
        match bytes[i] {
            b'[' => {
                i += 1; // array dimensions collapse into one reference argument
            }
            b'L' => {
                count += 1;
                while i < close && bytes[i] != b';' {
                    i += 1;
                }
                i += 1; // skip ';'
            }
            _ => {
                count += 1;
                i += 1;
            }
        }
    }

    let ret = match bytes.get(close + 1) {
        None | Some(b'V') => ReturnShape::Void,
        Some(b'J' | b'D') => ReturnShape::Wide,
        Some(_) => ReturnShape::Narrow,
    };
    (count, ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_invoke_recognises_semantic_categories() {
        assert_eq!(
            classify_invoke("net/fabricmc/loader/api/FabricLoader", "isModLoaded"),
            InvokeCategory::ModLoadedCheck
        );
        assert_eq!(
            classify_invoke("com/example/MyConfig", "getBoolean"),
            InvokeCategory::ConfigCheck
        );
        assert_eq!(
            classify_invoke("java/util/concurrent/CompletableFuture", "runAsync"),
            InvokeCategory::Async
        );
        assert_eq!(
            classify_invoke("net/minecraft/world/level/Level", "setBlock"),
            InvokeCategory::WorldMutation
        );
        assert_eq!(
            classify_invoke("org/slf4j/Logger", "info"),
            InvokeCategory::Logging
        );
        assert_eq!(
            classify_invoke("net/minecraft/world/entity/Entity", "tick"),
            InvokeCategory::Other
        );
    }

    #[test]
    fn abstract_value_join_is_a_lattice() {
        use AbstractValue::*;
        // Agreement is preserved (the precision win at a clean merge)…
        assert_eq!(Constant.join(Constant), Constant);
        assert_eq!(Argument.join(Argument), Argument);
        // …disagreement rises to the conservative top.
        assert_eq!(Constant.join(Argument), Unknown);
        assert_eq!(TargetField.join(Unknown), Unknown);
        // Refined: a constant is a degenerate computed value (still the LUB, sound).
        assert_eq!(Constant.join(Computed), Computed);
        assert_eq!(Computed.join(Constant), Computed);
        // But a target-derived value never silently merges with handler data.
        assert_eq!(TargetField.join(Argument), Unknown);
    }

    #[test]
    fn join_source_merges_constant_and_computed() {
        use ValueSource::*;
        assert_eq!(join_source(Some(Constant), Computed), Some(Computed));
        assert_eq!(join_source(Some(Computed), Constant), Some(Computed));
        assert_eq!(join_source(Some(Constant), Argument), Some(Unknown));
        assert_eq!(join_source(None, Constant), Some(Constant));
    }

    #[test]
    fn degrade_records_reason_and_sets_flag() {
        let mut df = HandlerDataflow::default();
        df.degrade(ImpreciseReason::Switch);
        df.degrade(ImpreciseReason::Switch); // de-duplicated
        df.degrade(ImpreciseReason::LoopBackEdge);
        assert!(df.imprecise);
        assert_eq!(df.imprecise_reasons.len(), 2);
        assert!(
            df.imprecise_reasons
                .contains(&ImpreciseReason::LoopBackEdge)
        );
    }

    #[test]
    fn pattern_pass_raises_confidence_for_known_shapes() {
        // logs-only is the safest shape → high confidence.
        let mut logs = HandlerDataflow {
            logs_only: true,
            confidence: 85,
            ..Default::default()
        };
        refine_with_patterns(&mut logs);
        assert!(logs.confidence >= 95);

        // A fully-resolved decisive set-return with a concrete source.
        let mut decisive = HandlerDataflow {
            sets_return_value: true,
            return_value_source: ValueSource::Constant,
            imprecise: false,
            confidence: 85,
            ..Default::default()
        };
        refine_with_patterns(&mut decisive);
        assert!(decisive.confidence >= 92);

        // An imprecise handler is not boosted by the decisive rule.
        let mut imprecise = HandlerDataflow {
            sets_return_value: true,
            return_value_source: ValueSource::Constant,
            imprecise: true,
            confidence: 55,
            ..Default::default()
        };
        refine_with_patterns(&mut imprecise);
        assert_eq!(imprecise.confidence, 55);
    }

    #[test]
    fn stack_join_requires_equal_height_and_merges_elementwise() {
        let a = Stack {
            words: vec![AbstractValue::Constant, AbstractValue::Argument],
        };
        let b = Stack {
            words: vec![AbstractValue::Constant, AbstractValue::This],
        };
        let merged = a.join(&b).expect("equal heights merge");
        assert_eq!(merged.words[0], AbstractValue::Constant); // agreed
        assert_eq!(merged.words[1], AbstractValue::Unknown); // disagreed
        // Mismatched heights are an irreducible merge → degrade.
        let tall = Stack {
            words: vec![AbstractValue::Constant],
        };
        assert!(a.join(&tall).is_none());
    }

    #[test]
    fn locals_join_pads_shorter_side_with_unknown() {
        let a = Locals {
            slots: vec![AbstractValue::Constant, AbstractValue::Argument],
        };
        let b = Locals {
            slots: vec![AbstractValue::Constant],
        };
        let merged = a.join(&b);
        assert_eq!(merged.slots.len(), 2);
        assert_eq!(merged.slots[0], AbstractValue::Constant);
        assert_eq!(merged.slots[1], AbstractValue::Unknown); // live on one path only
    }

    #[test]
    fn state_join_folds_predecessors_and_propagates_guard() {
        let mk = |v: AbstractValue, guarded: bool| State {
            stack: Stack { words: vec![v] },
            locals: Locals { slots: vec![] },
            guarded,
        };
        // Both branches return a constant → `Constant` survives the merge.
        let merged = mk(AbstractValue::Constant, false)
            .join(&mk(AbstractValue::Constant, false))
            .unwrap();
        assert_eq!(merged.stack.words[0], AbstractValue::Constant);
        assert!(!merged.guarded);
        // A dissenter collapses to `Unknown`; a guarded predecessor makes the merge
        // guarded (OR-join — sound: never claims unconditional unless all paths are).
        let mixed = mk(AbstractValue::Constant, false)
            .join(&mk(AbstractValue::Argument, true))
            .unwrap();
        assert_eq!(mixed.stack.words[0], AbstractValue::Unknown);
        assert!(mixed.guarded);
        // Mismatched stack heights → no merge.
        let tall = State {
            stack: Stack {
                words: vec![AbstractValue::Constant, AbstractValue::Constant],
            },
            locals: Locals { slots: vec![] },
            guarded: false,
        };
        assert!(mk(AbstractValue::Constant, false).join(&tall).is_none());
    }

    #[test]
    fn widen_collapses_to_unknown_keeping_height() {
        let s = State {
            stack: Stack {
                words: vec![
                    AbstractValue::Constant,
                    AbstractValue::Top,
                    AbstractValue::Argument,
                ],
            },
            locals: Locals {
                slots: vec![AbstractValue::This],
            },
            guarded: true,
        };
        let w = s.widen();
        assert_eq!(w.stack.words.len(), 3);
        assert_eq!(w.stack.words[0], AbstractValue::Unknown);
        assert_eq!(w.stack.words[1], AbstractValue::Top); // category-2 filler kept
        assert_eq!(w.locals.slots[0], AbstractValue::Unknown);
        assert!(w.guarded);
    }

    #[test]
    fn return_source_join_agrees_or_degrades() {
        // Both return sites agree → precise.
        let acc = join_source(None, ValueSource::Constant);
        assert_eq!(
            join_source(acc, ValueSource::Constant),
            Some(ValueSource::Constant)
        );
        // Disagreement → Unknown.
        let acc = join_source(None, ValueSource::Constant);
        assert_eq!(
            join_source(acc, ValueSource::Argument),
            Some(ValueSource::Unknown)
        );
    }

    #[test]
    fn parses_descriptor_arity_and_return_shape() {
        // (this is exercised end-to-end in bytecode.rs tests too)
        let (n, ret) = parse_descriptor("(ILjava/lang/String;[IJ)Z");
        assert_eq!(n, 4);
        assert!(matches!(ret, ReturnShape::Narrow));

        let (n, ret) = parse_descriptor("()V");
        assert_eq!(n, 0);
        assert!(matches!(ret, ReturnShape::Void));

        let (n, ret) = parse_descriptor("(Ljava/lang/Object;)J");
        assert_eq!(n, 1);
        assert!(matches!(ret, ReturnShape::Wide));
    }

    #[test]
    fn field_width_detects_category_two() {
        assert_eq!(field_width("J"), 2);
        assert_eq!(field_width("D"), 2);
        assert_eq!(field_width("I"), 1);
        assert_eq!(field_width("Ljava/lang/String;"), 1);
    }

    #[test]
    fn array_param_counts_as_one_argument() {
        let (n, _) = parse_descriptor("([[Ljava/lang/String;)V");
        assert_eq!(n, 1);
    }
}
