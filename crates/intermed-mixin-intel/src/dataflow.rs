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

use crate::model::{HandlerDataflow, TargetFieldWrite, ValueSource};

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
        if self == other {
            self
        } else {
            AbstractValue::Unknown
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
#[derive(Clone)]
struct Stack {
    words: Vec<AbstractValue>,
}

impl Stack {
    fn new() -> Self {
        Self { words: Vec::new() }
    }
    fn clear(&mut self) {
        self.words.clear();
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
#[derive(Clone)]
struct Locals {
    slots: Vec<AbstractValue>,
}

impl Locals {
    fn get(&self, index: usize) -> AbstractValue {
        self.slots.get(index).copied().unwrap_or(AbstractValue::Unknown)
    }
    fn set(&mut self, index: usize, v: AbstractValue, width: u8) {
        if index >= self.slots.len() {
            self.slots.resize(index + width as usize, AbstractValue::Unknown);
        }
        self.slots[index] = v;
        if width == 2 && index + 1 < self.slots.len() {
            self.slots[index + 1] = AbstractValue::Top;
        }
    }
    fn reset_unknown(&mut self) {
        for s in &mut self.slots {
            *s = AbstractValue::Unknown;
        }
    }
    /// Element-wise lattice join with another local array, padding the shorter
    /// with `Unknown` (a slot live on only one path is unknown after the merge).
    fn join(&self, other: &Locals) -> Locals {
        let len = self.slots.len().max(other.slots.len());
        let slots = (0..len)
            .map(|i| {
                let a = self.slots.get(i).copied().unwrap_or(AbstractValue::Unknown);
                let b = other.slots.get(i).copied().unwrap_or(AbstractValue::Unknown);
                a.join(b)
            })
            .collect();
        Locals { slots }
    }
}

/// Abstract machine state (operand stack + locals) at one program point, carried
/// along control-flow edges and merged at join points.
#[derive(Clone)]
struct State {
    stack: Stack,
    locals: Locals,
}

impl State {
    /// Join a non-empty set of predecessor states. Returns `None` (degrade) if any
    /// pair has mismatched stack heights.
    fn join_all(states: &[State]) -> Option<State> {
        let mut iter = states.iter();
        let first = iter.next()?.clone();
        let mut acc_stack = first.stack;
        let mut acc_locals = first.locals;
        for s in iter {
            acc_stack = acc_stack.join(&s.stack)?;
            acc_locals = acc_locals.join(&s.locals);
        }
        Some(State {
            stack: acc_stack,
            locals: acc_locals,
        })
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
    let mut stack = Stack::new();
    let mut locals = Locals {
        slots: init_locals(descriptor, is_static),
    };
    let opcodes = &bytecode.opcodes;
    let jump_targets = collect_jump_targets(opcodes);
    let loop_headers = collect_loop_headers(opcodes);

    let mut branch_seen = false;
    // `guarded` = the current point is control-dependent on a conditional branch,
    // so any cancel / setReturnValue here is *conditional*, not unconditional. It
    // becomes (stickily) true right after the first conditional branch — including
    // its fall-through path, which the old "set at the join target" logic missed.
    let mut guarded = false;
    // Abstract states arriving at an offset via a *forward* branch, merged when the
    // offset is reached. This is what turns the old "reset to Unknown at every
    // join" into a real lattice join: a value both predecessors agree on survives.
    let mut incoming: BTreeMap<usize, Vec<State>> = BTreeMap::new();
    let mut prev_falls_through = true;
    let mut cir_return: Option<ValueSource> = None;
    let mut typed_return: Option<ValueSource> = None;
    let mut writes: BTreeMap<String, ValueSource> = BTreeMap::new();

    for (idx, (offset, opcode)) in opcodes.iter().enumerate() {
        if idx > 0 {
            if jump_targets.contains(offset) {
                let mut preds = incoming.remove(offset).unwrap_or_default();
                if prev_falls_through {
                    preds.push(State {
                        stack: stack.clone(),
                        locals: locals.clone(),
                    });
                }
                // A loop header's back-edge state is unknown on a single forward
                // pass; an empty predecessor set means the point is reachable only
                // via an edge we don't model. Either way, degrade conservatively.
                match (loop_headers.contains(offset), State::join_all(&preds)) {
                    (false, Some(merged)) => {
                        stack = merged.stack;
                        locals = merged.locals;
                    }
                    _ => {
                        stack.clear();
                        locals.reset_unknown();
                        df.imprecise = true;
                    }
                }
            } else if !prev_falls_through {
                // Unreachable on fall-through and not a branch target (dead code
                // after a goto/return/throw): drop stale state, don't leak it.
                stack.clear();
                locals.reset_unknown();
            }
        }

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
            guarded,
        );

        if is_conditional_branch(opcode) {
            guarded = true;
        }
        // Record the post-instruction state on every forward branch edge so the
        // target can merge it. Back-edges are handled by `loop_headers`.
        if let Some(rel) = branch_offset(opcode) {
            let dest = *offset as i64 + rel as i64;
            if dest > *offset as i64 {
                incoming.entry(dest as usize).or_default().push(State {
                    stack: stack.clone(),
                    locals: locals.clone(),
                });
            }
        }
        prev_falls_through = falls_through(opcode);
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

    Some(df)
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

/// Offsets that are the destination of some jump (`if*`, `goto`, `jsr`) — the
/// control-flow join points. Switch targets are not enumerated; a switch instead
/// trips the conservative path via [`apply_opcode`].
fn collect_jump_targets(opcodes: &[(usize, Opcode<'_>)]) -> BTreeSet<usize> {
    let mut targets = BTreeSet::new();
    for (offset, opcode) in opcodes {
        if let Some(jump) = branch_offset(opcode) {
            let dest = *offset as i64 + jump as i64;
            if dest >= 0 {
                targets.insert(dest as usize);
            }
        }
    }
    targets
}

/// Offsets that are the destination of a *back* edge (a branch whose target is at
/// or before the branch itself) — i.e. loop headers. A single forward pass cannot
/// know the loop-carried state, so these merge points degrade conservatively.
fn collect_loop_headers(opcodes: &[(usize, Opcode<'_>)]) -> BTreeSet<usize> {
    let mut headers = BTreeSet::new();
    for (offset, opcode) in opcodes {
        if let Some(rel) = branch_offset(opcode) {
            let dest = *offset as i64 + rel as i64;
            if dest >= 0 && dest <= *offset as i64 {
                headers.insert(dest as usize);
            }
        }
    }
    headers
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
    Some(match acc {
        None => v,
        Some(a) if a == v => a,
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
        Opcode::Iaload | Opcode::Faload | Opcode::Aaload | Opcode::Baload | Opcode::Caload
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
        Opcode::Iastore | Opcode::Fastore | Opcode::Aastore | Opcode::Bastore
        | Opcode::Castore | Opcode::Sastore => {
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
        Opcode::Iadd | Opcode::Isub | Opcode::Imul | Opcode::Idiv | Opcode::Irem | Opcode::Iand
        | Opcode::Ior | Opcode::Ixor | Opcode::Ishl | Opcode::Ishr | Opcode::Iushr
        | Opcode::Fadd | Opcode::Fsub | Opcode::Fmul | Opcode::Fdiv | Opcode::Frem => {
            stack.pop_value();
            stack.pop_value();
            stack.push_value(V::Computed, 1);
        }
        Opcode::Ineg | Opcode::Fneg => {
            stack.pop_value();
            stack.push_value(V::Computed, 1);
        }
        // ── arithmetic / logic (wide) ──────────────────────────────────────
        Opcode::Ladd | Opcode::Lsub | Opcode::Lmul | Opcode::Ldiv | Opcode::Lrem | Opcode::Land
        | Opcode::Lor | Opcode::Lxor | Opcode::Dadd | Opcode::Dsub | Opcode::Dmul
        | Opcode::Ddiv | Opcode::Drem => {
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
            stack.pop_value();
            // A switch's successors are joins we do not enumerate: be conservative.
            df.imprecise = true;
        }
        Opcode::Goto(_) | Opcode::Jsr(_) | Opcode::Ret(_) | Opcode::Nop | Opcode::Breakpoint
        | Opcode::Impdep1 | Opcode::Impdep2 => {}

        // ── returns ────────────────────────────────────────────────────────
        Opcode::Ireturn | Opcode::Freturn | Opcode::Areturn | Opcode::Lreturn
        | Opcode::Dreturn => {
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
    let receiver = if is_static { None } else { Some(stack.pop_value()) };

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

    let result = if into_target { V::TargetCall } else { V::Computed };
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
        || (owner.ends_with("/Util") && (name.contains("ExecutorService") || name.contains("backgroundExecutor") || name.contains("ioPool")))
        || matches!(name, "submit" | "execute" | "scheduleAtFixedRate" | "schedule")
            && owner.contains("Executor")
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
    }

    #[test]
    fn stack_join_requires_equal_height_and_merges_elementwise() {
        let a = Stack { words: vec![AbstractValue::Constant, AbstractValue::Argument] };
        let b = Stack { words: vec![AbstractValue::Constant, AbstractValue::This] };
        let merged = a.join(&b).expect("equal heights merge");
        assert_eq!(merged.words[0], AbstractValue::Constant); // agreed
        assert_eq!(merged.words[1], AbstractValue::Unknown); // disagreed
        // Mismatched heights are an irreducible merge → degrade.
        let tall = Stack { words: vec![AbstractValue::Constant] };
        assert!(a.join(&tall).is_none());
    }

    #[test]
    fn locals_join_pads_shorter_side_with_unknown() {
        let a = Locals { slots: vec![AbstractValue::Constant, AbstractValue::Argument] };
        let b = Locals { slots: vec![AbstractValue::Constant] };
        let merged = a.join(&b);
        assert_eq!(merged.slots.len(), 2);
        assert_eq!(merged.slots[0], AbstractValue::Constant);
        assert_eq!(merged.slots[1], AbstractValue::Unknown); // live on one path only
    }

    #[test]
    fn state_join_all_folds_predecessors() {
        let mk = |v: AbstractValue| State {
            stack: Stack { words: vec![v] },
            locals: Locals { slots: vec![] },
        };
        // Three branches that all return a constant keep `Constant` after the merge.
        let merged = State::join_all(&[
            mk(AbstractValue::Constant),
            mk(AbstractValue::Constant),
            mk(AbstractValue::Constant),
        ])
        .unwrap();
        assert_eq!(merged.stack.words[0], AbstractValue::Constant);
        // One dissenter collapses the merge to `Unknown`.
        let mixed = State::join_all(&[
            mk(AbstractValue::Constant),
            mk(AbstractValue::Argument),
        ])
        .unwrap();
        assert_eq!(mixed.stack.words[0], AbstractValue::Unknown);
    }

    #[test]
    fn return_source_join_agrees_or_degrades() {
        // Both return sites agree → precise.
        let acc = join_source(None, ValueSource::Constant);
        assert_eq!(join_source(acc, ValueSource::Constant), Some(ValueSource::Constant));
        // Disagreement → Unknown.
        let acc = join_source(None, ValueSource::Constant);
        assert_eq!(join_source(acc, ValueSource::Argument), Some(ValueSource::Unknown));
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
