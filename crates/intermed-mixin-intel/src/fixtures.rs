//! Minimal Java class-file builder for mixin scanner tests.

use std::collections::HashMap;

/// Build a valid `.class` with `@Mixin(target)` and optional method annotations.
pub fn mixin_class(internal_name: &str, mixin_target: &str, method_ops: &[&str]) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");

    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));

    let mut ann = Vec::new();
    ann.extend_from_slice(&mixin_type.to_be_bytes());
    ann.extend_from_slice(&1u16.to_be_bytes());
    ann.extend_from_slice(&value.to_be_bytes());
    ann.push(b'c');
    ann.extend_from_slice(&target_desc.to_be_bytes());

    let mut rva = Vec::new();
    rva.extend_from_slice(&1u16.to_be_bytes());
    rva.extend_from_slice(&ann);

    let rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let mut methods = Vec::new();
    for (i, op) in method_ops.iter().enumerate() {
        let name = cp.utf8(&format!("m{i}"));
        let desc = cp.utf8("()V");
        let ann_type = cp.utf8(&format!("Lorg/spongepowered/asm/mixin/{op};"));
        let mut method_ann = Vec::new();
        method_ann.extend_from_slice(&ann_type.to_be_bytes());
        method_ann.extend_from_slice(&0u16.to_be_bytes());
        let mut method_rva = Vec::new();
        method_rva.extend_from_slice(&1u16.to_be_bytes());
        method_rva.extend_from_slice(&method_ann);
        let method_rva_name = cp.utf8("RuntimeVisibleAnnotations");
        methods.push((name, desc, method_rva_name, method_rva));
    }

    cp.finish_class(this, super_class, rva_name, rva, methods)
}

/// Build a valid `.class` with `@Mixin(targets = "dotted.Name")` — the string
/// target form used to name package-private / inaccessible classes that cannot
/// appear as a `.class` literal.
pub fn mixin_class_string_target(
    internal_name: &str,
    dotted_target: &str,
    method_ops: &[&str],
) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");

    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let targets = cp.utf8("targets");
    // Annotation `s` (string) element references a CONSTANT_Utf8 by index.
    let target_utf8 = cp.utf8(dotted_target);

    // `targets` is a String[]; wrap the single value in an array element (`[`).
    let mut ann = Vec::new();
    ann.extend_from_slice(&mixin_type.to_be_bytes());
    ann.extend_from_slice(&1u16.to_be_bytes());
    ann.extend_from_slice(&targets.to_be_bytes());
    ann.push(b'[');
    ann.extend_from_slice(&1u16.to_be_bytes());
    ann.push(b's');
    ann.extend_from_slice(&target_utf8.to_be_bytes());

    let mut rva = Vec::new();
    rva.extend_from_slice(&1u16.to_be_bytes());
    rva.extend_from_slice(&ann);

    let rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let mut methods = Vec::new();
    for (i, op) in method_ops.iter().enumerate() {
        let name = cp.utf8(&format!("m{i}"));
        let desc = cp.utf8("()V");
        let ann_type = cp.utf8(&format!("Lorg/spongepowered/asm/mixin/{op};"));
        let mut method_ann = Vec::new();
        method_ann.extend_from_slice(&ann_type.to_be_bytes());
        method_ann.extend_from_slice(&0u16.to_be_bytes());
        let mut method_rva = Vec::new();
        method_rva.extend_from_slice(&1u16.to_be_bytes());
        method_rva.extend_from_slice(&method_ann);
        let method_rva_name = cp.utf8("RuntimeVisibleAnnotations");
        methods.push((name, desc, method_rva_name, method_rva));
    }

    cp.finish_class(this, super_class, rva_name, rva, methods)
}

/// Build a `.class` with `@Mixin(target)` and a single method annotated
/// `@Inject(method = "<method>")` — exercises method-target extraction.
pub fn mixin_class_with_inject_method(
    internal_name: &str,
    mixin_target: &str,
    method: &str,
) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");

    // Class-level @Mixin(value = target.class).
    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));
    let mut ann = Vec::new();
    ann.extend_from_slice(&mixin_type.to_be_bytes());
    ann.extend_from_slice(&1u16.to_be_bytes());
    ann.extend_from_slice(&value.to_be_bytes());
    ann.push(b'c');
    ann.extend_from_slice(&target_desc.to_be_bytes());
    let mut rva = Vec::new();
    rva.extend_from_slice(&1u16.to_be_bytes());
    rva.extend_from_slice(&ann);
    let rva_name = cp.utf8("RuntimeVisibleAnnotations");

    // One method with @Inject(method = "<method>").
    let m_name = cp.utf8("handler");
    let m_desc = cp.utf8("()V");
    let inject_type = cp.utf8("Lorg/spongepowered/asm/mixin/injection/Inject;");
    let method_elem = cp.utf8("method");
    let method_val = cp.utf8(method);
    let mut method_ann = Vec::new();
    method_ann.extend_from_slice(&inject_type.to_be_bytes());
    method_ann.extend_from_slice(&1u16.to_be_bytes()); // one element: method = "…"
    method_ann.extend_from_slice(&method_elem.to_be_bytes());
    method_ann.push(b's');
    method_ann.extend_from_slice(&method_val.to_be_bytes());
    let mut method_rva = Vec::new();
    method_rva.extend_from_slice(&1u16.to_be_bytes());
    method_rva.extend_from_slice(&method_ann);
    let method_rva_name = cp.utf8("RuntimeVisibleAnnotations");
    let methods = vec![(m_name, m_desc, method_rva_name, method_rva)];

    cp.finish_class(this, super_class, rva_name, rva, methods)
}

/// Like [`mixin_class_with_inject_method`] but emits the `@Mixin` / `@Inject`
/// annotations into `RuntimeInvisibleAnnotations` — matching how real
/// SpongePowered-compiled mods ship (`@Retention(CLASS)`). Regression guard for
/// reading both visible and invisible annotation attributes.
pub fn mixin_class_invisible_annotations(
    internal_name: &str,
    mixin_target: &str,
    method: &str,
) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");

    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));
    let mut ann = Vec::new();
    ann.extend_from_slice(&mixin_type.to_be_bytes());
    ann.extend_from_slice(&1u16.to_be_bytes());
    ann.extend_from_slice(&value.to_be_bytes());
    ann.push(b'c');
    ann.extend_from_slice(&target_desc.to_be_bytes());
    let mut ria = Vec::new();
    ria.extend_from_slice(&1u16.to_be_bytes());
    ria.extend_from_slice(&ann);
    let ria_name = cp.utf8("RuntimeInvisibleAnnotations");

    let m_name = cp.utf8("handler");
    let m_desc = cp.utf8("()V");
    let inject_type = cp.utf8("Lorg/spongepowered/asm/mixin/injection/Inject;");
    let method_elem = cp.utf8("method");
    let method_val = cp.utf8(method);
    let mut method_ann = Vec::new();
    method_ann.extend_from_slice(&inject_type.to_be_bytes());
    method_ann.extend_from_slice(&1u16.to_be_bytes());
    method_ann.extend_from_slice(&method_elem.to_be_bytes());
    method_ann.push(b's');
    method_ann.extend_from_slice(&method_val.to_be_bytes());
    let mut method_ria = Vec::new();
    method_ria.extend_from_slice(&1u16.to_be_bytes());
    method_ria.extend_from_slice(&method_ann);
    let method_ria_name = cp.utf8("RuntimeInvisibleAnnotations");
    let methods = vec![(m_name, m_desc, method_ria_name, method_ria)];

    cp.finish_class(this, super_class, ria_name, ria, methods)
}

/// Build a mixin class with `@Inject(method = "…", at = @At("…"))`.
pub fn mixin_class_with_inject_at(
    internal_name: &str,
    mixin_target: &str,
    method: &str,
    at_value: &str,
) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");

    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));
    let mut ann = Vec::new();
    ann.extend_from_slice(&mixin_type.to_be_bytes());
    ann.extend_from_slice(&1u16.to_be_bytes());
    ann.extend_from_slice(&value.to_be_bytes());
    ann.push(b'c');
    ann.extend_from_slice(&target_desc.to_be_bytes());
    let mut rva = Vec::new();
    rva.extend_from_slice(&1u16.to_be_bytes());
    rva.extend_from_slice(&ann);
    let rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let m_name = cp.utf8("handler");
    let m_desc = cp.utf8("()V");
    let inject_type = cp.utf8("Lorg/spongepowered/asm/mixin/injection/Inject;");
    let at_type = cp.utf8("Lorg/spongepowered/asm/mixin/injection/At;");
    let method_elem = cp.utf8("method");
    let at_elem = cp.utf8("at");
    let value_elem = cp.utf8("value");
    let method_val = cp.utf8(method);
    let at_val = cp.utf8(at_value);

    let mut at_ann = Vec::new();
    at_ann.extend_from_slice(&at_type.to_be_bytes());
    at_ann.extend_from_slice(&1u16.to_be_bytes());
    at_ann.extend_from_slice(&value_elem.to_be_bytes());
    at_ann.push(b's');
    at_ann.extend_from_slice(&at_val.to_be_bytes());

    let mut method_ann = Vec::new();
    method_ann.extend_from_slice(&inject_type.to_be_bytes());
    method_ann.extend_from_slice(&2u16.to_be_bytes());
    method_ann.extend_from_slice(&method_elem.to_be_bytes());
    method_ann.push(b's');
    method_ann.extend_from_slice(&method_val.to_be_bytes());
    method_ann.extend_from_slice(&at_elem.to_be_bytes());
    method_ann.push(b'@');
    method_ann.extend_from_slice(&at_ann);

    let mut method_rva = Vec::new();
    method_rva.extend_from_slice(&1u16.to_be_bytes());
    method_rva.extend_from_slice(&method_ann);
    let method_rva_name = cp.utf8("RuntimeVisibleAnnotations");
    let methods = vec![(m_name, m_desc, method_rva_name, method_rva)];

    cp.finish_class(this, super_class, rva_name, rva, methods)
}

/// Build a mixin class with a handler whose parameter carries a MixinExtras
/// `@Local` annotation on a writable `LocalRef` parameter type. Used to exercise
/// [`crate::injection_point::parse_parameter_locals`] (parameter annotations,
/// which the SpongePowered `@LocalCapture` path never reads).
pub fn mixin_class_with_param_local(internal_name: &str, mixin_target: &str) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");

    // Class-level @Mixin(target).
    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));
    let mut ann = Vec::new();
    ann.extend_from_slice(&mixin_type.to_be_bytes());
    ann.extend_from_slice(&1u16.to_be_bytes());
    ann.extend_from_slice(&value.to_be_bytes());
    ann.push(b'c');
    ann.extend_from_slice(&target_desc.to_be_bytes());
    let mut rva = Vec::new();
    rva.extend_from_slice(&1u16.to_be_bytes());
    rva.extend_from_slice(&ann);
    let rva_name = cp.utf8("RuntimeVisibleAnnotations");

    // Handler `handler(LocalRef)` with a RuntimeVisibleParameterAnnotations
    // attribute: parameter 0 carries a bare `@Local`.
    let m_name = cp.utf8("handler");
    let m_desc = cp.utf8("(Lcom/llamalad7/mixinextras/sugar/ref/LocalRef;)V");
    let local_type = cp.utf8("Lcom/llamalad7/mixinextras/sugar/Local;");
    let rvpa_name = cp.utf8("RuntimeVisibleParameterAnnotations");

    let mut rvpa = Vec::new();
    rvpa.push(1u8); // num_parameters
    rvpa.extend_from_slice(&1u16.to_be_bytes()); // parameter 0: num_annotations
    rvpa.extend_from_slice(&local_type.to_be_bytes()); // annotation type
    rvpa.extend_from_slice(&0u16.to_be_bytes()); // num element value pairs

    let methods = vec![(m_name, m_desc, rvpa_name, rvpa)];
    cp.finish_class(this, super_class, rva_name, rva, methods)
}

/// Build a mixin class whose constant pool references a target-class method.
pub fn mixin_class_with_target_method_ref(
    internal_name: &str,
    mixin_target: &str,
    member_name: &str,
    member_desc: &str,
) -> Vec<u8> {
    let mut cp = Pool::new();
    let _target_class = cp.class(mixin_target);
    let _member = cp.method_ref(mixin_target, member_name, member_desc);
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");

    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));
    let mut ann = Vec::new();
    ann.extend_from_slice(&mixin_type.to_be_bytes());
    ann.extend_from_slice(&1u16.to_be_bytes());
    ann.extend_from_slice(&value.to_be_bytes());
    ann.push(b'c');
    ann.extend_from_slice(&target_desc.to_be_bytes());
    let mut rva = Vec::new();
    rva.extend_from_slice(&1u16.to_be_bytes());
    rva.extend_from_slice(&ann);
    let rva_name = cp.utf8("RuntimeVisibleAnnotations");
    cp.finish_class(this, super_class, rva_name, rva, Vec::new())
}

/// Build a minimal class extending `super_internal`.
pub fn class_extends(internal_name: &str, super_internal: &str) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class(super_internal);
    cp.finish_class_bare(this, super_class)
}

/// Build a plain class declaring a single `method_name(method_desc)` (with a
/// trivial `return` body) — for [`crate::apply_failure`] target-index tests.
pub fn class_with_method(internal_name: &str, method_name: &str, method_desc: &str) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");
    let mname = cp.utf8(method_name);
    let mdesc = cp.utf8(method_desc);
    let code_name = cp.utf8("Code");
    let code = build_code_attribute(&[0xB1], 0, 1); // return
    let rva_name = cp.utf8("RuntimeVisibleAnnotations");
    let mut rva = Vec::new();
    rva.extend_from_slice(&0u16.to_be_bytes()); // zero annotations
    cp.finish_class(this, super_class, rva_name, rva, vec![(mname, mdesc, code_name, code)])
}

/// Build a mixin class with `@Inject` handler bytecode that touches the target.
///
/// The handler performs `GETFIELD` on `tickCount`, `ISTORE` into a local, invokes
/// `CallbackInfo.cancel()`, and `ARETURN` — exercising Phase-1 bytecode metrics.
pub fn mixin_class_with_handler_bytecode(internal_name: &str, mixin_target: &str) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");
    cp.class(mixin_target);
    let field_ref = cp.field_ref(mixin_target, "tickCount", "I");
    let _method_ref = cp.method_ref(mixin_target, "doTick", "()V");
    let callback_class = "org/spongepowered/asm/mixin/injection/callback/CallbackInfo";
    cp.class(callback_class);
    let cancel_ref = cp.method_ref(callback_class, "cancel", "()V");

    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));
    let mut class_ann = Vec::new();
    class_ann.extend_from_slice(&mixin_type.to_be_bytes());
    class_ann.extend_from_slice(&1u16.to_be_bytes());
    class_ann.extend_from_slice(&value.to_be_bytes());
    class_ann.push(b'c');
    class_ann.extend_from_slice(&target_desc.to_be_bytes());
    let mut class_rva = Vec::new();
    class_rva.extend_from_slice(&1u16.to_be_bytes());
    class_rva.extend_from_slice(&class_ann);
    let class_rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let handler_name = cp.utf8("handler");
    let handler_desc = cp.utf8("(Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfo;)V");
    let inject_type = cp.utf8("Lorg/spongepowered/asm/mixin/injection/Inject;");
    let method_elem = cp.utf8("method");
    let method_val = cp.utf8("tick");
    let mut inject_ann = Vec::new();
    inject_ann.extend_from_slice(&inject_type.to_be_bytes());
    inject_ann.extend_from_slice(&1u16.to_be_bytes());
    inject_ann.extend_from_slice(&method_elem.to_be_bytes());
    inject_ann.push(b's');
    inject_ann.extend_from_slice(&method_val.to_be_bytes());
    let mut inject_rva = Vec::new();
    inject_rva.extend_from_slice(&1u16.to_be_bytes());
    inject_rva.extend_from_slice(&inject_ann);
    let inject_rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let mut bytecode = Vec::new();
    bytecode.push(0x2A); // aload_0 (mixin receiver)
    bytecode.push(0xB4); // getfield
    bytecode.extend_from_slice(&field_ref.to_be_bytes());
    bytecode.push(0x36); // istore
    bytecode.push(0x02);
    bytecode.push(0x1B); // aload_1 (CallbackInfo param)
    bytecode.push(0xB6); // invokevirtual cancel
    bytecode.extend_from_slice(&cancel_ref.to_be_bytes());
    bytecode.push(0xB0); // areturn

    let code_name = cp.utf8("Code");
    let code_body = build_code_attribute(&bytecode, 4, 3);
    cp.finish_class_with_method_attrs(
        this,
        super_class,
        class_rva_name,
        class_rva,
        vec![(
            handler_name,
            handler_desc,
            vec![(inject_rva_name, inject_rva), (code_name, code_body)],
        )],
    )
}

/// Handler that only throws — used to verify `throws_exception` detection.
pub fn mixin_class_with_throwing_handler(internal_name: &str, mixin_target: &str) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");

    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));
    let mut class_ann = Vec::new();
    class_ann.extend_from_slice(&mixin_type.to_be_bytes());
    class_ann.extend_from_slice(&1u16.to_be_bytes());
    class_ann.extend_from_slice(&value.to_be_bytes());
    class_ann.push(b'c');
    class_ann.extend_from_slice(&target_desc.to_be_bytes());
    let mut class_rva = Vec::new();
    class_rva.extend_from_slice(&1u16.to_be_bytes());
    class_rva.extend_from_slice(&class_ann);
    let class_rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let handler_name = cp.utf8("handler");
    let handler_desc = cp.utf8("()V");
    let inject_type = cp.utf8("Lorg/spongepowered/asm/mixin/injection/Inject;");
    let mut inject_ann = Vec::new();
    inject_ann.extend_from_slice(&inject_type.to_be_bytes());
    inject_ann.extend_from_slice(&0u16.to_be_bytes());
    let mut inject_rva = Vec::new();
    inject_rva.extend_from_slice(&1u16.to_be_bytes());
    inject_rva.extend_from_slice(&inject_ann);
    let inject_rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let bytecode = vec![0xBF]; // athrow (stack underflow tolerated by our summary pass)
    let code_name = cp.utf8("Code");
    let code_body = build_code_attribute(&bytecode, 4, 1);
    cp.finish_class_with_method_attrs(
        this,
        super_class,
        class_rva_name,
        class_rva,
        vec![(
            handler_name,
            handler_desc,
            vec![(inject_rva_name, inject_rva), (code_name, code_body)],
        )],
    )
}

/// Handler that writes a target field from a constant and unconditionally calls
/// `CallbackInfoReturnable.setReturnValue(<constant>)` — exercises the dataflow
/// interpreter's sink + provenance detection (constant return, target-state write).
pub fn mixin_class_with_returning_handler(internal_name: &str, mixin_target: &str) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");
    cp.class(mixin_target);
    let field_ref = cp.field_ref(mixin_target, "tickCount", "I");
    let cir_class = "org/spongepowered/asm/mixin/injection/callback/CallbackInfoReturnable";
    cp.class(cir_class);
    let set_return_ref = cp.method_ref(cir_class, "setReturnValue", "(I)V");

    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));
    let mut class_ann = Vec::new();
    class_ann.extend_from_slice(&mixin_type.to_be_bytes());
    class_ann.extend_from_slice(&1u16.to_be_bytes());
    class_ann.extend_from_slice(&value.to_be_bytes());
    class_ann.push(b'c');
    class_ann.extend_from_slice(&target_desc.to_be_bytes());
    let mut class_rva = Vec::new();
    class_rva.extend_from_slice(&1u16.to_be_bytes());
    class_rva.extend_from_slice(&class_ann);
    let class_rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let handler_name = cp.utf8("handler");
    let handler_desc =
        cp.utf8("(Lorg/spongepowered/asm/mixin/injection/callback/CallbackInfoReturnable;)V");
    let inject_type = cp.utf8("Lorg/spongepowered/asm/mixin/injection/Inject;");
    let mut inject_ann = Vec::new();
    inject_ann.extend_from_slice(&inject_type.to_be_bytes());
    inject_ann.extend_from_slice(&0u16.to_be_bytes());
    let mut inject_rva = Vec::new();
    inject_rva.extend_from_slice(&1u16.to_be_bytes());
    inject_rva.extend_from_slice(&inject_ann);
    let inject_rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let mut bytecode = Vec::new();
    bytecode.push(0x2A); // aload_0 (this == target)
    bytecode.push(0x07); // iconst_4 (constant value)
    bytecode.push(0xB5); // putfield tickCount
    bytecode.extend_from_slice(&field_ref.to_be_bytes());
    bytecode.push(0x2B); // aload_1 (CallbackInfoReturnable)
    bytecode.push(0x08); // iconst_5 (constant return value)
    bytecode.push(0xB6); // invokevirtual setReturnValue
    bytecode.extend_from_slice(&set_return_ref.to_be_bytes());
    bytecode.push(0xB1); // return

    let code_name = cp.utf8("Code");
    let code_body = build_code_attribute(&bytecode, 3, 2);
    cp.finish_class_with_method_attrs(
        this,
        super_class,
        class_rva_name,
        class_rva,
        vec![(
            handler_name,
            handler_desc,
            vec![(inject_rva_name, inject_rva), (code_name, code_body)],
        )],
    )
}

fn build_code_attribute(bytecode: &[u8], max_stack: u16, max_locals: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&max_stack.to_be_bytes());
    out.extend_from_slice(&max_locals.to_be_bytes());
    out.extend_from_slice(&(u32::try_from(bytecode.len()).unwrap_or(0)).to_be_bytes());
    out.extend_from_slice(bytecode);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

/// Build a mixin class with a `@Shadow` field on the target.
pub fn mixin_class_with_shadow(
    internal_name: &str,
    mixin_target: &str,
    field_name: &str,
    field_desc: &str,
) -> Vec<u8> {
    let mut cp = Pool::new();
    let this = cp.class(internal_name);
    let super_class = cp.class("java/lang/Object");

    let mixin_type = cp.utf8("Lorg/spongepowered/asm/mixin/Mixin;");
    let value = cp.utf8("value");
    let target_desc = cp.utf8(&format!("L{mixin_target};"));
    let mut ann = Vec::new();
    ann.extend_from_slice(&mixin_type.to_be_bytes());
    ann.extend_from_slice(&1u16.to_be_bytes());
    ann.extend_from_slice(&value.to_be_bytes());
    ann.push(b'c');
    ann.extend_from_slice(&target_desc.to_be_bytes());
    let mut rva = Vec::new();
    rva.extend_from_slice(&1u16.to_be_bytes());
    rva.extend_from_slice(&ann);
    let rva_name = cp.utf8("RuntimeVisibleAnnotations");

    let field_name_idx = cp.utf8(field_name);
    let field_desc_idx = cp.utf8(field_desc);
    let shadow_type = cp.utf8("Lorg/spongepowered/asm/mixin/Shadow;");
    let mut shadow_ann = Vec::new();
    shadow_ann.extend_from_slice(&shadow_type.to_be_bytes());
    shadow_ann.extend_from_slice(&0u16.to_be_bytes());
    let mut shadow_rva = Vec::new();
    shadow_rva.extend_from_slice(&1u16.to_be_bytes());
    shadow_rva.extend_from_slice(&shadow_ann);
    let shadow_rva_name = cp.utf8("RuntimeVisibleAnnotations");

    cp.finish_class_with_field(
        this,
        super_class,
        rva_name,
        rva,
        Vec::new(),
        field_name_idx,
        field_desc_idx,
        shadow_rva_name,
        shadow_rva,
    )
}

struct Pool {
    entries: Vec<Vec<u8>>,
    utf8: HashMap<String, u16>,
    class: HashMap<String, u16>,
    next: u16,
}

impl Pool {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            utf8: HashMap::new(),
            class: HashMap::new(),
            next: 1,
        }
    }

    fn utf8(&mut self, s: &str) -> u16 {
        if let Some(i) = self.utf8.get(s) {
            return *i;
        }
        let idx = self.next;
        self.next += 1;
        let mut e = vec![1u8];
        let b = s.as_bytes();
        e.extend_from_slice(&(b.len() as u16).to_be_bytes());
        e.extend_from_slice(b);
        self.entries.push(e);
        self.utf8.insert(s.to_string(), idx);
        idx
    }

    fn class(&mut self, internal: &str) -> u16 {
        if let Some(i) = self.class.get(internal) {
            return *i;
        }
        let name = self.utf8(internal);
        let idx = self.next;
        self.next += 1;
        self.entries
            .push(vec![7u8, (name >> 8) as u8, (name & 0xff) as u8]);
        self.class.insert(internal.to_string(), idx);
        idx
    }

    fn name_and_type(&mut self, name: &str, descriptor: &str) -> u16 {
        let n = self.utf8(name);
        let d = self.utf8(descriptor);
        let idx = self.next;
        self.next += 1;
        let mut e = vec![12u8];
        e.extend_from_slice(&n.to_be_bytes());
        e.extend_from_slice(&d.to_be_bytes());
        self.entries.push(e);
        idx
    }

    fn method_ref(&mut self, owner: &str, name: &str, descriptor: &str) -> u16 {
        let class_idx = self.class(owner);
        let nat = self.name_and_type(name, descriptor);
        let idx = self.next;
        self.next += 1;
        let mut e = vec![10u8];
        e.extend_from_slice(&class_idx.to_be_bytes());
        e.extend_from_slice(&nat.to_be_bytes());
        self.entries.push(e);
        idx
    }

    fn field_ref(&mut self, owner: &str, name: &str, descriptor: &str) -> u16 {
        let class_idx = self.class(owner);
        let nat = self.name_and_type(name, descriptor);
        let idx = self.next;
        self.next += 1;
        let mut e = vec![9u8];
        e.extend_from_slice(&class_idx.to_be_bytes());
        e.extend_from_slice(&nat.to_be_bytes());
        self.entries.push(e);
        idx
    }

    // Test bytecode builder: each tuple mirrors a class-file structure
    // (method → (name, desc, attrs)); a struct here would not aid a fixture.
    #[allow(clippy::type_complexity)]
    fn finish_class_with_method_attrs(
        self,
        this: u16,
        super_class: u16,
        class_rva_name: u16,
        class_rva: Vec<u8>,
        methods: Vec<(u16, u16, Vec<(u16, Vec<u8>)>)>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34]);
        out.extend_from_slice(&self.next.to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(e);
        }
        out.extend_from_slice(&0x0021u16.to_be_bytes());
        out.extend_from_slice(&this.to_be_bytes());
        out.extend_from_slice(&super_class.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&(methods.len() as u16).to_be_bytes());
        for (name, desc, attrs) in methods {
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&name.to_be_bytes());
            out.extend_from_slice(&desc.to_be_bytes());
            out.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
            for (attr_name, attr_body) in attrs {
                out.extend_from_slice(&attr_name.to_be_bytes());
                out.extend_from_slice(&(attr_body.len() as u32).to_be_bytes());
                out.extend_from_slice(&attr_body);
            }
        }
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&class_rva_name.to_be_bytes());
        out.extend_from_slice(&(class_rva.len() as u32).to_be_bytes());
        out.extend_from_slice(&class_rva);
        out
    }

    fn finish_class(
        self,
        this: u16,
        super_class: u16,
        rva_name: u16,
        rva: Vec<u8>,
        methods: Vec<(u16, u16, u16, Vec<u8>)>,
    ) -> Vec<u8> {
        self.finish_class_with_field(
            this,
            super_class,
            rva_name,
            rva,
            methods,
            0,
            0,
            0,
            Vec::new(),
        )
    }

    fn finish_class_bare(self, this: u16, super_class: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34]);
        out.extend_from_slice(&self.next.to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(e);
        }
        out.extend_from_slice(&0x0021u16.to_be_bytes());
        out.extend_from_slice(&this.to_be_bytes());
        out.extend_from_slice(&super_class.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // interfaces
        out.extend_from_slice(&0u16.to_be_bytes()); // fields
        out.extend_from_slice(&0u16.to_be_bytes()); // methods
        out.extend_from_slice(&0u16.to_be_bytes()); // attributes
        out
    }

    // Each argument is a distinct class-file layout field (this/super, the synthetic
    // method, and the optional field's name/desc/code); a test builder, not an API.
    #[allow(clippy::too_many_arguments)]
    fn finish_class_with_field(
        self,
        this: u16,
        super_class: u16,
        rva_name: u16,
        rva: Vec<u8>,
        methods: Vec<(u16, u16, u16, Vec<u8>)>,
        field_name: u16,
        field_desc: u16,
        field_rva_name: u16,
        field_rva: Vec<u8>,
    ) -> Vec<u8> {
        let field_count = u16::from(field_name != 0);
        let mut out = Vec::new();
        out.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34]);
        out.extend_from_slice(&self.next.to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(e);
        }
        out.extend_from_slice(&0x0021u16.to_be_bytes());
        out.extend_from_slice(&this.to_be_bytes());
        out.extend_from_slice(&super_class.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&field_count.to_be_bytes());
        if field_count > 0 {
            out.extend_from_slice(&0x0002u16.to_be_bytes()); // private
            out.extend_from_slice(&field_name.to_be_bytes());
            out.extend_from_slice(&field_desc.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&field_rva_name.to_be_bytes());
            out.extend_from_slice(&(field_rva.len() as u32).to_be_bytes());
            out.extend_from_slice(&field_rva);
        }
        out.extend_from_slice(&(methods.len() as u16).to_be_bytes());
        for (name, desc, attr_name, attr_body) in methods {
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&name.to_be_bytes());
            out.extend_from_slice(&desc.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&attr_name.to_be_bytes());
            out.extend_from_slice(&(attr_body.len() as u32).to_be_bytes());
            out.extend_from_slice(&attr_body);
        }
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&rva_name.to_be_bytes());
        out.extend_from_slice(&(rva.len() as u32).to_be_bytes());
        out.extend_from_slice(&rva);
        out
    }
}
