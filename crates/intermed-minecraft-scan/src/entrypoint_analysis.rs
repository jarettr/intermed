//! Production entrypoint-class intelligence (plan Phase 2.1).
//!
//! Replaces the constant-pool *substring* heuristic with real structural analysis
//! via [`cafebabe`]:
//!
//! * **Forge / NeoForge** — the class-level `@Mod$EventBusSubscriber` /
//!   `@EventBusSubscriber` annotation, and every `@SubscribeEvent` method, whose
//!   subscribed event is its **first parameter type** (not a string guess);
//!   `EventPriority` is read from the annotation when present.
//! * **Fabric / Quilt** — listener registration in method bodies: a
//!   `SomethingEvents.FIELD.register(…)` shape (a `getstatic` of a `*Events`
//!   field immediately feeding a `register` invoke) yields the actual event family
//!   and field (`ServerTickEvents.START_SERVER_TICK`).
//!
//! The result is precise — the events it reports are the ones the class genuinely
//! subscribes to or registers, with the false-positive surface of substring
//! matching removed.

use std::collections::BTreeSet;
use std::io::{Read, Seek};

use cafebabe::attributes::{Annotation, AnnotationElementValue, AttributeData};
use cafebabe::bytecode::Opcode;
use cafebabe::constant_pool::ConstantPoolItem;
use cafebabe::descriptors::FieldType;
use cafebabe::{parse_class_with_options, ParseOptions};

/// `@SubscribeEvent` method-annotation descriptors (Forge + NeoForge).
const SUBSCRIBE_EVENT: &[&str] = &[
    "Lnet/minecraftforge/eventbus/api/SubscribeEvent;",
    "Lnet/neoforged/bus/api/SubscribeEvent;",
];
/// Class-level `@Mod$EventBusSubscriber` / `@EventBusSubscriber` descriptors.
const EVENT_BUS_SUBSCRIBER: &[&str] = &[
    "Lnet/minecraftforge/fml/common/Mod$EventBusSubscriber;",
    "Lnet/neoforged/fml/common/EventBusSubscriber;",
];

/// Structural facts extracted from one entrypoint class.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct EntrypointAnalysis {
    /// Refined entrypoint type when the class structure determines one.
    pub entrypoint_type: Option<&'static str>,
    /// Event types the class subscribes to / registers, as `Owner` or
    /// `Owner.FIELD` simple names.
    pub events: Vec<String>,
    /// Highest declared `EventPriority` (mapped to Forge's numeric scale).
    pub priority: Option<i64>,
    /// The class registers listeners (annotation bus subscriber or Fabric register).
    pub registers_listeners: bool,
}

/// Analyse an entrypoint class's bytes. Returns `None` when the class cannot be
/// parsed or shows no entrypoint structure (callers keep the manifest heuristic).
pub(crate) fn analyze_entrypoint_class(bytes: &[u8]) -> Option<EntrypointAnalysis> {
    if bytes.len() < 4 || bytes[..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
        return None;
    }
    let mut opts = ParseOptions::default();
    opts.parse_bytecode(true);
    let class = parse_class_with_options(bytes, &opts).ok()?;
    let mut a = EntrypointAnalysis::default();

    // Class-level @EventBusSubscriber.
    if class
        .attributes
        .iter()
        .any(|attr| annotations_contain(&attr.data, EVENT_BUS_SUBSCRIBER).is_some())
    {
        a.entrypoint_type = Some("event_bus_subscriber");
        a.registers_listeners = true;
    }

    for method in &class.methods {
        // Forge/NeoForge @SubscribeEvent: the event is the first parameter type.
        if let Some(ann) = method
            .attributes
            .iter()
            .find_map(|attr| annotations_contain(&attr.data, SUBSCRIBE_EVENT))
        {
            a.registers_listeners = true;
            a.entrypoint_type = Some("event_bus_subscriber");
            if let Some(param) = method.descriptor.parameters.first() {
                if let Some(name) = object_simple_name(&param.field_type) {
                    push_unique(&mut a.events, name);
                }
            }
            if let Some(p) = subscribe_priority(ann) {
                a.priority = Some(a.priority.map_or(p, |cur| cur.max(p)));
            }
        }
        // Fabric/Quilt register(...) calls in the method body.
        scan_method_registrations(&method.attributes, &mut a);
    }

    if a.entrypoint_type.is_none() && a.events.is_empty() && !a.registers_listeners {
        return None;
    }
    Some(a)
}

/// If `data` is a `RuntimeVisibleAnnotations` attribute, return the first
/// annotation whose type descriptor is in `wanted`.
fn annotations_contain<'a>(
    data: &'a AttributeData<'a>,
    wanted: &[&str],
) -> Option<&'a Annotation<'a>> {
    let AttributeData::RuntimeVisibleAnnotations(annotations) = data else {
        return None;
    };
    annotations
        .iter()
        .find(|ann| wanted.contains(&ann.type_descriptor.to_string().as_str()))
}

/// Map an `EventPriority` enum element on a `@SubscribeEvent` to Forge's scale.
fn subscribe_priority(ann: &Annotation<'_>) -> Option<i64> {
    for element in &ann.elements {
        if element.name != "priority" {
            continue;
        }
        if let AnnotationElementValue::EnumConstant { const_name, .. } = &element.value {
            return Some(match const_name.as_ref() {
                "HIGHEST" => 1000,
                "HIGH" => 750,
                "NORMAL" => 500,
                "LOW" => 250,
                "LOWEST" => 0,
                _ => 500,
            });
        }
    }
    None
}

/// Detect Fabric/Quilt `SomethingEvents.FIELD.register(…)` listener registration:
/// a `getstatic` of a field on a `*Events`/`*Callback(s)` owner immediately
/// followed (in the same body) by a `register` invoke records the event family.
fn scan_method_registrations(attributes: &[cafebabe::attributes::AttributeInfo<'_>], a: &mut EntrypointAnalysis) {
    let Some(code) = attributes.iter().find_map(|attr| match &attr.data {
        AttributeData::Code(code) => Some(code),
        _ => None,
    }) else {
        return;
    };
    let Some(bytecode) = &code.bytecode else {
        return;
    };
    let mut pending: Option<String> = None;
    for (_, op) in &bytecode.opcodes {
        match op {
            Opcode::Getstatic(m) => {
                let owner = m.class_name.as_ref();
                if owner.contains("Events") || owner.ends_with("Callback") || owner.ends_with("Callbacks") {
                    pending = Some(format!(
                        "{}.{}",
                        simple_class(owner),
                        m.name_and_type.name.as_ref()
                    ));
                }
            }
            Opcode::Invokeinterface(m, _) | Opcode::Invokevirtual(m) | Opcode::Invokestatic(m)
                if m.name_and_type.name.as_ref() == "register" =>
            {
                if let Some(event) = pending.take() {
                    push_unique(&mut a.events, event);
                    a.registers_listeners = true;
                    if a.entrypoint_type.is_none() {
                        a.entrypoint_type = Some("event_bus_subscriber");
                    }
                }
            }
            _ => {}
        }
    }
}

/// Simple class name of an internal/dotted class reference.
fn simple_class(name: &str) -> &str {
    name.rsplit(['/', '.', '$']).next().unwrap_or(name)
}

/// Simple class name of an object field type, or `None` for primitives.
fn object_simple_name(ty: &FieldType<'_>) -> Option<String> {
    match ty {
        FieldType::Object(class) => Some(simple_class(class.as_ref()).to_string()),
        _ => None,
    }
}

fn push_unique(out: &mut Vec<String>, value: String) {
    if !value.is_empty() && !out.iter().any(|e| e == &value) {
        out.push(value);
    }
}

// ── Whole-jar bytecode intelligence ─────────────────────────────────────────

/// Cap on classes scanned per jar (pathological/obfuscated jars can ship tens of
/// thousands of classes; the signal saturates long before that).
const MAX_CLASSES_SCANNED: usize = 6000;

/// Distinctive framework class references → capability tokens. A *symbolic
/// reference* to one of these types in a class's constant pool is honest
/// structural evidence the code uses that framework — distinct from guessing by
/// the mod's name. Substrings are chosen to be specific (e.g. `DeferredRegister`,
/// not the over-broad `Registry`).
const CAPABILITY_REFS: &[(&str, &str)] = &[
    ("registries/DeferredRegister", "registers_content"),
    ("DeferredHolder", "registers_content"),
    ("RegistryObject", "registers_content"),
    ("bus/api/RegisterEvent", "registers_content"),
    ("registries/ForgeRegistries", "registers_content"),
    ("network/simple/SimpleChannel", "custom_networking"),
    ("network/PacketDistributor", "custom_networking"),
    ("registration/PayloadRegistrar", "custom_networking"),
    ("fabricmc/fabric/api/networking", "custom_networking"),
    ("CommandRegistrationCallback", "registers_commands"),
    ("event/RegisterCommandsEvent", "registers_commands"),
    ("ClientCommandRegistrationCallback", "registers_commands"),
    ("common/ForgeConfigSpec", "has_config"),
    ("common/ModConfigSpec", "has_config"),
    ("shedaniel/clothconfig", "has_config"),
    ("eu/midnightdust/lib/config", "has_config"),
    ("client/KeyMapping", "adds_keybindings"),
    ("client/option/KeyBinding", "adds_keybindings"),
    ("KeyBindingHelper", "adds_keybindings"),
    ("world/item/CreativeModeTab", "adds_creative_tab"),
    ("itemgroup/v1/FabricItemGroup", "adds_creative_tab"),
    ("block/entity/BlockEntityType", "adds_block_entities"),
    ("attachment/AttachmentType", "uses_data_attachments"),
    ("common/capabilities/CapabilityManager", "uses_forge_capabilities"),
    ("worldgen/feature/ConfiguredFeature", "has_worldgen"),
    ("worldgen/placement/PlacedFeature", "has_worldgen"),
];

/// Aggregated whole-jar intelligence: every event the mod subscribes to or
/// registers anywhere in its classes, and the capability tokens its bytecode
/// evidences.
#[derive(Default, Debug)]
pub(crate) struct JarIntel {
    pub events: Vec<String>,
    pub capabilities: Vec<String>,
}

/// Scan up to [`MAX_CLASSES_SCANNED`] of a jar's classes for event subscriptions
/// / registrations and capability references. `entrypoint_classes` (dotted names)
/// additionally get the bytecode opcode walk (Fabric/Quilt `register` calls);
/// every class gets the cheaper annotation + constant-pool pass.
pub(crate) fn analyze_jar<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    entrypoint_classes: &BTreeSet<String>,
) -> JarIntel {
    let mut events = Vec::new();
    let mut caps: BTreeSet<&'static str> = BTreeSet::new();
    let limit = archive.len().min(MAX_CLASSES_SCANNED);
    for i in 0..limit {
        let (dotted, bytes) = {
            let Ok(mut entry) = archive.by_index(i) else {
                continue;
            };
            let name = entry.name().to_string();
            if !name.ends_with(".class") || name.contains("module-info") {
                continue;
            }
            let dotted = name.strip_suffix(".class").unwrap_or(&name).replace('/', ".");
            let mut bytes = Vec::new();
            if entry.read_to_end(&mut bytes).is_err() {
                continue;
            }
            (dotted, bytes)
        };
        let is_entry = entrypoint_classes.contains(&dotted);
        scan_class_signals(&bytes, is_entry, &mut events, &mut caps);
    }
    JarIntel {
        events,
        capabilities: caps.into_iter().map(str::to_string).collect(),
    }
}

/// Per-class pass: `@SubscribeEvent`/`@EventBusSubscriber` annotations + Fabric
/// `register` opcodes (entry classes only) + capability constant-pool references.
fn scan_class_signals(
    bytes: &[u8],
    is_entry: bool,
    events: &mut Vec<String>,
    caps: &mut BTreeSet<&'static str>,
) {
    if bytes.len() < 4 || bytes[..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
        return;
    }
    let mut opts = ParseOptions::default();
    // Parse method bodies: the Fabric `register` walk and event-handler *cost*
    // analysis both need opcodes. (Full level only — see `analyze_jar`.)
    opts.parse_bytecode(true);
    let Ok(class) = parse_class_with_options(bytes, &opts) else {
        return;
    };

    for method in &class.methods {
        if method
            .attributes
            .iter()
            .any(|attr| annotations_contain(&attr.data, SUBSCRIBE_EVENT).is_some())
        {
            let event = method
                .descriptor
                .parameters
                .first()
                .and_then(|p| object_simple_name(&p.field_type));
            if let Some(name) = &event {
                push_unique(events, name.clone());
            }
            // Handler-body cost — a heavy handler on a *tick* event is a direct
            // performance signal (it runs every tick). Real bytecode analysis.
            let cost = method_body_cost(&method.attributes);
            let is_tick = event.as_deref().is_some_and(|e| e.to_ascii_lowercase().contains("tick"));
            if cost.is_heavy() {
                caps.insert("heavy_event_handler");
                if is_tick {
                    caps.insert("heavy_tick_handler");
                }
            }
        }
        if is_entry {
            let mut a = EntrypointAnalysis::default();
            scan_method_registrations(&method.attributes, &mut a);
            for e in a.events {
                push_unique(events, e);
            }
        }
    }

    for item in class.constantpool_iter() {
        let class_ref = match item {
            ConstantPoolItem::ClassInfo(name) => Some(name.as_ref().to_string()),
            ConstantPoolItem::MethodRef(m)
            | ConstantPoolItem::InterfaceMethodRef(m)
            | ConstantPoolItem::FieldRef(m) => Some(m.class_name.as_ref().to_string()),
            _ => None,
        };
        if let Some(class_ref) = class_ref {
            for (needle, token) in CAPABILITY_REFS {
                if class_ref.contains(needle) {
                    caps.insert(token);
                }
            }
        }
    }
}

/// Cheap structural cost of a method body, used to flag heavy event handlers.
struct MethodCost {
    instructions: usize,
    has_loop: bool,
    allocations: usize,
}

impl MethodCost {
    /// A handler is "heavy" when it is large, loops, or allocates repeatedly —
    /// each meaningful when the method runs every tick.
    fn is_heavy(&self) -> bool {
        self.instructions > 120
            || (self.instructions > 50 && self.has_loop)
            || self.allocations >= 4
    }
}

/// Structural cost of a method's `Code`: instruction count, whether it loops
/// (a back-edge branch), and how many objects/arrays it allocates.
fn method_body_cost(attributes: &[cafebabe::attributes::AttributeInfo<'_>]) -> MethodCost {
    let mut cost = MethodCost {
        instructions: 0,
        has_loop: false,
        allocations: 0,
    };
    let Some(code) = attributes.iter().find_map(|attr| match &attr.data {
        AttributeData::Code(c) => Some(c),
        _ => None,
    }) else {
        return cost;
    };
    let Some(bytecode) = &code.bytecode else {
        return cost;
    };
    cost.instructions = bytecode.opcodes.len();
    for (offset, op) in &bytecode.opcodes {
        match op {
            Opcode::New(_)
            | Opcode::Newarray(_)
            | Opcode::Anewarray(_)
            | Opcode::Multianewarray(_, _) => cost.allocations += 1,
            _ => {}
        }
        if let Some(rel) = branch_rel(op) {
            // A branch whose target is at or before it is a back-edge → a loop.
            if (*offset as i64 + rel as i64) <= *offset as i64 {
                cost.has_loop = true;
            }
        }
    }
    cost
}

/// Relative jump offset of a branch opcode, if any.
fn branch_rel(op: &Opcode<'_>) -> Option<i32> {
    match op {
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

#[cfg(test)]
pub(crate) mod testgen {
    //! Minimal hand-assembled class-file builder for tests (no `javac` available).
    //! cafebabe parses structurally without verifying, so a Code-less abstract
    //! method with a `@SubscribeEvent` annotation is enough to exercise the analyzer.

    fn u16v(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn utf8(out: &mut Vec<u8>, s: &str) {
        out.push(1);
        u16v(out, s.len() as u16);
        out.extend_from_slice(s.as_bytes());
    }
    fn class_entry(out: &mut Vec<u8>, name_idx: u16) {
        out.push(7);
        u16v(out, name_idx);
    }

    /// A class with one `@SubscribeEvent public abstract void onEvent(<event_desc>)`.
    /// `event_desc` is a JVM field descriptor, e.g.
    /// `Lnet/minecraftforge/event/server/ServerStartingEvent;`.
    pub fn subscribe_event_class(event_desc: &str) -> Vec<u8> {
        let method_desc = format!("({event_desc})V");
        let mut b = Vec::new();
        b.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        u16v(&mut b, 0); // minor
        u16v(&mut b, 52); // major (Java 8)
        u16v(&mut b, 9); // constant_pool_count = entries(8) + 1
        utf8(&mut b, "TestSub"); // #1
        class_entry(&mut b, 1); // #2
        utf8(&mut b, "java/lang/Object"); // #3
        class_entry(&mut b, 3); // #4
        utf8(&mut b, "onEvent"); // #5
        utf8(&mut b, &method_desc); // #6
        utf8(&mut b, "RuntimeVisibleAnnotations"); // #7
        utf8(&mut b, "Lnet/minecraftforge/eventbus/api/SubscribeEvent;"); // #8
        u16v(&mut b, 0x0421); // class: PUBLIC|SUPER|ABSTRACT
        u16v(&mut b, 2); // this_class
        u16v(&mut b, 4); // super_class
        u16v(&mut b, 0); // interfaces
        u16v(&mut b, 0); // fields
        u16v(&mut b, 1); // methods
        u16v(&mut b, 0x0401); // method: PUBLIC|ABSTRACT (legal without Code)
        u16v(&mut b, 5); // name_index
        u16v(&mut b, 6); // descriptor_index
        u16v(&mut b, 1); // attributes_count
        u16v(&mut b, 7); // attribute_name_index = RuntimeVisibleAnnotations
        b.extend_from_slice(&6u32.to_be_bytes()); // attribute_length
        u16v(&mut b, 1); // num_annotations
        u16v(&mut b, 8); // annotation type_index
        u16v(&mut b, 0); // num_element_value_pairs
        u16v(&mut b, 0); // class attributes_count
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_event_method_yields_event_from_first_parameter() {
        let bytes = testgen::subscribe_event_class(
            "Lnet/minecraftforge/event/server/ServerStartingEvent;",
        );
        let a = analyze_entrypoint_class(&bytes).expect("analysis");
        assert_eq!(a.entrypoint_type, Some("event_bus_subscriber"));
        assert!(a.registers_listeners);
        assert_eq!(a.events, vec!["ServerStartingEvent".to_string()]);
    }

    #[test]
    fn primitive_event_parameter_is_ignored_gracefully() {
        // A non-object first parameter (degenerate) must not panic or fabricate.
        let a = analyze_entrypoint_class(&testgen::subscribe_event_class("I")).expect("analysis");
        assert!(a.registers_listeners);
        assert!(a.events.is_empty());
    }

    #[test]
    fn non_class_bytes_return_none() {
        assert!(analyze_entrypoint_class(b"not a class").is_none());
        assert!(analyze_entrypoint_class(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00]).is_none());
    }

    #[test]
    fn simple_class_strips_package_and_inner() {
        assert_eq!(simple_class("net/minecraft/Foo"), "Foo");
        assert_eq!(simple_class("net.minecraft.Foo$Bar"), "Bar");
    }
}
