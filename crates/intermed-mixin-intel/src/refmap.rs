//! Refmap and mapping resolution for mixin injection points.
//!
//! Fabric mods ship `.refmap.json` files mapping obfuscated method keys to
//! named descriptors. When present, intermediary / yarn / mojmap Tiny v2 files
//! in the same jar are also parsed so names can be normalized within one scan.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Parsed SpongePowered `.refmap.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refmap {
    #[serde(default)]
    pub mappings: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub data: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
}

impl Refmap {
    /// Parse a refmap JSON document.
    pub fn parse(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// Resolve an injected method point for `target_class`.
    ///
    /// Returns `(resolved_name, was_mapped)` where `was_mapped` is `true` when
    /// a refmap entry changed the identifier.
    pub fn resolve_method(&self, target_class: &str, method: &str) -> (String, bool) {
        let class_slash = slash_name(target_class);

        for env_mappings in self.data.values() {
            if let Some(class_map) = env_mappings.get(&class_slash) {
                if let Some(mapped) = class_map.get(method) {
                    return (mapped.to_string(), true);
                }
            }
        }

        if let Some(class_map) = self.mappings.get(&class_slash) {
            if let Some(mapped) = class_map.get(method) {
                return (mapped.to_string(), true);
            }
        }

        (method.to_string(), false)
    }
}

/// The mapping namespace a resolved name is expressed in. Only names in the
/// *same* namespace are comparable across mods; **intermediary** is the one
/// namespace that is stable across every Fabric mod (yarn/named names are
/// per-mapping-version and effectively mod-private), so it is the canonical
/// comparison namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Namespace {
    /// `method_NNNN` / `field_NNNN` — Fabric-wide stable.
    Intermediary,
    /// A human/yarn name with no resolvable bridge to intermediary in this jar.
    Named,
    /// Empty or unclassifiable.
    Unknown,
}

impl Namespace {
    pub fn as_str(self) -> &'static str {
        match self {
            Namespace::Intermediary => "intermediary",
            Namespace::Named => "named",
            Namespace::Unknown => "unknown",
        }
    }
}

/// True when `name` (the bare name, no descriptor) is an intermediary token
/// (`method_<digits>` or `field_<digits>`) — the cross-mod-stable form.
pub fn is_intermediary_name(name: &str) -> bool {
    for prefix in ["method_", "field_"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
        }
    }
    false
}

/// Tiny v2 mapping layer (intermediary, yarn, mojmap, …).
///
/// Tiny v2 is a **nested, tab-indented** format: a top-level `c` row declares a
/// class, and `m`/`f` rows *indented one tab beneath it* declare its methods and
/// fields — the owner is the enclosing class, not a column on the member row.
/// Deeper-indented rows (`c` comments, `p` parameters, `v` locals) are skipped.
/// Names are positional per the header's namespace list (e.g.
/// `tiny 2 0 intermediary named`), so we resolve the `intermediary` and `named`
/// columns by namespace *name*, not a fixed column index.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TinyMappings {
    /// `namespace -> (src_class_slash -> mapped_class_slash)`.
    class_maps: BTreeMap<String, BTreeMap<String, String>>,
    /// `namespace -> (intermediary_class_slash -> (src_member -> mapped_member))`.
    method_maps: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    /// `namespace -> (intermediary_class_slash -> (src_field -> mapped_field))`.
    field_maps: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    /// Reverse index `intermediary_class_slash -> (named_name -> intermediary_name)`,
    /// so a named injection point can be canonicalized back to intermediary for
    /// cross-mod comparison.
    named_to_intermediary: BTreeMap<String, BTreeMap<String, String>>,
    /// `named_class_dotted -> intermediary_class_slash` from Tiny `c` rows.
    named_class_to_intermediary: BTreeMap<String, String>,
    /// `intermediary_class_slash -> named_class_dotted`.
    intermediary_class_to_named: BTreeMap<String, String>,
    /// The namespace used for human-readable resolution (`named` when present).
    named_ns: String,
}

impl TinyMappings {
    /// Parse Tiny v2 text. Returns `None` on empty or unrecognised input.
    ///
    /// Indentation is significant and must be preserved (the previous
    /// implementation trimmed every line, collapsing the nesting and mistaking a
    /// member's descriptor column for an owner — so real Tiny v2 never resolved).
    pub fn parse(text: &str) -> Option<Self> {
        let mut raw = text.lines();
        let header = loop {
            let l = raw.next()?;
            if !l.trim().is_empty() {
                break l;
            }
        };
        if !header.starts_with("tiny\t") {
            return None;
        }
        let parts: Vec<&str> = header.split('\t').collect();
        if parts.len() < 4 {
            return None;
        }
        let namespaces: Vec<String> = parts[3..].iter().map(|s| s.to_string()).collect();
        if namespaces.is_empty() {
            return None;
        }
        // The first namespace is the row "source"; resolve intermediary/named by
        // name so 2-ns (intermediary,named) and 3-ns (official,intermediary,named)
        // Tiny files both work.
        let inter_idx = namespaces.iter().position(|n| n == "intermediary").unwrap_or(0);
        let named_idx = namespaces
            .iter()
            .position(|n| n == "named")
            .unwrap_or(namespaces.len() - 1);
        let named_ns = namespaces[named_idx].clone();

        let mut out = Self {
            named_ns,
            ..Self::default()
        };
        for ns in &namespaces {
            out.class_maps.insert(ns.clone(), BTreeMap::new());
            out.method_maps.insert(ns.clone(), BTreeMap::new());
            out.field_maps.insert(ns.clone(), BTreeMap::new());
        }

        // The class currently in scope, as its intermediary slash (the key the
        // analyzer queries members by). `None` until the first `c` row.
        let mut class_inter: Option<String> = None;

        for line in raw {
            if line.trim().is_empty() {
                continue;
            }
            let depth = line.bytes().take_while(|&b| b == b'\t').count();
            let cols: Vec<&str> = line[depth..].split('\t').collect();
            match (depth, cols.first().copied()) {
                // Top-level class row.
                (0, Some("c")) => {
                    let names = &cols[1..];
                    if names.is_empty() {
                        class_inter = None;
                        continue;
                    }
                    let src = names[0].to_string();
                    let inter = names.get(inter_idx).copied().unwrap_or(names[0]).to_string();
                    class_inter = Some(inter.clone());
                    for (i, ns) in namespaces.iter().enumerate() {
                        let mapped = names.get(i).copied().unwrap_or(names[0]);
                        if let Some(m) = out.class_maps.get_mut(ns) {
                            m.insert(src.clone(), mapped.to_string());
                        }
                    }
                    if let Some(named) = names.get(named_idx) {
                        if *named != inter {
                            out.named_class_to_intermediary
                                .insert(dotted_name(named), inter.clone());
                            out.intermediary_class_to_named
                                .insert(inter.clone(), dotted_name(named));
                        }
                    }
                }
                // Member rows nested one tab under the current class. Layout:
                // `<tab>m<tab><descriptor><tab><ns0name><tab><ns1name>…`.
                (1, Some(tag @ ("m" | "f"))) => {
                    let Some(ref owner) = class_inter else { continue };
                    // cols[0]=tag, cols[1]=descriptor, cols[2..]=names per namespace.
                    if cols.len() < 3 {
                        continue;
                    }
                    let names = &cols[2..];
                    let src = names[0].to_string();
                    let target = if tag == "m" {
                        &mut out.method_maps
                    } else {
                        &mut out.field_maps
                    };
                    for (i, ns) in namespaces.iter().enumerate() {
                        let mapped = names.get(i).copied().unwrap_or(names[0]);
                        if let Some(by_class) = target.get_mut(ns) {
                            by_class
                                .entry(owner.clone())
                                .or_default()
                                .insert(src.clone(), mapped.to_string());
                        }
                    }
                    if tag == "m" {
                        if let Some(named) = names.get(named_idx) {
                            out.named_to_intermediary
                                .entry(owner.clone())
                                .or_default()
                                .insert((*named).to_string(), src.clone());
                        }
                    }
                }
                // Deeper rows (parameters, locals, comments) carry no class-level
                // identity we resolve on.
                _ => {}
            }
        }
        Some(out)
    }

    /// Resolve a method name within `class_slash` to its most human-readable
    /// form (the `named` namespace when present), else any non-identity mapping.
    pub fn resolve_method(&self, class_slash: &str, method: &str) -> Option<String> {
        if let Some(mapped) = self
            .method_maps
            .get(&self.named_ns)
            .and_then(|c| c.get(class_slash))
            .and_then(|mm| mm.get(method))
        {
            if mapped != method {
                return Some(mapped.clone());
            }
        }
        for (ns, map) in &self.method_maps {
            if ns == &self.named_ns {
                continue;
            }
            if let Some(mapped) = map.get(class_slash).and_then(|mm| mm.get(method)) {
                if mapped != method {
                    return Some(mapped.clone());
                }
            }
        }
        None
    }

    /// Map a *named* method back to its intermediary name within `class_slash`,
    /// for cross-mod canonicalization. `None` when this jar's Tiny file has no
    /// bridge for that name.
    pub fn to_intermediary(&self, class_slash: &str, named: &str) -> Option<String> {
        self.named_to_intermediary
            .get(class_slash)
            .and_then(|m| m.get(named))
            .cloned()
    }

    /// Map a *named* class (dotted or slash) to its intermediary slash form.
    pub fn to_intermediary_class(&self, class: &str) -> Option<String> {
        let dotted = dotted_name(class);
        self.named_class_to_intermediary.get(&dotted).cloned()
    }

    /// Map an intermediary class slash to its named dotted form.
    pub fn to_named_class(&self, class_slash: &str) -> Option<String> {
        self.intermediary_class_to_named.get(class_slash).cloned()
    }

    /// Expand mixin `@Mixin` targets into every JVM owner slash form that may
    /// appear in compiled handler bytecode for this jar.
    pub fn expand_target_owner_slash(&self, targets: &[String]) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for target in targets {
            let slash = target.replace('.', "/");
            out.insert(slash.clone());
            if let Some(inter) = self.to_intermediary_class(target) {
                out.insert(inter);
            }
            if let Some(named) = self.to_named_class(&slash) {
                out.insert(named.replace('.', "/"));
            }
        }
        out
    }
}

/// Combined mapping context used during one jar scan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MappingContext {
    pub refmap: Option<Refmap>,
    pub tiny: Option<TinyMappings>,
    /// Cross-run normalization table built from all resolved names in one scan.
    pub normalized_names: BTreeMap<String, String>,
}

impl MappingContext {
    /// Create an empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a parsed refmap.
    pub fn with_refmap(mut self, refmap: Refmap) -> Self {
        self.refmap = Some(refmap);
        self
    }

    /// Attach parsed Tiny mappings.
    pub fn with_tiny(mut self, tiny: TinyMappings) -> Self {
        self.tiny = Some(tiny);
        self
    }

    /// Resolve an injection point and canonicalize it for cross-mod comparison.
    ///
    /// `display` is the most human-readable resolution (refmap then Tiny applied);
    /// `canonical` is the key the analyzer compares on, expressed in the
    /// **intermediary** namespace whenever it can be determined (an intermediary
    /// token among the candidates, or a Tiny named→intermediary reverse lookup).
    /// When no bridge to intermediary exists, `canonical` stays the named form
    /// and `namespace` records that — so the analyzer never silently treats a
    /// named key and an intermediary key for the same method as *different*; it
    /// compares within one namespace and flags the residual ambiguity.
    pub fn resolve_injection(&mut self, target_class: &str, method: &str) -> ResolvedSite {
        let class_slash = slash_name(target_class);
        let mut display = method.to_string();
        let mut mapped = false;

        if let Some(ref r) = self.refmap {
            let (r_name, r_mapped) = r.resolve_method(target_class, method);
            display = r_name;
            mapped = r_mapped;
        }
        if let Some(ref tiny) = self.tiny {
            if let Some(t_name) = tiny.resolve_method(&class_slash, &display) {
                if t_name != display {
                    mapped = true;
                }
                display = t_name;
            }
        }

        let (canonical, namespace) = self.canonicalize(&class_slash, method, &display);
        self.normalized_names
            .entry(canonical.clone())
            .or_insert_with(|| display.clone());
        ResolvedSite {
            display,
            canonical,
            namespace,
            mapped,
        }
    }

    /// Express a resolved site in the intermediary namespace when possible.
    fn canonicalize(&self, class_slash: &str, original: &str, display: &str) -> (String, Namespace) {
        // 1. An intermediary token among the candidates is already canonical.
        for cand in [display, original] {
            let (name, desc) = split_method_name_descriptor(cand);
            if is_intermediary_name(name) {
                return (rejoin(name, desc), Namespace::Intermediary);
            }
        }
        // 2. Bridge a named token back to intermediary via this jar's Tiny file.
        if let Some(ref tiny) = self.tiny {
            let (name, desc) = split_method_name_descriptor(display);
            if let Some(inter) = tiny.to_intermediary(class_slash, name) {
                return (rejoin(&inter, desc), Namespace::Intermediary);
            }
        }
        // 3. No bridge: keep the named form, tagged as such.
        let d = display.trim();
        if d.is_empty() {
            (String::new(), Namespace::Unknown)
        } else {
            (d.to_string(), Namespace::Named)
        }
    }
}

/// A resolved injection point: human display name + a namespace-canonical key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSite {
    pub display: String,
    pub canonical: String,
    pub namespace: Namespace,
    pub mapped: bool,
}

/// Rejoin a split name and optional descriptor.
fn rejoin(name: &str, desc: Option<&str>) -> String {
    match desc {
        Some(d) => format!("{name}{d}"),
        None => name.to_string(),
    }
}

/// Convert dotted or slash class names to slash form.
pub fn slash_name(reference: &str) -> String {
    reference.trim().replace('.', "/")
}

/// Convert slash or dotted class names to dotted form.
pub fn dotted_name(reference: &str) -> String {
    reference.trim().replace('/', ".")
}

fn split_method_name_descriptor(method: &str) -> (&str, Option<&str>) {
    if let Some(ix) = method.find('(') {
        (&method[..ix], Some(&method[ix..]))
    } else if let Some(ix) = method.find(':') {
        (&method[..ix], Some(&method[ix..]))
    } else {
        (method, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_name_converts_slashes() {
        assert_eq!(
            dotted_name("net/minecraft/server/MinecraftServer"),
            "net.minecraft.server.MinecraftServer"
        );
    }

    #[test]
    fn refmap_resolves_obfuscated_method() {
        let json = r#"{
            "mappings": {
                "net/minecraft/server/MinecraftServer": {
                    "method_1574": "tick()V"
                }
            }
        }"#;
        let map = Refmap::parse(json).unwrap();
        let (resolved, mapped) = map.resolve_method("net.minecraft.server.MinecraftServer", "method_1574");
        assert_eq!(resolved, "tick()V");
        assert!(mapped);
    }

    #[test]
    fn tiny_v2_nested_method_rows_are_parsed_with_class_context() {
        // Real Tiny v2: the method row is indented one tab under its class `c`
        // row; the owner is the enclosing class, the descriptor is its own
        // column, and names are positional per the namespace header.
        let tiny = "tiny\t2\t0\tintermediary\tnamed\n\
                    c\tnet/minecraft/class_3218\tnet/minecraft/server/MinecraftServer\n\
                    \tm\t()V\tmethod_1574\ttick\n\
                    \tf\tI\tfield_100\tticks\n";
        let map = TinyMappings::parse(tiny).unwrap();
        // Members are keyed by the *intermediary* class slash (col for ns
        // `intermediary`), not by a column on the member row.
        let resolved = map
            .resolve_method("net/minecraft/class_3218", "method_1574")
            .unwrap();
        assert_eq!(resolved, "tick");
        // A named injection point bridges back to intermediary for comparison.
        assert_eq!(
            map.to_intermediary("net/minecraft/class_3218", "tick"),
            Some("method_1574".to_string())
        );
        // Class bridges resolve by namespace name (intermediary↔named).
        assert_eq!(
            map.to_intermediary_class("net.minecraft.server.MinecraftServer"),
            Some("net/minecraft/class_3218".to_string())
        );
    }

    #[test]
    fn tiny_skips_deeper_indented_comment_and_param_rows() {
        // Comments (`c`) and parameters (`p`) nested under a method must not be
        // mistaken for classes/members.
        let tiny = "tiny\t2\t0\tintermediary\tnamed\n\
                    c\tnet/minecraft/class_1\tnet/minecraft/Foo\n\
                    \tm\t(I)V\tmethod_2\tbar\n\
                    \t\tp\t0\t\tcount\n\
                    \t\tc\tThis is a comment\n";
        let map = TinyMappings::parse(tiny).unwrap();
        assert_eq!(map.resolve_method("net/minecraft/class_1", "method_2"), Some("bar".to_string()));
        // The deeper `c` comment must not have registered a bogus class.
        assert_eq!(map.to_intermediary_class("This is a comment"), None);
    }

    #[test]
    fn tiny_bridges_named_and_intermediary_classes() {
        let tiny = "tiny\t2\t0\tintermediary\tnamed\n\
                    c\tnet/minecraft/class_3215\tnet/minecraft/server/MinecraftServer\n";
        let map = TinyMappings::parse(tiny).unwrap();
        assert_eq!(
            map.to_intermediary_class("net.minecraft.server.MinecraftServer"),
            Some("net/minecraft/class_3215".to_string())
        );
        assert_eq!(
            map.to_named_class("net/minecraft/class_3215"),
            Some("net.minecraft.server.MinecraftServer".to_string())
        );
        let owners = map.expand_target_owner_slash(&[
            "net.minecraft.server.MinecraftServer".to_string()
        ]);
        assert!(owners.contains("net/minecraft/server/MinecraftServer"));
        assert!(owners.contains("net/minecraft/class_3215"));
    }

    #[test]
    fn named_bridges_to_intermediary_for_canonical_comparison() {
        // A jar that ships Tiny mappings can pull a named injection point back to
        // intermediary, so it lines up with another mod that used intermediary.
        let tiny = "tiny\t2\t0\tintermediary\tnamed\n\
                    c\tnet/minecraft/server/MinecraftServer\tnet/minecraft/server/MinecraftServer\n\
                    \tm\t()V\tmethod_1574\ttick\n";
        let mut ctx = MappingContext::new().with_tiny(TinyMappings::parse(tiny).unwrap());
        // Mod wrote the named form `tick`; canonical must come back as intermediary.
        let site = ctx.resolve_injection("net.minecraft.server.MinecraftServer", "tick");
        assert_eq!(site.namespace, Namespace::Intermediary);
        assert_eq!(site.canonical, "method_1574");

        // A mod already in intermediary canonicalizes to the same key.
        let mut ctx2 = MappingContext::new();
        let site2 = ctx2.resolve_injection("net.minecraft.server.MinecraftServer", "method_1574()V");
        assert_eq!(site2.namespace, Namespace::Intermediary);
        assert_eq!(site2.canonical, "method_1574()V");
    }

    #[test]
    fn named_without_bridge_stays_named_namespace() {
        let mut ctx = MappingContext::new();
        let site = ctx.resolve_injection("net.minecraft.Foo", "tick");
        assert_eq!(site.namespace, Namespace::Named);
        assert_eq!(site.canonical, "tick");
    }

    #[test]
    fn intermediary_detection() {
        assert!(is_intermediary_name("method_1574"));
        assert!(is_intermediary_name("field_42"));
        assert!(!is_intermediary_name("tick"));
        assert!(!is_intermediary_name("method_"));
        assert!(!is_intermediary_name("method_x"));
    }
}