//! Refmap and mapping resolution for mixin injection points.
//!
//! Fabric mods ship `.refmap.json` files mapping obfuscated method keys to
//! named descriptors. When present, intermediary / yarn / mojmap Tiny v2 files
//! in the same jar are also parsed so names can be normalized within one scan.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAPPING_PARSER_VERSION: &str = "tiny-v2-r2";

type SignatureTranslationKey = (String, String, String, String, String);
type SignatureTranslation = (String, String, String);
type SignatureTranslations = BTreeMap<SignatureTranslationKey, BTreeSet<SignatureTranslation>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MappingIncompatibility {
    MinecraftVersionMismatch { mapping: String, target: String },
    NamespaceNotDeclared { namespace: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingGap {
    pub edge: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resolution", rename_all = "kebab-case")]
pub enum MappingResolution<T> {
    Exact {
        value: T,
        path: Vec<MappingEdge>,
    },
    Ambiguous {
        candidates: Vec<T>,
    },
    Partial {
        translated: Option<T>,
        missing_edges: Vec<MappingGap>,
    },
    Incompatible {
        reason: MappingIncompatibility,
    },
    Unavailable,
}

impl<T> MappingResolution<T> {
    #[must_use]
    pub fn exact(self) -> Option<T> {
        match self {
            Self::Exact { value, .. } => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingEdge {
    pub from_namespace: String,
    pub to_namespace: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingFileIdentity {
    pub graph_id: String,
    pub source: String,
    pub sha256: String,
    pub minecraft_version: Option<String>,
    pub source_namespace: String,
    pub target_namespaces: Vec<String>,
    pub parser_version: String,
}

impl Default for MappingFileIdentity {
    fn default() -> Self {
        Self {
            graph_id: "mapping:unavailable".to_string(),
            source: String::new(),
            sha256: String::new(),
            minecraft_version: None,
            source_namespace: String::new(),
            target_namespaces: Vec::new(),
            parser_version: MAPPING_PARSER_VERSION.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MappedMethod {
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    pub namespace: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MappedField {
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    pub namespace: String,
}

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
            if let Some(class_map) = env_mappings.get(&class_slash)
                && let Some(mapped) = class_map.get(method)
            {
                return (mapped.to_string(), true);
            }
        }

        if let Some(class_map) = self.mappings.get(&class_slash)
            && let Some(mapped) = class_map.get(method)
        {
            return (mapped.to_string(), true);
        }

        (method.to_string(), false)
    }
}

/// The mapping namespace a resolved name is expressed in. Only names in the
/// *same* namespace are comparable across mods; **intermediary** is the one
/// namespace that is stable across every Fabric mod (yarn/named names are
/// per-mapping-version and effectively mod-private), so it is the canonical
/// comparison namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Namespace {
    /// `method_NNNN` / `field_NNNN` — Fabric-wide stable.
    Intermediary,
    /// A human/yarn name with no resolvable bridge to intermediary in this jar.
    Named,
    /// Empty or unclassifiable.
    #[default]
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
/// (`method_<digits>`, `field_<digits>`, or `class_<digits>`) — the cross-mod-stable form.
pub fn is_intermediary_name(name: &str) -> bool {
    for prefix in ["method_", "field_", "class_"] {
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
    identity: MappingFileIdentity,
    target_minecraft_version: Option<String>,
    namespaces: Vec<String>,
    /// Pairwise class-name graph keyed by `(from namespace, to namespace, name)`.
    class_translations: BTreeMap<(String, String, String), String>,
    /// Pairwise method-name graph keyed by `(from ns, to ns, owner, member)`.
    method_translations: BTreeMap<(String, String, String, String), String>,
    /// Descriptor-aware graph. Values are sets so overload ambiguity cannot be
    /// hidden by last-writer-wins insertion.
    method_signature_translations: SignatureTranslations,
    field_signature_translations: SignatureTranslations,
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
        Self::parse_with_identity(text, "embedded:mappings.tiny", None)
    }

    /// Parse a Tiny mapping graph while retaining the mapping artifact identity.
    pub fn parse_with_identity(
        text: &str,
        source: impl Into<String>,
        minecraft_version: Option<String>,
    ) -> Option<Self> {
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
        let inter_idx = namespaces
            .iter()
            .position(|n| n == "intermediary")
            .unwrap_or(0);
        let named_idx = namespaces
            .iter()
            .position(|n| n == "named")
            // Lazy fallback: the argument to `unwrap_or` is eager, so on an
            // empty (truncated) namespace list `namespaces.len() - 1` would
            // underflow before the guard above could ever matter. `saturating_sub`
            // keeps it safe even if that guard is removed.
            .unwrap_or_else(|| namespaces.len().saturating_sub(1));
        let named_ns = namespaces[named_idx].clone();

        let source = source.into();
        let sha256 = format!("{:x}", Sha256::digest(text.as_bytes()));
        let minecraft_version = minecraft_version.or_else(|| infer_minecraft_version(&source));
        let identity = MappingFileIdentity {
            graph_id: format!("mapping:sha256:{sha256}"),
            source,
            sha256,
            minecraft_version,
            source_namespace: namespaces[0].clone(),
            target_namespaces: namespaces.iter().skip(1).cloned().collect(),
            parser_version: MAPPING_PARSER_VERSION.to_string(),
        };
        let mut out = Self {
            identity,
            named_ns,
            namespaces: namespaces.clone(),
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
        let mut current_class_names: Option<Vec<String>> = None;
        let mut raw_members = Vec::<(String, String, Vec<String>, Vec<String>)>::new();

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
                    let all_names = (0..namespaces.len())
                        .map(|i| names.get(i).copied().unwrap_or(names[0]).to_string())
                        .collect::<Vec<_>>();
                    for (from_idx, from_ns) in namespaces.iter().enumerate() {
                        for (to_idx, to_ns) in namespaces.iter().enumerate() {
                            out.class_translations.insert(
                                (from_ns.clone(), to_ns.clone(), all_names[from_idx].clone()),
                                all_names[to_idx].clone(),
                            );
                        }
                    }
                    current_class_names = Some(all_names);
                    let inter = names
                        .get(inter_idx)
                        .copied()
                        .unwrap_or(names[0])
                        .to_string();
                    class_inter = Some(inter.clone());
                    for (i, ns) in namespaces.iter().enumerate() {
                        let mapped = names.get(i).copied().unwrap_or(names[0]);
                        if let Some(m) = out.class_maps.get_mut(ns) {
                            m.insert(src.clone(), mapped.to_string());
                        }
                    }
                    if let Some(named) = names.get(named_idx)
                        && *named != inter
                    {
                        out.named_class_to_intermediary
                            .insert(dotted_name(named), inter.clone());
                        out.intermediary_class_to_named
                            .insert(inter.clone(), dotted_name(named));
                    }
                }
                // Member rows nested one tab under the current class. Layout:
                // `<tab>m<tab><descriptor><tab><ns0name><tab><ns1name>…`.
                (1, Some(tag @ ("m" | "f"))) => {
                    let Some(ref owner) = class_inter else {
                        continue;
                    };
                    // cols[0]=tag, cols[1]=descriptor, cols[2..]=names per namespace.
                    if cols.len() < 3 {
                        continue;
                    }
                    let names = &cols[2..];
                    let src = names[0].to_string();
                    let all_member_names = (0..namespaces.len())
                        .map(|i| names.get(i).copied().unwrap_or(names[0]).to_string())
                        .collect::<Vec<_>>();
                    if let Some(class_names) = &current_class_names {
                        raw_members.push((
                            tag.to_string(),
                            cols[1].to_string(),
                            class_names.clone(),
                            all_member_names.clone(),
                        ));
                    }
                    if tag == "m"
                        && let Some(class_names) = &current_class_names
                    {
                        for (from_idx, from_ns) in namespaces.iter().enumerate() {
                            for (to_idx, to_ns) in namespaces.iter().enumerate() {
                                out.method_translations.insert(
                                    (
                                        from_ns.clone(),
                                        to_ns.clone(),
                                        class_names[from_idx].clone(),
                                        all_member_names[from_idx].clone(),
                                    ),
                                    all_member_names[to_idx].clone(),
                                );
                            }
                        }
                    }
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
                    if tag == "m"
                        && let Some(named) = names.get(named_idx)
                    {
                        out.named_to_intermediary
                            .entry(owner.clone())
                            .or_default()
                            .insert((*named).to_string(), src.clone());
                    }
                }
                // Deeper rows (parameters, locals, comments) carry no class-level
                // identity we resolve on.
                _ => {}
            }
        }
        // Build member edges only after every class row is known, because JVM
        // descriptors may refer to classes declared later in the Tiny file.
        for (tag, source_descriptor, class_names, member_names) in raw_members {
            for (from_idx, from_ns) in namespaces.iter().enumerate() {
                let descriptor_from =
                    out.translate_descriptor_between(&source_descriptor, &namespaces[0], from_ns);
                for (to_idx, to_ns) in namespaces.iter().enumerate() {
                    let descriptor_to =
                        out.translate_descriptor_between(&source_descriptor, &namespaces[0], to_ns);
                    let (Some(descriptor_from), Some(descriptor_to)) =
                        (descriptor_from.clone(), descriptor_to)
                    else {
                        continue;
                    };
                    let key = (
                        from_ns.clone(),
                        to_ns.clone(),
                        class_names[from_idx].clone(),
                        member_names[from_idx].clone(),
                        descriptor_from,
                    );
                    let value = (
                        class_names[to_idx].clone(),
                        member_names[to_idx].clone(),
                        descriptor_to,
                    );
                    let target = if tag == "m" {
                        &mut out.method_signature_translations
                    } else {
                        &mut out.field_signature_translations
                    };
                    target.entry(key).or_default().insert(value);
                }
            }
        }
        Some(out)
    }

    #[must_use]
    pub fn identity(&self) -> &MappingFileIdentity {
        &self.identity
    }

    #[must_use]
    pub fn with_target_minecraft_version(mut self, version: Option<String>) -> Self {
        self.target_minecraft_version = version;
        self
    }

    #[must_use]
    pub fn target_compatible(&self) -> bool {
        match (
            self.identity.minecraft_version.as_deref(),
            self.target_minecraft_version.as_deref(),
        ) {
            (Some(mapping), Some(target)) => mapping == target,
            _ => true,
        }
    }

    #[must_use]
    pub fn target_minecraft_version(&self) -> Option<&str> {
        self.target_minecraft_version.as_deref()
    }

    #[must_use]
    pub fn namespace_family(
        &self,
        namespace: &str,
    ) -> intermed_doctor_core::evidence::MappingNamespace {
        use intermed_doctor_core::evidence::MappingNamespace;
        match namespace {
            "official" => MappingNamespace::Official,
            "intermediary" => MappingNamespace::Intermediary,
            "srg" | "searge" => MappingNamespace::Srg,
            "neoform" => MappingNamespace::NeoForm,
            "named" if self.has_namespace("intermediary") => MappingNamespace::YarnNamed,
            "named" if self.has_namespace("official") => MappingNamespace::MojmapNamed,
            _ => MappingNamespace::Unknown,
        }
    }

    /// Resolve one overload-safe method symbol. Non-exact descriptor or version
    /// compatibility is an explicit non-Exact outcome and must not prove absence.
    pub fn resolve_method_symbol(
        &self,
        owner: &str,
        name: &str,
        descriptor: &str,
        from_namespace: &str,
        to_namespace: &str,
        target_minecraft_version: Option<&str>,
    ) -> MappingResolution<MappedMethod> {
        if let (Some(mapping), Some(target)) = (
            self.identity.minecraft_version.as_deref(),
            target_minecraft_version.or(self.target_minecraft_version.as_deref()),
        ) && mapping != target
        {
            return MappingResolution::Incompatible {
                reason: MappingIncompatibility::MinecraftVersionMismatch {
                    mapping: mapping.to_string(),
                    target: target.to_string(),
                },
            };
        }
        for namespace in [from_namespace, to_namespace] {
            if !self.has_namespace(namespace) {
                return MappingResolution::Incompatible {
                    reason: MappingIncompatibility::NamespaceNotDeclared {
                        namespace: namespace.to_string(),
                    },
                };
            }
        }
        if !is_valid_method_descriptor(descriptor) {
            return MappingResolution::Partial {
                translated: None,
                missing_edges: vec![MappingGap {
                    edge: "method-descriptor".to_string(),
                    detail: "an exact JVM method descriptor is required".to_string(),
                }],
            };
        }
        let key = (
            from_namespace.to_string(),
            to_namespace.to_string(),
            owner.replace('.', "/"),
            name.to_string(),
            descriptor.to_string(),
        );
        let Some(values) = self.method_signature_translations.get(&key) else {
            let translated = self
                .method_translations
                .get(&(
                    from_namespace.to_string(),
                    to_namespace.to_string(),
                    owner.replace('.', "/"),
                    name.to_string(),
                ))
                .map(|mapped_name| MappedMethod {
                    owner: self
                        .translate_class_from_to(owner, from_namespace, to_namespace)
                        .unwrap_or_else(|| owner.replace('.', "/")),
                    name: mapped_name.clone(),
                    descriptor: String::new(),
                    namespace: to_namespace.to_string(),
                });
            return MappingResolution::Partial {
                translated,
                missing_edges: vec![MappingGap {
                    edge: "descriptor-types".to_string(),
                    detail: "not every class type in the method descriptor has a mapping edge"
                        .to_string(),
                }],
            };
        };
        let candidates = values
            .iter()
            .map(|(owner, name, descriptor)| MappedMethod {
                owner: owner.clone(),
                name: name.clone(),
                descriptor: descriptor.clone(),
                namespace: to_namespace.to_string(),
            })
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            MappingResolution::Exact {
                value: candidates[0].clone(),
                path: vec![MappingEdge {
                    from_namespace: from_namespace.to_string(),
                    to_namespace: to_namespace.to_string(),
                    source: self.identity.graph_id.clone(),
                }],
            }
        } else {
            MappingResolution::Ambiguous { candidates }
        }
    }

    pub fn resolve_field_symbol(
        &self,
        owner: &str,
        name: &str,
        descriptor: &str,
        from_namespace: &str,
        to_namespace: &str,
    ) -> MappingResolution<MappedField> {
        let key = (
            from_namespace.to_string(),
            to_namespace.to_string(),
            owner.replace('.', "/"),
            name.to_string(),
            descriptor.to_string(),
        );
        let Some(values) = self.field_signature_translations.get(&key) else {
            return MappingResolution::Unavailable;
        };
        let candidates = values
            .iter()
            .map(|(owner, name, descriptor)| MappedField {
                owner: owner.clone(),
                name: name.clone(),
                descriptor: descriptor.clone(),
                namespace: to_namespace.to_string(),
            })
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            MappingResolution::Exact {
                value: candidates[0].clone(),
                path: vec![MappingEdge {
                    from_namespace: from_namespace.to_string(),
                    to_namespace: to_namespace.to_string(),
                    source: self.identity.graph_id.clone(),
                }],
            }
        } else {
            MappingResolution::Ambiguous { candidates }
        }
    }

    fn translate_class_from_to(&self, class: &str, from: &str, to: &str) -> Option<String> {
        self.class_translations
            .get(&(from.to_string(), to.to_string(), class.replace('.', "/")))
            .cloned()
    }

    fn translate_descriptor_between(
        &self,
        descriptor: &str,
        from: &str,
        to: &str,
    ) -> Option<String> {
        translate_jvm_descriptor(descriptor, |class| {
            self.translate_class_from_to(class, from, to)
        })
    }

    /// Resolve a method name within `class_slash` to its most human-readable
    /// form (the `named` namespace when present), else any non-identity mapping.
    pub fn resolve_method(&self, class_slash: &str, method: &str) -> Option<String> {
        if let Some(mapped) = self
            .method_maps
            .get(&self.named_ns)
            .and_then(|c| c.get(class_slash))
            .and_then(|mm| mm.get(method))
            && mapped != method
        {
            return Some(mapped.clone());
        }
        for (ns, map) in &self.method_maps {
            if ns == &self.named_ns {
                continue;
            }
            if let Some(mapped) = map.get(class_slash).and_then(|mm| mm.get(method))
                && mapped != method
            {
                return Some(mapped.clone());
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

    /// Translate a class from whichever declared namespace contains `class` to
    /// `to_namespace`. This is the class-symbol edge of the mapping graph.
    pub fn translate_class_to(&self, class: &str, to_namespace: &str) -> Option<String> {
        let slash = class.replace('.', "/");
        self.namespaces.iter().find_map(|from_namespace| {
            self.class_translations
                .get(&(
                    from_namespace.clone(),
                    to_namespace.to_string(),
                    slash.clone(),
                ))
                .cloned()
        })
    }

    /// Translate a method owner/name pair to another declared namespace.
    pub fn translate_method_to(
        &self,
        owner: &str,
        method: &str,
        to_namespace: &str,
    ) -> Option<String> {
        let owner = owner.replace('.', "/");
        self.namespaces.iter().find_map(|from_namespace| {
            self.method_translations
                .get(&(
                    from_namespace.clone(),
                    to_namespace.to_string(),
                    owner.clone(),
                    method.to_string(),
                ))
                .cloned()
        })
    }

    #[must_use]
    pub fn has_namespace(&self, namespace: &str) -> bool {
        self.namespaces
            .iter()
            .any(|candidate| candidate == namespace)
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
        if let Some(ref tiny) = self.tiny
            && let Some(t_name) = tiny.resolve_method(&class_slash, &display)
        {
            if t_name != display {
                mapped = true;
            }
            display = t_name;
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
    fn canonicalize(
        &self,
        class_slash: &str,
        original: &str,
        display: &str,
    ) -> (String, Namespace) {
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

fn is_valid_method_descriptor(descriptor: &str) -> bool {
    descriptor.starts_with('(')
        && descriptor
            .find(')')
            .is_some_and(|close| close + 1 < descriptor.len())
        && translate_jvm_descriptor(descriptor, |class| Some(class.to_string())).is_some()
}

/// Translate every object type in a JVM field/method descriptor. Platform and
/// library classes outside the Minecraft namespace retain identity; an unknown
/// Minecraft type makes the edge partial instead of guessing.
fn translate_jvm_descriptor(
    descriptor: &str,
    mut translate_class: impl FnMut(&str) -> Option<String>,
) -> Option<String> {
    if descriptor.is_empty() {
        return None;
    }
    let bytes = descriptor.as_bytes();
    let mut out = String::with_capacity(descriptor.len());
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'L' {
            let rest = &descriptor[index + 1..];
            let end = rest.find(';')?;
            let class = &rest[..end];
            let translated = translate_class(class).or_else(|| {
                (!class.starts_with("net/minecraft/") && !class.starts_with("com/mojang/"))
                    .then(|| class.to_string())
            })?;
            out.push('L');
            out.push_str(&translated);
            out.push(';');
            index += end + 2;
        } else {
            let ch = byte as char;
            if !matches!(
                ch,
                '(' | ')' | '[' | 'B' | 'C' | 'D' | 'F' | 'I' | 'J' | 'S' | 'Z' | 'V'
            ) {
                return None;
            }
            out.push(ch);
            index += 1;
        }
    }
    Some(out)
}

fn infer_minecraft_version(source: &str) -> Option<String> {
    source
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .map(|token| token.trim_matches('.'))
        .filter(|token| token.matches('.').count() >= 1)
        .find(|token| {
            token
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(str::to_string)
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
        let (resolved, mapped) =
            map.resolve_method("net.minecraft.server.MinecraftServer", "method_1574");
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
    fn mapping_graph_translates_official_intermediary_and_named_symbols() {
        let tiny = "tiny\t2\t0\tofficial\tintermediary\tnamed\n\
                    c\ta\tnet/minecraft/class_3218\tnet/minecraft/server/MinecraftServer\n\
                    \tm\t()V\tb\tmethod_1574\ttick\n";
        let map = TinyMappings::parse(tiny).unwrap();
        assert!(map.has_namespace("official"));
        assert_eq!(
            map.translate_class_to("net.minecraft.server.MinecraftServer", "official"),
            Some("a".to_string())
        );
        assert_eq!(
            map.translate_class_to("a", "intermediary"),
            Some("net/minecraft/class_3218".to_string())
        );
        assert_eq!(
            map.translate_method_to("net.minecraft.server.MinecraftServer", "tick", "official"),
            Some("b".to_string())
        );
    }

    #[test]
    fn descriptor_aware_mapping_is_overload_safe_and_translates_types() {
        let tiny = "tiny\t2\t0\tofficial\tintermediary\tnamed\n\
                    c\ta\tnet/minecraft/class_1\tnet/minecraft/Foo\n\
                    \tm\t(Lb;)Lc;\td\tmethod_1\ttick\n\
                    \tm\t(I)Lc;\te\tmethod_2\ttick\n\
                    c\tb\tnet/minecraft/class_2\tnet/minecraft/Arg\n\
                    c\tc\tnet/minecraft/class_3\tnet/minecraft/Result\n";
        let map = TinyMappings::parse(tiny).unwrap();
        let result = map.resolve_method_symbol(
            "net/minecraft/Foo",
            "tick",
            "(Lnet/minecraft/Arg;)Lnet/minecraft/Result;",
            "named",
            "official",
            None,
        );
        let MappingResolution::Exact { value, path } = result else {
            panic!("expected exact")
        };
        assert_eq!(value.owner, "a");
        assert_eq!(value.name, "d");
        assert_eq!(value.descriptor, "(Lb;)Lc;");
        assert_eq!(path[0].source, map.identity().graph_id);
    }

    #[test]
    fn missing_descriptor_edge_is_partial_not_an_absence_proof() {
        let tiny = "tiny\t2\t0\tofficial\tnamed\n\
                    c\ta\tnet/minecraft/Foo\n\
                    \tm\t(Lz;)V\tb\ttick\n";
        let map = TinyMappings::parse(tiny).unwrap();
        assert!(matches!(
            map.resolve_method_symbol(
                "net/minecraft/Foo",
                "tick",
                "(Lnet/minecraft/Missing;)V",
                "named",
                "official",
                None,
            ),
            MappingResolution::Partial { .. }
        ));
    }

    #[test]
    fn mapping_version_mismatch_is_incompatible() {
        let tiny = "tiny\t2\t0\tofficial\tnamed\n\
                    c\ta\tnet/minecraft/Foo\n\
                    \tm\t()V\tb\ttick\n";
        let map = TinyMappings::parse_with_identity(tiny, "/maps/minecraft-1.20.1.tiny", None)
            .unwrap()
            .with_target_minecraft_version(Some("1.21.1".to_string()));
        assert!(!map.target_compatible());
        assert!(matches!(
            map.resolve_method_symbol(
                "net/minecraft/Foo",
                "tick",
                "()V",
                "named",
                "official",
                None
            ),
            MappingResolution::Incompatible { .. }
        ));
    }

    #[test]
    fn named_namespace_family_is_not_interchangeable() {
        let yarn = TinyMappings::parse("tiny\t2\t0\tofficial\tintermediary\tnamed\n").unwrap();
        let mojmap = TinyMappings::parse("tiny\t2\t0\tofficial\tnamed\n").unwrap();
        assert_eq!(
            yarn.namespace_family("named"),
            intermed_doctor_core::evidence::MappingNamespace::YarnNamed
        );
        assert_eq!(
            mojmap.namespace_family("named"),
            intermed_doctor_core::evidence::MappingNamespace::MojmapNamed
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
        assert_eq!(
            map.resolve_method("net/minecraft/class_1", "method_2"),
            Some("bar".to_string())
        );
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
        let owners =
            map.expand_target_owner_slash(&["net.minecraft.server.MinecraftServer".to_string()]);
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
        let site2 =
            ctx2.resolve_injection("net.minecraft.server.MinecraftServer", "method_1574()V");
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
        assert!(is_intermediary_name("class_310"));
        assert!(!is_intermediary_name("tick"));
        assert!(!is_intermediary_name("method_"));
        assert!(!is_intermediary_name("method_x"));
        assert!(!is_intermediary_name("class_"));
        assert!(!is_intermediary_name("class_name"));
    }
}
