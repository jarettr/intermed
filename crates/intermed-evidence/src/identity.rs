//! Canonical identities shared by every analysis layer.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_id!(ArtifactId);
string_id!(MappingGraphId);
string_id!(DependencyEdgeId);
string_id!(ResourceKey);
string_id!(RuntimeOccurrenceId);
string_id!(ThrowableId);
string_id!(MixinSiteId);
string_id!(RecommendationId);
string_id!(EnvironmentId);
string_id!(JavaRuntimeId);

impl ArtifactId {
    /// Construct the preferred content identity for an artifact.
    #[must_use]
    pub fn from_sha256(hex: &str) -> Option<Self> {
        let normalized = hex.trim().to_ascii_lowercase();
        (normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| Self(format!("sha256:{normalized}")))
    }

    /// Stable unresolved identity used only until content hashing is available.
    /// The locator remains provenance and is never exposed as the artifact id.
    #[must_use]
    pub fn unresolved(locator: &str) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"intermed-unresolved-artifact-v1\0");
        digest.update(locator.replace('\\', "/").as_bytes());
        Self(format!("unresolved:{}", hex_digest(digest)))
    }
}

fn hex_digest(digest: Sha256) -> String {
    format!("{:x}", digest.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DescriptorKind {
    Fabric,
    Quilt,
    Forge,
    NeoForge,
    Bukkit,
    Paper,
    JarJar,
    Service,
    Unknown,
}

impl DescriptorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fabric => "fabric",
            Self::Quilt => "quilt",
            Self::Forge => "forge",
            Self::NeoForge => "neoforge",
            Self::Bukkit => "bukkit",
            Self::Paper => "paper",
            Self::JarJar => "jarjar",
            Self::Service => "service",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn from_token(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "fabric" | "fabric.mod.json" => Self::Fabric,
            "quilt" | "quilt.mod.json" => Self::Quilt,
            "forge" | "meta-inf/mods.toml" => Self::Forge,
            "neoforge" | "meta-inf/neoforge.mods.toml" => Self::NeoForge,
            "bukkit" | "plugin.yml" => Self::Bukkit,
            "paper" | "paper-plugin.yml" => Self::Paper,
            "jarjar" | "nested" => Self::JarJar,
            "service" => Self::Service,
            _ => Self::Unknown,
        }
    }
}

/// One declared mod identity inside one physical artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ModInstanceId {
    pub artifact: ArtifactId,
    pub declared_id: String,
    pub descriptor_kind: DescriptorKind,
    pub ordinal: u16,
}

impl fmt::Display for ModInstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{:?}:{}",
            self.artifact, self.declared_id, self.descriptor_kind, self.ordinal
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MappingNamespace {
    Official,
    MojmapNamed,
    YarnNamed,
    Intermediary,
    Srg,
    NeoForm,
    Unknown,
}

impl MappingNamespace {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::MojmapNamed => "mojmap-named",
            Self::YarnNamed => "yarn-named",
            Self::Intermediary => "intermediary",
            Self::Srg => "srg",
            Self::NeoForm => "neoform",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn from_token(value: &str) -> Self {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "official" | "official-obfuscated" => Self::Official,
            "mojmap" | "mojmap-named" | "named-mojmap" => Self::MojmapNamed,
            "yarn" | "yarn-named" | "named-yarn" => Self::YarnNamed,
            "intermediary" => Self::Intermediary,
            "srg" | "searge" => Self::Srg,
            "neoform" | "neo-form" => Self::NeoForm,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClassSymbol {
    pub name: String,
    pub namespace: MappingNamespace,
    pub mapping_graph: MappingGraphId,
}

impl ClassSymbol {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        namespace: MappingNamespace,
        mapping_graph: MappingGraphId,
    ) -> Self {
        Self {
            name: normalize_class_name(&name.into()),
            namespace,
            mapping_graph,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MethodDescriptor(pub String);

impl MethodDescriptor {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        is_method_descriptor(&value).then_some(Self(value))
    }

    #[must_use]
    pub fn unknown() -> Self {
        Self(String::new())
    }

    #[must_use]
    pub fn is_exact(&self) -> bool {
        !self.0.is_empty() && is_method_descriptor(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MethodSymbol {
    pub owner: ClassSymbol,
    pub name: String,
    pub descriptor: MethodDescriptor,
}

impl MethodSymbol {
    #[must_use]
    pub fn is_overload_safe(&self) -> bool {
        self.descriptor.is_exact()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "identity", rename_all = "kebab-case")]
pub enum EntityRef {
    Artifact(ArtifactId),
    Mod(ModInstanceId),
    Class(ClassSymbol),
    Method(MethodSymbol),
    Dependency(DependencyEdgeId),
    Resource(ResourceKey),
    RuntimeEvent(RuntimeOccurrenceId),
    Throwable(ThrowableId),
    MixinSite(MixinSiteId),
    Environment(EnvironmentId),
    JavaRuntime(JavaRuntimeId),
}

impl EntityRef {
    /// Stable semantic identity independent of the JSON wire representation.
    ///
    /// Lab datasets can outlive a report-schema revision.  Serializing this enum
    /// and using the resulting JSON as an identity would make harmless serde
    /// changes break longitudinal joins, so the identity is derived from tagged,
    /// length-delimited semantic fields instead.
    #[must_use]
    pub fn canonical_semantic_id(&self) -> String {
        let (kind, fields): (&str, Vec<String>) = match self {
            Self::Artifact(id) => ("artifact", vec![id.0.clone()]),
            Self::Mod(id) => (
                "mod",
                vec![
                    id.artifact.0.clone(),
                    id.declared_id.clone(),
                    id.descriptor_kind.as_str().to_string(),
                    id.ordinal.to_string(),
                ],
            ),
            Self::Class(symbol) => (
                "class",
                vec![
                    symbol.name.clone(),
                    symbol.namespace.as_str().to_string(),
                    symbol.mapping_graph.0.clone(),
                ],
            ),
            Self::Method(symbol) => (
                "method",
                vec![
                    symbol.owner.name.clone(),
                    symbol.owner.namespace.as_str().to_string(),
                    symbol.owner.mapping_graph.0.clone(),
                    symbol.name.clone(),
                    symbol.descriptor.0.clone(),
                ],
            ),
            Self::Dependency(id) => ("dependency", vec![id.0.clone()]),
            Self::Resource(id) => ("resource", vec![id.0.clone()]),
            Self::RuntimeEvent(id) => ("runtime-event", vec![id.0.clone()]),
            Self::Throwable(id) => ("throwable", vec![id.0.clone()]),
            Self::MixinSite(id) => ("mixin-site", vec![id.0.clone()]),
            Self::Environment(id) => ("environment", vec![id.0.clone()]),
            Self::JavaRuntime(id) => ("java-runtime", vec![id.0.clone()]),
        };
        let mut digest = Sha256::new();
        digest.update(b"intermed-entity-semantic-id-v1\0");
        tagged_field(&mut digest, kind.as_bytes());
        for field in fields {
            tagged_field(&mut digest, field.as_bytes());
        }
        format!("entity:{kind}:{}", hex_digest(digest))
    }
}

fn tagged_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

#[must_use]
pub fn normalize_class_name(value: &str) -> String {
    value.trim().trim_end_matches(".class").replace('/', ".")
}

fn is_method_descriptor(value: &str) -> bool {
    let Some(close) = value.find(')') else {
        return false;
    };
    value.starts_with('(') && close + 1 < value.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_identity_prefers_valid_sha256() {
        let hex = "a".repeat(64);
        assert_eq!(
            ArtifactId::from_sha256(&hex).unwrap().0,
            format!("sha256:{hex}")
        );
        assert!(ArtifactId::from_sha256("short").is_none());
    }

    #[test]
    fn method_identity_requires_descriptor_for_overload_safety() {
        let owner = ClassSymbol::new(
            "net/minecraft/Foo",
            MappingNamespace::Official,
            MappingGraphId::new("mapping:test"),
        );
        let exact = MethodSymbol {
            owner: owner.clone(),
            name: "tick".into(),
            descriptor: MethodDescriptor::new("(I)V").unwrap(),
        };
        let unknown = MethodSymbol {
            owner,
            name: "tick".into(),
            descriptor: MethodDescriptor::unknown(),
        };
        assert!(exact.is_overload_safe());
        assert!(!unknown.is_overload_safe());
    }

    #[test]
    fn semantic_entity_identity_is_tagged_and_wire_independent() {
        let artifact = EntityRef::Artifact(ArtifactId::new("ab:c"));
        let dependency = EntityRef::Dependency(DependencyEdgeId::new("ab:c"));
        assert_ne!(
            artifact.canonical_semantic_id(),
            dependency.canonical_semantic_id()
        );
        assert_eq!(
            artifact.canonical_semantic_id(),
            EntityRef::Artifact(ArtifactId::new("ab:c")).canonical_semantic_id()
        );
    }
}
