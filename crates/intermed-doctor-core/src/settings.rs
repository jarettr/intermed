//! Runtime diagnosis settings threaded through collectors and rules.

use std::path::PathBuf;
use std::time::SystemTime;

use intermed_facts::FactRetentionPolicy;

/// Per-layer tunables loaded from config / env / CLI.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DiagnosisSettings {
    pub metadata: MetadataSettings,
    pub security: SecuritySettings,
    pub sbom: SbomSettings,
    pub log: LogSettings,
    pub scan: ScanSettings,
    pub facts: FactStoreSettings,
    pub mixin: MixinSettings,
    pub resource: ResourceSettings,
    /// Optional Minecraft client/server jar, used to broaden the mixin
    /// apply-failure target index to vanilla classes (`--minecraft-jar`).
    pub minecraft_jar: Option<PathBuf>,
    /// Optional Yarn/Mojmap Tiny v2 mappings for bridging named mixin targets
    /// to intermediary classes in the Minecraft jar (`--minecraft-mappings`).
    pub minecraft_mappings: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataSettings {
    pub level: MetadataLevel,
}

impl Default for MetadataSettings {
    fn default() -> Self {
        Self {
            level: MetadataLevel::Enriched,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MetadataLevel {
    /// Existing manifest facts only.
    Basic,
    /// Rich manifest metadata, entrypoint classification, and relationships.
    #[default]
    Enriched,
    /// Adds class-symbol intelligence and inferred capabilities.
    Full,
}

/// Layer-F mixin analysis depth and noise controls.
///
/// Presets map to concrete toggles so large packs (`fabric_mega`) can run
/// overlap/risk scoring without hundreds of per-handler notes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MixinSettings {
    pub level: MixinLevel,
    pub handler_effects: bool,
    pub recommendations: bool,
}

impl Default for MixinSettings {
    fn default() -> Self {
        Self::from_level(MixinLevel::Detailed)
    }
}

/// Mixin analysis preset — overridden by explicit `handler_effects` /
/// `recommendations` flags from config or CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MixinLevel {
    /// Overlaps, risk scores, and high-risk overwrites only.
    #[default]
    Normal,
    /// Adds effect summaries and safer-mixin recommendations.
    Detailed,
    /// Full bytecode handler intelligence (can be noisy on large packs).
    Full,
}

impl MixinSettings {
    /// Resolve preset toggles for `level`.
    #[must_use]
    pub fn from_level(level: MixinLevel) -> Self {
        match level {
            MixinLevel::Normal => Self {
                level,
                handler_effects: false,
                recommendations: false,
            },
            MixinLevel::Detailed => Self {
                level,
                handler_effects: true,
                recommendations: true,
            },
            MixinLevel::Full => Self {
                level,
                handler_effects: true,
                recommendations: true,
            },
        }
    }

    /// Whether per-handler `mixin_handler_effect` facts should be emitted.
    #[must_use]
    pub fn emit_handler_effect_facts(self) -> bool {
        self.handler_effects
    }

    /// Whether safer-mixin `mixin_recommendation` facts should be emitted.
    #[must_use]
    pub fn emit_recommendation_facts(self) -> bool {
        self.recommendations
    }

    /// Whether [`MixinRiskRule`] should surface per-handler intelligence findings.
    #[must_use]
    pub fn handler_intelligence_findings(self) -> bool {
        self.handler_effects && self.level == MixinLevel::Full
    }

    /// Whether per-injection effect summary findings should emit.
    #[must_use]
    pub fn effect_summary_findings(self) -> bool {
        self.level != MixinLevel::Normal
    }
}

/// Layer-M (resource / data semantics) controls. The level gates *how deep* the
/// typed-resource AST goes; the byte/fact caps bound work on untrusted jars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceSettings {
    pub level: ResourceAstLevel,
    /// Skip resources whose raw bytes exceed this (DoS guard on JSON parsing).
    pub max_json_bytes: u64,
    /// Cap on facts emitted per resource (references are truncated past this).
    pub max_ast_facts_per_resource: usize,
}

impl Default for ResourceSettings {
    fn default() -> Self {
        Self {
            level: ResourceAstLevel::default(),
            max_json_bytes: 1_048_576,
            max_ast_facts_per_resource: 256,
        }
    }
}

/// Depth of the Layer-M resource AST.
///
/// `Basic` leaves the byte/collision view of Layer E untouched (no AST).
/// `Semantic` parses tags / recipes / lang / `pack.mcmeta` / namespaces.
/// `Full` adds models / blockstates / loot tables / atlases / advancements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResourceAstLevel {
    Basic,
    #[default]
    Semantic,
    Full,
}

impl ResourceAstLevel {
    /// Parse `basic|semantic|full` (case-insensitive); `None` if unrecognized.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "basic" => Some(Self::Basic),
            "semantic" => Some(Self::Semantic),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Semantic => "semantic",
            Self::Full => "full",
        }
    }
}

/// Incremental scan controls for jar/log collectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanSettings {
    /// When set, jar collectors skip archives whose mtime is older than this instant.
    pub changed_since: Option<SystemTime>,
}

/// Fact store size controls applied after collection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FactStoreSettings {
    pub retention: FactRetentionPolicy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecuritySettings {
    /// Minimum note-level signals before a grouped security finding emits.
    pub min_note_signals: usize,
    /// Confidence for reflection-corroborated security facts.
    pub corroborated_confidence: f32,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            min_note_signals: 2,
            corroborated_confidence: 0.4,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SbomSettings {
    /// Trust score (0..=100) at or above which SBOM×security correlation skips.
    pub well_identified_trust: i64,
}

impl Default for SbomSettings {
    fn default() -> Self {
        Self {
            well_identified_trust: 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogSettings {
    /// Line count above which log scanning uses Rayon.
    pub parallel_line_threshold: usize,
}

impl Default for LogSettings {
    fn default() -> Self {
        Self {
            parallel_line_threshold: 4_096,
        }
    }
}

/// Process-wide default settings for tests and examples.
pub fn default_settings() -> &'static DiagnosisSettings {
    use std::sync::LazyLock;
    static DEFAULT: LazyLock<DiagnosisSettings> = LazyLock::new(DiagnosisSettings::default);
    &DEFAULT
}
