//! Config file sections and their documented defaults.

use serde::{Deserialize, Serialize};

/// Default tick duration (ms) at or above which a spike is reported.
pub const DEFAULT_TICK_SPIKE_MS: i64 = 50;

/// Tick duration (ms) at or above which severity bumps to Warn (when no mixin correlation).
pub const DEFAULT_TICK_SPIKE_WARN_MS: i64 = 100;

/// Default CPU share (percent) for severe hot methods/mods.
pub const DEFAULT_HIGH_CPU_PERCENT: f64 = 50.0;

/// Default minimum CPU share (percent) for hot-method ↔ mixin correlation.
pub const DEFAULT_HOT_METHOD_FLOOR_PERCENT: f64 = 5.0;

/// Minimum note-level security signals before emitting a grouped finding.
pub const DEFAULT_SECURITY_MIN_NOTE_SIGNALS: usize = 2;

/// Confidence attached to reflection-corroborated security facts.
pub const DEFAULT_SECURITY_CORROBORATED_CONFIDENCE: f32 = 0.4;

/// SBOM trust score (0..=100) at or above which a jar is well-identified.
pub const DEFAULT_SBOM_WELL_IDENTIFIED_TRUST: i64 = 60;

/// Line count above which log scanning fans out in parallel.
pub const DEFAULT_LOG_PARALLEL_LINE_THRESHOLD: usize = 4_096;

/// Maximum characters kept from a smoke-test log excerpt in lab runs.
pub const DEFAULT_LAB_EXCERPT_MAX: usize = 280;

/// Default mixin analysis preset (`detailed` — overlaps + recommendations, no per-handler spam).
pub const DEFAULT_MIXIN_LEVEL: &str = "detailed";
pub const DEFAULT_METADATA_LEVEL: &str = "enriched";
pub const DEFAULT_RESOURCE_LEVEL: &str = "semantic";
pub const DEFAULT_RESOURCE_MAX_JSON_BYTES: u64 = 1_048_576;
pub const DEFAULT_RESOURCE_MAX_AST_FACTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheSection {
    /// Soft cap on jar cache size in MiB (default: 512).
    #[serde(default = "default_cache_max_mib")]
    pub max_size_mib: u64,
    /// Maximum cache entry age in days (default: 180).
    #[serde(default = "default_cache_max_age_days")]
    pub max_age_days: u64,
    /// Prune pass interval in days (default: 1).
    #[serde(default = "default_prune_interval_days")]
    pub prune_interval_days: u64,
    /// Fingerprint re-verify TTL in days (default: 30).
    #[serde(default = "default_fingerprint_reverify_days")]
    pub fingerprint_reverify_days: u64,
}

impl Default for CacheSection {
    fn default() -> Self {
        Self {
            max_size_mib: default_cache_max_mib(),
            max_age_days: default_cache_max_age_days(),
            prune_interval_days: default_prune_interval_days(),
            fingerprint_reverify_days: default_fingerprint_reverify_days(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceSection {
    /// Enable Layer-I Spark import during `doctor` (default: false).
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tick_spike_ms")]
    pub tick_spike_ms: i64,
    #[serde(default = "default_tick_spike_warn_ms")]
    pub tick_spike_warn_ms: i64,
    #[serde(default = "default_high_cpu_percent")]
    pub high_cpu_percent: f64,
    #[serde(default = "default_hot_method_floor")]
    pub hot_method_floor_percent: f64,
}

impl Default for PerformanceSection {
    fn default() -> Self {
        Self {
            enabled: false,
            tick_spike_ms: DEFAULT_TICK_SPIKE_MS,
            tick_spike_warn_ms: DEFAULT_TICK_SPIKE_WARN_MS,
            high_cpu_percent: DEFAULT_HIGH_CPU_PERCENT,
            hot_method_floor_percent: DEFAULT_HOT_METHOD_FLOOR_PERCENT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecuritySection {
    #[serde(default = "default_min_note_signals")]
    pub min_note_signals: usize,
    #[serde(default = "default_corroborated_confidence")]
    pub corroborated_confidence: f32,
}

impl Default for SecuritySection {
    fn default() -> Self {
        Self {
            min_note_signals: DEFAULT_SECURITY_MIN_NOTE_SIGNALS,
            corroborated_confidence: DEFAULT_SECURITY_CORROBORATED_CONFIDENCE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SbomSection {
    #[serde(default = "default_well_identified_trust")]
    pub well_identified_trust: i64,
}

impl Default for SbomSection {
    fn default() -> Self {
        Self {
            well_identified_trust: DEFAULT_SBOM_WELL_IDENTIFIED_TRUST,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogSection {
    #[serde(default = "default_parallel_line_threshold")]
    pub parallel_line_threshold: usize,
}

impl Default for LogSection {
    fn default() -> Self {
        Self {
            parallel_line_threshold: DEFAULT_LOG_PARALLEL_LINE_THRESHOLD,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LabSection {
    #[serde(default = "default_excerpt_max")]
    pub excerpt_max: usize,
}

impl Default for LabSection {
    fn default() -> Self {
        Self {
            excerpt_max: DEFAULT_LAB_EXCERPT_MAX,
        }
    }
}

/// Layer-F mixin scan depth and finding noise controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinSection {
    /// Preset: `normal` | `detailed` | `full` (default: `detailed`).
    #[serde(default = "default_mixin_level")]
    pub level: String,
    /// Emit per-handler bytecode intelligence facts (default: derived from `level`).
    #[serde(default)]
    pub handler_effects: Option<bool>,
    /// Emit safer-mixin recommendation facts (default: derived from `level`).
    #[serde(default)]
    pub recommendations: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataSection {
    /// Preset: `basic` | `enriched` | `full` (default: `enriched`).
    #[serde(default = "default_metadata_level")]
    pub level: String,
}

/// Layer-M resource / data-semantics (typed AST) controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSection {
    /// Depth: `basic` (AST off) | `semantic` | `full` (default: `semantic`).
    #[serde(default = "default_resource_level")]
    pub level: String,
    /// Per-resource JSON size cap in bytes; larger resources are skipped.
    #[serde(default = "default_resource_max_json_bytes")]
    pub max_json_bytes: u64,
    /// Cap on facts emitted per resource (reference fan-out is truncated past this).
    #[serde(default = "default_resource_max_ast_facts")]
    pub max_ast_facts_per_resource: usize,
}

impl Default for ResourceSection {
    fn default() -> Self {
        Self {
            level: default_resource_level(),
            max_json_bytes: DEFAULT_RESOURCE_MAX_JSON_BYTES,
            max_ast_facts_per_resource: DEFAULT_RESOURCE_MAX_AST_FACTS,
        }
    }
}

impl Default for MetadataSection {
    fn default() -> Self {
        Self {
            level: default_metadata_level(),
        }
    }
}

impl Default for MixinSection {
    fn default() -> Self {
        Self {
            level: default_mixin_level(),
            handler_effects: None,
            recommendations: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct RuntimeSection {
    /// Worker thread cap for parallel scanning (`0` = all cores).
    #[serde(default)]
    pub jobs: usize,
}

/// Layer-J declarative rule pack install and overlay settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RulesSection {
    /// Extra pack paths or installed pack ids merged on top of the embedded core.
    #[serde(default)]
    pub packs: Vec<String>,
    /// Override rule-pack install directory (default: XDG data path).
    #[serde(default)]
    pub install_dir: Option<String>,
    /// Registry index path or `https://` URL for resolving pack ids.
    #[serde(default)]
    pub registry: Option<String>,
    /// Trusted publisher public keys file for signed overlays.
    #[serde(default)]
    pub trusted_keys: Option<String>,
    /// When true, doctor uses only the embedded core pack.
    #[serde(default)]
    pub core_only: bool,
}

fn default_cache_max_mib() -> u64 {
    super::DEFAULT_CACHE_MAX_BYTES / (1024 * 1024)
}
fn default_cache_max_age_days() -> u64 {
    super::DEFAULT_CACHE_MAX_AGE_DAYS
}
fn default_prune_interval_days() -> u64 {
    super::DEFAULT_PRUNE_INTERVAL_DAYS
}
fn default_fingerprint_reverify_days() -> u64 {
    super::DEFAULT_FINGERPRINT_REVERIFY_DAYS
}
fn default_tick_spike_ms() -> i64 {
    DEFAULT_TICK_SPIKE_MS
}
fn default_tick_spike_warn_ms() -> i64 {
    DEFAULT_TICK_SPIKE_WARN_MS
}
fn default_high_cpu_percent() -> f64 {
    DEFAULT_HIGH_CPU_PERCENT
}
fn default_hot_method_floor() -> f64 {
    DEFAULT_HOT_METHOD_FLOOR_PERCENT
}
fn default_min_note_signals() -> usize {
    DEFAULT_SECURITY_MIN_NOTE_SIGNALS
}
fn default_corroborated_confidence() -> f32 {
    DEFAULT_SECURITY_CORROBORATED_CONFIDENCE
}
fn default_well_identified_trust() -> i64 {
    DEFAULT_SBOM_WELL_IDENTIFIED_TRUST
}
fn default_parallel_line_threshold() -> usize {
    DEFAULT_LOG_PARALLEL_LINE_THRESHOLD
}
fn default_excerpt_max() -> usize {
    DEFAULT_LAB_EXCERPT_MAX
}
fn default_mixin_level() -> String {
    DEFAULT_MIXIN_LEVEL.to_string()
}
fn default_metadata_level() -> String {
    DEFAULT_METADATA_LEVEL.to_string()
}
fn default_resource_level() -> String {
    DEFAULT_RESOURCE_LEVEL.to_string()
}
fn default_resource_max_json_bytes() -> u64 {
    DEFAULT_RESOURCE_MAX_JSON_BYTES
}
fn default_resource_max_ast_facts() -> usize {
    DEFAULT_RESOURCE_MAX_AST_FACTS
}
