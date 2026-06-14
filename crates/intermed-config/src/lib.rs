//! # intermed-config
//!
//! Unified configuration for the `intermed` workbench. Load order (lowest →
//! highest precedence):
//!
//! 1. Built-in defaults (documented constants in this crate)
//! 2. Home config (`$XDG_CONFIG_HOME/intermed/config.toml` or `~/.config/...`)
//! 3. Project config (first existing of [`DISCOVERY_PATHS`] in the cwd)
//! 4. `INTERMED_*` environment variables
//! 5. CLI flags (applied in `intermed-cli` after [`IntermedConfig::load`])
//!
//! Files are **deep-merged** key-by-key, not replaced: a project file that only
//! sets `[rules]` keeps the `[cache]` values from the home file, which in turn
//! keep any keys neither file mentions at their built-in defaults. A more
//! specific layer overrides the same key in a less specific one.
//!
//! `--config <path>` (or `INTERMED_CONFIG`) is an **authoritative single
//! source**: discovery is skipped so the result is reproducible regardless of
//! which home/project files happen to exist; the named file is still merged over
//! built-in defaults so partial files are allowed.
//!
//! See `docs/CONFIG.md` for the full key reference.

mod sections;

pub use sections::{
    CacheSection, LabSection, LogSection, MetadataSection, MixinSection, PerformanceSection,
    ResourceSection, RulesSection, RuntimeSection, SbomSection, SecuritySection,
};

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use intermed_doctor_core::{
    settings::{
        DiagnosisSettings, FactStoreSettings, LogSettings, MetadataLevel, MetadataSettings,
        MixinLevel, MixinSettings, ResourceAstLevel, ResourceSettings, ScanSettings, SbomSettings,
        SecuritySettings,
    },
    JarCacheConfig, DEFAULT_CACHE_MAX_AGE_DAYS, DEFAULT_CACHE_MAX_BYTES,
    DEFAULT_FINGERPRINT_REVERIFY_DAYS, DEFAULT_PRUNE_INTERVAL_DAYS,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level configuration file shape (`intermed-config-v1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntermedConfig {
    pub schema: String,
    #[serde(default)]
    pub cache: CacheSection,
    #[serde(default)]
    pub performance: PerformanceSection,
    #[serde(default)]
    pub security: SecuritySection,
    #[serde(default)]
    pub sbom: SbomSection,
    #[serde(default)]
    pub log: LogSection,
    #[serde(default)]
    pub lab: LabSection,
    #[serde(default)]
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub rules: RulesSection,
    #[serde(default)]
    pub metadata: MetadataSection,
    #[serde(default)]
    pub mixin: MixinSection,
    #[serde(default)]
    pub resource: ResourceSection,
}

impl Default for IntermedConfig {
    fn default() -> Self {
        Self {
            schema: CONFIG_SCHEMA.to_string(),
            cache: CacheSection::default(),
            performance: PerformanceSection::default(),
            security: SecuritySection::default(),
            sbom: SbomSection::default(),
            log: LogSection::default(),
            lab: LabSection::default(),
            runtime: RuntimeSection::default(),
            rules: RulesSection::default(),
            metadata: MetadataSection::default(),
            mixin: MixinSection::default(),
            resource: ResourceSection::default(),
        }
    }
}

/// Schema tag embedded in config files.
pub const CONFIG_SCHEMA: &str = "intermed-config-v1";

/// Standard config discovery paths (first existing file wins).
pub const DISCOVERY_PATHS: &[&str] = &[
    ".intermed.toml",
    "intermed.toml",
    ".config/intermed/config.toml",
];

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("unsupported config schema `{found}` in {path} (expected {CONFIG_SCHEMA})")]
    UnsupportedSchema { path: PathBuf, found: String },
}

impl IntermedConfig {
    /// Built-in defaults only (no file, no env).
    #[must_use]
    pub fn defaults() -> Self {
        Self::default()
    }

    /// Load defaults, then config files (deep-merged), then `INTERMED_*` env.
    ///
    /// When `explicit_path` (or `INTERMED_CONFIG`) is set, only that file is
    /// merged over defaults — discovery is skipped for reproducibility. See the
    /// module docs for the full precedence order.
    pub fn load(explicit_path: Option<&Path>) -> Result<Self, ConfigError> {
        // Accumulate raw TOML layers low→high, then deserialize once so that
        // serde `default`s fill any key no layer set. Deep-merging the raw
        // tables (rather than overwriting whole structs) is what makes partial
        // files compose instead of resetting unmentioned sections.
        let mut merged: Option<toml::Value> = None;
        let push = |path: &Path, merged: &mut Option<toml::Value>| -> Result<(), ConfigError> {
            let layer = read_layer(path)?;
            match merged {
                Some(base) => deep_merge(base, layer),
                None => *merged = Some(layer),
            }
            Ok(())
        };

        if let Some(path) = explicit_path {
            push(path, &mut merged)?;
        } else if let Some(path) = env::var_os("INTERMED_CONFIG").map(PathBuf::from) {
            push(&path, &mut merged)?;
        } else {
            // Home (global, lower precedence) before project (local, higher).
            if let Some(home) = home_config_path() {
                if home.is_file() {
                    push(&home, &mut merged)?;
                }
            }
            for rel in DISCOVERY_PATHS {
                let path = PathBuf::from(rel);
                if path.is_file() {
                    push(&path, &mut merged)?;
                    break;
                }
            }
        }

        let mut cfg = match merged {
            Some(value) => from_merged_value(value)?,
            None => Self::defaults(),
        };
        apply_env(&mut cfg);
        Ok(cfg)
    }

    /// Convert to [`JarCacheConfig`] for [`JarCache`](intermed_doctor_core::JarCache).
    #[must_use]
    pub fn jar_cache_config(&self) -> JarCacheConfig {
        JarCacheConfig::default()
            .with_max_bytes(self.cache.max_size_mib.saturating_mul(1024 * 1024))
            .with_max_age_days(self.cache.max_age_days)
            .with_prune_interval_days(self.cache.prune_interval_days)
            .with_fingerprint_reverify_days(self.cache.fingerprint_reverify_days)
    }

    /// Settings passed through [`RuleCtx`](intermed_doctor_core::RuleCtx) and collectors.
    #[must_use]
    pub fn diagnosis_settings(&self) -> DiagnosisSettings {
        DiagnosisSettings {
            metadata: MetadataSettings {
                level: parse_metadata_level(&self.metadata.level),
            },
            security: SecuritySettings {
                min_note_signals: self.security.min_note_signals,
                corroborated_confidence: self.security.corroborated_confidence,
            },
            sbom: SbomSettings {
                well_identified_trust: self.sbom.well_identified_trust,
            },
            log: LogSettings {
                parallel_line_threshold: self.log.parallel_line_threshold,
            },
            scan: ScanSettings::default(),
            facts: FactStoreSettings::default(),
            mixin: self.mixin_settings(),
            resource: self.resource_settings(),
            minecraft_jar: None,
            minecraft_mappings: None,
        }
    }

    /// Layer-M resource-AST settings for the collector.
    #[must_use]
    pub fn resource_settings(&self) -> ResourceSettings {
        ResourceSettings {
            level: parse_resource_level(&self.resource.level),
            max_json_bytes: self.resource.max_json_bytes,
            max_ast_facts_per_resource: self.resource.max_ast_facts_per_resource,
        }
    }

    /// Layer-F mixin analysis toggles for collectors and rules.
    #[must_use]
    pub fn mixin_settings(&self) -> MixinSettings {
        let level = parse_mixin_level(&self.mixin.level);
        let mut settings = MixinSettings::from_level(level);
        if let Some(v) = self.mixin.handler_effects {
            settings.handler_effects = v;
        }
        if let Some(v) = self.mixin.recommendations {
            settings.recommendations = v;
        }
        settings
    }

    /// Serialize as TOML (for `--dump-config`).
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Parse {
            path: PathBuf::from("<serialize>"),
            message: e.to_string(),
        })
    }
}

fn home_config_path() -> Option<PathBuf> {
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("intermed").join("config.toml"));
        }
    }
    env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("intermed")
            .join("config.toml")
    })
}

/// Read one config file into a schema-validated raw TOML value.
///
/// Validation happens on the *raw* table (before merge/deserialize) so that a
/// file with the wrong `schema` is rejected with its own path, and so a partial
/// file's omitted sections do not get silently defaulted away here — they stay
/// absent and are resolved later by the merge + serde defaults.
fn read_layer(path: &Path) -> Result<toml::Value, ConfigError> {
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let value: toml::Value = toml::from_str(&text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let schema = value.get("schema").and_then(toml::Value::as_str).unwrap_or("");
    if schema != CONFIG_SCHEMA {
        return Err(ConfigError::UnsupportedSchema {
            path: path.to_path_buf(),
            found: schema.to_string(),
        });
    }
    Ok(value)
}

/// Recursively merge `overlay` into `base`. Tables merge key-by-key; any
/// non-table value (scalar, array) from `overlay` replaces the one in `base`.
/// Later (higher-precedence) layers are passed as `overlay`.
fn deep_merge(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base_t), toml::Value::Table(over_t)) => {
            for (k, v) in over_t {
                match base_t.get_mut(&k) {
                    Some(existing) => deep_merge(existing, v),
                    None => {
                        base_t.insert(k, v);
                    }
                }
            }
        }
        (slot, overlay) => *slot = overlay,
    }
}

/// Deserialize the merged table over built-in defaults (serde `default`s fill
/// any key no layer set).
fn from_merged_value(value: toml::Value) -> Result<IntermedConfig, ConfigError> {
    value.try_into().map_err(|e: toml::de::Error| ConfigError::Parse {
        path: PathBuf::from("<merged-config>"),
        message: e.to_string(),
    })
}

fn parse_mixin_level(raw: &str) -> MixinLevel {
    match raw.trim().to_ascii_lowercase().as_str() {
        "normal" => MixinLevel::Normal,
        "full" => MixinLevel::Full,
        _ => MixinLevel::Detailed,
    }
}

fn parse_metadata_level(raw: &str) -> MetadataLevel {
    match raw.trim().to_ascii_lowercase().as_str() {
        "basic" => MetadataLevel::Basic,
        "full" => MetadataLevel::Full,
        _ => MetadataLevel::Enriched,
    }
}

fn parse_resource_level(raw: &str) -> ResourceAstLevel {
    ResourceAstLevel::parse(raw).unwrap_or_default()
}

fn apply_env(cfg: &mut IntermedConfig) {
    env_u64("INTERMED_CACHE_MAX_MIB", &mut cfg.cache.max_size_mib);
    env_u64("INTERMED_CACHE_MAX_AGE_DAYS", &mut cfg.cache.max_age_days);
    env_u64(
        "INTERMED_CACHE_PRUNE_INTERVAL_DAYS",
        &mut cfg.cache.prune_interval_days,
    );
    env_u64(
        "INTERMED_CACHE_FINGERPRINT_REVERIFY_DAYS",
        &mut cfg.cache.fingerprint_reverify_days,
    );
    env_i64(
        "INTERMED_PERF_TICK_SPIKE_MS",
        &mut cfg.performance.tick_spike_ms,
    );
    env_i64(
        "INTERMED_PERF_TICK_SPIKE_WARN_MS",
        &mut cfg.performance.tick_spike_warn_ms,
    );
    env_f64(
        "INTERMED_PERF_HIGH_CPU_PERCENT",
        &mut cfg.performance.high_cpu_percent,
    );
    env_f64(
        "INTERMED_PERF_HOT_METHOD_FLOOR",
        &mut cfg.performance.hot_method_floor_percent,
    );
    env_usize(
        "INTERMED_SECURITY_MIN_NOTE_SIGNALS",
        &mut cfg.security.min_note_signals,
    );
    env_f32(
        "INTERMED_SECURITY_CORROBORATED_CONFIDENCE",
        &mut cfg.security.corroborated_confidence,
    );
    env_i64(
        "INTERMED_SBOM_WELL_IDENTIFIED_TRUST",
        &mut cfg.sbom.well_identified_trust,
    );
    env_usize(
        "INTERMED_LOG_PARALLEL_LINE_THRESHOLD",
        &mut cfg.log.parallel_line_threshold,
    );
    env_usize("INTERMED_LAB_EXCERPT_MAX", &mut cfg.lab.excerpt_max);
    env_usize("INTERMED_JOBS", &mut cfg.runtime.jobs);
    if let Ok(v) = env::var("INTERMED_METADATA_LEVEL") {
        if !v.trim().is_empty() {
            cfg.metadata.level = v;
        }
    }
    if let Ok(v) = env::var("INTERMED_MIXIN_LEVEL") {
        if !v.trim().is_empty() {
            cfg.mixin.level = v;
        }
    }
    env_bool_opt("INTERMED_MIXIN_HANDLER_EFFECTS", &mut cfg.mixin.handler_effects);
    env_bool_opt("INTERMED_MIXIN_RECOMMENDATIONS", &mut cfg.mixin.recommendations);
    if let Ok(v) = env::var("INTERMED_RESOURCE_LEVEL") {
        if !v.trim().is_empty() {
            cfg.resource.level = v;
        }
    }
}

fn env_bool_opt(key: &str, target: &mut Option<bool>) {
    if let Ok(v) = env::var(key) {
        match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => *target = Some(true),
            "0" | "false" | "no" | "off" => *target = Some(false),
            _ => {}
        }
    }
}

fn env_u64(key: &str, target: &mut u64) {
    if let Ok(v) = env::var(key) {
        if let Ok(n) = v.parse() {
            *target = n;
        }
    }
}

fn env_i64(key: &str, target: &mut i64) {
    if let Ok(v) = env::var(key) {
        if let Ok(n) = v.parse() {
            *target = n;
        }
    }
}

fn env_usize(key: &str, target: &mut usize) {
    if let Ok(v) = env::var(key) {
        if let Ok(n) = v.parse() {
            *target = n;
        }
    }
}

fn env_f64(key: &str, target: &mut f64) {
    if let Ok(v) = env::var(key) {
        if let Ok(n) = v.parse() {
            *target = n;
        }
    }
}

fn env_f32(key: &str, target: &mut f32) {
    if let Ok(v) = env::var(key) {
        if let Ok(n) = v.parse() {
            *target = n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_schema_is_valid() {
        let cfg = IntermedConfig::defaults();
        assert_eq!(cfg.schema, CONFIG_SCHEMA);
        assert_eq!(
            cfg.cache.max_size_mib,
            DEFAULT_CACHE_MAX_BYTES / (1024 * 1024)
        );
        assert_eq!(cfg.cache.max_age_days, DEFAULT_CACHE_MAX_AGE_DAYS);
    }

    #[test]
    fn round_trips_through_toml() {
        let cfg = IntermedConfig::defaults();
        let text = cfg.to_toml().unwrap();
        let parsed: IntermedConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn deep_merge_preserves_unmentioned_sections() {
        // Home sets cache.max_size_mib; project sets only rules.packs.
        let mut base = toml::from_str::<toml::Value>(
            "schema = \"intermed-config-v1\"\n[cache]\nmax_size_mib = 4096\n",
        )
        .unwrap();
        let project = toml::from_str::<toml::Value>(
            "schema = \"intermed-config-v1\"\n[rules]\npacks = [\"my-pack\"]\n",
        )
        .unwrap();
        deep_merge(&mut base, project);

        let cfg = from_merged_value(base).unwrap();
        // Project file must NOT have reset cache back to default.
        assert_eq!(cfg.cache.max_size_mib, 4096);
        assert_eq!(cfg.rules.packs, vec!["my-pack".to_string()]);
    }

    #[test]
    fn deep_merge_higher_layer_overrides_same_key() {
        let mut home =
            toml::from_str::<toml::Value>("schema = \"intermed-config-v1\"\n[cache]\nmax_size_mib = 1024\n")
                .unwrap();
        let project =
            toml::from_str::<toml::Value>("schema = \"intermed-config-v1\"\n[cache]\nmax_size_mib = 8192\n")
                .unwrap();
        deep_merge(&mut home, project);
        let cfg = from_merged_value(home).unwrap();
        // Project (higher precedence) wins for the shared key.
        assert_eq!(cfg.cache.max_size_mib, 8192);
    }

    #[test]
    fn wrong_schema_is_rejected_per_layer() {
        let dir = std::env::temp_dir().join(format!(
            "intermed-cfg-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        fs::write(&path, "schema = \"nope\"\n").unwrap();
        let err = read_layer(&path).unwrap_err();
        assert!(matches!(err, ConfigError::UnsupportedSchema { .. }));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn env_overrides_win_over_defaults() {
        let key = "INTERMED_PERF_TICK_SPIKE_MS";
        // SAFETY: test runs single-threaded; env is restored on drop.
        unsafe { env::set_var(key, "77") };
        let cfg = IntermedConfig::load(None).unwrap();
        unsafe { env::remove_var(key) };
        assert_eq!(cfg.performance.tick_spike_ms, 77);
    }
}
