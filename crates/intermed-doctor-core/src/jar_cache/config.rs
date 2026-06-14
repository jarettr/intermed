//! Tunable jar-cache limits. Defaults match the historical hard-coded values;
//! callers (CLI, tests) override via [`JarCacheConfig`].

use std::time::Duration;

/// Default maximum age of a cache file before automatic pruning (≈6 months).
pub const DEFAULT_CACHE_MAX_AGE_DAYS: u64 = 180;

/// Default soft cap on total on-disk cache size; oldest entries are removed first.
pub const DEFAULT_CACHE_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Floor for a user-supplied cap (`--cache-max-size`): a single payload plus its
/// fingerprint must comfortably fit, or the cache thrashes itself empty.
pub const DEFAULT_CACHE_MIN_BYTES: u64 = 4 * 1024 * 1024;

/// Default interval between prune passes.
pub const DEFAULT_PRUNE_INTERVAL_DAYS: u64 = 1;

/// Default TTL for trusting a fingerprint's `mtime+size → sha256` mapping.
pub const DEFAULT_FINGERPRINT_REVERIFY_DAYS: u64 = 30;

/// Limits governing on-disk jar cache behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JarCacheConfig {
    /// Maximum age of a cache file before automatic pruning.
    pub max_age: Duration,
    /// Soft cap on total on-disk size; oldest entries are pruned first.
    pub max_bytes: u64,
    /// Minimum effective `max_bytes` after clamping user input.
    pub min_bytes: u64,
    /// Run pruning at most once per interval.
    pub prune_interval: Duration,
    /// How long a fingerprint mapping is trusted before re-hashing.
    pub fingerprint_reverify_ttl: Duration,
}

impl Default for JarCacheConfig {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(DEFAULT_CACHE_MAX_AGE_DAYS * 24 * 60 * 60),
            max_bytes: DEFAULT_CACHE_MAX_BYTES,
            min_bytes: DEFAULT_CACHE_MIN_BYTES,
            prune_interval: Duration::from_secs(DEFAULT_PRUNE_INTERVAL_DAYS * 24 * 60 * 60),
            fingerprint_reverify_ttl: Duration::from_secs(
                DEFAULT_FINGERPRINT_REVERIFY_DAYS * 24 * 60 * 60,
            ),
        }
    }
}

impl JarCacheConfig {
    /// Build config with an explicit soft size cap; `max_bytes` is clamped up to
    /// [`min_bytes`](Self::min_bytes).
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes.max(self.min_bytes);
        self
    }

    /// Override the maximum cache entry age.
    #[must_use]
    pub fn with_max_age_days(mut self, days: u64) -> Self {
        self.max_age = Duration::from_secs(days.saturating_mul(24 * 60 * 60));
        self
    }

    /// Override the prune pass interval.
    #[must_use]
    pub fn with_prune_interval_days(mut self, days: u64) -> Self {
        self.prune_interval = Duration::from_secs(days.saturating_mul(24 * 60 * 60));
        self
    }

    /// Override the fingerprint re-verify TTL.
    #[must_use]
    pub fn with_fingerprint_reverify_days(mut self, days: u64) -> Self {
        self.fingerprint_reverify_ttl = Duration::from_secs(days.saturating_mul(24 * 60 * 60));
        self
    }
}
