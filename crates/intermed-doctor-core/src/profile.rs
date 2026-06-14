//! Wall-clock profiling for one doctor run.
//!
//! Collectors and rules are timed individually (per `Collector::id` and
//! `Rule::id`); cache counters are copied from [`JarCache`](crate::jar_cache::JarCache)
//! when present. The profile is embedded in `--json` reports automatically when
//! the jar cache is enabled. This is intentionally lightweight (no `tracing`
//! subscriber) to keep cold start cheap.

use serde::{Deserialize, Serialize};

use crate::jar_cache::CacheStats;

/// Schema tag for `--profile` JSON output.
pub const PROFILE_SCHEMA: &str = "intermed-doctor-profile-v1";

/// One timed pipeline phase (collector or rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTiming {
    pub id: String,
    pub duration_ms: u64,
}

/// Complete timing snapshot for a diagnosis run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticProfile {
    pub schema: String,
    pub total_ms: u64,
    pub collectors: Vec<PhaseTiming>,
    pub rules: Vec<PhaseTiming>,
    pub cache: CacheStats,
    /// Number of verbose facts dropped by retention compaction *after* rules ran
    /// (0 when the store stayed under `max_facts`). Surfaced so users can see
    /// that the persisted fact snapshot is a subset of what rules evaluated.
    #[serde(default)]
    pub facts_dropped: usize,
}

impl DiagnosticProfile {
    pub fn new(
        total_ms: u64,
        collectors: Vec<PhaseTiming>,
        rules: Vec<PhaseTiming>,
        cache: CacheStats,
    ) -> Self {
        Self {
            schema: PROFILE_SCHEMA.to_string(),
            total_ms,
            collectors,
            rules,
            cache,
            facts_dropped: 0,
        }
    }

    /// Record how many facts retention compaction removed from the snapshot.
    pub fn with_facts_dropped(mut self, dropped: usize) -> Self {
        self.facts_dropped = dropped;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_schema_is_stable() {
        let p = DiagnosticProfile::new(10, vec![], vec![], CacheStats::default());
        assert_eq!(p.schema, PROFILE_SCHEMA);
    }
}
