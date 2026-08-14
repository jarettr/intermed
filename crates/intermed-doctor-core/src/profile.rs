//! Wall-clock profiling for one doctor run.
//!
//! Collectors and rules are timed individually (per `Collector::id` and
//! `Rule::id`); cache counters are copied from [`JarCache`](crate::jar_cache::JarCache)
//! when present. The profile is embedded in `--json` reports automatically when
//! the jar cache is enabled. This is intentionally lightweight (no `tracing`
//! subscriber) to keep cold start cheap.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::jar_cache::CacheStats;

/// Schema tag for `--profile` JSON output.
pub const PROFILE_SCHEMA: &str = "intermed-doctor-profile-v1";

/// One timed pipeline phase (collector or rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTiming {
    pub id: String,
    pub duration_ms: u64,
    /// Facts visible when the phase started.
    #[serde(default)]
    pub input_facts: usize,
    /// Facts emitted by a collector, or findings emitted by a rule.
    #[serde(default)]
    pub output_records: usize,
    /// Store size after the phase (unchanged for rules).
    #[serde(default)]
    pub store_facts_after: usize,
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts_generated_by_kind: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts_retained_by_kind: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts_dropped_by_kind: BTreeMap<String, usize>,
    /// Process high-water resident set where the host exposes it (`VmHWM` on Linux).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_rss_bytes: Option<u64>,
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
            facts_generated_by_kind: BTreeMap::new(),
            facts_retained_by_kind: BTreeMap::new(),
            facts_dropped_by_kind: BTreeMap::new(),
            peak_rss_bytes: None,
        }
    }

    /// Record how many facts retention compaction removed from the snapshot.
    pub fn with_facts_dropped(mut self, dropped: usize) -> Self {
        self.facts_dropped = dropped;
        self
    }

    pub fn with_fact_inventory(
        mut self,
        generated: BTreeMap<String, usize>,
        retained: BTreeMap<String, usize>,
    ) -> Self {
        self.facts_dropped_by_kind = generated
            .iter()
            .filter_map(|(kind, count)| {
                let dropped = count.saturating_sub(*retained.get(kind).unwrap_or(&0));
                (dropped > 0).then(|| (kind.clone(), dropped))
            })
            .collect();
        self.facts_generated_by_kind = generated;
        self.facts_retained_by_kind = retained;
        self
    }

    pub fn with_peak_rss(mut self, bytes: Option<u64>) -> Self {
        self.peak_rss_bytes = bytes;
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
