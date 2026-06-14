//! Tunable thresholds for Layer-I performance correlation.

/// Default tick duration (ms) at or above which a spike is reported.
pub const DEFAULT_TICK_SPIKE_MS: i64 = 50;

/// Default CPU share (percent) at or above which a hot method/mod is severe.
pub const DEFAULT_HIGH_CPU_PERCENT: f64 = 50.0;

/// Default minimum CPU share (percent) for hot-method ↔ mixin correlation.
pub const DEFAULT_HOT_METHOD_FLOOR_PERCENT: f64 = 5.0;

/// Tick duration (ms) at or above which tick-spike severity bumps to Warn.
pub const DEFAULT_TICK_SPIKE_WARN_MS: i64 = 100;

/// Thresholds for the performance-correlation rule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PerformanceThresholds {
    /// Profiled tick duration (ms) at or above this counts as a spike.
    pub tick_spike_ms: i64,
    /// Tick duration (ms) at or above which severity bumps to Warn (no correlation).
    pub tick_spike_warn_ms: i64,
    /// CPU share (percent) at or above which a hot method is treated as severe.
    pub high_cpu_percent: f64,
    /// Minimum CPU share (percent) for a hot method to be worth correlating.
    pub hot_method_floor_percent: f64,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            tick_spike_ms: DEFAULT_TICK_SPIKE_MS,
            tick_spike_warn_ms: DEFAULT_TICK_SPIKE_WARN_MS,
            high_cpu_percent: DEFAULT_HIGH_CPU_PERCENT,
            hot_method_floor_percent: DEFAULT_HOT_METHOD_FLOOR_PERCENT,
        }
    }
}
