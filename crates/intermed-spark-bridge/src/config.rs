//! Tunable thresholds for Layer-I performance correlation.

use std::fmt;

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

/// Invalid Layer-I threshold configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerformanceThresholdError {
    message: String,
}

impl fmt::Display for PerformanceThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PerformanceThresholdError {}

impl PerformanceThresholds {
    /// Validate the complete threshold set before a rule is registered.
    ///
    /// Keeping this validation here ensures CLI, config-file and programmatic
    /// callers all get identical semantics.
    pub fn validate(self) -> Result<(), PerformanceThresholdError> {
        let mut errors = Vec::new();
        if self.tick_spike_ms <= 0 {
            errors.push("tick_spike_ms must be greater than zero".to_string());
        }
        if self.tick_spike_warn_ms < self.tick_spike_ms {
            errors.push(format!(
                "tick_spike_warn_ms ({}) must be greater than or equal to tick_spike_ms ({})",
                self.tick_spike_warn_ms, self.tick_spike_ms
            ));
        }
        for (name, value) in [
            ("high_cpu_percent", self.high_cpu_percent),
            ("hot_method_floor_percent", self.hot_method_floor_percent),
        ] {
            if !value.is_finite() || !(0.0..=100.0).contains(&value) {
                errors.push(format!("{name} must be a finite percentage in 0..=100"));
            }
        }
        if self.hot_method_floor_percent > self.high_cpu_percent {
            errors.push(format!(
                "hot_method_floor_percent ({}) must not exceed high_cpu_percent ({})",
                self.hot_method_floor_percent, self.high_cpu_percent
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(PerformanceThresholdError {
                message: errors.join("; "),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_out_of_range_and_reversed_thresholds() {
        assert!(
            PerformanceThresholds {
                tick_spike_ms: 100,
                tick_spike_warn_ms: 50,
                high_cpu_percent: 101.0,
                hot_method_floor_percent: -1.0,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn accepts_default_thresholds() {
        PerformanceThresholds::default().validate().unwrap();
    }
}
