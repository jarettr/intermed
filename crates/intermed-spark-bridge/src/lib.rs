//! # intermed-spark-bridge — Layer I (Phase 7)
//!
//! Performance evidence as just another fact source. Not on the critical path:
//! imports an existing spark report (or optional JFR) rather than forking spark.
//!
//! **Will emit facts:** `tick_spike(ms)`, `hot_method(class, method, percent)`,
//! `hot_mod(mod, percent)`, `gc_pause(ms)`, `heap_pressure(bytes)`,
//! `thread_hotspot(thread, percent)`.
//!
//! **Datalog correlations later:** `tick_spike + worldgen_mod + high_view_distance
//! => probable_worldgen_pressure`, etc.
//!
//! **Donors:** `PrometheusExporter`, `OtelJsonExporter`, `TraceRecorder`,
//! `ObservabilityEvidenceReport`, `PerformanceMonitor`, `MetricsRegistry`.

use intermed_doctor_core::{Collector, DeferredCollector, Layer};

/// The (currently deferred) Layer-I collector.
pub fn collector() -> impl Collector {
    DeferredCollector::new("spark-importer", Layer::Performance)
}
