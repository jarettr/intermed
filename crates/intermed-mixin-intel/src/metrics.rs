//! Dataflow-precision metrics (plan §0).
//!
//! Aggregates, across every handler in a scan, how precisely the abstract
//! interpreter resolved its dataflow and — where it didn't — why. This is pure
//! measurement: it drives the `mixin_dataflow_metrics` fact and the
//! `--debug-mixin-dataflow` view, never a finding. It is the baseline that makes
//! precision regressions visible.

use std::collections::BTreeMap;

use crate::model::{HandlerDataflow, MixinScan};

/// Aggregate precision picture for one scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataflowMetrics {
    /// Handlers with a parsed dataflow summary.
    pub analyzed: usize,
    /// Handlers that resolved without degrading.
    pub precise: usize,
    /// Handlers that degraded at some point.
    pub imprecise: usize,
    /// Mean value-confidence across analyzed handlers (0–100).
    pub mean_confidence: u8,
    /// Count of handlers reaching each precision level.
    pub by_precision: BTreeMap<&'static str, usize>,
    /// Count of each imprecision reason across all handlers.
    pub by_reason: BTreeMap<&'static str, usize>,
}

impl DataflowMetrics {
    /// Compute metrics over every handler body's dataflow in the scan.
    #[must_use]
    pub fn from_scan(scan: &MixinScan) -> Self {
        Self::from_dataflows(
            scan.classes
                .iter()
                .flat_map(|c| c.handler_bodies.iter())
                .filter_map(|b| b.dataflow.as_ref()),
        )
    }

    /// Aggregate over a sequence of resolved handler dataflows.
    pub fn from_dataflows<'a>(dataflows: impl Iterator<Item = &'a HandlerDataflow>) -> Self {
        let mut m = DataflowMetrics::default();
        let mut confidence_sum: u64 = 0;
        for df in dataflows {
            m.analyzed += 1;
            confidence_sum += u64::from(df.confidence);
            *m.by_precision.entry(df.precision.as_str()).or_insert(0) += 1;
            if df.imprecise {
                m.imprecise += 1;
                for r in &df.imprecise_reasons {
                    *m.by_reason.entry(r.as_str()).or_insert(0) += 1;
                }
            } else {
                m.precise += 1;
            }
        }
        m.mean_confidence = if m.analyzed == 0 {
            0
        } else {
            (confidence_sum / m.analyzed as u64) as u8
        };
        m
    }

    /// Fraction (0–100) of analyzed handlers resolved precisely.
    #[must_use]
    pub fn precise_percent(&self) -> u8 {
        (self.precise * 100)
            .checked_div(self.analyzed)
            .map_or(100, |p| p as u8)
    }

    /// Reason counts as a stable, comma-separated `reason=count` string.
    #[must_use]
    pub fn reasons_csv(&self) -> String {
        self.by_reason
            .iter()
            .map(|(r, c)| format!("{r}={c}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ImpreciseReason, PrecisionLevel};

    #[test]
    fn aggregates_precision_and_reasons() {
        let precise = HandlerDataflow {
            precision: PrecisionLevel::ValueSource,
            confidence: 90,
            ..Default::default()
        };
        let mut imprecise = HandlerDataflow {
            precision: PrecisionLevel::Provenance,
            confidence: 54,
            ..Default::default()
        };
        imprecise.degrade(ImpreciseReason::LoopBackEdge);

        let dfs = [precise, imprecise];
        let m = DataflowMetrics::from_dataflows(dfs.iter());
        assert_eq!(m.analyzed, 2);
        assert_eq!(m.precise, 1);
        assert_eq!(m.imprecise, 1);
        assert_eq!(m.precise_percent(), 50);
        assert_eq!(m.by_reason.get("loop-back-edge"), Some(&1));
        assert_eq!(m.by_precision.get("value-source"), Some(&1));
        assert_eq!(m.mean_confidence, 72); // (90+54)/2
    }

    #[test]
    fn empty_scan_is_fully_precise() {
        let m = DataflowMetrics::from_dataflows(std::iter::empty());
        assert_eq!(m.analyzed, 0);
        assert_eq!(m.precise_percent(), 100);
        assert!(m.reasons_csv().is_empty());
    }
}
