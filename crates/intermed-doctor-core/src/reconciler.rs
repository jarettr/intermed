//! First-class cross-layer inference stage.

use intermed_evidence::{EvidenceGraph, Finding};
use intermed_facts::FactStore;
use thiserror::Error;

/// Observable result of one reconciliation pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconciliationOutcome {
    pub findings_adjusted: usize,
    pub graph_links: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct ReconciliationError {
    pub message: String,
}

impl ReconciliationError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Cross-layer inference that can constrain a locally derived finding.
pub trait Reconciler: Send + Sync {
    fn id(&self) -> &'static str;

    fn reconcile(
        &self,
        store: &FactStore,
        graph: &mut EvidenceGraph,
        findings: &mut [Finding],
    ) -> Result<ReconciliationOutcome, ReconciliationError>;
}

/// Canonical built-in runtime/static contradiction and evidence-path pass.
pub struct CrossLayerReconciler;

impl Reconciler for CrossLayerReconciler {
    fn id(&self) -> &'static str {
        "cross-layer-coherence"
    }

    fn reconcile(
        &self,
        store: &FactStore,
        graph: &mut EvidenceGraph,
        findings: &mut [Finding],
    ) -> Result<ReconciliationOutcome, ReconciliationError> {
        let before = findings
            .iter()
            .map(|finding| finding.assessment.adjustments.len())
            .sum::<usize>();
        crate::coherence::reconcile_findings(store, graph, findings);
        let after = findings
            .iter()
            .map(|finding| finding.assessment.adjustments.len())
            .sum::<usize>();
        Ok(ReconciliationOutcome {
            findings_adjusted: after.saturating_sub(before),
            graph_links: graph.links.len(),
        })
    }
}
