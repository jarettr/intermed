//! The diagnosis engine: run collectors → fact store → run rules → assemble
//! report. The engine knows nothing concrete about Minecraft, logs, or
//! dependencies — it only orchestrates [`Collector`]s and [`Rule`]s that the
//! composition root (the CLI) registers. Adding a layer never touches this file.

use intermed_evidence::Finding;
use intermed_facts::{Fact, FactStore};

use crate::collector::{CollectCtx, Collector};
use crate::report::{self, DoctorReport, RuleStat};
use crate::rule::{Rule, RuleCtx};
use crate::target::Target;

/// Holds the registered collectors and rules for a diagnosis run.
pub struct DiagnosticEngine {
    tool_version: String,
    collectors: Vec<Box<dyn Collector>>,
    rules: Vec<Box<dyn Rule>>,
}

/// Complete result of one pipeline execution.
///
/// [`DoctorReport`] intentionally carries compact report data; Phase 2 CLI
/// affordances such as `--dump-facts` and `--explain` need the fact snapshot
/// alongside it without running collectors twice.
#[derive(Debug, Clone)]
pub struct DiagnosticRun {
    pub report: DoctorReport,
    pub facts: Vec<Fact>,
}

impl DiagnosticEngine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            collectors: Vec::new(),
            rules: Vec::new(),
        }
    }

    /// Run the full pipeline against a detected target.
    pub fn diagnose(&self, target: &Target) -> DoctorReport {
        self.diagnose_with_facts(target).report
    }

    /// Run the full pipeline and keep the fact snapshot for provenance output.
    pub fn diagnose_with_facts(&self, target: &Target) -> DiagnosticRun {
        let mut store = FactStore::new();
        let mut collector_outcomes = Vec::with_capacity(self.collectors.len());

        for c in &self.collectors {
            let outcome = if c.applies(target) {
                let mut ctx = CollectCtx {
                    target,
                    store: &mut store,
                };
                c.collect(&mut ctx)
            } else {
                c.not_applicable(target)
            };
            collector_outcomes.push((c.id(), c.layer(), outcome));
        }

        let rctx = RuleCtx::new(&store, target);
        let mut findings: Vec<Finding> = Vec::new();
        let mut rule_stats: Vec<RuleStat> = Vec::with_capacity(self.rules.len());
        for r in &self.rules {
            let produced = r.evaluate(&rctx);
            rule_stats.push(RuleStat {
                id: r.id().to_string(),
                findings: produced.len(),
            });
            findings.extend(produced);
        }

        let report = report::assemble(
            &self.tool_version,
            target,
            &store,
            findings,
            collector_outcomes,
            rule_stats,
        );
        DiagnosticRun {
            report,
            facts: store.all().to_vec(),
        }
    }
}

/// Fluent registration of collectors and rules.
pub struct EngineBuilder {
    tool_version: String,
    collectors: Vec<Box<dyn Collector>>,
    rules: Vec<Box<dyn Rule>>,
}

impl EngineBuilder {
    pub fn tool_version(mut self, v: impl Into<String>) -> Self {
        self.tool_version = v.into();
        self
    }

    pub fn collector(mut self, c: impl Collector + 'static) -> Self {
        self.collectors.push(Box::new(c));
        self
    }

    pub fn boxed_collector(mut self, c: Box<dyn Collector>) -> Self {
        self.collectors.push(c);
        self
    }

    pub fn rule(mut self, r: impl Rule + 'static) -> Self {
        self.rules.push(Box::new(r));
        self
    }

    pub fn build(self) -> DiagnosticEngine {
        DiagnosticEngine {
            tool_version: self.tool_version,
            collectors: self.collectors,
            rules: self.rules,
        }
    }
}
