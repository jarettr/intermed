//! Coverage-aware runtime observations shared by captured and live Lab runs.
//!
//! Layer K deliberately reuses Layer D's event normalizer.  A campaign must not
//! grow a second definition of exception chains, terminality, or occurrence
//! identity merely because its input came from a launched process.

use serde::{Deserialize, Serialize};

use intermed_log::runtime::{EventTerminality, RuntimeEvent};

use crate::classify::FailureCategory;
use crate::run::RawSmokeOutput;

pub const OBSERVATION_SCHEMA: &str = "intermed-execution-observation-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMilestone {
    LoaderResolution,
    CommonSetup,
    ClientInit,
    ServerStarted,
    WorldLoaded,
    PlayerJoined,
    ResourceReload,
    DatapackLoad,
    SteadyStateTicks,
    GracefulShutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExecutionCoverage {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reached: Vec<RuntimeMilestone>,
    pub log_complete: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<String>,
}

impl ExecutionCoverage {
    #[must_use]
    pub fn reaches(&self, milestone: RuntimeMilestone) -> bool {
        self.reached.contains(&milestone)
    }

    fn normalize(&mut self) {
        self.reached.sort();
        self.reached.dedup();
        self.gaps.sort();
        self.gaps.dedup();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationStatus {
    Passed,
    Degraded,
    Failed,
    Crashed,
    TimedOutBeforeReadiness,
    TimedOutAfterReadiness,
    HarnessFailure,
    InfrastructureFailure,
    Inconclusive,
    Skipped,
}

/// Whether a finished execution attempt produced compatibility evidence that is
/// safe to feed into accuracy/calibration.  Attempt completion and evidence
/// completeness are intentionally separate concepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceState {
    Conclusive,
    Partial,
    #[default]
    Unavailable,
}

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
            Self::Crashed => "crashed",
            Self::TimedOutBeforeReadiness => "timed-out-before-readiness",
            Self::TimedOutAfterReadiness => "timed-out-after-readiness",
            Self::HarnessFailure => "harness-failure",
            Self::InfrastructureFailure => "infrastructure-failure",
            Self::Inconclusive => "inconclusive",
            Self::Skipped => "skipped",
        }
    }

    #[must_use]
    pub fn evidence_state(self) -> EvidenceState {
        match self {
            Self::Passed | Self::Degraded | Self::Failed | Self::Crashed => {
                EvidenceState::Conclusive
            }
            Self::TimedOutAfterReadiness | Self::TimedOutBeforeReadiness | Self::Inconclusive => {
                EvidenceState::Partial
            }
            Self::HarnessFailure | Self::InfrastructureFailure | Self::Skipped => {
                EvidenceState::Unavailable
            }
        }
    }

    #[must_use]
    pub fn eligible_for_accuracy(self) -> bool {
        self.evidence_state() != EvidenceState::Unavailable
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentObservation {
    pub occurrence_id: String,
    pub semantic_fingerprint: String,
    pub fuzzy_fingerprint: String,
    pub terminality: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<FailureCategory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throwable_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frame_symbols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frame_classes: Vec<String>,
    /// Conservative blame candidates: explicit loader module ids and the first
    /// non-platform frame of the deepest throwable. Context-only frames are not
    /// promoted wholesale.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributed_subjects: Vec<String>,
    pub source_line: u32,
    pub source_fragment: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionObservation {
    pub schema: String,
    pub environment: String,
    pub status: ObservationStatus,
    #[serde(default)]
    pub evidence_state: EvidenceState,
    pub coverage: ExecutionCoverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incidents: Vec<IncidentObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub background_events: Vec<IncidentObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failure_categories: Vec<FailureCategory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_time_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enforced_limits: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_limits: Vec<String>,
    #[serde(default)]
    pub isolation: String,
}

/// Normalize one smoke output into structured, coverage-aware evidence.
#[must_use]
pub fn observe_smoke(raw: &RawSmokeOutput) -> ExecutionObservation {
    let events = intermed_log::runtime::normalize_events(&raw.log, &raw.environment);
    let mut coverage = coverage_from_log(&raw.log, raw.log_complete);
    let readiness = coverage.reaches(RuntimeMilestone::ServerStarted)
        || coverage.reaches(RuntimeMilestone::ClientInit)
        || coverage.reaches(RuntimeMilestone::WorldLoaded);

    let mut incidents = Vec::new();
    let mut background_events = Vec::new();
    let mut nonterminal_candidates = Vec::new();
    for event in &events {
        let projected = project_event(event);
        let has_failure_shape = projected.category.is_some()
            || !event.exception_chain.is_empty()
            || matches!(event.level.as_deref(), Some("ERROR" | "FATAL"));
        if !has_failure_shape {
            continue;
        }
        if event.terminality.is_terminal() {
            incidents.push(projected);
        } else if matches!(
            event.terminality,
            EventTerminality::Recovered | EventTerminality::BackgroundError
        ) {
            background_events.push(projected);
        } else {
            nonterminal_candidates.push(projected);
        }
    }

    // A non-zero exit can corroborate one otherwise-unmarked terminal event, but
    // it must never promote every earlier warning/error in the process.  Use only
    // the last structured failure candidate when no parser-confirmed terminal
    // event exists; all earlier candidates remain background context.
    if incidents.is_empty() && !raw.exited_ok && !raw.timed_out {
        if let Some(last) = nonterminal_candidates.pop() {
            background_events.append(&mut nonterminal_candidates);
            incidents.push(last);
        }
    } else {
        background_events.append(&mut nonterminal_candidates);
    }

    let mut failure_categories = incidents
        .iter()
        .filter_map(|incident| incident.category)
        .collect::<Vec<_>>();
    let lower_log = raw.log.to_ascii_lowercase();
    let performance_degraded = readiness
        && (lower_log.contains("can't keep up")
            || lower_log.contains("server overloaded")
            || lower_log.contains("mspt"));
    if performance_degraded {
        failure_categories.push(FailureCategory::PerformanceRegression);
    }
    failure_categories.sort();
    failure_categories.dedup();

    if raw.timed_out {
        coverage.gaps.push(if readiness {
            "run timed out after reaching readiness; later runtime regions were not observed"
                .to_string()
        } else {
            "run timed out before a readiness milestone".to_string()
        });
    }
    if !matches!(
        raw.isolation.as_str(),
        "" | "external-capture" | "test" | "static-only"
    ) {
        for limit in &raw.requested_limits {
            if !raw.enforced_limits.iter().any(|value| value == limit) {
                coverage.gaps.push(format!(
                    "execution backend did not attest the `{limit}` limit"
                ));
            }
        }
    }
    coverage.normalize();

    let status = if raw.skipped {
        ObservationStatus::Skipped
    } else if raw.infrastructure_failure {
        ObservationStatus::InfrastructureFailure
    } else if raw.harness_failure {
        ObservationStatus::HarnessFailure
    } else if raw.timed_out && readiness {
        ObservationStatus::TimedOutAfterReadiness
    } else if raw.timed_out {
        ObservationStatus::TimedOutBeforeReadiness
    } else if !incidents.is_empty() {
        if incidents.iter().any(|event| {
            matches!(
                event.category,
                Some(
                    FailureCategory::OutOfMemory
                        | FailureCategory::StackOverflow
                        | FailureCategory::JvmCrash
                )
            )
        }) {
            ObservationStatus::Crashed
        } else {
            ObservationStatus::Failed
        }
    } else if raw.exited_ok && readiness && performance_degraded {
        ObservationStatus::Degraded
    } else if raw.exited_ok && readiness {
        ObservationStatus::Passed
    } else if raw.exited_ok {
        ObservationStatus::Inconclusive
    } else {
        ObservationStatus::Failed
    };

    let evidence_state = status.evidence_state();
    ExecutionObservation {
        schema: OBSERVATION_SCHEMA.to_string(),
        environment: raw.environment.clone(),
        status,
        evidence_state,
        coverage,
        incidents,
        background_events,
        failure_categories,
        exit_code: raw.exit_code,
        timed_out: raw.timed_out,
        wall_time_ms: raw.wall_time_ms,
        enforced_limits: raw.enforced_limits.clone(),
        requested_limits: raw.requested_limits.clone(),
        isolation: raw.isolation.clone(),
    }
}

fn project_event(event: &RuntimeEvent) -> IncidentObservation {
    let deepest = event.exception_chain.iter().rfind(|node| !node.suppressed);
    let text = std::iter::once(event.message.as_str())
        .chain(event.continuation_lines.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    let category = classify_event(event, &text);
    let frame_symbols = deepest
        .into_iter()
        .flat_map(|node| &node.frames)
        .map(|frame| format!("{}.{}", frame.class, frame.method))
        .collect();
    let frame_classes = deepest
        .into_iter()
        .flat_map(|node| &node.frames)
        .map(|frame| frame.class.clone())
        .collect();
    let mut attributed_subjects = deepest
        .into_iter()
        .flat_map(|node| &node.frames)
        .filter(|frame| {
            frame.classification == intermed_log::runtime::FrameClassification::ModOrLibrary
        })
        .take(1)
        .flat_map(|frame| {
            frame
                .module
                .iter()
                .cloned()
                .chain(std::iter::once(frame.class.clone()))
        })
        .collect::<Vec<_>>();
    if category == Some(FailureCategory::MissingDependency)
        && let Some(consumer) = dependency_consumer(&text)
    {
        attributed_subjects.push(consumer);
    }
    attributed_subjects.sort();
    attributed_subjects.dedup();
    IncidentObservation {
        occurrence_id: event.occurrence_id.clone(),
        semantic_fingerprint: event.semantic_fingerprint.clone(),
        fuzzy_fingerprint: event.fuzzy_fingerprint.clone(),
        terminality: event.terminality.as_str().to_string(),
        category,
        throwable_type: deepest.map(|node| node.throwable_type.clone()),
        message: deepest.and_then(|node| node.message.clone()),
        frame_symbols,
        frame_classes,
        attributed_subjects,
        source_line: event.source_line,
        source_fragment: event.source_fragment,
    }
}

fn dependency_consumer(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("mod ")? + "mod ".len();
    let rest = text.get(start..)?.trim_start();
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let consumer = rest[..end]
        .trim_matches(|character: char| {
            character.is_ascii_punctuation() || matches!(character, '„' | '“' | '”' | '«' | '»')
        })
        .trim();
    (!consumer.is_empty()).then(|| consumer.to_string())
}

fn classify_event(event: &RuntimeEvent, text: &str) -> Option<FailureCategory> {
    let deepest = event
        .exception_chain
        .iter()
        .rfind(|node| !node.suppressed)
        .map(|node| node.throwable_type.as_str())
        .unwrap_or("");
    let lower = text.to_ascii_lowercase();
    if deepest.ends_with("OutOfMemoryError") {
        Some(FailureCategory::OutOfMemory)
    } else if deepest.ends_with("StackOverflowError") {
        Some(FailureCategory::StackOverflow)
    } else if lower.contains("invalidmixinexception")
        || lower.contains("mixin apply failed")
        || lower.contains("mixintransformererror")
    {
        Some(FailureCategory::MixinApplyError)
    } else if deepest.ends_with("NoClassDefFoundError")
        || deepest.ends_with("ClassNotFoundException")
    {
        Some(FailureCategory::ClassNotFound)
    } else if is_loader_dependency_failure(event, &lower) {
        Some(FailureCategory::MissingDependency)
    } else if lower.contains("registry is already frozen") || lower.contains("registry freeze") {
        Some(FailureCategory::RegistryFreezeError)
    } else if lower.contains("failed to load datapacks")
        || lower.contains("error while loading data pack")
    {
        Some(FailureCategory::DatapackValidationError)
    } else if lower.contains("address already in use") || lower.contains("failed to bind to port") {
        Some(FailureCategory::PortInUse)
    } else if lower.contains("fatal error has been detected by the java runtime")
        || lower.contains("sigsegv")
        || lower.contains("exception_access_violation")
    {
        Some(FailureCategory::JvmCrash)
    } else if event.terminality.is_terminal() {
        Some(FailureCategory::Unknown)
    } else {
        None
    }
}

fn is_loader_dependency_failure(event: &RuntimeEvent, lower: &str) -> bool {
    let logger = event.logger.as_deref().unwrap_or("").to_ascii_lowercase();
    let loader_context = logger.contains("fabric")
        || logger.contains("forge")
        || logger.contains("neoforge")
        || logger.contains("quilt")
        || logger.contains("modlauncher")
        || lower.contains("mod loading has failed")
        || lower.contains("incompatible mod set")
        || lower.contains("could not find required mod")
        || lower.contains("requires version");
    let loader_context = loader_context
        || ((lower.trim_start().starts_with("mod ") || lower.contains(": mod "))
            && lower.contains(" requires "));
    let dependency_shape = lower.contains("could not find required mod")
        || lower.contains("requires version")
        || lower.contains("requires mod")
        || (lower.contains("requires")
            && (lower.contains("which is missing")
                || lower.contains("but it is not installed")
                || lower.contains("currently, it is not installed")));
    loader_context && dependency_shape
}

fn coverage_from_log(log: &str, log_complete: bool) -> ExecutionCoverage {
    let lower = log.to_ascii_lowercase();
    let mut reached = Vec::new();
    let loader_markers = [
        "fabric loader",
        "quilt loader",
        "forge mod loader",
        "neoforge",
        "modlauncher",
        "loading minecraft ",
        "loading mods",
        "loading 1 mod",
        "loading 2 mods",
    ];
    if loader_markers.iter().any(|marker| lower.contains(marker)) {
        reached.push(RuntimeMilestone::LoaderResolution);
    }
    let markers = [
        (
            RuntimeMilestone::CommonSetup,
            ["common setup", "common_setup"],
        ),
        (
            RuntimeMilestone::ClientInit,
            ["main menu", "client started"],
        ),
        (
            RuntimeMilestone::ServerStarted,
            ["done (", "server started"],
        ),
        (
            RuntimeMilestone::WorldLoaded,
            ["loaded world", "world load complete"],
        ),
        (
            RuntimeMilestone::PlayerJoined,
            [" joined the game", "logged in with entity id"],
        ),
        (
            RuntimeMilestone::ResourceReload,
            ["resource reload", "reloading resource"],
        ),
        (
            RuntimeMilestone::DatapackLoad,
            ["loaded datapack", "loaded data pack"],
        ),
        (
            RuntimeMilestone::SteadyStateTicks,
            ["average tick time", "mean tick time"],
        ),
        (
            RuntimeMilestone::GracefulShutdown,
            ["stopping server", "saving worlds"],
        ),
    ];
    for (milestone, needles) in markers {
        if needles.iter().any(|needle| lower.contains(needle)) {
            reached.push(milestone);
        }
    }
    // A sampled MSPT value is steady-state evidence only after readiness; an
    // early "can't keep up" line is not.
    if (reached.contains(&RuntimeMilestone::ServerStarted)
        || reached.contains(&RuntimeMilestone::ClientInit))
        && (lower.contains(" mspt:") || lower.contains("mspt="))
    {
        reached.push(RuntimeMilestone::SteadyStateTicks);
    }
    let mut gaps = Vec::new();
    if !log_complete {
        gaps.push("captured log was truncated or otherwise incomplete".to_string());
    }
    let mut coverage = ExecutionCoverage {
        reached,
        log_complete,
        gaps,
    };
    coverage.normalize();
    coverage
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(ok: bool, timed_out: bool, log: &str) -> RawSmokeOutput {
        RawSmokeOutput {
            schema: crate::run::SMOKE_OUTPUT_SCHEMA.into(),
            environment: "test".into(),
            exited_ok: ok,
            timed_out,
            log: log.into(),
            exit_code: ok.then_some(0),
            log_complete: true,
            infrastructure_failure: false,
            harness_failure: false,
            skipped: false,
            wall_time_ms: None,
            enforced_limits: Vec::new(),
            requested_limits: Vec::new(),
            isolation: "test".into(),
        }
    }

    #[test]
    fn recovered_error_is_background_not_incident() {
        let observation = observe_smoke(&raw(
            true,
            false,
            "[main/ERROR]: java.lang.IllegalStateException: optional check failed\nDone (2.0s)!",
        ));
        assert!(observation.incidents.is_empty());
        assert_eq!(observation.status, ObservationStatus::Passed);
        assert!(!observation.background_events.is_empty());
    }

    #[test]
    fn timeout_after_readiness_is_distinct() {
        let observation = observe_smoke(&raw(false, true, "Done (2.0s)!"));
        assert_eq!(
            observation.status,
            ObservationStatus::TimedOutAfterReadiness
        );
    }

    #[test]
    fn fatal_exception_uses_deepest_cause() {
        let observation = observe_smoke(&raw(
            false,
            false,
            "[main/FATAL]: net.minecraft.ReportedException: wrapper\nCaused by: java.lang.OutOfMemoryError: heap",
        ));
        assert_eq!(observation.status, ObservationStatus::Crashed);
        assert_eq!(
            observation.incidents[0].throwable_type.as_deref(),
            Some("java.lang.OutOfMemoryError")
        );
    }

    #[test]
    fn arbitrary_nonempty_log_does_not_reach_loader_resolution() {
        let observation = observe_smoke(&raw(
            false,
            false,
            "Error: Could not create the Java Virtual Machine",
        ));
        assert!(
            !observation
                .coverage
                .reaches(RuntimeMilestone::LoaderResolution)
        );
    }

    #[test]
    fn negative_or_preparatory_markers_do_not_claim_runtime_coverage() {
        let observation = observe_smoke(&raw(
            false,
            false,
            "Preparing spawn area: 10%\nFailed to load data pack\nCan't keep up!",
        ));
        assert!(!observation.coverage.reaches(RuntimeMilestone::WorldLoaded));
        assert!(!observation.coverage.reaches(RuntimeMilestone::DatapackLoad));
        assert!(
            !observation
                .coverage
                .reaches(RuntimeMilestone::SteadyStateTicks)
        );
    }

    #[test]
    fn nonzero_exit_promotes_only_the_last_unmarked_failure() {
        let observation = observe_smoke(&raw(
            false,
            false,
            "[main/ERROR]: Mixin apply failed optional probe\n[main/ERROR]: java.lang.OutOfMemoryError: heap",
        ));
        assert_eq!(observation.incidents.len(), 1);
        assert_eq!(
            observation.incidents[0].category,
            Some(FailureCategory::OutOfMemory)
        );
        assert_eq!(observation.background_events.len(), 1);
    }

    #[test]
    fn nonzero_exit_does_not_promote_known_background_error() {
        let observation = observe_smoke(&raw(
            false,
            false,
            "[update-check/ERROR]: java.io.IOException: update check failed\nConnection reset",
        ));
        assert!(observation.incidents.is_empty());
        assert_eq!(observation.background_events.len(), 1);
        assert_eq!(observation.status, ObservationStatus::Failed);
        assert!(observation.failure_categories.is_empty());
    }

    #[test]
    fn generic_requires_missing_text_is_not_a_dependency_failure() {
        let observation = observe_smoke(&raw(
            false,
            false,
            "[worker/ERROR]: Rendering requires missing texture state",
        ));
        assert!(
            !observation
                .failure_categories
                .contains(&FailureCategory::MissingDependency)
        );
    }

    #[test]
    fn final_loader_abort_does_not_inherit_an_earlier_unconnected_category() {
        let observation = observe_smoke(&raw(
            false,
            false,
            "[main/FATAL]: InvalidMixinException: apply failed\n[main/FATAL]: Mod sicherheit requires fabric-api which is missing",
        ));
        assert_eq!(
            observation.failure_categories,
            vec![FailureCategory::MissingDependency]
        );
    }

    #[test]
    fn operational_failures_are_not_accuracy_labels() {
        for status in [
            ObservationStatus::HarnessFailure,
            ObservationStatus::InfrastructureFailure,
            ObservationStatus::Skipped,
        ] {
            assert!(!status.eligible_for_accuracy());
            assert_eq!(status.evidence_state(), EvidenceState::Unavailable);
        }
        assert!(ObservationStatus::TimedOutAfterReadiness.eligible_for_accuracy());
        assert_eq!(
            ObservationStatus::TimedOutAfterReadiness.evidence_state(),
            EvidenceState::Partial
        );
    }
}
