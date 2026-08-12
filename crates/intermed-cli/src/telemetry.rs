//! Explicit, privacy-bounded outcome telemetry for `intermed doctor`.
//!
//! There is deliberately no background sender, persistent installation id, or
//! default destination. An event exists only when the caller requests a local
//! export or supplies an HTTPS endpoint for that invocation.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use intermed_doctor_core::evidence::Category;
use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{DiagnosticRun, TargetKind, write_atomic};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub const TELEMETRY_SCHEMA: &str = "intermed-telemetry-event-v1";
const MAX_LOG_EXCERPTS: usize = 20;
const MAX_EXCERPT_CHARS: usize = 240;

#[derive(Debug, Clone, Copy)]
pub struct TelemetryOptions<'a> {
    pub out: Option<&'a Path>,
    pub endpoint: Option<&'a str>,
    pub include_log_excerpts: bool,
}

impl TelemetryOptions<'_> {
    pub fn requested(self) -> bool {
        self.out.is_some() || self.endpoint.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryConsent {
    pub outcome_metrics: bool,
    pub log_excerpts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEnvironment {
    pub target_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loader: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minecraft_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryOperationalError {
    pub stage: String,
    pub component: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryLogExcerpt {
    pub signal: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub schema: String,
    pub tool_version: String,
    pub generated_at: String,
    pub consent: TelemetryConsent,
    pub environment: TelemetryEnvironment,
    pub total_duration_ms: u64,
    pub fact_count: usize,
    pub facts_dropped: usize,
    pub findings_by_severity: BTreeMap<String, usize>,
    pub findings_by_category: BTreeMap<String, usize>,
    pub findings_by_rule: BTreeMap<String, usize>,
    pub collectors_by_status: BTreeMap<String, usize>,
    pub collector_facts: BTreeMap<String, usize>,
    pub collector_duration_ms: BTreeMap<String, u64>,
    pub rule_duration_ms: BTreeMap<String, u64>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_writes: u64,
    pub operational_errors: Vec<TelemetryOperationalError>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log_excerpts: Vec<TelemetryLogExcerpt>,
}

/// Build the exact event that would be exported or sent. This function performs
/// no I/O and is public so callers can audit/preview the payload themselves.
pub fn build_event(run: &DiagnosticRun, include_log_excerpts: bool) -> TelemetryEvent {
    let mut severities = BTreeMap::new();
    let mut categories = BTreeMap::new();
    let mut rules = BTreeMap::new();
    for finding in &run.report.findings {
        *severities
            .entry(finding.severity.as_str().to_string())
            .or_insert(0) += 1;
        *categories
            .entry(category_name(finding.category).to_string())
            .or_insert(0) += 1;
        *rules.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }

    let mut collector_status = BTreeMap::new();
    let mut collector_facts = BTreeMap::new();
    for collector in &run.report.collectors {
        *collector_status
            .entry(collector.status.clone())
            .or_insert(0) += 1;
        collector_facts.insert(collector.id.clone(), collector.facts_emitted);
    }

    let environment = &run.report.environment;
    TelemetryEvent {
        schema: TELEMETRY_SCHEMA.to_string(),
        tool_version: run.report.tool_version.clone(),
        generated_at: run.report.generated_at.to_rfc3339(),
        consent: TelemetryConsent {
            outcome_metrics: true,
            log_excerpts: include_log_excerpts,
        },
        environment: TelemetryEnvironment {
            target_kind: target_kind_name(run.report.target.kind).to_string(),
            os: environment.os.clone(),
            java_version: environment.java_version.clone(),
            loader: environment.loader.map(|v| v.as_str().to_string()),
            minecraft_version: environment.minecraft_version.clone(),
            side: environment.side.map(serde_name),
            layout: environment.layout.map(|v| v.as_str().to_string()),
        },
        total_duration_ms: run.profile.total_ms,
        fact_count: run.facts.len(),
        facts_dropped: run.profile.facts_dropped,
        findings_by_severity: severities,
        findings_by_category: categories,
        findings_by_rule: rules,
        collectors_by_status: collector_status,
        collector_facts,
        collector_duration_ms: run
            .profile
            .collectors
            .iter()
            .map(|phase| (phase.id.clone(), phase.duration_ms))
            .collect(),
        rule_duration_ms: run
            .profile
            .rules
            .iter()
            .map(|phase| (phase.id.clone(), phase.duration_ms))
            .collect(),
        cache_hits: run.profile.cache.hits,
        cache_misses: run.profile.cache.misses,
        cache_writes: run.profile.cache.writes,
        operational_errors: run
            .report
            .operational_errors
            .iter()
            .map(|error| TelemetryOperationalError {
                stage: error.stage.clone(),
                component: error.component.clone(),
            })
            .collect(),
        log_excerpts: if include_log_excerpts {
            collect_log_excerpts(run)
        } else {
            Vec::new()
        },
    }
}

/// Validate consent options and perform the explicitly requested destinations.
/// A failed requested export/send is an operational failure, not a finding.
pub fn deliver(run: &DiagnosticRun, options: TelemetryOptions<'_>) -> Result<()> {
    validate(options)?;
    if !options.requested() {
        return Ok(());
    }

    let event = build_event(run, options.include_log_excerpts);
    let bytes = serde_json::to_vec_pretty(&event).context("serialize telemetry event")?;
    if let Some(path) = options.out {
        write_atomic(path, &bytes)
            .with_context(|| format!("could not write telemetry event to {}", path.display()))?;
    }
    if let Some(endpoint) = options.endpoint {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10))
            .timeout_write(Duration::from_secs(5))
            // Consent names one exact HTTPS destination. Do not silently follow
            // it to another host or to a downgraded transport.
            .redirects(0)
            .build();
        let response = agent
            .post(endpoint)
            .set("Content-Type", "application/json")
            .set(
                "User-Agent",
                concat!("intermed/", env!("CARGO_PKG_VERSION")),
            )
            .send_bytes(&bytes)
            .with_context(|| format!("telemetry POST to {endpoint} failed"))?;
        if !(200..300).contains(&response.status()) {
            bail!(
                "telemetry POST to {endpoint} returned HTTP {}",
                response.status()
            );
        }
    }
    Ok(())
}

/// Check telemetry consent and destination syntax without starting a scan.
pub fn validate(options: TelemetryOptions<'_>) -> Result<()> {
    if options.include_log_excerpts && !options.requested() {
        bail!("--telemetry-include-log-excerpts requires --telemetry-out or --telemetry-endpoint");
    }
    if let Some(endpoint) = options.endpoint {
        validate_endpoint(endpoint)?;
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    if !endpoint.starts_with("https://") {
        bail!("telemetry endpoint must use https://");
    }
    let authority = endpoint
        .strip_prefix("https://")
        .unwrap_or_default()
        .split('/')
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') || endpoint.chars().any(char::is_whitespace)
    {
        bail!("telemetry endpoint must be an HTTPS URL without credentials or whitespace");
    }
    Ok(())
}

fn collect_log_excerpts(run: &DiagnosticRun) -> Vec<TelemetryLogExcerpt> {
    run.facts
        .iter()
        .filter(|fact| fact.kind == kind::LOG_SIGNAL)
        .filter_map(|fact| {
            fact.attr("excerpt").map(|excerpt| TelemetryLogExcerpt {
                signal: fact.subject.clone(),
                excerpt: redact_excerpt(excerpt),
            })
        })
        .take(MAX_LOG_EXCERPTS)
        .collect()
}

fn redact_excerpt(text: &str) -> String {
    static SENSITIVE: OnceLock<Regex> = OnceLock::new();
    let sensitive = SENSITIVE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)(?:https?://\S+)",
            r"|(?:[\w.+-]+@[\w.-]+\.[a-z]{2,})",
            r"|(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)",
            r"|(?:(?:token|password|passwd|secret|authorization)\s*[=:]\s*\S+)",
            r"|(?:[a-z]:\\[^\s]+)",
            r"|(?:/(?:home|users|var|tmp|opt|srv|mnt|media)/[^\s]+)"
        ))
        .expect("telemetry redaction regex is valid")
    });
    let redacted = sensitive.replace_all(text, "<redacted>");
    redacted.chars().take(MAX_EXCERPT_CHARS).collect()
}

fn serde_name<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn target_kind_name(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Server => "server",
        TargetKind::Instance => "instance",
        TargetKind::ModsDir => "mods-dir",
        TargetKind::LogFile => "log-file",
        TargetKind::CrashReport => "crash-report",
        TargetKind::ModpackArchive => "modpack-archive",
        TargetKind::Unknown => "unknown",
    }
}

fn category_name(category: Category) -> &'static str {
    match category {
        Category::Environment => "environment",
        Category::Metadata => "metadata",
        Category::Dependency => "dependency",
        Category::Loader => "loader",
        Category::Log => "log",
        Category::Resource => "resource",
        Category::Mixin => "mixin",
        Category::Security => "security",
        Category::Performance => "performance",
        Category::Packaging => "packaging",
        Category::Runtime => "runtime",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::facts::{FactId, SourceRef};
    use intermed_doctor_core::{DiagnosticEngine, Target};

    fn run_with_private_data() -> DiagnosticRun {
        let target = Target::with_kind("/home/alice/private-pack", TargetKind::ModsDir);
        let mut run = DiagnosticEngine::builder()
            .build()
            .diagnose_with_facts(&target);
        run.facts.push(intermed_doctor_core::facts::Fact {
            id: FactId(99),
            kind: kind::LOG_SIGNAL.to_string(),
            subject: "ClassNotFound".to_string(),
            attributes: [(
                "excerpt".to_string(),
                "user alice@example.com at /home/alice/private-pack 10.1.2.3 https://host/x token=abc"
                    .into(),
            )]
            .into_iter()
            .collect(),
            source: SourceRef::file("/home/alice/private-pack/logs/latest.log"),
            confidence: 1.0,
            extractor: "test".to_string(),
        });
        run
    }

    #[test]
    fn default_event_excludes_paths_and_log_contents() {
        let event = build_event(&run_with_private_data(), false);
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("alice"));
        assert!(!json.contains("private-pack"));
        assert!(!json.contains("10.1.2.3"));
        assert!(event.log_excerpts.is_empty());
    }

    #[test]
    fn separately_consented_excerpts_are_bounded_and_redacted() {
        let event = build_event(&run_with_private_data(), true);
        assert_eq!(event.log_excerpts.len(), 1);
        let excerpt = &event.log_excerpts[0].excerpt;
        assert!(!excerpt.contains("alice@example.com"));
        assert!(!excerpt.contains("/home/alice"));
        assert!(!excerpt.contains("10.1.2.3"));
        assert!(!excerpt.contains("https://"));
        assert!(!excerpt.contains("token=abc"));
        assert!(excerpt.chars().count() <= MAX_EXCERPT_CHARS);
    }

    #[test]
    fn endpoint_requires_https_without_credentials() {
        assert!(validate_endpoint("http://example.test/events").is_err());
        assert!(validate_endpoint("https://user@example.test/events").is_err());
        assert!(validate_endpoint("https://example.test/events").is_ok());
    }
}
