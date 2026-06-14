//! DuckDB DDL and the single Rust ↔ row mapping layer (schema-sync source of truth).

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use intermed_doctor_core::report::DoctorReport;
use intermed_doctor_core::target::{InstanceType, Loader, Side};
use intermed_evidence::{EvidenceEdge, Finding, Relation};
use intermed_facts::{AttrValue, Fact, FactId};
use sha2::{Digest, Sha256};

/// Synthetic run id used for in-memory rule evaluation (not persisted to disk).
pub const EVAL_RUN_ID: &str = "rule-eval";

/// Idempotent DDL for the analytics store. Bound to [`RunRow`] / [`FactRow`] etc.
pub const SCHEMA_DDL: &str = r"
CREATE TABLE IF NOT EXISTS runs (
    run_id          VARCHAR PRIMARY KEY,
    generated_at    VARCHAR NOT NULL,
    tool_version    VARCHAR NOT NULL,
    target_path     VARCHAR NOT NULL,
    target_kind     VARCHAR NOT NULL,
    loader          VARCHAR,
    launcher        VARCHAR,
    host_launcher     VARCHAR,
    mc_version      VARCHAR,
    side            VARCHAR,
    instance_type     VARCHAR,
    layout            VARCHAR,
    total           BIGINT NOT NULL,
    error_count     BIGINT NOT NULL,
    warn_count      BIGINT NOT NULL,
    note_count      BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS facts (
    run_id          VARCHAR NOT NULL,
    fact_id         UBIGINT NOT NULL,
    kind            VARCHAR NOT NULL,
    subject         VARCHAR NOT NULL,
    confidence      REAL NOT NULL,
    extractor       VARCHAR NOT NULL,
    source_locator  VARCHAR NOT NULL,
    source_line     INTEGER,
    source_inner    VARCHAR,
    PRIMARY KEY (run_id, fact_id)
);

CREATE TABLE IF NOT EXISTS fact_attributes (
    run_id          VARCHAR NOT NULL,
    fact_id         UBIGINT NOT NULL,
    key             VARCHAR NOT NULL,
    val_type        VARCHAR NOT NULL,
    val_str         VARCHAR,
    val_int         BIGINT,
    val_float       DOUBLE,
    val_bool        BOOLEAN,
    PRIMARY KEY (run_id, fact_id, key)
);

CREATE TABLE IF NOT EXISTS findings (
    run_id          VARCHAR NOT NULL,
    finding_id      VARCHAR NOT NULL,
    rule_id         VARCHAR NOT NULL,
    severity        VARCHAR NOT NULL,
    category        VARCHAR NOT NULL,
    title           VARCHAR NOT NULL,
    explanation     VARCHAR NOT NULL,
    confidence      REAL NOT NULL,
    PRIMARY KEY (run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS finding_tags (
    run_id          VARCHAR NOT NULL,
    finding_id      VARCHAR NOT NULL,
    tag             VARCHAR NOT NULL,
    PRIMARY KEY (run_id, finding_id, tag)
);

CREATE TABLE IF NOT EXISTS finding_affects (
    run_id          VARCHAR NOT NULL,
    finding_id      VARCHAR NOT NULL,
    component       VARCHAR NOT NULL,
    PRIMARY KEY (run_id, finding_id, component)
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    run_id          VARCHAR NOT NULL,
    finding_id      VARCHAR NOT NULL,
    fact_id         UBIGINT NOT NULL,
    relation        VARCHAR NOT NULL,
    weight          REAL NOT NULL,
    PRIMARY KEY (run_id, finding_id, fact_id, relation)
);

-- ── Analytics views (queryable directly via `intermed db query`) ──────────────

-- One row per recurring *conflict* finding across the whole persisted history:
-- how many runs it appeared in, when it was first/last seen, and how many
-- distinct components it has touched. The conflict vocabulary (resource / mixin /
-- duplicate-id / those categories) is the same one `history conflicts` reports.
CREATE OR REPLACE VIEW historical_conflicts AS
SELECT
    f.finding_id,
    f.rule_id,
    f.severity,
    f.category,
    COUNT(DISTINCT f.run_id)        AS run_count,
    MIN(r.generated_at)             AS first_seen,
    MAX(r.generated_at)             AS last_seen,
    COUNT(DISTINCT af.component)    AS distinct_targets
FROM findings f
JOIN runs r ON f.run_id = r.run_id
LEFT JOIN finding_affects af
    ON f.run_id = af.run_id AND f.finding_id = af.finding_id
WHERE f.finding_id LIKE 'resource-conflict:%'
   OR f.finding_id LIKE 'mixin-overlap:%'
   OR f.finding_id LIKE 'mixin-overwrite:%'
   OR f.finding_id LIKE 'duplicate-id:%'
   OR f.category IN ('resource', 'mixin', 'metadata')
GROUP BY f.finding_id, f.rule_id, f.severity, f.category;

-- One row per *kind* of risk (rule + category) rolled up across history: the
-- shape of what keeps going wrong in this pack, independent of specific ids.
-- `worst_severity` orders fatal > error > warn > note > info.
CREATE OR REPLACE VIEW risk_patterns AS
SELECT
    f.rule_id,
    f.category,
    COUNT(*)                        AS occurrences,
    COUNT(DISTINCT f.finding_id)    AS distinct_findings,
    COUNT(DISTINCT f.run_id)        AS run_count,
    MAX(CASE f.severity
        WHEN 'fatal' THEN 4 WHEN 'error' THEN 3 WHEN 'warn' THEN 2
        WHEN 'note' THEN 1 ELSE 0 END)  AS severity_rank,
    MIN(r.generated_at)             AS first_seen,
    MAX(r.generated_at)             AS last_seen
FROM findings f
JOIN runs r ON f.run_id = r.run_id
GROUP BY f.rule_id, f.category;

-- Per-run finding counts by severity and category (quick health snapshot).
CREATE OR REPLACE VIEW run_findings_summary AS
SELECT
    r.run_id,
    r.generated_at,
    r.target_path,
    f.category,
    f.severity,
    COUNT(*) AS finding_count
FROM runs r
JOIN findings f ON f.run_id = r.run_id
GROUP BY r.run_id, r.generated_at, r.target_path, f.category, f.severity;

-- Mixin injection sites on server tick hot paths (perf triage).
CREATE OR REPLACE VIEW mixin_effect_hotpaths AS
SELECT run_id, mod_id, target, method, operation, hot_path
FROM (
    SELECT
        f.run_id,
        f.subject AS mod_id,
        MAX(CASE WHEN a.key = 'target' THEN a.val_str END) AS target,
        MAX(CASE WHEN a.key = 'method' THEN a.val_str END) AS method,
        MAX(CASE WHEN a.key = 'operation' THEN a.val_str END) AS operation,
        MAX(CASE
            WHEN a.key = 'hot_path' AND a.val_bool IS NOT NULL THEN
                CASE WHEN a.val_bool THEN 'true' ELSE 'false' END
            WHEN a.key = 'hot_path' THEN a.val_str
        END) AS hot_path
    FROM facts f
    JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.kind = 'mixin_effect'
    GROUP BY f.run_id, f.fact_id, f.subject
) hot_rows
WHERE COALESCE(hot_path, 'false') IN ('true', '1');

-- Security capability roll-up per mod/archive (Layer G analytics).
CREATE OR REPLACE VIEW security_capabilities AS
SELECT run_id, archive, capability, COUNT(*) AS signal_facts
FROM (
    SELECT
        f.run_id,
        COALESCE(MAX(CASE WHEN a.key = 'archive' THEN a.val_str END), f.subject) AS archive,
        f.kind AS capability
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.kind LIKE 'uses_%'
    GROUP BY f.run_id, f.fact_id, f.subject, f.kind
) per_fact
GROUP BY run_id, archive, capability;

-- SBOM trust distribution per run (Layer H analytics).
CREATE OR REPLACE VIEW sbom_trust_buckets AS
SELECT
    run_id,
    CASE
        WHEN trust_score >= 80 THEN 'high'
        WHEN trust_score >= 50 THEN 'medium'
        ELSE 'low'
    END AS trust_bucket,
    COUNT(*) AS archives
FROM (
    SELECT
        f.run_id,
        f.subject AS archive,
        COALESCE(MAX(CASE WHEN a.key = 'trust_score' THEN a.val_int END), 0) AS trust_score
    FROM facts f
    LEFT JOIN fact_attributes a
      ON f.run_id = a.run_id AND f.fact_id = a.fact_id
    WHERE f.kind = 'sbom'
    GROUP BY f.run_id, f.subject
) per_archive
GROUP BY run_id, trust_bucket;

-- Fact volume per kind (spot runaway collectors — mixin_effect spikes).
CREATE OR REPLACE VIEW fact_kind_counts AS
SELECT run_id, kind, COUNT(*) AS fact_count
FROM facts
GROUP BY run_id, kind;

-- Rich Layer-B capability inventory for cross-layer analytics.
CREATE OR REPLACE VIEW mod_capability_inventory AS
SELECT
    f.run_id,
    f.subject AS mod_id,
    MAX(CASE WHEN a.key = 'capability' THEN a.val_str END) AS capability,
    MAX(CASE WHEN a.key = 'reason' THEN a.val_str END) AS reason,
    f.confidence
FROM facts f
LEFT JOIN fact_attributes a
  ON f.run_id = a.run_id AND f.fact_id = a.fact_id
WHERE f.kind = 'mod_capability'
GROUP BY f.run_id, f.fact_id, f.subject, f.confidence;

-- Root-cause-oriented crash triage enriched by Layer-B metadata.
CREATE OR REPLACE VIEW log_root_causes AS
SELECT
    f.run_id,
    f.subject AS mod_id,
    MAX(CASE WHEN a.key = 'root_cause_exception' THEN a.val_str END) AS root_cause_exception,
    MAX(CASE WHEN a.key = 'phase' THEN a.val_str END) AS phase,
    MAX(CASE WHEN a.key = 'version' THEN a.val_str END) AS version,
    MAX(CASE WHEN a.key = 'environment' THEN a.val_str END) AS environment,
    MAX(CASE WHEN a.key = 'blame_score' THEN a.val_float END) AS blame_score
FROM facts f
LEFT JOIN fact_attributes a
  ON f.run_id = a.run_id AND f.fact_id = a.fact_id
WHERE f.kind = 'log_mod_error'
GROUP BY f.run_id, f.fact_id, f.subject;
";

/// One diagnosis run header row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRow {
    pub run_id: String,
    pub generated_at: String,
    pub tool_version: String,
    pub target_path: String,
    pub target_kind: String,
    pub loader: Option<String>,
    pub launcher: Option<String>,
    pub host_launcher: Option<String>,
    pub mc_version: Option<String>,
    pub side: Option<String>,
    pub instance_type: Option<String>,
    pub layout: Option<String>,
    pub total: i64,
    pub error_count: i64,
    pub warn_count: i64,
    pub note_count: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FactRow {
    pub run_id: String,
    pub fact_id: u64,
    pub kind: String,
    pub subject: String,
    pub confidence: f32,
    pub extractor: String,
    pub source_locator: String,
    pub source_line: Option<u32>,
    pub source_inner: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FactAttributeRow {
    pub run_id: String,
    pub fact_id: u64,
    pub key: String,
    pub val_type: String,
    pub val_str: Option<String>,
    pub val_int: Option<i64>,
    pub val_float: Option<f64>,
    pub val_bool: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindingRow {
    pub run_id: String,
    pub finding_id: String,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub explanation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingTagRow {
    pub run_id: String,
    pub finding_id: String,
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingAffectsRow {
    pub run_id: String,
    pub finding_id: String,
    pub component: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FindingEvidenceRow {
    pub run_id: String,
    pub finding_id: String,
    pub fact_id: u64,
    pub relation: String,
    pub weight: f32,
}

/// Tables touched by [`delete_run_statements`](delete_run_statements) (child → parent).
pub const RUN_CHILD_TABLES: &[&str] = &[
    "finding_evidence",
    "finding_affects",
    "finding_tags",
    "findings",
    "fact_attributes",
    "facts",
    "runs",
];

/// `run_id` = first 16 hex chars of `sha256(generated_at ‖ target_path ‖ tool_version)`.
#[must_use]
pub fn compute_run_id(
    generated_at: &DateTime<Utc>,
    target_path: &str,
    tool_version: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(generated_at.to_rfc3339().as_bytes());
    hasher.update(target_path.as_bytes());
    hasher.update(tool_version.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    digest[..16].to_string()
}

#[must_use]
pub fn run_row_from_report(report: &DoctorReport) -> RunRow {
    let run_id = compute_run_id(
        &report.generated_at,
        &report.target.path,
        &report.tool_version,
    );
    RunRow {
        run_id,
        generated_at: report.generated_at.to_rfc3339(),
        tool_version: report.tool_version.clone(),
        target_path: report.target.path.clone(),
        target_kind: format!("{:?}", report.target.kind).to_kebab_case(),
        loader: report.environment.loader.map(loader_label),
        launcher: report.environment.launcher.clone(),
        host_launcher: report.environment.host_launcher.clone(),
        mc_version: report.environment.minecraft_version.clone(),
        side: report.environment.side.map(side_label),
        instance_type: report
            .environment
            .instance_type
            .map(instance_type_label),
        layout: report.environment.layout.map(|l| l.as_str().to_string()),
        total: i64::try_from(report.summary.total).unwrap_or(i64::MAX),
        error_count: i64::try_from(report.summary.error).unwrap_or(i64::MAX),
        warn_count: i64::try_from(report.summary.warn).unwrap_or(i64::MAX),
        note_count: i64::try_from(report.summary.note).unwrap_or(i64::MAX),
    }
}

#[must_use]
pub fn fact_row(fact: &Fact, run_id: &str) -> FactRow {
    FactRow {
        run_id: run_id.to_string(),
        fact_id: fact.id.0,
        kind: fact.kind.clone(),
        subject: fact.subject.clone(),
        confidence: fact.confidence,
        extractor: fact.extractor.clone(),
        source_locator: fact.source.locator.clone(),
        source_line: fact.source.line,
        source_inner: fact.source.inner.clone(),
    }
}

#[must_use]
pub fn fact_attribute_rows(fact: &Fact, run_id: &str) -> Vec<FactAttributeRow> {
    fact.attributes
        .iter()
        .map(|(key, value)| attr_row(run_id, fact.id.0, key, value))
        .collect()
}

fn attr_row(run_id: &str, fact_id: u64, key: &str, value: &AttrValue) -> FactAttributeRow {
    let (val_type, val_str, val_int, val_float, val_bool) = match value {
        AttrValue::Str(s) => ("str", Some(s.clone()), None, None, None),
        AttrValue::Int(i) => ("int", None, Some(*i), None, None),
        AttrValue::Float(f) => ("float", None, None, Some(*f), None),
        AttrValue::Bool(b) => ("bool", None, None, None, Some(*b)),
    };
    FactAttributeRow {
        run_id: run_id.to_string(),
        fact_id,
        key: key.to_string(),
        val_type: val_type.to_string(),
        val_str,
        val_int,
        val_float,
        val_bool,
    }
}

/// All persistable rows for one diagnosis run.
#[derive(Debug, Clone, PartialEq)]
pub struct MaterializedRun {
    pub run: RunRow,
    pub facts: Vec<FactRow>,
    pub fact_attributes: Vec<FactAttributeRow>,
    pub findings: Vec<FindingRow>,
    pub finding_tags: Vec<FindingTagRow>,
    pub finding_affects: Vec<FindingAffectsRow>,
    pub finding_evidence: Vec<FindingEvidenceRow>,
}

/// Collapse duplicate primary-key rows before persistence.
///
/// Collectors can emit many `mixin_effect` facts; re-persisting the same `run_id`
/// must never hit DuckDB PRIMARY KEY conflicts from duplicate `(run_id, fact_id)`
/// or `(run_id, fact_id, key)` tuples in one batch.
#[must_use]
pub fn dedupe_materialized_run(bundle: MaterializedRun) -> MaterializedRun {
    MaterializedRun {
        run: bundle.run,
        facts: dedupe_rows(bundle.facts, |r| r.fact_id),
        fact_attributes: dedupe_rows(
            bundle.fact_attributes,
            |r| (r.fact_id, r.key.clone()),
        ),
        findings: dedupe_rows(bundle.findings, |r| r.finding_id.clone()),
        finding_tags: dedupe_rows(
            bundle.finding_tags,
            |r| (r.finding_id.clone(), r.tag.clone()),
        ),
        finding_affects: dedupe_rows(
            bundle.finding_affects,
            |r| (r.finding_id.clone(), r.component.clone()),
        ),
        finding_evidence: dedupe_rows(
            bundle.finding_evidence,
            |r| (r.finding_id.clone(), r.fact_id, r.relation.clone()),
        ),
    }
}

fn dedupe_rows<T, K>(rows: Vec<T>, key: impl Fn(&T) -> K) -> Vec<T>
where
    K: Ord,
{
    let mut out = Vec::with_capacity(rows.len());
    let mut seen = BTreeMap::new();
    for row in rows {
        let k = key(&row);
        if let Some(idx) = seen.get(&k) {
            out[*idx] = row;
        } else {
            seen.insert(k, out.len());
            out.push(row);
        }
    }
    out
}

/// Expand a report + fact snapshot into all persistable rows.
#[must_use]
pub fn materialize_run(report: &DoctorReport, facts: &[Fact]) -> MaterializedRun {
    let run = run_row_from_report(report);
    let run_id = run.run_id.clone();

    let mut fact_rows = Vec::with_capacity(facts.len());
    let mut attr_rows = Vec::new();
    for fact in facts {
        fact_rows.push(fact_row(fact, &run_id));
        attr_rows.extend(fact_attribute_rows(fact, &run_id));
    }

    let mut finding_rows = Vec::with_capacity(report.findings.len());
    let mut tag_rows = Vec::new();
    let mut affects_rows = Vec::new();
    let mut evidence_rows = Vec::new();
    for finding in &report.findings {
        finding_rows.push(finding_row(finding, &run_id));
        tag_rows.extend(finding_tag_rows(finding, &run_id));
        affects_rows.extend(finding_affects_rows(finding, &run_id));
        evidence_rows.extend(finding_evidence_rows(finding, &run_id));
    }

    dedupe_materialized_run(MaterializedRun {
        run,
        facts: fact_rows,
        fact_attributes: attr_rows,
        findings: finding_rows,
        finding_tags: tag_rows,
        finding_affects: affects_rows,
        finding_evidence: evidence_rows,
    })
}

#[must_use]
pub fn materialize_facts_only(
    run_id: &str,
    facts: &[Fact],
) -> (Vec<FactRow>, Vec<FactAttributeRow>) {
    let mut fact_rows = Vec::with_capacity(facts.len());
    let mut attr_rows = Vec::new();
    for fact in facts {
        fact_rows.push(fact_row(fact, run_id));
        attr_rows.extend(fact_attribute_rows(fact, run_id));
    }
    (fact_rows, attr_rows)
}

fn finding_row(finding: &Finding, run_id: &str) -> FindingRow {
    FindingRow {
        run_id: run_id.to_string(),
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        severity: finding.severity.as_str().to_string(),
        category: format!("{:?}", finding.category).to_kebab_case(),
        title: finding.title.clone(),
        explanation: finding.explanation.clone(),
        confidence: finding.confidence,
    }
}

fn finding_tag_rows(finding: &Finding, run_id: &str) -> Vec<FindingTagRow> {
    finding
        .machine_tags
        .iter()
        .map(|tag| FindingTagRow {
            run_id: run_id.to_string(),
            finding_id: finding.id.clone(),
            tag: tag.clone(),
        })
        .collect()
}

fn finding_affects_rows(finding: &Finding, run_id: &str) -> Vec<FindingAffectsRow> {
    finding
        .affected_components
        .iter()
        .map(|component| FindingAffectsRow {
            run_id: run_id.to_string(),
            finding_id: finding.id.clone(),
            component: component.clone(),
        })
        .collect()
}

fn finding_evidence_rows(finding: &Finding, run_id: &str) -> Vec<FindingEvidenceRow> {
    finding
        .evidence
        .iter()
        .map(|edge| FindingEvidenceRow {
            run_id: run_id.to_string(),
            finding_id: finding.id.clone(),
            fact_id: edge.fact.0,
            relation: relation_label(edge.relation).to_string(),
            weight: edge.weight,
        })
        .collect()
}

fn relation_label(relation: Relation) -> &'static str {
    match relation {
        Relation::Supports => "supports",
        Relation::Subject => "subject",
        Relation::Mentions => "mentions",
        Relation::Violates => "violates",
        Relation::ConflictsWith => "conflicts_with",
        Relation::CorrelatesWith => "correlates_with",
    }
}

fn loader_label(loader: Loader) -> String {
    loader.as_str().to_string()
}

fn instance_type_label(instance_type: InstanceType) -> String {
    instance_type.as_str().to_string()
}

fn side_label(side: Side) -> String {
    match side {
        Side::Client => "client".to_string(),
        Side::Server => "server".to_string(),
        Side::Both => "both".to_string(),
    }
}

trait KebabCase {
    fn to_kebab_case(self) -> String;
}

impl KebabCase for String {
    fn to_kebab_case(self) -> String {
        let mut out = String::with_capacity(self.len());
        for (i, ch) in self.chars().enumerate() {
            if ch.is_uppercase() {
                if i > 0 {
                    out.push('-');
                }
                out.extend(ch.to_lowercase());
            } else {
                out.push(ch);
            }
        }
        out
    }
}

/// SQL `DELETE` statements for idempotent re-persist of one run (children first).
#[must_use]
pub fn delete_run_statements(run_id: &str) -> Vec<String> {
    RUN_CHILD_TABLES
        .iter()
        .map(|table| format!("DELETE FROM {table} WHERE run_id = '{run_id}'"))
        .collect()
}

/// Index facts by id for evidence edge reconstruction in the SQL rule backend.
#[must_use]
pub fn facts_by_id(facts: &[Fact]) -> BTreeMap<u64, &Fact> {
    facts.iter().map(|f| (f.id.0, f)).collect()
}

/// Reconstruct an [`EvidenceEdge`] from a stored fact id.
#[must_use]
pub fn subject_edge(fact_id: FactId) -> EvidenceEdge {
    EvidenceEdge::subject(fact_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use intermed_doctor_core::report::{Summary, TargetView};
    use intermed_doctor_core::target::{Environment, TargetKind};
    use intermed_evidence::{Category, Severity};
    use intermed_facts::{kind, FactStore, SourceRef};

    #[test]
    fn run_id_is_stable_and_truncated() {
        let at = Utc.with_ymd_and_hms(2026, 6, 12, 10, 0, 0).unwrap();
        let a = compute_run_id(&at, "/mods", "0.1.0");
        let b = compute_run_id(&at, "/mods", "0.1.0");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        let c = compute_run_id(&at, "/other", "0.1.0");
        assert_ne!(a, c);
    }

    #[test]
    fn attr_value_maps_to_typed_columns() {
        let mut store = FactStore::new();
        store
            .fact("t", kind::HOT_METHOD)
            .subject("c")
            .attr("method", "tick")
            .attr("percent", 42.5_f64)
            .attr("hot", true)
            .emit();
        let fact = &store.all()[0];
        let rows = fact_attribute_rows(fact, "abc");
        let by_key: BTreeMap<_, _> = rows.iter().map(|r| (r.key.as_str(), r)).collect();
        assert_eq!(by_key["method"].val_type, "str");
        assert_eq!(by_key["method"].val_str.as_deref(), Some("tick"));
        assert_eq!(by_key["percent"].val_type, "float");
        assert_eq!(by_key["percent"].val_float, Some(42.5));
        assert_eq!(by_key["hot"].val_type, "bool");
        assert_eq!(by_key["hot"].val_bool, Some(true));
    }

    #[test]
    fn materialize_run_round_trips_counts() {
        let mut store = FactStore::new();
        let id = store
            .fact("meta", kind::MOD)
            .subject("alpha")
            .attr("file", "a.jar")
            .source(SourceRef::file("a.jar"))
            .emit();
        let facts: Vec<Fact> = store.all().to_vec();
        let report = DoctorReport {
            schema: "intermed-doctor-report-v1".into(),
            tool_version: "0.1.0".into(),
            generated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            target: TargetView {
                path: "/mods".into(),
                kind: TargetKind::ModsDir,
            },
            environment: Environment::default(),
            summary: Summary {
                total: 1,
                error: 1,
                ..Summary::default()
            },
            findings: vec![Finding::builder("duplicate-id", "duplicate-id:alpha")
                .severity(Severity::Error)
                .category(Category::Metadata)
                .title("dup")
                .explanation("dup")
                .evidence(EvidenceEdge::subject(id))
                .tag("metadata")
                .build()],
            fix_plan: Vec::new(),
            fact_stats: store.stats(),
            collectors: Vec::new(),
            rules: Vec::new(),
            deferred_layers: Vec::new(),
            profile: None,
        };

        let bundle = materialize_run(&report, &facts);
        assert_eq!(bundle.facts.len(), 1);
        assert_eq!(bundle.fact_attributes.len(), 1);
        assert_eq!(bundle.findings.len(), 1);
        assert_eq!(bundle.finding_tags.len(), 1);
        assert_eq!(bundle.finding_affects.len(), 0);
        assert_eq!(bundle.finding_evidence.len(), 1);
        assert_eq!(bundle.run.target_path, "/mods");
        assert_eq!(bundle.run.error_count, 1);
    }
}
