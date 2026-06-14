//! Pre-built analytics queries over persisted DuckDB history.
//!
//! These power `intermed history` and `intermed trends` so operators do not
//! need to hand-write SQL for the common cross-run questions.

use std::path::Path;

use chrono::{Duration, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::store::{DuckError, DuckStore, QueryResult};

/// Parse a relative window like `30d`, `7d`, or `24h`.
pub fn parse_since(input: &str) -> Result<Duration, AnalyticsError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AnalyticsError::InvalidSince(
            "empty duration".to_string(),
        ));
    }
    let (num, unit) = trimmed.split_at(trimmed.len().saturating_sub(1));
    let value: i64 = num
        .parse()
        .map_err(|_| AnalyticsError::InvalidSince(input.to_string()))?;
    if value <= 0 {
        return Err(AnalyticsError::InvalidSince(input.to_string()));
    }
    let duration = match unit {
        "d" | "D" => Duration::days(value),
        "h" | "H" => Duration::hours(value),
        "w" | "W" => Duration::weeks(value),
        _ => return Err(AnalyticsError::InvalidSince(input.to_string())),
    };
    Ok(duration)
}

/// One recurring conflict across multiple diagnosis runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecurringConflict {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: String,
    pub run_count: usize,
    pub first_seen: String,
    pub last_seen: String,
    /// Distinct affected components this conflict has touched across runs.
    pub distinct_targets: usize,
}

/// One recurring *kind* of risk (rule + category) rolled up across history —
/// from the `risk_patterns` view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskPattern {
    pub rule_id: String,
    pub category: String,
    pub occurrences: usize,
    pub distinct_findings: usize,
    pub run_count: usize,
    /// fatal=4, error=3, warn=2, note=1, info=0.
    pub severity_rank: u8,
    pub first_seen: String,
    pub last_seen: String,
}

/// Mixin-related finding counts for one persisted run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixinRiskTrendPoint {
    pub generated_at: String,
    pub target_path: String,
    pub mixin_findings: usize,
}

/// Kind of change between two runs for one finding id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunDeltaKind {
    Added,
    Removed,
    SeverityChanged,
    RuleChanged,
    Unchanged,
}

/// One finding delta between two persisted runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunFindingDelta {
    pub finding_id: String,
    pub change: RunDeltaKind,
    pub severity: String,
    pub rule_id: String,
    pub category: String,
    pub title: String,
    pub severity_a: Option<String>,
    pub severity_b: Option<String>,
    pub affected_a: usize,
    pub affected_b: usize,
}

/// Header metadata for one persisted run (helps pick `run_id` values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunSummary {
    pub run_id: String,
    pub generated_at: String,
    pub target_path: String,
    pub error_count: usize,
    pub warn_count: usize,
}

/// Roll-up counts for a two-run diff.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct HistoryDiffSummary {
    pub added: usize,
    pub removed: usize,
    pub severity_changed: usize,
    pub rule_changed: usize,
    pub unchanged: usize,
}

/// Structured diff between two runs, including run headers and summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryDiffReport {
    pub run_a: Option<RunSummary>,
    pub run_b: Option<RunSummary>,
    pub summary: HistoryDiffSummary,
    pub deltas: Vec<RunFindingDelta>,
}

/// Frequent mixin overlap keyed by mod set and target class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixinOverlapRank {
    pub mods: String,
    pub target: String,
    pub occurrences: usize,
    pub run_count: usize,
}

#[derive(Debug, Error)]
pub enum AnalyticsError {
    #[error("duckdb: {0}")]
    Duck(#[from] DuckError),
    #[error("invalid --since value: {0}")]
    InvalidSince(String),
    #[error("analytics query returned unexpected columns")]
    MalformedResult,
}

/// Analytics facade over a file-backed [`DuckStore`].
pub struct AnalyticsStore {
    store: DuckStore,
}

impl AnalyticsStore {
    /// Open (or create) the analytics database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AnalyticsError> {
        Ok(Self {
            store: DuckStore::open(path)?,
        })
    }

    /// Findings that recur across runs within the relative `since` window.
    pub fn history_conflicts(&self, since: &str) -> Result<Vec<RecurringConflict>, AnalyticsError> {
        let duration = parse_since(since)?;
        let cutoff = (Utc::now() - duration).to_rfc3339();
        let sql = format!(
            r"
            SELECT
                f.finding_id,
                f.rule_id,
                f.severity,
                COUNT(DISTINCT f.run_id) AS run_count,
                MIN(r.generated_at) AS first_seen,
                MAX(r.generated_at) AS last_seen,
                COUNT(DISTINCT af.component) AS distinct_targets
            FROM findings f
            JOIN runs r ON f.run_id = r.run_id
            LEFT JOIN finding_affects af
                ON f.run_id = af.run_id AND f.finding_id = af.finding_id
            WHERE r.generated_at >= '{cutoff}'
              AND (
                f.finding_id LIKE 'resource-conflict:%'
                OR f.finding_id LIKE 'mixin-overlap:%'
                OR f.finding_id LIKE 'mixin-overwrite:%'
                OR f.finding_id LIKE 'duplicate-id:%'
                OR f.category IN ('resource', 'mixin', 'metadata')
              )
            GROUP BY f.finding_id, f.rule_id, f.severity
            HAVING COUNT(DISTINCT f.run_id) >= 2
            ORDER BY run_count DESC, last_seen DESC
            "
        );
        map_recurring_conflicts(&self.store.query(&sql)?)
    }

    /// Recurring *kinds* of risk (rule + category) across the whole history, from
    /// the `risk_patterns` view — the shape of what keeps going wrong in this pack.
    pub fn risk_patterns(&self, limit: usize) -> Result<Vec<RiskPattern>, AnalyticsError> {
        let sql = format!(
            r"
            SELECT rule_id, category, occurrences, distinct_findings, run_count,
                   severity_rank, first_seen, last_seen
            FROM risk_patterns
            ORDER BY severity_rank DESC, run_count DESC, occurrences DESC
            LIMIT {limit}
            "
        );
        map_risk_patterns(&self.store.query(&sql)?)
    }

    /// Mixin-category finding counts per run (time series).
    pub fn trends_mixin_risk(&self) -> Result<Vec<MixinRiskTrendPoint>, AnalyticsError> {
        let sql = r"
            SELECT
                r.generated_at,
                r.target_path,
                COUNT(*) AS mixin_findings
            FROM findings f
            JOIN runs r ON f.run_id = r.run_id
            WHERE f.category = 'mixin'
               OR f.finding_id LIKE 'mixin-%'
            GROUP BY r.run_id, r.generated_at, r.target_path
            ORDER BY r.generated_at
        ";
        map_mixin_trends(&self.store.query(sql)?)
    }

    /// Top-N most frequent mixin overlaps aggregated across all runs.
    pub fn top_mixin_overlaps(&self, limit: usize) -> Result<Vec<MixinOverlapRank>, AnalyticsError> {
        let sql = format!(
            r"
            SELECT
                mods,
                target,
                COUNT(*) AS occurrences,
                COUNT(DISTINCT run_id) AS run_count
            FROM (
                SELECT
                    f.run_id,
                    f.subject AS target,
                    MAX(CASE WHEN a.key = 'mods' THEN a.val_str END) AS mods
                FROM facts f
                LEFT JOIN fact_attributes a
                  ON f.run_id = a.run_id AND f.fact_id = a.fact_id
                WHERE f.kind = 'mixin_overlap'
                GROUP BY f.run_id, f.fact_id, f.subject
            ) overlap_rows
            WHERE mods IS NOT NULL AND mods != ''
            GROUP BY mods, target
            ORDER BY occurrences DESC, run_count DESC
            LIMIT {limit}
            "
        );
        map_overlap_ranks(&self.store.query(&sql)?)
    }

    /// Recent persisted runs (newest first) for picking diff targets.
    pub fn list_runs(&self, limit: usize) -> Result<Vec<RunSummary>, AnalyticsError> {
        let sql = format!(
            r"
            SELECT run_id, generated_at, target_path, error_count, warn_count
            FROM runs
            ORDER BY generated_at DESC
            LIMIT {limit}
            "
        );
        map_run_summaries(&self.store.query(&sql)?)
    }

    /// Compare findings between two persisted runs (`run_id` values).
    pub fn history_diff(
        &self,
        run_a: &str,
        run_b: &str,
    ) -> Result<Vec<RunFindingDelta>, AnalyticsError> {
        Ok(self.history_diff_report(run_a, run_b)?.deltas)
    }

    /// Compare findings with run headers and roll-up counts.
    pub fn history_diff_report(
        &self,
        run_a: &str,
        run_b: &str,
    ) -> Result<HistoryDiffReport, AnalyticsError> {
        let sql = format!(
            r"
            WITH a AS (
                SELECT
                    f.finding_id,
                    f.rule_id,
                    f.severity,
                    f.category,
                    f.title,
                    COUNT(DISTINCT af.component) AS affected
                FROM findings f
                LEFT JOIN finding_affects af
                  ON f.run_id = af.run_id AND f.finding_id = af.finding_id
                WHERE f.run_id = '{run_a}'
                GROUP BY f.finding_id, f.rule_id, f.severity, f.category, f.title
            ),
            b AS (
                SELECT
                    f.finding_id,
                    f.rule_id,
                    f.severity,
                    f.category,
                    f.title,
                    COUNT(DISTINCT af.component) AS affected
                FROM findings f
                LEFT JOIN finding_affects af
                  ON f.run_id = af.run_id AND f.finding_id = af.finding_id
                WHERE f.run_id = '{run_b}'
                GROUP BY f.finding_id, f.rule_id, f.severity, f.category, f.title
            )
            SELECT
                COALESCE(a.finding_id, b.finding_id) AS finding_id,
                CASE
                    WHEN a.finding_id IS NULL THEN 'added'
                    WHEN b.finding_id IS NULL THEN 'removed'
                    WHEN a.severity != b.severity THEN 'severity_changed'
                    WHEN a.rule_id != b.rule_id THEN 'rule_changed'
                    ELSE 'unchanged'
                END AS change_kind,
                COALESCE(b.severity, a.severity) AS severity,
                COALESCE(b.rule_id, a.rule_id) AS rule_id,
                COALESCE(b.category, a.category) AS category,
                COALESCE(b.title, a.title) AS title,
                a.severity AS severity_a,
                b.severity AS severity_b,
                COALESCE(a.affected, 0) AS affected_a,
                COALESCE(b.affected, 0) AS affected_b
            FROM a
            FULL OUTER JOIN b ON a.finding_id = b.finding_id
            WHERE a.finding_id IS NULL
               OR b.finding_id IS NULL
               OR a.severity != b.severity
               OR a.rule_id != b.rule_id
            ORDER BY change_kind, category, finding_id
            "
        );
        let deltas = map_run_diff(&self.store.query(&sql)?)?;
        let mut summary = HistoryDiffSummary::default();
        for delta in &deltas {
            match delta.change {
                RunDeltaKind::Added => summary.added += 1,
                RunDeltaKind::Removed => summary.removed += 1,
                RunDeltaKind::SeverityChanged => summary.severity_changed += 1,
                RunDeltaKind::RuleChanged => summary.rule_changed += 1,
                RunDeltaKind::Unchanged => summary.unchanged += 1,
            }
        }
        Ok(HistoryDiffReport {
            run_a: self.run_summary(run_a)?,
            run_b: self.run_summary(run_b)?,
            summary,
            deltas,
        })
    }

    fn run_summary(&self, run_id: &str) -> Result<Option<RunSummary>, AnalyticsError> {
        let sql = format!(
            r"
            SELECT run_id, generated_at, target_path, error_count, warn_count
            FROM runs WHERE run_id = '{run_id}'
            LIMIT 1
            "
        );
        let result = self.store.query(&sql)?;
        if result.rows.is_empty() {
            return Ok(None);
        }
        map_run_summaries(&result).map(|mut v| v.pop())
    }

    /// Delete runs older than the relative `keep` window. Returns rows removed.
    pub fn history_prune(&self, keep: &str) -> Result<usize, AnalyticsError> {
        let duration = parse_since(keep)?;
        let cutoff = (Utc::now() - duration).to_rfc3339();
        let count_sql = format!(
            "SELECT COUNT(*) FROM runs WHERE generated_at < '{cutoff}'"
        );
        let count = self
            .store
            .query(&count_sql)?
            .rows
            .first()
            .and_then(|r| r.first())
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        if count == 0 {
            return Ok(0);
        }
        let delete_sql = format!(
            r"
            DELETE FROM fact_attributes WHERE run_id IN (
                SELECT run_id FROM runs WHERE generated_at < '{cutoff}'
            );
            DELETE FROM facts WHERE run_id IN (
                SELECT run_id FROM runs WHERE generated_at < '{cutoff}'
            );
            DELETE FROM finding_tags WHERE run_id IN (
                SELECT run_id FROM runs WHERE generated_at < '{cutoff}'
            );
            DELETE FROM finding_evidence WHERE run_id IN (
                SELECT run_id FROM runs WHERE generated_at < '{cutoff}'
            );
            DELETE FROM finding_affects WHERE run_id IN (
                SELECT run_id FROM runs WHERE generated_at < '{cutoff}'
            );
            DELETE FROM findings WHERE run_id IN (
                SELECT run_id FROM runs WHERE generated_at < '{cutoff}'
            );
            DELETE FROM runs WHERE generated_at < '{cutoff}';
            "
        );
        self.store.execute_batch(&delete_sql)?;
        Ok(count)
    }

    /// Escape hatch: run arbitrary read-only SQL.
    pub fn query(&self, sql: &str) -> Result<QueryResult, AnalyticsError> {
        Ok(self.store.query(sql)?)
    }
}

fn map_run_summaries(result: &QueryResult) -> Result<Vec<RunSummary>, AnalyticsError> {
    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        if row.len() < 5 {
            return Err(AnalyticsError::MalformedResult);
        }
        out.push(RunSummary {
            run_id: row[0].clone(),
            generated_at: row[1].clone(),
            target_path: row[2].clone(),
            error_count: row[3].parse().unwrap_or(0),
            warn_count: row[4].parse().unwrap_or(0),
        });
    }
    Ok(out)
}

fn map_run_diff(result: &QueryResult) -> Result<Vec<RunFindingDelta>, AnalyticsError> {
    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        if row.len() < 11 {
            return Err(AnalyticsError::MalformedResult);
        }
        let change = match row[1].as_str() {
            "added" => RunDeltaKind::Added,
            "removed" => RunDeltaKind::Removed,
            "severity_changed" => RunDeltaKind::SeverityChanged,
            "rule_changed" => RunDeltaKind::RuleChanged,
            _ => RunDeltaKind::Unchanged,
        };
        let severity_a = nullable_cell(&row[7]);
        let severity_b = nullable_cell(&row[8]);
        out.push(RunFindingDelta {
            finding_id: row[0].clone(),
            change,
            severity: row[2].clone(),
            rule_id: row[3].clone(),
            category: row[4].clone(),
            title: row[5].clone(),
            severity_a,
            severity_b,
            affected_a: row[9].parse().unwrap_or(0),
            affected_b: row[10].parse().unwrap_or(0),
        });
    }
    Ok(out)
}

fn nullable_cell(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn map_recurring_conflicts(result: &QueryResult) -> Result<Vec<RecurringConflict>, AnalyticsError> {
    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        if row.len() < 7 {
            return Err(AnalyticsError::MalformedResult);
        }
        out.push(RecurringConflict {
            finding_id: row[0].clone(),
            rule_id: row[1].clone(),
            severity: row[2].clone(),
            run_count: row[3].parse().unwrap_or(0),
            first_seen: row[4].clone(),
            last_seen: row[5].clone(),
            distinct_targets: row[6].parse().unwrap_or(0),
        });
    }
    Ok(out)
}

fn map_risk_patterns(result: &QueryResult) -> Result<Vec<RiskPattern>, AnalyticsError> {
    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        if row.len() < 8 {
            return Err(AnalyticsError::MalformedResult);
        }
        out.push(RiskPattern {
            rule_id: row[0].clone(),
            category: row[1].clone(),
            occurrences: row[2].parse().unwrap_or(0),
            distinct_findings: row[3].parse().unwrap_or(0),
            run_count: row[4].parse().unwrap_or(0),
            severity_rank: row[5].parse().unwrap_or(0),
            first_seen: row[6].clone(),
            last_seen: row[7].clone(),
        });
    }
    Ok(out)
}

fn map_mixin_trends(result: &QueryResult) -> Result<Vec<MixinRiskTrendPoint>, AnalyticsError> {
    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        if row.len() < 3 {
            return Err(AnalyticsError::MalformedResult);
        }
        out.push(MixinRiskTrendPoint {
            generated_at: row[0].clone(),
            target_path: row[1].clone(),
            mixin_findings: row[2].parse().unwrap_or(0),
        });
    }
    Ok(out)
}

fn map_overlap_ranks(result: &QueryResult) -> Result<Vec<MixinOverlapRank>, AnalyticsError> {
    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        if row.len() < 4 {
            return Err(AnalyticsError::MalformedResult);
        }
        out.push(MixinOverlapRank {
            mods: row[0].clone(),
            target: row[1].clone(),
            occurrences: row[2].parse().unwrap_or(0),
            run_count: row[3].parse().unwrap_or(0),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    #[test]
    fn parse_since_accepts_day_and_hour_suffixes() {
        assert_eq!(parse_since("30d").unwrap(), Duration::days(30));
        assert_eq!(parse_since("24h").unwrap(), Duration::hours(24));
        assert!(parse_since("").is_err());
        assert!(parse_since("0d").is_err());
    }

    #[test]
    fn cutoff_is_in_the_past() {
        let duration = parse_since("7d").unwrap();
        let cutoff: DateTime<Utc> = Utc::now() - duration;
        assert!(cutoff < Utc::now());
    }
}