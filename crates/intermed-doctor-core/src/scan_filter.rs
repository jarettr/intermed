//! Shared jar scan filtering for incremental diagnosis (`--changed-since`).

use std::fs;
use std::io;
use std::path::Path;
use std::time::SystemTime;

use crate::settings::ScanSettings;

/// Returns true when `path` should be scanned under `settings`.
///
/// Without `changed_since`, every existing readable path is scanned. With it,
/// only files whose modification time is at or after the cutoff are included.
pub fn should_scan_path(path: &Path, settings: &ScanSettings) -> bool {
    let Some(cutoff) = settings.changed_since else {
        return true;
    };
    match fs::metadata(path) {
        Ok(meta) => meta
            .modified()
            .map(|mtime| mtime >= cutoff)
            .unwrap_or(true),
        Err(_) => false,
    }
}

/// List `.jar` files in `dir`, optionally filtered by `changed_since`.
pub fn list_jar_archives(
    dir: &Path,
    settings: &ScanSettings,
) -> Result<Vec<std::path::PathBuf>, io::Error> {
    let mut jars: Vec<std::path::PathBuf> = fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("jar"))
        })
        .collect();
    jars.sort();
    filter_jar_paths(&mut jars, settings);
    Ok(jars)
}

/// Filter a sorted jar path list in place.
pub fn filter_jar_paths(paths: &mut Vec<std::path::PathBuf>, settings: &ScanSettings) {
    if settings.changed_since.is_none() {
        return;
    }
    paths.retain(|p| should_scan_path(p, settings));
}

/// Parse `--changed-since` values: RFC3339 timestamp or unix seconds.
pub fn parse_changed_since(input: &str) -> Result<SystemTime, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty timestamp".into());
    }
    if let Ok(secs) = trimmed.parse::<u64>() {
        return SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(secs))
            .ok_or_else(|| format!("unix timestamp out of range: {secs}"));
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let dt = date
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| format!("invalid date `{trimmed}`"))?;
        let parsed = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt, chrono::Utc);
        return Ok(SystemTime::UNIX_EPOCH
            + std::time::Duration::new(parsed.timestamp() as u64, parsed.timestamp_subsec_nanos()));
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(trimmed)
        .map_err(|e| format!("invalid RFC3339 timestamp `{trimmed}`: {e}"))?;
    Ok(SystemTime::UNIX_EPOCH
        + std::time::Duration::new(parsed.timestamp() as u64, parsed.timestamp_subsec_nanos()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn parse_unix_and_rfc3339() {
        let t = parse_changed_since("1700000000").expect("unix");
        assert!(t > UNIX_EPOCH);
        let rfc = parse_changed_since("2024-11-14T22:13:20Z").expect("rfc");
        assert!(rfc > UNIX_EPOCH);
        let date = parse_changed_since("2020-01-01").expect("date");
        assert!(date > UNIX_EPOCH);
    }

    #[test]
    fn filter_keeps_recent_files() {
        let dir = std::env::temp_dir().join(format!(
            "intermed-scan-filter-{}",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let old = dir.join("old.jar");
        let new = dir.join("new.jar");
        fs::write(&old, b"old").unwrap();
        fs::write(&new, b"new").unwrap();
        let cutoff = SystemTime::now() - Duration::from_secs(3600);
        let settings = ScanSettings {
            changed_since: Some(cutoff),
        };
        let mut paths = vec![old.clone(), new.clone()];
        filter_jar_paths(&mut paths, &settings);
        assert!(paths.iter().any(|p| p == &new));
        fs::remove_dir_all(dir).ok();
    }
}