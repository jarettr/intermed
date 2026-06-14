//! Lenient semver parsing for Minecraft mod and release versions.
//!
//! Layer C is deliberately conservative: when a version string or range cannot be
//! parsed as semver, callers treat it as undecidable rather than emitting a
//! false positive. Fabric space-separated AND ranges and `||` OR alternatives
//! are normalized before parsing.

use creeper_semver_pubgrub::SmallVersion;

/// `Some(true)` satisfied, `Some(false)` violated, `None` when we cannot decide
/// (non-semver version or range, wildcard edge cases). Conservative by design.
pub fn version_in_range(version: &str, range: &str) -> Option<bool> {
    let range = range.trim();
    if range.is_empty() || range == "*" {
        return Some(true);
    }
    let ver = parse_lenient(version)?;
    let reqs = parse_version_reqs(range)?;
    if reqs.is_empty() {
        return None;
    }
    Some(reqs.iter().any(|req| req.matches(&ver)))
}

/// Parse a mod version string into a [`SmallVersion`] when semver rules apply.
pub fn parse_mod_version(version: &str) -> Option<SmallVersion> {
    parse_lenient(version).map(SmallVersion::from)
}

/// Parse a metadata range into one or more semver requirements (OR-separated).
///
/// Two range dialects are supported: Fabric/Quilt space-and-`||` comparator
/// syntax, and Forge/NeoForge **Maven version intervals** (`[1.0,2.0)`, `[47,)`,
/// `(,3.0]`, `[1.5]`). The two are disambiguated by syntax — only Maven uses
/// brackets — so a Forge `[47,)` is now range-checked instead of dropped as
/// undecidable.
pub fn parse_version_reqs(range: &str) -> Option<Vec<semver::VersionReq>> {
    let trimmed = range.trim();
    if trimmed.starts_with('[') || trimmed.starts_with('(') {
        return parse_maven_ranges(trimmed);
    }
    let normalized = normalize_fabric_range(range);
    let parts: Vec<Option<semver::VersionReq>> = normalized
        .split("||")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(normalize_comparators)
        .map(|part| semver::VersionReq::parse(&part).ok())
        .collect();
    if parts.iter().any(|part| part.is_none()) {
        return None;
    }
    Some(parts.into_iter().flatten().collect())
}

/// Parse one or more Maven version intervals (comma-joined at the top level, e.g.
/// `[1.0,2.0),[3.0,)`) into an OR of semver requirements.
fn parse_maven_ranges(range: &str) -> Option<Vec<semver::VersionReq>> {
    let mut reqs = Vec::new();
    for interval in split_maven_intervals(range) {
        reqs.push(maven_interval_to_req(&interval)?);
    }
    (!reqs.is_empty()).then_some(reqs)
}

/// Split top-level `,`-joined Maven intervals while keeping each `[...]`/`(...)`
/// group intact (the comma *inside* a bracket is the lower/upper separator).
fn split_maven_intervals(range: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in range.chars() {
        match c {
            '[' | '(' => {
                depth += 1;
                cur.push(c);
            }
            ']' | ')' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth == 0 => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Convert a single Maven interval to a semver [`VersionReq`].
fn maven_interval_to_req(interval: &str) -> Option<semver::VersionReq> {
    // Strip exactly one bracket on each side, char-boundary-safe (an interval may
    // contain multi-byte garbage, and `[` alone must not slice out of range).
    let lower_inclusive = interval.starts_with('[');
    if !lower_inclusive && !interval.starts_with('(') {
        return None;
    }
    let upper_inclusive = interval.ends_with(']');
    if !upper_inclusive && !interval.ends_with(')') {
        return None;
    }
    let inner = interval
        .strip_prefix(['[', '('])
        .and_then(|s| s.strip_suffix([']', ')']))?;

    // `[1.5]` (no comma) is an exact pin.
    if !inner.contains(',') {
        let v = pad_mc_version(inner.trim());
        return semver::VersionReq::parse(&format!("={v}")).ok();
    }
    let (lo, hi) = inner.split_once(',')?;
    let (lo, hi) = (lo.trim(), hi.trim());
    let mut comparators = Vec::new();
    if !lo.is_empty() {
        let op = if lower_inclusive { ">=" } else { ">" };
        comparators.push(format!("{op}{}", pad_mc_version(lo)));
    }
    if !hi.is_empty() {
        let op = if upper_inclusive { "<=" } else { "<" };
        comparators.push(format!("{op}{}", pad_mc_version(hi)));
    }
    if comparators.is_empty() {
        // `(,)` — unbounded both ways = any version.
        return semver::VersionReq::parse("*").ok();
    }
    semver::VersionReq::parse(&comparators.join(", ")).ok()
}

/// Fabric ranges use space-separated AND (`>=0.11.6 <0.12.0`); semver wants commas.
/// OR alternatives use `||` in both ecosystems once normalized.
fn normalize_fabric_range(range: &str) -> String {
    range.trim().to_string()
}

/// Turn one Fabric/semver comparator token into comma-separated semver syntax,
/// padding bare MC release versions (`1.20` → `1.20.0`) before parsing.
fn normalize_comparators(part: &str) -> String {
    part.split_whitespace()
        .map(normalize_range_token)
        .collect::<Vec<_>>()
        .join(", ")
}

fn normalize_range_token(token: &str) -> String {
    let token = token.trim();
    for (prefix, op) in [
        (">=", ">="),
        ("<=", "<="),
        ("!=", "!="),
        (">", ">"),
        ("<", "<"),
    ] {
        if let Some(rest) = token.strip_prefix(prefix) {
            return format!("{op}{}", pad_mc_version(rest));
        }
    }
    if let Some(rest) = token.strip_prefix('=') {
        return format!("={}", pad_mc_version(rest));
    }
    pad_mc_version(token)
}

/// Mod versions frequently carry build metadata like `0.5.3+1.20.1`; strip a
/// trailing `+...` and parse the leading semver. MC release versions like `1.20`
/// are padded to `1.20.0`. Snapshot ids (`23w31a`) remain undecidable.
pub fn parse_lenient(version: &str) -> Option<semver::Version> {
    if is_mc_snapshot(version) {
        return None;
    }
    let trimmed = version.trim().trim_start_matches(['v', 'V']);
    let core = trimmed.split('+').next().unwrap_or(trimmed).trim();
    if let Ok(v) = semver::Version::parse(core) {
        return Some(v);
    }
    if let Ok(v) = semver::Version::parse(&pad_mc_version(core)) {
        return Some(v);
    }
    // Common mod builds append loader/MC labels with `_` or `-`. Prefer the
    // longest numeric dotted prefix and keep undecidable strings conservative.
    let prefix: String = core
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if prefix.is_empty() {
        return None;
    }
    semver::Version::parse(&pad_mc_version(prefix.trim_end_matches('.'))).ok()
}

/// Pad two-component Minecraft release versions so `1.20` matches `>=1.20.0`.
/// Snapshot ids (`23w31a`) are returned unchanged and remain undecidable.
fn pad_mc_version(version: &str) -> String {
    let version = version.trim();
    if is_mc_snapshot(version) {
        return version.to_string();
    }
    let parts: Vec<&str> = version.split('.').collect();
    match parts.len() {
        1 if parts[0].chars().all(|c| c.is_ascii_digit()) => {
            format!("{}.0.0", parts[0])
        }
        2 if parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())) => {
            format!("{}.{}.0", parts[0], parts[1])
        }
        _ => version.to_string(),
    }
}

fn is_mc_snapshot(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    lower.contains('w') && lower.chars().any(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_semantics() {
        assert_eq!(version_in_range("1.2.3", "*"), Some(true));
        assert_eq!(version_in_range("1.2.3", ">=1.0.0"), Some(true));
        assert_eq!(version_in_range("0.9.0", ">=1.0.0"), Some(false));
        assert_eq!(version_in_range("0.5.3+1.20.1", ">=0.5.0"), Some(true));
        assert_eq!(version_in_range("mc1.20.1-x", ">=1.0.0"), None);
    }

    #[test]
    fn adversarial_inputs_never_panic() {
        // Robustness ("fuzz-lite"): malformed/hostile version and range strings
        // must return a value, never panic. Untrusted manifests reach here.
        let nasty = [
            "", " ", "\u{0}", "[", "]", "(,", ",)", "[,]", "[[[", "))))",
            "1.2.3.4.5.6.7", "............", "1.", ".1", "->>=", "||||",
            "[1.0,", "1.0,2.0]", "v.v.v", "999999999999999999999999999",
            "[1.0,2.0,3.0]", "~^>=<=!=", "0x10", "NaN", "\t\n\r",
            "🦀.1.2", "1.2.3-+-+", "[a,b)", "1 2 3", "&&||",
        ];
        for v in nasty {
            for r in nasty {
                // The only contract: it returns (Some/None) without unwinding.
                let _ = version_in_range(v, r);
                let _ = parse_version_reqs(r);
                let _ = parse_lenient(v);
            }
        }
    }

    #[test]
    fn maven_intervals_parse() {
        // Forge/NeoForge style intervals.
        assert_eq!(version_in_range("47.2.0", "[47,)"), Some(true));
        assert_eq!(version_in_range("46.0.0", "[47,)"), Some(false));
        assert_eq!(version_in_range("1.5.0", "[1.0,2.0)"), Some(true));
        assert_eq!(version_in_range("2.0.0", "[1.0,2.0)"), Some(false));
        assert_eq!(version_in_range("2.0.0", "[1.0,2.0]"), Some(true));
        assert_eq!(version_in_range("3.0.0", "(,3.0]"), Some(true));
        assert_eq!(version_in_range("3.0.1", "(,3.0]"), Some(false));
        // Exact pin and multi-interval union.
        assert_eq!(version_in_range("1.5.0", "[1.5]"), Some(true));
        assert_eq!(version_in_range("1.6.0", "[1.5]"), Some(false));
        assert_eq!(version_in_range("3.1.0", "[1.0,2.0),[3.0,)"), Some(true));
        assert_eq!(version_in_range("2.5.0", "[1.0,2.0),[3.0,)"), Some(false));
    }

    #[test]
    fn mc_two_component_versions_match() {
        assert_eq!(version_in_range("1.20", ">=1.20"), Some(true));
        assert_eq!(version_in_range("1.19", ">=1.20"), Some(false));
        assert_eq!(version_in_range("1.21.1", ">=1.21"), Some(true));
    }

    #[test]
    fn fabric_space_separated_ranges_parse() {
        assert_eq!(version_in_range("0.11.7", ">=0.11.6 <0.12.0"), Some(true));
        assert_eq!(version_in_range("0.12.0", ">=0.11.6 <0.12.0"), Some(false));
        assert_eq!(version_in_range("0.11.5", ">=0.11.6 <0.12.0"), Some(false));
    }

    #[test]
    fn fabric_or_ranges_parse() {
        assert_eq!(version_in_range("1.0.0", ">=1.0.0 || >=2.0.0"), Some(true));
        assert_eq!(version_in_range("2.1.0", ">=1.0.0 || >=2.0.0"), Some(true));
        assert_eq!(version_in_range("1.5.0", ">=2.0.0 || >=3.0.0"), Some(false));
    }

    #[test]
    fn snapshots_are_undecidable() {
        assert_eq!(version_in_range("23w31a", ">=1.20"), None);
    }

    #[test]
    fn common_non_strict_mod_versions_parse() {
        assert_eq!(parse_lenient("v1.2.3").unwrap().to_string(), "1.2.3");
        assert_eq!(parse_lenient("1.20.1-forge").unwrap().to_string(), "1.20.1-forge");
        assert_eq!(parse_lenient("2.4_fabric").unwrap().to_string(), "2.4.0");
    }
}
