//! Lenient semver parsing for Minecraft mod and release versions.
//!
//! Layer C is deliberately conservative: when a version string or range cannot be
//! parsed as semver, callers treat it as undecidable rather than emitting a
//! false positive. Fabric space-separated AND ranges and `||` OR alternatives
//! are normalized before parsing.

use std::cmp::Ordering;

use creeper_semver_pubgrub::SmallVersion;
use serde::{Deserialize, Serialize};

/// Version language declared by the metadata that owns a dependency edge.
///
/// Parsing a version is not enough to select comparison semantics: Cargo-style
/// SemVer, Fabric Loader and Maven ranges intentionally disagree about
/// prereleases and accepted range syntax.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionDialect {
    FabricExtendedSemver,
    Quilt,
    MavenRange,
    #[default]
    GenericSemver,
    Opaque,
}

impl VersionDialect {
    pub fn from_loader(loader: &str) -> Self {
        match loader.trim().to_ascii_lowercase().as_str() {
            "fabric" => Self::FabricExtendedSemver,
            "quilt" => Self::Quilt,
            "forge" | "neoforge" => Self::MavenRange,
            "paper" | "spigot" | "bukkit" | "vanilla" => Self::GenericSemver,
            _ => Self::Opaque,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FabricExtendedSemver => "fabric-extended-semver",
            Self::Quilt => "quilt",
            Self::MavenRange => "maven-range",
            Self::GenericSemver => "generic-semver",
            Self::Opaque => "opaque",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "fabric-extended-semver" => Self::FabricExtendedSemver,
            "quilt" => Self::Quilt,
            "maven-range" => Self::MavenRange,
            "generic-semver" => Self::GenericSemver,
            "opaque" => Self::Opaque,
            _ => return None,
        })
    }

    /// Whether the loader itself defines ordering for a syntactically valid raw
    /// version, even when InterMed's display normalizer marks its numeric groups
    /// as ambiguous (for example `1.20-Fabric-4.0.6`).
    pub fn orders_raw_extended_versions(self) -> bool {
        matches!(self, Self::FabricExtendedSemver | Self::Quilt)
    }
}

/// `Some(true)` satisfied, `Some(false)` violated, `None` when we cannot decide
/// (non-semver version or range, wildcard edge cases). Conservative by design.
pub fn version_in_range(version: &str, range: &str) -> Option<bool> {
    version_in_range_with_dialect(version, range, VersionDialect::GenericSemver)
}

/// Evaluate a version using the comparison language of the declaring manifest.
pub fn version_in_range_with_dialect(
    version: &str,
    range: &str,
    dialect: VersionDialect,
) -> Option<bool> {
    let range = range.trim();
    if range.is_empty() || range == "*" {
        return Some(true);
    }
    match dialect {
        VersionDialect::FabricExtendedSemver | VersionDialect::Quilt => {
            fabric_version_in_range(version, range)
        }
        VersionDialect::MavenRange => maven_version_in_range(version, range),
        VersionDialect::GenericSemver => generic_version_in_range(version, range),
        VersionDialect::Opaque => opaque_version_in_range(version, range),
    }
}

fn generic_version_in_range(version: &str, range: &str) -> Option<bool> {
    let ver = parse_lenient(version)?;
    let reqs = parse_version_reqs(range)?;
    if reqs.is_empty() {
        return None;
    }
    Some(reqs.iter().any(|req| req.matches(&ver)))
}

fn maven_version_in_range(version: &str, range: &str) -> Option<bool> {
    let version = MavenVersion::parse(version)?;
    let range = range.trim();
    if !range.starts_with(['[', '(']) {
        // A bare Forge/NeoForge requirement is treated as an exact constraint in
        // the static model. Maven itself calls this a soft recommendation, but
        // InterMed has no repository selection step in which to apply one.
        let expected = range.strip_prefix('=').unwrap_or(range);
        return Some(version.cmp(&MavenVersion::parse(expected)?) == Ordering::Equal);
    }
    let intervals = split_maven_intervals(range);
    if intervals.is_empty() {
        return None;
    }
    let mut matched = false;
    for interval in intervals {
        matched |= maven_interval_matches(&version, &interval)?;
    }
    Some(matched)
}

#[derive(Debug, Clone)]
struct MavenVersion(Vec<MavenItem>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum MavenItem {
    Number(String),
    Qualifier(String),
    Minus,
}

impl MavenVersion {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty()
            || !raw
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '+'))
        {
            return None;
        }
        let mut items = Vec::new();
        let mut token = String::new();
        let mut numeric = None;
        let flush = |token: &mut String, numeric: Option<bool>, items: &mut Vec<MavenItem>| {
            if token.is_empty() {
                return;
            }
            if numeric == Some(true) {
                let normalized = token.trim_start_matches('0');
                items.push(MavenItem::Number(if normalized.is_empty() {
                    "0".to_string()
                } else {
                    normalized.to_string()
                }));
            } else {
                items.push(MavenItem::Qualifier(normalize_maven_qualifier(token)));
            }
            token.clear();
        };
        for ch in raw.chars() {
            if matches!(ch, '.' | '-' | '_' | '+') {
                flush(&mut token, numeric, &mut items);
                if ch == '-' {
                    items.push(MavenItem::Minus);
                }
                numeric = None;
                continue;
            }
            let is_numeric = ch.is_ascii_digit();
            if numeric.is_some_and(|was_numeric| was_numeric != is_numeric) {
                flush(&mut token, numeric, &mut items);
                items.push(MavenItem::Minus);
            }
            numeric = Some(is_numeric);
            token.push(ch.to_ascii_lowercase());
        }
        flush(&mut token, numeric, &mut items);
        (!items.is_empty()).then_some(Self(items))
    }
}

impl Ord for MavenVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_maven_items(&self.0, &other.0)
    }
}

impl PartialEq for MavenVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for MavenVersion {}

impl PartialOrd for MavenVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn normalize_maven_qualifier(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "a" => "alpha".into(),
        "b" => "beta".into(),
        "m" => "milestone".into(),
        "cr" => "rc".into(),
        "ga" | "final" | "release" => String::new(),
        value => value.to_string(),
    }
}

fn maven_qualifier_key(value: &str) -> (u8, &str) {
    match value {
        "alpha" => (0, ""),
        "beta" => (1, ""),
        "milestone" => (2, ""),
        "rc" => (3, ""),
        "snapshot" => (4, ""),
        "" => (5, ""),
        "sp" => (6, ""),
        // Unknown qualifiers sort after the well-known Maven qualifiers and
        // deterministically among themselves, matching ComparableVersion's
        // `qualifier-<name>` fallback ordering.
        other => (7, other),
    }
}

fn compare_maven_item(left: Option<&MavenItem>, right: Option<&MavenItem>) -> Ordering {
    match (left, right) {
        (Some(MavenItem::Number(a)), Some(MavenItem::Number(b))) => a
            .len()
            .cmp(&b.len())
            .then_with(|| a.as_bytes().cmp(b.as_bytes())),
        (Some(MavenItem::Qualifier(a)), Some(MavenItem::Qualifier(b))) => {
            maven_qualifier_key(a).cmp(&maven_qualifier_key(b))
        }
        (Some(MavenItem::Number(_)), Some(MavenItem::Qualifier(_))) => Ordering::Greater,
        (Some(MavenItem::Qualifier(_)), Some(MavenItem::Number(_))) => Ordering::Less,
        (Some(MavenItem::Minus), Some(MavenItem::Number(_))) => Ordering::Less,
        (Some(MavenItem::Minus), Some(MavenItem::Qualifier(_))) => Ordering::Greater,
        (Some(MavenItem::Number(_)), Some(MavenItem::Minus)) => Ordering::Greater,
        (Some(MavenItem::Qualifier(_)), Some(MavenItem::Minus)) => Ordering::Less,
        (Some(MavenItem::Number(a)), None) => compare_numeric_to_zero(a),
        (None, Some(MavenItem::Number(b))) => compare_numeric_to_zero(b).reverse(),
        (Some(MavenItem::Qualifier(a)), None) => {
            maven_qualifier_key(a).cmp(&maven_qualifier_key(""))
        }
        (None, Some(MavenItem::Qualifier(b))) => {
            maven_qualifier_key("").cmp(&maven_qualifier_key(b))
        }
        (Some(MavenItem::Minus), None) | (None, Some(MavenItem::Minus)) => Ordering::Equal,
        (Some(MavenItem::Minus), Some(MavenItem::Minus)) => Ordering::Equal,
        (None, None) => Ordering::Equal,
    }
}

fn compare_maven_items(left: &[MavenItem], right: &[MavenItem]) -> Ordering {
    let width = left.len().max(right.len());
    for index in 0..width {
        let order = match (left.get(index), right.get(index)) {
            (Some(MavenItem::Minus), Some(MavenItem::Minus)) => {
                compare_maven_items(&left[index + 1..], &right[index + 1..])
            }
            (Some(MavenItem::Minus), None) => compare_maven_items(&left[index + 1..], &[]),
            (None, Some(MavenItem::Minus)) => compare_maven_items(&[], &right[index + 1..]),
            pair => compare_maven_item(pair.0, pair.1),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    Ordering::Equal
}

fn compare_numeric_to_zero(value: &str) -> Ordering {
    if value == "0" {
        Ordering::Equal
    } else {
        Ordering::Greater
    }
}

fn maven_interval_matches(version: &MavenVersion, interval: &str) -> Option<bool> {
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
        .and_then(|value| value.strip_suffix([']', ')']))?;
    if !inner.contains(',') {
        return Some(version == &MavenVersion::parse(inner)?);
    }
    let (lower, upper) = inner.split_once(',')?;
    let lower_matches = if lower.trim().is_empty() {
        true
    } else {
        match version.cmp(&MavenVersion::parse(lower)?) {
            Ordering::Greater => true,
            Ordering::Equal => lower_inclusive,
            Ordering::Less => false,
        }
    };
    let upper_matches = if upper.trim().is_empty() {
        true
    } else {
        match version.cmp(&MavenVersion::parse(upper)?) {
            Ordering::Less => true,
            Ordering::Equal => upper_inclusive,
            Ordering::Greater => false,
        }
    };
    Some(lower_matches && upper_matches)
}

fn opaque_version_in_range(version: &str, range: &str) -> Option<bool> {
    let range = range.trim();
    if range.is_empty() || range == "*" {
        return Some(true);
    }
    let exact = range.strip_prefix('=').unwrap_or(range);
    if exact.starts_with(['<', '>', '^', '~', '[', '(']) || exact.contains(char::is_whitespace) {
        None
    } else {
        Some(version.trim() == exact.trim())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FabricVersion {
    components: Vec<u64>,
    /// `None` is a release; `Some([])` is Fabric's special earliest prerelease.
    prerelease: Option<Vec<FabricPrereleaseId>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FabricPrereleaseId {
    Numeric(u64),
    Text(String),
}

impl Ord for FabricPrereleaseId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.cmp(b),
            (Self::Numeric(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::Text(a), Self::Text(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for FabricPrereleaseId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FabricVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let width = self.components.len().max(other.components.len());
        for index in 0..width {
            let order = self
                .components
                .get(index)
                .copied()
                .unwrap_or(0)
                .cmp(&other.components.get(index).copied().unwrap_or(0));
            if order != Ordering::Equal {
                return order;
            }
        }
        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => compare_prerelease(a, b),
        }
    }
}

impl PartialOrd for FabricVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(a: &[FabricPrereleaseId], b: &[FabricPrereleaseId]) -> Ordering {
    for (left, right) in a.iter().zip(b) {
        let order = left.cmp(right);
        if order != Ordering::Equal {
            return order;
        }
    }
    a.len().cmp(&b.len())
}

fn parse_fabric_version(input: &str) -> Option<FabricVersion> {
    let without_build = input.trim().split('+').next()?.trim();
    let (core, prerelease) = match without_build.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (without_build, None),
    };
    let components: Vec<u64> = core
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<_>>()?;
    if components.is_empty() {
        return None;
    }
    let prerelease = match prerelease {
        None => None,
        Some("") => Some(Vec::new()),
        Some(raw) => Some(
            raw.split('.')
                .map(|part| {
                    if part.is_empty()
                        || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                    {
                        return None;
                    }
                    Some(match part.parse::<u64>() {
                        Ok(value) => FabricPrereleaseId::Numeric(value),
                        Err(_) => FabricPrereleaseId::Text(part.to_string()),
                    })
                })
                .collect::<Option<Vec<_>>>()?,
        ),
    };
    Some(FabricVersion {
        components,
        prerelease,
    })
}

fn fabric_version_in_range(version: &str, range: &str) -> Option<bool> {
    let version = parse_fabric_version(version)?;
    let branches: Vec<&str> = range
        .split("||")
        .map(str::trim)
        .filter(|branch| !branch.is_empty())
        .collect();
    if branches.is_empty() {
        return None;
    }
    let mut saw_valid = false;
    for branch in branches {
        let tokens: Vec<&str> = branch.split_whitespace().collect();
        if tokens.is_empty() {
            return None;
        }
        let matches = tokens
            .iter()
            .map(|token| fabric_token_matches(&version, token))
            .collect::<Option<Vec<_>>>()?;
        saw_valid = true;
        if matches.into_iter().all(|matched| matched) {
            return Some(true);
        }
    }
    saw_valid.then_some(false)
}

fn fabric_token_matches(version: &FabricVersion, token: &str) -> Option<bool> {
    if token == "*" {
        return Some(true);
    }
    if is_fabric_x_range(token) {
        return fabric_x_range_matches(version, token);
    }
    for (prefix, predicate) in [
        (">=", OrderingPredicate::GreaterEqual),
        ("<=", OrderingPredicate::LessEqual),
        (">", OrderingPredicate::Greater),
        ("<", OrderingPredicate::Less),
        ("=", OrderingPredicate::Equal),
    ] {
        if let Some(raw) = token.strip_prefix(prefix) {
            let bound = parse_fabric_version(raw)?;
            return Some(predicate.test(version.cmp(&bound)));
        }
    }
    if let Some(raw) = token.strip_prefix('^') {
        let lower = parse_fabric_version(raw)?;
        let mut upper = FabricVersion {
            components: vec![lower.components.first()?.checked_add(1)?],
            prerelease: Some(Vec::new()),
        };
        upper.components.resize(lower.components.len().max(1), 0);
        return Some(version >= &lower && version < &upper);
    }
    if let Some(raw) = token.strip_prefix('~') {
        let lower = parse_fabric_version(raw)?;
        let mut upper_components = lower.components.clone();
        if upper_components.len() < 2 {
            upper_components.resize(2, 0);
        }
        upper_components[1] = upper_components[1].checked_add(1)?;
        upper_components
            .iter_mut()
            .skip(2)
            .for_each(|part| *part = 0);
        let upper = FabricVersion {
            components: upper_components,
            prerelease: Some(Vec::new()),
        };
        return Some(version >= &lower && version < &upper);
    }
    let exact = parse_fabric_version(token)?;
    Some(version.cmp(&exact) == Ordering::Equal)
}

#[derive(Debug, Clone, Copy)]
enum OrderingPredicate {
    GreaterEqual,
    LessEqual,
    Greater,
    Less,
    Equal,
}

impl OrderingPredicate {
    fn test(self, ordering: Ordering) -> bool {
        match self {
            Self::GreaterEqual => ordering != Ordering::Less,
            Self::LessEqual => ordering != Ordering::Greater,
            Self::Greater => ordering == Ordering::Greater,
            Self::Less => ordering == Ordering::Less,
            Self::Equal => ordering == Ordering::Equal,
        }
    }
}

fn is_fabric_x_range(token: &str) -> bool {
    token.split('.').any(|part| matches!(part, "x" | "X" | "*"))
}

fn fabric_x_range_matches(version: &FabricVersion, token: &str) -> Option<bool> {
    let mut prefix = Vec::new();
    for part in token.split('.') {
        if matches!(part, "x" | "X" | "*") {
            break;
        }
        prefix.push(part.parse::<u64>().ok()?);
    }
    if prefix.is_empty() {
        return Some(true);
    }
    let lower = FabricVersion {
        components: prefix.clone(),
        prerelease: Some(Vec::new()),
    };
    let mut upper_components = prefix;
    let last = upper_components.last_mut()?;
    *last = last.checked_add(1)?;
    let upper = FabricVersion {
        components: upper_components,
        prerelease: Some(Vec::new()),
    };
    Some(version >= &lower && version < &upper)
}

/// Parse a mod version string into a [`SmallVersion`] when semver rules apply.
pub fn parse_mod_version(version: &str) -> Option<SmallVersion> {
    parse_lenient(version).map(SmallVersion::from)
}

/// Parse a generic compatibility range into one or more Cargo-semver
/// requirements (OR-separated).
///
/// This legacy parser accepts space-and-`||` comparator syntax and Maven interval
/// syntax (`[1.0,2.0)`, `[47,)`, `(,3.0]`, `[1.5]`). Loader metadata must use
/// [`version_in_range_with_dialect`] instead, because converting Fabric ranges to
/// `semver::VersionReq` would reintroduce Cargo's prerelease admission rules.
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
    let prefix = prefix.trim_end_matches('.');
    if prefix.is_empty() {
        return None;
    }
    semver::Version::parse(&pad_mc_version(prefix))
        .ok()
        // Many Forge/Bukkit mods carry 4+ numeric segments (`15.20.0.130`,
        // `0.103.0.0`). Strict semver rejects them, which would drop the mod
        // from the graph entirely. Collapse to the leading 3 segments so the
        // mod resolves; ranges practically never discriminate on a 4th segment.
        .or_else(|| semver::Version::parse(&truncate_to_three_segments(prefix)).ok())
}

/// Keep only the leading three dot-separated segments of a numeric version, so a
/// 4+-component build number parses as semver. Returns the input unchanged when
/// it already has three or fewer segments.
fn truncate_to_three_segments(version: &str) -> String {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() <= 3 {
        return version.to_string();
    }
    parts[..3].join(".")
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
    fn four_segment_versions_parse_and_compare() {
        // Real Forge/Bukkit mods (jei `15.20.0.130`, Towny `0.103.0.0`,
        // tconstruct `3.11.2.166`) use 4 numeric segments. They must parse so
        // the mod is not dropped from the dependency graph.
        assert!(parse_mod_version("15.20.0.130").is_some());
        assert!(parse_mod_version("0.103.0.0").is_some());
        assert!(parse_mod_version("3.11.2.166").is_some());
        // The leading 3 segments drive comparison.
        assert_eq!(version_in_range("15.20.0.130", ">=15.20.0"), Some(true));
        assert_eq!(version_in_range("15.20.0.130", ">=15.21.0"), Some(false));
        assert_eq!(version_in_range("0.103.0.0", ">=0.100"), Some(true));
        // The `+build` form already truncated at `+` keeps working.
        assert_eq!(
            version_in_range("6.0.8.1+build.1744-mc1.20.1", ">=6.0.0"),
            Some(true)
        );
    }

    #[test]
    fn adversarial_inputs_never_panic() {
        // Robustness ("fuzz-lite"): malformed/hostile version and range strings
        // must return a value, never panic. Untrusted manifests reach here.
        let nasty = [
            "",
            " ",
            "\u{0}",
            "[",
            "]",
            "(,",
            ",)",
            "[,]",
            "[[[",
            "))))",
            "1.2.3.4.5.6.7",
            "............",
            "1.",
            ".1",
            "->>=",
            "||||",
            "[1.0,",
            "1.0,2.0]",
            "v.v.v",
            "999999999999999999999999999",
            "[1.0,2.0,3.0]",
            "~^>=<=!=",
            "0x10",
            "NaN",
            "\t\n\r",
            "🦀.1.2",
            "1.2.3-+-+",
            "[a,b)",
            "1 2 3",
            "&&||",
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
    fn maven_dialect_uses_maven_qualifiers_and_real_pack_build_versions() {
        let dialect = VersionDialect::MavenRange;
        assert_eq!(
            version_in_range_with_dialect("2001.6.5-build.26", "[2001.6.4-build.120,)", dialect),
            Some(true)
        );
        assert_eq!(
            version_in_range_with_dialect("1.0-rc1", "[1.0-beta,1.0)", dialect),
            Some(true)
        );
        assert_eq!(
            version_in_range_with_dialect("1.0-final", "[1.0,1.0]", dialect),
            Some(true)
        );
        assert_eq!(
            version_in_range_with_dialect("1.0-sp", "(,1.0]", dialect),
            Some(false)
        );
        assert!(MavenVersion::parse("1.0.0-1").unwrap() < MavenVersion::parse("1.0.0.1").unwrap());
        assert_eq!(MavenVersion::parse("1a1"), MavenVersion::parse("1-alpha-1"));
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
    fn fabric_comparators_do_not_apply_cargo_prerelease_filtering() {
        let dialect = VersionDialect::FabricExtendedSemver;
        assert_eq!(
            version_in_range_with_dialect("1.0.2-rc1+1.20", ">=1.0.0", dialect),
            Some(true)
        );
        assert_eq!(
            version_in_range_with_dialect("1.0.2-rc1+1.20", ">=0.9.9", dialect),
            Some(true)
        );
        assert_eq!(
            version_in_range_with_dialect("1.2.19-1.20.1", ">=1.2.6-1.20.1", dialect),
            Some(true)
        );
        assert_eq!(
            version_in_range_with_dialect("1.2.19-1.20.1", ">=1.1.8", dialect),
            Some(true)
        );
        // Build metadata is irrelevant, and missing numeric components are zero.
        assert_eq!(
            version_in_range_with_dialect("1.2+mc1", "=1.2.0+mc2", dialect),
            Some(true)
        );
        // A prerelease is still lower than the release with the same core.
        assert_eq!(
            version_in_range_with_dialect("1.0.0-rc1", ">=1.0.0", dialect),
            Some(false)
        );
    }

    #[test]
    fn fabric_extended_ranges_cover_caret_tilde_x_and_prereleases() {
        let dialect = VersionDialect::FabricExtendedSemver;
        assert_eq!(
            version_in_range_with_dialect("0.9.0", "^0.8.0", dialect),
            Some(true),
            "Fabric caret does not special-case major zero"
        );
        assert_eq!(
            version_in_range_with_dialect("1.2.9", "~1.2.3", dialect),
            Some(true)
        );
        assert_eq!(
            version_in_range_with_dialect("2.0.0-beta.1", "2.x", dialect),
            Some(true)
        );
        assert_eq!(
            version_in_range_with_dialect("1.0.2-rc1", ">1.0.1 <1.0.2", dialect),
            Some(true)
        );
    }

    #[test]
    fn dialect_selection_changes_the_known_prerelease_case() {
        assert_eq!(
            version_in_range_with_dialect(
                "1.0.2-rc1+1.20",
                ">=1.0.0",
                VersionDialect::FabricExtendedSemver
            ),
            Some(true)
        );
        assert_eq!(
            version_in_range_with_dialect(
                "1.0.2-rc1+1.20",
                ">=1.0.0",
                VersionDialect::GenericSemver
            ),
            Some(false)
        );
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
        assert_eq!(
            parse_lenient("1.20.1-forge").unwrap().to_string(),
            "1.20.1-forge"
        );
        assert_eq!(parse_lenient("2.4_fabric").unwrap().to_string(), "2.4.0");
    }
}
