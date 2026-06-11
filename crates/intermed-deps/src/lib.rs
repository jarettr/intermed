//! # intermed-deps
//!
//! Layer C — dependency / version reasoning over metadata facts.
//!
//! Per the design doc this starts as a *simple imperative resolver*; adopting
//! the `pubgrub` crate (the canonical Rust port of the algorithm the old
//! `PubGrubResolver` implemented) is deferred to a later phase. Phase 1 detects
//! the high-value cases — missing mandatory dependencies, version mismatches,
//! and Minecraft-version mismatches — and is deliberately conservative: when a
//! version string or range is not standard semver it reports nothing rather
//! than a false positive.

use std::collections::{HashMap, HashSet};

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::kind;
use intermed_doctor_core::{Rule, RuleCtx};

/// Pseudo-dependencies that name the platform, not an installable mod.
const PLATFORM_IDS: &[&str] = &[
    "minecraft",
    "java",
    "fabricloader",
    "fabric-loader",
    "quilt_loader",
    "quilt_base",
    "minecraft_quilt_loader",
    "forge",
    "neoforge",
];

pub struct DependencyRule;

impl Rule for DependencyRule {
    fn id(&self) -> &'static str {
        "dependency"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let store = ctx.store;

        // Installed id -> version, plus virtual ids satisfied via `provides`.
        let mut installed: HashMap<String, String> = HashMap::new();
        for f in store.by_kind(kind::MOD).chain(store.by_kind(kind::PLUGIN)) {
            installed.insert(
                f.subject.clone(),
                f.attr("version").unwrap_or("0").to_string(),
            );
        }
        let mut provided: HashSet<String> = HashSet::new();
        for f in store.by_kind(kind::PROVIDED_DEPENDENCY) {
            if let Some(p) = f.attr("provides") {
                provided.insert(p.to_string());
            }
        }

        let mc_version = store
            .by_kind(kind::ENVIRONMENT)
            .next()
            .and_then(|f| f.attr("mc_version").map(str::to_string));

        let mut out = Vec::new();
        for dep in store.by_kind(kind::DEPENDENCY) {
            let modid = dep.subject.as_str();
            let dep_id = dep.attr("dep").unwrap_or("");
            let range = dep.attr("range").unwrap_or("*");
            let mandatory = dep.attr_bool("mandatory").unwrap_or(true);

            // Minecraft version is checked against the detected environment.
            if dep_id == "minecraft" {
                if let Some(mc) = &mc_version {
                    if matches!(version_in_range(mc, range), Some(false)) {
                        out.push(
                            Finding::builder(self.id(), format!("wrong-mc-version:{modid}"))
                                .severity(Severity::Warn)
                                .category(Category::Dependency)
                                .title(format!("{modid} targets a different Minecraft version"))
                                .explanation(format!(
                                    "{modid} requires Minecraft {range}, but the instance is {mc}."
                                ))
                                .evidence(EvidenceEdge::subject(dep.id))
                                .affects(modid)
                                .tag("dependency")
                                .tag("minecraft-version")
                                .build(),
                        );
                    }
                }
                continue;
            }

            if PLATFORM_IDS.contains(&dep_id) {
                continue; // loader/runtime pseudo-deps: not installable mods
            }

            let satisfied_by_provide = provided.contains(dep_id);
            match installed.get(dep_id) {
                None if mandatory && !satisfied_by_provide => {
                    out.push(
                        Finding::builder(
                            self.id(),
                            format!("missing-dependency:{modid}->{dep_id}"),
                        )
                        .severity(Severity::Error)
                        .category(Category::Dependency)
                        .title(format!("Missing dependency: {dep_id}"))
                        .explanation(format!(
                            "{modid} requires {dep_id} ({range}), but it is not installed."
                        ))
                        .evidence(EvidenceEdge::subject(dep.id))
                        .affects(modid)
                        .fix(FixCandidate::advice(format!(
                            "Install {dep_id} matching {range}."
                        )))
                        .tag("dependency")
                        .tag("missing")
                        .build(),
                    );
                }
                Some(installed_ver) => {
                    if matches!(version_in_range(installed_ver, range), Some(false)) {
                        out.push(
                            Finding::builder(
                                self.id(),
                                format!("wrong-version:{modid}->{dep_id}"),
                            )
                            .severity(Severity::Error)
                            .category(Category::Dependency)
                            .title(format!("Incompatible version of {dep_id}"))
                            .explanation(format!(
                                "{modid} requires {dep_id} {range}, but {installed_ver} is installed."
                            ))
                            .evidence(EvidenceEdge::subject(dep.id))
                            .affects(modid)
                            .affects(dep_id)
                            .fix(FixCandidate::advice(format!(
                                "Install {dep_id} at a version matching {range}."
                            )))
                            .tag("dependency")
                            .tag("version-mismatch")
                            .build(),
                        );
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// `Some(true)` satisfied, `Some(false)` violated, `None` when we cannot decide
/// (non-semver version or range, wildcard). Conservative by design.
fn version_in_range(version: &str, range: &str) -> Option<bool> {
    let range = range.trim();
    if range.is_empty() || range == "*" {
        return Some(true);
    }
    let req = semver::VersionReq::parse(range).ok()?;
    let ver = parse_lenient(version)?;
    Some(req.matches(&ver))
}

/// Mod versions frequently carry build metadata like `0.5.3+1.20.1`; strip a
/// trailing `+...` and parse the leading semver. Returns `None` if still not
/// parseable (e.g. `mc1.20.1-x`), which makes the caller skip the check.
fn parse_lenient(version: &str) -> Option<semver::Version> {
    if let Ok(v) = semver::Version::parse(version) {
        return Some(v);
    }
    let core = version.split('+').next().unwrap_or(version);
    semver::Version::parse(core).ok()
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
        // Non-semver → undecidable (no false positive).
        assert_eq!(version_in_range("mc1.20.1-x", ">=1.0.0"), None);
        assert_eq!(version_in_range("1.0.0", "[47,)"), None);
    }
}
