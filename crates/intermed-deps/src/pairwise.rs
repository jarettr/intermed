//! Pairwise dependency checks (Phase 1 semantics) over fact snapshots.

use std::collections::{HashMap, HashSet};

use intermed_doctor_core::RuleCtx;
use intermed_doctor_core::evidence::{
    Category, ConclusionKind, CoverageRequirement, EvidenceEdge, EvidenceOrigin, Finding,
    FixCandidate, Impact, ProofKind, Severity,
};
use intermed_doctor_core::facts::{FactId, kind};

use crate::graph::{is_platform_dep, platform_loader_family};
use crate::model::{ConstraintApplicability, ProviderResolution, ResolvedDependencyModel};
use crate::relation::DependencyRelation;
use crate::semver::{VersionDialect, version_in_range_with_dialect};

fn canonical_artifact_token(value: &str) -> String {
    let prefix: String = value
        .chars()
        .take_while(|ch| !ch.is_ascii_digit())
        .collect();
    let prefix = prefix
        .trim_end_matches(['-', '_', '.', ' '])
        .trim_end_matches(['v', 'V'])
        .trim_end_matches(['-', '_', '.', ' ']);
    prefix
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn plausible_artifact_for<'a>(
    dep_id: &str,
    artifacts: &'a [(String, FactId)],
) -> Option<&'a (String, FactId)> {
    let wanted: String = dep_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    (wanted.len() >= 4)
        .then(|| {
            artifacts
                .iter()
                .find(|(name, _)| canonical_artifact_token(name) == wanted)
        })
        .flatten()
}

/// A dependency `provides` declaration (e.g. a Jar-in-Jar bundled library, or a
/// mod that advertises an alias id), carrying the declared version when known so
/// the resolver can range-check it instead of treating any provider as a match.
#[cfg(test)]
struct ProviderEntry {
    version: Option<String>,
    version_ambiguous: bool,
    fact: FactId,
    /// Visibility scope: `classpath` (Jar-in-Jar), `metadata-alias` (a declared
    /// `provides` id), or `global` (default). Recorded for explanation; in
    /// Minecraft both nested jars and aliases are globally visible, so scope does
    /// not change satisfaction — only the wording/confidence of provider notes.
    scope: String,
    /// Whether both the provider identity and its activation are established.
    /// Plausible nested/opaque artifacts prevent a definite absence assertion
    /// but cannot satisfy a dependency as hard truth.
    confirmed: bool,
}

/// Outcome of checking the set of providers for a dependency id against a range.
enum ProviderStatus {
    /// At least one provider declares a version inside the range.
    Satisfied,
    /// Providers exist and all *known* versions fall outside the range
    /// (`fact`, provider `scope`).
    Unsatisfied(FactId, String),
    /// A provider exists but its version is missing/unparseable — can't range-check.
    Unknown(FactId, String),
    /// No provider declares this id at all.
    Absent,
}

#[cfg(test)]
fn provider_status(
    providers: Option<&Vec<ProviderEntry>>,
    range: &str,
    dialect: VersionDialect,
) -> ProviderStatus {
    let Some(providers) = providers.filter(|p| !p.is_empty()) else {
        return ProviderStatus::Absent;
    };
    let mut unknown: Option<&ProviderEntry> = None;
    let mut out_of_range: Option<&ProviderEntry> = None;
    for p in providers {
        if !p.confirmed {
            unknown.get_or_insert(p);
            continue;
        }
        if p.version_ambiguous && !dialect.orders_raw_extended_versions() {
            unknown.get_or_insert(p);
            continue;
        }
        match &p.version {
            Some(v) => match version_in_range_with_dialect(v, range, dialect) {
                Some(true) => return ProviderStatus::Satisfied,
                Some(false) => {
                    out_of_range.get_or_insert(p);
                }
                None => {
                    unknown.get_or_insert(p);
                }
            },
            None => {
                unknown.get_or_insert(p);
            }
        };
    }
    // A single unresolved provider keeps the universe undecidable: it may be the
    // satisfying provider. `Unsatisfied` is sound only when every provider has a
    // known version and every one is outside the range.
    match (out_of_range, unknown) {
        (_, Some(p)) => ProviderStatus::Unknown(p.fact, p.scope.clone()),
        (Some(p), None) => ProviderStatus::Unsatisfied(p.fact, p.scope.clone()),
        (None, None) => ProviderStatus::Absent,
    }
}

/// How a set of installed versions relates to a requested range.
enum RangeStatus {
    /// No copy of the id is installed.
    Absent,
    /// At least one installed version satisfies the range.
    InRange,
    /// Versions are installed but all parse as outside the range.
    OutOfRange,
    /// Installed, but the range/version could not be parsed — undecidable.
    Undecidable,
}

/// Classify the installed versions of an id against a range. A pack may install
/// the *same id twice* (a real, separate error surfaced by `duplicate-id`); when
/// it does, dependency reasoning here is intentionally lenient — *any* installed
/// version satisfying the range counts, so a version check never adds a second,
/// derived error on top of an already-ambiguous install state.
fn range_status(
    versions: &[String],
    range: &str,
    version_ambiguous: bool,
    dialect: VersionDialect,
) -> RangeStatus {
    if versions.is_empty() {
        return RangeStatus::Absent;
    }
    if version_ambiguous && !dialect.orders_raw_extended_versions() {
        return RangeStatus::Undecidable;
    }
    let mut any_undecidable = false;
    for v in versions {
        match version_in_range_with_dialect(v, range, dialect) {
            Some(true) => return RangeStatus::InRange,
            Some(false) => {}
            None => any_undecidable = true,
        }
    }
    if any_undecidable {
        RangeStatus::Undecidable
    } else {
        RangeStatus::OutOfRange
    }
}

/// Ordering hints (`loadbefore`/`loadafter`) declare *sequencing if present*, not a
/// requirement — they must never become "missing dependency" findings. The
/// dedicated ordering rule consults the installed set for real cycles.
fn is_ordering_relation(relation: &str) -> bool {
    DependencyRelation::parse(relation).is_ordering()
}

/// Evaluate direct missing / version / Minecraft constraints without PubGrub.
pub fn pairwise_findings(ctx: &RuleCtx<'_>, rule_id: &str) -> Vec<Finding> {
    let store = ctx.store;
    let model = ResolvedDependencyModel::from_store(store);

    // All installed versions per id (a duplicated id keeps every version, so a
    // version check stays correct instead of silently picking one copy).
    let mut installed: HashMap<String, Vec<String>> = HashMap::new();
    for package in model.confirmed_packages() {
        installed
            .entry(package.id.clone())
            .or_default()
            .push(package.version.clone().unwrap_or_else(|| "0".to_string()));
    }
    let ambiguous_versions: HashSet<String> = store
        .by_kind(kind::MOD_METADATA)
        .filter(|fact| fact.attr_bool("version_ambiguous").unwrap_or(false))
        .map(|fact| fact.subject.to_string())
        .collect();
    let loader_by_mod: HashMap<String, String> = model
        .confirmed_packages()
        .filter_map(|package| {
            package
                .loader
                .clone()
                .map(|loader| (package.id.clone(), loader))
        })
        .collect();
    let installed_versions = |id: &str| installed.get(id).map(Vec::as_slice).unwrap_or(&[]);
    let is_duplicated = |id: &str| installed.get(id).is_some_and(|v| v.len() > 1);
    // Physical archives whose loader identity could not be confirmed are not
    // installed providers, but they are important counter-evidence to a claim of
    // definite absence. Keep them as a separate plausible state.
    let mut plausible_artifacts: Vec<(String, FactId)> = store
        .by_kind(kind::CHECKSUM)
        .filter(|fact| fact.attr("input_kind") != Some("runtime-log"))
        .map(|fact| (fact.subject.to_string(), fact.id))
        .collect();
    plausible_artifacts.extend(
        store
            .by_kind(kind::MOD)
            .filter(|fact| {
                fact.attr("identity_certainty")
                    .is_some_and(|certainty| certainty != "confirmed")
            })
            .filter_map(|fact| fact.attr("file").map(|file| (file.to_string(), fact.id))),
    );

    let mc_version = model.environment.minecraft_version.clone();
    let env_loader = model.environment.loader.clone();
    let env_loader_version = model.environment.loader_version.clone();
    let java_version = model.environment.java_version.clone();
    let applicability_by_fact = model
        .constraints
        .iter()
        .map(|constraint| (constraint.fact_id, constraint.applicability))
        .collect::<HashMap<_, _>>();

    let mut out = Vec::new();
    for dep in store.by_kind(kind::DEPENDENCY) {
        let modid = dep.subject.as_str();
        let dep_id = dep.attr("dep").unwrap_or("");
        let range = dep.attr("range").unwrap_or("*");
        let mandatory = dep.attr_bool("mandatory").unwrap_or(true);
        let relation = dep.attr("relation").unwrap_or("depends");
        let relation_kind = DependencyRelation::parse(relation);

        // Feature/condition activation is target configuration, not an always-on
        // package constraint. Until an authoritative enabled-feature model says
        // otherwise, retain it as context and never turn it into a hard result.
        if dep.attr("feature").is_some()
            || dep.attr("condition").is_some()
            || dep.attr("side").is_some()
                && applicability_by_fact.get(&dep.id) != Some(&ConstraintApplicability::Active)
        {
            continue;
        }

        if let Some(certainty) = dep
            .attr("identity_certainty")
            .filter(|certainty| *certainty != "confirmed")
        {
            if mandatory && !is_platform_dep(dep_id) && !is_ordering_relation(relation) {
                let cross_loader = certainty == "cross-loader-unresolved";
                out.push(
                    Finding::builder(
                        rule_id,
                        format!(
                            "{}:{modid}->{dep_id}",
                            if cross_loader {
                                "dependency-cross-loader-inactive"
                            } else {
                                "dependency-identity-undecidable"
                            }
                        ),
                    )
                    .family(if cross_loader {
                        "dependency-cross-loader-inactive"
                    } else {
                        "dependency-identity-undecidable"
                    })
                    .severity(Severity::Note)
                    .proof_kind(ProofKind::DeterministicDerivation)
                    .confidence(0.35)
                    .category(Category::Dependency)
                    .title(if cross_loader {
                        format!("Inactive cross-loader descriptor for {modid}")
                    } else {
                        format!("Cannot select the active descriptor for {modid}")
                    })
                    .explanation(if cross_loader {
                        format!(
                            "A descriptor for a different loader says {modid} requires {dep_id} \
                             ({range}). The authoritative target loader does not activate that \
                             descriptor, and no proven runtime bridge makes its dependency \
                             assertion hard truth."
                        )
                    } else {
                        format!(
                            "One descriptor candidate says {modid} requires {dep_id} ({range}), \
                             but the archive's active identity is undecidable. The assertion is \
                             retained as context, not treated as a confirmed missing or \
                             incompatible dependency."
                        )
                    })
                    .evidence(EvidenceEdge::subject(dep.id))
                    .affects(modid)
                    .affects(dep_id)
                    .tag("dependency")
                    .tag(if cross_loader {
                        "cross-loader-inactive"
                    } else {
                        "undecidable-identity"
                    })
                    .build(),
                );
            }
            continue;
        }
        let dialect = dep
            .attr("version_dialect")
            .and_then(VersionDialect::parse)
            .or_else(|| {
                loader_by_mod
                    .get(modid)
                    .map(|loader| VersionDialect::from_loader(loader))
            })
            .unwrap_or(VersionDialect::GenericSemver);

        // Ordering hints are never requirements — handled by the ordering rule.
        if is_ordering_relation(relation) {
            continue;
        }

        if matches!(relation_kind, DependencyRelation::Breaks) {
            if is_platform_dep(dep_id) {
                continue;
            }
            let installed_desc = model.confirmed_versions(dep_id).join(", ");
            match model.provider_resolution(dep_id, range, dialect) {
                // Absent / out of the break range: compatible, stay silent.
                ProviderResolution::Absent | ProviderResolution::Unsatisfied { .. } => {}
                // An installed version really falls inside the declared break
                // range: a genuine, actionable incompatibility.
                ProviderResolution::Satisfied { .. } => out.push(
                    Finding::builder(rule_id, format!("incompatible-mod:{modid}->{dep_id}"))
                        .family("incompatible-mod")
                        .coverage_requirement(CoverageRequirement::LocalArtifact)
                        .coverage_requirement(CoverageRequirement::ActiveDescriptor)
                        .proof_kind(ProofKind::DeterministicDerivation)
                        .impact(Impact::StartupBlocking)
                        .evidence_origin(EvidenceOrigin::StaticExact)
                        .severity(Severity::Error)
                        .category(Category::Dependency)
                        .title(format!("Incompatible with installed mod: {dep_id}"))
                        .explanation(format!(
                            "{modid} breaks {dep_id} ({range}); installed version is {installed_desc}."
                        ))
                        .evidence(EvidenceEdge::subject(dep.id))
                        .affects(modid)
                        .affects(dep_id)
                        .fix(FixCandidate::advice(format!(
                            "Remove {modid} or change the installed version of {dep_id}."
                        )))
                        .tag("dependency")
                        .tag("breaks")
                        .build(),
                ),
                // Range/version unparseable — never a hard "remove one" ERROR.
                ProviderResolution::Unknown { evidence } => out.push(
                    Finding::builder(
                        rule_id,
                        format!("declared-incompatible-undecidable:{modid}->{dep_id}"),
                    )
                    .severity(Severity::Warn)
                    .confidence(0.4)
                    .category(Category::Dependency)
                    .title(format!("Declared incompatibility with {dep_id} (range undecidable)"))
                    .explanation(format!(
                        "{modid} declares it breaks {dep_id} ({range}); installed version is \
                         {installed_desc}, but the range or version could not be parsed, so the \
                         incompatibility cannot be confirmed."
                    ))
                    .evidence(EvidenceEdge::subject(dep.id))
                    .evidence(EvidenceEdge::supports(evidence))
                    .affects(modid)
                    .affects(dep_id)
                    .fix(FixCandidate::advice(format!(
                        "Manually check whether {dep_id} ({installed_desc}) falls in {range}."
                    )))
                    .tag("dependency")
                    .tag("breaks")
                    .tag("undecidable-range")
                    .build(),
                ),
            }
            continue;
        }

        // Fabric `conflicts` is negative but soft: a matching installed provider
        // produces a warning, while an unresolved provider remains explain-only.
        if matches!(relation_kind, DependencyRelation::Conflicts) {
            if is_platform_dep(dep_id) {
                continue;
            }
            match model.provider_resolution(dep_id, range, dialect) {
                ProviderResolution::Satisfied { evidence } => out.push(
                    Finding::builder(rule_id, format!("conflicting-mod:{modid}->{dep_id}"))
                        .family("conflicting-mod")
                        .severity(Severity::Warn)
                        .confidence(0.9)
                        .category(Category::Dependency)
                        .title(format!("Soft conflict with installed mod: {dep_id}"))
                        .explanation(format!(
                            "{modid} declares a soft conflict with {dep_id} {range}. Fabric can \
                             continue loading, but the mod author expects degraded or incorrect behaviour."
                        ))
                        .evidence(EvidenceEdge::subject(dep.id))
                        .evidence(EvidenceEdge::supports(evidence))
                        .affects(modid)
                        .affects(dep_id)
                        .tag("dependency")
                        .tag("conflicts")
                        .build(),
                ),
                ProviderResolution::Unknown { evidence } => out.push(
                    Finding::builder(
                        rule_id,
                        format!("conflicting-mod-undecidable:{modid}->{dep_id}"),
                    )
                    .severity(Severity::Note)
                    .confidence(0.4)
                    .category(Category::Dependency)
                    .title(format!("Cannot verify declared conflict with {dep_id}"))
                    .explanation(format!(
                        "{modid} declares a soft conflict with {dep_id} {range}, but provider \
                         identity or version evidence is incomplete."
                    ))
                    .evidence(EvidenceEdge::subject(dep.id))
                    .evidence(EvidenceEdge::supports(evidence))
                    .affects(modid)
                    .affects(dep_id)
                    .tag("dependency")
                    .tag("conflicts")
                    .tag("undecidable")
                    .build(),
                ),
                ProviderResolution::Unsatisfied { .. } | ProviderResolution::Absent => {}
            }
            continue;
        }

        // NeoForge `type = "discouraged"`: compatible load, but the author warns
        // when the named mod is present *within the discouraged range*.
        if matches!(relation_kind, DependencyRelation::Discouraged) {
            if is_platform_dep(dep_id) {
                continue;
            }
            let installed_desc = model.confirmed_versions(dep_id).join(", ");
            let (severity, confidence, undecidable, evidence) = match model
                .provider_resolution(dep_id, range, dialect)
            {
                // Not installed or outside the discouraged range: stay silent.
                ProviderResolution::Absent | ProviderResolution::Unsatisfied { .. } => continue,
                ProviderResolution::Satisfied { evidence } => {
                    (Severity::Warn, 0.9, false, evidence)
                }
                // Installed but range unparseable: low-confidence note.
                ProviderResolution::Unknown { evidence } => (Severity::Note, 0.4, true, evidence),
            };
            out.push(
                Finding::builder(rule_id, format!("discouraged-dependency:{modid}->{dep_id}"))
                    .severity(severity)
                    .confidence(confidence)
                    .category(Category::Dependency)
                    .title(format!("Discouraged alongside: {dep_id}"))
                    .explanation(if undecidable {
                        format!(
                            "{modid} discourages {dep_id} ({range}); installed version is \
                             {installed_desc}, but the range could not be parsed."
                        )
                    } else {
                        format!(
                            "{modid} discourages using {dep_id} {range} in the same pack \
                             (installed version is {installed_desc})."
                        )
                    })
                    .evidence(EvidenceEdge::subject(dep.id))
                    .evidence(EvidenceEdge::supports(evidence))
                    .affects(modid)
                    .affects(dep_id)
                    .fix(FixCandidate::advice(format!(
                        "Remove {dep_id} or review compatibility notes for {modid}."
                    )))
                    .tag("dependency")
                    .tag("discouraged")
                    .build(),
            );
            continue;
        }

        if dep_id == "minecraft" {
            if let Some(mc) = &mc_version
                && matches!(
                    version_in_range_with_dialect(mc, range, dialect),
                    Some(false)
                )
            {
                out.push(
                    Finding::builder(rule_id, format!("wrong-mc-version:{modid}"))
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
            continue;
        }

        // Java runtime constraint (`depends java >=21`).
        if dep_id == "java" {
            if let Some(java) = &java_version
                && matches!(
                    version_in_range_with_dialect(java, range, dialect),
                    Some(false)
                )
            {
                out.push(
                    Finding::builder(rule_id, format!("wrong-java-version:{modid}"))
                        .severity(Severity::Warn)
                        .category(Category::Dependency)
                        .title(format!("{modid} needs a different Java version"))
                        .explanation(format!(
                            "{modid} requires Java {range}, but the runtime is {java}."
                        ))
                        .evidence(EvidenceEdge::subject(dep.id))
                        .affects(modid)
                        .tag("dependency")
                        .tag("java-version")
                        .build(),
                );
            }
            continue;
        }

        // Loader runtime constraint (`depends fabricloader >=0.15`). Only checked
        // when the dep's loader family matches the detected environment loader and
        // we actually know the loader version — otherwise stay silent (a loader
        // *family* mismatch is the `loader-mismatch` rule's job, not a version one).
        if let Some(family) = platform_loader_family(dep_id) {
            if let (Some(env_fam), Some(loader_ver)) = (&env_loader, &env_loader_version)
                && env_fam == family
                && matches!(
                    version_in_range_with_dialect(loader_ver, range, dialect),
                    Some(false)
                )
            {
                out.push(
                        Finding::builder(rule_id, format!("wrong-loader-version:{modid}->{dep_id}"))
                            .severity(Severity::Warn)
                            .category(Category::Dependency)
                            .title(format!("{modid} needs {dep_id} {range}"))
                            .explanation(format!(
                                "{modid} requires {dep_id} {range}, but the {env_fam} loader is {loader_ver}."
                            ))
                            .evidence(EvidenceEdge::subject(dep.id))
                            .affects(modid)
                            .tag("dependency")
                            .tag("loader-version")
                            .build(),
                    );
            }
            continue;
        }

        if is_platform_dep(dep_id) {
            continue;
        }

        let provider = match model.provider_resolution(dep_id, range, dialect) {
            ProviderResolution::Satisfied { .. } => ProviderStatus::Satisfied,
            ProviderResolution::Unknown { evidence } => {
                ProviderStatus::Unknown(evidence, "provider-universe".to_string())
            }
            ProviderResolution::Unsatisfied { evidence } => {
                ProviderStatus::Unsatisfied(evidence, "provider-universe".to_string())
            }
            ProviderResolution::Absent => ProviderStatus::Absent,
        };
        let versions = installed_versions(dep_id);
        if matches!(
            range_status(
                versions,
                range,
                ambiguous_versions.contains(dep_id),
                dialect,
            ),
            RangeStatus::OutOfRange
        ) && let ProviderStatus::Unknown(provider_fact, scope) = &provider
        {
            if mandatory {
                out.push(
                    Finding::builder(
                        rule_id,
                        format!("provided-version-unknown:{modid}->{dep_id}"),
                    )
                    .severity(Severity::Warn)
                    .confidence(0.5)
                    .category(Category::Dependency)
                    .title(format!("Cannot confirm a compatible provider for {dep_id}"))
                    .explanation(format!(
                        "{modid} requires {dep_id} {range}. Known installed versions are outside \
                         that range, but an unresolved {scope} provider may satisfy it, so a hard \
                         version incompatibility cannot be asserted."
                    ))
                    .evidence(EvidenceEdge::subject(dep.id))
                    .evidence(EvidenceEdge::supports(*provider_fact))
                    .affects(modid)
                    .affects(dep_id)
                    .tag("dependency")
                    .tag("provider-unresolved")
                    .build(),
                );
            }
            continue;
        }
        match range_status(
            versions,
            range,
            ambiguous_versions.contains(dep_id),
            dialect,
        ) {
            // A copy in range satisfies the requirement; nothing to report.
            RangeStatus::InRange => {}
            // Installed copies all fall outside the range. For a mandatory dep this
            // is an Error; for an optional one (recommends/suggests), the
            // *integration* may not work but the pack still loads — Warn, not Error.
            // A bundled provider in-range still rescues it.
            RangeStatus::OutOfRange | RangeStatus::Undecidable
                if !matches!(provider, ProviderStatus::Satisfied) =>
            {
                let installed_desc = versions.join(", ");
                let undecidable = matches!(
                    range_status(
                        versions,
                        range,
                        ambiguous_versions.contains(dep_id),
                        dialect,
                    ),
                    RangeStatus::Undecidable
                );
                if undecidable {
                    let ambiguous = ambiguous_versions.contains(dep_id);
                    // Could not parse — never assert a hard mismatch.
                    let mut builder =
                        Finding::builder(rule_id, format!("version-undecidable:{modid}->{dep_id}"))
                            .severity(Severity::Note)
                            .confidence(0.4)
                            .category(Category::Dependency)
                            .title(format!("Cannot verify {dep_id} version"))
                            .explanation(if ambiguous {
                                format!(
                                    "{modid} requires {dep_id} {range}; installed version \
                                     `{installed_desc}` contains both a Minecraft-version prefix \
                                     and a mod-version component, so generic SemVer comparison is \
                                     not authoritative."
                                )
                            } else {
                                format!(
                                    "{modid} requires {dep_id} {range}; installed version is \
                                     {installed_desc}, but the range or version could not be parsed."
                                )
                            })
                            .evidence(EvidenceEdge::subject(dep.id))
                            .affects(modid)
                            .affects(dep_id)
                            .tag("dependency")
                            .tag("version-mismatch")
                            .tag("undecidable-range");
                    if ambiguous {
                        builder = builder.tag("ambiguous-version");
                    }
                    out.push(builder.build());
                } else {
                    let dup = is_duplicated(dep_id);
                    let mut b = Finding::builder(rule_id, format!("wrong-version:{modid}->{dep_id}"))
                        .family("wrong-version")
                        .conclusion_kind(ConclusionKind::WrongVersion)
                        .coverage_requirement(CoverageRequirement::CompletePack)
                        .coverage_requirement(CoverageRequirement::CompleteProviderUniverse)
                        .coverage_requirement(CoverageRequirement::ActiveDescriptor)
                        .proof_kind(ProofKind::DeterministicDerivation)
                        .impact(Impact::StartupBlocking)
                        .evidence_origin(EvidenceOrigin::StaticExact)
                        .severity(if mandatory { Severity::Error } else { Severity::Warn })
                        .confidence(if dup { 0.6 } else { 0.9 })
                        .category(Category::Dependency)
                        .title(if mandatory {
                            format!("Incompatible version of {dep_id}")
                        } else {
                            format!("Optional dependency {dep_id} version may not integrate")
                        })
                        .explanation(format!(
                            "{modid} {req} {dep_id} {range}, but {installed_desc} is installed.{dup_note}",
                            req = if mandatory { "requires" } else { "optionally uses" },
                            dup_note = if dup {
                                " Multiple versions of this id are installed, so this check is unreliable."
                            } else {
                                ""
                            }
                        ))
                        .evidence(EvidenceEdge::subject(dep.id))
                        .affects(modid)
                        .affects(dep_id)
                        .fix(FixCandidate::advice(format!(
                            "Install {dep_id} at a version matching {range}."
                        )))
                        .tag("dependency")
                        .tag("version-mismatch");
                    if !mandatory {
                        b = b.tag("optional");
                    }
                    if dup {
                        b = b.tag("ambiguous-duplicate");
                    }
                    out.push(b.build());
                }
            }
            RangeStatus::OutOfRange | RangeStatus::Undecidable => {}
            // Not directly installed: the requirement may still be met (or not) by a
            // `provides` declaration. Distinguish satisfied / out-of-range /
            // unknown-version / truly absent so a provider with the *wrong* version
            // is not mistaken for a satisfied dependency.
            RangeStatus::Absent => match provider {
                ProviderStatus::Satisfied => {}
                ProviderStatus::Unsatisfied(provider_fact, scope) => {
                    let (impact, title, explanation, fix) = if mandatory {
                        (
                            Impact::StartupBlocking,
                            format!("Provided {dep_id} does not satisfy {range}"),
                            format!(
                                "{modid} requires {dep_id} {range}. {dep_id} is not installed \
                                 directly; a {scope} provider exists but its version does \
                                 not satisfy the range."
                            ),
                            format!(
                                "Install {dep_id} at a version matching {range}; the bundled copy is too old/new."
                            ),
                        )
                    } else {
                        (
                            Impact::CompatibilityRisk,
                            format!("Optional {dep_id} integration may not match {range}"),
                            format!(
                                "{modid} optionally integrates with {dep_id} {range}. {dep_id} is not \
                                 installed directly; a {scope} provider exists but its version does not \
                                 satisfy the optional range. This does not prevent the pack from starting."
                            ),
                            format!(
                                "If this optional integration is needed, install {dep_id} at a version matching {range}."
                            ),
                        )
                    };
                    out.push(
                        Finding::builder(
                            rule_id,
                            format!("provided-version-mismatch:{modid}->{dep_id}"),
                        )
                        .family("wrong-version")
                        .conclusion_kind(ConclusionKind::WrongVersion)
                        .coverage_requirement(CoverageRequirement::CompletePack)
                        .coverage_requirement(CoverageRequirement::CompleteProviderUniverse)
                        .coverage_requirement(CoverageRequirement::ActiveDescriptor)
                        .proof_kind(ProofKind::DeterministicDerivation)
                        .impact(impact)
                        .evidence_origin(EvidenceOrigin::StaticExact)
                        .severity(if mandatory {
                            Severity::Error
                        } else {
                            Severity::Warn
                        })
                        .category(Category::Dependency)
                        .title(title)
                        .explanation(explanation)
                        .evidence(EvidenceEdge::subject(dep.id))
                        .evidence(EvidenceEdge::supports(provider_fact))
                        .affects(modid)
                        .affects(dep_id)
                        .fix(FixCandidate::advice(fix))
                        .tag("dependency")
                        .tag("version-mismatch")
                        .tag("provided")
                        .build(),
                    );
                }
                ProviderStatus::Unknown(provider_fact, scope) if mandatory => {
                    out.push(
                        Finding::builder(
                            rule_id,
                            format!("provided-version-unknown:{modid}->{dep_id}"),
                        )
                        .severity(Severity::Warn)
                        // Lower confidence: a provider exists but we can't
                        // range-check it, so we can't be sure it's a real miss.
                        .confidence(0.5)
                        .category(Category::Dependency)
                        .title(format!("Provided {dep_id} has an unknown version"))
                        .explanation(format!(
                            "{modid} requires {dep_id} {range}. A {scope} provider \
                             exists but declares no parseable version, so the range cannot \
                             be verified."
                        ))
                        .evidence(EvidenceEdge::subject(dep.id))
                        .evidence(EvidenceEdge::supports(provider_fact))
                        .affects(modid)
                        .affects(dep_id)
                        .tag("dependency")
                        .tag("provided")
                        .tag("unverified-version")
                        .build(),
                    );
                }
                ProviderStatus::Absent if mandatory => {
                    if let Some((artifact, artifact_fact)) =
                        plausible_artifact_for(dep_id, &plausible_artifacts)
                    {
                        out.push(
                            Finding::builder(
                                rule_id,
                                format!("provider-identity-unresolved:{modid}->{dep_id}"),
                            )
                            .family("provider-identity-unresolved")
                            .severity(Severity::Warn)
                            .confidence(0.55)
                            .category(Category::Dependency)
                            .title(format!("Provider identity not confirmed: {dep_id}"))
                            .explanation(format!(
                                "{modid} requires {dep_id} ({range}). No confirmed provider identity \
                                 was parsed, but `{artifact}` is a plausible matching artifact. It is \
                                 therefore not valid to state that the dependency is not installed."
                            ))
                            .evidence(EvidenceEdge::subject(dep.id))
                            .evidence(EvidenceEdge::supports(*artifact_fact))
                            .affects(modid)
                            .affects(dep_id)
                            .tag("dependency")
                            .tag("provider-unresolved")
                            .build(),
                        );
                        continue;
                    }
                    out.push(
                        Finding::builder(rule_id, format!("missing-dependency:{modid}->{dep_id}"))
                            .family("missing-dependency")
                            .conclusion_kind(ConclusionKind::MissingDependency)
                            .coverage_requirement(CoverageRequirement::CompletePack)
                            .coverage_requirement(CoverageRequirement::CompleteProviderUniverse)
                            .coverage_requirement(CoverageRequirement::ActiveDescriptor)
                            .proof_kind(ProofKind::DeterministicDerivation)
                            .impact(Impact::StartupBlocking)
                            .evidence_origin(EvidenceOrigin::StaticExact)
                            .severity(Severity::Error)
                            .category(Category::Dependency)
                            .title(format!("Missing dependency: {dep_id}"))
                            .explanation(format!(
                                "{modid} requires {dep_id} ({range}), but it is not installed."
                            ))
                            .evidence(EvidenceEdge::subject(dep.id))
                            .affects(modid)
                            .affects(dep_id)
                            .fix(FixCandidate::advice(format!(
                                "Install {dep_id} matching {range}."
                            )))
                            .tag("dependency")
                            .tag("missing")
                            .build(),
                    );
                }
                // Optional + (unknown provider or absent): nothing to report.
                ProviderStatus::Unknown(..) | ProviderStatus::Absent => {}
            },
        }
    }
    out
}

#[cfg(test)]
mod provider_truth_table_tests {
    use super::*;

    fn provider(version: Option<&str>, fact: u64) -> ProviderEntry {
        ProviderEntry {
            version: version.map(str::to_string),
            version_ambiguous: false,
            fact: FactId(fact),
            scope: "global".to_string(),
            confirmed: true,
        }
    }

    #[test]
    fn unknown_provider_prevents_out_of_range_assertion() {
        let providers = vec![provider(Some("1.0.0"), 1), provider(None, 2)];
        assert!(matches!(
            provider_status(
                Some(&providers),
                ">=2.0.0",
                VersionDialect::FabricExtendedSemver,
            ),
            ProviderStatus::Unknown(FactId(2), _)
        ));
    }

    #[test]
    fn all_known_out_of_range_is_unsatisfied() {
        let providers = vec![provider(Some("1.0.0"), 1), provider(Some("1.5.0"), 2)];
        assert!(matches!(
            provider_status(
                Some(&providers),
                ">=2.0.0",
                VersionDialect::FabricExtendedSemver,
            ),
            ProviderStatus::Unsatisfied(..)
        ));
    }

    #[test]
    fn plausible_provider_cannot_satisfy_but_prevents_absence() {
        let mut plausible = provider(Some("2.0.0"), 1);
        plausible.confirmed = false;
        assert!(matches!(
            provider_status(
                Some(&vec![plausible]),
                ">=1.0.0",
                VersionDialect::GenericSemver
            ),
            ProviderStatus::Unknown(..)
        ));
    }
}
