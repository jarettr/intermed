//! Pairwise dependency checks (Phase 1 semantics) over fact snapshots.

use std::collections::HashMap;

use intermed_doctor_core::RuleCtx;
use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::{FactId, kind};

use crate::graph::{is_platform_dep, platform_loader_family};
use crate::semver::version_in_range;

/// A dependency `provides` declaration (e.g. a Jar-in-Jar bundled library, or a
/// mod that advertises an alias id), carrying the declared version when known so
/// the resolver can range-check it instead of treating any provider as a match.
struct ProviderEntry {
    version: Option<String>,
    fact: FactId,
    /// Visibility scope: `classpath` (Jar-in-Jar), `metadata-alias` (a declared
    /// `provides` id), or `global` (default). Recorded for explanation; in
    /// Minecraft both nested jars and aliases are globally visible, so scope does
    /// not change satisfaction — only the wording/confidence of provider notes.
    scope: String,
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

fn provider_status(providers: Option<&Vec<ProviderEntry>>, range: &str) -> ProviderStatus {
    let Some(providers) = providers.filter(|p| !p.is_empty()) else {
        return ProviderStatus::Absent;
    };
    let mut unknown: Option<&ProviderEntry> = None;
    let mut out_of_range: Option<&ProviderEntry> = None;
    for p in providers {
        match &p.version {
            Some(v) => match version_in_range(v, range) {
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
    // Prefer reporting an out-of-range provider (actionable) over an unknown one.
    match (out_of_range, unknown) {
        (Some(p), _) => ProviderStatus::Unsatisfied(p.fact, p.scope.clone()),
        (None, Some(p)) => ProviderStatus::Unknown(p.fact, p.scope.clone()),
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
fn range_status(versions: &[String], range: &str) -> RangeStatus {
    if versions.is_empty() {
        return RangeStatus::Absent;
    }
    let mut any_undecidable = false;
    for v in versions {
        match version_in_range(v, range) {
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
    matches!(
        relation,
        "loadbefore" | "loadafter" | "load_before" | "load_after"
    )
}

/// Evaluate direct missing / version / Minecraft constraints without PubGrub.
pub fn pairwise_findings(ctx: &RuleCtx<'_>, rule_id: &str) -> Vec<Finding> {
    let store = ctx.store;

    // All installed versions per id (a duplicated id keeps every version, so a
    // version check stays correct instead of silently picking one copy).
    let mut installed: HashMap<String, Vec<String>> = HashMap::new();
    for f in store.by_kind(kind::MOD).chain(store.by_kind(kind::PLUGIN)) {
        installed
            .entry(f.subject.clone())
            .or_default()
            .push(f.attr("version").unwrap_or("0").to_string());
    }
    let installed_versions = |id: &str| installed.get(id).map(Vec::as_slice).unwrap_or(&[]);
    let is_duplicated = |id: &str| installed.get(id).is_some_and(|v| v.len() > 1);
    // Providers are version-aware: a bundled/aliased `provides` only satisfies a
    // requirement when its declared version is inside the requested range.
    let mut provided: HashMap<String, Vec<ProviderEntry>> = HashMap::new();
    for f in store.by_kind(kind::PROVIDED_DEPENDENCY) {
        if let Some(p) = f.attr("provides") {
            let version = f
                .attr("version")
                .map(str::to_string)
                .or_else(|| installed.get(&f.subject).and_then(|v| v.first()).cloned());
            provided
                .entry(p.to_string())
                .or_default()
                .push(ProviderEntry {
                    version,
                    fact: f.id,
                    scope: f.attr("scope").unwrap_or("global").to_string(),
                });
        }
    }

    let env = store.by_kind(kind::ENVIRONMENT).next();
    let mc_version = env.and_then(|f| f.attr("mc_version").map(str::to_string));
    let env_loader = env.and_then(|f| f.attr("loader").map(str::to_string));
    let env_loader_version = env.and_then(|f| f.attr("loader_version").map(str::to_string));
    let java_version = store
        .by_kind(kind::JAVA_RUNTIME)
        .next()
        .and_then(|f| f.attr("version").map(str::to_string));

    let mut out = Vec::new();
    for dep in store.by_kind(kind::DEPENDENCY) {
        let modid = dep.subject.as_str();
        let dep_id = dep.attr("dep").unwrap_or("");
        let range = dep.attr("range").unwrap_or("*");
        let mandatory = dep.attr_bool("mandatory").unwrap_or(true);
        let relation = dep.attr("relation").unwrap_or("depends");

        // Ordering hints are never requirements — handled by the ordering rule.
        if is_ordering_relation(relation) {
            continue;
        }

        if relation == "breaks" {
            if is_platform_dep(dep_id) {
                continue;
            }
            let versions = installed_versions(dep_id);
            let installed_desc = versions.join(", ");
            match range_status(versions, range) {
                // Absent / out of the break range: compatible, stay silent.
                RangeStatus::Absent | RangeStatus::OutOfRange => {}
                // An installed version really falls inside the declared break
                // range: a genuine, actionable incompatibility.
                RangeStatus::InRange => out.push(
                    Finding::builder(rule_id, format!("incompatible-mod:{modid}->{dep_id}"))
                        .severity(Severity::Error)
                        .category(Category::Dependency)
                        .title(format!("Incompatible with installed mod: {dep_id}"))
                        .explanation(format!(
                            "{modid} breaks {dep_id} ({range}); installed version is {installed_desc}."
                        ))
                        .evidence(EvidenceEdge::subject(dep.id))
                        .affects(modid)
                        .fix(FixCandidate::advice(format!(
                            "Remove {modid} or change the installed version of {dep_id}."
                        )))
                        .tag("dependency")
                        .tag("breaks")
                        .build(),
                ),
                // Range/version unparseable — never a hard "remove one" ERROR.
                RangeStatus::Undecidable => out.push(
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

        // NeoForge `type = "discouraged"`: compatible load, but the author warns
        // when the named mod is present *within the discouraged range*.
        if relation == "discouraged" {
            if is_platform_dep(dep_id) {
                continue;
            }
            let versions = installed_versions(dep_id);
            let installed_desc = versions.join(", ");
            let (severity, confidence, undecidable) = match range_status(versions, range) {
                // Not installed or outside the discouraged range: stay silent.
                RangeStatus::Absent | RangeStatus::OutOfRange => continue,
                RangeStatus::InRange => (Severity::Warn, 0.9, false),
                // Installed but range unparseable: low-confidence note.
                RangeStatus::Undecidable => (Severity::Note, 0.4, true),
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
            if let Some(mc) = &mc_version {
                if matches!(version_in_range(mc, range), Some(false)) {
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
            }
            continue;
        }

        // Java runtime constraint (`depends java >=21`).
        if dep_id == "java" {
            if let Some(java) = &java_version {
                if matches!(version_in_range(java, range), Some(false)) {
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
            }
            continue;
        }

        // Loader runtime constraint (`depends fabricloader >=0.15`). Only checked
        // when the dep's loader family matches the detected environment loader and
        // we actually know the loader version — otherwise stay silent (a loader
        // *family* mismatch is the `loader-mismatch` rule's job, not a version one).
        if let Some(family) = platform_loader_family(dep_id) {
            if let (Some(env_fam), Some(loader_ver)) = (&env_loader, &env_loader_version) {
                if env_fam == family && matches!(version_in_range(loader_ver, range), Some(false)) {
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
            }
            continue;
        }

        if is_platform_dep(dep_id) {
            continue;
        }

        let provider = provider_status(provided.get(dep_id), range);
        let versions = installed_versions(dep_id);
        match range_status(versions, range) {
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
                let undecidable = matches!(range_status(versions, range), RangeStatus::Undecidable);
                if undecidable {
                    // Could not parse — never assert a hard mismatch.
                    out.push(
                        Finding::builder(rule_id, format!("version-undecidable:{modid}->{dep_id}"))
                            .severity(Severity::Note)
                            .confidence(0.4)
                            .category(Category::Dependency)
                            .title(format!("Cannot verify {dep_id} version"))
                            .explanation(format!(
                                "{modid} requires {dep_id} {range}; installed version is \
                                 {installed_desc}, but the range could not be parsed."
                            ))
                            .evidence(EvidenceEdge::subject(dep.id))
                            .affects(modid)
                            .affects(dep_id)
                            .tag("dependency")
                            .tag("version-mismatch")
                            .tag("undecidable-range")
                            .build(),
                    );
                } else {
                    let dup = is_duplicated(dep_id);
                    let mut b = Finding::builder(rule_id, format!("wrong-version:{modid}->{dep_id}"))
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
                    out.push(
                        Finding::builder(
                            rule_id,
                            format!("provided-version-mismatch:{modid}->{dep_id}"),
                        )
                        .severity(if mandatory { Severity::Error } else { Severity::Warn })
                        .category(Category::Dependency)
                        .title(format!("Provided {dep_id} does not satisfy {range}"))
                        .explanation(format!(
                            "{modid} requires {dep_id} {range}. {dep_id} is not installed \
                             directly; a {scope} provider exists but its version does \
                             not satisfy the range."
                        ))
                        .evidence(EvidenceEdge::subject(dep.id))
                        .evidence(EvidenceEdge::supports(provider_fact))
                        .affects(modid)
                        .affects(dep_id)
                        .fix(FixCandidate::advice(format!(
                            "Install {dep_id} at a version matching {range}; the bundled copy is too old/new."
                        )))
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
                    out.push(
                        Finding::builder(rule_id, format!("missing-dependency:{modid}->{dep_id}"))
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
                // Optional + (unknown provider or absent): nothing to report.
                ProviderStatus::Unknown(..) | ProviderStatus::Absent => {}
            },
        }
    }
    out
}
