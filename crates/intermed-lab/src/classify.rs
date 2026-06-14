//! Smoke-test outcome classification.
//!
//! Maps a captured server/client log into a coarse [`FailureCategory`]. The
//! taxonomy is deliberately aligned with Layer D (`intermed-log` signal kinds)
//! so a failure classified here means the same thing as the equivalent
//! `log_signal` fact — the lab and the doctor speak one language.

use serde::{Deserialize, Serialize};

/// A coarse grouping over [`FailureCategory`], so reports can aggregate the flat
/// taxonomy into a handful of families (e.g. "3 mod-integration failures, 1
/// resource exhaustion") instead of a long flat histogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureFamily {
    /// Mods failing to load, resolve, or apply (mixin/dep/class/loading).
    ModIntegration,
    /// Game data rejected after load (registry freeze, datapack validation).
    DataIntegrity,
    /// The host environment, not the mods (e.g. port already bound).
    Environment,
    /// Resource exhaustion in the JVM (heap, stack).
    ResourceExhaustion,
    /// Tick lag / MSPT spikes while the process stayed up.
    Performance,
    /// A hard native/JVM crash.
    Crash,
    /// No known family.
    Unknown,
}

impl FailureFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            FailureFamily::ModIntegration => "mod-integration",
            FailureFamily::DataIntegrity => "data-integrity",
            FailureFamily::Environment => "environment",
            FailureFamily::ResourceExhaustion => "resource-exhaustion",
            FailureFamily::Performance => "performance",
            FailureFamily::Crash => "crash",
            FailureFamily::Unknown => "unknown",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            FailureFamily::ModIntegration => "Mod integration",
            FailureFamily::DataIntegrity => "Data integrity",
            FailureFamily::Environment => "Environment",
            FailureFamily::ResourceExhaustion => "Resource exhaustion",
            FailureFamily::Performance => "Performance regression",
            FailureFamily::Crash => "Crash",
            FailureFamily::Unknown => "Unknown",
        }
    }
}

/// Why a smoke test failed, in decreasing order of how actionable it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureCategory {
    MixinApplyError,
    MissingDependency,
    ModLoadingFailure,
    ClassNotFound,
    RegistryFreezeError,
    DatapackValidationError,
    PortInUse,
    OutOfMemory,
    StackOverflow,
    /// Server stayed up but tick budget was exceeded (MSPT / "can't keep up").
    PerformanceRegression,
    JvmCrash,
    /// Process exited non-zero but no known pattern matched.
    Unknown,
}

impl FailureCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            FailureCategory::MixinApplyError => "mixin-apply-error",
            FailureCategory::MissingDependency => "missing-dependency",
            FailureCategory::ModLoadingFailure => "mod-loading-failure",
            FailureCategory::ClassNotFound => "class-not-found",
            FailureCategory::RegistryFreezeError => "registry-freeze-error",
            FailureCategory::DatapackValidationError => "datapack-validation-error",
            FailureCategory::PortInUse => "port-in-use",
            FailureCategory::OutOfMemory => "out-of-memory",
            FailureCategory::StackOverflow => "stack-overflow",
            FailureCategory::PerformanceRegression => "performance-regression",
            FailureCategory::JvmCrash => "jvm-crash",
            FailureCategory::Unknown => "unknown",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            FailureCategory::MixinApplyError => "Mixin failed to apply",
            FailureCategory::MissingDependency => "Missing required dependency",
            FailureCategory::ModLoadingFailure => "A mod failed to load",
            FailureCategory::ClassNotFound => "Class not found at runtime",
            FailureCategory::RegistryFreezeError => "Registry modified after freeze",
            FailureCategory::DatapackValidationError => "Datapack failed validation",
            FailureCategory::PortInUse => "Server port already in use",
            FailureCategory::OutOfMemory => "Out of memory",
            FailureCategory::StackOverflow => "Stack overflow",
            FailureCategory::PerformanceRegression => "Server tick lag / MSPT regression",
            FailureCategory::JvmCrash => "JVM hard crash",
            FailureCategory::Unknown => "Unclassified failure",
        }
    }

    /// The family this category rolls up into (see [`FailureFamily`]).
    pub fn family(self) -> FailureFamily {
        match self {
            FailureCategory::MixinApplyError
            | FailureCategory::MissingDependency
            | FailureCategory::ModLoadingFailure
            | FailureCategory::ClassNotFound => FailureFamily::ModIntegration,
            FailureCategory::RegistryFreezeError | FailureCategory::DatapackValidationError => {
                FailureFamily::DataIntegrity
            }
            FailureCategory::PortInUse => FailureFamily::Environment,
            FailureCategory::OutOfMemory | FailureCategory::StackOverflow => {
                FailureFamily::ResourceExhaustion
            }
            FailureCategory::PerformanceRegression => FailureFamily::Performance,
            FailureCategory::JvmCrash => FailureFamily::Crash,
            FailureCategory::Unknown => FailureFamily::Unknown,
        }
    }
}

struct Pattern {
    category: FailureCategory,
    regex: &'static str,
}

/// Classification table. The first matching pattern wins, so the most specific /
/// most actionable categories are listed first.
fn patterns() -> &'static [Pattern] {
    &[
        Pattern {
            category: FailureCategory::MixinApplyError,
            regex: r"(?i)(InvalidMixinException|MixinTransformerError|Mixin apply failed|mixin transformation .* failed)",
        },
        Pattern {
            category: FailureCategory::PerformanceRegression,
            regex: r"(?i)(Can't keep up|can.t keep up|Running \d+ms behind|MSPT|server overloaded|tick took \d+)",
        },
        Pattern {
            category: FailureCategory::MissingDependency,
            regex: r"(?i)(requires .* which is missing|Missing or unsupported mandatory dependencies|requires version)",
        },
        Pattern {
            category: FailureCategory::ModLoadingFailure,
            regex: r"(?i)(Failed to load mod|ModResolutionException|Could not execute entrypoint)",
        },
        Pattern {
            category: FailureCategory::ClassNotFound,
            regex: r"(NoClassDefFoundError|ClassNotFoundException)",
        },
        Pattern {
            category: FailureCategory::RegistryFreezeError,
            regex: r"(?i)(Registry is already frozen|Trying to access unbound|registry freeze)",
        },
        Pattern {
            category: FailureCategory::DatapackValidationError,
            regex: r"(?i)(Couldn't load .* datapack|Failed to load datapacks|Error while loading data pack)",
        },
        Pattern {
            category: FailureCategory::PortInUse,
            regex: r"(?i)(Address already in use|FAILED TO BIND TO PORT)",
        },
        Pattern {
            category: FailureCategory::OutOfMemory,
            regex: r"OutOfMemoryError",
        },
        Pattern {
            category: FailureCategory::StackOverflow,
            regex: r"StackOverflowError",
        },
        Pattern {
            category: FailureCategory::JvmCrash,
            regex: r"(A fatal error has been detected by the Java Runtime|SIGSEGV|EXCEPTION_ACCESS_VIOLATION)",
        },
    ]
}

/// Compiled classification table, built once.
fn compiled() -> &'static [(FailureCategory, regex::Regex)] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<(FailureCategory, regex::Regex)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        patterns()
            .iter()
            .map(|p| {
                (
                    p.category,
                    regex::Regex::new(p.regex).expect("valid classification regex"),
                )
            })
            .collect()
    })
}

/// Classify a captured log into its single dominant failure category (the
/// highest-priority pattern that matches), if any. This drives the coarse smoke
/// verdict; use [`classify_log_all`] when independent failures matter.
#[must_use]
pub fn classify_log(log: &str) -> Option<FailureCategory> {
    compiled()
        .iter()
        .find(|(_, re)| re.is_match(log))
        .map(|(cat, _)| *cat)
}

/// Every distinct failure category whose pattern matches the log, in priority
/// order. A single log routinely carries several *independent* failures (mod A's
/// mixin error, mod B's missing dependency); collapsing to only the first hit
/// (as [`classify_log`] does for the verdict) hides the rest. This returns the
/// full set so the report can summarise all of them.
#[must_use]
pub fn classify_log_all(log: &str) -> Vec<FailureCategory> {
    compiled()
        .iter()
        .filter(|(_, re)| re.is_match(log))
        .map(|(cat, _)| *cat)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_failures() {
        assert_eq!(
            classify_log("net.fabricmc.loader ... InvalidMixinException: oops"),
            Some(FailureCategory::MixinApplyError)
        );
        assert_eq!(
            classify_log("java.lang.OutOfMemoryError: Java heap space"),
            Some(FailureCategory::OutOfMemory)
        );
        assert_eq!(
            classify_log("Caused by: java.lang.NoClassDefFoundError: foo/Bar"),
            Some(FailureCategory::ClassNotFound)
        );
    }

    #[test]
    fn mixin_wins_over_class_not_found_when_both_present() {
        let log = "InvalidMixinException ... NoClassDefFoundError";
        assert_eq!(classify_log(log), Some(FailureCategory::MixinApplyError));
    }

    #[test]
    fn clean_log_is_unclassified() {
        assert_eq!(
            classify_log("[Server] Done (3.2s)! For help, type \"help\""),
            None
        );
        assert!(classify_log_all("[Server] Done (3.2s)!").is_empty());
    }

    #[test]
    fn classify_all_surfaces_independent_failures() {
        // Two unrelated mods fail for two unrelated reasons in one log.
        let log = "Mod alpha: InvalidMixinException: boom\n\
                   Mod beta requires fabric-api which is missing";
        let all = classify_log_all(log);
        assert!(all.contains(&FailureCategory::MixinApplyError));
        assert!(all.contains(&FailureCategory::MissingDependency));
        // The single-category verdict still picks the highest-priority one.
        assert_eq!(classify_log(log), Some(FailureCategory::MixinApplyError));
    }

    #[test]
    fn classifies_performance_regression() {
        assert_eq!(
            classify_log("[Server thread/WARN]: Can't keep up! Is the server overloaded?"),
            Some(FailureCategory::PerformanceRegression)
        );
        assert_eq!(
            FailureCategory::PerformanceRegression.family(),
            FailureFamily::Performance
        );
    }

    #[test]
    fn families_group_the_flat_taxonomy() {
        assert_eq!(
            FailureCategory::MixinApplyError.family(),
            FailureFamily::ModIntegration
        );
        assert_eq!(
            FailureCategory::OutOfMemory.family(),
            FailureFamily::ResourceExhaustion
        );
        assert_eq!(FailureCategory::JvmCrash.family(), FailureFamily::Crash);
    }
}
