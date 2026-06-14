//! Failure attribution: which mod, class, or jar caused an observed crash.
//!
//! Lab classification already knows *what kind* of failure happened
//! ([`FailureCategory`]); attribution adds *who* — the subject a Doctor finding
//! can be joined against. Without subjects, `lab eval` can only measure
//! category co-occurrence per mod-set (one tp/fp per case), which collapses
//! intra-case multiplicity ("five overlap flags, one real crash" → one tp).
//!
//! Attribution is extracted from the same captured log the classifier reads.
//! Patterns are conservative: when no subject can be parsed, the failure is still
//! classified but left unattributed (finding-level metrics skip that case).

use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::classify::{classify_log, FailureCategory};

/// Minimum number of flagged predictions before [`super::eval::suggest_severity`]
/// may recommend above [`intermed_doctor_core::evidence::Severity::Note`].
pub const SEVERITY_CALIBRATION_MIN_SUPPORT: usize = 10;

/// One attributable cause extracted from a failure log.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FailureAttribution {
    pub category: FailureCategory,
    /// Normalized subject: dotted JVM class, mod id, jar stem, or `modA+modB`.
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_excerpt: Option<String>,
}

struct SubjectPattern {
    category: FailureCategory,
    regex: &'static str,
    /// Capture group (1-based) holding the primary subject.
    group: usize,
}

fn patterns() -> &'static [SubjectPattern] {
    &[
        SubjectPattern {
            category: FailureCategory::MixinApplyError,
            regex: r"(?i)(?:InvalidMixinException|Mixin apply failed|mixin transformation).*?(net\.[a-zA-Z0-9_$.]+)",
            group: 1,
        },
        SubjectPattern {
            category: FailureCategory::MixinApplyError,
            regex: r"(?i)@Mixin.*?target.*?([a-z][a-zA-Z0-9_/$.]+)",
            group: 1,
        },
        SubjectPattern {
            category: FailureCategory::MixinApplyError,
            regex: "(?i)Mod\\s+[\u{201e}\u{201c}\"']?([^\u{201e}\u{201c}\"'\\s:]+).*InvalidMixinException",
            group: 1,
        },
        SubjectPattern {
            category: FailureCategory::MissingDependency,
            regex: r"(?i)Mod\s+([a-zA-Z0-9_-]+)\s+requires\s+([a-zA-Z0-9_-]+)",
            group: 1,
        },
        SubjectPattern {
            category: FailureCategory::ModLoadingFailure,
            regex: r"(?i)Failed to load mod\s+([a-zA-Z0-9_-]+)",
            group: 1,
        },
        SubjectPattern {
            category: FailureCategory::ModLoadingFailure,
            regex: r"(?i)Could not execute entrypoint.*?\b([a-zA-Z0-9_-]+)\b",
            group: 1,
        },
        SubjectPattern {
            category: FailureCategory::ClassNotFound,
            regex: r"(?:NoClassDefFoundError|ClassNotFoundException):\s*([a-zA-Z0-9_$/]+)",
            group: 1,
        },
        SubjectPattern {
            category: FailureCategory::RegistryFreezeError,
            regex: r"(?i)(Registry is already frozen|Trying to access unbound).*?([a-z][a-zA-Z0-9_/$.]+)",
            group: 2,
        },
        SubjectPattern {
            category: FailureCategory::PerformanceRegression,
            regex: r"(?i)(?:MSPT|tick).*?(net\.[a-zA-Z0-9_$.]+)",
            group: 1,
        },
        SubjectPattern {
            category: FailureCategory::PerformanceRegression,
            regex: r"(?i)mod\s+([a-zA-Z0-9_-]+).*(?:can't keep up|can.t keep up|mspt)",
            group: 1,
        },
    ]
}

fn compiled() -> &'static [(FailureCategory, Regex, usize)] {
    static TABLE: OnceLock<Vec<(FailureCategory, Regex, usize)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        patterns()
            .iter()
            .filter_map(|p| {
                Regex::new(p.regex)
                    .ok()
                    .map(|re| (p.category, re, p.group))
            })
            .collect()
    })
}

/// Normalize a subject string for stable joins (slashes → dots, lowercased mod ids).
#[must_use]
pub fn normalize_subject(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches(".class");
    if trimmed.contains('/') {
        return trimmed.replace('/', ".");
    }
    if trimmed.contains('.') && trimmed.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        return trimmed.to_string();
    }
    trimmed.to_ascii_lowercase()
}

/// Extract every attributable subject from a log, deduplicated by (category, subject).
#[must_use]
pub fn extract_attributions(log: &str) -> Vec<FailureAttribution> {
    let mut out: Vec<FailureAttribution> = Vec::new();
    for line in log.lines() {
        let Some(category) = classify_log(line) else {
            continue;
        };
        for (pat_cat, re, group) in compiled() {
            if *pat_cat != category {
                continue;
            }
            let Some(caps) = re.captures(line) else {
                continue;
            };
            let Some(m) = caps.get(*group) else {
                continue;
            };
            let subject = normalize_subject(m.as_str());
            if subject.is_empty() {
                continue;
            }
            if out
                .iter()
                .any(|a| a.category == category && a.subject == subject)
            {
                continue;
            }
            out.push(FailureAttribution {
                category,
                subject,
                line_excerpt: Some(truncate_line(line, 200)),
            });
        }
    }
    out.sort();
    out
}

fn truncate_line(line: &str, max: usize) -> String {
    let t = line.trim();
    if t.len() <= max {
        return t.to_string();
    }
    let end = floor_char_boundary(t, max);
    format!("{}…", &t[..end])
}

fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

fn simple_name(subject: &str) -> String {
    normalize_subject(subject)
        .rsplit('.')
        .next()
        .unwrap_or(subject)
        .to_ascii_lowercase()
}

/// Whether a Doctor finding subject matches an attributed failure subject.
#[must_use]
pub fn subjects_match(prediction: &str, attribution: &str) -> bool {
    let p = normalize_subject(prediction);
    let a = normalize_subject(attribution);
    if p == a {
        return true;
    }
    if p.contains(&a) || a.contains(&p) {
        return true;
    }
    simple_name(&p) == simple_name(&a)
}

/// Extract the join key from a finding id (`rule:subject` or `rule:subject->target`).
#[must_use]
pub fn subject_from_finding_id(id: &str) -> &str {
    let rest = id.split_once(':').map(|(_, s)| s).unwrap_or(id);
    rest.split_once("->").map(|(_, t)| t).unwrap_or(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_mixin_class_from_log() {
        let log = "net.fabricmc.loader.impl.launch.knot.KnotClassLoader: \
                   org.spongepowered.asm.mixin.transformer.throwables.MixinTransformerError: \
                   InvalidMixinException: Mixin apply failed for \
                   net.minecraft.client.render.WorldRenderer";
        let attrs = extract_attributions(log);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].category, FailureCategory::MixinApplyError);
        assert_eq!(
            attrs[0].subject,
            "net.minecraft.client.render.WorldRenderer"
        );
    }

    #[test]
    fn extracts_mod_from_missing_dependency() {
        let log = "Mod create requires fabric-api which is missing";
        let attrs = extract_attributions(log);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].category, FailureCategory::MissingDependency);
        assert_eq!(attrs[0].subject, "create");
    }

    #[test]
    fn extracts_mod_from_localized_mixin_line() {
        let log = "[ERROR] Mod \u{201e}H\u{00f6}hlenausbau\u{201c} \u{1f6d1} InvalidMixinException: apply failed";
        let attrs = extract_attributions(log);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].subject, "h\u{00f6}hlenausbau");
    }

    #[test]
    fn subjects_match_by_class_suffix() {
        assert!(subjects_match(
            "net.minecraft.client.render.WorldRenderer",
            "WorldRenderer"
        ));
        assert!(!subjects_match("alpha", "beta"));
    }

    #[test]
    fn parses_finding_id_subjects() {
        assert_eq!(
            subject_from_finding_id("mixin-risk:net.minecraft.client.render.WorldRenderer"),
            "net.minecraft.client.render.WorldRenderer"
        );
        assert_eq!(
            subject_from_finding_id("mixin-overwrite:alpha->net.minecraft.Foo"),
            "net.minecraft.Foo"
        );
    }
}