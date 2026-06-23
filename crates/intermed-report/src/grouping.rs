//! Finding grouping for the terminal and HTML reports.
//!
//! A pack with 195 safe tag merges, 30 binary overrides, and 12 recipe conflicts
//! should not print 237 stanzas. Findings of the same *family* are collapsed into
//! one [`FindingGroup`] with a count and a bounded sample, so the default report
//! stays signal. The grouping is a *rendering* concern — the JSON report keeps the
//! flat findings list (machine consumers group themselves, and `evidence_summary`
//! is already inline), so this adds no schema churn.

use std::collections::BTreeMap;

use intermed_evidence::{Finding, Severity};

/// A collapsed family of findings sharing an id prefix (e.g. all
/// `recipe-output-override:*`). Carries the worst severity and a bounded sample.
pub struct FindingGroup<'a> {
    /// Family key — the finding id with its trailing per-instance segment removed
    /// (`recipe-output-override`, `resource-conflict:json-override`, …).
    pub key: String,
    /// Human title (`Recipe output override`).
    pub title: String,
    /// Worst severity across the group's members.
    pub severity: Severity,
    pub members: Vec<&'a Finding>,
}

impl FindingGroup<'_> {
    pub fn len(&self) -> usize {
        self.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Up to `max` distinct affected paths/ids across the group, for the sample line.
    pub fn sample_subjects(&self, max: usize) -> (Vec<String>, usize) {
        let mut seen = Vec::new();
        for f in &self.members {
            let subject = f
                .affected_components
                .first()
                .cloned()
                .unwrap_or_else(|| instance_tail(&f.id).to_string());
            if !seen.contains(&subject) {
                seen.push(subject);
            }
        }
        let extra = seen.len().saturating_sub(max);
        seen.truncate(max);
        (seen, extra)
    }
}

/// The family key of a finding id: everything before the last `:`-delimited
/// segment (the per-instance path / jar / dependency). Ids without a `:` are
/// their own family.
///
/// One wrinkle: an instance segment can itself contain `:` — JVM descriptors and
/// resource paths do (`mixin-effect-summary:apply@FIELD|…;flags:B`). A plain
/// `rsplit_once(':')` would then cut *inside* the descriptor and leave a unique
/// "family" per handler, so every such finding became its own singleton group.
/// We therefore re-cut: if the candidate family still contains a character that
/// only appears in an instance (`@ ( ) ; / < > | .`), the split landed inside an
/// instance — fall back to the prefix before the first segment carrying one.
pub fn finding_family(id: &str) -> &str {
    let candidate = id.rsplit_once(':').map(|(head, _)| head).unwrap_or(id);
    if candidate.contains(INSTANCE_CHARS) {
        // Re-cut before the first `:`-segment that carries an instance char.
        let mut end = 0;
        for seg in candidate.split(':') {
            if seg.contains(INSTANCE_CHARS) {
                return if end == 0 {
                    candidate
                } else {
                    &candidate[..end - 1]
                };
            }
            end += seg.len() + 1; // segment + the ':' delimiter
        }
    }
    candidate
}

/// Characters that appear in instance segments (descriptors / paths) but never in
/// a family's kebab-case type name. Note `-` is excluded (kebab) and so is `:`.
const INSTANCE_CHARS: &[char] = &['@', '(', ')', ';', '/', '<', '>', '|', '.'];

/// The per-instance tail of a finding id (after the last `:`).
fn instance_tail(id: &str) -> &str {
    id.rsplit_once(':').map(|(_, tail)| tail).unwrap_or(id)
}

/// Humanize a family key into a title: drop the leading `resource-conflict:`
/// noise, turn separators into spaces, capitalize.
fn humanize(key: &str) -> String {
    let core = key.strip_prefix("resource-conflict:").unwrap_or(key);
    let spaced = core.replace([':', '-'], " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => spaced,
    }
}

/// Group findings by family, preserving worst severity. Returns groups sorted by
/// severity (worst first) then key, so the report leads with what matters.
pub fn group_findings<'a>(findings: &'a [&'a Finding]) -> Vec<FindingGroup<'a>> {
    let mut by_key: BTreeMap<String, Vec<&'a Finding>> = BTreeMap::new();
    for f in findings {
        by_key
            .entry(finding_family(&f.id).to_string())
            .or_default()
            .push(f);
    }
    let mut groups: Vec<FindingGroup<'a>> = by_key
        .into_iter()
        .map(|(key, members)| {
            let severity = members
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Info);
            let title = humanize(&key);
            FindingGroup {
                key,
                title,
                severity,
                members,
            }
        })
        .collect();
    groups.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.key.cmp(&b.key)));
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, sev: Severity) -> Finding {
        Finding::builder("r", id)
            .severity(sev)
            .affects(id.rsplit_once(':').map(|(_, t)| t).unwrap_or(id))
            .build()
    }

    #[test]
    fn families_are_derived_from_id() {
        assert_eq!(
            finding_family("recipe-output-override:data/c/r.json"),
            "recipe-output-override"
        );
        assert_eq!(
            finding_family("resource-conflict:json-override:data/c/r.json"),
            "resource-conflict:json-override"
        );
        assert_eq!(finding_family("lang-key-conflict"), "lang-key-conflict");
    }

    #[test]
    fn descriptor_colons_do_not_fragment_families() {
        // Instance segments with JVM descriptors carry their own `:` — the family
        // must still collapse to the type prefix, not fragment per handler.
        assert_eq!(
            finding_family("mixin-effect-summary:<init>(I)V@RETURN"),
            "mixin-effect-summary"
        );
        assert_eq!(
            finding_family("mixin-effect-summary:apply@FIELD|net.minecraft.X;flags:B"),
            "mixin-effect-summary"
        );
        // Arrow-style instances (dependency edges) have no descriptor char and
        // must keep grouping under the type prefix via the normal last-colon cut.
        assert_eq!(
            finding_family("missing-dependency:bewitchment->fabric-api"),
            "missing-dependency"
        );
    }

    #[test]
    fn descriptor_colon_findings_group_together() {
        let findings = [
            f("mixin-effect-summary:<init>(I)V@RETURN", Severity::Note),
            f("mixin-effect-summary:tick@HEAD;x:B", Severity::Note),
            f("mixin-effect-summary:apply@FIELD|a.b.C;y:I", Severity::Note),
        ];
        let refs: Vec<&Finding> = findings.iter().collect();
        let groups = group_findings(&refs);
        assert_eq!(groups.len(), 1, "all three must collapse into one family");
        assert_eq!(groups[0].len(), 3);
    }

    #[test]
    fn groups_collapse_and_sort_by_severity() {
        let findings = [
            f("recipe-output-override:data/a.json", Severity::Warn),
            f("recipe-output-override:data/b.json", Severity::Warn),
            f("artifact-signature-status:unsigned:x.jar", Severity::Note),
        ];
        let refs: Vec<&Finding> = findings.iter().collect();
        let groups = group_findings(&refs);
        assert_eq!(groups.len(), 2);
        // Warn group first.
        assert_eq!(groups[0].key, "recipe-output-override");
        assert_eq!(groups[0].len(), 2);
        assert_eq!(groups[0].title, "Recipe output override");
        let (sample, extra) = groups[0].sample_subjects(8);
        assert_eq!(sample.len(), 2);
        assert_eq!(extra, 0);
    }
}
