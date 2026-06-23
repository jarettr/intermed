//! Curated cross-mod relationship knowledge (plan 3.1's "жёстко заданный список").
//!
//! Some relationships are not derivable from any manifest: Sodium and OptiFine
//! both replace the renderer and cannot coexist; Iris *requires* Sodium. This is a
//! deliberately small, conservative table of well-established facts, emitted as
//! `mod_relationship` facts alongside the manifest-derived ones. Entries are
//! directed (keyed by the installed mod) and bidirectional pairs are listed both
//! ways so the relationship surfaces whichever side is installed.

/// One curated relationship from a `subject` mod to a `related` mod.
pub(crate) struct Curated {
    pub related: &'static str,
    pub kind: &'static str,
    pub reason: &'static str,
    pub confidence: f32,
}

/// `(subject_mod_id, relationship)` table.
const TABLE: &[(&str, Curated)] = &[
    // ── Renderer replacements: mutually exclusive with OptiFine ──
    incompat("sodium", "optifine"),
    incompat("optifine", "sodium"),
    incompat("rubidium", "optifine"),
    incompat("optifine", "rubidium"),
    incompat("embeddium", "optifine"),
    incompat("optifine", "embeddium"),
    // Sodium and its Forge ports are the same renderer — never run two at once.
    incompat("rubidium", "embeddium"),
    incompat("embeddium", "rubidium"),
    // Shader mods are mutually exclusive with OptiFine's shader pipeline.
    incompat("iris", "optifine"),
    incompat("optifine", "iris"),
    incompat("oculus", "optifine"),
    incompat("optifine", "oculus"),
    // OptiFabric brings OptiFine to Fabric and clashes with the Sodium renderer.
    incompat("optifabric", "sodium"),
    incompat("sodium", "optifabric"),
    // ── Established companions ──
    recommend(
        "iris",
        "sodium",
        "Iris requires Sodium as its rendering backend",
    ),
    recommend(
        "sodium",
        "iris",
        "Iris is the standard shader companion for Sodium",
    ),
    recommend(
        "indium",
        "sodium",
        "Indium adds Fabric Rendering API support to Sodium",
    ),
    recommend(
        "sodium-extra",
        "sodium",
        "Sodium Extra extends Sodium's options",
    ),
    recommend(
        "reeses-sodium-options",
        "sodium",
        "Reese's Sodium Options is a Sodium UI addon",
    ),
    recommend(
        "oculus",
        "rubidium",
        "Oculus is the shader companion for Rubidium/Embeddium",
    ),
    recommend(
        "oculus",
        "embeddium",
        "Oculus is the shader companion for Embeddium",
    ),
    recommend(
        "create",
        "jei",
        "JEI surfaces Create's many custom recipe types",
    ),
    recommend(
        "emi",
        "jade",
        "EMI + Jade are a common item/tooltip information pairing",
    ),
];

const fn incompat(subject: &'static str, related: &'static str) -> (&'static str, Curated) {
    (
        subject,
        Curated {
            related,
            kind: "known_incompatible",
            reason: "curated: both replace the renderer / are the same renderer",
            confidence: 0.95,
        },
    )
}

const fn recommend(
    subject: &'static str,
    related: &'static str,
    reason: &'static str,
) -> (&'static str, Curated) {
    (
        subject,
        Curated {
            related,
            kind: "recommended_together",
            reason,
            confidence: 0.9,
        },
    )
}

/// Curated relationships declared for `mod_id`.
pub(crate) fn curated_relationships(mod_id: &str) -> Vec<&'static Curated> {
    TABLE
        .iter()
        .filter(|(subject, _)| *subject == mod_id)
        .map(|(_, rel)| rel)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sodium_is_incompatible_with_optifine_and_recommends_iris() {
        let rels = curated_relationships("sodium");
        assert!(
            rels.iter()
                .any(|r| r.related == "optifine" && r.kind == "known_incompatible")
        );
        assert!(
            rels.iter()
                .any(|r| r.related == "iris" && r.kind == "recommended_together")
        );
    }

    #[test]
    fn unknown_mod_has_no_curated_relationships() {
        assert!(curated_relationships("some-random-mod").is_empty());
    }
}
