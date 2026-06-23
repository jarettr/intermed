//! Semantic impact model — principled severity for Layer M.
//!
//! Severity must not be hand-assigned inside each domain parser/rule (it drifts
//! and becomes inconsistent). Instead every semantic diff declares *what kind of
//! impact* it has on the game, and severity is derived centrally from
//! `impact + confidence`. Adding a new diff kind then only requires saying what it
//! affects, not re-deriving a severity by gut feel.

use intermed_doctor_core::evidence::Severity;

/// What a semantic disagreement actually changes for the player / load.
///
/// Ordered roughly by seriousness, but severity is computed by
/// [`severity_for`] (which folds in confidence), not by this order alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticImpact {
    /// No player-visible effect (metadata-only difference).
    None,
    /// Purely cosmetic (visual/text) and low stakes.
    Cosmetic,
    /// Displayed text / translations.
    Localization,
    /// Client-side visuals (models, atlases, textures).
    AssetVisual,
    /// A behaviour change: what the player crafts, obtains, or triggers.
    GameplayBehavior,
    /// A cross-mod compatibility nuance (often intentional; rarely breaking).
    CompatRisk,
    /// A data pack may fail to load (missing serializer / hard reference).
    DatapackLoadRisk,
    /// A client asset may fail to load.
    ClientLoadRisk,
    /// A server-side load problem.
    ServerLoadRisk,
    /// Likely to crash.
    CrashRisk,
}

impl SemanticImpact {
    pub fn as_str(self) -> &'static str {
        match self {
            SemanticImpact::None => "none",
            SemanticImpact::Cosmetic => "cosmetic",
            SemanticImpact::Localization => "localization",
            SemanticImpact::AssetVisual => "asset-visual",
            SemanticImpact::GameplayBehavior => "gameplay-behavior",
            SemanticImpact::CompatRisk => "compat-risk",
            SemanticImpact::DatapackLoadRisk => "datapack-load-risk",
            SemanticImpact::ClientLoadRisk => "client-load-risk",
            SemanticImpact::ServerLoadRisk => "server-load-risk",
            SemanticImpact::CrashRisk => "crash-risk",
        }
    }

    /// Human label for the report's "Impact:" line.
    pub fn label(self) -> &'static str {
        match self {
            SemanticImpact::None => "no player-visible effect",
            SemanticImpact::Cosmetic => "cosmetic",
            SemanticImpact::Localization => "displayed text may change",
            SemanticImpact::AssetVisual => "visuals may change",
            SemanticImpact::GameplayBehavior => "gameplay behavior changes",
            SemanticImpact::CompatRisk => "cross-mod compatibility nuance",
            SemanticImpact::DatapackLoadRisk => "data pack may fail to load",
            SemanticImpact::ClientLoadRisk => "client asset may fail to load",
            SemanticImpact::ServerLoadRisk => "server may fail to load",
            SemanticImpact::CrashRisk => "may crash",
        }
    }
}

/// Derive severity from impact and the analysis confidence.
///
/// The confidence gate is what lets two same-impact situations differ: a model
/// override is `ClientLoadRisk` but models are routinely runtime-generated, so its
/// confidence is below the warn threshold → `Note`; an atlas override is
/// `AssetVisual` with high confidence → `Warn`.
#[must_use]
pub fn severity_for(impact: SemanticImpact, confidence: f32) -> Severity {
    /// Confidence at/above which a load-risk / visual impact escalates to Warn.
    const WARN_GATE: f32 = 0.85;
    match impact {
        SemanticImpact::CrashRisk => Severity::Error,
        SemanticImpact::GameplayBehavior
        | SemanticImpact::DatapackLoadRisk
        | SemanticImpact::ServerLoadRisk => {
            if confidence >= WARN_GATE {
                Severity::Warn
            } else {
                Severity::Note
            }
        }
        SemanticImpact::AssetVisual | SemanticImpact::ClientLoadRisk => {
            if confidence >= WARN_GATE {
                Severity::Warn
            } else {
                Severity::Note
            }
        }
        SemanticImpact::Localization | SemanticImpact::Cosmetic | SemanticImpact::CompatRisk => {
            Severity::Note
        }
        SemanticImpact::None => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gameplay_high_confidence_warns() {
        assert_eq!(
            severity_for(SemanticImpact::GameplayBehavior, 0.9),
            Severity::Warn
        );
    }

    #[test]
    fn client_load_low_confidence_is_note() {
        // Models are runtime-generatable → confidence below the gate → Note.
        assert_eq!(
            severity_for(SemanticImpact::ClientLoadRisk, 0.8),
            Severity::Note
        );
        assert_eq!(
            severity_for(SemanticImpact::AssetVisual, 0.9),
            Severity::Warn
        );
    }

    #[test]
    fn compat_and_localization_are_notes() {
        assert_eq!(
            severity_for(SemanticImpact::CompatRisk, 1.0),
            Severity::Note
        );
        assert_eq!(
            severity_for(SemanticImpact::Localization, 1.0),
            Severity::Note
        );
    }

    #[test]
    fn crash_is_error() {
        assert_eq!(
            severity_for(SemanticImpact::CrashRisk, 0.5),
            Severity::Error
        );
    }
}
