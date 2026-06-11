//! The twelve diagnostic layers (A–L) and the phase that brings each online.
//!
//! Every [`Collector`](crate::Collector) declares its layer. The report uses
//! this to show which layers ran and which are deferred to a future phase — so
//! the roadmap is always visible in the tool's own output.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layer {
    TargetDetection,  // A
    Metadata,         // B
    Dependency,       // C
    Log,              // D
    Resource,         // E
    Mixin,            // F
    Security,         // G
    Sbom,             // H
    Performance,      // I
    Rules,            // J
    Lab,              // K
    RuntimePreflight, // L
}

impl Layer {
    /// The letter used throughout the design doc.
    pub fn code(&self) -> &'static str {
        match self {
            Layer::TargetDetection => "A",
            Layer::Metadata => "B",
            Layer::Dependency => "C",
            Layer::Log => "D",
            Layer::Resource => "E",
            Layer::Mixin => "F",
            Layer::Security => "G",
            Layer::Sbom => "H",
            Layer::Performance => "I",
            Layer::Rules => "J",
            Layer::Lab => "K",
            Layer::RuntimePreflight => "L",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Layer::TargetDetection => "Target / environment detection",
            Layer::Metadata => "Mod & plugin metadata",
            Layer::Dependency => "Dependency / version reasoner",
            Layer::Log => "Log / crash analyzer",
            Layer::Resource => "Resource / data conflicts (VFS)",
            Layer::Mixin => "Mixin intelligence",
            Layer::Security => "Security / supply-chain audit",
            Layer::Sbom => "SBOM / provenance",
            Layer::Performance => "Performance evidence (spark)",
            Layer::Rules => "Rule engine",
            Layer::Lab => "Compatibility lab",
            Layer::RuntimePreflight => "Runtime preflight",
        }
    }

    /// The phase in which this layer becomes a working feature.
    pub fn phase(&self) -> u8 {
        match self {
            Layer::TargetDetection
            | Layer::Metadata
            | Layer::Dependency
            | Layer::Log
            | Layer::Rules => 1,
            Layer::Resource => 3,
            Layer::Mixin => 4,
            Layer::Security | Layer::Sbom => 6,
            Layer::Performance => 7,
            Layer::Lab => 8,
            Layer::RuntimePreflight => 9,
        }
    }
}
