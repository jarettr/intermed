//! Runtime classpath coverage model (plan Phase 4).
//!
//! An "apply failure" that says a target class is *missing* is only as strong as
//! the classpath the analyzer actually saw. A class absent from the Minecraft jar
//! might still exist at runtime — provided by a library, the loader, or a shaded
//! dependency the index never ingested. This module makes that explicit: it records
//! which scopes were indexed and at what [`CoverageLevel`], so absence-based
//! conclusions never sound more certain than the coverage permits.

use serde::{Deserialize, Serialize};

use crate::apply_failure::TargetClassIndex;

/// How complete the analyzer's view of the runtime classpath is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageLevel {
    /// Only mod jars were indexed — Minecraft/library absence proves nothing.
    ModsOnly,
    /// Only Minecraft classes were indexed (no mod target classes seen).
    MinecraftOnly,
    /// Minecraft + mod jars indexed (the common `--minecraft-jar` case).
    MinecraftAndMods,
    /// Minecraft + mods + libraries — absence of a library class is meaningful.
    MinecraftModsLibraries,
    /// The full runtime classpath was reconstructed.
    RuntimeComplete,
    /// Nothing was indexed / coverage is indeterminate.
    #[default]
    Unknown,
}

impl CoverageLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageLevel::ModsOnly => "mods-only",
            CoverageLevel::MinecraftOnly => "minecraft-only",
            CoverageLevel::MinecraftAndMods => "minecraft-and-mods",
            CoverageLevel::MinecraftModsLibraries => "minecraft-mods-libraries",
            CoverageLevel::RuntimeComplete => "runtime-complete",
            CoverageLevel::Unknown => "unknown",
        }
    }

    /// `true` when the absence of a class on this side can be trusted as a real
    /// missing target. Without library/loader coverage, only Minecraft absence is
    /// conclusive (and only when Minecraft was indexed at all).
    pub fn minecraft_absence_conclusive(self) -> bool {
        matches!(
            self,
            CoverageLevel::MinecraftOnly
                | CoverageLevel::MinecraftAndMods
                | CoverageLevel::MinecraftModsLibraries
                | CoverageLevel::RuntimeComplete
        )
    }
}

/// What the analyzer actually had loaded when verifying mixin application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClasspathCoverage {
    pub level: CoverageLevel,
    /// Minecraft classes were indexed (e.g. via `--minecraft-jar`).
    pub minecraft: bool,
    /// Mod jar classes were indexed (always, when a pack was scanned).
    pub mods: bool,
    /// Library jars were indexed.
    pub libraries: bool,
    /// Loader classes were indexed.
    pub loader: bool,
    pub minecraft_classes: usize,
    pub mod_classes: usize,
    /// Scopes that were *not* indexed — absence-based conclusions about classes
    /// these scopes could provide are necessarily inconclusive (plan Phase 15).
    pub missing_scopes: Vec<String>,
}

impl ClasspathCoverage {
    /// Derive coverage from the target-class index built during scanning.
    pub fn from_index(index: &TargetClassIndex) -> Self {
        let (minecraft_classes, mod_classes) = index.class_scope_counts();
        let minecraft = index.has_minecraft_coverage();
        let mods = mod_classes > 0;
        // Libraries / loader / shaded deps are not yet ingested into the index.
        let libraries = false;
        let loader = false;

        let level = match (minecraft, mods) {
            (false, false) => CoverageLevel::Unknown,
            (true, false) => CoverageLevel::MinecraftOnly,
            (false, true) => CoverageLevel::ModsOnly,
            (true, true) => CoverageLevel::MinecraftAndMods,
        };

        let mut missing_scopes = Vec::new();
        if !minecraft {
            missing_scopes.push("minecraft".to_string());
        }
        if !libraries {
            missing_scopes.push("libraries".to_string());
        }
        if !loader {
            missing_scopes.push("loader".to_string());
        }

        ClasspathCoverage {
            level,
            minecraft,
            mods,
            libraries,
            loader,
            minecraft_classes,
            mod_classes,
            missing_scopes,
        }
    }

    /// One-line summary for `--explain` / reports.
    pub fn summary(&self) -> String {
        format!(
            "classpath coverage `{}` ({} Minecraft + {} mod classes indexed; not indexed: {})",
            self.level.as_str(),
            self.minecraft_classes,
            self.mod_classes,
            if self.missing_scopes.is_empty() {
                "none".to_string()
            } else {
                self.missing_scopes.join(", ")
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_index_is_unknown_coverage() {
        let index = TargetClassIndex::new();
        let cov = ClasspathCoverage::from_index(&index);
        assert_eq!(cov.level, CoverageLevel::Unknown);
        assert!(!cov.level.minecraft_absence_conclusive());
        assert!(cov.missing_scopes.contains(&"minecraft".to_string()));
        // Mods/minecraft both absent ⇒ also flagged as missing scopes.
        assert!(cov.missing_scopes.contains(&"libraries".to_string()));
    }

    #[test]
    fn coverage_level_gating() {
        assert!(CoverageLevel::MinecraftAndMods.minecraft_absence_conclusive());
        assert!(CoverageLevel::MinecraftOnly.minecraft_absence_conclusive());
        assert!(!CoverageLevel::ModsOnly.minecraft_absence_conclusive());
        assert!(!CoverageLevel::Unknown.minecraft_absence_conclusive());
        assert!(CoverageLevel::RuntimeComplete.minecraft_absence_conclusive());
    }
}
