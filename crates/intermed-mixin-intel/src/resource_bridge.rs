//! Mixin → resource/data cross-layer bridge (Layer F ↔ Layer M ↔ Dynamics).
//!
//! Layer M analyzes datapack/resource JSON *statically*; the Dynamics layer tracks
//! *script*-driven runtime mutation (KubeJS removing recipes, etc.). But a third
//! source mutates the very same runtime data and was invisible to both: **mixins
//! that hook Minecraft's data loaders** (`RecipeManager`, `LootManager`,
//! `TagManagerLoader`, `ServerAdvancementLoader`, …). A `@Redirect` on
//! `RecipeManager.apply` can rewrite, drop, or inject recipes at load time — so the
//! static datapack picture Layer M builds may be silently overridden.
//!
//! This module recognizes those data-loader targets on [`ApplicationSite`]s and
//! emits a runtime-resource-mutation signal keyed to the same
//! [`ResourceDomain`](intermed_resource_identity::ResourceDomain) string Layer M and
//! Dynamics use, so a cross-layer rule can correlate all three.

use serde::{Deserialize, Serialize};

use crate::site::ApplicationSite;

/// A Minecraft data subsystem a mixin can hook to mutate runtime resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceSubsystem {
    Recipe,
    LootTable,
    Tag,
    Advancement,
    Predicate,
    ItemModifier,
    Structure,
    Function,
    /// Registry / data-pack contents / reload coordinator — broad data surface.
    Registry,
}

impl ResourceSubsystem {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceSubsystem::Recipe => "recipe",
            ResourceSubsystem::LootTable => "loot-table",
            ResourceSubsystem::Tag => "tag",
            ResourceSubsystem::Advancement => "advancement",
            ResourceSubsystem::Predicate => "predicate",
            ResourceSubsystem::ItemModifier => "item-modifier",
            ResourceSubsystem::Structure => "structure",
            ResourceSubsystem::Function => "function",
            ResourceSubsystem::Registry => "registry",
        }
    }

    /// The [`ResourceDomain`](intermed_resource_identity::ResourceDomain) string this
    /// subsystem loads — the join key against Layer M / Dynamics facts. Subsystems
    /// without a 1:1 datapack domain (registry/function) map to their own label.
    pub fn domain(self) -> &'static str {
        match self {
            ResourceSubsystem::Recipe => "recipe",
            ResourceSubsystem::LootTable => "loot-table",
            ResourceSubsystem::Tag => "tag",
            ResourceSubsystem::Advancement => "advancement",
            ResourceSubsystem::Predicate => "predicate",
            ResourceSubsystem::ItemModifier => "item-modifier",
            ResourceSubsystem::Structure => "structure",
            ResourceSubsystem::Function => "function",
            ResourceSubsystem::Registry => "registry",
        }
    }
}

/// Classify a mixin target class as a data-loader subsystem. Matches the simple
/// class name (yarn/mojmap, version-robust) and the known 1.20.1 intermediary
/// (`class_NNNN`) names so both namespaces resolve.
pub fn classify_resource_loader(target_class: &str) -> Option<ResourceSubsystem> {
    let simple = target_class
        .rsplit(['.', '/'])
        .next()
        .unwrap_or(target_class);
    // Simple-name match (yarn / mojmap), case-insensitive, exact match.
    // IMPORTANT: must be an *exact* match (not a substring) to avoid false positives
    // such as `AdvancedRecipeManager` being classified as the vanilla RecipeManager
    // subsystem and generating bogus Layer-F ↔ Layer-M correlations.
    let lower = simple.to_ascii_lowercase();
    let by_name = |needles: &[&str]| needles.iter().any(|n| lower == *n);

    // Intermediary 1.20.1 data-loader classes.
    let inter = match simple {
        "class_1863" => Some(ResourceSubsystem::Recipe), // RecipeManager
        "class_60" => Some(ResourceSubsystem::LootTable), // LootManager
        "class_3505" => Some(ResourceSubsystem::Tag),    // TagManagerLoader
        "class_2989" => Some(ResourceSubsystem::Advancement), // ServerAdvancementLoader
        "class_2991" => Some(ResourceSubsystem::Function), // FunctionLoader
        "class_5350" => Some(ResourceSubsystem::Registry), // DataPackContents
        "class_3485" => Some(ResourceSubsystem::Structure), // StructureTemplateManager
        "class_2378" | "class_2370" => Some(ResourceSubsystem::Registry), // Registry / SimpleRegistry
        _ => None,
    };
    if inter.is_some() {
        return inter;
    }

    // Named (yarn / mojmap) match. Order: most specific first.
    if by_name(&["recipemanager"]) {
        Some(ResourceSubsystem::Recipe)
    } else if by_name(&["lootmanager", "lootdatamanager", "loottables"]) {
        Some(ResourceSubsystem::LootTable)
    } else if by_name(&["tagmanagerloader", "taggrouploader", "tagloader"]) {
        Some(ResourceSubsystem::Tag)
    } else if by_name(&[
        "serveradvancementloader",
        "advancementmanager",
        "advancementloader",
    ]) {
        Some(ResourceSubsystem::Advancement)
    } else if by_name(&["lootitemfunction", "itemmodifiermanager"]) {
        Some(ResourceSubsystem::ItemModifier)
    } else if by_name(&["lootitemcondition", "predicatemanager"]) {
        Some(ResourceSubsystem::Predicate)
    } else if by_name(&["structuretemplatemanager", "structuremanager"]) {
        Some(ResourceSubsystem::Structure)
    } else if by_name(&["functionloader", "functionmanager"]) {
        Some(ResourceSubsystem::Function)
    } else if by_name(&[
        "datapackcontents",
        "reloadableserverresources",
        "reloadableregistries",
        "registrydataloader",
    ]) {
        Some(ResourceSubsystem::Registry)
    } else {
        None
    }
}

/// How strongly a mixin operation mutates the loaded data (vs. merely observing it).
fn mutation_strength(operation: &str) -> (&'static str, u8) {
    match operation {
        "overwrite" => ("replaces-loader", 90),
        "redirect" | "wrap-operation" => ("rewrites-load-call", 85),
        "modify-return-value" | "modify-expression-value" => ("rewrites-loaded-value", 80),
        "modify-arg" | "modify-args" | "modify-variable" => ("mutates-load-args", 70),
        "inject" => ("hooks-loader", 55),
        _ => ("hooks-loader", 50),
    }
}

/// One mixin that mutates a runtime resource subsystem (Layer F → M/Dynamics bridge).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeResourceMutation {
    pub mod_id: String,
    pub mixin_class: String,
    pub site_id: String,
    pub target_class: String,
    pub subsystem: ResourceSubsystem,
    /// The Layer-M / Dynamics domain string this maps to (join key).
    pub domain: String,
    pub operation: String,
    /// How the operation affects the data (`replaces-loader`, `hooks-loader`, …).
    pub effect: String,
    /// 0–100 confidence this is a genuine runtime mutation of that subsystem.
    pub confidence: u8,
}

/// Detect every site that hooks a Minecraft data-loader, as a runtime-resource
/// mutation. Deduplicated by (site_id) — one mutation per site.
pub fn detect_resource_mutations(sites: &[ApplicationSite]) -> Vec<RuntimeResourceMutation> {
    let mut out = Vec::new();
    for s in sites {
        let Some(subsystem) = classify_resource_loader(&s.target_class) else {
            continue;
        };
        let (effect, base) = mutation_strength(&s.operation);
        // A site we couldn't even resolve gets a confidence haircut.
        let confidence = if s.confidence < 60 {
            base.saturating_sub(15)
        } else {
            base
        };
        out.push(RuntimeResourceMutation {
            mod_id: s.mod_id.clone(),
            mixin_class: s.mixin_class.clone(),
            site_id: s.site_id.clone(),
            target_class: s.target_class.clone(),
            subsystem,
            domain: subsystem.domain().to_string(),
            operation: s.operation.clone(),
            effect: effect.to_string(),
            confidence,
        });
    }
    out.sort_by(|a, b| a.site_id.cmp(&b.site_id));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::{NameSource, ResolvedName};
    use crate::refmap::Namespace;

    fn site(target_class: &str, operation: &str) -> ApplicationSite {
        ApplicationSite {
            site_id: format!("mod::M::h->{target_class}#apply@HEAD"),
            mod_id: "mod".into(),
            archive: "mod.jar".into(),
            config_path: "m.json".into(),
            mixin_class: "mod.M".into(),
            handler_method: "h".into(),
            handler_descriptor: String::new(),
            operation: operation.into(),
            target_class: target_class.into(),
            target_method: "apply()V".into(),
            at_target: "HEAD".into(),
            at_detail: "HEAD".into(),
            site_key: "apply()V@HEAD".into(),
            namespace: Namespace::Intermediary,
            target_name: ResolvedName {
                original: "apply".into(),
                canonical: "apply()V".into(),
                namespace_original: Namespace::Intermediary,
                namespace_canonical: Namespace::Intermediary,
                source: NameSource::IntermediaryDirect,
                confidence: 100,
                reason: String::new(),
            },
            target_resolution: crate::target_res::TargetResolution::Unchecked,
            selector_verification: crate::selector::SelectorVerification::Unchecked,
            signature_check: crate::signature::SignatureCheck::Unchecked,
            local_capture_status: crate::locals::LocalCaptureStatus::NoLocalCapture,
            side: crate::model::Side::Both,
            activation: crate::model::ActivationStatus::ActiveAssumed,
            priority: 1000,
            require: None,
            expect: None,
            allow: None,
            cancellable: false,
            confidence: 100,
            imprecision_reasons: Vec::new(),
        }
    }

    #[test]
    fn mod_recipe_manager_subclass_is_not_a_false_positive() {
        // A mod-owned class whose simple name *contains* "recipemanager" but is NOT
        // the vanilla loader must not be classified as ResourceSubsystem::Recipe.
        // Prior to this fix, `contains("recipemanager")` would return Some(Recipe)
        // for classes like `com.mymod.gui.AdvancedRecipeManager`.
        assert_eq!(
            classify_resource_loader("com.mymod.gui.AdvancedRecipeManager"),
            None
        );
        assert_eq!(
            classify_resource_loader("net.mymod.gui.LootManagerExtension"),
            None
        );
    }

    #[test]
    fn recognizes_named_and_intermediary_loaders() {
        assert_eq!(
            classify_resource_loader("net.minecraft.recipe.RecipeManager"),
            Some(ResourceSubsystem::Recipe)
        );
        assert_eq!(
            classify_resource_loader("net/minecraft/class_1863"),
            Some(ResourceSubsystem::Recipe)
        );
        assert_eq!(
            classify_resource_loader("net.minecraft.loot.LootManager"),
            Some(ResourceSubsystem::LootTable)
        );
        assert_eq!(
            classify_resource_loader("net/minecraft/class_3505"),
            Some(ResourceSubsystem::Tag)
        );
        assert_eq!(classify_resource_loader("net.minecraft.world.World"), None);
    }

    #[test]
    fn redirect_on_recipe_manager_is_a_strong_mutation() {
        let m =
            detect_resource_mutations(&[site("net.minecraft.recipe.RecipeManager", "redirect")]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].subsystem, ResourceSubsystem::Recipe);
        assert_eq!(m[0].domain, "recipe");
        assert_eq!(m[0].effect, "rewrites-load-call");
        assert!(m[0].confidence >= 80);
    }

    #[test]
    fn inject_observer_is_a_weaker_hook() {
        let m = detect_resource_mutations(&[site("net.minecraft.loot.LootManager", "inject")]);
        assert_eq!(m[0].confidence, 55);
        assert_eq!(m[0].effect, "hooks-loader");
    }

    #[test]
    fn non_loader_targets_are_ignored() {
        assert!(
            detect_resource_mutations(&[site("net.minecraft.entity.Entity", "redirect")])
                .is_empty()
        );
    }
}
