//! Extensible hot-path classification for mixin targets.
//!
//! Default rules mirror Phase-4 behaviour (simple class-name heuristics) and add
//! optional package-prefix and injected-method name rules. Callers can extend or
//! override via [`HotPathRules`] for pack-specific tuning.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::class_parser::RawInjection;

/// Default hot-path tags keyed by lowercased simple class name.
pub fn default_rules() -> HotPathRules {
    let mut tags = BTreeMap::new();
    for (simple, tag) in [
        ("worldrenderer", "world-render"),
        ("levelrenderer", "world-render"),
        ("gamemode", "world-render"),
        ("minecraft", "client-tick"),
        ("minecraftserver", "server-tick"),
        ("serverlevel", "server-tick"),
        ("serverworld", "server-tick"),
        ("chunkmap", "chunk"),
        ("chunkmanager", "chunk"),
        ("chunkstorage", "chunk"),
        ("chunkgenerator", "chunk"),
        ("entity", "entity"),
        ("livingentity", "entity"),
        ("mob", "entity"),
        ("connection", "network"),
        ("servergamepacketlistenerimpl", "network"),
        ("registry", "registry"),
        ("reloadableregistry", "registry"),
        ("recipemanager", "registry"),
    ] {
        tags.insert(simple.to_string(), tag.to_string());
    }

    let mut package_prefix = BTreeMap::new();
    for (prefix, tag) in [
        ("net.minecraft.client.render", "world-render"),
        ("net.minecraft.client.gui", "client-ui"),
        ("net.minecraft.server.level", "server-tick"),
        ("net.minecraft.world.level.chunk", "chunk"),
        ("net.minecraft.network", "network"),
    ] {
        package_prefix.insert(prefix.to_string(), tag.to_string());
    }

    let mut method_names = BTreeMap::new();
    for (name, tag) in [
        ("tick", "server-tick"),
        ("render", "world-render"),
        ("onrender", "world-render"),
        ("handle", "network"),
        ("load", "chunk"),
    ] {
        method_names.insert(name.to_string(), tag.to_string());
    }

    HotPathRules {
        simple_class: tags,
        package_prefix,
        method_names,
    }
}

/// Configurable hot-path rules (serializable for future config file support).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotPathRules {
    /// Lowercased simple class name → tag.
    pub simple_class: BTreeMap<String, String>,
    /// Dotted package prefix → tag (longest prefix wins).
    #[serde(default)]
    pub package_prefix: BTreeMap<String, String>,
    /// Injected/resolves method bare name → tag.
    #[serde(default)]
    pub method_names: BTreeMap<String, String>,
}

impl Default for HotPathRules {
    fn default() -> Self {
        default_rules()
    }
}

impl HotPathRules {
    /// Return a hot-path tag when `target` matches a rule.
    pub fn tag_for(&self, target: &str) -> Option<String> {
        if let Some(tag) = self.tag_by_simple_name(target) {
            return Some(tag);
        }
        self.tag_by_package_prefix(target)
    }

    /// Classify using target FQN plus resolved injection method names.
    pub fn tag_for_injection(&self, target: &str, method_display: &str) -> Option<String> {
        self.tag_for(target)
            .or_else(|| self.tag_by_method_name(method_display))
    }

    /// Merge additional rules on top of defaults (later entries win).
    pub fn with_extra(mut self, extra: BTreeMap<String, String>) -> Self {
        for (k, v) in extra {
            self.simple_class.insert(k.to_ascii_lowercase(), v);
        }
        self
    }

    fn tag_by_simple_name(&self, target: &str) -> Option<String> {
        let simple = target.rsplit('.').next().unwrap_or(target);
        self.simple_class.get(&simple.to_ascii_lowercase()).cloned()
    }

    fn tag_by_package_prefix(&self, target: &str) -> Option<String> {
        let mut best: Option<(&str, &str)> = None;
        for (prefix, tag) in &self.package_prefix {
            if target.starts_with(prefix.as_str())
                && best.is_none_or(|(p, _)| prefix.len() > p.len())
            {
                best = Some((prefix.as_str(), tag.as_str()));
            }
        }
        best.map(|(_, tag)| tag.to_string())
    }

    fn tag_by_method_name(&self, method_display: &str) -> Option<String> {
        let bare = method_display
            .split('(')
            .next()
            .unwrap_or(method_display)
            .rsplit('.')
            .next()
            .unwrap_or(method_display)
            .to_ascii_lowercase();
        self.method_names.get(&bare).cloned()
    }
}

/// True when any target or injection method in `targets` / `injections` is hot.
pub fn any_hot_path(
    rules: &HotPathRules,
    targets: &[String],
    injections: &[RawInjection],
) -> Vec<String> {
    let mut out = Vec::new();
    for target in targets {
        if let Some(tag) = rules.tag_for(target) {
            push_unique(&mut out, tag);
        }
    }
    for inj in injections {
        for method in &inj.methods {
            if let Some(tag) =
                rules.tag_for_injection(targets.first().map(String::as_str).unwrap_or(""), method)
            {
                push_unique(&mut out, tag);
            }
        }
    }
    out
}

fn push_unique(out: &mut Vec<String>, tag: String) {
    if !out.iter().any(|t| t == &tag) {
        out.push(tag);
    }
}
