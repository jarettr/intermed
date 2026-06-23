//! Performance correlation match quality (plan Phase 12).
//!
//! Correlating a Spark hot method to a mixin at *class* or *mod* granularity is too
//! coarse — it makes "this mod is slow" sound like "this handler is the cause".
//! [`MatchQuality`] grades how precisely a hot method lines up with an
//! [`ApplicationSite`], so only a high-quality match on a destructive handler is
//! allowed to drive a high-severity performance finding.

use serde::{Deserialize, Serialize};

use crate::site::ApplicationSite;

/// How precisely a Spark hot method matches a mixin application site, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MatchQuality {
    /// Same owner class, method name *and* descriptor.
    ExactSignature,
    /// Same owner class and method name (descriptor unknown/unmatched).
    ExactOwnerMethod,
    /// Owner+method matched only after mapping normalization.
    MappedOwnerMethod,
    /// Same exact owner class, but a different method.
    ExactClassOnly,
    /// Same class by an alias / different namespace form.
    AliasClassOnly,
    /// Only the simple class name matched (different package).
    SimpleNameOnly,
    /// Only the owning mod matched (no class/method correspondence).
    HotModOnly,
    /// No correspondence.
    #[default]
    NoMatch,
}

impl MatchQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchQuality::ExactSignature => "exact-signature",
            MatchQuality::ExactOwnerMethod => "exact-owner-method",
            MatchQuality::MappedOwnerMethod => "mapped-owner-method",
            MatchQuality::ExactClassOnly => "exact-class-only",
            MatchQuality::AliasClassOnly => "alias-class-only",
            MatchQuality::SimpleNameOnly => "simple-name-only",
            MatchQuality::HotModOnly => "hot-mod-only",
            MatchQuality::NoMatch => "no-match",
        }
    }

    /// `true` when the match pins the hot cost to the exact woven method/site
    /// (the only quality strong enough to anchor a high-severity perf finding).
    pub fn is_method_exact(self) -> bool {
        matches!(
            self,
            MatchQuality::ExactSignature
                | MatchQuality::ExactOwnerMethod
                | MatchQuality::MappedOwnerMethod
        )
    }
}

/// `true` when an operation rewrites/replaces behaviour (so weaving cost lands on
/// the hot path rather than merely observing it).
pub fn is_destructive_operation(operation: &str) -> bool {
    matches!(
        operation,
        "overwrite"
            | "redirect"
            | "wrap-operation"
            | "modify-variable"
            | "modify-arg"
            | "modify-args"
    )
}

fn simple_name(class: &str) -> &str {
    class.rsplit(['.', '/']).next().unwrap_or(class)
}

fn normalize_class(class: &str) -> String {
    class.replace('/', ".")
}

fn method_name(reference: &str) -> &str {
    reference.split(['(', ' ', ':']).next().unwrap_or(reference)
}

fn descriptor(reference: &str) -> Option<&str> {
    reference.find('(').map(|i| &reference[i..])
}

/// Grade how precisely a hot method (owner class, method name, optional descriptor)
/// matches the site's target method.
pub fn grade_match(
    hot_owner: &str,
    hot_method: &str,
    hot_descriptor: Option<&str>,
    site: &ApplicationSite,
) -> MatchQuality {
    let hot_owner = normalize_class(hot_owner);
    let site_owner = normalize_class(&site.target_class);
    let site_method = method_name(&site.target_method);
    let hot_method_name = method_name(hot_method);

    if hot_owner == site_owner {
        if hot_method_name == site_method {
            let site_desc = descriptor(&site.target_method);
            match (hot_descriptor, site_desc) {
                (Some(a), Some(b)) if a == b => MatchQuality::ExactSignature,
                _ => MatchQuality::ExactOwnerMethod,
            }
        } else {
            MatchQuality::ExactClassOnly
        }
    } else if simple_name(&hot_owner) == simple_name(&site_owner) {
        // Same simple name in a different package. Only treat this as a real namespace
        // alias (`AliasClassOnly`) when one side carries an intermediary `class_NNNN`
        // pattern — indicating these are two namespace forms of the same Minecraft class.
        // Otherwise (e.g. `com.mod_a.Util` vs `net.minecraft.util.Util`) it is a
        // coincidental name collision and must be `SimpleNameOnly` to avoid generating
        // spurious hot-path × mixin correlations in reports.
        let is_namespace_alias = simple_name(&hot_owner).starts_with("class_")
            || simple_name(&site_owner).starts_with("class_");
        if hot_method_name == site_method && is_namespace_alias {
            MatchQuality::AliasClassOnly
        } else {
            MatchQuality::SimpleNameOnly
        }
    } else if site.mod_id == hot_owner || hot_owner.contains(&site.mod_id) {
        MatchQuality::HotModOnly
    } else {
        MatchQuality::NoMatch
    }
}

/// May a correlation drive a *high-severity* performance finding? Only when the hot
/// method is pinned exactly, the handler is destructive, the side matches, and the
/// site resolution is confident (plan Phase 12).
pub fn allows_high_severity(
    quality: MatchQuality,
    operation: &str,
    side_matches: bool,
    site_confidence: u8,
) -> bool {
    quality.is_method_exact()
        && is_destructive_operation(operation)
        && side_matches
        && site_confidence >= 70
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::{NameSource, ResolvedName};
    use crate::refmap::Namespace;

    fn site(
        target_class: &str,
        target_method: &str,
        operation: &str,
        confidence: u8,
    ) -> ApplicationSite {
        ApplicationSite {
            site_id: "s".into(),
            mod_id: "mod".into(),
            archive: "mod.jar".into(),
            config_path: "m.json".into(),
            mixin_class: "mod.M".into(),
            handler_method: "h".into(),
            handler_descriptor: String::new(),
            operation: operation.into(),
            target_class: target_class.into(),
            target_method: target_method.into(),
            at_target: "HEAD".into(),
            at_detail: "HEAD".into(),
            site_key: format!("{target_method}@HEAD"),
            namespace: Namespace::Intermediary,
            target_name: ResolvedName {
                original: "m".into(),
                canonical: target_method.into(),
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
            confidence,
            imprecision_reasons: Vec::new(),
        }
    }

    #[test]
    fn exact_signature_is_best() {
        let s = site("net.minecraft.Server", "tick()V", "redirect", 100);
        assert_eq!(
            grade_match("net/minecraft/Server", "tick", Some("()V"), &s),
            MatchQuality::ExactSignature
        );
        assert_eq!(
            grade_match("net.minecraft.Server", "tick", None, &s),
            MatchQuality::ExactOwnerMethod
        );
        assert_eq!(
            grade_match("net.minecraft.Server", "render", None, &s),
            MatchQuality::ExactClassOnly
        );
    }

    #[test]
    fn simple_name_only_is_weak() {
        let s = site("net.minecraft.Server", "tick()V", "redirect", 100);
        assert_eq!(
            grade_match("com.other.Server", "render", None, &s),
            MatchQuality::SimpleNameOnly
        );
    }

    #[test]
    fn coincidental_simple_name_match_is_not_alias() {
        // `com.mod_a.Util` and `net.minecraft.util.Util` share a simple name but are
        // completely unrelated classes. Before this fix, a matching method name would
        // have promoted this to AliasClassOnly, creating spurious hot-path correlations.
        // Neither side contains `class_` so it must stay SimpleNameOnly.
        let s = site("net.minecraft.util.Util", "process()V", "redirect", 100);
        assert_eq!(
            grade_match("com.mod_a.Util", "process", None, &s),
            MatchQuality::SimpleNameOnly
        );

        // Two intermediary namespace paths for the same class both carry `class_NNNN`
        // in their simple name — but here they're identical, so it's ExactClassOnly.
        // The AliasClassOnly branch requires: same simple name, different full paths,
        // at least one side starts_with("class_"). This scenario only occurs when
        // one mod uses yarn/mojmap naming and the other uses the raw intermediary.
        // Since yarn simple names differ from class_NNNN names, the most we can
        // verify here is the guard: RecipeManager (no class_ prefix) stays SimpleNameOnly.
        let s2 = site(
            "net.minecraft.recipe.RecipeManager",
            "tick()V",
            "redirect",
            100,
        );
        assert_eq!(
            grade_match("com.mymod.RecipeManager", "render", None, &s2),
            MatchQuality::SimpleNameOnly,
            "Non-matching method should stay SimpleNameOnly"
        );
        assert_eq!(
            grade_match("com.mymod.RecipeManager", "tick", None, &s2),
            MatchQuality::SimpleNameOnly,
            "Matching method but no class_ prefix must NOT promote to AliasClassOnly"
        );
    }

    #[test]
    fn high_severity_gating() {
        let s = site("net.minecraft.Server", "tick()V", "redirect", 90);
        // Exact + destructive + side + confident ⇒ allowed.
        assert!(allows_high_severity(
            MatchQuality::ExactSignature,
            "redirect",
            true,
            90
        ));
        // Observer inject ⇒ not destructive ⇒ not allowed.
        assert!(!allows_high_severity(
            MatchQuality::ExactSignature,
            "inject",
            true,
            90
        ));
        // Weak match ⇒ not allowed.
        assert!(!allows_high_severity(
            MatchQuality::SimpleNameOnly,
            "redirect",
            true,
            90
        ));
        // Low confidence ⇒ not allowed.
        assert!(!allows_high_severity(
            MatchQuality::ExactSignature,
            "redirect",
            true,
            40
        ));
        let _ = s;
    }
}
