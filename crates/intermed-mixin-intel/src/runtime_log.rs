//! Runtime log confirmation (plan Phase 11).
//!
//! Static verification produces *hypotheses* ("this injection point probably won't
//! match"). A game log that actually failed to apply the same mixin turns a
//! hypothesis into a *confirmed* finding. This module is a specialized parser for
//! SpongePowered Mixin runtime failures — it pulls the config, mixin class, target,
//! handler, injection point, and failure reason out of the (noisy) log text, then
//! joins those to [`ApplicationSite`]s so a matching static hypothesis is confirmed.
//!
//! It uses plain string scanning (no regex dependency) and is deliberately
//! conservative: a field it cannot extract is left empty rather than guessed.

use serde::{Deserialize, Serialize};

use crate::site::ApplicationSite;

/// Why a mixin failed to apply at runtime (plan Phase 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeFailureReason {
    TargetClassNotFound,
    TargetMethodNotFound,
    InjectionPointNotFound,
    RequireFailed,
    InvalidHandlerSignature,
    LocalCaptureFailed,
    RefmapLoadFailed,
    ConstraintViolation,
    TransformerConflict,
    #[default]
    Unknown,
}

impl RuntimeFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeFailureReason::TargetClassNotFound => "target-class-not-found",
            RuntimeFailureReason::TargetMethodNotFound => "target-method-not-found",
            RuntimeFailureReason::InjectionPointNotFound => "injection-point-not-found",
            RuntimeFailureReason::RequireFailed => "require-failed",
            RuntimeFailureReason::InvalidHandlerSignature => "invalid-handler-signature",
            RuntimeFailureReason::LocalCaptureFailed => "local-capture-failed",
            RuntimeFailureReason::RefmapLoadFailed => "refmap-load-failed",
            RuntimeFailureReason::ConstraintViolation => "constraint-violation",
            RuntimeFailureReason::TransformerConflict => "transformer-conflict",
            RuntimeFailureReason::Unknown => "unknown",
        }
    }
}

/// One Mixin runtime failure extracted from a log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeMixinFailure {
    pub exception_type: String,
    pub config: String,
    pub mixin_class: String,
    pub target_class: String,
    pub handler_method: String,
    pub injection_point: String,
    pub reason: RuntimeFailureReason,
    /// The log line the failure was extracted from (trimmed excerpt).
    pub excerpt: String,
}

/// Classify a failure reason from the message text (first match wins, most specific
/// first). Returns `Unknown` if no known phrase is present.
fn classify_reason(lower: &str) -> RuntimeFailureReason {
    // Order matters: check the more specific phrases before the generic ones.
    if lower.contains("could not find any targets matching")
        || lower.contains("injection point") && lower.contains("could not find")
        || lower.contains("@at") && lower.contains("could not find")
    {
        RuntimeFailureReason::InjectionPointNotFound
    } else if lower.contains("require")
        && (lower.contains("but found 0") || lower.contains("not satisfied"))
    {
        RuntimeFailureReason::RequireFailed
    } else if lower.contains("target class") && lower.contains("not found")
        || lower.contains("could not load") && lower.contains("target")
    {
        RuntimeFailureReason::TargetClassNotFound
    } else if (lower.contains("method") || lower.contains("target"))
        && lower.contains("was not found")
    {
        RuntimeFailureReason::TargetMethodNotFound
    } else if lower.contains("captur") && (lower.contains("fail") || lower.contains("local")) {
        RuntimeFailureReason::LocalCaptureFailed
    } else if lower.contains("refmap") {
        RuntimeFailureReason::RefmapLoadFailed
    } else if lower.contains("incompatible") || lower.contains("signature") {
        RuntimeFailureReason::InvalidHandlerSignature
    } else if lower.contains("constraint") {
        RuntimeFailureReason::ConstraintViolation
    } else if lower.contains("conflict") {
        RuntimeFailureReason::TransformerConflict
    } else {
        RuntimeFailureReason::Unknown
    }
}

/// Extract `(config, mixin_class)` from a `somemod.mixins.json:SomeMixin` reference.
fn extract_config_and_mixin(line: &str) -> Option<(String, String)> {
    let marker = ".mixins.json:";
    let idx = line.find(marker)?;
    // Walk left to the start of the config token. Restrict the boundary set to
    // ASCII delimiters: `char::is_whitespace` also matches multi-byte Unicode
    // spaces (NBSP U+00A0, line separator U+2028, …), and `rfind` returns the
    // *byte* index of such a char — so `i + 1` would land mid-codepoint and the
    // `&line[start..]` slice below would panic on a non-char-boundary.
    let start = line[..idx]
        .rfind([' ', '\t', '(', '['])
        .map(|i| i + 1)
        .unwrap_or(0);
    let config = format!("{}.mixins.json", &line[start..idx]);
    let after = &line[idx + marker.len()..];
    let end = after
        .find(|c: char| c.is_whitespace() || matches!(c, ':' | ';' | ',' | ')' | ']'))
        .unwrap_or(after.len());
    let mixin = after[..end].to_string();
    if mixin.is_empty() {
        return None;
    }
    Some((config, mixin))
}

/// Extract a quoted target like `'tick()V'` or `'tick'` from a message.
fn extract_quoted(line: &str) -> Option<String> {
    let start = line.find('\'')?;
    let rest = &line[start + 1..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

/// Extract the throwable simple name (`InvalidInjectionException`) when present.
fn extract_exception(line: &str) -> String {
    for token in line.split(|c: char| c.is_whitespace() || c == ':') {
        if token.ends_with("Exception") || token.ends_with("Error") {
            return token.rsplit('.').next().unwrap_or(token).to_string();
        }
    }
    String::new()
}

/// Parse all Mixin runtime failures out of a log. Only lines that name a
/// `*.mixins.json:Mixin` reference are treated as structured failures.
pub fn parse_runtime_failures(log: &str) -> Vec<RuntimeMixinFailure> {
    let mut out = Vec::new();
    for raw in log.lines() {
        let line = raw.trim();
        let Some((config, mixin_class)) = extract_config_and_mixin(line) else {
            continue;
        };
        let lower = line.to_ascii_lowercase();
        let reason = classify_reason(&lower);
        let injection_point = match reason {
            RuntimeFailureReason::InjectionPointNotFound
            | RuntimeFailureReason::TargetMethodNotFound => {
                extract_quoted(line).unwrap_or_default()
            }
            _ => String::new(),
        };
        out.push(RuntimeMixinFailure {
            exception_type: extract_exception(line),
            config,
            mixin_class,
            target_class: String::new(),
            handler_method: String::new(),
            injection_point,
            reason,
            excerpt: line.chars().take(300).collect(),
        });
    }
    out
}

/// A static site confirmed (or raised) by a runtime failure (plan Phase 11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteConfirmation {
    pub site_id: String,
    pub reason: RuntimeFailureReason,
    /// How the log failure matched the site (`mixin-class`, `mixin+config`, …).
    pub matched_on: String,
}

/// Does a runtime failure's mixin reference match this site's mixin class? The log
/// form is usually a simple class name (`SomeMixin`) while the site carries the
/// dotted form (`mod.mixin.SomeMixin`), so match on suffix.
fn mixin_matches(failure: &RuntimeMixinFailure, site: &ApplicationSite) -> bool {
    let simple = failure
        .mixin_class
        .rsplit(['.', '$'])
        .next()
        .unwrap_or(&failure.mixin_class);
    site.mixin_class == failure.mixin_class
        || site.mixin_class.rsplit(['.', '$']).next() == Some(simple)
}

/// Join parsed runtime failures to application sites, producing confirmations for
/// the sites whose mixin a failure names. Config equality strengthens the match.
pub fn confirm_sites(
    failures: &[RuntimeMixinFailure],
    sites: &[ApplicationSite],
) -> Vec<SiteConfirmation> {
    let mut out = Vec::new();
    for failure in failures {
        for site in sites {
            if !mixin_matches(failure, site) {
                continue;
            }
            // If the failure names an injection point, only confirm matching sites.
            if !failure.injection_point.is_empty()
                && !site.target_method.contains(&failure.injection_point)
                && !site.site_key.contains(&failure.injection_point)
            {
                continue;
            }
            let matched_on = if site.config_path == failure.config {
                "mixin+config"
            } else {
                "mixin-class"
            };
            out.push(SiteConfirmation {
                site_id: site.site_id.clone(),
                reason: failure.reason,
                matched_on: matched_on.to_string(),
            });
        }
    }
    out.sort_by(|a, b| a.site_id.cmp(&b.site_id));
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "[12:00:00] [main/ERROR]: org.spongepowered.asm.mixin.injection.throwables.InvalidInjectionException: @Inject annotation could not find any targets matching 'tick()V' in somemod.mixins.json:ServerMixin\n\
[12:00:01] [main/INFO]: a normal line with no failure\n\
[12:00:02] [main/ERROR]: Mixin apply failed other.mixins.json:RenderMixin -> refmap could not be read\n";

    #[test]
    fn parses_structured_failures() {
        let failures = parse_runtime_failures(LOG);
        assert_eq!(failures.len(), 2);
        let inj = &failures[0];
        assert_eq!(inj.config, "somemod.mixins.json");
        assert_eq!(inj.mixin_class, "ServerMixin");
        assert_eq!(inj.reason, RuntimeFailureReason::InjectionPointNotFound);
        assert_eq!(inj.injection_point, "tick()V");
        assert_eq!(inj.exception_type, "InvalidInjectionException");

        let refmap = &failures[1];
        assert_eq!(refmap.reason, RuntimeFailureReason::RefmapLoadFailed);
        assert_eq!(refmap.mixin_class, "RenderMixin");
    }

    #[test]
    fn confirms_matching_site() {
        use crate::naming::{NameSource, ResolvedName};
        use crate::refmap::Namespace;

        let failures = parse_runtime_failures(LOG);
        let site = ApplicationSite {
            site_id:
                "somemod::somemod.mixin.ServerMixin::onTick->net.minecraft.Server#tick()V@HEAD"
                    .into(),
            mod_id: "somemod".into(),
            archive: "somemod.jar".into(),
            config_path: "somemod.mixins.json".into(),
            mixin_class: "somemod.mixin.ServerMixin".into(),
            handler_method: "onTick".into(),
            handler_descriptor: String::new(),
            operation: "inject".into(),
            target_class: "net.minecraft.Server".into(),
            target_method: "tick()V".into(),
            at_target: "HEAD".into(),
            at_detail: "HEAD".into(),
            site_key: "tick()V@HEAD".into(),
            namespace: Namespace::Intermediary,
            target_name: ResolvedName {
                original: "tick".into(),
                canonical: "tick()V".into(),
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
        };
        let confirmations = confirm_sites(&failures, std::slice::from_ref(&site));
        assert_eq!(confirmations.len(), 1);
        assert_eq!(confirmations[0].matched_on, "mixin+config");
        assert_eq!(
            confirmations[0].reason,
            RuntimeFailureReason::InjectionPointNotFound
        );
    }

    #[test]
    fn no_false_confirmation_for_unrelated_mixin() {
        let failures = parse_runtime_failures(LOG);
        let sites: Vec<ApplicationSite> = Vec::new();
        assert!(confirm_sites(&failures, &sites).is_empty());
    }
}
