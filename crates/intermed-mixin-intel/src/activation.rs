//! Activation & side model (plan Phase 1).
//!
//! Turns the raw provenance of a mixin declaration — which config array it came
//! from (`mixins` / `client` / `server`), any Fabric/Quilt object-form
//! `environment`, and config-level plugin gating — into a first-class
//! [`Side`] and [`ActivationStatus`]. Downstream analysis reads these so a
//! `client`-only vs `server`-only pair is no longer counted as a conflict, and so
//! plugin/constraint-gated mixins carry honest, lower certainty.

use crate::model::{ActivationStatus, MixinConfigRecord, Side};

/// Map a Fabric/Quilt `environment` string to a [`Side`]. `"*"` (or anything
/// unrecognized) means "both", matching the loader's own default.
pub fn side_from_environment(env: &str) -> Side {
    match env.trim().to_ascii_lowercase().as_str() {
        "client" => Side::Client,
        "server" => Side::Server,
        _ => Side::Both,
    }
}

/// Resolve the side of one `mixins`/`client`/`server` array entry: an object-form
/// `{ "config": …, "environment": … }` (Fabric/Quilt) overrides the array default,
/// otherwise the array's own default side applies.
pub fn entry_side(entry: &serde_json::Value, array_default: Side) -> Side {
    if let serde_json::Value::Object(o) = entry {
        if let Some(env) = o.get("environment").and_then(|e| e.as_str()) {
            return side_from_environment(env);
        }
    }
    array_default
}

/// Derive a class-level [`ActivationStatus`] and a human-readable reason for one
/// mixin, given its owning config and resolved [`Side`].
///
/// Without an explicitly chosen analyzed environment we never assert
/// `InactiveBySide` here (that is a *comparison* result, applied when a target side
/// is fixed); the honest class-level verdict is "assumed active" unless a plugin
/// makes it conditional.
pub fn class_activation(config: &MixinConfigRecord, side: Side) -> (ActivationStatus, String) {
    if let Some(plugin) = &config.plugin {
        return (
            ActivationStatus::ConditionalByPlugin,
            format!(
                "config `{}` declares plugin `{plugin}` which can toggle this mixin at load time; \
                 side `{}`",
                config.path,
                side.as_str()
            ),
        );
    }
    (
        ActivationStatus::ActiveAssumed,
        format!(
            "declared in config `{}` with no plugin gating; assumed active on side `{}`",
            config.path,
            side.as_str()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_form_environment_overrides_array_default() {
        let entry = json!({"config": "x", "environment": "client"});
        // Even when listed in the common `mixins` array (default Both), the
        // object-form environment pins it to the client.
        assert_eq!(entry_side(&entry, Side::Both), Side::Client);
    }

    #[test]
    fn bare_string_entry_takes_array_default() {
        let entry = json!("net.example.FooMixin");
        assert_eq!(entry_side(&entry, Side::Server), Side::Server);
    }

    #[test]
    fn star_environment_is_both() {
        assert_eq!(side_from_environment("*"), Side::Both);
        assert_eq!(side_from_environment(""), Side::Both);
    }

    #[test]
    fn client_and_server_are_incompatible_but_both_is_universal() {
        assert!(!Side::Client.compatible_with(Side::Server));
        assert!(!Side::Server.compatible_with(Side::Client));
        assert!(Side::Both.compatible_with(Side::Client));
        assert!(Side::Both.compatible_with(Side::Server));
        assert!(Side::Unknown.compatible_with(Side::Server));
        assert!(Side::Client.compatible_with(Side::Client));
    }

    #[test]
    fn merge_widens_disagreement_to_both() {
        assert_eq!(Side::Client.merge(Side::Server), Side::Both);
        assert_eq!(Side::Client.merge(Side::Client), Side::Client);
        assert_eq!(Side::Unknown.merge(Side::Server), Side::Server);
        assert_eq!(Side::Both.merge(Side::Client), Side::Both);
    }

    #[test]
    fn plugin_makes_activation_conditional() {
        let config = MixinConfigRecord {
            archive: "m.jar".into(),
            path: "m.mixins.json".into(),
            mod_id: "m".into(),
            package: "m.mixin".into(),
            priority: 1000,
            refmap: None,
            mixins: vec!["FooMixin".into()],
            plugin: Some("m.mixin.Plugin".into()),
            mixin_sides: Default::default(),
        };
        let (status, _) = class_activation(&config, Side::Both);
        assert_eq!(status, ActivationStatus::ConditionalByPlugin);

        let mut ungated = config.clone();
        ungated.plugin = None;
        let (status, _) = class_activation(&ungated, Side::Both);
        assert_eq!(status, ActivationStatus::ActiveAssumed);
    }
}
