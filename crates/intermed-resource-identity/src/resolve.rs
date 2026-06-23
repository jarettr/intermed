//! Reference resolution: classifying a referenced namespace against the world,
//! and deriving a resolve state from that class plus the reference's requirement.
//!
//! This is the shared, pure core (no I/O, no fact store) used by both Layer M
//! (which emits `resource_resolve_result` facts) and Layer C (which turns
//! required-missing references into a dependency finding). Keeping it here means
//! "is `ae2` satisfied by an installed `appliedenergistics2`?" is answered one way
//! everywhere — the alias / platform knowledge already lives in this crate.

use std::collections::BTreeSet;

use crate::alias::namespace_aliases;
use crate::namespace::is_platform_namespace;

/// What kind of thing a referenced namespace is, relative to the installed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceClass {
    /// An installed mod / plugin id (or a resource-namespace owner).
    InstalledMod,
    /// Installed under a different id via a known alias or declared `provides`.
    ProvidedAlias,
    /// Vanilla `minecraft`.
    BuiltinMinecraft,
    /// Cross-loader convention namespace (`c`, `common`).
    CommonConvention,
    /// Loader-provided (`forge`, `neoforge`, `fabric`, `quilt`).
    LoaderNamespace,
    /// A plausible mod namespace that nothing installed provides.
    MissingCandidate,
    /// Indeterminate.
    Unknown,
}

impl NamespaceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            NamespaceClass::InstalledMod => "installed-mod",
            NamespaceClass::ProvidedAlias => "provided-alias",
            NamespaceClass::BuiltinMinecraft => "builtin-minecraft",
            NamespaceClass::CommonConvention => "common-convention",
            NamespaceClass::LoaderNamespace => "loader-namespace",
            NamespaceClass::MissingCandidate => "missing-candidate",
            NamespaceClass::Unknown => "unknown",
        }
    }

    /// Whether this class means the namespace is satisfied (present in the world).
    pub fn is_satisfied(self) -> bool {
        matches!(
            self,
            NamespaceClass::InstalledMod
                | NamespaceClass::ProvidedAlias
                | NamespaceClass::BuiltinMinecraft
                | NamespaceClass::CommonConvention
                | NamespaceClass::LoaderNamespace
        )
    }
}

/// Classify a namespace against the installed id set (mod ids + provided aliases +
/// resource-namespace owners). Platform namespaces are recognized first so they
/// are never mistaken for a missing mod.
#[must_use]
pub fn classify_namespace(ns: &str, installed: &BTreeSet<String>) -> NamespaceClass {
    match ns {
        "minecraft" => return NamespaceClass::BuiltinMinecraft,
        "c" | "common" => return NamespaceClass::CommonConvention,
        "forge" | "neoforge" | "fabric" | "fabric-api" | "quilt" | "quilt_loader" => {
            return NamespaceClass::LoaderNamespace;
        }
        _ => {}
    }
    if is_platform_namespace(ns) {
        return NamespaceClass::LoaderNamespace;
    }
    if installed.contains(ns) {
        return NamespaceClass::InstalledMod;
    }
    if namespace_aliases(ns).iter().any(|a| installed.contains(*a)) {
        return NamespaceClass::ProvidedAlias;
    }
    NamespaceClass::MissingCandidate
}

/// How a specific reference resolves — the namespace class combined with whether
/// the reference is required and whether it is gated by a load condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveState {
    /// Target's namespace is installed directly.
    Present,
    /// Installed via a known alias / `provides`.
    PresentViaAlias,
    /// Vanilla namespace.
    Builtin,
    /// Convention/loader namespace (`c`, `forge`, …).
    CommonNamespace,
    /// Missing, but the reference is optional or gated by a load condition.
    OptionalMissing,
    /// Missing and unconditionally required — the actionable case.
    RequiredMissing,
    /// The namespace itself is absent and no reference makes it required.
    NamespaceAbsent,
    /// The reference id was dynamic / could not be determined.
    UnknownDynamic,
    /// The defining resource used a custom serializer we cannot interpret.
    ParserOpaque,
}

impl ResolveState {
    pub fn as_str(self) -> &'static str {
        match self {
            ResolveState::Present => "present",
            ResolveState::PresentViaAlias => "present-via-alias",
            ResolveState::Builtin => "builtin",
            ResolveState::CommonNamespace => "common-namespace",
            ResolveState::OptionalMissing => "optional-missing",
            ResolveState::RequiredMissing => "required-missing",
            ResolveState::NamespaceAbsent => "namespace-absent",
            ResolveState::UnknownDynamic => "unknown-dynamic",
            ResolveState::ParserOpaque => "parser-opaque",
        }
    }

    /// Only `RequiredMissing` is an actionable finding; everything else is either
    /// satisfied or a low-signal note/info.
    pub fn is_actionable_missing(self) -> bool {
        self == ResolveState::RequiredMissing
    }
}

/// Derive the resolve state for a reference into `class`, given whether the
/// reference is required and whether it is gated by a load condition.
///
/// Conditional awareness (§21): a reference gated by `modloaded:X` (or any
/// condition) is **never** `RequiredMissing` — the author intentionally guarded
/// it, so a missing target there is `OptionalMissing`, not a problem.
#[must_use]
pub fn resolve_state(class: NamespaceClass, required: bool, conditioned: bool) -> ResolveState {
    match class {
        NamespaceClass::InstalledMod => ResolveState::Present,
        NamespaceClass::ProvidedAlias => ResolveState::PresentViaAlias,
        NamespaceClass::BuiltinMinecraft => ResolveState::Builtin,
        NamespaceClass::CommonConvention | NamespaceClass::LoaderNamespace => {
            ResolveState::CommonNamespace
        }
        NamespaceClass::MissingCandidate | NamespaceClass::Unknown => {
            // Required *and* unconditioned is the only actionable miss; a
            // conditioned or optional reference is `OptionalMissing` (the author
            // guarded it, so its absence is expected — conditional awareness §21).
            if required && !conditioned {
                ResolveState::RequiredMissing
            } else {
                ResolveState::OptionalMissing
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classifies_platform_and_installed_and_alias() {
        let world = installed(&["create", "appliedenergistics2"]);
        assert_eq!(
            classify_namespace("minecraft", &world),
            NamespaceClass::BuiltinMinecraft
        );
        assert_eq!(
            classify_namespace("c", &world),
            NamespaceClass::CommonConvention
        );
        assert_eq!(
            classify_namespace("forge", &world),
            NamespaceClass::LoaderNamespace
        );
        assert_eq!(
            classify_namespace("create", &world),
            NamespaceClass::InstalledMod
        );
        // ae2 references resolve to installed appliedenergistics2 via alias.
        assert_eq!(
            classify_namespace("ae2", &world),
            NamespaceClass::ProvidedAlias
        );
        assert_eq!(
            classify_namespace("thermal", &world),
            NamespaceClass::MissingCandidate
        );
    }

    #[test]
    fn conditioned_missing_is_not_required_missing() {
        let c = NamespaceClass::MissingCandidate;
        assert_eq!(resolve_state(c, true, false), ResolveState::RequiredMissing);
        // Same required reference, but gated by a condition → optional.
        assert_eq!(resolve_state(c, true, true), ResolveState::OptionalMissing);
        assert_eq!(
            resolve_state(c, false, false),
            ResolveState::OptionalMissing
        );
    }

    #[test]
    fn satisfied_states() {
        assert_eq!(
            resolve_state(NamespaceClass::InstalledMod, true, false),
            ResolveState::Present
        );
        assert_eq!(
            resolve_state(NamespaceClass::ProvidedAlias, true, false),
            ResolveState::PresentViaAlias
        );
        assert!(!ResolveState::Present.is_actionable_missing());
        assert!(ResolveState::RequiredMissing.is_actionable_missing());
    }
}
