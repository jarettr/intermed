//! Rule-pack distribution: registry fetch, HTTPS install, and doctor resolution.
//!
//! Closes the community loop: `rules update` can fetch signed packs over HTTPS,
//! and `doctor` merges installed packs with the embedded core without recompiling
//! the binary.

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;

use crate::merge::merge_rule_packs;
use crate::model::RulePack;
use crate::pack::{default_core_pack_v2, default_core_pack_without_mixin, load_rule_pack};
use crate::signing::{
    canonical_digest, default_registry, default_rule_pack_install_dir, install_pack_from_registry,
    load_registry_from_source, trusted_keys_for_publisher, verify_rule_pack_trust, PackOrigin,
    RuleRegistry, SigningError, TrustLevel, TrustPolicy,
};
/// Doctor-facing selection of which packs to merge into the embedded core.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulePackSelection {
    /// Extra pack paths or installed pack ids (repeatable CLI `--rule-pack`).
    pub extras: Vec<String>,
    /// Override install directory (default: XDG `.../intermed/rule-packs`).
    pub install_dir: Option<PathBuf>,
    /// When true, skip auto-loading packs from the install directory.
    pub skip_installed: bool,
    /// Optional registry index for resolving pack ids (file path or `https://` URL).
    pub registry_source: Option<String>,
    /// Optional trusted-keys file for verifying signed overlays.
    pub trusted_keys_path: Option<PathBuf>,
    /// Supply-chain trust policy (HTTPS / signature requirements + overrides).
    pub trust_policy: TrustPolicy,
}

/// The trust verdict recorded for one resolved overlay pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackTrust {
    pub id: String,
    pub trust: TrustLevel,
}

/// Resolved pack set ready for [`crate::DeclarativeRulePack`].
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedRulePacks {
    pub pack: RulePack,
    pub overlay_ids: Vec<String>,
    /// Per-overlay trust verdicts, in resolution order, for report/CLI display.
    pub trust: Vec<PackTrust>,
}

/// Build the effective rule pack for a doctor run.
///
/// Starts from the embedded core (optionally without mixin rules when Layer F
/// owns mixin imperatively), merges installed packs from XDG, then applies
/// explicit `--rule-pack` overlays in order.
pub fn resolve_doctor_packs(
    without_mixin: bool,
    selection: &RulePackSelection,
) -> Result<ResolvedRulePacks, SigningError> {
    let base = if without_mixin {
        default_core_pack_without_mixin()
    } else {
        default_core_pack_v2()
    };
    let trusted = load_trusted_keys_optional(selection.trusted_keys_path.as_deref())?;
    let policy = &selection.trust_policy;
    let registry = load_effective_registry(selection.registry_source.as_deref(), policy)?;
    let install_dir = selection
        .install_dir
        .clone()
        .or_else(|| default_rule_pack_install_dir().ok());

    let mut overlays = Vec::new();
    let mut overlay_ids = Vec::new();
    let mut trust = Vec::new();

    if !selection.skip_installed {
        if let Some(dir) = &install_dir {
            for path in list_installed_pack_paths(dir) {
                let (pack, level) = load_and_verify_pack(&path, &registry, &trusted, policy)?;
                if pack.id == base.id {
                    continue;
                }
                overlay_ids.push(pack.id.clone());
                trust.push(PackTrust { id: pack.id.clone(), trust: level });
                overlays.push(pack);
            }
        }
    }

    for extra in &selection.extras {
        let (pack, level) =
            resolve_pack_ref(extra, install_dir.as_deref(), &registry, &trusted, policy)?;
        overlay_ids.push(pack.id.clone());
        trust.push(PackTrust { id: pack.id.clone(), trust: level });
        overlays.push(pack);
    }

    let pack = merge_rule_packs(base, overlays).map_err(SigningError::Pack)?;
    Ok(ResolvedRulePacks {
        pack,
        overlay_ids,
        trust,
    })
}

/// Install a pack and its `depends_on` chain from the registry (topological order).
pub fn install_pack_with_dependencies(
    registry: &RuleRegistry,
    pack_id: &str,
    install_dir: &Path,
    trusted: &[VerifyingKey],
    policy: &TrustPolicy,
) -> Result<Vec<PathBuf>, SigningError> {
    let order = resolve_install_order(registry, pack_id)?;
    let mut installed = Vec::new();
    for id in order {
        let path = install_pack_from_registry(registry, &id, install_dir, trusted, policy)?;
        installed.push(path);
    }
    Ok(installed)
}

fn resolve_install_order(registry: &RuleRegistry, pack_id: &str) -> Result<Vec<String>, SigningError> {
    let mut order = Vec::new();
    let mut visiting = std::collections::BTreeSet::new();
    let mut visited = std::collections::BTreeSet::new();
    visit_pack(registry, pack_id, &mut order, &mut visiting, &mut visited)?;
    Ok(order)
}

fn visit_pack(
    registry: &RuleRegistry,
    pack_id: &str,
    order: &mut Vec<String>,
    visiting: &mut std::collections::BTreeSet<String>,
    visited: &mut std::collections::BTreeSet<String>,
) -> Result<(), SigningError> {
    if visited.contains(pack_id) {
        return Ok(());
    }
    if !visiting.insert(pack_id.to_string()) {
        return Err(SigningError::Message(format!(
            "cyclic rule pack dependency involving `{pack_id}`"
        )));
    }
    let entry = registry.find_pack(pack_id).ok_or_else(|| {
        SigningError::Message(format!("pack id not found in registry: {pack_id}"))
    })?;
    for dep in &entry.depends_on {
        visit_pack(registry, dep, order, visiting, visited)?;
    }
    visiting.remove(pack_id);
    if visited.insert(pack_id.to_string()) {
        order.push(pack_id.to_string());
    }
    Ok(())
}

/// List `*.rules.json` files in the install directory (stable sort).
#[must_use]
pub fn list_installed_pack_paths(install_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(install_dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|x| x == "json")
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".rules.json"))
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Load a registry from the embedded default, a local path, or a remote URL.
pub fn load_effective_registry(
    source: Option<&str>,
    policy: &TrustPolicy,
) -> Result<RuleRegistry, SigningError> {
    match source {
        Some(src) if !src.trim().is_empty() => load_registry_from_source(src, policy),
        Some(_) | None => Ok(merged_default_registry()),
    }
}

/// Embedded core registry unioned with the shipped community index (may be empty).
#[must_use]
pub fn merged_default_registry() -> RuleRegistry {
    let mut registry = default_registry();
    if let Ok(community) = parse_embedded_community_registry() {
        merge_registry_entries(&mut registry, community);
    }
    registry
}

const EMBEDDED_COMMUNITY_REGISTRY: &str =
    include_str!("../../../rules/community-registry.json");

fn parse_embedded_community_registry() -> Result<RuleRegistry, SigningError> {
    serde_json::from_str(EMBEDDED_COMMUNITY_REGISTRY)
        .map_err(|e| SigningError::Message(format!("parse embedded community registry: {e}")))
}

fn merge_registry_entries(base: &mut RuleRegistry, overlay: RuleRegistry) {
    for pack in overlay.packs {
        if !base.packs.iter().any(|p| p.id == pack.id) {
            base.packs.push(pack);
        }
    }
    for publisher in overlay.publishers {
        if !base.publishers.iter().any(|p| p.id == publisher.id) {
            base.publishers.push(publisher);
        }
    }
}

fn resolve_pack_ref(
    reference: &str,
    install_dir: Option<&Path>,
    registry: &RuleRegistry,
    trusted: &[VerifyingKey],
    policy: &TrustPolicy,
) -> Result<(RulePack, TrustLevel), SigningError> {
    let path = Path::new(reference);
    if path.is_file() {
        return load_and_verify_pack(path, registry, trusted, policy);
    }
    if let Some(dir) = install_dir {
        let installed = dir.join(format!("{reference}.rules.json"));
        if installed.is_file() {
            return load_and_verify_pack(&installed, registry, trusted, policy);
        }
    }
    if registry.find_pack(reference).is_some() {
        let dir = install_dir
            .map(Path::to_path_buf)
            .or_else(|| default_rule_pack_install_dir().ok())
            .ok_or_else(|| {
                SigningError::Message(format!(
                    "pack id `{reference}` not installed; run `intermed rules update --pack {reference}` first"
                ))
            })?;
        let path = install_pack_from_registry(registry, reference, &dir, trusted, policy)?;
        return load_and_verify_pack(&path, registry, trusted, policy);
    }
    Err(SigningError::Message(format!(
        "rule pack not found: {reference} (expected file path or installed/registry pack id)"
    )))
}

/// Load a pack from a local path and establish its trust level.
///
/// Packs on disk (the install dir or an explicit path) are `LocalFile` origin:
/// they were fetched-and-trust-checked at install time, or the user pointed at
/// them directly, so unsigned ones are accepted but reported as such. We still
/// run the full trust check (signature math + key pinning) when a signature is
/// present, and re-verify the registry digest when the registry knows the pack.
fn load_and_verify_pack(
    path: &Path,
    registry: &RuleRegistry,
    trusted: &[VerifyingKey],
    policy: &TrustPolicy,
) -> Result<(RulePack, TrustLevel), SigningError> {
    let pack = load_rule_pack(path).map_err(SigningError::Pack)?;
    let registry_declared = match pack.publisher.as_deref() {
        Some(publisher) => trusted_keys_for_publisher(registry, publisher)?,
        None => Vec::new(),
    };
    let level = verify_rule_pack_trust(
        &pack,
        PackOrigin::LocalFile,
        trusted,
        &registry_declared,
        policy,
    )?;
    if let Some(entry) = registry.packs.iter().find(|e| e.id == pack.id) {
        if canonical_digest(&pack) != entry.sha256 {
            return Err(SigningError::Message(format!(
                "pack `{}` digest does not match registry sha256",
                pack.id
            )));
        }
    }
    Ok((pack, level))
}

fn load_trusted_keys_optional(path: Option<&Path>) -> Result<Vec<VerifyingKey>, SigningError> {
    match path {
        Some(p) => crate::signing::load_trusted_keys(p),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RULE_REGISTRY_SCHEMA;
    use crate::signing::{fetch_pack_for_entry, sign_rule_pack, RegistryPackEntry};
    use ed25519_dalek::SigningKey;

    #[test]
    fn merged_registry_includes_community_index() {
        let reg = merged_default_registry();
        assert_eq!(reg.schema, RULE_REGISTRY_SCHEMA);
        assert!(reg.packs.iter().any(|p| p.id == "intermed-core"));
    }

    #[test]
    fn list_installed_sorts_paths() {
        let dir = std::env::temp_dir().join(format!(
            "intermed-pack-list-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.rules.json"), "{}").unwrap();
        std::fs::write(dir.join("a.rules.json"), "{}").unwrap();
        let paths = list_installed_pack_paths(&dir);
        assert_eq!(paths.len(), 2);
        assert!(paths[0].file_name().unwrap().to_str().unwrap().starts_with('a'));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn fetch_pack_rejects_digest_mismatch() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let mut pack = default_core_pack_v2();
        pack.publisher = Some("test".to_string());
        let sig = sign_rule_pack(&pack, &signing_key, "2026-01-01T00:00:00Z").unwrap();
        pack.signature = Some(sig);
        let json = serde_json::to_string(&pack).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "intermed-pack-fetch-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("pack.rules.json");
        std::fs::write(&file_path, json).unwrap();
        let entry = RegistryPackEntry {
            id: pack.id.clone(),
            version: pack.version.clone(),
            url: format!("file://{}", file_path.display()),
            sha256: "deadbeef".to_string(),
            publisher: "test".to_string(),
            changelog: None,
            depends_on: Vec::new(),
        };
        let err = fetch_pack_for_entry(&entry).unwrap_err();
        assert!(err.to_string().contains("digest"));
        std::fs::remove_dir_all(dir).ok();
    }
}