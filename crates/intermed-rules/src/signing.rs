//! Ed25519 signing and verification for distributable rule packs.
//!
//! Signed packs use schema `intermed-rule-pack-v2`. The signature covers a
//! canonical JSON payload (rules + metadata, without the signature block) so
//! third-party marketplaces can pin trust to publisher keys.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::validate::validate_rule_pack;
use crate::{RulePack, RulePackError, RULE_PACK_SCHEMA_V2, RULE_REGISTRY_SCHEMA};

/// Maximum registry index download size (1 MiB).
const MAX_REGISTRY_BYTES: usize = 1024 * 1024;

/// Maximum rule-pack download size (10 MiB).
const MAX_PACK_BYTES: usize = 10 * 1024 * 1024;

/// Supported signature algorithm (wire token).
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

/// Detached signature envelope attached to a v2 rule pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulePackSignature {
    pub algorithm: String,
    /// Base64-encoded Ed25519 public key (32 bytes).
    pub public_key: String,
    /// RFC3339 timestamp recorded at signing time.
    pub signed_at: String,
    /// Base64-encoded detached signature over the canonical payload.
    pub value: String,
}

/// Signing / verification failures.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("rule pack: {0}")]
    Pack(#[from] RulePackError),
    #[error("signing: {0}")]
    Message(String),
}

impl From<String> for SigningError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}

/// Canonical signing payload for a v2 pack (deterministic key order).
#[derive(Debug, Serialize)]
struct CanonicalPack<'a> {
    schema: &'a str,
    id: &'a str,
    version: &'a str,
    publisher: &'a str,
    rules: &'a [crate::RuleSpec],
}

/// SHA256 hex digest of the canonical signing bytes.
#[must_use]
pub fn canonical_digest(pack: &RulePack) -> String {
    let bytes = canonical_bytes(pack);
    let hash = Sha256::digest(&bytes);
    hex::encode(hash)
}

fn canonical_bytes(pack: &RulePack) -> Vec<u8> {
    let body = CanonicalPack {
        schema: &pack.schema,
        id: &pack.id,
        version: &pack.version,
        publisher: pack.publisher.as_deref().unwrap_or(""),
        rules: &pack.rules,
    };
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Sign a validated v2 pack, stamping the current UTC time.
pub fn sign_rule_pack_now(
    pack: &RulePack,
    signing_key: &SigningKey,
) -> Result<RulePackSignature, SigningError> {
    sign_rule_pack(pack, signing_key, &Utc::now().to_rfc3339())
}

/// Sign a validated v2 pack with a 32-byte Ed25519 seed (`signing.key` format).
pub fn sign_rule_pack(
    pack: &RulePack,
    signing_key: &SigningKey,
    signed_at: &str,
) -> Result<RulePackSignature, SigningError> {
    if pack.schema != RULE_PACK_SCHEMA_V2 {
        return Err(SigningError::Message(format!(
            "only {RULE_PACK_SCHEMA_V2} packs can be signed"
        )));
    }
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&canonical_bytes(pack));
    Ok(RulePackSignature {
        algorithm: SIGNATURE_ALGORITHM.to_string(),
        public_key: B64.encode(verifying_key.as_bytes()),
        signed_at: signed_at.to_string(),
        value: B64.encode(signature.to_bytes()),
    })
}

/// Low-level signature primitive: checks the Ed25519 signature math and, when
/// `trusted_keys` is non-empty, that the signing key is a member of that set.
///
/// **This is not a trust decision.** With an empty `trusted_keys` it confirms
/// only that the pack is *self-consistent* (signed by whatever key it carries),
/// which an attacker who controls the pack can trivially satisfy. Callers that
/// ingest untrusted packs (anything not embedded/local-and-user-chosen) must go
/// through [`verify_rule_pack_trust`], which applies the supply-chain policy.
pub fn verify_rule_pack_signature(
    pack: &RulePack,
    trusted_keys: &[VerifyingKey],
) -> Result<(), SigningError> {
    let Some(sig) = pack.signature.as_ref() else {
        return Err(SigningError::Message("pack has no signature".into()));
    };
    if sig.algorithm != SIGNATURE_ALGORITHM {
        return Err(SigningError::Message(format!(
            "unsupported signature algorithm: {}",
            sig.algorithm
        )));
    }
    let public_key = decode_verifying_key(&sig.public_key)?;
    if !trusted_keys.is_empty() && !trusted_keys.iter().any(|k| k == &public_key) {
        return Err(SigningError::Message(
            "signature public key is not in the trusted key set".into(),
        ));
    }
    let signature = decode_signature(&sig.value)?;
    public_key
        .verify(&canonical_bytes(pack), &signature)
        .map_err(|e| SigningError::Message(format!("signature invalid: {e}")))?;
    Ok(())
}

/// Supply-chain trust policy for ingesting rule packs and registries.
///
/// The default (both flags `false`) is strict: remote sources must use HTTPS and
/// ship a signature whose key is pinned (via `--rule-pack-trusted-keys`) or
/// declared by a (non-HTTP) registry. The two escapes are deliberate opt-ins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrustPolicy {
    /// Permit `http://` registry/pack sources (otherwise HTTPS is required).
    pub allow_insecure_registry: bool,
    /// Permit unsigned, or signed-but-unpinned, remote rule packs.
    pub allow_unsigned_rules: bool,
}

/// Where a pack/registry was obtained from — drives the transport requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackOrigin {
    /// Compiled into the binary; implicitly trusted.
    Embedded,
    /// A file the user pointed at locally (path or `file://`).
    LocalFile,
    /// Fetched over HTTPS.
    RemoteSecure,
    /// Fetched over plain HTTP.
    RemoteInsecure,
}

impl PackOrigin {
    /// Classify a registry/pack URL or path into an origin.
    #[must_use]
    pub fn classify(url: &str) -> Self {
        if url.starts_with("embedded://") {
            PackOrigin::Embedded
        } else if url.starts_with("https://") {
            PackOrigin::RemoteSecure
        } else if url.starts_with("http://") {
            PackOrigin::RemoteInsecure
        } else {
            // file://, bare paths, anything else → treated as local & user-chosen.
            PackOrigin::LocalFile
        }
    }
}

/// The trust verdict for one pack, surfaced in reports so users can see *why* a
/// pack's findings should (or should not) be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    /// Built into the binary.
    Embedded,
    /// Valid signature by a locally pinned key (strongest).
    SignedPinnedKey,
    /// Valid signature by a key the registry declares for the publisher.
    SignedRegistryKey,
    /// Local file, no signature (allowed; the user chose it).
    UnsignedLocal,
    /// Valid signature but the key is not pinned/declared (allowed only via override).
    SignedUntrusted,
    /// Remote and unsigned (allowed only via override).
    UnsignedRemote,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            TrustLevel::Embedded => "embedded",
            TrustLevel::SignedPinnedKey => "signed-pinned-key",
            TrustLevel::SignedRegistryKey => "signed-registry-key",
            TrustLevel::UnsignedLocal => "unsigned-local",
            TrustLevel::SignedUntrusted => "signed-untrusted",
            TrustLevel::UnsignedRemote => "unsigned-remote",
        }
    }

    /// Human-readable one-line summary for CLI/report.
    pub fn describe(self) -> &'static str {
        match self {
            TrustLevel::Embedded => "embedded core (trusted)",
            TrustLevel::SignedPinnedKey => "signed by a pinned key",
            TrustLevel::SignedRegistryKey => "signed by a registry-declared key",
            TrustLevel::UnsignedLocal => "unsigned local file",
            TrustLevel::SignedUntrusted => "signed by an unpinned key (accepted via override)",
            TrustLevel::UnsignedRemote => "unsigned remote pack (accepted via override)",
        }
    }
}

/// Apply the supply-chain [`TrustPolicy`] to a pack obtained from `origin`.
///
/// `pinned` are keys the user pinned locally; `registry_declared` are keys the
/// registry lists for the pack's publisher (weaker — a compromised registry can
/// list its own). Returns the established [`TrustLevel`] or rejects with an
/// actionable message naming the override that would accept it.
pub fn verify_rule_pack_trust(
    pack: &RulePack,
    origin: PackOrigin,
    pinned: &[VerifyingKey],
    registry_declared: &[VerifyingKey],
    policy: &TrustPolicy,
) -> Result<TrustLevel, SigningError> {
    // Transport: a plain-HTTP source is rejected unless explicitly allowed,
    // because over HTTP the registry, URL, digest and publisher key can all be
    // swapped together — the digest then proves nothing.
    if origin == PackOrigin::RemoteInsecure && !policy.allow_insecure_registry {
        return Err(SigningError::Message(
            "rule pack source uses insecure http://; use https:// or pass \
             --allow-insecure-registry to override"
                .into(),
        ));
    }

    if origin == PackOrigin::Embedded {
        return Ok(TrustLevel::Embedded);
    }

    match pack.signature.as_ref() {
        None => {
            if origin == PackOrigin::LocalFile {
                Ok(TrustLevel::UnsignedLocal)
            } else if policy.allow_unsigned_rules {
                Ok(TrustLevel::UnsignedRemote)
            } else {
                Err(SigningError::Message(format!(
                    "remote rule pack `{}` is unsigned; pass --allow-unsigned-rules to accept it",
                    pack.id
                )))
            }
        }
        Some(_) => {
            // Always check the signature math first.
            verify_rule_pack_signature(pack, &[])?;
            let key = decode_verifying_key(&pack.signature.as_ref().unwrap().public_key)?;

            if pinned.iter().any(|k| k == &key) {
                return Ok(TrustLevel::SignedPinnedKey);
            }
            if registry_declared.iter().any(|k| k == &key) {
                return Ok(TrustLevel::SignedRegistryKey);
            }
            // Signed, but by a key we have no reason to trust.
            if origin == PackOrigin::LocalFile || policy.allow_unsigned_rules {
                Ok(TrustLevel::SignedUntrusted)
            } else {
                Err(SigningError::Message(format!(
                    "rule pack `{}` is signed by a key that is not pinned or registry-declared; \
                     pin it with --rule-pack-trusted-keys or pass --allow-unsigned-rules",
                    pack.id
                )))
            }
        }
    }
}

/// Load a 32-byte Ed25519 seed from raw bytes or base64 text.
pub fn load_signing_key(raw: &[u8]) -> Result<SigningKey, SigningError> {
    let seed = if raw.len() == 32 {
        raw.to_vec()
    } else {
        let text = std::str::from_utf8(raw)
            .map_err(|e| SigningError::Message(format!("invalid signing key utf-8: {e}")))?;
        B64.decode(text.trim())
            .map_err(|e| SigningError::Message(format!("invalid signing key base64: {e}")))?
    };
    if seed.len() != 32 {
        return Err(SigningError::Message(format!(
            "signing key must be 32 bytes, got {}",
            seed.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&arr))
}

/// Parse a trusted-keys file: one base64-encoded verifying key per line.
pub fn load_trusted_keys(path: &std::path::Path) -> Result<Vec<VerifyingKey>, SigningError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| SigningError::Message(format!("read {}: {e}", path.display())))?;
    let mut keys = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        keys.push(decode_verifying_key(trimmed)?);
    }
    if keys.is_empty() {
        return Err(SigningError::Message(
            "trusted keys file has no keys".into(),
        ));
    }
    Ok(keys)
}

fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, SigningError> {
    let bytes = B64
        .decode(encoded.trim())
        .map_err(|e| SigningError::Message(format!("invalid public key base64: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SigningError::Message("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| SigningError::Message(format!("invalid public key: {e}")))
}

fn decode_signature(encoded: &str) -> Result<Signature, SigningError> {
    let bytes = B64
        .decode(encoded.trim())
        .map_err(|e| SigningError::Message(format!("invalid signature base64: {e}")))?;
    Signature::from_slice(&bytes)
        .map_err(|e| SigningError::Message(format!("invalid signature bytes: {e}")))
}

/// Minimal hex encoder (avoids pulling `hex` crate for one call site).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Publisher metadata for marketplace listings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherInfo {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub public_keys: Vec<String>,
}

/// One downloadable pack entry in a registry index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryPackEntry {
    pub id: String,
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub publisher: String,
    #[serde(default)]
    pub changelog: Option<String>,
    /// Pack ids that must be installed before this pack (registry resolution order).
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// Local or remote rule-pack registry index (`intermed-rule-registry-v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRegistry {
    pub schema: String,
    #[serde(default)]
    pub packs: Vec<RegistryPackEntry>,
    #[serde(default)]
    pub publishers: Vec<PublisherInfo>,
}

impl RuleRegistry {
    pub fn find_pack(&self, id: &str) -> Option<&RegistryPackEntry> {
        self.packs.iter().find(|p| p.id == id)
    }
}

/// Built-in registry pointing at the embedded core pack (offline-safe default).
#[must_use]
pub fn default_registry() -> RuleRegistry {
    let pack = crate::default_core_pack_v2();
    RuleRegistry {
        schema: crate::RULE_REGISTRY_SCHEMA.to_string(),
        packs: vec![RegistryPackEntry {
            id: pack.id.clone(),
            version: pack.version.clone(),
            url: "embedded://intermed-core-datalog".to_string(),
            sha256: canonical_digest(&pack),
            publisher: pack.publisher.clone().unwrap_or_else(|| "intermed".to_string()),
            changelog: Some("Embedded InterMed core declarative pack".to_string()),
            depends_on: Vec::new(),
        }],
        publishers: vec![PublisherInfo {
            id: "intermed".to_string(),
            display_name: "InterMed Project".to_string(),
            public_keys: Vec::new(),
        }],
    }
}

/// Serialize a registry index with stable pack ordering.
#[must_use]
pub fn registry_to_json(registry: &RuleRegistry) -> String {
    let mut packs = registry.packs.clone();
    packs.sort_by(|a, b| a.id.cmp(&b.id).then(a.version.cmp(&b.version)));
    let ordered = RuleRegistry {
        schema: registry.schema.clone(),
        packs,
        publishers: registry.publishers.clone(),
    };
    serde_json::to_string_pretty(&ordered).unwrap_or_else(|_| "{}".to_string())
}

/// Default XDG data directory for installed rule packs.
pub fn default_rule_pack_install_dir() -> Result<std::path::PathBuf, SigningError> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| {
                std::path::PathBuf::from(home)
                    .join(".local")
                    .join("share")
            })
        })
        .ok_or_else(|| SigningError::Message("could not resolve XDG data home".into()))?;
    Ok(base.join("intermed").join("rule-packs"))
}

/// Load a registry index from a local path, `file://` URL, or `https://` URL.
///
/// Plain `http://` is refused unless `policy.allow_insecure_registry` is set, so
/// the publisher keys and pack digests a registry declares can't be silently
/// swapped by a network attacker.
pub fn load_registry_from_source(
    source: &str,
    policy: &TrustPolicy,
) -> Result<RuleRegistry, SigningError> {
    if PackOrigin::classify(source) == PackOrigin::RemoteInsecure && !policy.allow_insecure_registry
    {
        return Err(SigningError::Message(format!(
            "registry source `{source}` uses insecure http://; use https:// or pass \
             --allow-insecure-registry"
        )));
    }
    let text = if source.starts_with("https://") || source.starts_with("http://") {
        let bytes = fetch_url_limited(source, MAX_REGISTRY_BYTES)?;
        String::from_utf8(bytes)
            .map_err(|e| SigningError::Message(format!("registry at {source} is not utf-8: {e}")))?
    } else if let Some(path) = source.strip_prefix("file://") {
        std::fs::read_to_string(path)
            .map_err(|e| SigningError::Message(format!("read {path}: {e}")))?
    } else {
        std::fs::read_to_string(source)
            .map_err(|e| SigningError::Message(format!("read {source}: {e}")))?
    };
    let registry: RuleRegistry = serde_json::from_str(&text)
        .map_err(|e| SigningError::Message(format!("parse registry: {e}")))?;
    if registry.schema != RULE_REGISTRY_SCHEMA {
        return Err(SigningError::Message(format!(
            "unsupported registry schema: {}",
            registry.schema
        )));
    }
    Ok(registry)
}

/// Connect/read/write timeouts for remote registry / rule-pack fetches. Remote
/// endpoints are untrusted network: without explicit timeouts a slow or
/// slowloris-style server can hang the CLI indefinitely.
const HTTP_CONNECT_TIMEOUT_SECS: u64 = 5;
const HTTP_READ_TIMEOUT_SECS: u64 = 15;
const HTTP_WRITE_TIMEOUT_SECS: u64 = 5;

/// A `ureq` agent with explicit, bounded timeouts for remote fetches.
fn http_agent() -> ureq::Agent {
    use std::time::Duration;
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(HTTP_CONNECT_TIMEOUT_SECS))
        .timeout_read(Duration::from_secs(HTTP_READ_TIMEOUT_SECS))
        .timeout_write(Duration::from_secs(HTTP_WRITE_TIMEOUT_SECS))
        .build()
}

/// GET a URL with explicit timeouts and a hard response size cap.
pub fn fetch_url_limited(url: &str, max_bytes: usize) -> Result<Vec<u8>, SigningError> {
    let response = http_agent()
        .get(url)
        .call()
        .map_err(|e| SigningError::Message(format!("fetch {url}: {e}")))?;
    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(SigningError::Message(format!(
            "fetch {url}: HTTP {status}"
        )));
    }
    let mut body = Vec::new();
    let mut reader = response.into_reader();
    let mut buf = [0u8; 8192];
    loop {
        let n = std::io::Read::read(&mut reader, &mut buf)
            .map_err(|e| SigningError::Message(format!("read {url}: {e}")))?;
        if n == 0 {
            break;
        }
        if body.len().saturating_add(n) > max_bytes {
            return Err(SigningError::Message(format!(
                "fetch {url}: response exceeds {max_bytes} byte limit"
            )));
        }
        body.extend_from_slice(&buf[..n]);
    }
    Ok(body)
}

/// Fetch and validate a pack for a registry entry (`embedded://`, `file://`,
/// `https://`). Equivalent to [`fetch_pack_for_entry_with_policy`] under the
/// strict default policy (no insecure transport).
pub fn fetch_pack_for_entry(entry: &RegistryPackEntry) -> Result<RulePack, SigningError> {
    fetch_pack_for_entry_with_policy(entry, &TrustPolicy::default())
}

/// Fetch and validate a pack, refusing `http://` unless the policy allows it.
pub fn fetch_pack_for_entry_with_policy(
    entry: &RegistryPackEntry,
    policy: &TrustPolicy,
) -> Result<RulePack, SigningError> {
    if PackOrigin::classify(&entry.url) == PackOrigin::RemoteInsecure
        && !policy.allow_insecure_registry
    {
        return Err(SigningError::Message(format!(
            "pack `{}` is served over insecure http://; use https:// or pass \
             --allow-insecure-registry",
            entry.id
        )));
    }
    let pack = if entry.url.starts_with("embedded://") {
        let mut embedded = crate::default_core_pack_v2();
        if embedded.id != entry.id {
            return Err(SigningError::Message(format!(
                "embedded pack id mismatch: expected {}, got {}",
                entry.id, embedded.id
            )));
        }
        embedded.version = entry.version.clone();
        embedded
    } else if let Some(path) = entry.url.strip_prefix("file://") {
        crate::load_rule_pack(std::path::Path::new(path)).map_err(SigningError::Pack)?
    } else if entry.url.starts_with("https://") || entry.url.starts_with("http://") {
        let bytes = fetch_url_limited(&entry.url, MAX_PACK_BYTES)?;
        let text = std::str::from_utf8(&bytes).map_err(|e| {
            SigningError::Message(format!("pack at {} is not valid utf-8: {e}", entry.url))
        })?;
        let pack: RulePack = serde_json::from_str(text)
            .map_err(|e| SigningError::Message(format!("parse pack json: {e}")))?;
        validate_rule_pack(&pack).map_err(SigningError::Pack)?;
        pack
    } else {
        return Err(SigningError::Message(format!(
            "unsupported pack url scheme: {}",
            entry.url
        )));
    };
    if canonical_digest(&pack) != entry.sha256 {
        return Err(SigningError::Message(
            "pack digest does not match registry sha256".into(),
        ));
    }
    Ok(pack)
}

/// Install or refresh a pack from a registry entry (embedded, file, or remote URL).
pub fn install_pack_from_registry(
    registry: &RuleRegistry,
    pack_id: &str,
    install_dir: &std::path::Path,
    trusted_keys: &[VerifyingKey],
    policy: &TrustPolicy,
) -> Result<std::path::PathBuf, SigningError> {
    let entry = registry
        .find_pack(pack_id)
        .ok_or_else(|| SigningError::Message(format!("pack not found in registry: {pack_id}")))?;
    // Establish origin from the entry URL *before* fetching so an http:// entry
    // is refused up front (fetch_pack_for_entry also re-checks transport).
    let origin = PackOrigin::classify(&entry.url);
    let pack = fetch_pack_for_entry_with_policy(entry, policy)?;
    // Pinned keys come from the caller (--rule-pack-trusted-keys); registry keys
    // are the weaker publisher-declared set. The policy decides what's acceptable.
    let registry_declared = trusted_keys_for_publisher(registry, &entry.publisher)?;
    verify_rule_pack_trust(&pack, origin, trusted_keys, &registry_declared, policy)?;
    std::fs::create_dir_all(install_dir).map_err(|e| {
        SigningError::Message(format!("create {}: {e}", install_dir.display()))
    })?;
    let out = install_dir.join(format!("{}.rules.json", pack.id));
    let json = serde_json::to_string_pretty(&pack)
        .map_err(|e| SigningError::Message(format!("serialize pack: {e}")))?;
    // Atomic write (temp file in the same dir → fsync → rename): an interrupted
    // install can never leave a half-written pack the loader would later choke on.
    intermed_doctor_core::write_atomic(&out, json.as_bytes())
        .map_err(|e| SigningError::Message(format!("write {}: {e}", out.display())))?;
    Ok(out)
}

/// Lookup table for quick publisher-key resolution.
#[must_use]
pub fn trusted_keys_from_registry(registry: &RuleRegistry) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for publisher in &registry.publishers {
        out.insert(publisher.id.clone(), publisher.public_keys.clone());
    }
    out
}

/// Decode the trusted Ed25519 verifying keys a registry declares for a publisher
/// id, reading the base64 entries from its publisher table.
///
/// Returns an empty vector when the publisher is unknown or lists no keys, which
/// the verifier treats as "trust any self-consistent signature".
pub fn trusted_keys_for_publisher(
    registry: &RuleRegistry,
    publisher_id: &str,
) -> Result<Vec<VerifyingKey>, SigningError> {
    let table = trusted_keys_from_registry(registry);
    let Some(encoded) = table.get(publisher_id) else {
        return Ok(Vec::new());
    };
    encoded.iter().map(|enc| decode_verifying_key(enc)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use ed25519_dalek::SigningKey;

    fn signed_pack(seed: u8) -> (RulePack, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let mut pack = crate::default_core_pack_v2();
        pack.publisher = Some("acme".to_string());
        let sig = sign_rule_pack(&pack, &signing_key, "2026-01-01T00:00:00Z").unwrap();
        pack.signature = Some(sig);
        (pack, signing_key)
    }

    fn registry_for(publisher: &str, keys: Vec<String>) -> RuleRegistry {
        RuleRegistry {
            schema: crate::RULE_REGISTRY_SCHEMA.to_string(),
            packs: Vec::new(),
            publishers: vec![PublisherInfo {
                id: publisher.to_string(),
                display_name: publisher.to_string(),
                public_keys: keys,
            }],
        }
    }

    #[test]
    fn resolves_declared_publisher_keys() {
        let (_, signing_key) = signed_pack(7);
        let encoded = B64.encode(signing_key.verifying_key().as_bytes());
        let registry = registry_for("acme", vec![encoded]);
        let keys = trusted_keys_for_publisher(&registry, "acme").unwrap();
        assert_eq!(keys, vec![signing_key.verifying_key()]);
    }

    #[test]
    fn unknown_publisher_resolves_empty() {
        let registry = registry_for("acme", vec!["x".into()]);
        let keys = trusted_keys_for_publisher(&registry, "nobody").unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn verifies_against_registry_declared_key() {
        let (pack, signing_key) = signed_pack(7);
        let encoded = B64.encode(signing_key.verifying_key().as_bytes());
        let registry = registry_for("acme", vec![encoded]);
        let trusted = trusted_keys_for_publisher(&registry, "acme").unwrap();
        assert!(verify_rule_pack_signature(&pack, &trusted).is_ok());
    }

    #[test]
    fn trust_rejects_unsigned_remote_by_default() {
        let mut pack = crate::default_core_pack_v2();
        pack.signature = None;
        let err = verify_rule_pack_trust(
            &pack,
            PackOrigin::RemoteSecure,
            &[],
            &[],
            &TrustPolicy::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsigned"));
    }

    #[test]
    fn trust_allows_unsigned_remote_with_override() {
        let mut pack = crate::default_core_pack_v2();
        pack.signature = None;
        let policy = TrustPolicy {
            allow_unsigned_rules: true,
            ..TrustPolicy::default()
        };
        let level =
            verify_rule_pack_trust(&pack, PackOrigin::RemoteSecure, &[], &[], &policy).unwrap();
        assert_eq!(level, TrustLevel::UnsignedRemote);
    }

    #[test]
    fn trust_rejects_insecure_http_by_default() {
        let pack = crate::default_core_pack_v2();
        let err = verify_rule_pack_trust(
            &pack,
            PackOrigin::RemoteInsecure,
            &[],
            &[],
            &TrustPolicy::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("http"));
    }

    #[test]
    fn trust_rejects_signed_remote_with_unpinned_key() {
        // A self-consistent signature must NOT pass when nothing pins the key.
        let (pack, _signer) = signed_pack(7);
        let err = verify_rule_pack_trust(
            &pack,
            PackOrigin::RemoteSecure,
            &[],
            &[],
            &TrustPolicy::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not pinned"));
    }

    #[test]
    fn trust_accepts_signed_remote_with_pinned_key() {
        let (pack, signer) = signed_pack(7);
        let level = verify_rule_pack_trust(
            &pack,
            PackOrigin::RemoteSecure,
            &[signer.verifying_key()],
            &[],
            &TrustPolicy::default(),
        )
        .unwrap();
        assert_eq!(level, TrustLevel::SignedPinnedKey);
    }

    #[test]
    fn trust_accepts_signed_remote_with_registry_key() {
        let (pack, signer) = signed_pack(7);
        let level = verify_rule_pack_trust(
            &pack,
            PackOrigin::RemoteSecure,
            &[],
            &[signer.verifying_key()],
            &TrustPolicy::default(),
        )
        .unwrap();
        assert_eq!(level, TrustLevel::SignedRegistryKey);
    }

    #[test]
    fn trust_accepts_unsigned_local_file() {
        let mut pack = crate::default_core_pack_v2();
        pack.signature = None;
        let level = verify_rule_pack_trust(
            &pack,
            PackOrigin::LocalFile,
            &[],
            &[],
            &TrustPolicy::default(),
        )
        .unwrap();
        assert_eq!(level, TrustLevel::UnsignedLocal);
    }

    #[test]
    fn rejects_when_registry_declares_a_different_key() {
        let (pack, _signer) = signed_pack(7);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let encoded = B64.encode(other.verifying_key().as_bytes());
        let registry = registry_for("acme", vec![encoded]);
        let trusted = trusted_keys_for_publisher(&registry, "acme").unwrap();
        let err = verify_rule_pack_signature(&pack, &trusted).unwrap_err();
        assert!(err.to_string().contains("not in the trusted key set"));
    }
}