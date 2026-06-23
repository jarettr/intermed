//! Reference [`RemoteCacheTier`] backed by a filesystem directory.
//!
//! This is both the example implementation and the seam a real object-store /
//! HTTP tier slots into: point it at a shared network mount or a CI cache
//! directory to share scan payloads across machines. A production S3/HTTP tier
//! implements the same two-method [`RemoteCacheTier`] trait and is attached with
//! [`JarCache::with_remote`](super::JarCache::with_remote) — no other code changes.

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::io_util::write_atomic;

use super::RemoteCacheTier;

/// A [`RemoteCacheTier`] that stores records as files under `root`, sharded by a
/// hash of the (filesystem-unsafe) cache key.
pub struct LocalDirRemoteTier {
    root: PathBuf,
}

impl LocalDirRemoteTier {
    /// Create a directory-backed remote tier rooted at `root` (created on first put).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Map an opaque cache key to a sharded, filesystem-safe path. The key itself
    /// contains NUL separators and a SHA, so it is hashed rather than used raw.
    fn path(&self, key: &str) -> PathBuf {
        let digest = hex(&Sha256::digest(key.as_bytes()));
        self.root.join(&digest[..2]).join(format!("{digest}.json"))
    }
}

impl RemoteCacheTier for LocalDirRemoteTier {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        fs::read(self.path(key)).ok()
    }

    fn put(&self, key: &str, bytes: &[u8]) {
        let path = self.path(key);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = write_atomic(&path, bytes);
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_round_trips() {
        let dir = std::env::temp_dir().join(format!("imd-remote-{}", std::process::id()));
        let tier = LocalDirRemoteTier::new(&dir);
        assert!(tier.get("collector\0v1\0abc").is_none());
        tier.put("collector\0v1\0abc", b"{\"payload\":1}");
        assert_eq!(
            tier.get("collector\0v1\0abc").as_deref(),
            Some(&b"{\"payload\":1}"[..])
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
