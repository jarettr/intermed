use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

pub(crate) const WRITE_SHARDS: usize = 256;

pub(crate) fn new_write_locks() -> Box<[Mutex<()>; WRITE_SHARDS]> {
    (0..WRITE_SHARDS)
        .map(|_| Mutex::new(()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed shard count"))
}

/// Make a `cache_version` safe to use as a single path segment. Versions are
/// normally already safe (`"0.1.0-r1"`); this guards against stray separators.
pub(crate) fn sanitize_segment(value: &str) -> String {
    if value.is_empty() {
        return "v0".to_string();
    }
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn shard_index(sha256: &str) -> usize {
    u8::from_str_radix(sha256.get(..2).unwrap_or("00"), 16).unwrap_or(0) as usize
}

pub(crate) fn jar_path_digest(jar: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(jar.to_string_lossy().as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn file_mtime(meta: &fs::Metadata) -> (u64, u32) {
    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let duration = modified.duration_since(UNIX_EPOCH).unwrap_or_default();
    (duration.as_secs(), duration.subsec_nanos())
}

pub(crate) fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Resolve the default per-user cache base, or `None` when neither
/// `XDG_CACHE_HOME` nor `HOME` is set. Never returns a world-writable path: a
/// predictable shared location (`/tmp/intermed`) would be a cache-poisoning
/// vector, so absence of a private directory disables the cache instead.
pub(crate) fn default_cache_root() -> Option<std::path::PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Some(std::path::PathBuf::from(xdg).join("intermed"));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return Some(
                std::path::PathBuf::from(home)
                    .join(".cache")
                    .join("intermed"),
            );
        }
    }
    None
}
