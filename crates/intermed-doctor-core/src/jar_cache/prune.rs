use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::config::JarCacheConfig;

/// Remove stale payload entries (by mtime) and aged-out fingerprint sidecars
/// (by `last_verified_secs` in the JSON). Then trim payloads to
/// `config.max_bytes` by evicting oldest files first.
///
/// Returns total bytes freed across both kinds of deletion; the caller uses
/// this to decide whether to invalidate an in-memory `disk_usage` cache.
pub(crate) fn prune_stale_entries(root: &Path, config: &JarCacheConfig) -> io::Result<u64> {
    let cutoff = SystemTime::now()
        .checked_sub(config.max_age)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let max_age_secs = config.max_age.as_secs();

    // Surviving payload files — fed into the size-cap pass below.
    let mut payloads: Vec<(SystemTime, PathBuf, u64)> = Vec::new();
    let mut freed = 0u64;

    walk_cache_files(root, &mut |path, modified, size| {
        if is_fingerprint_path(path) {
            // Fingerprints are pruned by the age recorded in their own JSON
            // (`last_verified_secs`), not by filesystem mtime, which the OS
            // can update independently on metadata-only writes.
            if should_prune_fingerprint(path, max_age_secs) && fs::remove_file(path).is_ok() {
                freed = freed.saturating_add(size);
            }
            // Fingerprints are excluded from the payload size-cap pass.
            return;
        }

        if modified < cutoff {
            if fs::remove_file(path).is_ok() {
                freed = freed.saturating_add(size);
            }
            return;
        }
        payloads.push((modified, path.to_path_buf(), size));
    })?;

    // Size-cap: trim oldest payload files until we fit within max_bytes.
    // Uses a separate counter so fingerprint bytes freed above don't
    // incorrectly reduce the eviction budget.
    let payload_total: u64 = payloads.iter().map(|(_, _, s)| s).sum();
    if payload_total > config.max_bytes {
        payloads.sort_by_key(|(modified, _, _)| *modified);
        let target = payload_total.saturating_sub(config.max_bytes);
        let mut evicted = 0u64;
        for (_, path, size) in payloads {
            if evicted >= target {
                break;
            }
            if fs::remove_file(&path).is_ok() {
                evicted = evicted.saturating_add(size);
            }
        }
        freed = freed.saturating_add(evicted);
    }

    Ok(freed)
}

/// True when a file path passes through an `fp` directory component —
/// i.e. it is a fingerprint sidecar, not a payload cache file.
fn is_fingerprint_path(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "fp")
}

/// Read a fingerprint file and decide whether it is old enough to prune.
///
/// Uses `last_verified_secs` from the JSON body. A value of `0` (absent in
/// records written before the field existed) is treated as never verified —
/// always eligible for pruning.
///
/// Returns `false` on any I/O or parse error: conservative, keep on doubt.
fn should_prune_fingerprint(path: &Path, max_age_secs: u64) -> bool {
    #[derive(serde::Deserialize)]
    struct FpAge {
        #[serde(default)]
        last_verified_secs: u64,
    }
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(fp) = serde_json::from_str::<FpAge>(&text) else {
        return false;
    };
    let now = super::util::now_unix_secs();
    now.saturating_sub(fp.last_verified_secs) >= max_age_secs
}

/// Run pruning at most once per `config.prune_interval`.
///
/// Returns bytes freed (0 when the interval has not elapsed yet), so the
/// caller can invalidate its in-memory `disk_usage` cache when needed.
pub(crate) fn maybe_prune(root: &Path, config: &JarCacheConfig) -> io::Result<u64> {
    let marker = root.join(".prune-marker");
    if let Ok(meta) = fs::metadata(&marker) {
        if let Ok(modified) = meta.modified() {
            if modified.elapsed().unwrap_or(config.prune_interval) < config.prune_interval {
                return Ok(0);
            }
        }
    }
    let freed = prune_stale_entries(root, config)?;
    let _ = fs::write(&marker, b"");
    Ok(freed)
}

/// Walk every `.json` file under `root` (including `fp/` subdirectories),
/// calling `f` with `(path, mtime, size_bytes)` for each.
pub(crate) fn walk_cache_files(
    root: &Path,
    f: &mut dyn FnMut(&Path, SystemTime, u64),
) -> io::Result<()> {
    if !root.is_dir() {
        return Ok(());
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            f(&path, modified, meta.len());
        }
    }
    Ok(())
}

/// Total bytes occupied by all cache and fingerprint files on disk.
pub(crate) fn disk_usage(root: &Path) -> u64 {
    let mut total = 0u64;
    let _ = walk_cache_files(root, &mut |_, _, size| {
        total = total.saturating_add(size);
    });
    total
}
