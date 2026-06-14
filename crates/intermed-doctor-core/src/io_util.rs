//! Small shared I/O helpers.
//!
//! The atomic-write discipline (temp sibling + rename) appears across the
//! workspace — the jar cache, the lab artifacts, and CLI dumps all need a write
//! that a concurrent reader or a crash mid-write never observes half-finished.
//! It lives here, once, so every writer shares the exact same guarantee instead
//! of re-implementing it per crate.

use std::fs;
use std::io;
use std::path::Path;

/// Write `bytes` to `path` atomically: stage into a unique temp sibling, then
/// rename over the target. A concurrent reader or a crash mid-write therefore
/// never sees a truncated file; the rename is the single atomic publish step.
///
/// The temp name is unique per process **and** per thread, so the parallel jar
/// scanners that share a cache directory cannot collide on it. On rename failure
/// the temp file is cleaned up rather than left behind.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("out");
    let tmp = parent.join(format!(
        ".{file_name}.tmp-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    fs::write(&tmp, bytes)?;
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_full_content_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!("imd-ioutil-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("out.json");
        write_atomic(&target, b"hello").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "hello");
        // No leftover temp siblings.
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let name = entry.file_name();
            assert!(!name.to_string_lossy().contains(".tmp-"));
        }
        fs::remove_dir_all(&dir).ok();
    }
}
