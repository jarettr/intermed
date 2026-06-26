//! Bounded reads over zip archives — a single hardening layer so every scanner
//! (metadata, SBOM, Mixin, …) defends against crafted or oversized archives the
//! same way.
//!
//! Reading a zip entry with `read_to_string` / `read_to_end` trusts the archive
//! to be honest about size: a *zip bomb* declares a small entry that inflates to
//! gigabytes, and `read_to_end` will happily allocate all of it. Every reader
//! here bounds decompression with [`Read::take`] so a lying header cannot drive
//! unbounded allocation, and reports an explicit [`BoundedReadError::TooLarge`]
//! that callers surface as a `scan_truncated` diagnostic rather than dropping
//! evidence silently.
//!
//! The per-entry caps below are shared across layers so the tool's resilience to
//! a hostile jar does not depend on which scanner happened to open it.

use std::io::{Read, Seek};

use zip::ZipArchive;
use zip::result::ZipError;

/// Loader manifests: `mods.toml`, `MANIFEST.MF`, `fabric.mod.json`,
/// `quilt.mod.json`, `*.mods.toml`, `plugin.yml`. Real manifests are kilobytes;
/// 8 MiB is a generous ceiling that still caps a hostile archive.
pub const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// A single Mixin config (`*.mixins.json`). These list class names; even a large
/// pack's config is well under a megabyte.
pub const MAX_MIXIN_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// A Mixin refmap (`*-refmap.json`). Refmaps can be large on big mods, so this
/// cap is higher than a plain config.
pub const MAX_REFMAP_BYTES: u64 = 32 * 1024 * 1024;

/// A single nested jar (jar-in-jar). Bundled libraries can be sizeable, but a
/// single inner jar above this is treated as hostile and skipped.
pub const MAX_NESTED_JAR_BYTES: u64 = 128 * 1024 * 1024;

/// A single `.class` entry. Mirrors the security scanner's per-class cap.
pub const MAX_CLASS_BYTES: u64 = 16 * 1024 * 1024;

/// Aggregate budget for reading `.class` bytes while indexing a jar for Mixin
/// analysis. Caps total decompression across all classes in one archive.
pub const MAX_CLASS_INDEX_BYTES_TOTAL: u64 = 512 * 1024 * 1024;

/// Pick the per-entry decompression cap from the entry name, so every scanner
/// bounds the same entry types identically without each call site repeating the
/// mapping. Manifests are the conservative default.
#[must_use]
pub fn cap_for_entry(name: &str) -> u64 {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".jar") {
        MAX_NESTED_JAR_BYTES
    } else if lower.ends_with(".class") {
        MAX_CLASS_BYTES
    } else if lower.ends_with("refmap.json") {
        MAX_REFMAP_BYTES
    } else if lower.ends_with(".mixins.json") {
        MAX_MIXIN_CONFIG_BYTES
    } else {
        MAX_MANIFEST_BYTES
    }
}

/// Why a bounded read did not return content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedReadError {
    /// The entry's decompressed size reached the cap and was not read. Carries
    /// the entry name and the cap that was hit.
    TooLarge { name: String, cap: u64 },
    /// The entry exists but could not be read (IO error, corrupt deflate, or —
    /// for the text variant — invalid UTF-8).
    Unreadable { name: String, reason: String },
}

impl BoundedReadError {
    /// A short, user-facing reason suitable for a `scan_truncated` fact.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            BoundedReadError::TooLarge { name, cap } => {
                format!("{name}: exceeds {cap} byte cap, skipped")
            }
            BoundedReadError::Unreadable { name, reason } => format!("{name}: {reason}"),
        }
    }
}

impl std::fmt::Display for BoundedReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason())
    }
}

impl std::error::Error for BoundedReadError {}

/// Read a zip entry as bytes, bounding decompression at `max_bytes`.
///
/// - `Ok(Some(bytes))` — the entry exists and fits within the cap.
/// - `Ok(None)` — the entry is absent (a missing manifest is not an error).
/// - `Err(TooLarge)` — decompression reached the cap; nothing is returned.
/// - `Err(Unreadable)` — IO/corruption.
///
/// The cap is enforced with [`Read::take`], so an entry whose header lies about
/// its size still cannot inflate past `max_bytes + 1` bytes in memory.
pub fn read_zip_bytes_bounded<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, BoundedReadError> {
    let entry = match archive.by_name(name) {
        Ok(entry) => entry,
        Err(ZipError::FileNotFound) => return Ok(None),
        Err(e) => {
            return Err(BoundedReadError::Unreadable {
                name: name.to_string(),
                reason: e.to_string(),
            });
        }
    };
    // Reserve against the declared size, but never more than the cap — a hostile
    // header could claim a huge size to force a giant up-front allocation.
    let hint = entry.size().min(max_bytes) as usize;
    let mut buf = Vec::with_capacity(hint);
    entry
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| BoundedReadError::Unreadable {
            name: name.to_string(),
            reason: e.to_string(),
        })?;
    if buf.len() as u64 > max_bytes {
        return Err(BoundedReadError::TooLarge {
            name: name.to_string(),
            cap: max_bytes,
        });
    }
    Ok(Some(buf))
}

/// UTF-8 text variant of [`read_zip_bytes_bounded`]. Non-UTF-8 content yields an
/// [`BoundedReadError::Unreadable`].
pub fn read_zip_text_bounded<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    max_bytes: u64,
) -> Result<Option<String>, BoundedReadError> {
    match read_zip_bytes_bounded(archive, name, max_bytes)? {
        Some(bytes) => {
            String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| BoundedReadError::Unreadable {
                    name: name.to_string(),
                    reason: "invalid utf-8".to_string(),
                })
        }
        None => Ok(None),
    }
}

/// Convenience for the common "best-effort optional text" case: absent entries,
/// oversized entries, and unreadable entries all collapse to `None`. Use the
/// `Result`-returning [`read_zip_text_bounded`] when truncation must be surfaced
/// as a diagnostic.
#[must_use]
pub fn read_zip_text_opt<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    max_bytes: u64,
) -> Option<String> {
    read_zip_text_bounded(archive, name, max_bytes)
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn zip_with(name: &str, body: &[u8]) -> ZipArchive<Cursor<Vec<u8>>> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            zip.start_file(name, SimpleFileOptions::default()).unwrap();
            zip.write_all(body).unwrap();
            zip.finish().unwrap();
        }
        cursor.set_position(0);
        ZipArchive::new(cursor).unwrap()
    }

    #[test]
    fn reads_entry_within_cap() {
        let mut z = zip_with("a.txt", b"hello");
        let out = read_zip_text_bounded(&mut z, "a.txt", 1024).unwrap();
        assert_eq!(out.as_deref(), Some("hello"));
    }

    #[test]
    fn absent_entry_is_none_not_error() {
        let mut z = zip_with("a.txt", b"hello");
        assert_eq!(read_zip_text_bounded(&mut z, "missing", 1024), Ok(None));
    }

    #[test]
    fn oversized_entry_is_too_large() {
        let mut z = zip_with("big.txt", &vec![b'x'; 4096]);
        let err = read_zip_bytes_bounded(&mut z, "big.txt", 1024).unwrap_err();
        assert!(matches!(err, BoundedReadError::TooLarge { cap: 1024, .. }));
        // Best-effort variant collapses the truncation to None.
        assert_eq!(read_zip_text_opt(&mut z, "big.txt", 1024), None);
    }

    #[test]
    fn cap_is_enforced_on_decompressed_length() {
        // A highly compressible body (zip-bomb shape) must still be bounded by
        // the cap on the *decompressed* size, not the stored size.
        let mut z = zip_with("bomb.txt", &vec![0u8; 1_000_000]);
        let err = read_zip_bytes_bounded(&mut z, "bomb.txt", 64 * 1024).unwrap_err();
        assert!(matches!(err, BoundedReadError::TooLarge { .. }));
    }

    #[test]
    fn invalid_utf8_is_unreadable() {
        let mut z = zip_with("bin", &[0xff, 0xfe, 0x00]);
        let err = read_zip_text_bounded(&mut z, "bin", 1024).unwrap_err();
        assert!(matches!(err, BoundedReadError::Unreadable { .. }));
    }
}
