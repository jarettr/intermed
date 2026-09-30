//! Shared bounded text-file reads for logs and script-engine output.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct BoundedText {
    pub text: String,
    pub truncated: bool,
    pub file_bytes: u64,
}

/// Read at most `max_bytes` from the tail of a text file. If the read begins in
/// the middle of a physical line, that fragment is discarded.
pub fn read_text_tail(path: &Path, max_bytes: u64) -> std::io::Result<BoundedText> {
    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    let truncated = length > max_bytes;
    if truncated {
        file.seek(SeekFrom::Start(length - max_bytes))?;
    }
    let mut bytes = Vec::with_capacity(length.min(max_bytes) as usize);
    file.take(max_bytes).read_to_end(&mut bytes)?;
    if truncated && let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
        bytes.drain(..=newline);
    }
    Ok(BoundedText {
        text: String::from_utf8_lossy(&bytes).into_owned(),
        truncated,
        file_bytes: length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_is_bounded_and_starts_on_a_physical_line() {
        let path =
            std::env::temp_dir().join(format!("intermed-bounded-text-{}", std::process::id()));
        std::fs::write(&path, "first\nsecond\nthird\n").unwrap();
        let read = read_text_tail(&path, 13).unwrap();
        assert!(read.truncated);
        assert_eq!(read.text, "third\n");
        std::fs::remove_file(path).ok();
    }
}
