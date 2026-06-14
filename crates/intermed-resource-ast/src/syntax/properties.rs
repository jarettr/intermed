//! `.lang` properties syntax (`key=value` lines), the legacy Forge translation
//! format. Comments (`#`) and blank lines are ignored.

use std::collections::BTreeMap;

/// Parse `key=value` lines into a sorted map. Returns `None` if the bytes are not
/// UTF-8. Malformed lines (no `=`) are skipped rather than failing the whole file.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            if !k.is_empty() {
                out.insert(k.to_string(), v.trim().to_string());
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_value_lines() {
        let m = parse(b"# comment\nitem.a=A\n\nitem.b = B\n").unwrap();
        assert_eq!(m.get("item.a").map(String::as_str), Some("A"));
        assert_eq!(m.get("item.b").map(String::as_str), Some("B"));
        assert_eq!(m.len(), 2);
    }
}
