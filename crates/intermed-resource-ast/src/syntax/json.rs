//! JSON syntax layer.
//!
//! The "syntax AST" for JSON resources is `serde_json::Value` — a faithful syntax
//! tree we do not need to reinvent. This module is the thin, fallible boundary
//! from bytes to that tree (domain parsers then lower the `Value`). Minecraft
//! tolerates JSON-with-comments in some places; we strip `//` / `/* */` and a
//! leading UTF-8 BOM before parsing to avoid spurious "invalid" classifications.

use serde_json::Value;

/// Parse resource bytes into the JSON syntax tree, or an error message.
pub fn parse(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not utf-8: {e}"))?;
    let cleaned = strip_bom_and_comments(text);
    // Minecraft / mod loaders (GSON, Patchouli, …) tolerate trailing commas; strip
    // them so book/content JSON the game loads fine isn't flagged as malformed.
    let cleaned = strip_trailing_commas(&cleaned);
    serde_json::from_str(&cleaned).map_err(|e| e.to_string())
}

/// Remove trailing commas (`,` before a closing `}`/`]`), string-aware. Runs on
/// already comment-stripped text, so only whitespace can sit between the comma and
/// the closer.
fn strip_trailing_commas(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            out.push(c as char);
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_string = true;
            out.push('"');
            i += 1;
            continue;
        }
        if c == b',' {
            // Peek past whitespace for a closer.
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b'}' || bytes[j] == b']') {
                i += 1; // drop the trailing comma
                continue;
            }
        }
        let ch_len = utf8_len(c);
        let end = (i + ch_len).min(bytes.len());
        out.push_str(&text[i..end]);
        i = end;
    }
    out
}

/// Remove a leading BOM and line/block comments (Minecraft's JSON5-ish tolerance),
/// preserving everything inside string literals.
fn strip_bom_and_comments(text: &str) -> String {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            out.push(c as char);
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_string = true;
                out.push('"');
                i += 1;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            // Non-ASCII bytes are part of a multi-byte UTF-8 char; copy verbatim.
            _ => {
                // Copy a whole UTF-8 char to avoid splitting multibyte sequences.
                let ch_len = utf8_len(c);
                let end = (i + ch_len).min(bytes.len());
                out.push_str(&text[i..end]);
                i = end;
            }
        }
    }
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_json() {
        assert!(parse(br#"{"a":1}"#).is_ok());
    }

    #[test]
    fn strips_comments_and_bom() {
        let v = parse("\u{feff}{ // c\n \"a\": 1 /* b */ }".as_bytes()).unwrap();
        assert_eq!(v["a"], serde_json::json!(1));
    }

    #[test]
    fn slashes_inside_strings_are_preserved() {
        let v = parse(br#"{"url":"http://x//y"}"#).unwrap();
        assert_eq!(v["url"], serde_json::json!("http://x//y"));
    }

    #[test]
    fn malformed_is_error_not_panic() {
        assert!(parse(b"{not json").is_err());
        assert!(parse(b"\xff\xfe").is_err());
    }

    #[test]
    fn tolerates_trailing_commas() {
        // Common in Patchouli / mod book content; the game loads these fine.
        let v = parse(br#"{"a":1,"b":[1,2,],}"#).unwrap();
        assert_eq!(v["a"], serde_json::json!(1));
        assert_eq!(v["b"], serde_json::json!([1, 2]));
        let nested = parse(br#"{"pools":[{"x":1,},],}"#).unwrap();
        assert_eq!(nested["pools"][0]["x"], serde_json::json!(1));
    }

    #[test]
    fn comma_inside_string_is_preserved() {
        let v = parse(br#"{"text":"a, b, c","n":1}"#).unwrap();
        assert_eq!(v["text"], serde_json::json!("a, b, c"));
        // A literal comma-then-brace inside a string must not be stripped.
        let v2 = parse(br#"{"t":"x,}"}"#).unwrap();
        assert_eq!(v2["t"], serde_json::json!("x,}"));
    }
}
