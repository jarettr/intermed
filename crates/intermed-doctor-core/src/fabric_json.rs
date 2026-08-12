//! Fabric Loader-compatible JSON parsing shared by metadata and SBOM scans.

/// Escape literal control characters only inside quoted strings. Fabric
/// Loader's vendored `JsonReader` accepts these in `fabric.mod.json`, whereas
/// strict `serde_json` rejects them.
#[must_use]
pub fn escape_string_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in text.chars() {
        if !in_string {
            out.push(ch);
            if ch == '"' {
                in_string = true;
            }
            continue;
        }
        if escaped {
            if ch == '\n' {
                out.push('n');
            } else {
                out.push(ch);
            }
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                out.push(ch);
                escaped = true;
            }
            '"' => {
                out.push(ch);
                in_string = false;
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            control if control <= '\u{001f}' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            _ => out.push(ch),
        }
    }
    out
}

pub fn parse_value(text: &str) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(&escape_string_controls(text))
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_literal_newline_inside_description() {
        let value = super::parse_value("{\"description\":\"one\ntwo\"}").unwrap();
        assert_eq!(value["description"], "one\ntwo");
    }

    #[test]
    fn structural_errors_stay_errors() {
        assert!(super::parse_value("{\"id\":}").is_err());
    }
}
