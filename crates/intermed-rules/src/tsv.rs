//! TSV and Souffle `.facts` field escaping.
//!
//! Generic TSV ([`escape_tsv_field`]) follows RFC-4180-style quoting for tab-
//! separated output. Souffle `.input` relations typed as `symbol` do **not**
//! parse CSV quotes — they use backslash escapes instead. Use
//! [`escape_souffle_symbol`] when materializing `.facts` files.

/// Escape one TSV field (RFC-4180 style: quote when special characters appear).
pub fn escape_tsv_field(s: &str) -> String {
    let needs_quote = s.is_empty()
        || s.contains(['\t', '\n', '\r', '"', '\\'])
        || s.starts_with(' ')
        || s.ends_with(' ');
    if !needs_quote {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        if ch == '"' {
            out.push_str("\"\"");
        } else {
            out.push(ch);
        }
    }
    out.push('"');
    out
}

/// Escape a Souffle `symbol` literal for `.facts` files.
///
/// Tabs, newlines, and backslashes become escape sequences; other non-printable
/// ASCII is written as `\u{XX}`. Printable characters (including spaces) are
/// preserved — Souffle does not collapse whitespace in symbols.
pub fn escape_souffle_symbol(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_ascii() && !c.is_ascii_graphic() && c != ' ' => {
                out.push_str(&format!("\\u{{{:02x}}}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn tsv_quotes_tabs_and_newlines() {
        assert_eq!(escape_tsv_field("plain"), "plain");
        assert_eq!(escape_tsv_field("mod\tid"), "\"mod\tid\"");
        assert_eq!(escape_tsv_field("line\nbreak"), "\"line\nbreak\"");
        assert_eq!(escape_tsv_field("quote\"field"), "\"quote\"\"field\"");
    }

    #[test]
    fn souffle_escapes_control_chars() {
        assert_eq!(escape_souffle_symbol("plain"), "plain");
        assert_eq!(escape_souffle_symbol("a\tb"), "a\\tb");
        assert_eq!(escape_souffle_symbol("a\nb"), "a\\nb");
        assert_eq!(escape_souffle_symbol("back\\slash"), "back\\\\slash");
        assert_eq!(escape_souffle_symbol(" spaced "), " spaced ");
    }
}
