//! Writer (owning mod) identity from Forge/NeoForge `mods.toml` text.
//!
//! Both Layer E (VFS) and Layer M (resource AST) need the *writer* — the mod that
//! owns a resource — and both used to hand-roll the same `mods.toml` scan, with
//! the same two bugs: they took the first `modId` line (which can belong to a
//! `[[dependencies]]` block) and stripped quotes with `trim_matches('"')`, which
//! left a trailing `# comment` attached (`sophisticatedbackpacks" # mandatory`).
//! The canonical parser lives here so the byte layer and the AST layer agree.

/// The owning mod id from a Forge/NeoForge `mods.toml`: the `modId` of the first
/// `[[mods]]` entry. Scoping to that block avoids picking up a `[[dependencies]]`
/// entry's `modId`, and [`toml_string_value`] reads the quoted value so a trailing
/// `# comment` (e.g. `modId = "x" # required`) never leaks into the writer name.
#[must_use]
pub fn mod_id_from_mods_toml(text: &str) -> Option<String> {
    let mut in_mods = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("[[mods]]") {
            in_mods = true;
            continue;
        }
        // Any other table header ends the `[[mods]]` scope.
        if l.starts_with('[') {
            in_mods = false;
        }
        if in_mods {
            if let Some(value) = parse_mod_id_assignment(l) {
                return Some(value);
            }
        }
    }
    // Fallback for malformed files with no `[[mods]]` header: first `modId` line.
    text.lines()
        .map(str::trim)
        .find_map(parse_mod_id_assignment)
}

/// `modId = "value"` (with optional whitespace / trailing comment) → `value`.
fn parse_mod_id_assignment(line: &str) -> Option<String> {
    line.strip_prefix("modId")
        .and_then(|rest| rest.trim_start().strip_prefix('='))
        .and_then(toml_string_value)
}

/// Read a TOML quoted string value, ignoring surrounding whitespace and any
/// trailing `# comment`. Accepts `"..."` and `'...'`. Returns `None` when the
/// value is not quoted, so callers fall through rather than capture a comment.
fn toml_string_value(s: &str) -> Option<String> {
    let s = s.trim_start();
    let quote = s.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &s[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owning_mod_id_ignores_trailing_comment() {
        let toml = "modLoader=\"javafml\"\n[[mods]]\nmodId=\"sophisticatedbackpacks\" # required\nversion=\"1.0\"\n";
        assert_eq!(
            mod_id_from_mods_toml(toml).as_deref(),
            Some("sophisticatedbackpacks")
        );
    }

    #[test]
    fn owning_mod_id_beats_dependency_mod_id() {
        let toml = "[[mods]]\nmodId='apotheosis'\n[[dependencies.apotheosis]]\nmodId=\"placebo\"\nmandatory=true\n";
        assert_eq!(mod_id_from_mods_toml(toml).as_deref(), Some("apotheosis"));
    }

    #[test]
    fn no_mods_block_falls_back_to_first_modid() {
        let toml = "[[dependencies.x]]\nmodId=\"only_dep\"\n";
        assert_eq!(mod_id_from_mods_toml(toml).as_deref(), Some("only_dep"));
    }

    #[test]
    fn unquoted_or_absent_is_none() {
        assert_eq!(mod_id_from_mods_toml("[[mods]]\nversion=\"1\"\n"), None);
    }
}
