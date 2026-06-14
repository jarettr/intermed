//! Access Transformer (Forge / NeoForge) and Access Widener (Fabric / Quilt)
//! parsing.
//!
//! Both mechanisms relax the JVM access of *game* (or library) members so a mod
//! can touch internals the vanilla bytecode hides. They are a frequent, quiet
//! source of cross-mod conflict: two mods widening the same member differently,
//! or one mod's `@Mixin`/`@Shadow` assuming a visibility another mod's transform
//! changed. Parsing them into structured [`AccessDirective`]s lets Layer B emit
//! `access_transform` facts the rules can correlate — the same way mixin sites are
//! compared.

/// One parsed access-changing directive, normalised across both mechanisms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessDirective {
    /// `access-transformer` (Forge) or `access-widener` (Fabric/Quilt).
    pub(crate) mechanism: &'static str,
    /// Normalised access verb: `public` / `protected` / `private` / `default`
    /// (Forge) or `accessible` / `extendable` / `mutable` (Fabric/Quilt), with any
    /// `transitive-` / `-f` qualifier preserved in [`Self::qualifier`].
    pub(crate) access: String,
    /// Extra qualifier when present: Forge `-f`/`-m` (final/method flag) or Fabric
    /// `transitive`. Empty otherwise.
    pub(crate) qualifier: String,
    /// Dotted target class (`net.minecraft.world.level.Level`).
    pub(crate) target_class: String,
    /// Member the directive targets (`method_5678 (…)V`, `field_72995_K`), or
    /// `None` for a whole-class directive (`extendable class …`).
    pub(crate) member: Option<String>,
}

/// Strip a trailing `#`/`//` comment and surrounding whitespace from one line.
fn strip_comment(line: &str) -> &str {
    let line = line
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(line);
    let line = line.split_once("//").map(|(head, _)| head).unwrap_or(line);
    line.trim()
}

fn slash_to_dot(class: &str) -> String {
    class.replace('/', ".")
}

/// Parse a Forge / NeoForge `accesstransformer.cfg`.
///
/// Lines look like `public net.minecraft.world.level.Level shouldUpdate()Z` or
/// `public-f net.minecraft.world.entity.Entity field_5953`. The access token may
/// carry a `-f` (make non-final) / `-m` qualifier suffix; the class is already
/// dotted; the member (method `name(desc)ret` or field `name`) is optional.
pub(crate) fn parse_access_transformer(text: &str) -> Vec<AccessDirective> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = strip_comment(raw);
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let Some(access_token) = tokens.next() else {
            continue;
        };
        let Some(class) = tokens.next() else {
            continue;
        };
        let (access, qualifier) = match access_token.split_once('-') {
            Some((verb, qual)) => (verb.to_string(), qual.to_string()),
            None => (access_token.to_string(), String::new()),
        };
        // Anything after the class is the member (method+descriptor or field).
        let member: String = tokens.collect::<Vec<_>>().join(" ");
        out.push(AccessDirective {
            mechanism: "access-transformer",
            access,
            qualifier,
            target_class: class.to_string(),
            member: (!member.is_empty()).then_some(member),
        });
    }
    out
}

/// Parse a Fabric / Quilt `.accesswidener` file.
///
/// Header line `accessWidener v2 named` is skipped; directives look like
/// `accessible method net/minecraft/class_1234 method_5678 (…)V`,
/// `mutable field … field_5678 I`, or `extendable class net/minecraft/class_1234`.
/// The access verb may be prefixed `transitive-`; the class is in slash form and
/// is normalised to dotted.
pub(crate) fn parse_access_widener(text: &str) -> Vec<AccessDirective> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = strip_comment(raw);
        if line.is_empty() || line.starts_with("accessWidener") {
            continue; // header or blank
        }
        let mut tokens = line.split_whitespace();
        let Some(access_token) = tokens.next() else {
            continue;
        };
        let Some(member_type) = tokens.next() else {
            continue;
        };
        let Some(class) = tokens.next() else {
            continue;
        };
        let (qualifier, access) = match access_token.strip_prefix("transitive-") {
            Some(rest) => ("transitive".to_string(), rest.to_string()),
            None => (String::new(), access_token.to_string()),
        };
        // `class` directives have no member; `method`/`field` carry name (+desc).
        let member = if member_type == "class" {
            None
        } else {
            let m = tokens.collect::<Vec<_>>().join(" ");
            (!m.is_empty()).then_some(m)
        };
        out.push(AccessDirective {
            mechanism: "access-widener",
            access,
            qualifier,
            target_class: slash_to_dot(class),
            member,
        });
    }
    out
}

/// A stable comparison key for a directive's *target* (class + member), used to
/// spot two mods transforming the same member. Mechanism- and access-independent,
/// so a Forge AT and a Fabric AW on the same member produce the same key.
pub(crate) fn target_key_owned(target_class: &str, member: Option<&str>) -> String {
    match member {
        Some(member) => format!("{target_class}#{member}"),
        None => target_class.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_forge_access_transformer() {
        let cfg = "\
# comment line
public net.minecraft.world.level.Level shouldUpdate()Z
public-f net.minecraft.world.entity.Entity field_5953
protected net.minecraft.server.MinecraftServer
";
        let d = parse_access_transformer(cfg);
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].access, "public");
        assert_eq!(d[0].target_class, "net.minecraft.world.level.Level");
        assert_eq!(d[0].member.as_deref(), Some("shouldUpdate()Z"));
        assert_eq!(d[1].access, "public");
        assert_eq!(d[1].qualifier, "f");
        assert_eq!(d[2].member, None); // class-level
    }

    #[test]
    fn parses_fabric_access_widener() {
        let aw = "\
accessWidener v2 named
# widen a method
accessible method net/minecraft/class_1234 method_5678 (Lnet/minecraft/class_1;)V
mutable field net/minecraft/class_1234 field_5678 I
transitive-extendable class net/minecraft/class_9999
";
        let d = parse_access_widener(aw);
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].mechanism, "access-widener");
        assert_eq!(d[0].access, "accessible");
        assert_eq!(d[0].target_class, "net.minecraft.class_1234");
        assert!(d[0].member.as_deref().unwrap().starts_with("method_5678"));
        assert_eq!(d[2].access, "extendable");
        assert_eq!(d[2].qualifier, "transitive");
        assert_eq!(d[2].member, None);
    }

    #[test]
    fn target_key_is_mechanism_independent() {
        let at = &parse_access_transformer("public net.minecraft.Foo bar()V")[0];
        let aw = &parse_access_widener(
            "accessWidener v1 named\naccessible method net/minecraft/Foo bar()V",
        )[0];
        assert_eq!(
            target_key_owned(&at.target_class, at.member.as_deref()),
            target_key_owned(&aw.target_class, aw.member.as_deref())
        );
    }

    #[test]
    fn empty_and_comment_only_inputs_yield_nothing() {
        assert!(parse_access_transformer("# just a comment\n\n").is_empty());
        assert!(parse_access_widener("accessWidener v1 named\n# c\n").is_empty());
    }
}
