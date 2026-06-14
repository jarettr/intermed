//! Convert mod metadata range strings into PubGrub [`VersionSet`] values.

use creeper_semver_pubgrub::{SemverPubgrub, SmallVersion};

use crate::semver;

/// PubGrub version set used throughout Layer C.
pub type ModRange = SemverPubgrub<SmallVersion>;

/// Parse a mod dependency range into a PubGrub set. Returns `None` when the
/// range cannot be expressed in semver (conservative skip, same as pairwise).
pub fn parse_mod_range(range: &str) -> Option<ModRange> {
    let range = range.trim();
    if range.is_empty() || range == "*" {
        return Some(ModRange::full());
    }

    let reqs = semver::parse_version_reqs(range)?;
    if reqs.is_empty() {
        return None;
    }

    let mut union = ModRange::empty();
    for req in &reqs {
        let set = ModRange::from(req);
        union = union.union(&set);
    }
    Some(union)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::semver::Version;

    #[test]
    fn wildcard_is_full() {
        let full = parse_mod_range("*").expect("wildcard");
        let v = SmallVersion::from(Version::new(9, 9, 9));
        assert!(full.contains(&v));
    }

    #[test]
    fn fabric_and_range_parses() {
        let range = parse_mod_range(">=0.11.6 <0.12.0").expect("fabric range");
        let ok = SmallVersion::from(Version::new(0, 11, 7));
        let bad = SmallVersion::from(Version::new(0, 12, 0));
        assert!(range.contains(&ok));
        assert!(!range.contains(&bad));
    }
}