//! Well-known namespace ↔ mod-id aliases.
//!
//! A mod's resource namespace is frequently *not* its mod id: Applied
//! Energistics 2 ships resources under `ae2` but its mod id is
//! `appliedenergistics2`; Just Enough Items uses `jei`. Without this table the
//! implicit-dependency resolver would treat `ae2:*` references as a missing mod
//! even when AE2 is installed — a confident false positive.
//!
//! The table is intentionally small and curated (high-confidence, widely-known
//! aliases only). It is bidirectional: querying either side returns the other.

/// Curated `(a, b)` alias pairs. Order within a pair is irrelevant — lookups are
/// symmetric. Keep entries to well-established mods where the namespace/id split
/// is stable across versions.
const ALIAS_PAIRS: &[(&str, &str)] = &[
    ("ae2", "appliedenergistics2"),
    ("jei", "jeed"),
    ("jei", "justenoughitems"),
    ("rei", "roughlyenoughitems"),
    ("create", "createaddition"),
    ("ie", "immersiveengineering"),
    ("mekanism", "mekanismgenerators"),
    ("cfm", "moderfurniture"),
    ("supplementaries", "supplementariescore"),
    ("ftbquests", "ftblibrary"),
    ("emi", "emi_loot"),
];

/// Alternate ids a namespace might be provided under (well-known aliases).
///
/// Returns every counterpart of `ns` in the alias table. Empty when `ns` has no
/// known alias — callers fall back to exact matching.
#[must_use]
pub fn namespace_aliases(ns: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (a, b) in ALIAS_PAIRS {
        if *a == ns {
            out.push(*b);
        } else if *b == ns {
            out.push(*a);
        }
    }
    out
}

/// Whether `ns` is satisfied by an installed id set, allowing for known aliases:
/// `ns` itself is installed, or one of its aliases is.
#[must_use]
pub fn is_satisfied_by<S: AsRef<str>>(ns: &str, installed: impl IntoIterator<Item = S>) -> bool {
    let aliases = namespace_aliases(ns);
    installed
        .into_iter()
        .any(|id| id.as_ref() == ns || aliases.iter().any(|a| *a == id.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_are_bidirectional() {
        assert!(namespace_aliases("ae2").contains(&"appliedenergistics2"));
        assert!(namespace_aliases("appliedenergistics2").contains(&"ae2"));
        assert!(namespace_aliases("unknownmod").is_empty());
    }

    #[test]
    fn satisfied_via_alias() {
        let installed = ["appliedenergistics2".to_string()];
        assert!(is_satisfied_by("ae2", &installed));
        assert!(!is_satisfied_by("thermal", &installed));
        assert!(is_satisfied_by("appliedenergistics2", &installed));
    }
}
