//! Property + fuzz tests for the Layer-M parsers and semantic invariants.
//!
//! These guard the two contracts that make the cache and the safe-merge logic
//! sound: (1) the semantic hash is order-independent, so two writers that differ
//! only in key/entry order are recognised as identical; and (2) no malformed mod
//! resource can ever panic the parser.

use intermed_resource_ast::model::ResourceSummary;
use intermed_resource_ast::{parse_resource, ResourceLevel};
use proptest::prelude::*;

/// A namespaced id like `ns:path` from constrained chars (valid Minecraft ids).
fn id_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,8}:[a-z][a-z0-9_/]{0,12}"
}

proptest! {
    /// The semantic hash of a recipe is invariant under output ordering: a recipe
    /// listing results [a, b] hashes the same as one listing [b, a]. This is what
    /// lets the diff layer treat key-reordered duplicates as identical.
    #[test]
    fn recipe_semantic_hash_is_order_independent(
        outputs in prop::collection::vec(id_strategy(), 1..6)
    ) {
        let forward: Vec<_> = outputs.iter().map(|o| serde_json::json!({"item": o})).collect();
        let mut rev = forward.clone();
        rev.reverse();

        let a = serde_json::json!({"type": "minecraft:crafting_shapeless", "results": forward});
        let b = serde_json::json!({"type": "minecraft:crafting_shapeless", "results": rev});

        let pa = parse_resource("data/c/recipe/x.json", a.to_string().as_bytes(), ResourceLevel::Full);
        let pb = parse_resource("data/c/recipe/x.json", b.to_string().as_bytes(), ResourceLevel::Full);
        prop_assert_eq!(pa.semantic_hash, pb.semantic_hash);
    }

    /// Tag entry sets are order-independent and de-duplicated, so the summary is a
    /// canonical set: union with a permutation/duplication yields the same hash.
    #[test]
    fn tag_entries_are_a_canonical_set(
        values in prop::collection::vec(id_strategy(), 1..8)
    ) {
        let mut dup = values.clone();
        dup.extend(values.iter().cloned()); // duplicate every entry
        dup.reverse();

        let a = serde_json::json!({"values": values});
        let b = serde_json::json!({"values": dup});
        let pa = parse_resource("data/c/tags/items/t.json", a.to_string().as_bytes(), ResourceLevel::Full);
        let pb = parse_resource("data/c/tags/items/t.json", b.to_string().as_bytes(), ResourceLevel::Full);

        // Idempotent + commutative: duplicates and reordering collapse to one set.
        if let (ResourceSummary::Tag(sa), ResourceSummary::Tag(sb)) = (&pa.summary, &pb.summary) {
            prop_assert_eq!(&sa.entries, &sb.entries);
        }
        prop_assert_eq!(pa.semantic_hash, pb.semantic_hash);
    }

    /// Fuzz: arbitrary bytes at any classified path never panic — they become an
    /// `Invalid`/`Skipped` AST, never a crash. Untrusted jars must be safe.
    #[test]
    fn parse_never_panics_on_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..512),
        which in 0usize..6,
    ) {
        let path = ["data/c/tags/items/x.json", "data/c/recipe/x.json",
                    "assets/c/lang/en_us.json", "pack.mcmeta",
                    "assets/c/models/item/x.json", "data/c/loot_table/x.json"][which];
        // Must not panic; result is intentionally ignored.
        let _ = parse_resource(path, &bytes, ResourceLevel::Full);
    }

    /// Fuzz: structurally-valid-but-weird JSON also never panics.
    #[test]
    fn parse_never_panics_on_arbitrary_json(
        json in any::<String>().prop_filter("non-empty", |s| !s.is_empty()),
    ) {
        let wrapped = format!("{{\"type\":{json:?},\"values\":[{json:?}]}}");
        let _ = parse_resource("data/c/tags/items/x.json", wrapped.as_bytes(), ResourceLevel::Full);
        let _ = parse_resource("data/c/recipe/x.json", wrapped.as_bytes(), ResourceLevel::Full);
    }
}
