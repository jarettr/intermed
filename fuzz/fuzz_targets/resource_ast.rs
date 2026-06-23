#![no_main]
//! Fuzz the Layer-M resource/data parser across every domain. `parse_resource`
//! dispatches on the path to the recipe/loot/tag/model/blockstate/atlas/lang/
//! pack_mcmeta/worldgen analyzers — all of which read untrusted JSON from jars.
//! None may panic on arbitrary bytes, at any resource level.
use intermed_resource_ast::{parse_resource, ResourceLevel};
use libfuzzer_sys::fuzz_target;

const PATHS: &[&str] = &[
    "data/m/recipe/x.json",
    "data/m/loot_table/x.json",
    "data/m/tags/items/x.json",
    "assets/m/models/block/x.json",
    "assets/m/blockstates/x.json",
    "assets/m/atlases/blocks.json",
    "assets/m/lang/en_us.json",
    "pack.mcmeta",
    "data/m/worldgen/biome/x.json",
    "data/m/advancement/x.json",
    "data/m/predicate/x.json",
];

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // First byte selects the domain (so the fuzzer can steer toward any analyzer);
    // the rest is the file body.
    let path = PATHS[data[0] as usize % PATHS.len()];
    let bytes = &data[1..];
    for level in [
        ResourceLevel::Basic,
        ResourceLevel::Semantic,
        ResourceLevel::Full,
    ] {
        let _ = parse_resource(path, bytes, level);
    }
});
