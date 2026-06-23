#![no_main]
//! Fuzz the Layer-C version / range parsers. Versions and ranges come from mod
//! metadata (fabric.mod.json / mods.toml) which is attacker-influenced; the
//! lenient parsers must never panic and `version_in_range` must stay total.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let s = s.as_ref();
    let _ = intermed_deps::parse_mod_version(s);
    let _ = intermed_deps::parse_mod_range(s);
    let _ = intermed_deps::parse_version_reqs(s);
    let _ = intermed_deps::parse_lenient(s);
    // `version_in_range(version, range)`: split the input so both sides are fuzzed.
    if let Some((version, range)) = s.split_once('\n') {
        let _ = intermed_deps::version_in_range(version, range);
    }
});
