#![no_main]
//! Fuzz Layer-D physical-to-semantic normalization. Arbitrary launcher text
//! must not panic while splitting flattened traces, retaining byte/line
//! provenance, parsing throwable chains, or hashing event identities.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = intermed_log::runtime::expand_flattened_lines(&text);
    let _ = intermed_log::runtime::normalize_events(&text, "fuzz/source.log");
});
