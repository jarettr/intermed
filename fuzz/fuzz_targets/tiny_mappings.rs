#![no_main]
//! Fuzz the Tiny v2 mapping parser. A corrupt/truncated mapping file from a jar
//! must never panic — this is the surface of the `namespaces.len() - 1` underflow
//! bug (a header with no namespace columns).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Lossy so arbitrary bytes (including multi-byte UTF-8) reach the parser.
    let text = String::from_utf8_lossy(data);
    let _ = intermed_mixin_intel::TinyMappings::parse(&text);
});
