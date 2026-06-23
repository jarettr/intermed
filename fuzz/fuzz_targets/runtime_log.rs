#![no_main]
//! Fuzz the Mixin runtime-log parser. Logs are arbitrary text (possibly with
//! multi-byte Unicode spaces); the token walkers must stay on char boundaries —
//! this is the surface of the `&line[start..]` "not a char boundary" bug.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let log = String::from_utf8_lossy(data);
    let _ = intermed_mixin_intel::parse_runtime_failures(&log);
});
