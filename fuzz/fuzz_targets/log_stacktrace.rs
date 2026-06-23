#![no_main]
//! Fuzz the Layer-D crash/stacktrace parser. Logs are arbitrary user text; the
//! frame/cause walker must never panic on malformed traces (mismatched "Caused by",
//! truncated frames, multi-byte content).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = intermed_log::stacktrace::parse_stacktraces(&text);
});
