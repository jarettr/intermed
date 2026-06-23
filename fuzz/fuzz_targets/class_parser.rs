#![no_main]
//! Fuzz the mixin `.class` bytecode parser. Class bytes come straight from
//! untrusted mod jars, so the constant-pool / attribute walker must tolerate any
//! byte sequence without panicking (no OOB slice, no integer overflow).
//!
//! KNOWN UPSTREAM ISSUE (do not re-investigate as a local bug): with
//! `-detect_leaks=1`, `cafebabe` 0.9.0 (latest) leaks ~792 bytes of
//! `Rc<ConstantPoolEntry>` on some *malformed* constant pools (valid `CAFEBABE`
//! magic, corrupt body). Valid class files do not leak; our code drops the parsed
//! class and retains only owned `String`s, so the cycle is internal to the crate.
//! Impact is bounded and only on corrupt classes. Run with `-detect_leaks=0` to
//! fuzz purely for panics/OOB.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = intermed_mixin_intel::parse_mixin_class(data);
});
