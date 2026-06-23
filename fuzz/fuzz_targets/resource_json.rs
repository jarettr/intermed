#![no_main]
//! Fuzz the resource-AST JSON syntax parser directly (the lenient JSON reader that
//! tolerates comments/trailing commas the way Minecraft loaders do). Must never
//! panic on arbitrary bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = intermed_resource_ast::syntax::json::parse(data);
});
