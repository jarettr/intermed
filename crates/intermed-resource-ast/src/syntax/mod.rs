//! Syntax layer: bytes → faithful syntax tree, before any domain meaning.
//!
//! JSON is the dominant resource format (`serde_json::Value` is its syntax tree);
//! `.lang` properties and `.mcfunction` scripts are line-oriented. Domain parsers
//! consume these neutral trees and never re-read raw bytes.

pub mod json;
pub mod properties;
