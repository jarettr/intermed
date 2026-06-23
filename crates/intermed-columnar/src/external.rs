//! External-function contract for `CallExternal` (plan Phase 4.1).
//!
//! The IR's [`CallExternal`](crate::ir::RelExpr::CallExternal) node hands a relation to
//! a named external module (the plan's WASM sandbox endpoint). This module defines the
//! **contract** without committing to a sandbox runtime:
//!
//! - **Registration.** External functions are *pre-registered* by name in a
//!   [`FunctionRegistry`]. The engine only ever calls functions the host installed —
//!   there is no path to execute arbitrary code, so the model is capability-safe by
//!   construction (the same discipline as the declarative rule packs).
//! - **Data exchange.** In-process functions implement [`ExternalFunction`] over a
//!   [`Relation`] (rows in, rows out). The ABI-stable, out-of-process boundary (a real
//!   Wasmtime/Souffle module) is the Arrow **C Data Interface** already provided by
//!   [`ffi`](crate::ffi): a host converts the relation to a `RecordBatch`, exports it
//!   over the C Data Interface, the module returns a `RecordBatch`, and it is imported
//!   back. A future `WasmFunction` implements [`ExternalFunction`] by doing exactly
//!   that; nothing else in the engine changes.
//! - **Security.** A registered function is trusted by the host that registered it.
//!   The deferred WASM backend adds the sandbox's own guarantees (fuel, memory limits,
//!   no ambient capabilities) behind this same trait.
//!
//! When a `CallExternal` names a module that is *not* registered, the engine passes its
//! input through unchanged (the historical behavior), so plans remain runnable without
//! any functions installed.

use crate::error::ColumnarError;
use crate::value::Relation;

/// A host-provided function the query engine can invoke by name over a relation.
pub trait ExternalFunction: Send + Sync {
    /// The module name this function answers to (matches `CallExternal { module }`).
    fn name(&self) -> &str;

    /// Transform the input relation into an output relation. Errors surface as a
    /// [`ColumnarError`] and abort the query.
    fn call(&self, input: &Relation) -> Result<Relation, ColumnarError>;
}

/// A registry of external functions, keyed by module name. An empty registry makes
/// every `CallExternal` a pass-through.
#[derive(Default)]
pub struct FunctionRegistry {
    functions: Vec<Box<dyn ExternalFunction>>,
}

impl FunctionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty registry (pass-through for all external calls).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Register a function. Later registrations of the same name shadow earlier ones.
    pub fn register(&mut self, function: Box<dyn ExternalFunction>) -> &mut Self {
        self.functions.push(function);
        self
    }

    /// Look up a function by module name (last registration wins).
    pub fn get(&self, module: &str) -> Option<&dyn ExternalFunction> {
        self.functions
            .iter()
            .rev()
            .find(|f| f.name() == module)
            .map(|f| f.as_ref())
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::{Row, Value};

    /// A trivial external function: tag every row with `external = "seen"`.
    struct Tagger;
    impl ExternalFunction for Tagger {
        fn name(&self) -> &str {
            "tagger"
        }
        fn call(&self, input: &Relation) -> Result<Relation, ColumnarError> {
            let rows = input
                .rows
                .iter()
                .map(|r| {
                    let mut row: Row = r.clone();
                    row.insert("external".into(), Value::Str("seen".into()));
                    row
                })
                .collect();
            Ok(Relation::new(rows))
        }
    }

    #[test]
    fn registry_resolves_and_shadows() {
        let mut reg = FunctionRegistry::new();
        assert!(reg.is_empty());
        reg.register(Box::new(Tagger));
        assert!(reg.get("tagger").is_some());
        assert!(reg.get("missing").is_none());
    }

    #[test]
    fn function_transforms_a_relation() {
        let f = Tagger;
        let input = Relation::new(vec![
            [("a".to_string(), Value::Int(1))].into_iter().collect(),
        ]);
        let out = f.call(&input).unwrap();
        assert_eq!(
            out.rows[0].get("external"),
            Some(&Value::Str("seen".into()))
        );
    }
}
