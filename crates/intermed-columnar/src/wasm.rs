//! Real Wasmtime sandbox for `CallExternal` (plan Phase 4.1), behind the `wasm`
//! feature.
//!
//! A [`WasmFunction`] implements [`ExternalFunction`] by running a sandboxed
//! WebAssembly module. The data contract is a **JSON ABI** over the module's linear
//! memory — language-agnostic, so a guest can be written in any language that targets
//! WASM:
//!
//! The guest must export:
//! - `memory` — its linear memory.
//! - `alloc(len: i32) -> i32` — reserve `len` bytes, return the offset.
//! - `process(ptr: i32, len: i32) -> i64` — read the input JSON at `ptr..ptr+len`,
//!   write the output JSON into its memory, and return a packed `(out_ptr << 32) |
//!   out_len`.
//!
//! The host serializes the input [`Relation`] to a JSON array of row objects, hands it
//! over, and parses the returned JSON back into a [`Relation`].
//!
//! **Sandboxing.** The module is instantiated with **no imports**, so it has no host
//! capabilities (no I/O, no clock, no network). Execution is bounded by **fuel** and
//! memory by a **store limit**; a fresh store per call isolates invocations.

use serde_json::Value as Json;
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimitsBuilder};

use crate::error::ColumnarError;
use crate::external::ExternalFunction;
use crate::value::{Relation, Row, Value};

/// CPU budget (fuel units) per call. Generous, but bounds runaway guests.
const DEFAULT_FUEL: u64 = 1_000_000_000;
/// Linear-memory cap per call (bytes).
const DEFAULT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
/// Maximum module size accepted by `from_bytes`.
const DEFAULT_MODULE_LIMIT: usize = 16 * 1024 * 1024;
/// Maximum JSON input payload copied into guest memory.
const DEFAULT_INPUT_LIMIT: usize = 16 * 1024 * 1024;
/// Maximum rows a guest may return in one call.
const DEFAULT_OUTPUT_ROW_LIMIT: usize = 100_000;
/// Maximum parsed JSON nesting depth accepted from a guest.
const DEFAULT_JSON_DEPTH_LIMIT: usize = 64;

/// A sandboxed WebAssembly external function.
pub struct WasmFunction {
    name: String,
    engine: Engine,
    module: Module,
    fuel: u64,
    memory_limit: usize,
    input_limit: usize,
    output_row_limit: usize,
    json_depth_limit: usize,
}

fn err(e: impl std::fmt::Display) -> ColumnarError {
    ColumnarError::Schema(format!("wasm: {e}"))
}

impl WasmFunction {
    /// Build from raw `.wasm` (or `.wat`) bytes registered under `name`.
    pub fn from_bytes(name: impl Into<String>, bytes: &[u8]) -> Result<Self, ColumnarError> {
        if bytes.len() > DEFAULT_MODULE_LIMIT {
            return Err(err(format!(
                "module is too large: {} bytes > {DEFAULT_MODULE_LIMIT}",
                bytes.len()
            )));
        }
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(err)?;
        let module = Module::new(&engine, bytes).map_err(err)?;
        Ok(WasmFunction {
            name: name.into(),
            engine,
            module,
            fuel: DEFAULT_FUEL,
            memory_limit: DEFAULT_MEMORY_LIMIT,
            input_limit: DEFAULT_INPUT_LIMIT,
            output_row_limit: DEFAULT_OUTPUT_ROW_LIMIT,
            json_depth_limit: DEFAULT_JSON_DEPTH_LIMIT,
        })
    }

    /// Build from a `.wasm` file on disk.
    pub fn from_file(
        name: impl Into<String>,
        path: &std::path::Path,
    ) -> Result<Self, ColumnarError> {
        let bytes = std::fs::read(path).map_err(err)?;
        Self::from_bytes(name, &bytes)
    }

    /// Override the per-call fuel budget.
    pub fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel = fuel;
        self
    }

    /// Override the guest linear-memory and host output allocation cap.
    pub fn with_memory_limit(mut self, bytes: usize) -> Self {
        self.memory_limit = bytes;
        self
    }

    /// Override the maximum JSON input bytes copied into guest memory.
    pub fn with_input_limit(mut self, bytes: usize) -> Self {
        self.input_limit = bytes;
        self
    }

    /// Override the maximum output rows accepted from the guest.
    pub fn with_output_row_limit(mut self, rows: usize) -> Self {
        self.output_row_limit = rows;
        self
    }
}

impl ExternalFunction for WasmFunction {
    fn name(&self) -> &str {
        &self.name
    }

    fn call(&self, input: &Relation) -> Result<Relation, ColumnarError> {
        let payload = relation_to_json(input);
        let bytes = serde_json::to_vec(&payload).map_err(err)?;
        if bytes.len() > self.input_limit || bytes.len() > self.memory_limit {
            return Err(err(format!(
                "input JSON is too large: {} bytes (input_limit={}, memory_limit={})",
                bytes.len(),
                self.input_limit,
                self.memory_limit
            )));
        }

        let limits = StoreLimitsBuilder::new()
            .memory_size(self.memory_limit)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|l| l);
        store.set_fuel(self.fuel).map_err(err)?;

        // No imports ⇒ the guest has no host capabilities.
        let instance = Instance::new(&mut store, &self.module, &[]).map_err(err)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| err("module does not export `memory`"))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(err)?;
        let process = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "process")
            .map_err(err)?;

        let len = i32::try_from(bytes.len()).map_err(|_| err("input too large"))?;
        let ptr = alloc.call(&mut store, len).map_err(err)?;
        let ptr = usize::try_from(ptr).map_err(|_| err("alloc returned a negative pointer"))?;
        let input_end = ptr
            .checked_add(bytes.len())
            .ok_or_else(|| err("input pointer range overflowed"))?;
        if input_end > memory.data_size(&store) {
            return Err(err("guest alloc returned a pointer outside memory"));
        }
        memory.write(&mut store, ptr, &bytes).map_err(err)?;
        let packed = process.call(&mut store, (ptr as i32, len)).map_err(err)? as u64;
        let out_ptr = (packed >> 32) as usize;
        let out_len = (packed & 0xFFFF_FFFF) as usize;

        if out_len > self.memory_limit {
            return Err(err(format!(
                "guest output length {out_len} exceeds output limit {}",
                self.memory_limit
            )));
        }
        let out_end = out_ptr
            .checked_add(out_len)
            .ok_or_else(|| err("guest output pointer range overflowed"))?;
        if out_end > memory.data_size(&store) {
            return Err(err(format!(
                "guest output range {out_ptr}..{out_end} exceeds memory size {}",
                memory.data_size(&store)
            )));
        }

        let mut buf = vec![0u8; out_len];
        memory.read(&store, out_ptr, &mut buf).map_err(err)?;
        let out: Json = serde_json::from_slice(&buf).map_err(err)?;
        if json_depth(&out) > self.json_depth_limit {
            return Err(err(format!(
                "guest output JSON exceeds depth limit {}",
                self.json_depth_limit
            )));
        }
        json_to_relation(&out, self.output_row_limit)
    }
}

fn value_to_json(v: &Value) -> Json {
    match v {
        Value::Str(s) => Json::String(s.clone()),
        Value::Int(i) => Json::Number((*i).into()),
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Json::Number)
            .unwrap_or(Json::Null),
        Value::Bool(b) => Json::Bool(*b),
        Value::Null => Json::Null,
    }
}

fn json_to_value(j: &Json) -> Value {
    match j {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        Json::String(s) => Value::Str(s.clone()),
        // Arrays / nested objects have no scalar cell; keep their text form.
        other => Value::Str(other.to_string()),
    }
}

fn relation_to_json(rel: &Relation) -> Json {
    Json::Array(
        rel.rows
            .iter()
            .map(|row| {
                Json::Object(
                    row.iter()
                        .map(|(k, v)| (k.clone(), value_to_json(v)))
                        .collect(),
                )
            })
            .collect(),
    )
}

fn json_depth(j: &Json) -> usize {
    match j {
        Json::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Json::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn json_to_relation(j: &Json, row_limit: usize) -> Result<Relation, ColumnarError> {
    let rows = match j {
        Json::Array(arr) => {
            if arr.len() > row_limit {
                return Err(err(format!(
                    "guest returned {} rows, exceeding limit {row_limit}",
                    arr.len()
                )));
            }
            arr.iter()
                .filter_map(|item| match item {
                    Json::Object(map) => Some(
                        map.iter()
                            .map(|(k, v)| (k.clone(), json_to_value(v)))
                            .collect::<Row>(),
                    ),
                    _ => None,
                })
                .collect()
        }
        _ => Vec::new(),
    };
    Ok(Relation::new(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal guest implementing the ABI as an identity: it echoes the input bytes
    /// (returns the same `ptr`/`len` it was given). Proves the full JSON marshalling
    /// round-trip works through a real sandboxed module.
    const IDENTITY_WAT: &str = r#"
    (module
      (memory (export "memory") 4)
      (func (export "alloc") (param i32) (result i32)
        i32.const 1024)
      (func (export "process") (param i32 i32) (result i64)
        (i64.or
          (i64.shl (i64.extend_i32_u (local.get 0)) (i64.const 32))
          (i64.extend_i32_u (local.get 1)))))
    "#;

    const HUGE_OUTPUT_WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32)
        i32.const 0)
      (func (export "process") (param i32 i32) (result i64)
        i64.const 4294967295))
    "#;

    #[test]
    fn wasm_identity_round_trips_a_relation() {
        let wasm = wat::parse_str(IDENTITY_WAT).unwrap();
        let f = WasmFunction::from_bytes("identity", &wasm).unwrap();

        let mut row: Row = Row::new();
        row.insert("subject".into(), Value::Str("sodium".into()));
        row.insert("count".into(), Value::Int(3));
        let input = Relation::new(vec![row]);

        let out = f.call(&input).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out.rows[0].get("subject"),
            Some(&Value::Str("sodium".into()))
        );
        assert_eq!(out.rows[0].get("count"), Some(&Value::Int(3)));
    }

    #[test]
    fn guest_output_length_is_checked_before_host_allocation() {
        let wasm = wat::parse_str(HUGE_OUTPUT_WAT).unwrap();
        let f = WasmFunction::from_bytes("huge-output", &wasm).unwrap();

        let err = f.call(&Relation::new(Vec::new())).unwrap_err().to_string();
        assert!(err.contains("output length"), "{err}");
    }

    #[test]
    fn missing_export_is_an_error() {
        // A module with no `process` export fails cleanly (not a panic).
        let wasm = wat::parse_str("(module (memory (export \"memory\") 1))").unwrap();
        let f = WasmFunction::from_bytes("bad", &wasm).unwrap();
        assert!(f.call(&Relation::new(Vec::new())).is_err());
    }
}
