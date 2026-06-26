//! Fact-schema contract gate (CI).
//!
//! Enforces that the stringly-typed fact model stays in sync with its declared
//! contract, so drift is caught here rather than in production analytics:
//!
//! 1. the [`kind::all_kinds`] registry matches the `pub const` declarations;
//! 2. every registered kind is declared exactly once in `schema.toml`, and no
//!    schema entry names a non-existent kind;
//! 3. the runtime typed-attribute table (`schema::constrained_attrs`) only names
//!    real kinds, and agrees with the static contract for `complete` kinds.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use intermed_facts::kind;
use intermed_facts::schema;
use intermed_facts::schema_contract::{self, AttrType};

/// The source of the `kind` module, parsed to recover the declared constants.
const LIB_SRC: &str = include_str!("../src/lib.rs");

/// Extract the predicate string of every `pub const X: &str = "y";` line.
fn declared_kind_values() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in LIB_SRC.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        // `NAME: &str = "value";`
        let Some((_, after_eq)) = rest.split_once('=') else {
            continue;
        };
        let after_eq = after_eq.trim();
        if let Some(inner) = after_eq.strip_prefix('"').and_then(|s| s.split('"').next()) {
            out.insert(inner.to_string());
        }
    }
    out
}

fn declared_kind_const_map() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in LIB_SRC.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, after_eq)) = rest.split_once('=') else {
            continue;
        };
        let name = name.split(':').next().unwrap_or("").trim();
        let after_eq = after_eq.trim();
        if let Some(inner) = after_eq.strip_prefix('"').and_then(|s| s.split('"').next()) {
            out.insert(name.to_string(), inner.to_string());
        }
    }
    out
}

#[test]
fn all_kinds_registry_matches_source_constants() {
    let declared = declared_kind_values();
    let registered: BTreeSet<String> = kind::all_kinds().iter().map(|s| s.to_string()).collect();

    let missing: Vec<_> = declared.difference(&registered).collect();
    let extra: Vec<_> = registered.difference(&declared).collect();
    assert!(
        missing.is_empty(),
        "kind constants missing from kind::all_kinds(): {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "kind::all_kinds() lists predicates with no `pub const`: {extra:?}"
    );
    // No duplicate predicate strings in the registry.
    assert_eq!(
        kind::all_kinds().len(),
        registered.len(),
        "duplicate predicate in kind::all_kinds()"
    );
}

#[test]
fn schema_declares_exactly_the_registered_kinds() {
    let contract = schema_contract::contract();
    let registered: BTreeSet<String> = kind::all_kinds().iter().map(|s| s.to_string()).collect();
    let declared: BTreeSet<String> = contract.kinds.keys().cloned().collect();

    let missing: Vec<_> = registered.difference(&declared).collect();
    let extra: Vec<_> = declared.difference(&registered).collect();
    assert!(
        missing.is_empty(),
        "kinds with no schema.toml entry: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "schema.toml entries for non-existent kinds: {extra:?}"
    );
}

#[test]
fn runtime_typed_attrs_agree_with_contract() {
    let contract = schema_contract::contract();
    let registered: BTreeSet<String> = kind::all_kinds().iter().map(|s| s.to_string()).collect();

    for (k, attr, ty) in schema::constrained_attrs() {
        assert!(
            registered.contains(*k),
            "typed schema constrains unknown kind `{k}`"
        );
        let Some(kind_schema) = contract.kind(k) else {
            continue; // covered by the previous test
        };
        if !kind_schema.complete {
            continue; // attributes not yet pinned for this kind
        }
        let declared = kind_schema.attrs.get(*attr);
        assert!(
            declared.is_some(),
            "kind `{k}` is `complete` but typed attr `{attr}` is not declared in schema.toml"
        );
        // The runtime types (Int/Float/Bool) must match the contract.
        let expected = match ty {
            schema::AttrType::Int => AttrType::Int,
            schema::AttrType::Float => AttrType::Float,
            schema::AttrType::Bool => AttrType::Bool,
        };
        assert_eq!(
            declared,
            Some(&expected),
            "type mismatch for `{k}.{attr}` between runtime schema and schema.toml"
        );
    }
}

#[derive(Debug)]
struct EmittedAttrs {
    attrs: BTreeMap<String, Vec<String>>,
}

impl EmittedAttrs {
    fn insert(&mut self, attr: String, location: String) {
        self.attrs.entry(attr).or_default().push(location);
    }

    fn attr_set(&self) -> BTreeSet<String> {
        self.attrs.keys().cloned().collect()
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read source dir") {
        let entry = entry.expect("read source entry");
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn source_before_tests(src: &str) -> String {
    let mut out = String::new();
    for line in src.lines() {
        if line.trim() == "#[cfg(test)]" {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn quoted_literals_after(line: &str, marker: &str) -> Vec<String> {
    let Some(start) = line.find(marker) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut chars = line[start + marker.len()..].chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut s = String::new();
        let mut escaped = false;
        for ch in chars.by_ref() {
            if escaped {
                s.push(ch);
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == '"' {
                break;
            }
            s.push(ch);
        }
        out.push(s);
    }
    out
}

fn kind_from_fact_line(line: &str, kind_consts: &BTreeMap<String, String>) -> Option<String> {
    if let Some(start) = line.find("kind::") {
        let rest = &line[start + "kind::".len()..];
        let ident: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        return kind_consts.get(&ident).cloned();
    }

    let quoted = quoted_literals_after(line, ".fact(");
    (quoted.len() >= 2).then(|| quoted[1].clone())
}

fn attr_from_line(line: &str) -> Option<String> {
    quoted_literals_after(line, ".attr(").into_iter().next()
}

fn first_string_literal(line: &str) -> Option<String> {
    quoted_literals_after(line, "").into_iter().next()
}

fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
}

fn statically_emitted_attrs() -> BTreeMap<String, EmittedAttrs> {
    let root = workspace_root();
    let mut files = Vec::new();
    for entry in fs::read_dir(root.join("crates")).expect("read workspace crates") {
        let entry = entry.expect("read crate entry");
        let src = entry.path().join("src");
        if src.is_dir() {
            rust_sources(&src, &mut files);
        }
    }
    let kind_consts = declared_kind_const_map();
    let mut out: BTreeMap<String, EmittedAttrs> = BTreeMap::new();

    for path in files {
        let src = source_before_tests(&fs::read_to_string(&path).expect("read Rust source"));
        let rel = path.strip_prefix(&root).unwrap_or(&path);
        let mut active: Option<(String, usize)> = None;
        let mut pending_attr = false;

        for (idx, line) in src.lines().enumerate() {
            let line_no = idx + 1;
            if is_comment(line) {
                continue;
            }

            if pending_attr {
                if let (Some((kind, start_line)), Some(attr)) =
                    (active.as_ref(), first_string_literal(line))
                {
                    out.entry(kind.clone())
                        .or_insert_with(|| EmittedAttrs {
                            attrs: BTreeMap::new(),
                        })
                        .insert(
                            attr,
                            format!("{}:{line_no} (fact at {start_line})", rel.display()),
                        );
                    pending_attr = false;
                }
            }

            if line.contains(".fact(") {
                active = kind_from_fact_line(line, &kind_consts).map(|kind| (kind, line_no));
            }

            if let Some((kind, start_line)) = active.as_ref() {
                if let Some(attr) = attr_from_line(line) {
                    out.entry(kind.clone())
                        .or_insert_with(|| EmittedAttrs {
                            attrs: BTreeMap::new(),
                        })
                        .insert(
                            attr,
                            format!("{}:{line_no} (fact at {start_line})", rel.display()),
                        );
                } else if line.contains(".attr(") {
                    pending_attr = true;
                }
            }

            if line.contains(".emit(") {
                active = None;
                pending_attr = false;
            }
        }
    }

    out
}

#[test]
fn complete_schema_matches_static_emitter_attrs() {
    let contract = schema_contract::contract();
    let emitted = statically_emitted_attrs();
    let mut bad = Vec::new();

    for (kind_name, observed) in emitted {
        let Some(kind_schema) = contract.kind(&kind_name) else {
            continue; // unknown-kind coverage is handled by other gates.
        };
        if !kind_schema.complete {
            continue;
        }
        let observed_attrs = observed.attr_set();
        let declared_attrs: BTreeSet<String> = kind_schema.attrs.keys().cloned().collect();

        for attr in observed_attrs.difference(&declared_attrs) {
            let locations = observed.attrs.get(attr).cloned().unwrap_or_default();
            bad.push(format!(
                "emitter writes `{kind_name}.{attr}` but schema.toml does not declare it: {locations:?}"
            ));
        }
        for attr in declared_attrs.difference(&observed_attrs) {
            bad.push(format!(
                "schema.toml declares `{kind_name}.{attr}` but no production emitter writes it"
            ));
        }
    }

    assert!(
        bad.is_empty(),
        "`complete = true` schema drift against production emitters: {bad:#?}"
    );
}
