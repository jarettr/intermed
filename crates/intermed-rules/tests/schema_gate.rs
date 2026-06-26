//! Rule-side schema contract gate (CI).
//!
//! The fact schema is only useful if rule packs cannot drift from it. This gate
//! checks the embedded core pack against the contract:
//!
//! 1. every fact kind a rule consumes (`input_kinds`, join/correlation arms,
//!    `related_kinds`) is a registered kind — a typo'd kind silently matches
//!    nothing, which this catches;
//! 2. for a `fact-finding` rule over a single `complete` kind, every attribute
//!    its `where_all` / `where_not` filters reference is declared on that kind in
//!    `schema.toml` — the explicit opt-out is marking a kind `complete = false`.

use std::collections::BTreeSet;

use intermed_doctor_core::facts::{kind, schema_contract};
use intermed_rules::{RuleSpec, default_core_pack_v2};

fn registered_kinds() -> BTreeSet<String> {
    kind::all_kinds().iter().map(|s| s.to_string()).collect()
}

/// Every fact kind a rule reads from.
fn consumed_kinds(rule: &RuleSpec) -> Vec<String> {
    let mut out = rule.input_kinds.clone();
    for arm in [
        rule.left.as_ref(),
        rule.right.as_ref(),
        rule.anchor.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        out.push(arm.kind.clone());
    }
    out.extend(rule.related_kinds.iter().cloned());
    if let Some(ev) = &rule.evidence {
        out.push(ev.kind.clone());
    }
    out
}

#[test]
fn core_rules_only_reference_registered_kinds() {
    let pack = default_core_pack_v2();
    let registered = registered_kinds();
    let mut bad = Vec::new();
    for rule in &pack.rules {
        for k in consumed_kinds(rule) {
            if !registered.contains(&k) {
                bad.push(format!("{}: unknown kind `{k}`", rule.id));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "rules reference unregistered kinds: {bad:#?}"
    );
}

#[test]
fn fact_finding_filters_use_declared_attrs_on_complete_kinds() {
    let pack = default_core_pack_v2();
    let contract = schema_contract::contract();
    let mut bad = Vec::new();

    for rule in &pack.rules {
        // Only fact-finding rules over a single input kind have an unambiguous
        // owning kind for their `where_*` attribute filters.
        if rule.input_kinds.len() != 1 {
            continue;
        }
        let kind_name = &rule.input_kinds[0];
        let Some(kind_schema) = contract.kind(kind_name) else {
            continue; // unknown-kind case is the previous test's job
        };
        if !kind_schema.complete {
            continue; // attributes not yet pinned for this kind (explicit opt-out)
        }
        for key in rule.where_all.keys().chain(rule.where_not.keys()) {
            // Filters key on `attr:NAME`; `subject`/`kind` are intrinsic.
            let Some(attr) = key.strip_prefix("attr:") else {
                continue;
            };
            if !kind_schema.attrs.contains_key(attr) {
                bad.push(format!(
                    "{}: reads `{kind_name}.attr:{attr}` not declared in schema.toml",
                    rule.id
                ));
            }
        }
    }

    assert!(
        bad.is_empty(),
        "rules read attributes not declared on their (complete) input kind: {bad:#?}"
    );
}
