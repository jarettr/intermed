//! Universal interpreter that evaluates [`RuleSpec`] directly over a [`FactStore`].
//!
//! All declarative backends (in-process, DuckDB row mapping, Soufflé) share this
//! logic for finding construction; SQL/Datalog codegen only materialize candidate rows.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use intermed_doctor_core::RuleCtx;
use intermed_doctor_core::evidence::{EvidenceEdge, Finding, FixCandidate};
use intermed_doctor_core::facts::{Fact, FactId};

use crate::expr::{ExprCtx, eval_bool, resolve_term, term_value};
use crate::join_plan::{BROADCAST_SIDE_MAX, index_facts_by_term, plan_equijoins};
use crate::model::{RuleKind, RulePack, RuleSpec};
use crate::template::{
    VarMap, default_confidence, parse_category, parse_severity, render_finding_fields,
};

/// Evaluate every rule in `pack` and return findings. A single [`EvidenceCache`] is
/// shared across all rules, so rules with the same related-evidence spec build the
/// candidate index once for the whole pack.
pub fn evaluate_pack<'a>(pack: &RulePack, ctx: &RuleCtx<'a>) -> Vec<Finding> {
    let settings = settings_literals(ctx.settings);
    let cache = EvidenceCache::new();
    let mut out = Vec::new();
    for spec in &pack.rules {
        match spec.kind {
            RuleKind::GroupDistinct => {
                evaluate_group_distinct(ctx, spec, &settings, &mut out, &cache)
            }
            RuleKind::FactFinding => evaluate_fact_finding(ctx, spec, &settings, &mut out, &cache),
            RuleKind::Join => evaluate_join(ctx, spec, &settings, &mut out, &cache),
            RuleKind::Aggregate => evaluate_aggregate(ctx, spec, &settings, &mut out, &cache),
            RuleKind::Correlation => evaluate_correlation(ctx, spec, &settings, &mut out, &cache),
        }
    }
    out
}

fn settings_literals(
    settings: &intermed_doctor_core::DiagnosisSettings,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "settings.sbom.well_identified_trust".to_string(),
        settings.sbom.well_identified_trust.to_string(),
    );
    map.insert(
        "settings.security.min_note_signals".to_string(),
        settings.security.min_note_signals.to_string(),
    );
    map
}

fn evaluate_group_distinct<'a>(
    ctx: &RuleCtx<'a>,
    spec: &RuleSpec,
    settings: &BTreeMap<String, String>,
    out: &mut Vec<Finding>,
    cache: &EvidenceCache<'a>,
) {
    let Some(group_by) = &spec.group_by else {
        return;
    };
    let Some(distinct) = &spec.distinct else {
        return;
    };
    let prepared = prepare_evidence(spec, ctx, settings, cache);

    let mut groups: BTreeMap<String, Vec<&Fact>> = BTreeMap::new();
    for fact in matching_facts_v1(ctx, spec) {
        if let Some(key) = term_value(fact, group_by) {
            groups.entry(key).or_default().push(fact);
        }
    }

    for (key, facts) in groups {
        let distinct_values: BTreeSet<String> = facts
            .iter()
            .filter_map(|fact| term_value(fact, distinct))
            .collect();
        if distinct_values.len() < spec.min_count {
            continue;
        }

        let mut vars = VarMap::new();
        vars.insert("group".to_string(), key);
        vars.insert("count".to_string(), distinct_values.len().to_string());
        vars.insert(
            "values".to_string(),
            distinct_values.into_iter().collect::<Vec<_>>().join(", "),
        );
        out.push(build_finding(
            spec,
            &vars,
            facts,
            settings,
            prepared.as_ref(),
        ));
    }
}

fn evaluate_fact_finding<'a>(
    ctx: &RuleCtx<'a>,
    spec: &RuleSpec,
    settings: &BTreeMap<String, String>,
    out: &mut Vec<Finding>,
    cache: &EvidenceCache<'a>,
) {
    let alias = spec.alias.as_deref().unwrap_or("f");
    let where_expr = spec.r#where.as_deref();
    let prepared = prepare_evidence(spec, ctx, settings, cache);
    for fact in matching_facts_v1(ctx, spec) {
        // Honor a full `where` expression (single binding) in addition to the v1
        // `where_all`/`where_not` maps, so external rulepacks behave as authored.
        if let Some(expr) = where_expr {
            let bindings = single_binding(alias, fact);
            let ectx = ExprCtx {
                bindings: &bindings,
                settings,
                vars: None,
            };
            if !crate::expr::eval_bool(expr, &ectx) {
                continue;
            }
        }
        let vars = vars_from_fact(fact);
        out.push(build_finding(
            spec,
            &vars,
            vec![fact],
            settings,
            prepared.as_ref(),
        ));
    }
}

fn evaluate_join<'a>(
    ctx: &RuleCtx<'a>,
    spec: &RuleSpec,
    settings: &BTreeMap<String, String>,
    out: &mut Vec<Finding>,
    cache: &EvidenceCache<'a>,
) {
    let (Some(left), Some(right)) = (&spec.left, &spec.right) else {
        return;
    };
    let on = spec.on.as_deref().unwrap_or("TRUE");
    let filter = spec.r#where.as_deref().unwrap_or("TRUE");

    let left_facts: Vec<&Fact> = ctx.store.by_kind(&left.kind).collect();
    let right_facts: Vec<&Fact> = ctx.store.by_kind(&right.kind).collect();
    if left_facts.is_empty() || right_facts.is_empty() {
        return;
    }
    let prepared = prepare_evidence(spec, ctx, settings, cache);

    let equijoins = plan_equijoins(on, &left.alias, &right.alias);
    if let Some(key) = equijoins.first() {
        let right_index =
            index_facts_by_term(&right_facts, &right.alias, &key.right_term, settings);
        for lf in &left_facts {
            let left_only = single_binding(&left.alias, lf);
            let left_ctx = ExprCtx {
                bindings: &left_only,
                settings,
                vars: None,
            };
            let Some(join_val) = resolve_term(&key.left_term, &left_ctx) else {
                continue;
            };
            let Some(candidates) = right_index.get(&join_val) else {
                continue;
            };
            for rf in candidates {
                let mut bindings = BTreeMap::new();
                bindings.insert(left.alias.clone(), *lf);
                bindings.insert(right.alias.clone(), *rf);
                let expr_ctx = ExprCtx {
                    bindings: &bindings,
                    settings,
                    vars: None,
                };
                if !eval_bool(on, &expr_ctx) || !eval_bool(filter, &expr_ctx) {
                    continue;
                }
                let vars = vars_from_bindings(&bindings);
                let facts = vec![*lf, *rf];
                out.push(build_finding(
                    spec,
                    &vars,
                    facts,
                    settings,
                    prepared.as_ref(),
                ));
            }
        }
        return;
    }

    // `on: TRUE` with a tiny right relation (typical: one `environment` fact).
    if equijoins.is_empty()
        && on.eq_ignore_ascii_case("true")
        && right_facts.len() <= BROADCAST_SIDE_MAX
    {
        for lf in &left_facts {
            for rf in &right_facts {
                let mut bindings = BTreeMap::new();
                bindings.insert(left.alias.clone(), *lf);
                bindings.insert(right.alias.clone(), *rf);
                let expr_ctx = ExprCtx {
                    bindings: &bindings,
                    settings,
                    vars: None,
                };
                if !eval_bool(filter, &expr_ctx) {
                    continue;
                }
                let vars = vars_from_bindings(&bindings);
                let facts = vec![*lf, *rf];
                out.push(build_finding(
                    spec,
                    &vars,
                    facts,
                    settings,
                    prepared.as_ref(),
                ));
            }
        }
        return;
    }

    for lf in &left_facts {
        for rf in &right_facts {
            let mut bindings = BTreeMap::new();
            bindings.insert(left.alias.clone(), *lf);
            bindings.insert(right.alias.clone(), *rf);
            let expr_ctx = ExprCtx {
                bindings: &bindings,
                settings,
                vars: None,
            };
            if !eval_bool(on, &expr_ctx) || !eval_bool(filter, &expr_ctx) {
                continue;
            }
            let vars = vars_from_bindings(&bindings);
            let facts = vec![*lf, *rf];
            out.push(build_finding(
                spec,
                &vars,
                facts,
                settings,
                prepared.as_ref(),
            ));
        }
    }
}

fn evaluate_aggregate<'a>(
    ctx: &RuleCtx<'a>,
    spec: &RuleSpec,
    settings: &BTreeMap<String, String>,
    out: &mut Vec<Finding>,
    cache: &EvidenceCache<'a>,
) {
    let Some(input) = &spec.input else {
        return;
    };
    let group_fields: Vec<String> = if !spec.group_by_fields.is_empty() {
        spec.group_by_fields.clone()
    } else {
        spec.group_by.clone().into_iter().collect()
    };
    if group_fields.is_empty() {
        return;
    }
    let prepared = prepare_evidence(spec, ctx, settings, cache);

    let mut groups: BTreeMap<Vec<String>, Vec<&Fact>> = BTreeMap::new();
    for fact in ctx.store.by_kind(&input.kind) {
        let key: Vec<String> = group_fields
            .iter()
            .filter_map(|field| {
                let term = if field.contains('.') {
                    field.clone()
                } else {
                    format!("{}.{}", input.alias, field)
                };
                resolve_term(
                    &term,
                    &ExprCtx {
                        bindings: &single_binding(&input.alias, fact),
                        settings,
                        vars: None,
                    },
                )
            })
            .collect();
        if key.len() != group_fields.len() {
            continue;
        }
        groups.entry(key).or_default().push(fact);
    }

    let having = spec.having.as_deref().unwrap_or("TRUE");
    for (keys, facts) in groups {
        let representative = facts[0];
        let bindings = single_binding(&input.alias, representative);
        let mut vars = vars_from_bindings(&bindings);
        for (idx, field) in group_fields.iter().enumerate() {
            let short = field
                .split('.')
                .next_back()
                .unwrap_or(field.as_str())
                .to_string();
            if let Some(val) = keys.get(idx) {
                vars.insert(short.clone(), val.clone());
                vars.insert(format!("{}.{}", input.alias, short), val.clone());
            }
        }
        if let Some(distinct) = &spec.distinct {
            let distinct_count = facts
                .iter()
                .filter_map(|f| term_value(f, distinct))
                .collect::<BTreeSet<_>>()
                .len();
            vars.insert("count".to_string(), distinct_count.to_string());
            if distinct_count < spec.min_count {
                continue;
            }
        }
        // `having` can reference the computed aggregate (`count`, the group key
        // shorts) — feed `vars` so e.g. `having: "count >= 3"` works.
        let expr_ctx = ExprCtx {
            bindings: &bindings,
            settings,
            vars: Some(&vars),
        };
        if !eval_bool(having, &expr_ctx) {
            continue;
        }
        out.push(build_finding(
            spec,
            &vars,
            facts,
            settings,
            prepared.as_ref(),
        ));
    }
}

fn evaluate_correlation<'a>(
    ctx: &RuleCtx<'a>,
    spec: &RuleSpec,
    settings: &BTreeMap<String, String>,
    out: &mut Vec<Finding>,
    cache: &EvidenceCache<'a>,
) {
    let Some(anchor_src) = &spec.anchor else {
        return;
    };
    let match_on = spec.match_on.as_deref().unwrap_or("TRUE");
    let filter = spec.r#where.as_deref().unwrap_or("TRUE");
    let prepared = prepare_evidence(spec, ctx, settings, cache);

    let equijoins = plan_equijoins(match_on, &anchor_src.alias, "related");
    let related_index = if let Some(key) = equijoins.first() {
        let mut buckets: BTreeMap<String, Vec<&Fact>> = BTreeMap::new();
        for kind_name in &spec.related_kinds {
            let facts: Vec<&Fact> = ctx.store.by_kind(kind_name).collect();
            let index = index_facts_by_term(&facts, "related", &key.right_term, settings);
            for (k, group) in index {
                buckets.entry(k).or_default().extend(group);
            }
        }
        Some((key.left_term.clone(), buckets))
    } else {
        None
    };

    for anchor in ctx.store.by_kind(&anchor_src.kind) {
        let mut bindings = single_binding(&anchor_src.alias, anchor);
        let expr_ctx = ExprCtx {
            bindings: &bindings,
            settings,
            vars: None,
        };
        if !eval_bool(filter, &expr_ctx) {
            continue;
        }

        let mut related: Vec<&Fact> = Vec::new();
        if let Some((left_term, buckets)) = &related_index {
            if let Some(join_val) = resolve_term(left_term, &expr_ctx) {
                if let Some(candidates) = buckets.get(&join_val) {
                    for candidate in candidates {
                        bindings.insert("related".to_string(), candidate);
                        let related_ctx = ExprCtx {
                            bindings: &bindings,
                            settings,
                            vars: None,
                        };
                        if eval_bool(match_on, &related_ctx) {
                            related.push(candidate);
                        }
                        bindings.remove("related");
                    }
                }
            }
        } else {
            for kind_name in &spec.related_kinds {
                for candidate in ctx.store.by_kind(kind_name) {
                    bindings.insert("related".to_string(), candidate);
                    let related_ctx = ExprCtx {
                        bindings: &bindings,
                        settings,
                        vars: None,
                    };
                    if eval_bool(match_on, &related_ctx) {
                        related.push(candidate);
                    }
                    bindings.remove("related");
                }
            }
        }
        if related.is_empty() {
            continue;
        }

        let mut vars = vars_from_bindings(&bindings);
        vars.insert("subject".to_string(), anchor.subject.clone());
        let labels: BTreeSet<String> = related.iter().map(|f| f.kind.replace('_', " ")).collect();
        vars.insert(
            "capabilities".to_string(),
            labels.into_iter().collect::<Vec<_>>().join(", "),
        );
        vars.insert(
            "trust".to_string(),
            anchor
                .attr("trust_score")
                .map(str::to_string)
                .or_else(|| term_value(anchor, "attr:trust_score"))
                .unwrap_or_else(|| "0".to_string()),
        );

        let mut facts = vec![anchor];
        facts.extend(related);
        out.push(build_finding(
            spec,
            &vars,
            facts,
            settings,
            prepared.as_ref(),
        ));
    }
}

fn matching_facts_v1<'a>(
    ctx: &'a RuleCtx<'_>,
    spec: &'a RuleSpec,
) -> impl Iterator<Item = &'a Fact> + 'a {
    ctx.store
        .all()
        .iter()
        .filter(move |fact| matches_where_v1(fact, spec))
}

/// Build the findings for a `FactFinding` rule from a set of *already-matched* facts
/// (e.g. ids returned by the IR→Datalog/Souffle or IR→DuckDB backend). Emission reuses
/// the interpreter's `build_finding`, so a backend only does the *matching* — the
/// finding content is identical regardless of which backend matched, by construction.
pub fn fact_finding_findings<'a>(
    spec: &RuleSpec,
    matched: &[&Fact],
    ctx: &RuleCtx<'a>,
    cache: &EvidenceCache<'a>,
) -> Vec<Finding> {
    let settings = settings_literals(ctx.settings);
    // The related-evidence index comes from the pack-shared cache (built once per
    // evidence spec), so backends that emit rule-by-rule still share it across rules.
    let prepared = prepare_evidence(spec, ctx, &settings, cache);
    matched
        .iter()
        .map(|fact| {
            let vars = vars_from_fact(fact);
            build_finding(spec, &vars, vec![*fact], &settings, prepared.as_ref())
        })
        .collect()
}

/// Build the findings for a `Join` rule from engine-matched `(left_fact_id,
/// right_fact_id)` pairs. Emission reuses `vars_from_bindings` + `build_finding`, so it
/// is byte-identical to the interpreter's join loop given the same matched pairs (the
/// IR `JoinFilter` matching is proven ≡ interpreter via the Soufflé/DuckDB backends).
pub fn join_findings<'a>(
    spec: &RuleSpec,
    matched: &[(u64, u64)],
    ctx: &RuleCtx<'a>,
    cache: &EvidenceCache<'a>,
) -> Vec<Finding> {
    let (Some(left), Some(right)) = (&spec.left, &spec.right) else {
        return Vec::new();
    };
    let settings = settings_literals(ctx.settings);
    let prepared = prepare_evidence(spec, ctx, &settings, cache);
    matched
        .iter()
        .filter_map(|(lid, rid)| {
            let lf = ctx.store.get(FactId(*lid))?;
            let rf = ctx.store.get(FactId(*rid))?;
            let mut bindings = BTreeMap::new();
            bindings.insert(left.alias.clone(), lf);
            bindings.insert(right.alias.clone(), rf);
            let vars = vars_from_bindings(&bindings);
            Some(build_finding(
                spec,
                &vars,
                vec![lf, rf],
                &settings,
                prepared.as_ref(),
            ))
        })
        .collect()
}

/// Build the findings for a `GroupDistinct` rule from the engine-matched group keys
/// (the subjects whose distinct count met `min_count`). Re-gathers each group's member
/// facts and distinct values so the `{group}`/`{count}`/`{values}` vars and the evidence
/// match the interpreter's group loop exactly.
pub fn group_distinct_findings<'a>(
    spec: &RuleSpec,
    matched_groups: &[String],
    ctx: &RuleCtx<'a>,
    cache: &EvidenceCache<'a>,
) -> Vec<Finding> {
    let (Some(group_by), Some(distinct)) = (&spec.group_by, &spec.distinct) else {
        return Vec::new();
    };
    let settings = settings_literals(ctx.settings);
    let prepared = prepare_evidence(spec, ctx, &settings, cache);
    let wanted: std::collections::HashSet<&str> =
        matched_groups.iter().map(String::as_str).collect();

    // Gather members per matched group (same predicate the engine matched on).
    let mut groups: BTreeMap<String, Vec<&Fact>> = BTreeMap::new();
    for fact in ctx.store.all().iter().filter(|f| matches_where_v1(f, spec)) {
        if let Some(key) = term_value(fact, group_by) {
            if wanted.contains(key.as_str()) {
                groups.entry(key).or_default().push(fact);
            }
        }
    }

    let mut out = Vec::new();
    for (key, facts) in groups {
        let distinct_values: BTreeSet<String> = facts
            .iter()
            .filter_map(|f| term_value(f, distinct))
            .collect();
        if distinct_values.len() < spec.min_count {
            continue;
        }
        let mut vars = VarMap::new();
        vars.insert("group".to_string(), key);
        vars.insert("count".to_string(), distinct_values.len().to_string());
        vars.insert(
            "values".to_string(),
            distinct_values.into_iter().collect::<Vec<_>>().join(", "),
        );
        out.push(build_finding(
            spec,
            &vars,
            facts,
            &settings,
            prepared.as_ref(),
        ));
    }
    out
}

/// The v1 `where_all` / `where_not` / `input_kinds` predicate for one fact — the
/// single source of truth for "does this fact match a `FactFinding` rule's filters"
/// (the `where`-string refinement is applied separately by the caller).
pub fn matches_where_v1(fact: &Fact, spec: &RuleSpec) -> bool {
    (spec.input_kinds.is_empty() || spec.input_kinds.iter().any(|k| k == &fact.kind))
        && spec
            .where_all
            .iter()
            .all(|(term, expected)| term_value(fact, term).as_deref() == Some(expected.as_str()))
        && spec
            .where_not
            .iter()
            .all(|(term, rejected)| term_value(fact, term).as_deref() != Some(rejected.as_str()))
}

/// Fact ids matched by a rule's v1 predicate — exposed for the columnar IR
/// migration's shadow comparison (proves the new engine selects the same facts).
pub fn matching_fact_ids(
    spec: &RuleSpec,
    store: &intermed_doctor_core::facts::FactStore,
) -> Vec<intermed_doctor_core::facts::FactId> {
    store
        .all()
        .iter()
        .filter(|fact| matches_where_v1(fact, spec))
        .map(|f| f.id)
        .collect()
}

fn vars_from_fact(fact: &Fact) -> VarMap {
    let mut vars = VarMap::new();
    vars.insert("subject".to_string(), fact.subject.clone());
    for (k, v) in &fact.attributes {
        if let Some(s) = v.as_str() {
            vars.insert(format!("attr:{k}"), s.to_string());
        } else {
            vars.insert(
                format!("attr:{k}"),
                serde_json::to_string(v).unwrap_or_default(),
            );
        }
    }
    vars
}

fn vars_from_bindings(bindings: &BTreeMap<String, &Fact>) -> VarMap {
    let mut vars = VarMap::new();
    for (alias, fact) in bindings {
        vars.insert(format!("{alias}.subject"), fact.subject.clone());
        vars.insert("subject".to_string(), fact.subject.clone());
        for (k, v) in &fact.attributes {
            let rendered = match v {
                intermed_doctor_core::facts::AttrValue::Str(s) => s.clone(),
                intermed_doctor_core::facts::AttrValue::Int(i) => i.to_string(),
                intermed_doctor_core::facts::AttrValue::Float(f) => f.to_string(),
                intermed_doctor_core::facts::AttrValue::Bool(b) => b.to_string(),
            };
            vars.insert(format!("{alias}.attr:{k}"), rendered.clone());
            vars.insert(format!("{alias}.{k}"), rendered.clone());
            vars.insert(format!("attr:{k}"), rendered);
        }
    }
    vars
}

fn enrich_derived_vars(vars: &mut VarMap) {
    if let Some(writers) = vars.get("attr:writers").cloned() {
        let list: Vec<&str> = writers
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect();
        vars.insert("writer_count".to_string(), list.len().to_string());
        vars.insert("writers_list".to_string(), list.join(", "));
    }
}

fn single_binding<'a>(alias: &str, fact: &'a Fact) -> BTreeMap<String, &'a Fact> {
    let mut map = BTreeMap::new();
    map.insert(alias.to_string(), fact);
    map
}

fn build_finding(
    spec: &RuleSpec,
    vars: &VarMap,
    facts: Vec<&Fact>,
    settings: &BTreeMap<String, String>,
    prepared: Option<&PreparedEvidence<'_>>,
) -> Finding {
    let severity = parse_severity(&spec.finding.severity)
        .unwrap_or(intermed_doctor_core::evidence::Severity::Warn);
    let category = parse_category(&spec.finding.category)
        .unwrap_or(intermed_doctor_core::evidence::Category::Metadata);
    let mut vars = vars.clone();
    enrich_derived_vars(&mut vars);
    let (id, title, explanation, fix, tags) = render_finding_fields(&spec.finding, &vars);
    let rule_id = spec.finding.rule_id.as_deref().unwrap_or(spec.id.as_str());
    let mut b = Finding::builder(rule_id, id)
        .severity(severity)
        .category(category)
        .title(title)
        .explanation(explanation)
        .confidence(default_confidence(category));
    for fact in &facts {
        b = b.evidence(EvidenceEdge::subject(fact.id));
    }
    if let Some(fix_text) = fix {
        b = b.fix(FixCandidate::advice(fix_text));
    }
    for tag in tags {
        b = b.tag(tag);
    }
    // Declared `affects` templates (e.g. both sides of a join) take precedence;
    // otherwise default to the primary fact's subject.
    if spec.finding.affects.is_empty() {
        if let Some(primary) = facts.first() {
            b = b.affects(primary.subject.clone());
        }
    } else {
        for tmpl in &spec.finding.affects {
            let rendered = crate::template::render_template(tmpl, &vars);
            if !rendered.is_empty() && !rendered.contains('{') {
                b = b.affects(rendered);
            }
        }
    }
    if let Some(prep) = prepared {
        b = apply_related_evidence(b, prep, facts.first().copied(), settings);
    }
    b.build()
}

/// The candidate index for a related-evidence join — a function of the evidence
/// *spec* `(kind, on)`, not the rule. Many rules declare the **identical** evidence
/// (e.g. all 7 `resource-conflict-*` rules join `resource_writer` on
/// `primary.subject = related.attr:path`), so it is built **once per spec** and shared
/// across the whole pack via [`EvidenceCache`]. Building it per rule (let alone per
/// finding) re-scanned tens of thousands of facts needlessly.
struct SharedEvidence<'a> {
    /// Equijoin path: `(primary key term, related facts indexed by their join term)`.
    keyed: Option<(String, std::collections::HashMap<String, Vec<&'a Fact>>)>,
    /// Non-equijoin fallback: the candidate facts to scan per finding.
    candidates: Vec<&'a Fact>,
}

/// Pack-scoped cache of [`SharedEvidence`] keyed by the evidence spec `(kind, on)`, so
/// rules with the same evidence build the index once. Created once per pack evaluation.
pub struct EvidenceCache<'a> {
    inner: std::cell::RefCell<
        std::collections::HashMap<(String, String), std::rc::Rc<SharedEvidence<'a>>>,
    >,
}

impl<'a> EvidenceCache<'a> {
    pub fn new() -> Self {
        EvidenceCache {
            inner: std::cell::RefCell::new(std::collections::HashMap::new()),
        }
    }

    /// The shared index for `related`, building and caching it on first use.
    fn get_or_build(
        &self,
        related: &crate::model::RelatedEvidenceSpec,
        ctx: &RuleCtx<'a>,
        settings: &BTreeMap<String, String>,
    ) -> std::rc::Rc<SharedEvidence<'a>> {
        let key = (related.kind.clone(), related.on.clone());
        if let Some(shared) = self.inner.borrow().get(&key) {
            return shared.clone();
        }
        // `all().filter` (not `by_kind`) so the borrowed facts carry the store's `'a`
        // lifetime cleanly. Runs at most once per distinct evidence spec per pack.
        let candidates: Vec<&'a Fact> = ctx
            .store
            .all()
            .iter()
            .filter(|f| f.kind == related.kind)
            .collect();
        let equijoins = plan_equijoins(&related.on, "primary", "related");
        let keyed = equijoins.first().map(|k| {
            let index = index_facts_by_term(&candidates, "related", &k.right_term, settings);
            (k.left_term.clone(), index)
        });
        let shared = std::rc::Rc::new(SharedEvidence { keyed, candidates });
        self.inner.borrow_mut().insert(key, shared.clone());
        shared
    }
}

impl Default for EvidenceCache<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// The related-evidence join for one rule: the per-rule relation/weight/on plus the
/// shared candidate index from [`EvidenceCache`]. [`apply_related_evidence`] probes it
/// per finding.
struct PreparedEvidence<'a> {
    relation: intermed_evidence::Relation,
    weight: f32,
    on: String,
    shared: std::rc::Rc<SharedEvidence<'a>>,
}

/// Prepare a rule's evidence join from the pack cache (`None` when no evidence).
fn prepare_evidence<'a>(
    spec: &RuleSpec,
    ctx: &RuleCtx<'a>,
    settings: &BTreeMap<String, String>,
    cache: &EvidenceCache<'a>,
) -> Option<PreparedEvidence<'a>> {
    let related = spec.evidence.as_ref()?;
    Some(PreparedEvidence {
        relation: parse_relation(&related.relation),
        weight: related.weight,
        on: related.on.clone(),
        shared: cache.get_or_build(related, ctx, settings),
    })
}

fn apply_related_evidence(
    mut builder: intermed_doctor_core::evidence::FindingBuilder,
    prepared: &PreparedEvidence<'_>,
    primary: Option<&Fact>,
    settings: &BTreeMap<String, String>,
) -> intermed_doctor_core::evidence::FindingBuilder {
    let Some(primary) = primary else {
        return builder;
    };
    let add = |builder: intermed_doctor_core::evidence::FindingBuilder, candidate: &Fact| {
        let mut bindings = BTreeMap::new();
        bindings.insert("primary".to_string(), primary);
        bindings.insert("related".to_string(), candidate);
        let expr_ctx = ExprCtx {
            bindings: &bindings,
            settings,
            vars: None,
        };
        if eval_bool(&prepared.on, &expr_ctx) {
            builder.evidence(intermed_doctor_core::evidence::EvidenceEdge::new(
                candidate.id,
                prepared.relation,
                prepared.weight,
            ))
        } else {
            builder
        }
    };

    if let Some((left_term, index)) = &prepared.shared.keyed {
        let primary_bindings = single_binding("primary", primary);
        let primary_ctx = ExprCtx {
            bindings: &primary_bindings,
            settings,
            vars: None,
        };
        if let Some(join_val) = resolve_term(left_term, &primary_ctx) {
            if let Some(matches) = index.get(&join_val) {
                for candidate in matches {
                    builder = add(builder, candidate);
                }
            }
        }
        return builder;
    }

    for candidate in &prepared.shared.candidates {
        builder = add(builder, candidate);
    }
    builder
}

fn parse_relation(name: &str) -> intermed_evidence::Relation {
    use intermed_evidence::Relation;
    match name {
        "conflicts_with" => Relation::ConflictsWith,
        "supports" => Relation::Supports,
        "correlates_with" => Relation::CorrelatesWith,
        _ => Relation::Supports,
    }
}

/// Deduplicate findings by `(rule_id, id)` — the same occurrence identity the
/// report uses. Keying on `id` alone would silently drop a finding from a
/// *different* rule that happens to reuse the same id pattern (e.g. two resource
/// rules both emitting `resource-conflict:{subject}`).
pub fn dedupe_by_subject(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for finding in findings {
        let key = (finding.rule_id.clone(), finding.id.clone());
        if seen.insert(key) {
            out.push(finding);
        }
    }
    out
}
