//! # intermed-rules
//!
//! Phase-1 imperative rules that don't need version math (that's
//! `intermed-deps`) or log knowledge (that's `intermed-log`). These operate on
//! metadata + environment facts:
//!
//! * [`DuplicateIdRule`] — two artifacts claim the same id.
//! * [`LoaderMismatchRule`] — a mod's loader differs from the instance loader.
//! * [`SideMismatchRule`] — a client-only mod on a server (or vice versa).
//!
//! In Phase 5 these become declarative rule packs evaluated by a Datalog
//! backend; the [`Rule`] trait boundary means the engine never has to care.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::{kind, Fact, FactId};
use intermed_doctor_core::{Rule, RuleCtx};
use serde::{Deserialize, Serialize};

/// Loaders that load *mods* (as opposed to server plugins). Loader mismatch is
/// only meaningful within this family.
fn is_mod_loader(l: &str) -> bool {
    matches!(l, "fabric" | "quilt" | "forge" | "neoforge")
}

// ── duplicate id ───────────────────────────────────────────────────────────

pub struct DuplicateIdRule;

impl Rule for DuplicateIdRule {
    fn id(&self) -> &'static str {
        "duplicate-id"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut by_id: BTreeMap<&str, Vec<&intermed_doctor_core::facts::Fact>> = BTreeMap::new();
        for f in ctx
            .store
            .by_kind(kind::MOD)
            .chain(ctx.store.by_kind(kind::PLUGIN))
        {
            by_id.entry(f.subject.as_str()).or_default().push(f);
        }
        let mut out = Vec::new();
        for (id, facts) in by_id {
            if facts.len() > 1 {
                let files: Vec<String> = facts
                    .iter()
                    .map(|f| f.attr("file").unwrap_or("?").to_string())
                    .collect();
                let mut b = Finding::builder(self.id(), format!("duplicate-id:{id}"))
                    .severity(Severity::Error)
                    .category(Category::Metadata)
                    .title(format!("Duplicate id '{id}' in {} files", facts.len()))
                    .explanation(format!(
                        "The id '{id}' is declared by multiple archives: {}. Only one can load.",
                        files.join(", ")
                    ))
                    .affects(id)
                    .fix(FixCandidate::advice("Remove the duplicate/older jar."))
                    .tag("metadata")
                    .tag("duplicate");
                for f in &facts {
                    b = b.evidence(EvidenceEdge::subject(f.id));
                }
                out.push(b.build());
            }
        }
        out
    }
}

// ── loader mismatch ──────────────────────────────────────────────────────

pub struct LoaderMismatchRule;

impl Rule for LoaderMismatchRule {
    fn id(&self) -> &'static str {
        "loader-mismatch"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let Some(env_loader) = ctx
            .store
            .by_kind(kind::ENVIRONMENT)
            .next()
            .and_then(|f| f.attr("loader").map(str::to_string))
        else {
            return Vec::new();
        };
        if !is_mod_loader(&env_loader) {
            return Vec::new();
        }

        let mut out = Vec::new();
        for m in ctx.store.by_kind(kind::MOD) {
            let Some(ml) = m.attr("loader") else { continue };
            if is_mod_loader(ml) && ml != env_loader {
                out.push(
                    Finding::builder(self.id(), format!("loader-mismatch:{}", m.subject))
                        .severity(Severity::Error)
                        .category(Category::Loader)
                        .title(format!("'{}' is a {ml} mod on a {env_loader} instance", m.subject))
                        .explanation(format!(
                            "{} is built for {ml}, but this instance runs {env_loader}. It will not load.",
                            m.subject
                        ))
                        .evidence(EvidenceEdge::subject(m.id))
                        .affects(m.subject.clone())
                        .fix(FixCandidate::advice(format!(
                            "Use the {env_loader} build of this mod, or remove it."
                        )))
                        .tag("loader")
                        .tag("mismatch")
                        .build(),
                );
            }
        }
        out
    }
}

// ── side mismatch ──────────────────────────────────────────────────────────

pub struct SideMismatchRule;

impl Rule for SideMismatchRule {
    fn id(&self) -> &'static str {
        "side-mismatch"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let env_side = ctx
            .store
            .by_kind(kind::ENVIRONMENT)
            .next()
            .and_then(|f| f.attr("side").map(str::to_string));
        let Some(env_side) = env_side else {
            return Vec::new();
        };

        let mut out = Vec::new();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for s in ctx.store.by_kind(kind::MOD_SIDE) {
            let Some(mod_side) = s.attr("side") else {
                continue;
            };
            if mod_side == "both" || !seen.insert(s.subject.as_str()) {
                continue;
            }
            // A side-locked mod running on the opposite side.
            if mod_side != env_side {
                let (sev, title, expl) = if env_side == "server" {
                    (
                        Severity::Warn,
                        format!("'{}' is client-only on a server", s.subject),
                        format!(
                            "{} declares environment=client; on a dedicated server it is dead weight or may error.",
                            s.subject
                        ),
                    )
                } else {
                    (
                        Severity::Note,
                        format!("'{}' is server-only on a client", s.subject),
                        format!(
                            "{} declares environment=server; it will do nothing client-side.",
                            s.subject
                        ),
                    )
                };
                out.push(
                    Finding::builder(self.id(), format!("side-mismatch:{}", s.subject))
                        .severity(sev)
                        .category(Category::Loader)
                        .title(title)
                        .explanation(expl)
                        .evidence(EvidenceEdge::subject(s.id))
                        .affects(s.subject.clone())
                        .tag("side")
                        .build(),
                );
            }
        }
        out
    }
}

/// All Phase-1 generic rules, for convenient registration.
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DuplicateIdRule),
        Box::new(LoaderMismatchRule),
        Box::new(SideMismatchRule),
    ]
}

// ── Phase 5: Datalog-compatible rule packs ────────────────────────────────

/// Serializable rule-pack schema.
pub const RULE_PACK_SCHEMA: &str = "intermed-rule-pack-v1";

/// Declarative evaluation strategy supported by the Phase-5 internal backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleKind {
    /// Group matching facts and emit one finding when at least `min_count`
    /// distinct values exist in the group.
    GroupDistinct,
    /// Emit one finding for each matching fact.
    FactFinding,
}

/// A small, Datalog-compatible rule pack. It is intentionally data-only: facts
/// are selected by predicate/attributes, variables are group keys, and findings
/// are emitted from templates with evidence edges back to source facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulePack {
    pub schema: String,
    pub id: String,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSpec {
    pub id: String,
    pub kind: RuleKind,
    #[serde(default)]
    pub input_kinds: Vec<String>,
    #[serde(default)]
    pub where_all: BTreeMap<String, String>,
    #[serde(default)]
    pub where_not: BTreeMap<String, String>,
    pub group_by: Option<String>,
    pub distinct: Option<String>,
    #[serde(default = "default_min_count")]
    pub min_count: usize,
    pub finding: FindingTemplate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingTemplate {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub explanation: String,
    #[serde(default)]
    pub fix: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_min_count() -> usize {
    1
}

/// Validation / load failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulePackError {
    pub message: String,
}

impl RulePackError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RulePackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RulePackError {}

/// Result for `intermed rules check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulePackCheck {
    pub files: usize,
    pub rules: usize,
    pub errors: Vec<String>,
}

impl RulePackCheck {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Internal Datalog-compatible backend. Souffle/DuckDB can compile from the
/// same data model later; this backend keeps Phase 5 shippable in one binary.
pub struct DatalogRulePack {
    pack: RulePack,
}

impl DatalogRulePack {
    pub fn new(pack: RulePack) -> Result<Self, RulePackError> {
        validate_rule_pack(&pack)?;
        Ok(Self { pack })
    }

    pub fn default_core() -> Self {
        Self::new(default_core_pack()).expect("embedded core rule pack is valid")
    }
}

impl Rule for DatalogRulePack {
    fn id(&self) -> &'static str {
        "datalog-rule-pack"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for spec in &self.pack.rules {
            match spec.kind {
                RuleKind::GroupDistinct => evaluate_group_distinct(ctx, spec, &mut out),
                RuleKind::FactFinding => evaluate_fact_finding(ctx, spec, &mut out),
            }
        }
        out
    }
}

/// Optional external Souffle backend. It materializes selected facts as
/// `.facts`, writes a generated `.dl` program, runs `souffle`, then maps output
/// relations back into normal InterMed findings.
pub struct SouffleRulePack;

impl SouffleRulePack {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SouffleRulePack {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SouffleRulePack {
    fn id(&self) -> &'static str {
        "souffle-rule-pack"
    }

    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        match run_souffle(ctx) {
            Ok(findings) => findings,
            Err(e) => vec![
                Finding::builder("souffle-rule-pack", "souffle-backend-failed")
                    .severity(Severity::Fatal)
                    .category(Category::Runtime)
                    .title("Souffle backend failed")
                    .explanation(e.to_string())
                    .tag("logic")
                    .tag("souffle")
                    .build(),
            ],
        }
    }
}

pub fn souffle_available() -> bool {
    Command::new("souffle")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn run_souffle(ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, RulePackError> {
    let root = temp_souffle_dir();
    let facts_dir = root.join("facts");
    let out_dir = root.join("out");
    std::fs::create_dir_all(&facts_dir)
        .map_err(|e| RulePackError::new(format!("create {}: {e}", facts_dir.display())))?;
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| RulePackError::new(format!("create {}: {e}", out_dir.display())))?;

    let result = (|| {
        write_souffle_facts(ctx, &facts_dir)?;
        let program = root.join("intermed_core.dl");
        std::fs::write(&program, souffle_program())
            .map_err(|e| RulePackError::new(format!("write {}: {e}", program.display())))?;

        let output = Command::new("souffle")
            .arg(&program)
            .arg("-F")
            .arg(&facts_dir)
            .arg("-D")
            .arg(&out_dir)
            .output()
            .map_err(|e| RulePackError::new(format!("run souffle: {e}")))?;
        if !output.status.success() {
            return Err(RulePackError::new(format!(
                "souffle exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(read_souffle_findings(ctx, &out_dir))
    })();

    let _ = std::fs::remove_dir_all(&root);
    result
}

fn write_souffle_facts(ctx: &RuleCtx<'_>, facts_dir: &Path) -> Result<(), RulePackError> {
    let mut mod_decl = std::fs::File::create(facts_dir.join("mod_decl.facts"))
        .map_err(|e| RulePackError::new(format!("write mod_decl.facts: {e}")))?;
    for fact in ctx
        .store
        .by_kind(kind::MOD)
        .chain(ctx.store.by_kind(kind::PLUGIN))
    {
        let file = fact.attr("file").unwrap_or(&fact.source.locator);
        writeln!(
            mod_decl,
            "{}\t{}\t{}",
            souffle_symbol(&fact.subject),
            souffle_symbol(file),
            fact.id
        )
        .map_err(|e| RulePackError::new(format!("write mod_decl.facts: {e}")))?;
    }

    let mut overlap = std::fs::File::create(facts_dir.join("mixin_overlap_input.facts"))
        .map_err(|e| RulePackError::new(format!("write mixin_overlap_input.facts: {e}")))?;
    for fact in ctx.store.by_kind(kind::MIXIN_OVERLAP) {
        writeln!(
            overlap,
            "{}\t{}\t{}\t{}\t{}",
            souffle_symbol(&fact.subject),
            souffle_symbol(fact.attr("mods").unwrap_or("")),
            souffle_symbol(fact.attr("operations").unwrap_or("")),
            souffle_symbol(fact.attr("hot_path").unwrap_or("false")),
            fact.id
        )
        .map_err(|e| RulePackError::new(format!("write mixin_overlap_input.facts: {e}")))?;
    }

    let mut overwrite = std::fs::File::create(facts_dir.join("mixin_overwrite_input.facts"))
        .map_err(|e| RulePackError::new(format!("write mixin_overwrite_input.facts: {e}")))?;
    for fact in ctx.store.by_kind(kind::HIGH_RISK_OVERWRITE) {
        writeln!(
            overwrite,
            "{}\t{}\t{}\t{}",
            souffle_symbol(&fact.subject),
            souffle_symbol(fact.attr("target").unwrap_or("")),
            souffle_symbol(fact.attr("hot_path").unwrap_or("false")),
            fact.id
        )
        .map_err(|e| RulePackError::new(format!("write mixin_overwrite_input.facts: {e}")))?;
    }
    Ok(())
}

fn read_souffle_findings(ctx: &RuleCtx<'_>, out_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for row in read_relation(out_dir, "duplicate_id") {
        let Some(id) = row.first() else {
            continue;
        };
        let facts: Vec<&Fact> = ctx
            .store
            .by_kind(kind::MOD)
            .chain(ctx.store.by_kind(kind::PLUGIN))
            .filter(|fact| fact.subject == *id)
            .collect();
        let files: BTreeSet<String> = facts
            .iter()
            .filter_map(|fact| fact.attr("file").map(str::to_string))
            .collect();
        let mut b = Finding::builder("souffle-duplicate-id", format!("duplicate-id:{id}"))
            .severity(Severity::Error)
            .category(Category::Metadata)
            .title(format!("Duplicate id '{id}' in {} files", files.len()))
            .explanation(format!(
                "The id '{id}' is declared by multiple archives: {}. Only one can load.",
                files.into_iter().collect::<Vec<_>>().join(", ")
            ))
            .fix(FixCandidate::advice("Remove the duplicate/older jar."))
            .tag("metadata")
            .tag("duplicate")
            .tag("souffle");
        for fact in facts {
            b = b.evidence(EvidenceEdge::subject(fact.id));
        }
        findings.push(b.build());
    }

    for row in read_relation(out_dir, "mixin_overlap_out") {
        if row.len() < 5 {
            continue;
        }
        let target = &row[0];
        let hot = row[3] == "true";
        let fact = fact_by_display(ctx, &row[4]);
        let mut b = Finding::builder("souffle-mixin-overlap", format!("mixin-overlap:{target}"))
            .severity(if hot { Severity::Error } else { Severity::Warn })
            .category(Category::Mixin)
            .title(format!("Mixin target overlap: {target}"))
            .explanation(format!(
                "Multiple mods target {target}: {}. Operations: {}.",
                row[1], row[2]
            ))
            .fix(FixCandidate::advice(
                "Check mod compatibility notes and prefer versions known to share this target.",
            ))
            .tag("mixin")
            .tag("overlap")
            .tag("souffle");
        if let Some(fact) = fact {
            b = b.evidence(EvidenceEdge::subject(fact.id));
        }
        findings.push(b.build());
    }

    for row in read_relation(out_dir, "mixin_overwrite_out") {
        if row.len() < 4 {
            continue;
        }
        let mod_id = &row[0];
        let target = &row[1];
        let hot = row[2] == "true";
        let fact = fact_by_display(ctx, &row[3]);
        let mut b = Finding::builder(
            "souffle-mixin-overwrite",
            format!("mixin-overwrite:{mod_id}->{target}"),
        )
        .severity(if hot { Severity::Error } else { Severity::Warn })
        .category(Category::Mixin)
        .title(format!("High-risk @Overwrite mixin: {target}"))
        .explanation(format!(
            "{mod_id} overwrites code in {target}. @Overwrite has a high compatibility risk because it replaces target behavior."
        ))
        .fix(FixCandidate::advice(
            "Prefer versions without competing overwrites, or remove one conflicting mod.",
        ))
        .tag("mixin")
        .tag("overwrite")
        .tag("souffle");
        if let Some(fact) = fact {
            b = b.evidence(EvidenceEdge::subject(fact.id));
        }
        findings.push(b.build());
    }

    findings
}

fn read_relation(out_dir: &Path, relation: &str) -> Vec<Vec<String>> {
    let paths = [
        out_dir.join(format!("{relation}.csv")),
        out_dir.join(relation),
    ];
    let Some(path) = paths.iter().find(|path| path.is_file()) else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split('\t').map(str::to_string).collect())
        .collect()
}

fn fact_by_display<'a>(ctx: &'a RuleCtx<'_>, id: &str) -> Option<&'a Fact> {
    let raw = id.strip_prefix('f')?;
    let n = raw.parse::<u64>().ok()?;
    ctx.store.all().iter().find(|fact| fact.id == FactId(n))
}

fn souffle_symbol(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

pub fn souffle_program() -> &'static str {
    r#".decl mod_decl(id:symbol, file:symbol, fact:symbol)
.input mod_decl

.decl duplicate_id(id:symbol)
.output duplicate_id
duplicate_id(id) :- mod_decl(id, f1, _), mod_decl(id, f2, _), f1 != f2.

.decl mixin_overlap_input(target:symbol, mods:symbol, operations:symbol, hot:symbol, fact:symbol)
.input mixin_overlap_input
.decl mixin_overlap_out(target:symbol, mods:symbol, operations:symbol, hot:symbol, fact:symbol)
.output mixin_overlap_out
mixin_overlap_out(t, m, o, h, f) :- mixin_overlap_input(t, m, o, h, f).

.decl mixin_overwrite_input(mod:symbol, target:symbol, hot:symbol, fact:symbol)
.input mixin_overwrite_input
.decl mixin_overwrite_out(mod:symbol, target:symbol, hot:symbol, fact:symbol)
.output mixin_overwrite_out
mixin_overwrite_out(m, t, h, f) :- mixin_overwrite_input(m, t, h, f).
"#
}

fn temp_souffle_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("intermed-souffle-{}-{nanos}", std::process::id()))
}

fn evaluate_group_distinct(ctx: &RuleCtx<'_>, spec: &RuleSpec, out: &mut Vec<Finding>) {
    let Some(group_by) = &spec.group_by else {
        return;
    };
    let Some(distinct) = &spec.distinct else {
        return;
    };

    let mut groups: BTreeMap<String, Vec<&Fact>> = BTreeMap::new();
    for fact in matching_facts(ctx, spec) {
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

        let mut vars = BTreeMap::new();
        vars.insert("group".to_string(), key.clone());
        vars.insert("count".to_string(), distinct_values.len().to_string());
        vars.insert(
            "values".to_string(),
            distinct_values.into_iter().collect::<Vec<_>>().join(", "),
        );
        out.push(build_finding(spec, &vars, facts));
    }
}

fn evaluate_fact_finding(ctx: &RuleCtx<'_>, spec: &RuleSpec, out: &mut Vec<Finding>) {
    for fact in matching_facts(ctx, spec) {
        let mut vars = BTreeMap::new();
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
        out.push(build_finding(spec, &vars, vec![fact]));
    }
}

fn matching_facts<'a>(
    ctx: &'a RuleCtx<'_>,
    spec: &'a RuleSpec,
) -> impl Iterator<Item = &'a Fact> + 'a {
    ctx.store.all().iter().filter(move |fact| {
        (spec.input_kinds.is_empty() || spec.input_kinds.iter().any(|k| k == &fact.kind))
            && spec.where_all.iter().all(|(term, expected)| {
                term_value(fact, term).as_deref() == Some(expected.as_str())
            })
            && spec.where_not.iter().all(|(term, rejected)| {
                term_value(fact, term).as_deref() != Some(rejected.as_str())
            })
    })
}

fn term_value(fact: &Fact, term: &str) -> Option<String> {
    if term == "subject" {
        return Some(fact.subject.clone());
    }
    if term == "kind" {
        return Some(fact.kind.clone());
    }
    if let Some(attr) = term.strip_prefix("attr:") {
        return fact.attributes.get(attr).map(|value| match value {
            intermed_doctor_core::facts::AttrValue::Str(s) => s.clone(),
            intermed_doctor_core::facts::AttrValue::Int(i) => i.to_string(),
            intermed_doctor_core::facts::AttrValue::Float(f) => f.to_string(),
            intermed_doctor_core::facts::AttrValue::Bool(b) => b.to_string(),
        });
    }
    None
}

fn build_finding(spec: &RuleSpec, vars: &BTreeMap<String, String>, facts: Vec<&Fact>) -> Finding {
    let severity = parse_severity(&spec.finding.severity).unwrap_or(Severity::Warn);
    let category = parse_category(&spec.finding.category).unwrap_or(Category::Metadata);
    let confidence = if category == Category::Mixin {
        0.7
    } else {
        0.9
    };
    let mut b = Finding::builder(&spec.id, render_template(&spec.finding.id, vars))
        .severity(severity)
        .category(category)
        .title(render_template(&spec.finding.title, vars))
        .explanation(render_template(&spec.finding.explanation, vars))
        .confidence(confidence);
    for fact in &facts {
        b = b.evidence(EvidenceEdge::subject(fact.id));
    }
    if let Some(fix) = &spec.finding.fix {
        b = b.fix(FixCandidate::advice(render_template(fix, vars)));
    }
    for tag in &spec.finding.tags {
        b = b.tag(render_template(tag, vars));
    }
    b.build()
}

fn render_template(template: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = template.to_string();
    for (key, value) in vars {
        out = out.replace(&format!("{{{key}}}"), value);
    }
    out
}

fn parse_severity(s: &str) -> Option<Severity> {
    Some(match s {
        "info" => Severity::Info,
        "note" => Severity::Note,
        "warn" | "warning" => Severity::Warn,
        "error" => Severity::Error,
        "fatal" => Severity::Fatal,
        _ => return None,
    })
}

fn parse_category(s: &str) -> Option<Category> {
    Some(match s {
        "environment" => Category::Environment,
        "metadata" => Category::Metadata,
        "dependency" => Category::Dependency,
        "loader" => Category::Loader,
        "log" => Category::Log,
        "resource" => Category::Resource,
        "mixin" => Category::Mixin,
        "security" => Category::Security,
        "performance" => Category::Performance,
        "packaging" => Category::Packaging,
        "runtime" => Category::Runtime,
        _ => return None,
    })
}

pub fn validate_rule_pack(pack: &RulePack) -> Result<(), RulePackError> {
    if pack.schema != RULE_PACK_SCHEMA {
        return Err(RulePackError::new(format!(
            "unsupported rule-pack schema: {}",
            pack.schema
        )));
    }
    if pack.id.trim().is_empty() {
        return Err(RulePackError::new("rule pack id is empty"));
    }
    if pack.rules.is_empty() {
        return Err(RulePackError::new("rule pack has no rules"));
    }

    let mut ids = BTreeSet::new();
    for rule in &pack.rules {
        if !ids.insert(rule.id.as_str()) {
            return Err(RulePackError::new(format!(
                "duplicate rule id: {}",
                rule.id
            )));
        }
        if rule.input_kinds.is_empty() {
            return Err(RulePackError::new(format!(
                "{}: input_kinds must not be empty",
                rule.id
            )));
        }
        if parse_severity(&rule.finding.severity).is_none() {
            return Err(RulePackError::new(format!(
                "{}: invalid severity {}",
                rule.id, rule.finding.severity
            )));
        }
        if parse_category(&rule.finding.category).is_none() {
            return Err(RulePackError::new(format!(
                "{}: invalid category {}",
                rule.id, rule.finding.category
            )));
        }
        if matches!(rule.kind, RuleKind::GroupDistinct)
            && (rule.group_by.is_none() || rule.distinct.is_none() || rule.min_count < 2)
        {
            return Err(RulePackError::new(format!(
                "{}: group-distinct requires group_by, distinct, min_count >= 2",
                rule.id
            )));
        }
    }
    Ok(())
}

pub fn load_rule_pack(path: &Path) -> Result<RulePack, RulePackError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| RulePackError::new(format!("read {}: {e}", path.display())))?;
    let pack = if path.extension().and_then(|x| x.to_str()) == Some("json") {
        serde_json::from_str(&text)
            .map_err(|e| RulePackError::new(format!("parse {}: {e}", path.display())))?
    } else {
        serde_yaml::from_str(&text)
            .map_err(|e| RulePackError::new(format!("parse {}: {e}", path.display())))?
    };
    validate_rule_pack(&pack)?;
    Ok(pack)
}

pub fn check_rule_packs(path: &Path) -> RulePackCheck {
    let mut files = Vec::new();
    gather_rule_files(path, &mut files);
    files.sort();
    let file_count = files.len();

    let mut rules = 0usize;
    let mut errors = Vec::new();
    for file in files {
        match load_rule_pack(&file) {
            Ok(pack) => rules += pack.rules.len(),
            Err(e) => errors.push(format!("{}: {e}", file.display())),
        }
    }

    RulePackCheck {
        files: file_count,
        rules,
        errors,
    }
}

fn gather_rule_files(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        if is_rule_file(path) {
            out.push(path.to_path_buf());
        }
        return;
    }
    if let Ok(rd) = std::fs::read_dir(path) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                gather_rule_files(&p, out);
            } else if is_rule_file(&p) {
                out.push(p);
            }
        }
    }
}

fn is_rule_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|x| x.to_str()),
        Some("json" | "yaml" | "yml")
    )
}

pub fn default_core_pack() -> RulePack {
    RulePack {
        schema: RULE_PACK_SCHEMA.to_string(),
        id: "intermed-core-datalog".to_string(),
        rules: vec![
            RuleSpec {
                id: "datalog-duplicate-id".to_string(),
                kind: RuleKind::GroupDistinct,
                input_kinds: vec![kind::MOD.to_string(), kind::PLUGIN.to_string()],
                where_all: BTreeMap::new(),
                where_not: BTreeMap::new(),
                group_by: Some("subject".to_string()),
                distinct: Some("attr:file".to_string()),
                min_count: 2,
                finding: FindingTemplate {
                    id: "duplicate-id:{group}".to_string(),
                    severity: "error".to_string(),
                    category: "metadata".to_string(),
                    title: "Duplicate id '{group}' in {count} files".to_string(),
                    explanation: "The id '{group}' is declared by multiple archives: {values}. Only one can load.".to_string(),
                    fix: Some("Remove the duplicate/older jar.".to_string()),
                    tags: vec!["metadata".to_string(), "duplicate".to_string(), "datalog".to_string()],
                },
            },
            mixin_overlap_rule("datalog-mixin-overlap-hot", "true", "error"),
            mixin_overlap_rule("datalog-mixin-overlap", "false", "warn"),
            mixin_overwrite_rule("datalog-mixin-overwrite-hot", "true", "error"),
            mixin_overwrite_rule("datalog-mixin-overwrite", "false", "warn"),
        ],
    }
}

fn mixin_overlap_rule(id: &str, hot_path: &str, severity: &str) -> RuleSpec {
    let mut where_all = BTreeMap::new();
    where_all.insert("attr:hot_path".to_string(), hot_path.to_string());
    RuleSpec {
        id: id.to_string(),
        kind: RuleKind::FactFinding,
        input_kinds: vec![kind::MIXIN_OVERLAP.to_string()],
        where_all,
        where_not: BTreeMap::new(),
        group_by: None,
        distinct: None,
        min_count: 1,
        finding: FindingTemplate {
            id: "mixin-overlap:{subject}".to_string(),
            severity: severity.to_string(),
            category: "mixin".to_string(),
            title: "Mixin target overlap: {subject}".to_string(),
            explanation:
                "Multiple mods target {subject}: {attr:mods}. Operations: {attr:operations}."
                    .to_string(),
            fix: Some(
                "Check mod compatibility notes and prefer versions known to share this target."
                    .to_string(),
            ),
            tags: vec![
                "mixin".to_string(),
                "overlap".to_string(),
                "datalog".to_string(),
            ],
        },
    }
}

fn mixin_overwrite_rule(id: &str, hot_path: &str, severity: &str) -> RuleSpec {
    let mut where_all = BTreeMap::new();
    where_all.insert("attr:hot_path".to_string(), hot_path.to_string());
    RuleSpec {
        id: id.to_string(),
        kind: RuleKind::FactFinding,
        input_kinds: vec![kind::HIGH_RISK_OVERWRITE.to_string()],
        where_all,
        where_not: BTreeMap::new(),
        group_by: None,
        distinct: None,
        min_count: 1,
        finding: FindingTemplate {
            id: "mixin-overwrite:{subject}->{attr:target}".to_string(),
            severity: severity.to_string(),
            category: "mixin".to_string(),
            title: "High-risk @Overwrite mixin: {attr:target}".to_string(),
            explanation:
                "{subject} overwrites code in {attr:target}. @Overwrite has a high compatibility risk because it replaces target behavior."
                    .to_string(),
            fix: Some(
                "Prefer versions without competing overwrites, or remove one conflicting mod."
                    .to_string(),
            ),
            tags: vec![
                "mixin".to_string(),
                "overwrite".to_string(),
                "datalog".to_string(),
            ],
        },
    }
}

#[cfg(test)]
mod logic_tests {
    use super::*;
    use intermed_doctor_core::facts::{FactStore, SourceRef};
    use intermed_doctor_core::{Target, TargetKind};

    #[test]
    fn default_pack_detects_duplicate_id() {
        let mut store = FactStore::new();
        store
            .fact("test", kind::MOD)
            .subject("alpha")
            .attr("file", "a.jar")
            .source(SourceRef::file("a.jar"))
            .emit();
        store
            .fact("test", kind::MOD)
            .subject("alpha")
            .attr("file", "b.jar")
            .source(SourceRef::file("b.jar"))
            .emit();
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
        };
        let ctx = RuleCtx::new(&store, &target);
        let findings = DatalogRulePack::default_core().evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "duplicate-id:alpha");
    }

    #[test]
    fn validates_schema_and_rule_shape() {
        let pack = default_core_pack();
        validate_rule_pack(&pack).unwrap();

        let mut bad = pack;
        bad.rules[0].min_count = 1;
        assert!(validate_rule_pack(&bad).is_err());
    }

    #[test]
    fn generated_souffle_program_declares_real_relations() {
        let program = souffle_program();
        assert!(program.contains(".decl mod_decl"));
        assert!(program.contains(".output duplicate_id"));
        assert!(program.contains(".decl mixin_overlap_out"));
        assert!(program.contains(".decl mixin_overwrite_out"));
    }
}
