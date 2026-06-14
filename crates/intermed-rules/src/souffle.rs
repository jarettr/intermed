//! Optional external Souffle backend (generated Datalog from the core pack).

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, FixCandidate, Severity};
use intermed_doctor_core::facts::{kind, Fact, FactId};
use intermed_doctor_core::{Rule, RuleCtx};

use crate::datalog_codegen::generate_pack_datalog;
use crate::pack::default_core_pack_v2;
use crate::tsv::escape_souffle_symbol;
use crate::RulePackError;

/// Optional external Souffle backend.
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

/// Soufflé program generated from the embedded core pack.
pub fn souffle_program() -> String {
    generate_pack_datalog(&default_core_pack_v2())
}

fn run_souffle(ctx: &RuleCtx<'_>) -> Result<Vec<Finding>, RulePackError> {
    let root = temp_souffle_dir();
    let facts_dir = root.join("facts");
    let out_dir = root.join("out");
    std::fs::create_dir_all(&facts_dir)
        .map_err(|e| RulePackError(format!("create {}: {e}", facts_dir.display())))?;
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| RulePackError(format!("create {}: {e}", out_dir.display())))?;

    let result = (|| {
        write_souffle_facts(ctx, &facts_dir)?;
        let program = root.join("intermed_core.dl");
        std::fs::write(&program, souffle_program())
            .map_err(|e| RulePackError(format!("write {}: {e}", program.display())))?;

        let output = Command::new("souffle")
            .arg(&program)
            .arg("-F")
            .arg(&facts_dir)
            .arg("-D")
            .arg(&out_dir)
            .output()
            .map_err(|e| RulePackError(format!("run souffle: {e}")))?;
        if !output.status.success() {
            return Err(RulePackError(format!(
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
        .map_err(|e| RulePackError(format!("write mod_decl.facts: {e}")))?;
    for fact in ctx
        .store
        .by_kind(kind::MOD)
        .chain(ctx.store.by_kind(kind::PLUGIN))
    {
        let file = fact.attr("file").unwrap_or(&fact.source.locator);
        writeln!(
            mod_decl,
            "{}\t{}\t{}",
            escape_souffle_symbol(&fact.subject),
            escape_souffle_symbol(file),
            fact.id
        )
        .map_err(|e| RulePackError(format!("write mod_decl.facts: {e}")))?;
    }

    let mut overlap = std::fs::File::create(facts_dir.join("mixin_overlap_input.facts"))
        .map_err(|e| RulePackError(format!("write mixin_overlap_input.facts: {e}")))?;
    for fact in ctx.store.by_kind(kind::MIXIN_OVERLAP) {
        writeln!(
            overlap,
            "{}\t{}\t{}\t{}\t{}",
            escape_souffle_symbol(&fact.subject),
            escape_souffle_symbol(fact.attr("mods").unwrap_or("")),
            escape_souffle_symbol(fact.attr("operations").unwrap_or("")),
            escape_souffle_symbol(fact.attr("hot_path").unwrap_or("false")),
            fact.id
        )
        .map_err(|e| RulePackError(format!("write mixin_overlap_input.facts: {e}")))?;
    }

    let mut overwrite = std::fs::File::create(facts_dir.join("mixin_overwrite_input.facts"))
        .map_err(|e| RulePackError(format!("write mixin_overwrite_input.facts: {e}")))?;
    for fact in ctx.store.by_kind(kind::HIGH_RISK_OVERWRITE) {
        writeln!(
            overwrite,
            "{}\t{}\t{}\t{}",
            escape_souffle_symbol(&fact.subject),
            escape_souffle_symbol(fact.attr("target").unwrap_or("")),
            escape_souffle_symbol(fact.attr("hot_path").unwrap_or("false")),
            fact.id
        )
        .map_err(|e| RulePackError(format!("write mixin_overwrite_input.facts: {e}")))?;
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
        let mut b = Finding::builder("duplicate-id", format!("duplicate-id:{id}"))
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
        let mut b = Finding::builder("mixin-overlap", format!("mixin-overlap:{target}"))
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
            "mixin-overwrite",
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
    ctx.store.get(FactId(n))
}

fn temp_souffle_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("intermed-souffle-{}-{nanos}", std::process::id()))
}