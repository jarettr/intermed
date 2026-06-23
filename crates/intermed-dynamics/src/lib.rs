//! # intermed-dynamics
//!
//! Layer E (dynamics). The static collectors (metadata, VFS) see what a jar
//! *contains*; they cannot see what a pack's data-pack scripts **remove** at
//! load time. A modpack routinely deletes hundreds of recipes and hides items
//! through [KubeJS] and [CraftTweaker]. An item that exists in a jar but whose
//! only recipe was scripted away is, in practice, unobtainable — and the static
//! graph would never know.
//!
//! This is the "сенсоры динамики" extraction from the design doc's Appendix B
//! ("Транзакционная VFS и учет динамики"): **pure evidence**, no runtime
//! enforcement. The collector reads the script engines' own load logs and
//! injects runtime-removal facts; [`ScriptDynamicsRule`] folds them into one
//! auditable note.
//!
//! [KubeJS]: https://kubejs.com/
//! [CraftTweaker]: https://docs.blamejared.com/
//!
//! ## Scope and honesty
//!
//! Script engines do not emit a stable, machine-readable removal manifest;
//! their human logs vary by engine and version. [`patterns`] is therefore a
//! best-effort marker table (the same approach as `intermed-log`), each entry
//! capturing the affected registry id. Facts are emitted at reduced confidence
//! and always carry the source line + excerpt so a human can audit them. The
//! table is the single point of extension when new log formats appear.

use std::path::PathBuf;

use intermed_doctor_core::evidence::{Category, EvidenceEdge, Finding, Severity};
use intermed_doctor_core::facts::{SourceRef, kind};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorOutcome, Layer, RuleCtx, Target, TargetKind,
};

use regex::Regex;

pub mod script_scan;

/// Confidence stamped on dynamics facts. Below the structural collectors (1.0):
/// these are heuristic reads of free-form logs, not parsed registries.
const DYNAMICS_CONFIDENCE: f32 = 0.6;

/// Which script engine produced a marker (the `engine` attribute on facts).
pub mod engine {
    pub const CRAFTTWEAKER: &str = "crafttweaker";
    pub const KUBEJS: &str = "kubejs";
    pub const RHINO: &str = "rhino";
    pub const GROOVYSCRIPT: &str = "groovyscript";
}

/// How a target stopped being obtainable (the `via` attribute on facts).
pub mod via {
    /// A recipe was removed by name/id.
    pub const RECIPE_REMOVED: &str = "recipe-removed";
    /// Every recipe producing an item was removed (item still registered, uncraftable).
    pub const RECIPE_OUTPUT_REMOVED: &str = "recipe-output-removed";
    /// An item was hidden/removed from the game by a script.
    pub const ITEM_REMOVED: &str = "item-removed";
    /// A loot table was removed or replaced away.
    pub const LOOT_TABLE_REMOVED: &str = "loot-table-removed";
    /// A tag was removed or emptied by a script.
    pub const TAG_REMOVED: &str = "tag-removed";
}

/// One removal marker: a regex with a single capture group (the registry id of
/// the affected recipe, item, loot table, or tag).
struct Pattern {
    engine: &'static str,
    fact_kind: &'static str,
    via: &'static str,
    regex: &'static str,
}

/// The marker table. First match wins per line. Each `regex` must expose the
/// affected registry id as capture group 1.
fn patterns() -> &'static [Pattern] {
    &[
        // CraftTweaker — "Removing all recipes for <item:mod:id>" (item uncraftable).
        Pattern {
            engine: engine::CRAFTTWEAKER,
            fact_kind: kind::RUNTIME_REMOVED_ITEM,
            via: via::RECIPE_OUTPUT_REMOVED,
            regex: r"(?i)removing all recipes\b[^<]*<item:([a-z0-9_.-]+:[a-z0-9_./-]+)>",
        },
        // CraftTweaker — "Hiding/Removing item <item:mod:id>".
        Pattern {
            engine: engine::CRAFTTWEAKER,
            fact_kind: kind::RUNTIME_REMOVED_ITEM,
            via: via::ITEM_REMOVED,
            regex: r"(?i)(?:hiding|removing) item\b[^<]*<item:([a-z0-9_.-]+:[a-z0-9_./-]+)>",
        },
        // CraftTweaker — recipe removal.
        Pattern {
            engine: engine::CRAFTTWEAKER,
            fact_kind: kind::RUNTIME_REMOVED_RECIPE,
            via: via::RECIPE_REMOVED,
            regex: r#"(?i)removing recipe\b[^a-z0-9]*(?:<?recipe:)?([a-z0-9_.-]+:[a-z0-9_./-]+)>?"#,
        },
        // CraftTweaker — tag removal.
        Pattern {
            engine: engine::CRAFTTWEAKER,
            fact_kind: kind::RUNTIME_REMOVED_TAG,
            via: via::TAG_REMOVED,
            regex: r"(?i)(?:removing|clearing)\b[^<]*<tag:([a-z0-9_.-]+:[a-z0-9_./-]+)>",
        },
        // CraftTweaker — loot table removal.
        Pattern {
            engine: engine::CRAFTTWEAKER,
            fact_kind: kind::RUNTIME_REMOVED_LOOT_TABLE,
            via: via::LOOT_TABLE_REMOVED,
            regex: r"(?i)(?:removing|replacing)\b[^<]*<loot_table:([a-z0-9_.-]+:[a-z0-9_./-]+)>",
        },
        // GroovyScript — bracket-tagged lines must win over generic KubeJS-shaped markers.
        Pattern {
            engine: engine::GROOVYSCRIPT,
            fact_kind: kind::RUNTIME_REMOVED_RECIPE,
            via: via::RECIPE_REMOVED,
            regex: r#"(?i)\[groovyscript\][^\n]*?\brecipe\b[^\n]*?['"]([a-z0-9_.-]+:[a-z0-9_./-]+)['"]"#,
        },
        // KubeJS — recipe removal.
        Pattern {
            engine: engine::KUBEJS,
            fact_kind: kind::RUNTIME_REMOVED_RECIPE,
            via: via::RECIPE_REMOVED,
            regex: r#"(?i)remov(?:e|ed|ing)\b[^\n]*?\brecipe\b[^\n]*?['"]([a-z0-9_.-]+:[a-z0-9_./-]+)['"]"#,
        },
        // KubeJS — item removal.
        Pattern {
            engine: engine::KUBEJS,
            fact_kind: kind::RUNTIME_REMOVED_ITEM,
            via: via::ITEM_REMOVED,
            regex: r#"(?i)remov(?:e|ed|ing)\b[^\n]*?\bitem\b[^\n]*?['"]([a-z0-9_.-]+:[a-z0-9_./-]+)['"]"#,
        },
        // KubeJS — tag removal / emptying.
        Pattern {
            engine: engine::KUBEJS,
            fact_kind: kind::RUNTIME_REMOVED_TAG,
            via: via::TAG_REMOVED,
            regex: r#"(?i)(?:remov(?:e|ed|ing)|clear(?:ed|ing)?)\b[^\n]*?\btag\b[^\n]*?['"](#?[a-z0-9_.-]+:[a-z0-9_./-]+)['"]"#,
        },
        // KubeJS — loot table removal.
        Pattern {
            engine: engine::KUBEJS,
            fact_kind: kind::RUNTIME_REMOVED_LOOT_TABLE,
            via: via::LOOT_TABLE_REMOVED,
            regex: r#"(?i)remov(?:e|ed|ing)\b[^\n]*?\bloot(?:\s*table)?\b[^\n]*?['"]([a-z0-9_.-]+:[a-z0-9_./-]+)['"]"#,
        },
        // GroovyScript — item/tag markers (Forge-side scripting).
        Pattern {
            engine: engine::GROOVYSCRIPT,
            fact_kind: kind::RUNTIME_REMOVED_ITEM,
            via: via::ITEM_REMOVED,
            regex: r#"(?i)remov(?:e|ed|ing)\b[^\n]*?\bitem\b[^\n]*?['"]([a-z0-9_.-]+:[a-z0-9_./-]+)['"]"#,
        },
        Pattern {
            engine: engine::GROOVYSCRIPT,
            fact_kind: kind::RUNTIME_REMOVED_TAG,
            via: via::TAG_REMOVED,
            regex: r#"(?i)(?:remov(?:e|ed|ing)|clear(?:ed|ing)?)\b[^\n]*?\btag\b[^\n]*?['"]([a-z0-9_.-]+:[a-z0-9_./-]+)['"]"#,
        },
        // Rhino — CraftTweaker's JS backend sometimes logs bare ids.
        Pattern {
            engine: engine::RHINO,
            fact_kind: kind::RUNTIME_REMOVED_RECIPE,
            via: via::RECIPE_REMOVED,
            regex: r#"(?i)remov(?:e|ed|ing)\s+recipe\s+['"]([a-z0-9_.-]+:[a-z0-9_./-]+)['"]"#,
        },
        Pattern {
            engine: engine::RHINO,
            fact_kind: kind::RUNTIME_REMOVED_ITEM,
            via: via::ITEM_REMOVED,
            regex: r#"(?i)remov(?:e|ed|ing)\s+item\s+['"]([a-z0-9_.-]+:[a-z0-9_./-]+)['"]"#,
        },
    ]
}

// ── Collector ──────────────────────────────────────────────────────────────

/// Scans script-engine load logs and emits runtime-removal facts.
pub struct ScriptDynamicsCollector;

/// Construct the Layer-E dynamics collector.
#[must_use]
pub fn collector() -> ScriptDynamicsCollector {
    ScriptDynamicsCollector
}

impl Collector for ScriptDynamicsCollector {
    fn id(&self) -> &'static str {
        "script-dynamics"
    }
    fn layer(&self) -> Layer {
        Layer::Resource
    }
    fn applies(&self, target: &Target) -> bool {
        matches!(target.kind, TargetKind::Server | TargetKind::Instance)
            && !script_log_files(target).is_empty()
    }
    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let files = script_log_files(ctx.target);
        if files.is_empty() {
            return CollectorOutcome::skipped("no script-engine logs found");
        }
        let compiled: Vec<(Regex, &Pattern)> = patterns()
            .iter()
            .filter_map(|p| Regex::new(p.regex).ok().map(|re| (re, p)))
            .collect();

        let mut emitted = 0usize;
        let mut scanned = 0usize;
        for file in &files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            scanned += 1;
            let locator = file.display().to_string();
            for hit in scan_lines(&text, &compiled) {
                ctx.store
                    .fact(self.id(), hit.fact_kind)
                    .subject(hit.target)
                    .attr("engine", hit.engine)
                    .attr("via", hit.via)
                    .attr("line", (hit.lineno as i64) + 1)
                    .attr("excerpt", hit.excerpt)
                    .source(SourceRef::at_line(locator.clone(), (hit.lineno as u32) + 1))
                    .confidence(DYNAMICS_CONFIDENCE)
                    .emit();
                emitted += 1;
            }
        }
        CollectorOutcome::active(emitted, format!("{scanned} script log(s) scanned"))
    }
}

/// One matched line: the marker it hit and the captured registry id.
struct MarkerHit {
    lineno: usize,
    engine: &'static str,
    fact_kind: &'static str,
    via: &'static str,
    target: String,
    excerpt: String,
}

/// Match every line against the compiled patterns (first match wins per line),
/// returning hits in line order.
fn scan_lines(text: &str, compiled: &[(Regex, &'static Pattern)]) -> Vec<MarkerHit> {
    text.lines()
        .enumerate()
        .filter_map(|(lineno, line)| {
            compiled.iter().find_map(|(re, p)| {
                let caps = re.captures(line)?;
                let target = caps.get(1)?.as_str().to_string();
                Some(MarkerHit {
                    lineno,
                    engine: p.engine,
                    fact_kind: p.fact_kind,
                    via: p.via,
                    target,
                    excerpt: truncate(line, 200),
                })
            })
        })
        .collect()
}

/// Candidate script-engine log files under a server/instance root, in a stable
/// order. Only existing files are returned.
fn script_log_files(target: &Target) -> Vec<PathBuf> {
    if !matches!(target.kind, TargetKind::Server | TargetKind::Instance) {
        return Vec::new();
    }
    // Search every candidate root (e.g. the launcher instance dir *and* its
    // `.minecraft` game root) so script-engine logs aren't missed on Prism /
    // MultiMC / CurseForge layouts.
    let mut out: Vec<PathBuf> = Vec::new();
    for root in target.candidate_roots() {
        let candidates = [
            root.join("crafttweaker.log"),
            root.join("logs").join("crafttweaker.log"),
            root.join("logs").join("kubejs").join("startup.log"),
            root.join("logs").join("kubejs").join("server.log"),
            root.join("logs").join("kubejs").join("client.log"),
            root.join("logs").join("groovyscript").join("server.log"),
            root.join("logs").join("groovyscript").join("client.log"),
            root.join("logs").join("groovyscript.log"),
            root.join("logs").join("rhino.log"),
            root.join("logs").join("script").join("rhino.log"),
        ];
        out.extend(candidates.into_iter().filter(|p| p.is_file()));
    }
    out.dedup();
    out
}

fn truncate(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= max {
        t.to_string()
    } else {
        let cut: String = t.chars().take(max).collect();
        format!("{cut}…")
    }
}

// ── Static script collector ────────────────────────────────────────────────

/// Scans a pack's data-pack **scripts on disk** (KubeJS `.js`, CraftTweaker
/// `.zs`) and emits runtime-removal/modification facts — the static counterpart
/// to [`ScriptDynamicsCollector`], which reads run logs. Together they let the
/// engine downgrade a static recipe finding that a script deletes anyway.
pub struct StaticScriptCollector;

/// Construct the static script-source collector.
#[must_use]
pub fn static_script_collector() -> StaticScriptCollector {
    StaticScriptCollector
}

impl Collector for StaticScriptCollector {
    fn id(&self) -> &'static str {
        "static-script-scanner"
    }
    fn layer(&self) -> Layer {
        Layer::Resource
    }
    fn applies(&self, target: &Target) -> bool {
        !script_scan::script_files(target).is_empty()
    }
    fn collect(&self, ctx: &mut CollectCtx<'_>) -> CollectorOutcome {
        let n = script_scan::script_files(ctx.target).len();
        if n == 0 {
            return CollectorOutcome::skipped("no KubeJS/CraftTweaker scripts found");
        }
        let emitted = script_scan::emit(ctx.store, ctx.target);
        CollectorOutcome::active(emitted, format!("{n} script file(s) scanned"))
    }
}

// ── Rule ─────────────────────────────────────────────────────────────────

/// Folds runtime-removal facts into a single auditable note.
pub struct ScriptDynamicsRule;

/// Construct the Layer-E dynamics rule.
#[must_use]
pub fn rule() -> ScriptDynamicsRule {
    ScriptDynamicsRule
}

/// Cap on how many ids are spelled out in the note's explanation; the rest are
/// summarised as a count so a kitchen-sink pack does not produce a wall of text.
const SAMPLE_LIMIT: usize = 12;

impl intermed_doctor_core::Rule for ScriptDynamicsRule {
    fn id(&self) -> &'static str {
        "script-dynamics"
    }
    fn evaluate(&self, ctx: &RuleCtx<'_>) -> Vec<Finding> {
        let recipes: Vec<&_> = ctx.store.by_kind(kind::RUNTIME_REMOVED_RECIPE).collect();
        let items: Vec<&_> = ctx.store.by_kind(kind::RUNTIME_REMOVED_ITEM).collect();
        let loot_tables: Vec<&_> = ctx
            .store
            .by_kind(kind::RUNTIME_REMOVED_LOOT_TABLE)
            .collect();
        let tags: Vec<&_> = ctx.store.by_kind(kind::RUNTIME_REMOVED_TAG).collect();
        if recipes.is_empty() && items.is_empty() && loot_tables.is_empty() && tags.is_empty() {
            return Vec::new();
        }

        let all_facts: Vec<&intermed_doctor_core::facts::Fact> = recipes
            .iter()
            .chain(items.iter())
            .chain(loot_tables.iter())
            .chain(tags.iter())
            .copied()
            .collect();

        let mut engines: Vec<&str> = all_facts.iter().filter_map(|f| f.attr("engine")).collect();
        engines.sort_unstable();
        engines.dedup();

        let explanation = format!(
            "Data-pack scripts ({}) removed {} recipe(s), {} item(s), {} loot table(s), and {} tag(s) at load time. \
             Items, recipes, and loot present in jars may therefore be unobtainable or unreachable in-game; \
             treat static content as a superset of what is actually reachable.{}{}{}{}",
            if engines.is_empty() {
                "script engine".to_string()
            } else {
                engines.join(", ")
            },
            recipes.len(),
            items.len(),
            loot_tables.len(),
            tags.len(),
            sample_clause("recipes", &recipes),
            sample_clause("items", &items),
            sample_clause("loot tables", &loot_tables),
            sample_clause("tags", &tags),
        );

        let mut builder = Finding::builder("script-dynamics", "runtime-content-removed")
            .severity(Severity::Note)
            .category(Category::Resource)
            .title(format!(
                "Scripts removed {} recipe(s), {} item(s), {} loot table(s), {} tag(s) at runtime",
                recipes.len(),
                items.len(),
                loot_tables.len(),
                tags.len()
            ))
            .explanation(explanation)
            .tag("dynamics")
            .tag("script-engine");
        for engine in &engines {
            builder = builder.tag(*engine);
        }
        for fact in &all_facts {
            builder = builder.evidence(EvidenceEdge::subject(fact.id));
        }
        vec![builder.build()]
    }
}

/// Render a "; e.g. a, b, c (+N more)" clause for a fact group, or empty if none.
fn sample_clause(label: &str, facts: &[&intermed_doctor_core::facts::Fact]) -> String {
    if facts.is_empty() {
        return String::new();
    }
    let mut ids: Vec<&str> = facts.iter().map(|f| f.subject.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    let shown: Vec<&str> = ids.iter().take(SAMPLE_LIMIT).copied().collect();
    let extra = ids.len().saturating_sub(shown.len());
    let suffix = if extra > 0 {
        format!(" (+{extra} more)")
    } else {
        String::new()
    };
    format!(" Removed {label}: {}{suffix}.", shown.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::{DiagnosticEngine, Rule, Target, TargetKind};

    fn write(path: &std::path::Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn crafttweaker_and_kubejs_markers_become_facts_and_a_note() {
        let dir = std::env::temp_dir().join(format!("imd-dyn-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        write(
            &dir.join("crafttweaker.log"),
            "[INITIALIZE][SERVER][INFO] Removing recipe <recipe:minecraft:furnace>\n\
             [INITIALIZE][SERVER][INFO] Removing all recipes for <item:minecraft:stick>\n\
             [INITIALIZE][SERVER][INFO] Hiding item <item:create:brass_ingot>\n\
             [INITIALIZE][SERVER][INFO] Clearing <tag:minecraft:logs>\n\
             [INITIALIZE][SERVER][INFO] Removing <loot_table:minecraft:chests/simple_dungeon>\n\
             [INITIALIZE][SERVER][INFO] ordinary line, nothing here\n",
        );
        write(
            &dir.join("logs").join("kubejs").join("server.log"),
            "[18:00:00] [Server thread/INFO] [KubeJS Server/]: Removed recipe 'minecraft:crafting_table'\n\
             [18:00:00] [Server thread/INFO] [KubeJS Server/]: Removed item 'farmersdelight:rice'\n\
             [18:00:00] [Server thread/INFO] [KubeJS Server/]: Removed tag '#minecraft:planks'\n\
             [18:00:00] [Server thread/INFO] [KubeJS Server/]: Removed loot table 'minecraft:blocks/oak_log'\n",
        );

        let engine = DiagnosticEngine::builder()
            .collector(collector())
            .rule(rule())
            .build();
        let target = Target {
            path: dir.clone(),
            kind: TargetKind::Server,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let run = engine.diagnose_with_facts(&target);

        let recipe_facts: Vec<_> = run
            .facts
            .iter()
            .filter(|f| f.kind == kind::RUNTIME_REMOVED_RECIPE)
            .collect();
        let item_facts: Vec<_> = run
            .facts
            .iter()
            .filter(|f| f.kind == kind::RUNTIME_REMOVED_ITEM)
            .collect();
        let tag_facts: Vec<_> = run
            .facts
            .iter()
            .filter(|f| f.kind == kind::RUNTIME_REMOVED_TAG)
            .collect();
        let loot_facts: Vec<_> = run
            .facts
            .iter()
            .filter(|f| f.kind == kind::RUNTIME_REMOVED_LOOT_TABLE)
            .collect();
        assert_eq!(recipe_facts.len(), 2, "furnace + crafting_table");
        assert_eq!(item_facts.len(), 3, "stick + brass_ingot + rice");
        assert_eq!(tag_facts.len(), 2, "logs + planks");
        assert_eq!(loot_facts.len(), 2, "dungeon + oak_log");
        assert!(
            recipe_facts
                .iter()
                .any(|f| f.subject == "minecraft:furnace")
        );
        assert!(item_facts.iter().any(|f| f.subject == "create:brass_ingot"));

        let note = run
            .report
            .findings
            .iter()
            .find(|f| f.id == "runtime-content-removed")
            .expect("dynamics note emitted");
        assert!(note.machine_tags.iter().any(|t| t == engine::CRAFTTWEAKER));
        assert!(note.machine_tags.iter().any(|t| t == engine::KUBEJS));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn groovyscript_marker_regex_matches_bracketed_log_line() {
        let pat = patterns()
            .iter()
            .find(|p| {
                p.engine == engine::GROOVYSCRIPT && p.fact_kind == kind::RUNTIME_REMOVED_RECIPE
            })
            .expect("groovy recipe pattern");
        let re = Regex::new(pat.regex).expect("regex compiles");
        let line = "[INFO] [GroovyScript] Removed recipe 'create:mixing'";
        assert!(re.is_match(line), "pattern `{}` must match", pat.regex);
    }

    #[test]
    fn groovyscript_log_is_scanned() {
        let dir = std::env::temp_dir().join(format!("imd-dyn-groovy-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let log = dir.join("logs").join("groovyscript.log");
        write(
            &log,
            "[INFO] [GroovyScript] Removed recipe 'create:mixing'\n",
        );
        let target = Target {
            path: dir.clone(),
            kind: TargetKind::Server,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        assert!(
            collector().applies(&target),
            "expected script log at {}",
            log.display()
        );
        let text = std::fs::read_to_string(&log).unwrap();
        let compiled: Vec<(Regex, &Pattern)> = patterns()
            .iter()
            .filter_map(|p| Regex::new(p.regex).ok().map(|re| (re, p)))
            .collect();
        let hits = scan_lines(&text, &compiled);
        assert!(
            hits.iter().any(|h| h.engine == engine::GROOVYSCRIPT),
            "expected GroovyScript marker in log"
        );

        let engine = DiagnosticEngine::builder().collector(collector()).build();
        let run = engine.diagnose_with_facts(&target);
        assert!(run.facts.iter().any(|f| {
            f.kind == kind::RUNTIME_REMOVED_RECIPE && f.attr("engine") == Some(engine::GROOVYSCRIPT)
        }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_script_logs_yields_no_facts() {
        let dir = std::env::temp_dir().join(format!("imd-dyn-empty-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let target = Target {
            path: dir.clone(),
            kind: TargetKind::Server,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        assert!(!collector().applies(&target));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rule_is_silent_without_facts() {
        let store = intermed_doctor_core::facts::FactStore::new();
        let target = Target {
            path: ".".into(),
            kind: TargetKind::Server,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        assert!(ScriptDynamicsRule.evaluate(&ctx).is_empty());
    }
}
