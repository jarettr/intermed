//! Self-contained, tabbed HTML renderer for [`DoctorReport`].
//!
//! One file, inline CSS + JS, **no network**: tabs (Summary / Findings / Mixin /
//! Facts / Performance), client-side severity & category filtering on the
//! findings table, expandable per-finding **provenance** (evidence edges resolved
//! to the facts they cite), and a mixin risk **heatmap**. When facts are supplied
//! ([`render_html_with_facts`]) the Mixin / Facts / Performance tabs and provenance
//! are populated; the legacy [`render_html`] keeps working facts-free.

use std::collections::BTreeMap;

use intermed_doctor_core::DoctorReport;
use intermed_facts::{AttrValue, Fact, FactId, SourceRef};

/// Render the report with no fact corpus (provenance / mixin / fact tabs degrade
/// to "no data"). Kept for the generic `render(report, Format::Html)` path.
#[must_use]
pub fn render_html(report: &DoctorReport) -> String {
    render_html_with_facts(report, &[])
}

/// Render the full interactive report, using `facts` to populate provenance, the
/// mixin heatmap, the fact explorer, and the performance tab.
#[must_use]
pub fn render_html_with_facts(report: &DoctorReport, facts: &[Fact]) -> String {
    let by_id: BTreeMap<FactId, &Fact> = facts.iter().map(|f| (f.id, f)).collect();

    let summary = summary_section(report);
    let findings = findings_section(report, &by_id);
    let deps = dependencies_section(facts);
    let resources = resources_section(report, facts);
    let mixin = mixin_section(facts);
    let security = security_section(facts);
    let facts_tab = facts_section(report, facts);
    let perf = performance_section(report, facts);

    SHELL
        .replace("__TARGET__", &escape(&report.target.path))
        .replace("__GENERATED__", &escape(&report.generated_at.to_rfc3339()))
        .replace("__VERSION__", &escape(&report.tool_version))
        .replace("__SUMMARY__", &summary)
        .replace("__FINDINGS__", &findings)
        .replace("__DEPS__", &deps)
        .replace("__RESOURCES__", &resources)
        .replace("__MIXIN__", &mixin)
        .replace("__SECURITY__", &security)
        .replace("__FACTS__", &facts_tab)
        .replace("__PERF__", &perf)
}

// ── Summary tab ──────────────────────────────────────────────────────────────

fn summary_section(report: &DoctorReport) -> String {
    let env = &report.environment;
    let s = &report.summary;
    let worst = s
        .worst
        .map(|w| format!("{w:?}"))
        .unwrap_or_else(|| "none".into());
    let opt = |o: &Option<String>| escape(o.as_deref().unwrap_or("?"));
    // A bare mods dir has no instance to read loader / MC version from, so the
    // report infers them from the scanned mods. Label those cells as inferred so
    // they are not mistaken for an authoritative instance reading.
    let inferred = matches!(
        env.layout,
        Some(intermed_doctor_core::LayoutKind::BareModsDir)
    );
    let derived = |o: &Option<String>| match o {
        Some(v) if inferred => format!("{} <span class=\"muted\">(inferred)</span>", escape(v)),
        Some(v) => escape(v),
        None => "?".into(),
    };

    // Split the headline into signal vs. noise: actionable = fatal+error+warn
    // (things to act on), informational = note+info (safe merges, per-handler
    // effect notes, …). The raw `total` alone overstates how much needs attention.
    let actionable = s.fatal + s.error + s.warn;
    let informational = s.note + s.info;
    let mut out = String::new();
    out.push_str(&format!(
        "<div class=\"cards\">\
         <div class=\"card sev-{worst_l}\" title=\"fatal + error + warn — findings to act on\">\
           <div class=\"num\">{actionable}</div><div>actionable</div></div>\
         <div class=\"card\" title=\"note + info — safe merges, effect notes, context\">\
           <div class=\"num\">{informational}</div><div>informational</div></div>\
         <div class=\"card\"><div class=\"num\">{total}</div><div>total</div></div>\
         <div class=\"sep\"></div>\
         <div class=\"card sev-fatal\"><div class=\"num\">{fatal}</div><div>fatal</div></div>\
         <div class=\"card sev-error\"><div class=\"num\">{error}</div><div>error</div></div>\
         <div class=\"card sev-warn\"><div class=\"num\">{warn}</div><div>warn</div></div>\
         <div class=\"card sev-note\"><div class=\"num\">{note}</div><div>note</div></div>\
         <div class=\"card\"><div class=\"num\">{exit}</div><div>exit code</div></div>\
         </div>",
        worst_l = escape(&worst.to_lowercase()),
        total = s.total,
        fatal = s.fatal,
        error = s.error,
        warn = s.warn,
        note = s.note,
        exit = report.exit_code(),
    ));

    out.push_str("<h3>Environment</h3><table class=\"kv\">");
    for (k, v) in [
        ("Target", escape(&report.target.path)),
        ("Kind", escape(&format!("{:?}", report.target.kind))),
        (
            "Loader",
            derived(&env.loader.as_ref().map(|l| l.as_str().to_string())),
        ),
        ("Minecraft", derived(&env.minecraft_version)),
        ("Launcher", opt(&env.launcher)),
        ("Side", dbg_opt(&env.side)),
        ("OS", opt(&env.os)),
        ("Worst severity", escape(&worst)),
    ] {
        out.push_str(&format!("<tr><th>{k}</th><td>{v}</td></tr>"));
    }
    out.push_str("</table>");

    out.push_str("<h3>Collectors</h3><table><thead><tr><th>Collector</th><th>Layer</th><th>Status</th><th>Facts</th></tr></thead><tbody>");
    for c in &report.collectors {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&c.id),
            escape(&c.layer_code),
            escape(&c.status),
            c.facts_emitted
        ));
    }
    out.push_str("</tbody></table>");

    if !report.deferred_layers.is_empty() {
        out.push_str("<h3>Deferred layers</h3><ul>");
        for d in &report.deferred_layers {
            out.push_str(&format!("<li>{}</li>", escape(&format!("{d:?}"))));
        }
        out.push_str("</ul>");
    }
    out
}

// ── Findings tab (filter + provenance) ───────────────────────────────────────

fn findings_section(report: &DoctorReport, by_id: &BTreeMap<FactId, &Fact>) -> String {
    if report.findings.is_empty() {
        return "<p class=\"empty\">No findings — the pack looks healthy.</p>".into();
    }
    let mut categories: Vec<String> = report
        .findings
        .iter()
        .map(|f| format!("{:?}", f.category))
        .collect();
    categories.sort();
    categories.dedup();

    let mut out = group_overview_html(report);

    out.push_str("<div class=\"filters\"><strong>Severity:</strong> ");
    for sev in ["fatal", "error", "warn", "note", "info"] {
        out.push_str(&format!(
            "<label><input type=\"checkbox\" class=\"f-sev\" value=\"{sev}\" checked>{sev}</label> "
        ));
    }
    out.push_str("<br><strong>Category:</strong> ");
    for cat in &categories {
        let c = escape(cat);
        out.push_str(&format!(
            "<label><input type=\"checkbox\" class=\"f-cat\" value=\"{c}\" checked>{c}</label> "
        ));
    }
    out.push_str("</div>");

    out.push_str("<table id=\"findings\"><thead><tr><th></th><th>Severity</th><th>Category</th><th>Id</th><th>Title</th></tr></thead><tbody>");
    for (i, f) in report.findings.iter().enumerate() {
        let sev = format!("{:?}", f.severity).to_lowercase();
        let cat = format!("{:?}", f.category);
        out.push_str(&format!(
            "<tr class=\"frow sev-{sev}\" data-sev=\"{sev}\" data-cat=\"{cat}\" onclick=\"tog({i})\">\
             <td class=\"caret\">▸</td><td>{sev}</td><td>{cat}</td><td><code>{id}</code></td><td>{title}</td></tr>",
            cat = escape(&cat), id = escape(&f.id), title = escape(&f.title),
        ));
        // Detail row: explanation + fixes + provenance.
        let mut detail = format!("<p>{}</p>", escape(&f.explanation));
        if !f.fix_candidates.is_empty() {
            detail.push_str("<p><strong>Fixes:</strong></p><ul>");
            for fix in &f.fix_candidates {
                detail.push_str(&format!("<li>{}</li>", escape(&fix.description)));
            }
            detail.push_str("</ul>");
        }
        detail.push_str(&provenance_html(f, by_id));
        out.push_str(&format!(
            "<tr class=\"detail\" id=\"d{i}\" style=\"display:none\"><td></td><td colspan=\"4\">{detail}</td></tr>"
        ));
    }
    out.push_str("</tbody></table>");
    out
}

/// A collapsible per-family overview above the findings table: each finding
/// family (`recipe-output-override`, …) is one `<details>` with its count, worst
/// severity, and member ids. "Normal state" families (safe merges, pack.mcmeta)
/// are summarised as a single collapsed line so they don't dominate.
fn group_overview_html(report: &DoctorReport) -> String {
    let visible: Vec<&intermed_doctor_core::evidence::Finding> = report
        .findings
        .iter()
        .filter(|f| f.visibility.shown_by_default())
        .collect();
    let hidden = report.findings.len() - visible.len();
    let groups = crate::grouping::group_findings(&visible);

    let mut out = String::from("<div class=\"groups\"><h3>Finding groups</h3>");
    if groups.is_empty() {
        out.push_str("<p class=\"empty\">No actionable findings.</p>");
    }
    for g in &groups {
        let sev = format!("{:?}", g.severity).to_lowercase();
        out.push_str(&format!(
            "<details class=\"grp sev-{sev}\"><summary><strong>{title}</strong> \
             <span class=\"badge\">{sev}</span> · {n} finding(s)</summary><ul>",
            title = escape(&g.title),
            n = g.len(),
        ));
        for f in &g.members {
            out.push_str(&format!(
                "<li><code>{}</code> — {}</li>",
                escape(&f.id),
                escape(&f.title)
            ));
        }
        out.push_str("</ul></details>");
    }
    if hidden > 0 {
        out.push_str(&format!(
            "<p class=\"hidden-note\">{hidden} normal-state finding(s) (safe merges / pack.mcmeta) \
             hidden — see the full table below or <code>--vfs-explain-safe</code>.</p>"
        ));
    }
    out.push_str("</div>");
    out
}

fn provenance_html(
    f: &intermed_doctor_core::evidence::Finding,
    by_id: &BTreeMap<FactId, &Fact>,
) -> String {
    if f.evidence.is_empty() {
        return String::new();
    }
    // A synthetic / derived fact (no file source, or one the rule fabricated and
    // never stored) is explained by the *other* facts this finding cites, so its
    // "source" reads "derived from <kind>#<id>, …" instead of an empty dash.
    let sibling_refs: Vec<String> = f
        .evidence
        .iter()
        .filter_map(|e| {
            by_id
                .get(&e.fact)
                .map(|fact| format!("{}#{}", fact.kind, e.fact.0))
        })
        .collect();
    let derived_from = |self_id: FactId| -> String {
        let refs: Vec<&String> = sibling_refs
            .iter()
            .filter(|r| !r.ends_with(&format!("#{}", self_id.0)))
            .collect();
        if refs.is_empty() {
            "synthetic (no backing fact retained)".to_string()
        } else {
            format!(
                "derived from {}",
                refs.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    };

    let mut out = String::from(
        "<p><strong>Provenance (evidence):</strong></p><table class=\"evidence\"><thead><tr><th>Relation</th><th>Fact</th><th>Subject</th><th>Attributes</th><th>Source</th><th>Extractor</th><th>Weight</th></tr></thead><tbody>",
    );
    for e in &f.evidence {
        let (kind, subject, attrs, source, extractor) = match by_id.get(&e.fact) {
            Some(fact) => {
                let raw_source = source_str(&fact.source);
                // A retained fact with no real source is still synthetic — explain
                // its derivation rather than printing an empty source.
                let source = if raw_source.trim().is_empty() {
                    escape(&derived_from(e.fact))
                } else {
                    escape(&raw_source)
                };
                let extractor = if fact.extractor.trim().is_empty() {
                    "derived".to_string()
                } else {
                    escape(&fact.extractor)
                };
                (
                    escape(&fact.kind),
                    if fact.subject.is_empty() {
                        "—".into()
                    } else {
                        escape(&fact.subject)
                    },
                    attr_summary(fact),
                    source,
                    extractor,
                )
            }
            // The fact id was never stored (a purely synthetic evidence edge).
            None => (
                "synthetic".to_string(),
                "—".into(),
                "—".into(),
                escape(&derived_from(e.fact)),
                "derived".to_string(),
            ),
        };
        out.push_str(&format!(
            "<tr><td>{rel:?}</td><td><code>{kind}</code></td><td>{subject}</td><td class=\"attrs\">{attrs}</td><td class=\"src\">{source}</td><td>{extractor}</td><td>{w:.2}</td></tr>",
            rel = e.relation, w = e.weight,
        ));
    }
    out.push_str("</tbody></table>");
    out
}

/// Compact `key=value` summary of a fact's attributes for the provenance table.
fn attr_summary(fact: &Fact) -> String {
    if fact.attributes.is_empty() {
        return "—".to_string();
    }
    let mut parts: Vec<String> = fact
        .attributes
        .keys()
        .map(|k| format!("{}={}", k, attr_display(fact, k, "?")))
        .collect();
    parts.sort();
    // Keep the cell readable; cap the number of attributes shown.
    const MAX: usize = 6;
    let extra = parts.len().saturating_sub(MAX);
    parts.truncate(MAX);
    let mut joined = escape(&parts.join(", "));
    if extra > 0 {
        joined.push_str(&format!(" … (+{extra})"));
    }
    joined
}

// ── Mixin tab (risk heatmap + overlaps + complexity/bloat) ───────────────────

fn mixin_section(facts: &[Fact]) -> String {
    let risk: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind == "mixin_risk_score")
        .collect();
    let overlaps: Vec<&Fact> = facts.iter().filter(|f| f.kind == "mixin_overlap").collect();
    let complexity: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind == "mixin_mod_complexity")
        .collect();
    let bloat: Vec<&Fact> = facts.iter().filter(|f| f.kind == "mixin_bloat").collect();

    if risk.is_empty() && overlaps.is_empty() && complexity.is_empty() {
        return "<p class=\"empty\">No mixin facts. Run <code>doctor --mixin-risk</code>.</p>"
            .into();
    }

    let mut out = String::new();
    if !risk.is_empty() {
        out.push_str("<h3>Risk heatmap (per target)</h3><div class=\"heatmap\">");
        let mut sorted = risk.clone();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.attr_int("score").unwrap_or(0)));
        for f in sorted {
            let score = f.attr_int("score").unwrap_or(0);
            let reasons = escape(f.attr("reasons").unwrap_or(""));
            out.push_str(&format!(
                "<div class=\"hcell\" style=\"background:{}\" title=\"{reasons}\">\
                 <div class=\"score\">{score}</div><div class=\"htarget\">{target}</div></div>",
                heat_color(score),
                target = escape(&f.subject),
            ));
        }
        out.push_str("</div>");
    }

    if !complexity.is_empty() {
        out.push_str("<h3>Mixin Complexity Score (per mod)</h3><table><thead><tr><th>Mod</th><th>Score</th><th>Classes</th><th>Targets</th></tr></thead><tbody>");
        let mut sorted = complexity.clone();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.attr_int("score").unwrap_or(0)));
        for f in sorted {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&f.subject),
                f.attr_int("score").unwrap_or(0),
                f.attr_int("class_count").unwrap_or(0),
                f.attr_int("target_count").unwrap_or(0),
            ));
        }
        out.push_str("</tbody></table>");
    }

    if !bloat.is_empty() {
        out.push_str("<h3>Mixin bloat (low-yield handlers)</h3><table><thead><tr><th>Mod</th><th>Score</th><th>Inert / total handlers</th></tr></thead><tbody>");
        for f in &bloat {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{} / {}</td></tr>",
                escape(&f.subject),
                f.attr_int("score").unwrap_or(0),
                f.attr_int("inert_handlers").unwrap_or(0),
                f.attr_int("total_handlers").unwrap_or(0),
            ));
        }
        out.push_str("</tbody></table>");
    }

    if !overlaps.is_empty() {
        out.push_str(
            "<h3>Overlaps</h3><table><thead><tr><th>Target</th><th>Mods</th></tr></thead><tbody>",
        );
        for f in &overlaps {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                escape(&f.subject),
                escape(f.attr("mods").unwrap_or("")),
            ));
        }
        out.push_str("</tbody></table>");
    }
    out
}

/// Green → amber → red by score (0–100).
fn heat_color(score: i64) -> &'static str {
    match score {
        0..=40 => "#2e7d32",
        41..=60 => "#9e9d24",
        61..=80 => "#ef6c00",
        _ => "#c62828",
    }
}

// ── Facts tab ────────────────────────────────────────────────────────────────

fn facts_section(report: &DoctorReport, facts: &[Fact]) -> String {
    let mut out = String::from("<h3>Predicate histogram</h3>");
    out.push_str(&histogram_table(&report.fact_stats));
    if facts.is_empty() {
        return out;
    }
    out.push_str("<h3>Facts</h3><p class=\"muted\">First 500 facts.</p>");
    out.push_str(
        "<table><thead><tr><th>Kind</th><th>Subject</th><th>Source</th></tr></thead><tbody>",
    );
    for f in facts.iter().take(500) {
        out.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td class=\"src\">{}</td></tr>",
            escape(&f.kind),
            escape(&f.subject),
            escape(&source_str(&f.source)),
        ));
    }
    out.push_str("</tbody></table>");
    out
}

// ── Performance tab ──────────────────────────────────────────────────────────

fn performance_section(report: &DoctorReport, facts: &[Fact]) -> String {
    let mut out = String::new();

    let hot_methods: Vec<&Fact> = facts.iter().filter(|f| f.kind == "hot_method").collect();
    let hot_mods: Vec<&Fact> = facts.iter().filter(|f| f.kind == "hot_mod").collect();
    let spikes: Vec<&Fact> = facts.iter().filter(|f| f.kind == "tick_spike").collect();

    if !hot_mods.is_empty() {
        out.push_str(
            "<h3>Hot mods (CPU %)</h3><table><thead><tr><th>Mod</th><th>%</th></tr></thead><tbody>",
        );
        for f in &hot_mods {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                escape(&f.subject),
                escape(&attr_display(f, "percent", "?"))
            ));
        }
        out.push_str("</tbody></table>");
    }
    if !hot_methods.is_empty() {
        out.push_str("<h3>Hot methods</h3><table><thead><tr><th>Class</th><th>Method</th><th>%</th></tr></thead><tbody>");
        for f in &hot_methods {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&f.subject),
                escape(&attr_display(f, "method", "")),
                escape(&attr_display(f, "percent", "?"))
            ));
        }
        out.push_str("</tbody></table>");
    }
    if !spikes.is_empty() {
        out.push_str(&format!(
            "<p><strong>{} tick spike(s) recorded.</strong></p>",
            spikes.len()
        ));
    }

    if let Some(profile) = &report.profile {
        out.push_str(&format!(
            "<h3>Phase timings (total {} ms)</h3>",
            profile.total_ms
        ));
        out.push_str(
            "<table><thead><tr><th>Phase</th><th>Kind</th><th>ms</th></tr></thead><tbody>",
        );
        for p in &profile.collectors {
            out.push_str(&format!(
                "<tr><td>{}</td><td>collector</td><td>{}</td></tr>",
                escape(&p.id),
                p.duration_ms
            ));
        }
        for p in &profile.rules {
            out.push_str(&format!(
                "<tr><td>{}</td><td>rule</td><td>{}</td></tr>",
                escape(&p.id),
                p.duration_ms
            ));
        }
        out.push_str("</tbody></table>");
    }

    if out.is_empty() {
        out.push_str("<p class=\"empty\">No performance data. Run with <code>--performance --spark-report</code>.</p>");
    }
    out
}

// ── Dependencies tab (Layer C) ───────────────────────────────────────────────

/// Loader/runtime pseudo-dependencies every mod declares — not actionable as
/// "missing mod" rows, so they are folded out of the declared-deps table.
const PSEUDO_DEPS: &[&str] = &[
    "minecraft",
    "java",
    "forge",
    "neoforge",
    "fabricloader",
    "fabric",
    "quilt_loader",
    "fml",
];

fn dependencies_section(facts: &[Fact]) -> String {
    let declared: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind == "dependency")
        .filter(|f| !PSEUDO_DEPS.contains(&f.attr("dep").unwrap_or("")))
        .collect();
    let implicit: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind == "implicit_dependency_candidate")
        .collect();
    let provided: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind == "provided_dependency")
        .collect();

    if declared.is_empty() && implicit.is_empty() && provided.is_empty() {
        return "<p class=\"empty\">No inter-mod dependency facts.</p>".into();
    }

    let mut out = String::new();

    if !declared.is_empty() {
        out.push_str("<h3>Declared dependencies (mod → mod)</h3>");
        out.push_str("<table><thead><tr><th>Mod</th><th>Requires</th><th>Range</th><th>Mandatory</th><th>Relation</th></tr></thead><tbody>");
        let mut rows = declared.clone();
        rows.sort_by(|a, b| (a.subject.as_str(), a.attr("dep")).cmp(&(&b.subject, b.attr("dep"))));
        for f in rows {
            let mandatory = f.attr("mandatory").unwrap_or("?") == "true"
                || matches!(f.attributes.get("mandatory"), Some(AttrValue::Bool(true)));
            out.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td class=\"src\">{}</td><td>{}</td><td>{}</td></tr>",
                escape(&f.subject),
                escape(f.attr("dep").unwrap_or("?")),
                escape(f.attr("range").unwrap_or("*")),
                if mandatory { "required" } else { "optional" },
                escape(f.attr("relation").unwrap_or("depends")),
            ));
        }
        out.push_str("</tbody></table>");
    }

    if !implicit.is_empty() {
        out.push_str("<h3>Implicit dependencies (data references an uninstalled mod)</h3>");
        out.push_str("<table><thead><tr><th>Referenced namespace</th><th>From</th><th>Refs</th><th>State</th></tr></thead><tbody>");
        for f in &implicit {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td class=\"src\">{}</td><td>{}</td><td>{}</td></tr>",
                escape(&f.subject),
                escape(f.attr("from_path").unwrap_or("?")),
                attr_display(f, "ref_count", "?"),
                escape(f.attr("resolve_state").unwrap_or("?")),
            ));
        }
        out.push_str("</tbody></table>");
    }

    if !provided.is_empty() {
        out.push_str("<h3>Provided / bundled dependencies (Jar-in-Jar)</h3>");
        out.push_str("<table><thead><tr><th>Provider</th><th>Provides</th><th>Version</th><th>Scope</th></tr></thead><tbody>");
        for f in &provided {
            out.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td class=\"src\">{}</td><td>{}</td></tr>",
                escape(&f.subject),
                escape(f.attr("provides").unwrap_or("?")),
                escape(f.attr("version").unwrap_or("?")),
                escape(f.attr("scope").unwrap_or("?")),
            ));
        }
        out.push_str("</tbody></table>");
    }
    out
}

// ── Resources tab (Layer M) ──────────────────────────────────────────────────

fn resources_section(report: &DoctorReport, facts: &[Fact]) -> String {
    let parsed = count_kind(facts, "resource_ast_parsed");
    let writers = count_kind(facts, "resource_writer");
    let collisions: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind == "resource_collision")
        .collect();
    let owners: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind == "namespace_owner")
        .collect();
    let unresolved: Vec<&Fact> = facts
        .iter()
        .filter(|f| {
            f.kind == "resource_resolve_result"
                && f.attr("state")
                    .map(|s| s.contains("missing"))
                    .unwrap_or(false)
        })
        .collect();
    let diffs: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind == "resource_semantic_diff")
        .collect();

    // Contested namespaces: a namespace written by more than one mod.
    let mut by_ns: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for f in &owners {
        if let Some(w) = f.attr("writer") {
            by_ns.entry(f.subject.as_str()).or_default().push(w);
        }
    }
    let contested: Vec<(&str, Vec<&str>)> = by_ns
        .into_iter()
        .filter(|(_, w)| w.len() > 1)
        .map(|(ns, mut w)| {
            w.sort();
            w.dedup();
            (ns, w)
        })
        .filter(|(_, w)| w.len() > 1)
        .collect();

    if parsed == 0 && writers == 0 && collisions.is_empty() && owners.is_empty() {
        return "<p class=\"empty\">No resource (Layer M) facts. Run <code>doctor --resource-level semantic</code>.</p>".into();
    }

    let mut out = String::from("<div class=\"cards\">");
    for (n, label) in [
        (parsed, "AST parsed"),
        (writers, "writer records"),
        (owners.len(), "namespaces"),
        (collisions.len(), "collisions"),
        (contested.len(), "contested ns"),
        (unresolved.len(), "unresolved refs"),
    ] {
        out.push_str(&format!(
            "<div class=\"card\"><div class=\"num\">{n}</div><div>{label}</div></div>"
        ));
    }
    out.push_str("</div>");

    // Semantic overrides (the actionable Layer-M diffs).
    if !diffs.is_empty() {
        out.push_str("<h3>Semantic overrides</h3><table><thead><tr><th>Resource</th><th>Kind</th><th>Detail</th></tr></thead><tbody>");
        for f in &diffs {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td class=\"src\">{}</td></tr>",
                escape(&f.subject),
                escape(
                    f.attr("class")
                        .or_else(|| f.attr("kind"))
                        .unwrap_or("override")
                ),
                escape(f.attr("detail").unwrap_or("")),
            ));
        }
        out.push_str("</tbody></table>");
    }

    if !contested.is_empty() {
        out.push_str("<h3>Contested namespaces (multiple writers)</h3><table><thead><tr><th>Namespace</th><th>Writers</th></tr></thead><tbody>");
        for (ns, writers) in &contested {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td></tr>",
                escape(ns),
                escape(&writers.join(", ")),
            ));
        }
        out.push_str("</tbody></table>");
    }

    if !collisions.is_empty() {
        // Group collisions by their classification for a digestible summary.
        let mut by_class: BTreeMap<&str, (usize, &str)> = BTreeMap::new();
        for f in &collisions {
            let class = f.attr("class").unwrap_or("override");
            let entry = by_class.entry(class).or_insert((0, ""));
            entry.0 += 1;
            if entry.1.is_empty() {
                entry.1 = f.subject.as_str();
            }
        }
        out.push_str("<h3>Collisions by kind</h3><table><thead><tr><th>Kind</th><th>Count</th><th>Example</th></tr></thead><tbody>");
        for (class, (n, example)) in &by_class {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"src\"><code>{}</code></td></tr>",
                escape(class),
                n,
                escape(example),
            ));
        }
        out.push_str("</tbody></table>");
    }

    if !unresolved.is_empty() {
        out.push_str("<h3>Unresolved references</h3><table><thead><tr><th>Namespace</th><th>From</th><th>Required</th></tr></thead><tbody>");
        for f in unresolved.iter().take(200) {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td class=\"src\">{}</td><td>{}</td></tr>",
                escape(&f.subject),
                escape(f.attr("source_path").unwrap_or("?")),
                attr_display(f, "required", "?"),
            ));
        }
        out.push_str("</tbody></table>");
    }

    let _ = report;
    out
}

// ── Security tab (Layer 6: SBOM / trust / dangerous API surface) ──────────────

fn security_section(facts: &[Fact]) -> String {
    let trust: Vec<&Fact> = facts.iter().filter(|f| f.kind == "trust_score").collect();
    let sigs: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind == "signature_status")
        .collect();
    let coremods: Vec<&Fact> = facts.iter().filter(|f| f.kind == "coremod").collect();
    // Dangerous-API capability facts share the `uses_` kind prefix.
    let dangerous: Vec<&Fact> = facts
        .iter()
        .filter(|f| f.kind.starts_with("uses_"))
        .collect();

    if trust.is_empty() && sigs.is_empty() && coremods.is_empty() && dangerous.is_empty() {
        return "<p class=\"empty\">No SBOM / security facts.</p>".into();
    }

    let mut out = String::new();

    if !dangerous.is_empty() {
        out.push_str("<h3>Dangerous API surface</h3><p class=\"muted\">Constant-pool preflight hints — a reference, not proof of runtime behaviour.</p>");
        out.push_str("<table><thead><tr><th>Mod</th><th>Capability</th><th>Dangerous / scanned classes</th><th>Evidence</th></tr></thead><tbody>");
        let mut rows = dangerous.clone();
        rows.sort_by_key(|f| std::cmp::Reverse(f.attr_int("dangerous_classes").unwrap_or(0)));
        for f in rows {
            let cap = f
                .kind
                .strip_prefix("uses_")
                .unwrap_or(&f.kind)
                .replace('_', " ");
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{} / {}</td><td>{}</td></tr>",
                escape(&f.subject),
                escape(&cap),
                attr_display(f, "dangerous_classes", "?"),
                attr_display(f, "classes_scanned", "?"),
                escape(f.attr("evidence_strength").unwrap_or("?")),
            ));
        }
        out.push_str("</tbody></table>");
    }

    if !trust.is_empty() {
        out.push_str("<h3>Trust scores (lowest first)</h3><table><thead><tr><th>Artifact</th><th>Score</th></tr></thead><tbody>");
        let mut rows = trust.clone();
        rows.sort_by_key(|f| f.attr_int("score").unwrap_or(0));
        for f in rows {
            let score = f.attr_int("score").unwrap_or(0);
            out.push_str(&format!(
                "<tr><td>{}</td><td style=\"color:{}\">{}</td></tr>",
                escape(&f.subject),
                heat_color(100 - score),
                score,
            ));
        }
        out.push_str("</tbody></table>");
    }

    if !sigs.is_empty() {
        let unsigned: Vec<&&Fact> = sigs
            .iter()
            .filter(|f| f.attr("status").map(|s| s != "signed").unwrap_or(true))
            .collect();
        out.push_str(&format!(
            "<h3>Signatures</h3><p>{} of {} artifact(s) are unsigned.</p>",
            unsigned.len(),
            sigs.len()
        ));
        if !unsigned.is_empty() {
            out.push_str("<details><summary>Unsigned artifacts</summary><ul>");
            for f in &unsigned {
                out.push_str(&format!("<li><code>{}</code></li>", escape(&f.subject)));
            }
            out.push_str("</ul></details>");
        }
    }

    if !coremods.is_empty() {
        out.push_str("<h3>Coremods (bytecode transformers)</h3><table><thead><tr><th>Mod</th><th>Transformer</th><th>Loader</th></tr></thead><tbody>");
        for f in &coremods {
            out.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                escape(&f.subject),
                escape(f.attr("name").unwrap_or("?")),
                escape(f.attr("loader").unwrap_or("?")),
            ));
        }
        out.push_str("</tbody></table>");
    }
    out
}

/// Count facts of a given kind.
fn count_kind(facts: &[Fact], kind: &str) -> usize {
    facts.iter().filter(|f| f.kind == kind).count()
}

// ── shared helpers ───────────────────────────────────────────────────────────

fn histogram_table(hist: &BTreeMap<String, usize>) -> String {
    if hist.is_empty() {
        return "<p class=\"empty\">none</p>".into();
    }
    let mut out =
        String::from("<table><thead><tr><th>Predicate</th><th>Count</th></tr></thead><tbody>");
    for (k, v) in hist {
        out.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td></tr>",
            escape(k),
            v
        ));
    }
    out.push_str("</tbody></table>");
    out
}

/// Escape a `Debug`-rendered `Option<T>`, or `?` when absent.
fn dbg_opt<T: std::fmt::Debug>(o: &Option<T>) -> String {
    escape(
        &o.as_ref()
            .map(|v| format!("{v:?}"))
            .unwrap_or_else(|| "?".into()),
    )
}

fn source_str(s: &SourceRef) -> String {
    let mut out = s.locator.clone();
    if let Some(line) = s.line {
        out.push_str(&format!(":{line}"));
    }
    if let Some(inner) = &s.inner {
        out.push('!');
        out.push_str(inner);
    }
    out
}

/// Render any attribute value for display. Unlike `Fact::attr`, which only
/// returns string-typed attributes, this formats `Int`/`Float`/`Bool` too —
/// numeric attributes (e.g. spark `percent`, stored as a `Float`) would
/// otherwise render as `?` even when present.
fn attr_display(f: &Fact, key: &str, fallback: &str) -> String {
    match f.attributes.get(key) {
        Some(AttrValue::Str(s)) => s.clone(),
        Some(AttrValue::Int(i)) => i.to_string(),
        Some(AttrValue::Float(x)) => format!("{x:.2}"),
        Some(AttrValue::Bool(b)) => b.to_string(),
        None => fallback.to_string(),
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const SHELL: &str = r##"<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>InterMed Doctor Report — __TARGET__</title>
<style>
  :root{--bg:#0f1115;--panel:#171a21;--line:#2a2f3a;--fg:#e6e6e6;--muted:#8a93a6}
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg)}
  header{padding:14px 20px;background:var(--panel);border-bottom:1px solid var(--line)}
  header h1{margin:0;font-size:17px}
  header .meta{color:var(--muted);font-size:12px;margin-top:4px}
  nav{display:flex;gap:2px;padding:0 12px;background:var(--panel);border-bottom:1px solid var(--line)}
  nav button{background:none;border:0;color:var(--muted);padding:10px 16px;cursor:pointer;font-size:13px;border-bottom:2px solid transparent}
  nav button.active{color:var(--fg);border-bottom-color:#6ea8fe}
  main{padding:20px;max-width:1200px}
  section{display:none} section.active{display:block}
  h3{margin:22px 0 8px;font-size:14px;color:#b9c2d6}
  table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
  th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
  th{background:#1f242e}
  code{color:#9ecbff}
  .src{color:var(--muted);font-size:12px}
  .muted,.empty{color:var(--muted)}
  .cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px;align-items:center}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px 16px;min-width:90px;text-align:center}
  .card .num{font-size:24px;font-weight:600}
  .cards .sep{width:1px;align-self:stretch;background:var(--line);margin:0 4px}
  table.kv th{width:160px}
  .filters{margin:6px 0 10px;font-size:12px;color:var(--muted)} .filters label{margin-right:6px;cursor:pointer}
  tr.frow{cursor:pointer} tr.frow .caret{color:var(--muted)}
  tr.sev-fatal td,tr.sev-error td{border-left:3px solid #c62828}
  tr.sev-warn td{border-left:3px solid #ef6c00}
  tr.sev-note td,tr.sev-info td{border-left:3px solid #2e7d32}
  .detail td{background:#12151b;color:#cfd6e4}
  table.evidence{margin-top:6px} table.evidence th{background:#161a22}
  .heatmap{display:flex;flex-wrap:wrap;gap:6px}
  .hcell{border-radius:5px;padding:8px;min-width:120px;color:#fff;cursor:help}
  .hcell .score{font-size:18px;font-weight:700} .hcell .htarget{font-size:11px;opacity:.9;word-break:break-all}
</style></head><body>
<header><h1>InterMed Doctor Report</h1>
<div class="meta">Target <strong>__TARGET__</strong> · tool __VERSION__ · generated __GENERATED__</div></header>
<nav>
  <button class="tab active" data-t="summary">Summary</button>
  <button class="tab" data-t="findings">Findings</button>
  <button class="tab" data-t="deps">Dependencies</button>
  <button class="tab" data-t="resources">Resources</button>
  <button class="tab" data-t="mixin">Mixin</button>
  <button class="tab" data-t="security">Security</button>
  <button class="tab" data-t="facts">Facts</button>
  <button class="tab" data-t="perf">Performance</button>
</nav>
<main>
  <section id="summary" class="active">__SUMMARY__</section>
  <section id="findings">__FINDINGS__</section>
  <section id="deps">__DEPS__</section>
  <section id="resources">__RESOURCES__</section>
  <section id="mixin">__MIXIN__</section>
  <section id="security">__SECURITY__</section>
  <section id="facts">__FACTS__</section>
  <section id="perf">__PERF__</section>
</main>
<script>
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('section').forEach(s=>s.classList.remove('active'));
  b.classList.add('active'); document.getElementById(b.dataset.t).classList.add('active');
});
function tog(i){const d=document.getElementById('d'+i); if(d) d.style.display = d.style.display==='none'?'':'none';}
function applyFilters(){
  const sev=[...document.querySelectorAll('.f-sev:checked')].map(c=>c.value);
  const cat=[...document.querySelectorAll('.f-cat:checked')].map(c=>c.value);
  document.querySelectorAll('tr.frow').forEach((r,i)=>{
    const ok = sev.includes(r.dataset.sev) && cat.includes(r.dataset.cat);
    r.style.display = ok?'':'none';
    const d=document.getElementById('d'+i); if(d&&!ok) d.style.display='none';
  });
}
document.querySelectorAll('.f-sev,.f-cat').forEach(c=>c.onchange=applyFilters);
</script></body></html>
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::report::{RuleStat, assemble};
    use intermed_doctor_core::{Target, TargetKind};
    use intermed_evidence::{Category, EvidenceEdge, Finding, Relation, Severity};
    use intermed_facts::FactStore;

    fn sample_report() -> (DoctorReport, Vec<Fact>) {
        let mut store = FactStore::new();
        store
            .fact("env", intermed_facts::kind::ENVIRONMENT)
            .attr("os", "linux")
            .attr("loader", "fabric")
            .attr("mc_version", "1.20.1")
            .emit();
        let dup_fact = store
            .fact("meta", intermed_facts::kind::MOD)
            .subject("alpha")
            .emit();
        store
            .fact("mixin-analyzer", "mixin_risk_score")
            .subject("net.minecraft.Foo")
            .attr("score", 85i64)
            .attr("reasons", "overwrite; hot-path")
            .emit();

        let findings = vec![
            Finding::builder("test", "test:1")
                .severity(Severity::Error)
                .category(Category::Metadata)
                .title("Test <script>")
                .explanation("Explained")
                .evidence(EvidenceEdge::new(dup_fact, Relation::Subject, 1.0))
                .build(),
        ];
        let target = Target {
            path: "./mods".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let facts = store.all().to_vec();
        let report = assemble(
            "0.1.0-test",
            &target,
            &store,
            findings,
            vec![],
            vec![RuleStat {
                id: "test".into(),
                findings: 1,
            }],
            None,
        );
        (report, facts)
    }

    #[test]
    fn html_is_self_contained_and_escaped() {
        let (report, facts) = sample_report();
        let html = render_html_with_facts(&report, &facts);
        assert!(html.starts_with("<!DOCTYPE html>"));
        // Self-contained: no network.
        assert!(!html.contains("http://") && !html.contains("https://"));
        assert!(!html.contains("<script>Test") && !html.contains("Test <script>"));
        assert!(html.contains("&lt;script&gt;"));
        // No leftover placeholders.
        assert!(!html.contains("__FINDINGS__") && !html.contains("__SUMMARY__"));
    }

    #[test]
    fn tabs_filters_provenance_and_heatmap_present() {
        let (report, facts) = sample_report();
        let html = render_html_with_facts(&report, &facts);
        assert!(html.contains("data-t=\"findings\"")); // tabbed
        assert!(html.contains("class=\"f-sev\"")); // severity filter
        assert!(html.contains("Provenance (evidence)")); // clickable provenance
        assert!(html.contains("heatmap") && html.contains(">85<")); // mixin risk heatmap
    }

    #[test]
    fn facts_free_render_still_works() {
        let (report, _) = sample_report();
        let html = render_html(&report);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("No mixin facts"));
    }
}
