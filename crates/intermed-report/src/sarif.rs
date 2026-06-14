//! Minimal SARIF 2.1.0 export so findings drop straight into IDEs and CI code
//! scanning. One `run`, one tool driver (`InterMed Doctor`), rules derived from
//! distinct `rule_id`s, and one result per finding.
//!
//! When the run's fact corpus is available, each finding's evidence edges are
//! resolved to their [`SourceRef`](intermed_facts::SourceRef) and emitted as
//! SARIF `physicalLocation`s (file uri + line), so a reviewer can jump straight
//! to the jar/log line that justified the finding instead of only seeing a
//! module name.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use intermed_doctor_core::DoctorReport;
use intermed_facts::{Fact, FactId};

/// SARIF export without a fact corpus: locations fall back to logical module
/// names from `affected_components`.
pub fn to_sarif(report: &DoctorReport) -> Value {
    to_sarif_with_facts(report, &[])
}

/// SARIF export that resolves evidence facts to physical source locations.
pub fn to_sarif_with_facts(report: &DoctorReport, facts: &[Fact]) -> Value {
    let by_id: BTreeMap<FactId, &Fact> = facts.iter().map(|f| (f.id, f)).collect();

    // Collect distinct rules referenced by findings.
    let mut rule_ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();

    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": *id }
            })
        })
        .collect();

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            // Physical locations from evidence facts (preferred — clickable).
            let mut locations: Vec<Value> = Vec::new();
            for edge in &f.evidence {
                if let Some(fact) = by_id.get(&edge.fact) {
                    locations.push(physical_location(fact));
                }
            }
            // Fall back to / augment with logical module names.
            for c in &f.affected_components {
                locations.push(json!({
                    "logicalLocations": [ { "name": c, "kind": "module" } ]
                }));
            }
            json!({
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level(),
                "message": { "text": format!("{}\n{}", f.title, f.explanation) },
                "properties": {
                    "findingId": f.id,
                    "category": f.category,
                    "confidence": f.confidence,
                    "tags": f.machine_tags,
                },
                "locations": locations
            })
        })
        .collect();

    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [ {
            "tool": {
                "driver": {
                    "name": "InterMed Doctor",
                    "informationUri": "https://github.com/intermed/intermed",
                    "version": report.tool_version,
                    "rules": rules
                }
            },
            "results": results,
            "properties": {
                "schema": report.schema,
                "target": report.target.path,
                "generatedAt": report.generated_at.to_rfc3339()
            }
        } ]
    })
}

/// Build a SARIF `physicalLocation` from a fact's [`SourceRef`].
fn physical_location(fact: &Fact) -> Value {
    let src = &fact.source;
    let mut region = serde_json::Map::new();
    if let Some(line) = src.line {
        region.insert("startLine".into(), json!(line));
    }
    let mut props = serde_json::Map::new();
    if let Some(inner) = &src.inner {
        // e.g. `fabric.mod.json` inside `mods/foo.jar`.
        props.insert("inner".into(), json!(inner));
    }
    props.insert("factKind".into(), json!(fact.kind));

    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": src.locator },
            "region": Value::Object(region),
            "properties": Value::Object(props)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use intermed_doctor_core::report::{assemble, RuleStat};
    use intermed_doctor_core::{Target, TargetKind};
    use intermed_evidence::{Category, EvidenceEdge, Finding, Severity};
    use intermed_facts::{kind, FactStore, SourceRef};

    #[test]
    fn evidence_facts_become_physical_locations() {
        let mut store = FactStore::new();
        let fid = store
            .fact("meta", kind::MOD)
            .subject("create")
            .source(SourceRef::inside("mods/create.jar", "fabric.mod.json"))
            .emit();
        let findings = vec![Finding::builder("missing-dependency", "missing-dependency:create")
            .severity(Severity::Error)
            .category(Category::Dependency)
            .title("Missing dependency")
            .explanation("x")
            .evidence(EvidenceEdge::subject(fid))
            .affects("create")
            .build()];
        let target = Target {
            path: "./mods".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let report = assemble("t", &target, &store, findings, vec![], vec![RuleStat {
            id: "missing-dependency".into(),
            findings: 1,
        }], None);

        let facts = store.all().to_vec();
        let sarif = to_sarif_with_facts(&report, &facts);
        let locs = &sarif["runs"][0]["results"][0]["locations"];
        // First location must be the physical one resolved from the evidence fact.
        assert_eq!(
            locs[0]["physicalLocation"]["artifactLocation"]["uri"],
            "mods/create.jar"
        );
        assert_eq!(
            locs[0]["physicalLocation"]["properties"]["inner"],
            "fabric.mod.json"
        );
    }

    #[test]
    fn without_facts_falls_back_to_logical_location() {
        let mut store = FactStore::new();
        store.fact("env", kind::ENVIRONMENT).attr("os", "linux").emit();
        let findings = vec![Finding::builder("r", "r:1")
            .severity(Severity::Warn)
            .affects("modx")
            .build()];
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let report = assemble("t", &target, &store, findings, vec![], vec![], None);
        let sarif = to_sarif(&report);
        let locs = &sarif["runs"][0]["results"][0]["locations"];
        assert_eq!(locs[0]["logicalLocations"][0]["name"], "modx");
    }
}
