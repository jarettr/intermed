//! Minimal SARIF 2.1.0 export so findings drop straight into IDEs and CI code
//! scanning. One `run`, one tool driver (`InterMed Doctor`), rules derived from
//! distinct `rule_id`s, and one result per finding.

use serde_json::{json, Value};

use intermed_doctor_core::DoctorReport;

pub fn to_sarif(report: &DoctorReport) -> Value {
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
            let locations: Vec<Value> = f
                .affected_components
                .iter()
                .map(|c| {
                    json!({
                        "logicalLocations": [ { "name": c, "kind": "module" } ]
                    })
                })
                .collect();
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
