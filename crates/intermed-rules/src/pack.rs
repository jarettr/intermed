//! Rule-pack loading, embedded core pack, and marketplace helpers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use intermed_doctor_core::facts::kind;

use crate::RulePackError;
use crate::convert::upgrade_pack_to_v2;
use crate::model::{FindingTemplate, RULE_PACK_SCHEMA, RuleKind, RulePack, RuleSpec};
use crate::validate::validate_rule_pack;

/// Embedded v2 core pack (single source of truth for Layer-J declarative rules).
const EMBEDDED_CORE_V2: &str = include_str!("../../../rules/core/intermed-core.rules.v2.json");

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

/// Parse and validate a rule pack from JSON/YAML text.
pub fn parse_rule_pack(text: &str, path_label: &str) -> Result<RulePack, RulePackError> {
    let pack: RulePack = if path_label.ends_with(".json") {
        serde_json::from_str(text).map_err(|e| RulePackError(format!("parse {path_label}: {e}")))?
    } else {
        serde_yaml::from_str(text).map_err(|e| RulePackError(format!("parse {path_label}: {e}")))?
    };
    validate_rule_pack(&pack)?;
    Ok(pack)
}

pub fn load_rule_pack(path: &Path) -> Result<RulePack, RulePackError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| RulePackError(format!("read {}: {e}", path.display())))?;
    let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("json");
    parse_rule_pack(&text, ext)
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
    if !matches!(
        path.extension().and_then(|x| x.to_str()),
        Some("json" | "yaml" | "yml")
    ) {
        return false;
    }
    // Non-pack JSON under rules/: registry indexes, JSON Schema, etc.
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name == "community-registry.json"
            || name.ends_with("-registry.json")
            || name.ends_with(".schema.json")
        {
            return false;
        }
    }
    if let Ok(text) = std::fs::read_to_string(path) {
        if text.contains("\"intermed-rule-registry-v1\"") {
            return false;
        }
    }
    true
}

/// Legacy v1 core pack (tests and backward compatibility).
#[must_use]
pub fn default_core_pack() -> RulePack {
    let mut pack = default_core_pack_v2();
    pack.schema = RULE_PACK_SCHEMA.to_string();
    pack.version.clear();
    pack.publisher = None;
    pack.signature = None;
    pack
}

/// Core pack without mixin overlap/overwrite rules (Layer F owns those in imperative mode).
#[must_use]
pub fn default_core_pack_without_mixin() -> RulePack {
    let mut pack = default_core_pack_v2();
    pack.rules.retain(|r| {
        !r.id.starts_with("mixin-")
            && !r
                .input_kinds
                .iter()
                .any(|k| k == kind::MIXIN_OVERLAP || k == kind::HIGH_RISK_OVERWRITE)
    });
    pack
}

/// Current core pack: embedded JSON + log-signal rules derived from [`intermed_log`].
#[must_use]
pub fn default_core_pack_v2() -> RulePack {
    let mut pack = parse_rule_pack(EMBEDDED_CORE_V2, "embedded-core-v2.json")
        .expect("embedded core rule pack is valid");
    pack.rules.extend(log_signal_rules());
    pack
}

fn log_signal_rules() -> Vec<RuleSpec> {
    use intermed_log::signal::{self};
    use intermed_log::{signal_severity, signal_title};

    let specs = [
        signal::MIXIN_APPLY_ERROR,
        signal::CLASS_NOT_FOUND,
        signal::NO_CLASS_DEF_FOUND,
        signal::MOD_LOADING_FAILURE,
        signal::MISSING_DEPENDENCY,
        signal::OUT_OF_MEMORY,
        signal::STACK_OVERFLOW,
        signal::JVM_CRASH,
        signal::PORT_IN_USE,
        signal::DATAPACK_VALIDATION_ERROR,
        signal::REGISTRY_FREEZE_ERROR,
    ];
    specs
        .into_iter()
        .map(|sig| {
            let severity = match signal_severity(sig) {
                intermed_doctor_core::evidence::Severity::Fatal => "fatal",
                intermed_doctor_core::evidence::Severity::Error => "error",
                intermed_doctor_core::evidence::Severity::Warn => "warn",
                intermed_doctor_core::evidence::Severity::Note => "note",
                intermed_doctor_core::evidence::Severity::Info => "info",
            };
            let mut where_all = BTreeMap::new();
            where_all.insert("subject".to_string(), sig.to_string());
            RuleSpec {
                id: format!("log-{sig}"),
                alias: None,
                kind: RuleKind::FactFinding,
                input_kinds: vec![kind::LOG_SIGNAL.to_string()],
                where_all,
                where_not: BTreeMap::new(),
                group_by: None,
                group_by_fields: Vec::new(),
                distinct: None,
                min_count: 1,
                left: None,
                right: None,
                on: None,
                r#where: None,
                having: None,
                input: None,
                anchor: None,
                related_kinds: Vec::new(),
                match_on: None,
                settings_refs: BTreeMap::new(),
                evidence: None,
                finding: FindingTemplate {
                    id: "log:{subject}:{attr:line}".to_string(),
                    rule_id: None,
                    severity: severity.to_string(),
                    category: "log".to_string(),
                    title: signal_title(sig).to_string(),
                    explanation: "Detected at line {attr:line}: {attr:excerpt}".to_string(),
                    fix: None,
                    tags: vec!["log".to_string(), sig.to_string()],
                    affects: Vec::new(),
                },
            }
        })
        .collect()
}

/// Normalize any pack to v2 schema (no-op for v2 packs).
pub fn normalize_pack(mut pack: RulePack) -> RulePack {
    upgrade_pack_to_v2(&mut pack);
    pack
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RULE_PACK_SCHEMA_V2;

    #[test]
    fn malformed_packs_error_without_panicking() {
        // Untrusted marketplace rulepacks: garbage input must produce a clean
        // `Err`, never a panic.
        let nasty = [
            "",
            "{",
            "}",
            "[]",
            "null",
            "true",
            "{\"schema\":1}",
            "{\"schema\":\"intermed-rule-pack-v2\"}", // no rules
            "{\"schema\":\"intermed-rule-pack-v2\",\"id\":\"x\",\"rules\":\"notarray\"}",
            "\u{0}\u{0}\u{0}",
            "not json at all",
            "{\"rules\":[{}]}",
            "{\"schema\":\"intermed-rule-pack-v2\",\"id\":\"x\",\"version\":\"1\",\"publisher\":\"p\",\"rules\":[{\"id\":\"r\",\"kind\":\"join\"}]}",
        ];
        for input in nasty {
            // Both extensions exercise the JSON and YAML paths; never unwinds.
            let _ = parse_rule_pack(input, "x.json");
            let _ = parse_rule_pack(input, "x.yaml");
        }
    }

    #[test]
    fn embedded_v2_pack_is_valid() {
        let pack = default_core_pack_v2();
        assert_eq!(pack.schema, RULE_PACK_SCHEMA_V2);
        validate_rule_pack(&pack).expect("valid");
        assert!(pack.rules.iter().any(|r| r.id == "loader-mismatch"));
        assert!(pack.rules.iter().any(|r| r.kind == RuleKind::Join));
    }

    #[test]
    fn check_skips_registry_index_files() {
        let dir = std::env::temp_dir().join(format!(
            "intermed-rules-check-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("community-registry.json"),
            r#"{"schema":"intermed-rule-registry-v1","packs":[]}"#,
        )
        .unwrap();
        let check = check_rule_packs(&dir);
        assert!(check.is_ok(), "{:?}", check.errors);
        std::fs::remove_dir_all(dir).ok();
    }
}
