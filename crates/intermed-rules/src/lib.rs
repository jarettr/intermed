//! # intermed-rules
//!
//! Layer J declarative rule packs — single source of truth for detection logic
//! shared across the interpreter, DuckDB SQL, and Soufflé Datalog backends.
//!
//! * [`DeclarativeRulePack`] — evaluates [`RulePack`] rules in-process.
//! * [`sql_codegen`] / [`datalog_codegen`] — generate backend artifacts from the pack.
//! * Imperative wrappers ([`DuplicateIdRule`], …) delegate to the same pack.

mod columnar;
mod convert;
mod declarative;
mod distribution;
mod expr;
mod generate;
mod imperative;
mod interpreter;
mod ir_lowering;
mod join_plan;
mod merge;
mod model;
mod pack;
mod signing;
mod souffle;
mod sql_codegen;
mod template;
mod trace;
mod tsv;
mod validate;

pub use columnar::ColumnarRulePack;
pub use convert::{convert_v1_to_v2, upgrade_pack_to_v2};
pub use declarative::{DatalogRulePack, DeclarativeRulePack};
pub use distribution::{
    PackTrust, ResolvedRulePacks, RulePackSelection, install_pack_with_dependencies,
    list_installed_pack_paths, load_effective_registry, merged_default_registry,
    resolve_doctor_packs,
};
pub use generate::{
    GenerateBackend, explain_plans, generate_rule_datalog_list, generate_rule_sql, generate_rules,
};
pub use imperative::{
    DuplicateIdRule, LoaderMismatchRule, MixedLoaderPackRule, SideMismatchRule, default_rules,
};
pub use interpreter::{
    EvidenceCache, dedupe_by_subject, evaluate_pack, fact_finding_findings,
    group_distinct_findings, join_findings, matches_where_v1, matching_fact_ids,
};
pub use ir_lowering::{Lowering, rule_to_ir};
pub use merge::merge_rule_packs;
pub use model::{
    FactSource, FindingTemplate, RULE_PACK_SCHEMA, RULE_PACK_SCHEMA_V2, RULE_REGISTRY_SCHEMA,
    RelatedEvidenceSpec, RuleKind, RulePack, RuleSpec,
};
pub use pack::{
    RulePackCheck, check_rule_packs, default_core_pack, default_core_pack_v2,
    default_core_pack_without_mixin, load_rule_pack, normalize_pack, parse_rule_pack,
};
pub use signing::{
    PackOrigin, PublisherInfo, RegistryPackEntry, RulePackSignature, RuleRegistry,
    SIGNATURE_ALGORITHM, SigningError, TrustLevel, TrustPolicy, canonical_digest, default_registry,
    default_rule_pack_install_dir, fetch_pack_for_entry, fetch_url_limited,
    install_pack_from_registry, load_registry_from_source, load_signing_key, load_trusted_keys,
    registry_to_json, sign_rule_pack, sign_rule_pack_now, trusted_keys_for_publisher,
    trusted_keys_from_registry, verify_rule_pack_signature, verify_rule_pack_trust,
};
pub use souffle::{SouffleRulePack, souffle_available, souffle_program};
pub use sql_codegen::{
    ANALYTICS_VIEW_DDL, HOT_PATH_EXPR, generate_analytics_bundle, prepare_analytics_views,
    prepare_sql,
};
pub use template::{parse_category, parse_severity, render_template};
pub use trace::{RuleTraceLine, format_trace, trace_pack};
pub use tsv::{escape_souffle_symbol, escape_tsv_field};
pub use validate::validate_rule_pack;

/// Validation / load failure.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct RulePackError(String);

impl RulePackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[cfg(test)]
mod logic_tests {
    use super::*;
    use intermed_doctor_core::facts::{FactStore, SourceRef, kind};
    use intermed_doctor_core::{Rule, RuleCtx, Target, TargetKind};

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
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = DeclarativeRulePack::default_core().evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "duplicate-id:alpha");
    }

    #[test]
    fn mixed_loader_pack_fires_in_bare_mods_dir() {
        let mut store = FactStore::new();
        store
            .fact("meta", kind::ENVIRONMENT)
            .subject("env")
            .attr("os", "linux")
            .emit();
        store
            .fact("meta", kind::MOD)
            .subject("lithium")
            .attr("loader", "fabric")
            .emit();
        store
            .fact("meta", kind::MOD)
            .subject("jei")
            .attr("loader", "forge")
            .emit();
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = MixedLoaderPackRule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "mixed-loader-pack:mods-dir");
    }

    #[test]
    fn loader_mismatch_join_rule_fires() {
        let mut store = FactStore::new();
        store
            .fact("env", kind::ENVIRONMENT)
            .subject("instance")
            .attr("loader", "fabric")
            .emit();
        store
            .fact("meta", kind::MOD)
            .subject("alpha")
            .attr("loader", "forge")
            .emit();
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = LoaderMismatchRule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "loader-mismatch:alpha");
    }

    #[test]
    fn validates_schema_and_rule_shape() {
        let pack = default_core_pack();
        validate_rule_pack(&pack).expect("v1 valid");

        let mut bad = pack;
        bad.rules[0].min_count = 1;
        assert!(validate_rule_pack(&bad).is_err());
    }

    #[test]
    fn side_mismatch_warns_for_client_mod_on_server() {
        let mut store = FactStore::new();
        store
            .fact("env", kind::ENVIRONMENT)
            .subject("instance")
            .attr("side", "server")
            .emit();
        store
            .fact("meta", kind::MOD_SIDE)
            .subject("sodium")
            .attr("side", "client")
            .source(SourceRef::file("sodium.jar"))
            .emit();
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = SideMismatchRule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("client-only on a server"));
    }

    #[test]
    fn generated_souffle_program_declares_real_relations() {
        // The generic IR-driven program declares the flat fact relations and emits
        // an output relation per lowerable FactFinding rule.
        let program = souffle_program();
        assert!(program.contains(".decl fact(id:number, kind:symbol, subject:symbol)"));
        assert!(program.contains(".decl fact_attr(id:number, key:symbol, val:symbol)"));
        assert!(program.contains(".input fact"));
        // At least one rule clause selecting matching ids.
        assert!(program.contains(":- fact(id,"));
        assert!(program.contains(".output r"));
    }

    #[test]
    fn sbom_security_correlation_flags_low_trust() {
        let mut store = FactStore::new();
        store
            .fact("sbom", kind::SBOM)
            .subject("shady.jar")
            .attr("trust_score", 10_i64)
            .emit();
        store
            .fact("security", kind::USES_PROCESS_SPAWN)
            .subject("shady.jar")
            .attr("archive", "shady.jar")
            .emit();
        let target = Target {
            path: ".".into(),
            kind: TargetKind::ModsDir,
            mods_dir: None,
            game_root: None,
            layout: None,
            instance_type: None,
            spark_report: None,
        };
        let ctx = RuleCtx::for_test(&store, &target);
        let findings = DeclarativeRulePack::default_core().evaluate(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.id == "low-trust-capability:shady.jar"),
            "findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn v1_pack_upgrades_to_v2() {
        let v1 = default_core_pack();
        assert_eq!(v1.schema, RULE_PACK_SCHEMA);
        let v2 = convert_v1_to_v2(v1);
        assert_eq!(v2.schema, RULE_PACK_SCHEMA_V2);
    }
}
