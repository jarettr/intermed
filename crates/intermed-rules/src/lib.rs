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
    EvidenceCache, apply_pack_trust_contract, dedupe_by_subject, evaluate_pack,
    fact_finding_findings, group_distinct_findings, join_findings, matches_where_v1,
    matching_fact_ids,
};
pub use ir_lowering::{Lowering, rule_to_ir};
pub use merge::merge_rule_packs;
pub use model::{
    FactSource, FindingTemplate, MissingPrerequisiteBehavior, RULE_PACK_SCHEMA,
    RULE_PACK_SCHEMA_V2, RULE_PACK_SCHEMA_V3, RULE_REGISTRY_SCHEMA, RelatedEvidenceSpec,
    RuleAssessmentContract, RuleKind, RulePack, RuleSpec,
};
pub use pack::{
    RulePackCheck, check_rule_packs, default_core_pack, default_core_pack_v2, default_core_pack_v3,
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

/// Derive the typed input contract of a declarative pack from its fact sources
/// and v3 assessment declarations. Backends share this exact contract, so an
/// external engine cannot weaken coverage policy merely by changing execution
/// strategy.
pub fn requirements_for_pack(pack: &RulePack) -> intermed_doctor_core::RuleRequirements {
    use intermed_doctor_core::{Layer, RuleRequirements};
    let mut requirements = RuleRequirements::default();
    for rule in &pack.rules {
        let mut add_kind = |kind: &str| {
            requirements.required_fact_kinds.insert(kind.to_string());
            requirements.input_layers.insert(layer_for_fact_kind(kind));
        };
        for kind in &rule.input_kinds {
            add_kind(kind);
        }
        for source in [&rule.left, &rule.right, &rule.input, &rule.anchor]
            .into_iter()
            .flatten()
        {
            add_kind(&source.kind);
        }
        for kind in &rule.related_kinds {
            add_kind(kind);
        }
        if let Some(evidence) = &rule.evidence {
            add_kind(&evidence.kind);
        }
        if let Some(contract) = &rule.assessment {
            requirements
                .permitted_proof_kinds
                .insert(contract.proof_kind);
            for coverage in &contract.coverage_requirements {
                requirements.minimum_coverage.insert(*coverage);
                requirements
                    .required_regions
                    .extend(regions_for_requirement(*coverage));
            }
        }
    }
    requirements.input_layers.insert(Layer::Rules);
    requirements
}

fn layer_for_fact_kind(kind: &str) -> intermed_doctor_core::Layer {
    use intermed_doctor_core::Layer;
    use intermed_doctor_core::facts::kind::FactLayer;
    match intermed_doctor_core::facts::kind::layer(kind) {
        Some(FactLayer::TargetDetection) => Layer::TargetDetection,
        Some(FactLayer::Metadata) => Layer::Metadata,
        Some(FactLayer::Dependency) => Layer::Dependency,
        Some(FactLayer::Log) => Layer::Log,
        Some(FactLayer::Resource) => Layer::Resource,
        Some(FactLayer::Mixin) => Layer::Mixin,
        Some(FactLayer::Security) => Layer::Security,
        Some(FactLayer::Sbom) => Layer::Sbom,
        Some(FactLayer::Performance) => Layer::Performance,
        Some(FactLayer::Rules) => Layer::Rules,
        Some(FactLayer::DataSemantics) => Layer::DataSemantics,
        None => panic!("rule references unregistered fact kind `{kind}`"),
    }
}

fn regions_for_requirement(
    requirement: intermed_doctor_core::evidence::CoverageRequirement,
) -> Vec<intermed_doctor_core::TargetRegion> {
    use intermed_doctor_core::TargetRegion;
    use intermed_doctor_core::evidence::CoverageRequirement::*;
    match requirement {
        LocalArtifact | CompletePack | CompleteProviderUniverse | ActiveDescriptor => {
            vec![TargetRegion::Artifacts]
        }
        CompleteClasspath => vec![TargetRegion::MinecraftClasspath],
        RuntimeEvidence | TerminalRuntime => vec![TargetRegion::Logs],
        RuntimeProfile => vec![TargetRegion::RuntimeProfile],
        AuthoritativeLoader => vec![TargetRegion::Manifest],
        KnownBridgeSemantics => vec![TargetRegion::LoaderClasspath],
        CompatibleMappings => vec![TargetRegion::Mappings],
        ApplicableMixin => vec![TargetRegion::ModClasspath],
        CompleteResourceBlobs => vec![TargetRegion::ResourceBlobs],
        RelevantResources => vec![TargetRegion::Datapacks],
        CompleteVanillaBaseline => vec![TargetRegion::VanillaResources],
        KnownRuntimeMutators => vec![TargetRegion::Scripts, TargetRegion::ModClasspath],
    }
}

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
        let findings = DeclarativeRulePack::default_core().evaluate(&ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "duplicate-id:alpha");
    }

    #[test]
    fn aliases_from_one_archive_are_not_known_incompatible_mods() {
        let mut store = FactStore::new();
        for id in ["rubidium", "embeddium"] {
            store
                .fact("test", kind::MOD)
                .subject(id)
                .attr("file", "xenon.jar")
                .emit();
        }
        store
            .fact("test", kind::MOD_RELATIONSHIP)
            .subject("embeddium")
            .attr("related", "rubidium")
            .attr("type", "known_incompatible")
            .attr("reason", "curated")
            .attr("archive", "xenon.jar")
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
        let findings = DeclarativeRulePack::default_core()
            .evaluate(&RuleCtx::for_test(&store, &target))
            .unwrap();
        assert!(findings.iter().all(|f| f.rule_id != "known-incompatible"));
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
        let findings = MixedLoaderPackRule.evaluate(&ctx).unwrap();
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
        let findings = LoaderMismatchRule.evaluate(&ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "loader-mismatch:alpha");
    }

    #[test]
    fn fabric_artifact_is_compatible_with_quilt_runtime() {
        let mut store = FactStore::new();
        store
            .fact("env", kind::ENVIRONMENT)
            .subject("instance")
            .attr("loader", "quilt")
            .emit();
        store
            .fact("meta", kind::MOD)
            .subject("fabric-api")
            .attr("loader", "fabric")
            .attr("identity_certainty", "confirmed")
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
        let findings = LoaderMismatchRule.evaluate(&ctx).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn quilt_artifact_is_not_assumed_compatible_with_fabric_runtime() {
        let mut store = FactStore::new();
        store
            .fact("env", kind::ENVIRONMENT)
            .subject("instance")
            .attr("loader", "fabric")
            .emit();
        store
            .fact("meta", kind::MOD)
            .subject("quilt-only")
            .attr("loader", "quilt")
            .attr("identity_certainty", "confirmed")
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
        let findings = LoaderMismatchRule.evaluate(&ctx).unwrap();
        assert_eq!(findings.len(), 1);
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
        let findings = SideMismatchRule.evaluate(&ctx).unwrap();
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
        let artifact_id = format!("sha256:{}", "a".repeat(64));
        store
            .fact("sbom", kind::SBOM)
            .subject(artifact_id.clone())
            .attr("archive", "shady.jar")
            .attr("trust_score", 10_i64)
            .attr("provenance_correlation_eligible", true)
            .emit();
        store
            .fact("security", kind::USES_PROCESS_SPAWN)
            .subject("shady.jar")
            .attr("archive", "shady.jar")
            .attr("artifact_id", artifact_id.clone())
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
        let findings = DeclarativeRulePack::default_core().evaluate(&ctx).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.id == format!("low-trust-capability:{artifact_id}")),
            "findings: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn offline_v1_struct_upgrade_remains_available_but_v1_runtime_load_is_removed() {
        let mut v1 = default_core_pack_v2();
        v1.schema = RULE_PACK_SCHEMA.to_string();
        assert!(validate_rule_pack(&v1).is_err());
        let v2 = convert_v1_to_v2(v1);
        assert_eq!(v2.schema, RULE_PACK_SCHEMA_V2);
        assert!(validate_rule_pack(&v2).is_ok());
    }
}
