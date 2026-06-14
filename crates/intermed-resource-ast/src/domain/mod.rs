//! Domain layer: classify a resource path, then lower its syntax tree into a
//! typed domain AST + compact [`ResourceSummary`].
//!
//! Each domain parser returns a [`DomainParse`]; [`parse_resource`] is the single
//! entry point that classifies, parses at the active [`ResourceLevel`], computes
//! the order-independent semantic hash, and assembles the [`CachedResourceAst`].

pub mod atlas;
pub mod blockstate;
pub mod classify;
pub mod lang;
pub mod loot_table;
pub mod model;
pub mod pack_mcmeta;
pub mod recipe;
pub mod tag;

use sha2::{Digest, Sha256};

use crate::model::{
    CachedResourceAst, ParseStatus, ResourceDomain, ResourceLevel, ResourceParseDiagnostic,
    ResourceReference, ResourceSummary,
};

/// Schema tag for the cached resource-AST payload (cache-invalidating).
pub const RESOURCE_AST_CACHE_SCHEMA: &str = "intermed-resource-ast-cache-v1";

/// Uniform output of a single domain parser.
pub struct DomainParse {
    pub summary: ResourceSummary,
    pub references: Vec<ResourceReference>,
    pub diagnostics: Vec<ResourceParseDiagnostic>,
    pub status: ParseStatus,
}

impl DomainParse {
    /// An empty, generic, skipped parse (domain not parsed at this level).
    pub fn skipped() -> Self {
        Self {
            summary: ResourceSummary::Generic,
            references: Vec::new(),
            diagnostics: Vec::new(),
            status: ParseStatus::Skipped,
        }
    }

    /// A parse that failed (malformed for its domain).
    pub fn invalid(diagnostics: Vec<ResourceParseDiagnostic>) -> Self {
        Self {
            summary: ResourceSummary::Generic,
            references: Vec::new(),
            diagnostics,
            status: ParseStatus::Invalid,
        }
    }
}

/// Combined parser version string for the active level — every domain's version
/// folded together so a change to any parser invalidates the cache.
#[must_use]
pub fn parser_version() -> String {
    format!(
        "{}+{}+{}+{}+{}+{}+{}+{}",
        tag::TAG_AST_VERSION,
        recipe::RECIPE_AST_VERSION,
        lang::LANG_AST_VERSION,
        pack_mcmeta::PACK_MCMETA_AST_VERSION,
        model::MODEL_AST_VERSION,
        blockstate::BLOCKSTATE_AST_VERSION,
        loot_table::LOOT_TABLE_AST_VERSION,
        atlas::ATLAS_AST_VERSION,
    )
}

/// Parse one resource into its cached AST summary. Never panics on bad input —
/// malformed resources become `ParseStatus::Invalid` with a diagnostic.
#[must_use]
pub fn parse_resource(path: &str, bytes: &[u8], level: ResourceLevel) -> CachedResourceAst {
    let domain = classify::classify(path);
    let parse = if domain.parsed_at(level) {
        parse_domain(domain, path, bytes)
    } else {
        DomainParse::skipped()
    };
    let semantic_hash = hash_summary(&parse.summary);
    CachedResourceAst {
        schema: RESOURCE_AST_CACHE_SCHEMA.to_string(),
        parser_version: parser_version(),
        resource_path: path.to_string(),
        domain,
        parse_status: parse.status,
        semantic_hash,
        summary: parse.summary,
        references: parse.references,
        diagnostics: parse.diagnostics,
    }
}

fn parse_domain(domain: ResourceDomain, path: &str, bytes: &[u8]) -> DomainParse {
    // Lang has a non-JSON `.lang` variant; everything else is JSON-rooted.
    if domain == ResourceDomain::Lang && path.ends_with(".lang") {
        return lang::parse_properties(bytes);
    }
    let value = match crate::syntax::json::parse(bytes) {
        Ok(v) => v,
        Err(e) => {
            return DomainParse::invalid(vec![ResourceParseDiagnostic {
                severity: crate::model::DiagnosticSeverity::Error,
                message: format!("invalid JSON: {e}"),
            }]);
        }
    };
    match domain {
        ResourceDomain::Tag => tag::parse(path, &value),
        ResourceDomain::Recipe => recipe::parse(&value),
        ResourceDomain::Lang => lang::parse_json(&value),
        ResourceDomain::PackMcmeta => pack_mcmeta::parse(&value),
        ResourceDomain::Model => model::parse(&value),
        ResourceDomain::Blockstate => blockstate::parse(&value),
        ResourceDomain::LootTable => loot_table::parse(&value),
        ResourceDomain::Atlas => atlas::parse(&value),
        _ => DomainParse::skipped(),
    }
}

/// Order-independent content hash of a summary: serialise to canonical JSON (maps
/// are sorted by serde_json) and SHA-256. Two writers that differ only in key
/// order produce the same hash — the basis for safe-merge equality and diffs.
fn hash_summary(summary: &ResourceSummary) -> String {
    let json = serde_json::to_vec(summary).unwrap_or_default();
    let digest = Sha256::digest(&json);
    format!("{digest:x}")
}
