//! Finding template rendering and enum parsing shared by all backends.

use std::collections::BTreeMap;

use intermed_doctor_core::evidence::{Category, Severity};

use crate::model::FindingTemplate;

/// Variable bindings for template substitution (`{key}` tokens).
pub type VarMap = BTreeMap<String, String>;

/// Substitute `{key}` placeholders in `template` using `vars`.
pub fn render_template(template: &str, vars: &VarMap) -> String {
    let mut out = template.to_string();
    for (key, value) in vars {
        out = out.replace(&format!("{{{key}}}"), value);
    }
    out
}

/// Parse a wire-format severity string into [`Severity`].
pub fn parse_severity(s: &str) -> Option<Severity> {
    Some(match s {
        "info" => Severity::Info,
        "note" => Severity::Note,
        "warn" | "warning" => Severity::Warn,
        "error" => Severity::Error,
        "fatal" => Severity::Fatal,
        _ => return None,
    })
}

/// Parse a wire-format category string into [`Category`].
pub fn parse_category(s: &str) -> Option<Category> {
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

/// Default confidence for a finding category.
pub fn default_confidence(category: Category) -> f32 {
    if category == Category::Mixin {
        0.7
    } else {
        0.9
    }
}

/// Expand a [`FindingTemplate`] into wire strings (id, title, explanation, fix, tags).
pub fn render_finding_fields(
    template: &FindingTemplate,
    vars: &VarMap,
) -> (String, String, String, Option<String>, Vec<String>) {
    let fix = template.fix.as_ref().map(|f| render_template(f, vars));
    let tags = template
        .tags
        .iter()
        .map(|t| render_template(t, vars))
        .collect();
    (
        render_template(&template.id, vars),
        render_template(&template.title, vars),
        render_template(&template.explanation, vars),
        fix,
        tags,
    )
}