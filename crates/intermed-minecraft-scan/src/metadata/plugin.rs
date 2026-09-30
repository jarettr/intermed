//! Bukkit, Spigot and Paper plugin descriptor parsing.

use intermed_doctor_core::Loader;

use super::{
    Artifact, BytecodeSignals, DataSignals, Dep, Entrypoint, ParseErr, load_order_static,
    split_people,
};

pub(super) fn parse_plugin_yml(
    text: &str,
    loader: Loader,
    manifest_name: &'static str,
) -> Result<Artifact, ParseErr> {
    let value: serde_yaml::Value = serde_yaml::from_str(text)
        .map_err(|error| ParseErr::descriptor(manifest_name, error.to_string()))?;
    let id = value
        .get("name")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("?")
        .to_string();
    let version = yaml_scalar(value.get("version")).unwrap_or_else(|| "0".to_string());
    let api_version = yaml_scalar(value.get("api-version"));
    let load_order = value
        .get("load")
        .and_then(serde_yaml::Value::as_str)
        .and_then(load_order_static);
    let mut deps = Vec::new();
    for (key, mandatory, relation) in [
        ("depend", true, "depends"),
        ("softdepend", false, "suggests"),
        // Ordering only applies when the named plugin is installed; it is not
        // a provider requirement.
        ("loadbefore", false, "loadbefore"),
    ] {
        if let Some(entries) = value.get(key).and_then(serde_yaml::Value::as_sequence) {
            for entry in entries {
                if let Some(id) = entry.as_str() {
                    deps.push(Dep {
                        id: id.to_string(),
                        range: "*".into(),
                        mandatory,
                        relation,
                        feature: None,
                        lifecycle: None,
                        ordering: None,
                        join_classpath: None,
                        condition: None,
                        side: None,
                    });
                }
            }
        }
    }
    if let Some(paper_deps) = value.get("dependencies") {
        push_paper_plugin_deps(&mut deps, paper_deps);
    }
    Ok(Artifact {
        id,
        version,
        loader,
        side: Some("server"),
        deps,
        dependency_expressions: Vec::new(),
        provides: yaml_string_list(value.get("provides")),
        provided_versions: Default::default(),
        is_plugin: true,
        manifest_name,
        api_version,
        load_order,
        bundled: Vec::new(),
        entrypoints: yaml_scalar(value.get("main"))
            .map(|class| {
                vec![Entrypoint {
                    phase: "main".to_string(),
                    class,
                    entrypoint_type: "main".to_string(),
                    events: Vec::new(),
                    priority: 0,
                }]
            })
            .unwrap_or_default(),
        access_widener_files: Vec::new(),
        access_transforms: Vec::new(),
        coremods: Vec::new(),
        mixin_configs: Vec::new(),
        name: yaml_scalar(value.get("name")),
        description: yaml_scalar(value.get("description")),
        authors: yaml_people(value.get("authors").or_else(|| value.get("author"))),
        license: yaml_scalar(value.get("license")),
        icon: None,
        update_json: yaml_scalar(value.get("website")),
        data_signals: DataSignals::default(),
        bytecode: BytecodeSignals::default(),
        secondary: None,
        package_roots: Vec::new(),
    })
}

fn push_paper_plugin_deps(deps: &mut Vec<Dep>, root: &serde_yaml::Value) {
    for lifecycle in ["bootstrap", "server"] {
        let Some(entries) = root.get(lifecycle).and_then(serde_yaml::Value::as_mapping) else {
            continue;
        };
        for (name, options) in entries {
            let Some(id) = name.as_str() else { continue };
            let required = options
                .get("required")
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(true);
            let ordering = options
                .get("load")
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_ascii_lowercase);
            let join_classpath = options
                .get("join-classpath")
                .and_then(serde_yaml::Value::as_bool)
                .unwrap_or(true);
            deps.push(Dep {
                id: id.to_string(),
                range: "*".into(),
                mandatory: required,
                relation: if required { "depends" } else { "suggests" },
                feature: None,
                lifecycle: Some(lifecycle.to_string()),
                ordering,
                join_classpath: Some(join_classpath),
                condition: None,
                side: None,
            });
        }
    }
}

fn yaml_string_list(value: Option<&serde_yaml::Value>) -> Vec<String> {
    match value {
        Some(serde_yaml::Value::String(value)) => vec![value.clone()],
        Some(serde_yaml::Value::Sequence(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// YAML versions are often unquoted numbers; coerce them to strings.
fn yaml_scalar(value: Option<&serde_yaml::Value>) -> Option<String> {
    match value? {
        serde_yaml::Value::String(value) => Some(value.clone()),
        serde_yaml::Value::Number(value) => Some(value.to_string()),
        serde_yaml::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn yaml_people(value: Option<&serde_yaml::Value>) -> Vec<String> {
    match value {
        Some(serde_yaml::Value::String(value)) => split_people(value),
        Some(serde_yaml::Value::Sequence(values)) => values
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}
