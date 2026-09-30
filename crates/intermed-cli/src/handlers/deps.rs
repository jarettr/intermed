use crate::*;

pub(crate) fn run_deps(args: DepsArgs) -> ExitCode {
    match args.command {
        DepsCommand::Graph(args) => {
            let target = match deps_target(&args) {
                Ok(t) => t,
                Err(code) => return code,
            };
            let store = match collect_layer_c_facts(&target) {
                Ok(s) => s,
                Err(code) => return code,
            };
            let graph = build_graph(&store);
            let payload = serde_json::json!({
                "schema": "intermed-modpack-graph-v1",
                "graph": graph,
            });
            match serde_json::to_string_pretty(&payload) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: serialize graph: {e}");
                    ExitCode::from(2)
                }
            }
        }
        DepsCommand::Resolve(args) => {
            let target = match deps_target(&args) {
                Ok(t) => t,
                Err(code) => return code,
            };
            let store = match collect_layer_c_facts(&target) {
                Ok(s) => s,
                Err(code) => return code,
            };
            match resolve_store(&store) {
                Ok(outcome) => {
                    let payload = serde_json::json!({
                        "schema": "intermed-deps-resolution-v1",
                        "outcome": outcome,
                    });
                    match serde_json::to_string_pretty(&payload) {
                        Ok(text) => {
                            println!("{text}");
                            let exit = match &outcome {
                                ResolutionOutcome::Unsatisfiable { .. } => 1,
                                _ => 0,
                            };
                            ExitCode::from(exit)
                        }
                        Err(e) => {
                            eprintln!("error: serialize resolution: {e}");
                            ExitCode::from(2)
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        DepsCommand::Why(args) => run_deps_why(args, false),
        DepsCommand::WhyMissing(args) => run_deps_why(args, true),
        DepsCommand::Implicit(args) => run_deps_implicit(args),
        DepsCommand::Path(args) => run_deps_path(args),
    }
}

/// Resolve a target from an id-bearing deps arg, collecting Layer-C facts.
fn collect_for_id(
    target_path: &std::path::Path,
    mods_dir: Option<&std::path::Path>,
) -> Result<intermed_doctor_core::facts::FactStore, ExitCode> {
    let target = detect_target_or_exit(target_path)?;
    let target = match mods_dir {
        Some(md) => Target {
            mods_dir: Some(md.to_path_buf()),
            game_root: None,
            layout: None,
            instance_type: None,
            ..target
        },
        None => target,
    };
    collect_layer_c_facts(&target)
}

fn run_deps_why(args: DepsIdArgs, missing: bool) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let report = if missing {
        intermed_deps::why_missing(&store, &args.id)
    } else {
        intermed_deps::why(&store, &args.id)
    };
    if args.json {
        emit_json("intermed-deps-why-v1", "report", &report)
    } else {
        println!("{}", report.render());
        // why-missing of an absent, required dependency is an actionable state.
        if missing && !report.present && !report.reasons.is_empty() {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}

fn run_deps_implicit(args: DepsImplicitArgs) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let refs = intermed_deps::implicit_for_namespace(&store, &args.namespace);
    if args.json {
        let payload = serde_json::json!({
            "schema": "intermed-deps-implicit-v1",
            "namespace": args.namespace,
            "references": refs,
        });
        print_json_payload(&payload)
    } else {
        if refs.is_empty() {
            println!("No implicit references to namespace `{}`.", args.namespace);
            return ExitCode::SUCCESS;
        }
        println!(
            "{} mod(s) implicitly reference namespace `{}`:",
            refs.len(),
            args.namespace
        );
        for r in &refs {
            let req = if r.required {
                "required"
            } else {
                "conditional"
            };
            println!(
                "  {} -> {} -> namespace {} ({}, {} ref(s), e.g. {}) [{}]",
                r.consumer, r.via, args.namespace, req, r.ref_count, r.sample_path, r.resolve_state
            );
        }
        ExitCode::SUCCESS
    }
}

fn run_deps_path(args: DepsPathArgs) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let chain = intermed_deps::dependency_path(&store, &args.from, &args.to);
    if args.json {
        let payload = serde_json::json!({
            "schema": "intermed-deps-path-v1",
            "from": args.from,
            "to": args.to,
            "path": chain,
        });
        print_json_payload(&payload)
    } else {
        match chain {
            Some(edges) => {
                println!("Dependency path {} -> {}:", args.from, args.to);
                for e in &edges {
                    println!("  {}", e.render());
                }
                ExitCode::SUCCESS
            }
            None => {
                println!("No dependency path from {} to {}.", args.from, args.to);
                ExitCode::SUCCESS
            }
        }
    }
}

pub(crate) fn run_impact(args: ImpactArgs) -> ExitCode {
    match args.command {
        ImpactCommand::Remove(args) => run_impact_remove(args),
        ImpactCommand::Update(args) => run_impact_update(args),
    }
}

fn run_impact_remove(args: ImpactRemoveArgs) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let impact = intermed_deps::remove_impact(&store, &args.id);
    if args.json {
        return emit_json("intermed-impact-remove-v1", "impact", &impact);
    }
    println!(
        "Removing {} ({}):",
        impact.target,
        if impact.installed {
            "installed"
        } else {
            "not an installed mod id"
        }
    );
    if impact.is_empty() {
        println!("  nothing in the pack references it.");
        return ExitCode::SUCCESS;
    }
    for (domain, count) in &impact.resources.by_domain {
        println!(
            "  - {count} {domain}(s) reference the {} namespace",
            impact.target
        );
    }
    if !impact.implicit_dependents.is_empty() {
        println!(
            "  - {} mod(s) have an implicit static dependency on {}",
            impact.implicit_dependents.len(),
            impact.target
        );
        for d in &impact.implicit_dependents {
            println!("      {} (via {})", d.mod_id, d.via);
        }
    }
    if !impact.declared_dependents.is_empty() {
        println!(
            "  - {} declared dependency/ies require {}",
            impact.declared_dependents.len(),
            impact.target
        );
        for d in &impact.declared_dependents {
            println!("      {d}");
        }
    }
    if !impact.provides.is_empty() {
        println!(
            "  - also provides (lost on removal): {}",
            impact.provides.join(", ")
        );
    }
    ExitCode::SUCCESS
}

fn run_impact_update(args: ImpactUpdateArgs) -> ExitCode {
    let store = match collect_for_id(&args.target, args.mods_dir.as_deref()) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let from = if args.from == "-" {
        None
    } else {
        Some(args.from.as_str())
    };
    let impact = intermed_deps::update_impact(&store, &args.id, from, &args.to);
    if args.json {
        return emit_json("intermed-impact-update-v1", "impact", &impact);
    }
    match &impact.from {
        Some(f) => println!("Updating {} {} -> {}:", impact.target, f, impact.to),
        None => println!("Updating {} to {}:", impact.target, impact.to),
    }
    if impact.breaks.is_empty() && impact.now_satisfied.is_empty() && impact.undecidable.is_empty()
    {
        println!(
            "  no declared dependency ranges constrain {}.",
            impact.target
        );
        return ExitCode::SUCCESS;
    }
    for b in &impact.breaks {
        let kind = if b.mandatory {
            "requires"
        } else {
            "optionally uses"
        };
        println!(
            "  BREAKS: {} {} {} {} — rejects {}",
            b.mod_id, kind, impact.target, b.range, impact.to
        );
    }
    for s in &impact.now_satisfied {
        println!(
            "  FIXED:  {} {} {} — now satisfied by {}",
            s.mod_id, impact.target, s.range, impact.to
        );
    }
    for u in &impact.undecidable {
        println!(
            "  CHECK:  {} {} {} — range could not be parsed",
            u.mod_id, impact.target, u.range
        );
    }
    if impact.breaks.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// Serialize `value` under a `{schema, <key>: value}` envelope and print it.
fn emit_json<T: serde::Serialize>(schema: &str, key: &str, value: &T) -> ExitCode {
    let payload = serde_json::json!({ "schema": schema, key: value });
    print_json_payload(&payload)
}

fn print_json_payload(payload: &serde_json::Value) -> ExitCode {
    match serde_json::to_string_pretty(payload) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: serialize: {e}");
            ExitCode::from(2)
        }
    }
}

fn deps_target(args: &intermed_cli::command::DepsTargetArgs) -> Result<Target, ExitCode> {
    let target = detect_target_or_exit(&args.target)?;
    if let Some(mods_dir) = &args.mods_dir {
        Ok(Target {
            mods_dir: Some(mods_dir.clone()),
            game_root: None,
            layout: None,
            instance_type: None,
            ..target
        })
    } else {
        Ok(target)
    }
}

fn collect_layer_c_facts(
    target: &Target,
) -> Result<intermed_doctor_core::facts::FactStore, ExitCode> {
    // The resource AST is off by default; the implicit + effective dependency
    // levels (and the reverse resource graph behind `impact`) need it parsed, so
    // raise the level to Full for these dependency-intelligence commands. We also
    // disable fact compaction (no rules run here to cite the resource facts, so the
    // default retention policy would strip `resource_reference` / implicit edges).
    let mut settings = DiagnosisSettings::default();
    settings.resource.level = intermed_doctor_core::ResourceAstLevel::Full;
    settings.facts.retention.max_facts = usize::MAX;
    let engine = DiagnosticEngine::builder()
        .settings(settings)
        .collector(EnvironmentCollector)
        .collector(MetadataCollector)
        // Layer M — resource/data semantics: needed for the implicit + effective
        // dependency levels (`implicit_dependency_edge` / `resource_reference`).
        .collector(intermed_resource_ast::collector())
        .build_checked()
        .map_err(|error| {
            eprintln!("error: invalid dependency-analysis registration: {error}");
            ExitCode::from(2)
        })?;
    let run = engine.diagnose_with_facts(target);
    Ok(intermed_doctor_core::facts::FactStore::from_snapshot(
        run.facts,
    ))
}
