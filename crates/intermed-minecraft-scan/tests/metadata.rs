use std::io::Write;
use std::path::Path;

use intermed_doctor_core::facts::{FactStore, kind};
use intermed_doctor_core::{
    CollectCtx, Collector, CollectorStatus, DiagnosisSettings, LayoutKind, MetadataLevel, Target,
    TargetKind, default_settings,
};
use intermed_minecraft_scan::MetadataCollector;
use zip::write::SimpleFileOptions;

#[test]
fn legacy_forge_mcmod_info_establishes_provider_identity_and_range() {
    let root = temp_dir("legacy-forge-metadata");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("CreativeCore_v1.10.71_mc1.12.2.jar"),
        &[(
            "mcmod.info",
            br#"[{"modid":"creativecore","name":"CreativeCore","version":"1.10.71","requiredMods":["Forge@[14.23.5.2847,)"]}]"#,
        )],
    );

    let facts = collect_facts(&mods);
    let provider = facts
        .iter()
        .find(|fact| fact.kind == kind::MOD && fact.subject == "creativecore")
        .expect("legacy Forge mod identity");
    assert_eq!(provider.attr("version"), Some("1.10.71"));
    assert_eq!(provider.attr("loader"), Some("forge"));
    assert_eq!(provider.attr("identity_certainty"), Some("confirmed"));
    let dependency = facts
        .iter()
        .find(|fact| fact.kind == kind::DEPENDENCY && fact.subject == "creativecore")
        .expect("legacy Forge requiredMods dependency");
    assert_eq!(dependency.attr("dep"), Some("forge"));
    assert_eq!(dependency.attr("range"), Some("[14.23.5.2847,)"));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn legacy_forge_mcmod_info_accepts_platform_encoded_display_text() {
    let root = temp_dir("legacy-forge-platform-encoding");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("legacy.jar"),
        &[(
            "mcmod.info",
            b"[{\"modid\":\"legacy\",\"name\":\"Legacy \xb4 Name\",\"version\":\"1.0\"}]",
        )],
    );

    let facts = collect_facts(&mods);
    assert!(facts.iter().any(|fact| {
        fact.kind == kind::MOD && fact.subject == "legacy" && fact.attr("version") == Some("1.0")
    }));
    assert!(!facts.iter().any(|fact| {
        fact.kind == kind::SCAN_TRUNCATED && fact.attr("layer") == Some("metadata")
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn forge_1_12_environment_selects_legacy_descriptor_for_real_collector() {
    let root = temp_dir("legacy-forge-instance-selection");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("EnhancedVisuals.jar"),
        &[
            (
                "META-INF/mods.toml",
                b"[[mods]]\nmodId=\"enhancedvisuals\"\nversion=\"1.3.0\"\n\n[[dependencies.enhancedvisuals]]\nmodId=\"creativecore\"\nmandatory=true\nversionRange=\"[2.0.0,)\"\n",
            ),
            (
                "mcmod.info",
                br#"[{"modid":"enhancedvisuals","version":"1.3","requiredMods":[]}]"#,
            ),
        ],
    );
    let target = Target {
        path: mods.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods.clone()),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    store
        .fact("environment", kind::ENVIRONMENT)
        .subject("")
        .attr("loader", "forge")
        .attr("mc_version", "1.12.2")
        .emit();
    let inputs = FactStore::from_snapshot(store.all().to_vec());
    let settings = default_settings();
    MetadataCollector.collect(&mut CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings,
    });
    let artifact = store
        .by_kind(kind::MOD)
        .find(|fact| fact.subject == "enhancedvisuals")
        .unwrap();
    assert_eq!(artifact.source.inner.as_deref(), Some("mcmod.info"));
    assert!(
        !store
            .by_kind(kind::DEPENDENCY)
            .any(|fact| fact.subject == "enhancedvisuals"
                && fact.attr("dep") == Some("creativecore"))
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn fabric_dep_space_and_range_emits_dependency_fact() {
    let root = temp_dir("fabric-deps");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"alpha","version":"1.0.0","depends":{"fabric-api":">=0.11.6 <0.12.0"}}"#,
        )],
    );

    let facts = collect_facts(&mods);
    let dep = facts
        .iter()
        .find(|f| f.kind == kind::DEPENDENCY && f.subject == "alpha")
        .expect("dependency fact");
    assert_eq!(dep.attr("range"), Some(">=0.11.6 <0.12.0"));
    assert_eq!(dep.attr("version_dialect"), Some("fabric-extended-semver"));
}

#[test]
fn normalized_game_root_plugins_are_scanned() {
    let root = temp_dir("normalized-plugin-root");
    let plugins = root.join("overrides/plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    write_jar(
        &plugins.join("vault-compat.jar"),
        &[("plugin.yml", b"name: VaultCompat\nversion: 1.0\n")],
    );
    let target = Target {
        path: root.clone(),
        kind: TargetKind::Instance,
        mods_dir: None,
        game_root: Some(root.join("overrides")),
        layout: Some(LayoutKind::CurseForgePack),
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    store
        .fact("environment", kind::ENVIRONMENT)
        .attr("loader", "paper")
        .attr("loader_source", "pack-manifest")
        .emit();
    let inputs = FactStore::from_snapshot(store.all().to_vec());
    let outcome = MetadataCollector.collect(&mut CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings: default_settings(),
    });
    assert_eq!(outcome.status, CollectorStatus::Active);
    assert!(
        store
            .by_kind(kind::PLUGIN)
            .any(|fact| fact.subject == "VaultCompat")
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn conflicting_equal_authority_environment_does_not_select_a_descriptor() {
    let root = temp_dir("conflicting-environment");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("hybrid.jar"),
        &[
            (
                "fabric.mod.json",
                br#"{"schemaVersion":1,"id":"fabric_role","version":"1.0"}"#,
            ),
            (
                "META-INF/neoforge.mods.toml",
                b"[[mods]]\nmodId=\"neoforge_role\"\nversion=\"1.0\"\n",
            ),
        ],
    );
    let target = Target {
        path: root.clone(),
        kind: TargetKind::Instance,
        mods_dir: Some(mods),
        game_root: Some(root.clone()),
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    for loader in ["fabric", "neoforge"] {
        store
            .fact("environment", kind::ENVIRONMENT)
            .attr("loader", loader)
            .attr("loader_source", "runtime-log")
            .emit();
    }
    let inputs = FactStore::from_snapshot(store.all().to_vec());
    MetadataCollector.collect(&mut CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings: default_settings(),
    });
    let artifact = store.by_kind(kind::MOD).next().expect("candidate artifact");
    assert_eq!(artifact.attr("identity_certainty"), Some("undecidable"));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn fabric_instance_dependency_override_removes_descriptor_break() {
    let root = temp_dir("fabric-dependency-override");
    let mods = root.join("mods");
    let config = root.join("config");
    std::fs::create_dir_all(&mods).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    write_jar(
        &mods.join("consumer.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"consumer","version":"1.0.0","breaks":{"provider":"<=1.0.0"}}"#,
        )],
    );
    std::fs::write(
        config.join("fabric_loader_dependencies.json"),
        br#"{"version":1,"overrides":{"consumer":{"-breaks":{"provider":"*"}}}}"#,
    )
    .unwrap();

    let target = Target {
        path: root.clone(),
        kind: TargetKind::Instance,
        mods_dir: Some(mods),
        game_root: Some(root.clone()),
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    store
        .fact("environment", kind::ENVIRONMENT)
        .subject("")
        .attr("loader", "fabric")
        .emit();
    let inputs = FactStore::from_snapshot(store.all().to_vec());
    let outcome = MetadataCollector.collect(&mut CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings: default_settings(),
    });
    assert_eq!(outcome.status, CollectorStatus::Active);
    assert!(!store.by_kind(kind::DEPENDENCY).any(|fact| {
        fact.subject == "consumer"
            && fact.attr("dep") == Some("provider")
            && fact.attr("relation") == Some("breaks")
    }));
    let capability = store
        .by_kind(kind::MOD_CAPABILITY)
        .find(|fact| {
            fact.subject == "consumer"
                && fact.attr("capability") == Some("fabric-dependency-override-applied")
        })
        .expect("override provenance fact");
    assert!(
        capability
            .source
            .locator
            .ends_with("config/fabric_loader_dependencies.json")
    );
    let checksum = store
        .by_kind(kind::CHECKSUM)
        .find(|fact| fact.attr("input_kind") == Some("instance-config"))
        .expect("override config input fingerprint");
    assert_eq!(checksum.subject, "config/fabric_loader_dependencies.json");
    assert_eq!(checksum.attr("algorithm"), Some("sha256"));
    assert_eq!(checksum.attr("hex").map(str::len), Some(64));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn malformed_fabric_dependency_override_suppresses_descriptor_dependency_truth() {
    let root = temp_dir("fabric-dependency-override-invalid");
    let mods = root.join("mods");
    let config = root.join("config");
    std::fs::create_dir_all(&mods).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    write_jar(
        &mods.join("consumer.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"consumer","version":"1.0.0","depends":{"provider":"*"}}"#,
        )],
    );
    std::fs::write(
        config.join("fabric_loader_dependencies.json"),
        br#"{"version":1,"overrides":{"consumer":{"depends":{"provider":3}}}}"#,
    )
    .unwrap();

    let target = Target {
        path: root.clone(),
        kind: TargetKind::Instance,
        mods_dir: Some(mods),
        game_root: Some(root.clone()),
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    store
        .fact("environment", kind::ENVIRONMENT)
        .subject("")
        .attr("loader", "fabric")
        .emit();
    let inputs = FactStore::from_snapshot(store.all().to_vec());
    let outcome = MetadataCollector.collect(&mut CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings: default_settings(),
    });
    assert_eq!(outcome.status, CollectorStatus::Incomplete);
    assert_eq!(store.by_kind(kind::DEPENDENCY).count(), 0);
    assert!(store.by_kind(kind::INVALID_METADATA).any(|fact| {
        fact.subject == "fabric_loader_dependencies.json"
            && fact.attr_bool("active_for_instance") == Some(true)
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn enriched_fabric_metadata_relationships_and_capabilities_emit() {
    let root = temp_dir("fabric-enriched");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("renderplus.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"renderplus","version":"v1.2",
                 "name":"Render Plus","description":"Rendering improvements",
                 "authors":[{"name":"Ada"}],"license":"MIT","environment":"client",
                 "icon":"assets/renderplus/icon.png","recommends":{"iris":"*"},
                 "entrypoints":{"client":["example.render.ClientEntrypoint"]},
                 "mixins":["renderplus.mixins.json"]}"#,
        )],
    );

    let facts = collect_facts(&mods);
    let metadata = facts
        .iter()
        .find(|f| f.kind == kind::MOD_METADATA && f.subject == "renderplus")
        .expect("mod_metadata");
    assert_eq!(metadata.attr("name"), Some("Render Plus"));
    assert_eq!(metadata.attr("authors"), Some("[\"Ada\"]"));
    assert_eq!(metadata.attr("environment"), Some("client"));
    assert_eq!(metadata.attr("version_raw"), Some("v1.2"));
    assert_eq!(metadata.attr("version_normalized"), Some("1.2.0"));
    assert!(facts.iter().any(|f| {
        f.kind == kind::MOD_RELATIONSHIP
            && f.attr("related") == Some("iris")
            && f.attr("type") == Some("recommended_together")
    }));
    assert!(facts.iter().any(|f| {
        f.kind == kind::MOD_CAPABILITY && f.attr("capability") == Some("modifies_rendering")
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn basic_metadata_level_preserves_legacy_facts_only() {
    let root = temp_dir("fabric-basic");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"alpha","version":"1.0","name":"Alpha"}"#,
        )],
    );
    let target = Target {
        path: mods.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods.clone()),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut settings = DiagnosisSettings::default();
    settings.metadata.level = MetadataLevel::Basic;
    let mut store = FactStore::new();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &FactStore::new(),
        jar_cache: None,
        settings: &settings,
    };
    MetadataCollector.collect(&mut ctx);
    assert!(store.by_kind(kind::MOD).any(|f| f.subject == "alpha"));
    assert_eq!(store.by_kind(kind::MOD_METADATA).count(), 0);
    assert_eq!(store.by_kind(kind::MOD_CAPABILITY).count(), 0);
    std::fs::remove_dir_all(root).ok();
}

/// Hand-assemble a class with one `@SubscribeEvent void onEvent(<event_desc>)` —
/// cafebabe parses structurally without verifying, so this exercises the real
/// annotation + first-parameter-type analysis (no `javac` in the environment).
fn subscribe_event_class(event_desc: &str) -> Vec<u8> {
    fn u16v(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn utf8(out: &mut Vec<u8>, s: &str) {
        out.push(1);
        u16v(out, s.len() as u16);
        out.extend_from_slice(s.as_bytes());
    }
    let method_desc = format!("({event_desc})V");
    let mut b = Vec::new();
    b.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    u16v(&mut b, 0);
    u16v(&mut b, 52);
    u16v(&mut b, 9);
    utf8(&mut b, "Events"); // #1
    b.push(7);
    u16v(&mut b, 1); // #2 Class -> #1
    utf8(&mut b, "java/lang/Object"); // #3
    b.push(7);
    u16v(&mut b, 3); // #4 Class -> #3
    utf8(&mut b, "onEvent"); // #5
    utf8(&mut b, &method_desc); // #6
    utf8(&mut b, "RuntimeVisibleAnnotations"); // #7
    utf8(&mut b, "Lnet/minecraftforge/eventbus/api/SubscribeEvent;"); // #8
    u16v(&mut b, 0x0421); // class PUBLIC|SUPER|ABSTRACT
    u16v(&mut b, 2);
    u16v(&mut b, 4);
    u16v(&mut b, 0); // interfaces
    u16v(&mut b, 0); // fields
    u16v(&mut b, 1); // methods
    u16v(&mut b, 0x0401); // method PUBLIC|ABSTRACT
    u16v(&mut b, 5);
    u16v(&mut b, 6);
    u16v(&mut b, 1); // method attributes
    u16v(&mut b, 7);
    b.extend_from_slice(&6u32.to_be_bytes());
    u16v(&mut b, 1); // num_annotations
    u16v(&mut b, 8); // annotation type
    u16v(&mut b, 0); // element pairs
    u16v(&mut b, 0); // class attributes
    b
}

/// A minimal class whose constant pool references `framework_internal` (a `Class`
/// entry) — exercises the whole-jar capability scan without needing real bytecode.
fn class_referencing(framework_internal: &str) -> Vec<u8> {
    fn u16v(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn utf8(out: &mut Vec<u8>, s: &str) {
        out.push(1);
        u16v(out, s.len() as u16);
        out.extend_from_slice(s.as_bytes());
    }
    let mut b = Vec::new();
    b.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    u16v(&mut b, 0);
    u16v(&mut b, 52);
    u16v(&mut b, 7); // cp_count
    utf8(&mut b, "Content"); // #1
    b.push(7);
    u16v(&mut b, 1); // #2 Class -> #1
    utf8(&mut b, "java/lang/Object"); // #3
    b.push(7);
    u16v(&mut b, 3); // #4 Class -> #3
    utf8(&mut b, framework_internal); // #5
    b.push(7);
    u16v(&mut b, 5); // #6 Class -> #5 (the framework reference)
    u16v(&mut b, 0x0021); // class
    u16v(&mut b, 2); // this
    u16v(&mut b, 4); // super
    u16v(&mut b, 0); // interfaces
    u16v(&mut b, 0); // fields
    u16v(&mut b, 0); // methods
    u16v(&mut b, 0); // attributes
    b
}

#[test]
fn full_level_whole_jar_scan_detects_content_and_networking_capabilities() {
    let root = temp_dir("whole-jar");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("contentmod.jar"),
        &[
            (
                "fabric.mod.json",
                br#"{"schemaVersion":1,"id":"contentmod","version":"1.0","entrypoints":{"main":["cm.Main"]}}"#,
            ),
            // Registration + networking references live in NON-entrypoint classes —
            // only a whole-jar scan finds them.
            (
                "cm/registry/Registration.class",
                class_referencing("net/minecraftforge/registries/DeferredRegister").as_slice(),
            ),
            (
                "cm/net/Packets.class",
                class_referencing("net/minecraft/network/simple/SimpleChannel").as_slice(),
            ),
        ],
    );

    let target = Target {
        path: mods.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods.clone()),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut settings = DiagnosisSettings::default();
    settings.metadata.level = MetadataLevel::Full;
    let mut store = FactStore::new();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &FactStore::new(),
        jar_cache: None,
        settings: &settings,
    };
    MetadataCollector.collect(&mut ctx);

    let caps: Vec<String> = store
        .by_kind(kind::MOD_CAPABILITY)
        .filter(|f| f.subject == "contentmod")
        .filter_map(|f| f.attr("capability").map(str::to_string))
        .collect();
    assert!(caps.contains(&"registers_content".to_string()), "{caps:?}");
    assert!(caps.contains(&"custom_networking".to_string()), "{caps:?}");
    // A content mod must NOT be classified performance-oriented.
    assert!(
        !caps.contains(&"performance_oriented".to_string()),
        "{caps:?}"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn capabilities_are_evidence_based_not_mod_name_based() {
    let root = temp_dir("cap-evidence");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    // Content mod: ships worldgen data + a mixin. has_worldgen (strong), NOT
    // performance_oriented (it ships content).
    write_jar(
        &mods.join("biomes.jar"),
        &[
            (
                "fabric.mod.json",
                br#"{"schemaVersion":1,"id":"biomesplus","version":"1.0","mixins":["biomesplus.mixins.json"]}"#,
            ),
            ("data/biomesplus/worldgen/biome/foo.json", b"{}"),
        ],
    );
    // Behavioural mod: a mixin, no content data → performance_oriented by evidence.
    // Note the id is *not* a known perf-mod name — inference must not rely on it.
    write_jar(
        &mods.join("tweaks.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"randomtweaks","version":"1.0","mixins":["randomtweaks.mixins.json"]}"#,
        )],
    );

    let facts = collect_facts(&mods);
    let caps = |mod_id: &str| -> Vec<String> {
        facts
            .iter()
            .filter(|f| f.kind == kind::MOD_CAPABILITY && f.subject == mod_id)
            .filter_map(|f| f.attr("capability").map(str::to_string))
            .collect()
    };

    let biomes = caps("biomesplus");
    assert!(biomes.contains(&"has_worldgen".to_string()), "{biomes:?}");
    assert!(
        !biomes.contains(&"performance_oriented".to_string()),
        "content mod is not perf: {biomes:?}"
    );

    let tweaks = caps("randomtweaks");
    assert!(
        tweaks.contains(&"performance_oriented".to_string()),
        "{tweaks:?}"
    );
    assert!(
        tweaks.contains(&"modifies_game_code".to_string()),
        "{tweaks:?}"
    );
    assert!(!tweaks.contains(&"has_worldgen".to_string()), "{tweaks:?}");

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn full_metadata_level_extracts_real_entrypoint_events_from_bytecode() {
    let root = temp_dir("fabric-full-entrypoint");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    // A real (parseable) class with @SubscribeEvent(TickEvent$ServerTickEvent).
    let class = subscribe_event_class("Lnet/minecraftforge/event/TickEvent$ServerTickEvent;");
    write_jar(
        &mods.join("events.jar"),
        &[
            (
                "fabric.mod.json",
                br#"{"schemaVersion":1,"id":"events","version":"1.0",
                     "entrypoints":{"main":["example.Events"]}}"#,
            ),
            ("example/Events.class", class.as_slice()),
        ],
    );
    let target = Target {
        path: mods.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods.clone()),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut settings = DiagnosisSettings::default();
    settings.metadata.level = MetadataLevel::Full;
    let mut store = FactStore::new();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &FactStore::new(),
        jar_cache: None,
        settings: &settings,
    };
    MetadataCollector.collect(&mut ctx);
    let detail = store
        .by_kind(kind::ENTRYPOINT_DETAIL)
        .next()
        .expect("entrypoint_detail");
    assert_eq!(detail.attr("entrypoint_type"), Some("event_bus_subscriber"));
    // The event is the @SubscribeEvent method's first-parameter type, parsed from
    // the descriptor — not a substring guess.
    assert_eq!(detail.attr("events"), Some("[\"ServerTickEvent\"]"));
    assert!(
        store
            .by_kind(kind::MOD_CAPABILITY)
            .any(|f| f.attr("capability") == Some("hooks_game_tick"))
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn fabric_entrypoints_and_access_widener_emit_facts() {
    let root = temp_dir("fabric-entry-aw");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[
            (
                "fabric.mod.json",
                br#"{"schemaVersion":1,"id":"alpha","version":"1.0.0",
                     "entrypoints":{"main":["alpha.Main"],"client":[{"value":"alpha.Client","adapter":"kotlin"}]},
                     "accessWidener":"alpha.accesswidener"}"#,
            ),
            (
                "alpha.accesswidener",
                b"accessWidener v2 named\naccessible field net/minecraft/class_1 field_2 I\n",
            ),
        ],
    );

    let facts = collect_facts(&mods);

    let entry_classes: Vec<&str> = facts
        .iter()
        .filter(|f| f.kind == kind::ENTRYPOINT && f.subject == "alpha")
        .filter_map(|f| f.attr("class"))
        .collect();
    assert!(entry_classes.contains(&"alpha.Main"), "{entry_classes:?}");
    assert!(entry_classes.contains(&"alpha.Client"), "{entry_classes:?}");

    let aw = facts
        .iter()
        .find(|f| f.kind == kind::ACCESS_TRANSFORM && f.subject == "alpha")
        .expect("access_transform fact");
    assert_eq!(aw.attr("mechanism"), Some("access-widener"));
    assert_eq!(aw.attr("access"), Some("accessible"));
    assert_eq!(aw.attr("target_class"), Some("net.minecraft.class_1"));
    assert_eq!(
        aw.attr("target_key"),
        Some("net.minecraft.class_1#field_2 I")
    );
}

#[test]
fn forge_mods_toml_mod_gets_entrypoint_from_mod_annotation() {
    let root = temp_dir("forge-entry");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let class = include_bytes!("fixtures/forge_mod_annotated.class");
    write_jar(
        &mods.join("testmod.jar"),
        &[
            (
                "META-INF/mods.toml",
                b"modLoader=\"javafml\"\nloaderVersion=\"[47,)\"\n[[mods]]\nmodId=\"testmod\"\nversion=\"1.0.0\"\n",
            ),
            ("com/example/TestMod.class", class),
        ],
    );

    let facts = collect_facts(&mods);
    let entry = facts
        .iter()
        .find(|f| f.kind == kind::ENTRYPOINT && f.subject == "testmod")
        .expect("entrypoint fact for testmod from @Mod scan");
    assert_eq!(entry.attr("phase"), Some("mod"));
    assert_eq!(entry.attr("class"), Some("com.example.TestMod"));
}

#[test]
fn forge_access_transformer_and_coremods_emit_facts() {
    let root = temp_dir("forge-at-coremod");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("beta.jar"),
        &[
            (
                "META-INF/mods.toml",
                br#"
modLoader="javafml"
loaderVersion="[47,)"
[[mods]]
modId="beta"
version="1.0.0"
"#,
            ),
            (
                "META-INF/accesstransformer.cfg",
                b"public net.minecraft.world.level.Level shouldUpdate()Z\n",
            ),
            (
                "META-INF/coremods.json",
                br#"{"beta_coremod":"coremods/beta.js"}"#,
            ),
        ],
    );

    let facts = collect_facts(&mods);

    let at = facts
        .iter()
        .find(|f| f.kind == kind::ACCESS_TRANSFORM && f.subject == "beta")
        .expect("access_transform fact");
    assert_eq!(at.attr("mechanism"), Some("access-transformer"));
    assert_eq!(
        at.attr("target_class"),
        Some("net.minecraft.world.level.Level")
    );

    let coremod = facts
        .iter()
        .find(|f| f.kind == kind::COREMOD && f.subject == "beta")
        .expect("coremod fact");
    assert_eq!(coremod.attr("name"), Some("beta_coremod"));
}

#[test]
fn forge_mod_side_is_not_inferred_from_dependency_side() {
    let root = temp_dir("forge-side");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("forge.jar"),
        &[(
            "META-INF/mods.toml",
            br#"
modLoader="javafml"
loaderVersion="[47,)"
[[mods]]
modId="alpha"
version="1.0.0"
[[dependencies.alpha]]
modId="minecraft"
mandatory=true
versionRange="[1.20,)"
side="CLIENT"
"#,
        )],
    );

    let facts = collect_facts(&mods);
    assert!(
        facts
            .iter()
            .any(|f| f.kind == kind::MOD && f.subject == "alpha")
    );
    assert!(!facts.iter().any(|f| f.kind == kind::MOD_SIDE));
    let dependency = facts
        .iter()
        .find(|fact| fact.kind == kind::DEPENDENCY && fact.subject == "alpha")
        .expect("Forge dependency fact");
    assert_eq!(dependency.attr("side"), Some("client"));
}

#[test]
fn json_range_array_or_is_preserved() {
    let root = temp_dir("json-or");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"alpha","version":"1.0.0","depends":{"minecraft":[">=1.20","<1.21"]}}"#,
        )],
    );

    let facts = collect_facts(&mods);
    let dep = facts
        .iter()
        .find(|f| f.kind == kind::DEPENDENCY && f.attr("dep") == Some("minecraft"))
        .unwrap();
    assert_eq!(dep.attr("range"), Some(">=1.20 || <1.21"));
}

#[test]
fn plugins_sibling_directory_is_scanned() {
    let root = temp_dir("plugins");
    let plugins = root.join("plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    write_jar(
        &plugins.join("plugin.jar"),
        &[("plugin.yml", b"name: Demo\nversion: 1\nmain: demo.Main\n")],
    );

    let target = Target {
        path: root.clone(),
        kind: TargetKind::Server,
        mods_dir: Some(root.join("mods")),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &FactStore::new(),
        jar_cache: None,
        settings: default_settings(),
    };
    MetadataCollector.collect(&mut ctx);
    assert!(store.by_kind(kind::PLUGIN).any(|f| f.subject == "Demo"));
}

#[test]
fn sanitized_paper_corpus_selects_modern_descriptor_and_keeps_legacy_role() {
    let root = temp_dir("paper-corpus");
    let plugins = root.join("plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    write_jar(
        &plugins.join("dual-plugin.jar"),
        &[
            (
                "plugin.yml",
                include_bytes!("fixtures/ecosystem/paper/plugin.yml"),
            ),
            (
                "paper-plugin.yml",
                include_bytes!("fixtures/ecosystem/paper/paper-plugin.yml"),
            ),
        ],
    );

    let facts = collect_instance_with_loader(&root, "paper");
    let plugin = facts
        .iter()
        .find(|fact| fact.kind == kind::PLUGIN)
        .expect("active Paper plugin");
    assert_eq!(plugin.subject.as_str(), "SanitizedPaperPlugin");
    assert_eq!(plugin.source.inner.as_deref(), Some("paper-plugin.yml"));
    let roles = facts
        .iter()
        .filter(|fact| fact.kind == kind::ARTIFACT_ROLE)
        .collect::<Vec<_>>();
    assert_eq!(roles.len(), 2);
    assert!(roles.iter().any(|fact| {
        fact.attr("descriptor") == Some("paper-plugin.yml")
            && fact.attr("activation") == Some("active")
    }));
    assert!(roles.iter().any(|fact| {
        fact.attr("descriptor") == Some("plugin.yml")
            && fact.attr("activation") == Some("compatible-candidate")
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn sanitized_quilt_corpus_emits_lossless_group_expressions() {
    let root = temp_dir("quilt-corpus");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("quilt.jar"),
        &[(
            "quilt.mod.json",
            include_bytes!("fixtures/ecosystem/quilt/quilt.mod.json"),
        )],
    );

    let facts = collect_instance_with_loader(&root, "quilt");
    let expressions = facts
        .iter()
        .filter(|fact| fact.kind == kind::DEPENDENCY_EXPRESSION)
        .collect::<Vec<_>>();
    assert_eq!(
        expressions.len(),
        3,
        "any, unless and environment are grouped"
    );
    assert!(expressions.iter().any(|fact| {
        fact.attr("expression")
            .is_some_and(|expression| expression.contains("\"operator\":\"any\""))
    }));
    assert!(expressions.iter().any(|fact| {
        fact.attr("expression")
            .is_some_and(|expression| expression.contains("\"unless\""))
    }));
    assert!(facts.iter().any(|fact| {
        fact.kind == kind::DEPENDENCY
            && fact.attr("dep") == Some("bounded_provider")
            && fact.attr("range") == Some(r#"{"all":[">=1.0.0","<2.0.0"]}"#)
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn sanitized_universal_corpus_records_every_role_but_activates_target_loader_only() {
    let root = temp_dir("hybrid-corpus");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("universal.jar"),
        &[
            (
                "fabric.mod.json",
                include_bytes!("fixtures/ecosystem/hybrid/fabric.mod.json"),
            ),
            (
                "META-INF/mods.toml",
                include_bytes!("fixtures/ecosystem/hybrid/META-INF/mods.toml"),
            ),
            (
                "META-INF/neoforge.mods.toml",
                include_bytes!("fixtures/ecosystem/hybrid/META-INF/neoforge.mods.toml"),
            ),
        ],
    );

    let facts = collect_instance_with_loader(&root, "forge");
    let roles = facts
        .iter()
        .filter(|fact| fact.kind == kind::ARTIFACT_ROLE)
        .collect::<Vec<_>>();
    assert_eq!(roles.len(), 3);
    assert_eq!(
        roles
            .iter()
            .filter(|fact| fact.attr("activation") == Some("active"))
            .count(),
        1
    );
    assert!(roles.iter().any(|fact| {
        fact.attr("loader") == Some("forge") && fact.attr("activation") == Some("active")
    }));
    assert!(
        !facts.iter().any(|fact| {
            fact.kind == kind::DEPENDENCY && fact.attr("dep") == Some("fabricloader")
        })
    );
    std::fs::remove_dir_all(root).ok();
}

fn collect_instance_with_loader(
    root: &Path,
    loader: &str,
) -> Vec<intermed_doctor_core::facts::Fact> {
    let target = Target {
        path: root.to_path_buf(),
        kind: TargetKind::Instance,
        mods_dir: Some(root.join("mods")),
        game_root: Some(root.to_path_buf()),
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut inputs = FactStore::new();
    inputs
        .fact("test-environment", kind::ENVIRONMENT)
        .attr("loader", loader)
        .attr("loader_source", "explicit-pack-manifest")
        .emit();
    let mut store = FactStore::new();
    MetadataCollector.collect(&mut CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings: default_settings(),
    });
    store.all().to_vec()
}

fn collect_facts(mods_dir: &Path) -> Vec<intermed_doctor_core::facts::Fact> {
    let target = Target {
        path: mods_dir.to_path_buf(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods_dir.to_path_buf()),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &FactStore::new(),
        jar_cache: None,
        settings: default_settings(),
    };
    MetadataCollector.collect(&mut ctx);
    store.all().to_vec()
}

#[test]
fn missing_mod_id_emits_invalid_metadata_not_placeholder_subject() {
    let root = temp_dir("missing-id");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("broken.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"version":"1.0.0"}"#,
        )],
    );

    let facts = collect_facts(&mods);
    // No `?` placeholder subject leaks into mod facts.
    assert!(
        !facts
            .iter()
            .any(|f| f.kind == kind::MOD && f.subject == "?"),
        "placeholder '?' must never be a mod subject"
    );
    assert!(
        facts.iter().any(|f| f.kind == "invalid_metadata"),
        "broken manifest should emit invalid_metadata"
    );
    // The synthetic mod fact is archive-scoped and flagged.
    let synthetic = facts
        .iter()
        .find(|f| f.kind == kind::MOD && f.subject.starts_with("unknown:"))
        .expect("synthetic mod fact");
    assert_eq!(synthetic.attr_bool("synthetic_id"), Some(true));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn hybrid_plugin_with_mod_manifest_records_secondary_identity() {
    let root = temp_dir("hybrid");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("viabridge.jar"),
        &[
            ("plugin.yml", b"name: ViaBridge\nversion: 1.0\nmain: x.Y\n"),
            (
                "fabric.mod.json",
                br#"{"schemaVersion":1,"id":"viabridge_fabric","version":"1.0.0"}"#,
            ),
        ],
    );

    let facts = collect_facts(&mods);
    // The plugin remains the deterministic presentation candidate, but without
    // target-loader evidence the hybrid identity is not canonical truth.
    let plugin = facts
        .iter()
        .find(|f| f.kind == kind::PLUGIN && f.subject == "ViaBridge")
        .expect("plugin candidate");
    assert_eq!(plugin.attr("identity_certainty"), Some("undecidable"));
    assert!(
        !facts
            .iter()
            .any(|f| f.kind == kind::MOD && f.subject == "viabridge_fabric")
    );
    // The second role is recorded informationally.
    let sec = facts
        .iter()
        .find(|f| f.kind == "secondary_identity")
        .expect("secondary identity recorded");
    assert_eq!(sec.attr("role"), Some("fabric"));
    assert_eq!(sec.attr("secondary_id"), Some("viabridge_fabric"));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn fabric_breaks_emits_breaks_relation() {
    let root = temp_dir("fabric-breaks");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"alpha","version":"1.0.0","breaks":{"beta":">=2.0.0"}}"#,
        )],
    );

    let facts = collect_facts(&mods);
    let dep = facts
        .iter()
        .find(|f| f.kind == kind::DEPENDENCY && f.attr("dep") == Some("beta"))
        .expect("breaks fact");
    assert_eq!(dep.attr("relation"), Some("breaks"));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn forge_multi_mod_jar_emits_two_mod_facts() {
    let root = temp_dir("forge-multi");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("multi.jar"),
        &[(
            "META-INF/mods.toml",
            br#"
modLoader="javafml"
loaderVersion="[47,)"
[[mods]]
modId="alpha"
version="1.0.0"
[[mods]]
modId="beta"
version="2.0.0"
"#,
        )],
    );

    let facts = collect_facts(&mods);
    assert!(
        facts
            .iter()
            .any(|f| f.kind == kind::MOD && f.subject == "alpha")
    );
    assert!(
        facts
            .iter()
            .any(|f| f.kind == kind::MOD && f.subject == "beta")
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn paper_plugin_yml_emits_api_version() {
    let root = temp_dir("paper-api");
    let plugins = root.join("plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    write_jar(
        &plugins.join("plugin.jar"),
        &[(
            "plugin.yml",
            b"name: Demo\nversion: 1\napi-version: '1.20'\nmain: demo.Main\n",
        )],
    );

    let target = Target {
        path: root.clone(),
        kind: TargetKind::Server,
        mods_dir: Some(root.join("mods")),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    let mut ctx = CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &FactStore::new(),
        jar_cache: None,
        settings: default_settings(),
    };
    MetadataCollector.collect(&mut ctx);
    let plugin = store
        .by_kind(kind::PLUGIN)
        .find(|f| f.subject == "Demo")
        .expect("plugin");
    assert_eq!(plugin.attr("api_version"), Some("1.20"));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn metadata_cache_records_hits_on_second_collect() {
    let root = temp_dir("metadata-cache");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"alpha","version":"1.0.0"}"#,
        )],
    );

    let cache_dir = root.join("cache");
    let cache = intermed_doctor_core::JarCache::new(true, Some(cache_dir)).unwrap();
    let target = Target {
        path: mods.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods.clone()),
        game_root: None,
        layout: None,
        instance_type: None,
        spark_report: None,
    };

    let mut store1 = FactStore::new();
    let mut ctx1 = CollectCtx {
        target: &target,
        store: &mut store1,
        inputs: &FactStore::new(),
        jar_cache: Some(&cache),
        settings: default_settings(),
    };
    MetadataCollector.collect(&mut ctx1);
    assert_eq!(cache.stats().misses, 1);

    let mut store2 = FactStore::new();
    let mut ctx2 = CollectCtx {
        target: &target,
        store: &mut store2,
        inputs: &FactStore::new(),
        jar_cache: Some(&cache),
        settings: default_settings(),
    };
    MetadataCollector.collect(&mut ctx2);
    assert!(cache.stats().hits >= 1);
    assert!(cache.stats().fast_hits >= 1);

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn neoforge_dependency_types_map_to_layer_c_semantics() {
    let root = temp_dir("neoforge-dep-types");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("create.jar"),
        &[(
            "META-INF/neoforge.mods.toml",
            br#"
modLoader="javafml"
loaderVersion="[1,)"
license="MIT"
[[mods]]
modId="create"
version="6.0.10"
[[dependencies.create]]
modId="sodium"
type="optional"
versionRange="[0.6.9,)"
[[dependencies.create]]
modId="radium"
type="incompatible"
versionRange="*"
[[dependencies.create]]
modId="flywheel"
type="required"
versionRange="[1.0,)"
[[dependencies.create]]
modId="jei"
mandatory=false
versionRange="[19,)"
"#,
        )],
    );

    let facts = collect_facts(&mods);

    let sodium = facts
        .iter()
        .find(|f| {
            f.kind == kind::DEPENDENCY && f.subject == "create" && f.attr("dep") == Some("sodium")
        })
        .expect("optional sodium dep");
    assert_eq!(sodium.attr_bool("mandatory"), Some(false));
    assert_eq!(sodium.attr("relation"), Some("recommends"));

    let radium = facts
        .iter()
        .find(|f| {
            f.kind == kind::DEPENDENCY && f.subject == "create" && f.attr("dep") == Some("radium")
        })
        .expect("incompatible radium dep");
    assert_eq!(radium.attr_bool("mandatory"), Some(false));
    assert_eq!(radium.attr("relation"), Some("breaks"));

    let flywheel = facts
        .iter()
        .find(|f| {
            f.kind == kind::DEPENDENCY && f.subject == "create" && f.attr("dep") == Some("flywheel")
        })
        .expect("required flywheel dep");
    assert_eq!(flywheel.attr_bool("mandatory"), Some(true));
    assert_eq!(flywheel.attr("relation"), Some("depends"));
    assert_eq!(flywheel.attr("version_dialect"), Some("maven-range"));

    let jei = facts
        .iter()
        .find(|f| {
            f.kind == kind::DEPENDENCY && f.subject == "create" && f.attr("dep") == Some("jei")
        })
        .expect("legacy optional jei dep");
    assert_eq!(jei.attr_bool("mandatory"), Some(false));
    assert_eq!(jei.attr("relation"), Some("suggests"));

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn neoforge_discouraged_dependency_emits_discouraged_relation() {
    let root = temp_dir("neoforge-discouraged");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[(
            "META-INF/neoforge.mods.toml",
            br#"
modLoader="javafml"
loaderVersion="[1,)"
license="MIT"
[[mods]]
modId="alpha"
version="1.0.0"
[[dependencies.alpha]]
modId="legacyopt"
type="discouraged"
versionRange="*"
"#,
        )],
    );

    let facts = collect_facts(&mods);
    let dep = facts
        .iter()
        .find(|f| {
            f.kind == kind::DEPENDENCY && f.subject == "alpha" && f.attr("dep") == Some("legacyopt")
        })
        .expect("discouraged dep");
    assert_eq!(dep.attr_bool("mandatory"), Some(false));
    assert_eq!(dep.attr("relation"), Some("discouraged"));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn neoforge_ordering_maps_to_loadbefore() {
    let root = temp_dir("neoforge-ordering");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("create.jar"),
        &[(
            "META-INF/neoforge.mods.toml",
            br#"
modLoader="javafml"
loaderVersion="[1,)"
license="MIT"
[[mods]]
modId="create"
version="6.0.10"
[[dependencies.create]]
modId="flywheel"
type="required"
ordering="BEFORE"
versionRange="[1.0,)"
"#,
        )],
    );

    let facts = collect_facts(&mods);
    let dep = facts
        .iter()
        .find(|f| {
            f.kind == kind::DEPENDENCY && f.subject == "create" && f.attr("dep") == Some("flywheel")
        })
        .expect("loadbefore flywheel");
    assert_eq!(dep.attr("relation"), Some("loadbefore"));
    assert_eq!(dep.attr_bool("mandatory"), Some(true));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn forge_mods_toml_mixins_and_access_transformers() {
    let root = temp_dir("forge-mixins-at");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[
            (
                "META-INF/mods.toml",
                br#"
modLoader="javafml"
loaderVersion="[1,)"
license="MIT"
[[mods]]
modId="alpha"
version="1.0.0"
[[mixins]]
config="alpha.mixins.json"
[[accessTransformers]]
file="META-INF/accesstransformer.cfg"
"#,
            ),
            (
                "META-INF/accesstransformer.cfg",
                b"public net.minecraft.example.Cls method",
            ),
        ],
    );

    let facts = collect_facts(&mods);
    assert!(facts.iter().any(|f| {
        f.kind == kind::MIXIN_CONFIG
            && f.subject == "alpha"
            && f.attr("config") == Some("alpha.mixins.json")
    }));
    assert!(facts.iter().any(|f| f.kind == kind::ACCESS_TRANSFORM));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn neoforge_access_transformer_basename_is_relative_to_meta_inf() {
    let root = temp_dir("neoforge-at-relative");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[
            (
                "META-INF/neoforge.mods.toml",
                br#"
modLoader="javafml"
loaderVersion="[1,)"
license="MIT"
[[mods]]
modId="alpha"
version="1.0.0"
[[accessTransformers]]
file="accesstransformer.cfg"
"#,
            ),
            (
                "META-INF/accesstransformer.cfg",
                b"public net.minecraft.example.Cls method",
            ),
        ],
    );

    let facts = collect_facts(&mods);
    assert!(facts.iter().any(|fact| {
        fact.kind == kind::ACCESS_TRANSFORM
            && fact.subject == "alpha"
            && fact.attr("target_class") == Some("net.minecraft.example.Cls")
    }));
    assert!(!facts.iter().any(|fact| {
        fact.kind == kind::SCAN_TRUNCATED
            && fact.attr("layer") == Some("metadata")
            && fact
                .attr("reason")
                .is_some_and(|reason| reason.contains("access transformer"))
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn commented_coremods_manifest_matches_modlauncher_json_dialect() {
    let root = temp_dir("forge-commented-coremods");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("alpha.jar"),
        &[
            (
                "META-INF/mods.toml",
                b"modLoader=\"javafml\"\nloaderVersion=\"[1,)\"\n[[mods]]\nmodId=\"alpha\"\nversion=\"1.0.0\"\n",
            ),
            (
                "META-INF/coremods.json",
                b"{\n  // \"disabled\": \"coremods/disabled.js\"\n}\n",
            ),
        ],
    );

    let facts = collect_facts(&mods);
    assert!(!facts.iter().any(|fact| {
        fact.kind == kind::SCAN_TRUNCATED
            && fact.attr("layer") == Some("metadata")
            && fact
                .attr("reason")
                .is_some_and(|reason| reason.contains("coremods.json"))
    }));
    assert!(!facts.iter().any(|fact| fact.kind == kind::COREMOD));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn nested_jar_registers_versioned_provider() {
    let root = temp_dir("nested-jij");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    // A library bundled (Jar-in-Jar) inside `api.jar`, carrying its own version.
    let child = build_jar(&[(
        "fabric.mod.json",
        br#"{"schemaVersion":1,"id":"renderer-api","version":"3.2.2"}"#,
    )]);
    write_jar(
        &mods.join("api.jar"),
        &[
            (
                "fabric.mod.json",
                br#"{"schemaVersion":1,"id":"api","version":"1.0.0","jars":[{"file":"META-INF/jars/renderer-api.jar"}]}"#,
            ),
            ("META-INF/jars/renderer-api.jar", &child),
        ],
    );
    // A consumer that requires the bundled lib at a version only the nested jar
    // satisfies (the parent `api` is 1.0.0, the nested lib is 3.2.2).
    write_jar(
        &mods.join("consumer.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"consumer","version":"1.0.0","depends":{"renderer-api":">=3.2.0"}}"#,
        )],
    );

    let facts = collect_facts(&mods);

    // The nesting is recorded as evidence with the nested module's own version.
    let nested = facts
        .iter()
        .find(|f| f.kind == kind::NESTED_JAR && f.attr("nested") == Some("renderer-api"))
        .expect("nested_jar fact");
    assert_eq!(nested.attr("version"), Some("3.2.2"));

    // And as a versioned provider, so the consumer's `>=3.2.0` resolves.
    let provided = facts
        .iter()
        .find(|f| f.kind == kind::PROVIDED_DEPENDENCY && f.attr("provides") == Some("renderer-api"))
        .expect("provided_dependency for bundled module");
    assert_eq!(provided.attr("version"), Some("3.2.2"));
}

#[test]
fn forge_jarjar_fabric_library_is_observed_without_becoming_a_provider_gap() {
    let root = temp_dir("forge-jarjar-fabric-library");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let child = build_jar(&[(
        "fabric.mod.json",
        br#"{"schemaVersion":1,"id":"generated_maven_library","version":"4.5.10","custom":{"fabric-loom:generated":true}}"#,
    )]);
    write_jar(
        &mods.join("forge-parent.jar"),
        &[
            (
                "META-INF/mods.toml",
                b"modLoader=\"javafml\"\nloaderVersion=\"[47,)\"\n[[mods]]\nmodId=\"forge_parent\"\nversion=\"1.0\"\n",
            ),
            (
                "META-INF/jarjar/metadata.json",
                br#"{"jars":[{"path":"META-INF/jars/library.jar"}]}"#,
            ),
            ("META-INF/jars/library.jar", &child),
        ],
    );

    let facts = collect_facts(&mods);
    let nested = facts
        .iter()
        .find(|fact| {
            fact.kind == kind::NESTED_JAR && fact.attr("nested") == Some("generated_maven_library")
        })
        .expect("classpath-only nested component");
    assert_eq!(
        nested.attr("activation"),
        Some("classpath-only-cross-loader-descriptor")
    );
    assert!(!facts.iter().any(|fact| {
        fact.kind == kind::PROVIDED_DEPENDENCY
            && fact.attr("provides") == Some("generated_maven_library")
    }));
    assert!(!facts.iter().any(|fact| {
        fact.kind == kind::SCAN_TRUNCATED && fact.attr("layer") == Some("metadata")
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn quilt_nested_jar_registers_versioned_provider() {
    let root = temp_dir("quilt-nested-jij");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let child = build_jar(&[(
        "quilt.mod.json",
        br#"{"schema_version":1,"quilt_loader":{"group":"org.example","id":"quilt-api-module","version":"4.2.0","provides":[{"id":"fabric-api-base","version":"0.4.15"}]}}"#,
    )]);
    write_jar(
        &mods.join("quilt-api.jar"),
        &[
            (
                "quilt.mod.json",
                br#"{"schema_version":1,"quilt_loader":{"group":"org.example","id":"quilt-api","version":"1.0.0","jars":["META-INF/jars/quilt-api-module.jar"]}}"#,
            ),
            ("META-INF/jars/quilt-api-module.jar", &child),
        ],
    );

    let facts = collect_facts(&mods);
    let nested = facts
        .iter()
        .find(|fact| {
            fact.kind == kind::NESTED_JAR && fact.attr("nested") == Some("quilt-api-module")
        })
        .expect("Quilt nested_jar fact");
    assert_eq!(nested.attr("version"), Some("4.2.0"));

    let provided = facts
        .iter()
        .find(|fact| {
            fact.kind == kind::PROVIDED_DEPENDENCY
                && fact.attr("provides") == Some("quilt-api-module")
        })
        .expect("Quilt nested provider");
    assert_eq!(provided.attr("version"), Some("4.2.0"));
    let alias = facts
        .iter()
        .find(|fact| {
            fact.kind == kind::PROVIDED_DEPENDENCY
                && fact.attr("provides") == Some("fabric-api-base")
        })
        .expect("versioned Quilt compatibility alias");
    assert_eq!(alias.attr("version"), Some("0.4.15"));
}

#[test]
fn quilt_target_honors_nested_jars_from_active_fabric_descriptor() {
    let root = temp_dir("quilt-fabric-nested-jij");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    let child = build_jar(&[(
        "fabric.mod.json",
        br#"{"schemaVersion":1,"id":"fabric-module","version":"1.2.3"}"#,
    )]);
    write_jar(
        &mods.join("fabric-on-quilt.jar"),
        &[
            (
                "fabric.mod.json",
                br#"{"schemaVersion":1,"id":"fabric-parent","version":"1.0.0","jars":[{"file":"META-INF/jars/module.jar"}]}"#,
            ),
            ("META-INF/jars/module.jar", &child),
        ],
    );

    let facts = collect_instance_with_loader(&root, "quilt");
    assert!(facts.iter().any(|fact| {
        fact.kind == kind::PROVIDED_DEPENDENCY
            && fact.attr("provides") == Some("fabric-module")
            && fact.attr("version") == Some("1.2.3")
    }));
    assert!(!facts.iter().any(|fact| {
        fact.kind == kind::SCAN_TRUNCATED && fact.attr("layer") == Some("metadata")
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn fabric_lenient_descriptor_keeps_nested_provider_complete() {
    let root = temp_dir("fabric-lenient-nested-jij");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let child = build_jar(&[(
        "fabric.mod.json",
        br#"{"schemaVersion":1,"id":"lenient-child","version":"2.0.0"}"#,
    )]);
    write_jar(
        &mods.join("lenient-parent.jar"),
        &[
            (
                "fabric.mod.json",
                b"{\"schemaVersion\":1,\"id\":\"lenient-parent\",\"version\":\"1.0.0\",\"description\":\"first line\nsecond line\",\"jars\":[{\"file\":\"META-INF/jars/child.jar\"}]}",
            ),
            ("META-INF/jars/child.jar", &child),
        ],
    );

    let facts = collect_facts(&mods);
    assert!(facts.iter().any(|fact| {
        fact.kind == kind::PROVIDED_DEPENDENCY
            && fact.attr("provides") == Some("lenient-child")
            && fact.attr("version") == Some("2.0.0")
    }));
    assert!(!facts.iter().any(|fact| {
        fact.kind == kind::SCAN_TRUNCATED
            && fact.attr("layer") == Some("metadata")
            && fact.subject == "lenient-parent.jar"
    }));
}

#[test]
fn missing_loader_declared_nested_jar_marks_metadata_incomplete() {
    let root = temp_dir("missing-declared-jij");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("broken-parent.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"broken_parent","version":"1.0","jars":[{"file":"libs/missing.jar"}]}"#,
        )],
    );
    let target = Target {
        path: mods.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods),
        game_root: Some(root.clone()),
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    let inputs = FactStore::new();
    let outcome = MetadataCollector.collect(&mut CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings: default_settings(),
    });
    assert_eq!(outcome.status, CollectorStatus::Incomplete);
    assert!(store.by_kind(kind::SCAN_TRUNCATED).any(|fact| {
        fact.attr("reason")
            .is_some_and(|reason| reason.contains("loader-declared nested archive is missing"))
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn missing_declared_access_widener_marks_metadata_incomplete() {
    let root = temp_dir("missing-access-widener");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();
    write_jar(
        &mods.join("broken-aw.jar"),
        &[(
            "fabric.mod.json",
            br#"{"schemaVersion":1,"id":"broken_aw","version":"1.0","accessWidener":"missing.accesswidener"}"#,
        )],
    );
    let target = Target {
        path: mods.clone(),
        kind: TargetKind::ModsDir,
        mods_dir: Some(mods),
        game_root: Some(root.clone()),
        layout: None,
        instance_type: None,
        spark_report: None,
    };
    let mut store = FactStore::new();
    let inputs = FactStore::new();
    let outcome = MetadataCollector.collect(&mut CollectCtx {
        target: &target,
        store: &mut store,
        inputs: &inputs,
        jar_cache: None,
        settings: default_settings(),
    });
    assert_eq!(outcome.status, CollectorStatus::Incomplete);
    assert!(store.by_kind(kind::SCAN_TRUNCATED).any(|fact| {
        fact.attr("reason")
            .is_some_and(|reason| reason.contains("access widener") && reason.contains("missing"))
    }));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn physically_nested_but_undeclared_mod_is_not_a_provider() {
    let root = temp_dir("detached-nested-provider");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let child = build_jar(&[(
        "META-INF/mods.toml",
        br#"modLoader="kotlinforforge"
loaderVersion="[4,)"
license="LGPL-3.0"
[[mods]]
modId="kotlinforforge"
version="4.12.0"
displayName="Kotlin for Forge"
"#,
    )]);
    write_jar(
        &mods.join("kotlinforforge-container.jar"),
        &[("META-INF/jarjar/kffmod-4.12.0.jar", &child)],
    );

    let facts = collect_facts(&mods);
    assert!(!facts.iter().any(|fact| fact.kind == kind::MOD));
    assert!(!facts.iter().any(|fact| {
        fact.kind == kind::PROVIDED_DEPENDENCY && fact.attr("provides") == Some("kotlinforforge")
    }));
    assert!(facts.iter().any(|fact| {
        fact.kind == kind::NESTED_JAR
            && fact.attr("nested_path") == Some("META-INF/jarjar/kffmod-4.12.0.jar")
            && fact.attr("activation") == Some("not-loader-declared")
    }));
    std::fs::remove_dir_all(root).ok();
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("intermed-metadata-{label}-{nanos}"))
}

fn write_jar(path: &Path, entries: &[(&str, &[u8])]) {
    std::fs::write(path, build_jar(entries)).unwrap();
}

/// Build jar (zip) bytes in memory — used to nest a jar inside another jar.
fn build_jar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(&mut buf);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in entries {
        zip.start_file(*name, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
    buf.into_inner()
}
