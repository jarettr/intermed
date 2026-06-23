//! Integration tests for effect modelling + recommendations end-to-end.

use intermed_mixin_intel::fixtures;
use intermed_mixin_intel::{MixinOperation, scan_mods_dir};

use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;

#[test]
fn scan_emits_effects_and_recommendations_for_hot_overwrite() {
    let root = temp_dir("effect-pipeline");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let alpha_class = fixtures::mixin_class(
        "alpha/mixin/RenderMixin",
        "net/minecraft/client/render/WorldRenderer",
        &["injection/Inject"],
    );
    let beta_class = fixtures::mixin_class(
        "beta/mixin/RenderMixin",
        "net/minecraft/client/render/WorldRenderer",
        &["Overwrite"],
    );
    write_mixin_jar(
        &mods.join("alpha.jar"),
        "alpha",
        "alpha.mixins.json",
        "alpha.mixin",
        &[("RenderMixin", alpha_class.as_slice())],
    );
    write_mixin_jar(
        &mods.join("beta.jar"),
        "beta",
        "beta.mixins.json",
        "beta.mixin",
        &[("RenderMixin", beta_class.as_slice())],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert!(!scan.mixin_effects.is_empty());
    assert!(
        scan.mixin_effects
            .iter()
            .any(|e| e.operation == MixinOperation::Overwrite)
    );
    assert!(
        scan.recommendations
            .iter()
            .any(|r| r.recommendation.title.contains("@Inject"))
    );
    assert_eq!(scan.high_risk_overwrites.len(), 1);
    assert!(!scan.high_risk_overwrites[0].effect_description.is_empty());
    assert!(
        !scan.high_risk_overwrites[0].site_key.is_empty(),
        "overwrite site_key must match injection point for recommendation lookup"
    );
    assert!(scan.recommendations.iter().all(|r| !r.site_key.is_empty()));

    std::fs::remove_dir_all(root).ok();
}

#[test]
fn handler_bytecode_fixture_produces_handler_effect_in_scan() {
    let root = temp_dir("handler-bytecode");
    let mods = root.join("mods");
    std::fs::create_dir_all(&mods).unwrap();

    let class = fixtures::mixin_class_with_handler_bytecode(
        "alpha/mixin/TickMixin",
        "net/minecraft/server/MinecraftServer",
    );
    write_mixin_jar(
        &mods.join("alpha.jar"),
        "alpha",
        "alpha.mixins.json",
        "alpha.mixin",
        &[("TickMixin", class.as_slice())],
    );

    let scan = scan_mods_dir(&mods).unwrap();
    assert_eq!(scan.classes.len(), 1);
    let body = &scan.classes[0].handler_bodies;
    assert!(
        body.iter()
            .any(|b| b.uses_callback_info && b.handler_local_store)
    );
    assert!(
        scan.classes[0]
            .effects
            .iter()
            .any(|e| !e.effect_description.is_empty())
    );

    std::fs::remove_dir_all(root).ok();
}

fn write_mixin_jar(
    path: &Path,
    id: &str,
    config_name: &str,
    package: &str,
    classes: &[(&str, &[u8])],
) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.start_file("fabric.mod.json", options).unwrap();
    write!(
        zip,
        r#"{{"schemaVersion":1,"id":"{id}","version":"1.0.0","mixins":["{config_name}"]}}"#
    )
    .unwrap();

    zip.start_file(config_name, options).unwrap();
    write!(
        zip,
        r#"{{"required":true,"package":"{package}","mixins":["{}"]}}"#,
        classes
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>()
            .join("\",\"")
    )
    .unwrap();

    for (class, bytes) in classes {
        let class_path = format!("{}/{}.class", package.replace('.', "/"), class);
        zip.start_file(class_path, options).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "intermed-mixin-{label}-{}-{nanos}",
        std::process::id()
    ))
}
