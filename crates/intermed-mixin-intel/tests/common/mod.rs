//! Shared jar builders for integration tests.

use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;

pub fn write_mixin_jar(
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

pub fn temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "intermed-mixin-{label}-{}-{nanos}",
        std::process::id()
    ))
}
