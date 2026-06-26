//! SPDX and CycloneDX SBOM export from [`SbomScan`] records.

use serde::Serialize;

use crate::{JarSbomRecord, SbomScan};

/// Supported external SBOM wire formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomExportFormat {
    SpdxJson,
    CycloneDxJson,
}

/// Export a scan result in the requested format.
pub fn export_scan(scan: &SbomScan, format: SbomExportFormat) -> Result<String, String> {
    match format {
        SbomExportFormat::SpdxJson => spdx_json(scan),
        SbomExportFormat::CycloneDxJson => cyclonedx_json(scan),
    }
}

fn spdx_json(scan: &SbomScan) -> Result<String, String> {
    let packages: Vec<SpdxPackage> = scan.records.iter().map(spdx_package_from_record).collect();
    let doc = SpdxDocument {
        spdx_version: "SPDX-2.3",
        data_license: "CC0-1.0",
        spdx_id: "SPDXRef-DOCUMENT",
        name: format!("intermed-sbom:{}", scan.target),
        document_namespace: format!(
            "https://intermed.local/sbom/{}",
            scan.target.replace('/', "-")
        ),
        creation_info: SpdxCreationInfo {
            // SPDX 2.x requires UTC, seconds precision, no fractional part.
            created: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            creators: vec![format!("Tool: intermed-{}", env!("CARGO_PKG_VERSION"))],
        },
        packages,
    };
    serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct SpdxDocument<'a> {
    #[serde(rename = "spdxVersion")]
    spdx_version: &'a str,
    #[serde(rename = "dataLicense")]
    data_license: &'a str,
    #[serde(rename = "SPDXID")]
    spdx_id: &'a str,
    name: String,
    #[serde(rename = "documentNamespace")]
    document_namespace: String,
    // Required by the SPDX 2.x schema; conformant validators reject a document
    // without it.
    #[serde(rename = "creationInfo")]
    creation_info: SpdxCreationInfo,
    packages: Vec<SpdxPackage>,
}

#[derive(Serialize)]
struct SpdxCreationInfo {
    created: String,
    creators: Vec<String>,
}

#[derive(Serialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "versionInfo")]
    version_info: String,
    #[serde(rename = "downloadLocation")]
    download_location: String,
    #[serde(rename = "filesAnalyzed")]
    files_analyzed: bool,
    #[serde(rename = "checksums")]
    checksums: Vec<SpdxChecksum>,
    #[serde(rename = "externalRefs")]
    external_refs: Vec<SpdxExternalRef>,
}

#[derive(Serialize)]
struct SpdxChecksum {
    #[serde(rename = "algorithm")]
    algorithm: String,
    #[serde(rename = "checksumValue")]
    checksum_value: String,
}

#[derive(Serialize)]
struct SpdxExternalRef {
    #[serde(rename = "referenceCategory")]
    reference_category: String,
    #[serde(rename = "referenceType")]
    reference_type: String,
    #[serde(rename = "referenceLocator")]
    reference_locator: String,
}

fn spdx_package_from_record(r: &JarSbomRecord) -> SpdxPackage {
    let name = r.mod_id.clone().unwrap_or_else(|| r.archive.clone());
    let version = r.version.clone().unwrap_or_else(|| "UNKNOWN".into());
    let purl = purl_for_record(r);
    SpdxPackage {
        spdx_id: format!("SPDXRef-Package-{}", sanitize_id(&r.archive)),
        name,
        version_info: version,
        download_location: "NOASSERTION".into(),
        files_analyzed: false,
        checksums: vec![SpdxChecksum {
            algorithm: "SHA256".into(),
            checksum_value: r.sha256.clone(),
        }],
        external_refs: vec![SpdxExternalRef {
            reference_category: "PACKAGE-MANAGER".into(),
            reference_type: "purl".into(),
            reference_locator: purl,
        }],
    }
}

fn cyclonedx_json(scan: &SbomScan) -> Result<String, String> {
    let components: Vec<CycloneComponent> = scan
        .records
        .iter()
        .map(cyclone_component_from_record)
        .collect();
    let doc = CycloneDocument {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        version: 1,
        metadata: CycloneMetadata {
            component: CycloneComponent {
                typ: "application".into(),
                name: scan.target.clone(),
                version: None,
                purl: None,
                hashes: Vec::new(),
            },
        },
        components,
    };
    serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct CycloneDocument {
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    version: u8,
    metadata: CycloneMetadata,
    components: Vec<CycloneComponent>,
}

#[derive(Serialize)]
struct CycloneMetadata {
    component: CycloneComponent,
}

#[derive(Serialize)]
struct CycloneComponent {
    #[serde(rename = "type")]
    typ: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<CycloneHash>,
}

#[derive(Serialize)]
struct CycloneHash {
    alg: String,
    content: String,
}

fn cyclone_component_from_record(r: &JarSbomRecord) -> CycloneComponent {
    CycloneComponent {
        typ: "library".into(),
        name: r.mod_id.clone().unwrap_or_else(|| r.archive.clone()),
        version: r.version.clone(),
        purl: Some(purl_for_record(r)),
        hashes: vec![CycloneHash {
            alg: "SHA-256".into(),
            content: r.sha256.clone(),
        }],
    }
}

fn purl_for_record(r: &JarSbomRecord) -> String {
    let loader = r.loader.as_deref().unwrap_or("generic");
    let name = r.mod_id.as_deref().unwrap_or(&r.archive);
    let version = r.version.as_deref().unwrap_or("unknown");
    format!("pkg:{loader}/{name}@{version}?archive={}", r.archive)
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceClass;

    fn sample_scan() -> SbomScan {
        SbomScan {
            target: "./mods".into(),
            records: vec![JarSbomRecord {
                archive: "sodium.jar".into(),
                mod_id: Some("sodium".into()),
                version: Some("0.5.3".into()),
                loader: Some("fabric".into()),
                sha256: "abc".repeat(8),
                signed: false,
                signature_strength: crate::SignatureStrength::Unsigned,
                platform: None,
                in_corpus_lock: false,
                trust_score: 80,
                source_class: SourceClass::Identified,
            }],
            failures: Vec::new(),
        }
    }

    #[test]
    fn spdx_and_cyclonedx_export() {
        let scan = sample_scan();
        let spdx = export_scan(&scan, SbomExportFormat::SpdxJson).expect("spdx");
        assert!(spdx.contains("SPDX-2.3"));
        assert!(spdx.contains("sodium"));
        let cdx = export_scan(&scan, SbomExportFormat::CycloneDxJson).expect("cdx");
        assert!(cdx.contains("CycloneDX"));
        assert!(cdx.contains("sodium"));
    }

    #[test]
    fn spdx_package_keys_are_spec_camel_case() {
        // SPDX 2.3 JSON uses camelCase property names; snake_case keys are
        // dropped by conformant consumers (e.g. the version would be lost).
        let spdx = export_scan(&sample_scan(), SbomExportFormat::SpdxJson).expect("spdx");
        let doc: serde_json::Value = serde_json::from_str(&spdx).unwrap();
        let pkg = &doc["packages"][0];
        assert_eq!(pkg["versionInfo"], "0.5.3");
        assert!(pkg.get("filesAnalyzed").is_some());
        assert!(pkg.get("version_info").is_none(), "leaked snake_case key");
        assert!(pkg.get("files_analyzed").is_none(), "leaked snake_case key");
    }

    #[test]
    fn spdx_document_has_required_creation_info() {
        // SPDX 2.x marks creationInfo (with created + creators) as required.
        let spdx = export_scan(&sample_scan(), SbomExportFormat::SpdxJson).expect("spdx");
        let doc: serde_json::Value = serde_json::from_str(&spdx).unwrap();
        let ci = &doc["creationInfo"];
        assert!(ci["created"].as_str().unwrap().ends_with('Z'));
        assert!(
            ci["creators"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c.as_str().unwrap().starts_with("Tool: intermed-"))
        );
    }
}
