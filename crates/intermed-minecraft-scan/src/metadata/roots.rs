//! Canonical artifact inventory traversal for Layer B.

use std::path::PathBuf;

use intermed_doctor_core::{ScanSettings, Target, list_jar_archives};

pub(super) fn gather_jars(target: &Target, scan: &ScanSettings) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in target.artifact_roots() {
        if let Ok(mut jars) = list_jar_archives(&root.path, scan) {
            out.append(&mut jars);
        }
    }
    out.sort();
    out.dedup();
    out
}
