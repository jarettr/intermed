//! Target class hierarchy index built from mod jar class files.
//!
//! Mixin targets usually live in Minecraft itself, but mod jars sometimes ship
//! named/dev class stubs or mapped copies. When present, superclass chains let
//! the analyzer detect inherited injection collisions (parent/child targets).

use std::collections::{BTreeMap, BTreeSet};

use cafebabe::{ParseOptions, parse_class_with_options};
use serde::{Deserialize, Serialize};

use crate::model::MixinHierarchyEdge;

/// Aggregated hierarchy knowledge from all jars in one scan.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HierarchyIndex {
    /// `slash/class` → immediate superclass (`None` for `java/lang/Object` roots).
    supers: BTreeMap<String, Option<String>>,
    /// `slash/class` → directly implemented interfaces.
    interfaces: BTreeMap<String, Vec<String>>,
}

impl HierarchyIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one `.class` file when magic is valid.
    pub fn ingest_class(&mut self, bytes: &[u8]) {
        if bytes.len() < 4 || bytes[..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
            return;
        }
        let mut opts = ParseOptions::default();
        opts.parse_bytecode(false);
        let Ok(class) = parse_class_with_options(bytes, &opts) else {
            return;
        };
        let this = class.this_class.to_string();
        let super_name = class
            .super_class
            .as_ref()
            .map(ToString::to_string)
            .filter(|s| s != "java/lang/Object");
        let ifaces: Vec<String> = class.interfaces.iter().map(ToString::to_string).collect();
        self.supers.insert(this.clone(), super_name);
        if !ifaces.is_empty() {
            self.interfaces.insert(this, ifaces);
        }
    }

    /// Merge another index into this one (later jars do not overwrite known edges).
    pub fn merge(&mut self, other: &Self) {
        for (k, v) in &other.supers {
            self.supers.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, v) in &other.interfaces {
            self.interfaces
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
    }

    /// Return the ancestor chain for `class_slash`, closest first (excluding self).
    pub fn ancestors(&self, class_slash: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = class_slash.to_string();
        let mut seen = BTreeSet::from([cur.clone()]);
        while let Some(super_name) = self.supers.get(&cur).and_then(|s| s.clone()) {
            if !seen.insert(super_name.clone()) {
                break;
            }
            out.push(super_name.clone());
            cur = super_name;
        }
        out
    }

    /// True when `a` and `b` share an ancestor/descendant relationship in the index.
    pub fn related(&self, a_slash: &str, b_slash: &str) -> bool {
        if a_slash == b_slash {
            return true;
        }
        let a_anc: BTreeSet<_> = self.ancestors(a_slash).into_iter().collect();
        if a_anc.contains(b_slash) {
            return true;
        }
        let b_anc: BTreeSet<_> = self.ancestors(b_slash).into_iter().collect();
        b_anc.contains(a_slash)
    }

    /// Build hierarchy fact edges for one dotted mixin target.
    pub fn edges_for_target(&self, target_dotted: &str) -> Vec<MixinHierarchyEdge> {
        let slash = target_dotted.replace('.', "/");
        if !self.supers.contains_key(&slash) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (depth, ancestor) in self.ancestors(&slash).into_iter().enumerate() {
            out.push(MixinHierarchyEdge {
                target: target_dotted.to_string(),
                ancestor: ancestor.replace('/', "."),
                depth: u8::try_from(depth.saturating_add(1)).unwrap_or(u8::MAX),
                relation: "superclass".to_string(),
            });
        }
        for iface in self.interfaces.get(&slash).into_iter().flatten() {
            out.push(MixinHierarchyEdge {
                target: target_dotted.to_string(),
                ancestor: iface.replace('/', "."),
                depth: 1,
                relation: "interface".to_string(),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn tracks_superclass_chain() {
        let child = fixtures::class_extends("example/Child", "example/Parent");
        let parent = fixtures::class_extends("example/Parent", "java/lang/Object");
        let mut index = HierarchyIndex::new();
        index.ingest_class(&child);
        index.ingest_class(&parent);
        assert!(index.related("example/Child", "example/Parent"));
        let edges = index.edges_for_target("example.Child");
        assert!(edges.iter().any(|e| e.ancestor == "example.Parent"));
    }
}
