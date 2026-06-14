//! v1 → v2 rule-pack upgrade for backward compatibility.

use crate::model::{RulePack, RULE_PACK_SCHEMA, RULE_PACK_SCHEMA_V2};

/// Upgrade a v1 pack to v2 schema in place (idempotent for v2 packs).
pub fn upgrade_pack_to_v2(pack: &mut RulePack) {
    if pack.schema == RULE_PACK_SCHEMA {
        pack.schema = RULE_PACK_SCHEMA_V2.to_string();
    }
    if pack.version.is_empty() {
        pack.version = env!("CARGO_PKG_VERSION").to_string();
    }
    if pack.publisher.is_none() {
        pack.publisher = Some("intermed".to_string());
    }
}

/// Return an owned v2 copy of `pack`.
#[must_use]
pub fn convert_v1_to_v2(pack: RulePack) -> RulePack {
    let mut out = pack;
    upgrade_pack_to_v2(&mut out);
    out
}