//! Mixin → capability (Layer B) and security-surface (Layer G) bridge.
//!
//! A mod's mixin *targets* are the most honest statement of what it actually
//! touches — far better than its metadata. A jar that calls itself a "tweak" but
//! `@Overwrite`s `WorldRenderer` is a rendering mod; one woven into
//! `ServerPlayNetworkHandler` touches the network packet path. This module
//! classifies a mixin target class into a [`Subsystem`], which yields (a) a
//! behaviour-grounded **capability** (so Layer-B consumers — the perf correlator,
//! the risk explainer — see bytecode-true reach) and (b) a **security sensitivity**
//! flag when the subsystem is one where woven code is a real audit concern
//! (networking, class loading, (de)serialization, save IO).

use serde::{Deserialize, Serialize};

use crate::site::ApplicationSite;

/// A Minecraft engine subsystem a mixin can hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Subsystem {
    Rendering,
    WorldGen,
    Networking,
    Entity,
    Lighting,
    Chunk,
    ServerTick,
    WorldEvents,
    Gui,
    Audio,
    Persistence,
    ClassLoading,
    Serialization,
}

impl Subsystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Subsystem::Rendering => "rendering",
            Subsystem::WorldGen => "worldgen",
            Subsystem::Networking => "networking",
            Subsystem::Entity => "entity",
            Subsystem::Lighting => "lighting",
            Subsystem::Chunk => "chunk",
            Subsystem::ServerTick => "server-tick",
            Subsystem::WorldEvents => "world-events",
            Subsystem::Gui => "gui",
            Subsystem::Audio => "audio",
            Subsystem::Persistence => "persistence",
            Subsystem::ClassLoading => "class-loading",
            Subsystem::Serialization => "serialization",
        }
    }

    /// The Layer-B capability string this subsystem implies (reuses the existing
    /// capability vocabulary where one exists, e.g. `modifies_rendering`).
    pub fn capability(self) -> &'static str {
        match self {
            Subsystem::Rendering => "modifies_rendering",
            Subsystem::WorldGen => "modifies_worldgen",
            Subsystem::Networking => "modifies_networking",
            Subsystem::Entity => "modifies_entities",
            Subsystem::Lighting => "modifies_lighting",
            Subsystem::Chunk => "modifies_chunk_io",
            Subsystem::ServerTick => "hooks_game_tick",
            Subsystem::WorldEvents => "hooks_world_events",
            Subsystem::Gui => "modifies_gui",
            Subsystem::Audio => "modifies_audio",
            Subsystem::Persistence => "modifies_persistence",
            Subsystem::ClassLoading => "modifies_class_loading",
            Subsystem::Serialization => "modifies_serialization",
        }
    }

    /// When woven code in this subsystem is a security-audit concern, the reason;
    /// `None` for performance/behaviour-only subsystems.
    pub fn security_concern(self) -> Option<&'static str> {
        match self {
            Subsystem::Networking => Some("weaves into network packet / connection handling"),
            Subsystem::ClassLoading => Some("weaves into class loading / bytecode transformation"),
            Subsystem::Serialization => Some("weaves into (de)serialization / NBT / codecs"),
            Subsystem::Persistence => Some("weaves into world save / file IO"),
            _ => None,
        }
    }
}

/// Classify a mixin target class into a [`Subsystem`]. Matches the simple class name
/// (yarn/mojmap, substring-tolerant) and a curated set of 1.20.1 intermediary
/// (`class_NNNN`) names for the highest-value vanilla classes.
pub fn classify_subsystem(target_class: &str) -> Option<Subsystem> {
    let simple = target_class
        .rsplit(['.', '/'])
        .next()
        .unwrap_or(target_class);

    // Curated 1.20.1 intermediary classes (vanilla targets are usually intermediary).
    if let Some(s) = match simple {
        "class_1132" => Some(Subsystem::ServerTick), // MinecraftServer
        "class_3218" | "class_1937" => Some(Subsystem::WorldEvents), // ServerWorld / World
        "class_2535" | "class_3244" | "class_634" | "class_2547" | "class_8610" => {
            Some(Subsystem::Networking) // ClientConnection / Server+Client PlayNetworkHandler / packet listeners
        }
        "class_761" | "class_757" | "class_4587" | "class_287" => Some(Subsystem::Rendering), // WorldRenderer / GameRenderer / MatrixStack / BufferBuilder
        "class_1297" | "class_1309" | "class_1308" => Some(Subsystem::Entity), // Entity / LivingEntity / MobEntity
        "class_2818" | "class_3215" | "class_3193" => Some(Subsystem::Chunk), // WorldChunk / ServerChunkManager / ThreadedAnvilChunkStorage
        "class_2794" | "class_3754" => Some(Subsystem::WorldGen), // ChunkGenerator / NoiseChunkGenerator
        "class_3568" => Some(Subsystem::Lighting),                // LightingProvider
        "class_437" | "class_332" => Some(Subsystem::Gui),        // Screen / DrawContext
        "class_1144" | "class_4224" => Some(Subsystem::Audio),    // SoundManager / SoundSystem
        _ => None,
    } {
        return Some(s);
    }

    // Named / mojmap substring match (works for mod-targeting mixins and dev jars).
    let l = simple.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));

    if has(&[
        "classloader",
        "knotclassloader",
        "transformer",
        "classdefiner",
    ]) {
        Some(Subsystem::ClassLoading)
    } else if has(&[
        "packet",
        "networkhandler",
        "clientconnection",
        "serverconnection",
        "channelhandler",
    ]) {
        Some(Subsystem::Networking)
    } else if has(&[
        "nbtio",
        "codec",
        "datafixer",
        "serializ",
        "deserializ",
        "jsonhelper",
        "streamcodec",
    ]) {
        Some(Subsystem::Serialization)
    } else if has(&[
        "regionfile",
        "levelstorage",
        "sessionlock",
        "worldsavehandler",
        "anvil",
        "chunkstorage",
        "savehandler",
    ]) {
        Some(Subsystem::Persistence)
    } else if has(&[
        "worldrenderer",
        "gamerenderer",
        "rendersystem",
        "bufferbuilder",
        "renderlayer",
    ]) || (l.ends_with("renderer") && !l.contains("data"))
    {
        Some(Subsystem::Rendering)
    } else if has(&[
        "chunkgenerator",
        "noisechunk",
        "surfacebuilder",
        "structurefeature",
        "biomesource",
    ]) {
        Some(Subsystem::WorldGen)
    } else if has(&["lightingprovider", "lightprovider", "chunklightprovider"]) {
        Some(Subsystem::Lighting)
    } else if has(&["chunkmanager", "chunkstorage", "serverchunk", "worldchunk"]) {
        Some(Subsystem::Chunk)
    } else if has(&["minecraftserver", "serverlifecycle"]) {
        Some(Subsystem::ServerTick)
    } else if has(&["serverworld", "serverlevel", "worldevents"]) {
        Some(Subsystem::WorldEvents)
    } else if has(&["screen", "drawcontext", "guigraphics", "hud", "widget"]) {
        Some(Subsystem::Gui)
    } else if has(&["soundmanager", "soundsystem", "soundengine"]) {
        Some(Subsystem::Audio)
    } else if has(&["livingentity", "mobentity"]) || l == "entity" {
        Some(Subsystem::Entity)
    } else {
        None
    }
}

/// A behaviour-grounded capability a mod earns by weaving a mixin (Layer F → B).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinCapability {
    pub mod_id: String,
    pub capability: String,
    pub subsystem: Subsystem,
    /// Human-readable justification (the strongest hooking site).
    pub reason: String,
    /// 0–100: how strongly the evidence supports the capability.
    pub confidence: u8,
}

/// A security-sensitive subsystem a mixin weaves into (Layer F → G).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MixinSecuritySurface {
    pub mod_id: String,
    pub mixin_class: String,
    pub site_id: String,
    pub target_class: String,
    pub subsystem: Subsystem,
    pub operation: String,
    pub reason: String,
    pub confidence: u8,
}

/// How strongly an operation asserts the capability / surface (a replacement is a
/// stronger statement of intent than an observing inject).
fn operation_weight(operation: &str) -> u8 {
    match operation {
        "overwrite" => 95,
        "redirect" | "wrap-operation" => 90,
        "modify-return-value" | "modify-arg" | "modify-args" | "modify-variable" => 80,
        "inject" => 70,
        _ => 65,
    }
}

/// Derive per-mod capabilities and security surfaces from the application sites.
pub fn derive_subsystems(
    sites: &[ApplicationSite],
) -> (Vec<MixinCapability>, Vec<MixinSecuritySurface>) {
    use std::collections::BTreeMap;

    // Best (mod, subsystem) capability evidence, keeping the strongest site.
    let mut caps: BTreeMap<(String, Subsystem), (u8, String)> = BTreeMap::new();
    let mut surfaces = Vec::new();

    for s in sites {
        let Some(subsystem) = classify_subsystem(&s.target_class) else {
            continue;
        };
        let weight = operation_weight(&s.operation).min(if s.confidence < 60 { 85 } else { 100 });
        let reason = format!(
            "mixin `{}` ({}) on `{}`",
            s.mixin_class, s.operation, s.target_class
        );
        caps.entry((s.mod_id.clone(), subsystem))
            .and_modify(|(w, r)| {
                if weight > *w {
                    *w = weight;
                    *r = reason.clone();
                }
            })
            .or_insert((weight, reason.clone()));

        if let Some(concern) = subsystem.security_concern() {
            surfaces.push(MixinSecuritySurface {
                mod_id: s.mod_id.clone(),
                mixin_class: s.mixin_class.clone(),
                site_id: s.site_id.clone(),
                target_class: s.target_class.clone(),
                subsystem,
                operation: s.operation.clone(),
                reason: concern.to_string(),
                confidence: weight,
            });
        }
    }

    let capabilities = caps
        .into_iter()
        .map(
            |((mod_id, subsystem), (confidence, reason))| MixinCapability {
                mod_id,
                capability: subsystem.capability().to_string(),
                subsystem,
                reason,
                confidence,
            },
        )
        .collect();

    surfaces.sort_by(|a, b| a.site_id.cmp(&b.site_id));
    (capabilities, surfaces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::{NameSource, ResolvedName};
    use crate::refmap::Namespace;

    fn site(mod_id: &str, target_class: &str, operation: &str) -> ApplicationSite {
        ApplicationSite {
            site_id: format!("{mod_id}::M::h->{target_class}#m@HEAD"),
            mod_id: mod_id.into(),
            archive: format!("{mod_id}.jar"),
            config_path: "m.json".into(),
            mixin_class: format!("{mod_id}.M"),
            handler_method: "h".into(),
            handler_descriptor: String::new(),
            operation: operation.into(),
            target_class: target_class.into(),
            target_method: "m()V".into(),
            at_target: "HEAD".into(),
            at_detail: "HEAD".into(),
            site_key: "m()V@HEAD".into(),
            namespace: Namespace::Intermediary,
            target_name: ResolvedName {
                original: "m".into(),
                canonical: "m()V".into(),
                namespace_original: Namespace::Intermediary,
                namespace_canonical: Namespace::Intermediary,
                source: NameSource::IntermediaryDirect,
                confidence: 100,
                reason: String::new(),
            },
            target_resolution: crate::target_res::TargetResolution::Unchecked,
            selector_verification: crate::selector::SelectorVerification::Unchecked,
            signature_check: crate::signature::SignatureCheck::Unchecked,
            local_capture_status: crate::locals::LocalCaptureStatus::NoLocalCapture,
            side: crate::model::Side::Both,
            activation: crate::model::ActivationStatus::ActiveAssumed,
            priority: 1000,
            require: None,
            expect: None,
            allow: None,
            cancellable: false,
            confidence: 100,
            imprecision_reasons: Vec::new(),
        }
    }

    #[test]
    fn classifies_named_and_intermediary() {
        assert_eq!(
            classify_subsystem("net.minecraft.client.render.WorldRenderer"),
            Some(Subsystem::Rendering)
        );
        assert_eq!(
            classify_subsystem("net/minecraft/class_3244"),
            Some(Subsystem::Networking)
        );
        assert_eq!(
            classify_subsystem("net.minecraft.network.ClientConnection"),
            Some(Subsystem::Networking)
        );
        assert_eq!(classify_subsystem("net.minecraft.util.math.BlockPos"), None);
    }

    #[test]
    fn networking_is_security_sensitive_rendering_is_not() {
        assert!(Subsystem::Networking.security_concern().is_some());
        assert!(Subsystem::ClassLoading.security_concern().is_some());
        assert!(Subsystem::Rendering.security_concern().is_none());
    }

    #[test]
    fn derives_capability_and_security_surface() {
        let (caps, surfaces) = derive_subsystems(&[
            site(
                "rendermod",
                "net.minecraft.client.render.WorldRenderer",
                "redirect",
            ),
            site("netmod", "net.minecraft.network.ClientConnection", "inject"),
        ]);
        assert!(
            caps.iter()
                .any(|c| c.mod_id == "rendermod" && c.capability == "modifies_rendering")
        );
        assert!(
            caps.iter()
                .any(|c| c.mod_id == "netmod" && c.capability == "modifies_networking")
        );
        // Only the networking hook produces a security surface.
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].subsystem, Subsystem::Networking);
    }

    #[test]
    fn overwrite_outweighs_inject_for_capability() {
        let (caps, _) = derive_subsystems(&[
            site("m", "net.minecraft.client.render.WorldRenderer", "inject"),
            site("m", "net.minecraft.client.render.GameRenderer", "overwrite"),
        ]);
        let c = caps.iter().find(|c| c.mod_id == "m").unwrap();
        assert_eq!(c.confidence, 95); // overwrite weight wins
    }
}
