//! Per-capability signal collapse across a jar scan.

use std::collections::{BTreeMap, BTreeSet};

use crate::detect::{DetectedSignal, SecuritySignal, SignalProvenance};

/// Collapse jar-wide detections to one entry per capability, preferring
/// structural provenance and the strongest evidence seen when the same
/// capability appears in several classes (proven in one, only string-inferred in
/// another, corroborated in a third).
pub fn collapse_per_capability(detections: BTreeSet<DetectedSignal>) -> Vec<DetectedSignal> {
    let mut best: BTreeMap<SecuritySignal, DetectedSignal> = BTreeMap::new();
    for d in detections {
        best.entry(d.signal)
            .and_modify(|cur| {
                if d.provenance == SignalProvenance::Structural {
                    cur.provenance = SignalProvenance::Structural;
                }
                cur.strength = cur.strength.max(d.strength);
            })
            .or_insert(d);
    }
    best.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::EvidenceStrength;

    fn signal(
        signal: SecuritySignal,
        provenance: SignalProvenance,
        strength: EvidenceStrength,
    ) -> DetectedSignal {
        DetectedSignal {
            signal,
            provenance,
            strength,
        }
    }

    #[test]
    fn reflection_only_stays_reflection_corroborated() {
        let input = BTreeSet::from([signal(
            SecuritySignal::ProcessSpawn,
            SignalProvenance::ReflectionCorroborated,
            EvidenceStrength::Low,
        )]);
        let out = collapse_per_capability(input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].provenance, SignalProvenance::ReflectionCorroborated);
        assert_eq!(out[0].strength, EvidenceStrength::Low);
    }

    #[test]
    fn mixed_structural_and_reflection_prefers_structural() {
        let input = BTreeSet::from([
            signal(
                SecuritySignal::Socket,
                SignalProvenance::ReflectionCorroborated,
                EvidenceStrength::High,
            ),
            signal(
                SecuritySignal::Socket,
                SignalProvenance::Structural,
                EvidenceStrength::Low,
            ),
        ]);
        let out = collapse_per_capability(input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].provenance, SignalProvenance::Structural);
        assert_eq!(out[0].strength, EvidenceStrength::High);
    }

    #[test]
    fn structural_strength_is_max_across_classes() {
        let input = BTreeSet::from([
            signal(
                SecuritySignal::Unsafe,
                SignalProvenance::Structural,
                EvidenceStrength::Medium,
            ),
            signal(
                SecuritySignal::Unsafe,
                SignalProvenance::Structural,
                EvidenceStrength::Low,
            ),
        ]);
        let out = collapse_per_capability(input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].provenance, SignalProvenance::Structural);
        assert_eq!(out[0].strength, EvidenceStrength::Medium);
    }

    #[test]
    fn distinct_capabilities_are_all_retained() {
        let input = BTreeSet::from([
            signal(
                SecuritySignal::Socket,
                SignalProvenance::Structural,
                EvidenceStrength::Medium,
            ),
            signal(
                SecuritySignal::NativeLibrary,
                SignalProvenance::ReflectionCorroborated,
                EvidenceStrength::Low,
            ),
        ]);
        let out = collapse_per_capability(input);
        assert_eq!(out.len(), 2);
        let signals: BTreeSet<_> = out.iter().map(|d| d.signal).collect();
        assert!(signals.contains(&SecuritySignal::Socket));
        assert!(signals.contains(&SecuritySignal::NativeLibrary));
    }

    #[test]
    fn reflection_high_strength_upgrades_structural_low() {
        let input = BTreeSet::from([
            signal(
                SecuritySignal::ProcessSpawn,
                SignalProvenance::Structural,
                EvidenceStrength::Low,
            ),
            signal(
                SecuritySignal::ProcessSpawn,
                SignalProvenance::ReflectionCorroborated,
                EvidenceStrength::High,
            ),
        ]);
        let out = collapse_per_capability(input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].provenance, SignalProvenance::Structural);
        assert_eq!(out[0].strength, EvidenceStrength::High);
    }

    #[test]
    fn structural_wins_over_reflection_for_same_capability_across_classes() {
        // Class A: structural Medium. Class B: reflection-only High for the same
        // capability. Collapse must keep structural provenance with max strength.
        let input = BTreeSet::from([
            signal(
                SecuritySignal::ReflectiveInvocation,
                SignalProvenance::Structural,
                EvidenceStrength::Medium,
            ),
            signal(
                SecuritySignal::ReflectiveInvocation,
                SignalProvenance::ReflectionCorroborated,
                EvidenceStrength::High,
            ),
        ]);
        let out = collapse_per_capability(input);
        assert_eq!(out[0].provenance, SignalProvenance::Structural);
        assert_eq!(out[0].strength, EvidenceStrength::High);
    }

    #[test]
    fn mixed_capabilities_keep_independent_provenance() {
        let input = BTreeSet::from([
            signal(
                SecuritySignal::Socket,
                SignalProvenance::ReflectionCorroborated,
                EvidenceStrength::Low,
            ),
            signal(
                SecuritySignal::Unsafe,
                SignalProvenance::Structural,
                EvidenceStrength::Medium,
            ),
            signal(
                SecuritySignal::Socket,
                SignalProvenance::Structural,
                EvidenceStrength::Low,
            ),
        ]);
        let out = collapse_per_capability(input);
        assert_eq!(out.len(), 2);
        let socket = out
            .iter()
            .find(|d| d.signal == SecuritySignal::Socket)
            .unwrap();
        let unsafe_sig = out
            .iter()
            .find(|d| d.signal == SecuritySignal::Unsafe)
            .unwrap();
        assert_eq!(socket.provenance, SignalProvenance::Structural);
        assert_eq!(unsafe_sig.provenance, SignalProvenance::Structural);
        assert_eq!(unsafe_sig.strength, EvidenceStrength::Medium);
    }

    #[test]
    fn order_independence_for_mixed_provenance() {
        let a = BTreeSet::from([
            signal(
                SecuritySignal::ProcessSpawn,
                SignalProvenance::ReflectionCorroborated,
                EvidenceStrength::Medium,
            ),
            signal(
                SecuritySignal::ProcessSpawn,
                SignalProvenance::Structural,
                EvidenceStrength::Low,
            ),
        ]);
        let b = BTreeSet::from([
            signal(
                SecuritySignal::ProcessSpawn,
                SignalProvenance::Structural,
                EvidenceStrength::Low,
            ),
            signal(
                SecuritySignal::ProcessSpawn,
                SignalProvenance::ReflectionCorroborated,
                EvidenceStrength::Medium,
            ),
        ]);
        assert_eq!(collapse_per_capability(a), collapse_per_capability(b));
    }
}
