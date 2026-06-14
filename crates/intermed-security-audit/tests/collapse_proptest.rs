//! Property tests for per-capability signal collapse invariants.

use std::collections::{BTreeMap, BTreeSet};

use intermed_security_audit::{
    collapse_per_capability, DetectedSignal, EvidenceStrength, SecuritySignal, SignalProvenance,
};
use proptest::prelude::*;

fn signal_strategy() -> impl Strategy<Value = SecuritySignal> {
    prop_oneof![
        Just(SecuritySignal::ProcessSpawn),
        Just(SecuritySignal::Socket),
        Just(SecuritySignal::Unsafe),
        Just(SecuritySignal::NativeLibrary),
        Just(SecuritySignal::ReflectiveInvocation),
    ]
}

fn provenance_strategy() -> impl Strategy<Value = SignalProvenance> {
    prop_oneof![
        Just(SignalProvenance::Structural),
        Just(SignalProvenance::ReflectionCorroborated),
    ]
}

fn strength_strategy() -> impl Strategy<Value = EvidenceStrength> {
    prop_oneof![
        Just(EvidenceStrength::Low),
        Just(EvidenceStrength::Medium),
        Just(EvidenceStrength::High),
    ]
}

fn detection_strategy() -> impl Strategy<Value = DetectedSignal> {
    (
        signal_strategy(),
        provenance_strategy(),
        strength_strategy(),
    )
        .prop_map(|(signal, provenance, strength)| DetectedSignal {
            signal,
            provenance,
            strength,
        })
}

fn expected_collapse(input: &BTreeSet<DetectedSignal>) -> BTreeMap<SecuritySignal, DetectedSignal> {
    let mut best: BTreeMap<SecuritySignal, DetectedSignal> = BTreeMap::new();
    for d in input {
        best.entry(d.signal)
            .and_modify(|cur| {
                if d.provenance == SignalProvenance::Structural {
                    cur.provenance = SignalProvenance::Structural;
                }
                cur.strength = cur.strength.max(d.strength);
            })
            .or_insert(*d);
    }
    best
}

proptest! {
    #[test]
    fn collapse_has_at_most_one_entry_per_capability(
        detections in prop::collection::btree_set(detection_strategy(), 0..24),
    ) {
        let out = collapse_per_capability(detections);
        let signals: BTreeSet<_> = out.iter().map(|d| d.signal).collect();
        prop_assert_eq!(signals.len(), out.len());
    }

    #[test]
    fn collapse_matches_reference_semantics(
        detections in prop::collection::btree_set(detection_strategy(), 0..24),
    ) {
        let out = collapse_per_capability(detections.clone());
        let expected = expected_collapse(&detections);
        prop_assert_eq!(out.len(), expected.len());
        for got in out {
            let want = expected.get(&got.signal).expect("missing capability");
            prop_assert_eq!(got.provenance, want.provenance);
            prop_assert_eq!(got.strength, want.strength);
        }
    }

    #[test]
    fn mixed_provenance_never_downgrades_to_reflection(
        detections in prop::collection::btree_set(detection_strategy(), 2..12),
    ) {
        let out = collapse_per_capability(detections.clone());
        for got in &out {
            let inputs: Vec<_> = detections
                .iter()
                .filter(|d| d.signal == got.signal)
                .collect();
            let any_structural = inputs
                .iter()
                .any(|d| d.provenance == SignalProvenance::Structural);
            if any_structural {
                prop_assert_eq!(got.provenance, SignalProvenance::Structural);
            }
        }
    }

    #[test]
    fn structural_provenance_wins_when_any_input_is_structural(
        signal in signal_strategy(),
        strength in strength_strategy(),
    ) {
        let input = BTreeSet::from([
            DetectedSignal {
                signal,
                provenance: SignalProvenance::ReflectionCorroborated,
                strength: EvidenceStrength::High,
            },
            DetectedSignal {
                signal,
                provenance: SignalProvenance::Structural,
                strength,
            },
        ]);
        let out = collapse_per_capability(input);
        prop_assert_eq!(out.len(), 1);
        prop_assert_eq!(out[0].provenance, SignalProvenance::Structural);
        prop_assert_eq!(out[0].strength, strength.max(EvidenceStrength::High));
    }

    #[test]
    fn collapse_is_idempotent(
        detections in prop::collection::btree_set(detection_strategy(), 0..16),
    ) {
        let once = collapse_per_capability(detections.clone());
        let twice = collapse_per_capability(once.iter().copied().collect());
        prop_assert_eq!(once, twice);
    }
}
