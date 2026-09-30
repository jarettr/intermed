use intermed_deps::{dependency_path, remove_impact, update_impact, why_missing};
use intermed_doctor_core::facts::{FactStore, kind};

fn package(store: &mut FactStore, id: &str, version: &str) {
    store
        .fact("test", kind::MOD)
        .subject(id)
        .attr("version", version)
        .emit();
}

fn edge(store: &mut FactStore, from: &str, to: &str, relation: &str, range: &str) {
    store
        .fact("test", kind::DEPENDENCY)
        .subject(from)
        .attr("dep", to)
        .attr("relation", relation)
        .attr("range", range)
        .attr("mandatory", true)
        .emit();
}

#[test]
fn negative_and_ordering_edges_never_become_positive_dependency_paths() {
    let mut store = FactStore::new();
    for id in ["target", "required", "breaker", "ordered"] {
        package(&mut store, id, "1.0.0");
    }
    edge(&mut store, "required", "target", "depends", ">=1");
    edge(&mut store, "breaker", "target", "breaks", "<2");
    edge(&mut store, "ordered", "target", "loadbefore", "*");

    let why = why_missing(&store, "target");
    assert_eq!(why.reasons.len(), 1);
    assert_eq!(why.reasons[0].from, "required");
    assert!(dependency_path(&store, "breaker", "target").is_none());
    assert!(dependency_path(&store, "ordered", "target").is_none());

    let removal = remove_impact(&store, "target");
    assert_eq!(removal.declared_dependents, vec!["required"]);
    let update = update_impact(&store, "target", Some("1.0.0"), "3.0.0");
    assert!(update.breaks.is_empty());
    assert!(
        update
            .now_satisfied
            .iter()
            .any(|dependency| dependency.mod_id == "breaker")
    );
}
