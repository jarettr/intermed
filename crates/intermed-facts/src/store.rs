use super::*;

/// A fact under construction. Obtained from [`FactStore::fact`] or a
/// write-only [`FactWrite`] capability; the id is
/// assigned on [`FactBuilder::emit`].
#[must_use = "call .emit() to record the fact"]
pub struct FactBuilder<'s> {
    store: &'s mut FactStore,
    kind: InternedString,
    subject: InternedString,
    attributes: Attributes,
    source: SourceRef,
    confidence: f32,
    extractor: InternedString,
}

impl<'s> FactBuilder<'s> {
    pub fn subject(mut self, subject: impl Into<InternedString>) -> Self {
        self.subject = self.store.intern_arc(subject.into());
        self
    }
    pub fn attr(mut self, key: &str, value: impl Into<AttrValue>) -> Self {
        let key = self.store.intern_str(key);
        self.attributes.insert(key, value.into());
        self
    }
    pub fn source(mut self, source: SourceRef) -> Self {
        self.source = source;
        self
    }
    pub fn confidence(mut self, c: f32) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }
    /// Record the fact and return its assigned id.
    pub fn emit(self) -> FactId {
        let id = FactId(self.store.next_id);
        self.store.next_id += 1;
        let idx = self.store.facts.len();
        let kind = self.kind;
        let extractor = self.extractor;
        let attributes = self.attributes;
        let source = SourceRef {
            locator: self.store.intern_arc(self.source.locator),
            line: self.source.line,
            // Inner archive paths are normally high-cardinality resource/class
            // names. Keeping them owned avoids pinning every discarded path in
            // the interner after post-rule compaction.
            inner: self.source.inner,
        };
        self.store.facts.push(Fact {
            id,
            kind: kind.clone(),
            subject: self.subject,
            attributes,
            source,
            confidence: self.confidence,
            extractor,
        });
        self.store
            .kind_index
            .entry(kind.clone())
            .or_default()
            .push(idx);
        self.store
            .subject_index
            .entry(self.store.facts[idx].subject.clone())
            .or_default()
            .push(idx);
        let id_slot = id.0 as usize;
        if self.store.id_index.len() <= id_slot {
            self.store.id_index.resize(id_slot + 1, None);
        }
        self.store.id_index[id_slot] = Some(idx);
        *self.store.emitted_stats.entry(kind).or_insert(0) += 1;
        self.store.maybe_compact_live();
        id
    }
}

/// Write-only capability handed to collectors.
///
/// Keeping this interface separate from [`FactStore`] makes the architectural
/// boundary enforceable: collectors can append observations, but cannot query
/// facts emitted by an earlier collector and thereby acquire a hidden ordering
/// dependency. Rules receive the read-only [`FactStore`] after collection.
pub trait FactWrite {
    fn fact<'a>(&'a mut self, extractor: &str, kind: &str) -> FactBuilder<'a>;
}

/// Read-only fact capability used by collectors that explicitly consume facts
/// produced by an earlier collector.  Keeping this separate from [`FactStore`]
/// lets the engine expose a filtered, zero-copy view instead of cloning every
/// consumed fact into a temporary store.
pub trait FactRead {
    fn by_kind<'a>(&'a self, kind: &'a str) -> Box<dyn Iterator<Item = &'a Fact> + 'a>;

    fn get(&self, id: FactId) -> Option<&Fact>;
}

/// A predicate-filtered view over an existing store.  Facts remain owned by the
/// canonical store; the view only gates which declared predicates are visible.
pub struct FilteredFactView<'a> {
    store: &'a FactStore,
    allowed: &'a BTreeSet<String>,
}

impl<'a> FilteredFactView<'a> {
    #[must_use]
    pub fn new(store: &'a FactStore, allowed: &'a BTreeSet<String>) -> Self {
        Self { store, allowed }
    }
}

impl FactRead for FilteredFactView<'_> {
    fn by_kind<'a>(&'a self, kind: &'a str) -> Box<dyn Iterator<Item = &'a Fact> + 'a> {
        if self.allowed.contains(kind) {
            Box::new(self.store.by_kind(kind))
        } else {
            Box::new(std::iter::empty())
        }
    }

    fn get(&self, id: FactId) -> Option<&Fact> {
        self.store
            .get(id)
            .filter(|fact| self.allowed.contains(fact.kind.as_str()))
    }
}

/// Policy for dropping verbose low-signal facts from an exported snapshot.
///
/// Collectors emit many mixin bytecode facts; rules rarely need all of them.
/// Compaction keeps predicates required for findings and drops the rest once
/// `max_facts` is exceeded. Diagnosis engines must apply this only after all
/// rules have evaluated; collectors enforce their own input/work budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactRetentionPolicy {
    /// When `facts.len()` exceeds this, the post-rule snapshot is compacted.
    pub max_facts: usize,
    /// Predicates always retained (findings depend on these).
    pub keep_kinds: BTreeSet<String>,
}

impl Default for FactRetentionPolicy {
    fn default() -> Self {
        let mut keep = BTreeSet::new();
        for k in [
            kind::MOD,
            kind::PLUGIN,
            kind::DEPENDENCY,
            kind::PROVIDED_DEPENDENCY,
            kind::MOD_SIDE,
            kind::ENVIRONMENT,
            kind::ANALYSIS_ENVIRONMENT,
            kind::JAVA_RUNTIME,
            kind::TARGET,
            kind::LOG_SIGNAL,
            kind::LOG_MENTIONS_MOD,
            kind::LOG_CRASH,
            kind::LOG_MOD_ERROR,
            // Runtime incident evidence is sparse and causally stronger than
            // bulk resource/mixin detail. It must survive retention regardless
            // of how many low-priority facts a large pack emits.
            kind::RUNTIME_EVENT,
            kind::THROWABLE_NODE,
            kind::STACK_FRAME,
            kind::CRASH_ANCHOR,
            kind::SCAN_TRUNCATED,
            kind::INVALID_METADATA,
            kind::UNPARSEABLE_ARCHIVE,
            kind::MOD_METADATA,
            kind::PACKAGE_OWNER,
            kind::ARTIFACT_IDENTITY,
            kind::COMPATIBILITY_BRIDGE,
            kind::RESOURCE_COLLISION,
            kind::RESOURCE_OVERLAY_ACTION,
            kind::RUNTIME_REMOVED_RECIPE,
            kind::RUNTIME_REMOVED_ITEM,
            kind::RUNTIME_REMOVED_LOOT_TABLE,
            kind::RUNTIME_REMOVED_TAG,
            kind::RUNTIME_SCRIPT_MODIFIES_RECIPE,
            kind::MODPACK_INCOMPLETE,
            kind::MODPACK_MANIFEST,
            kind::MIXIN_OVERLAP,
            kind::MIXIN_DATAFLOW_METRICS,
            kind::HIGH_RISK_OVERWRITE,
            // Site-level overhaul (plan Phases 1–14): conclusion-bearing diagnoses.
            // The verbose per-site `mixin_application_site` stays droppable (like
            // `mixin_injection_point`) — preserved only when a finding cites it.
            kind::MIXIN_ACTIVATION,
            kind::MIXIN_CLASSPATH_COVERAGE,
            kind::MIXIN_COMPOSITION,
            kind::MIXIN_RISK_CLUSTER,
            kind::MIXIN_RUNTIME_RESOURCE_MUTATION,
            kind::MIXIN_SECURITY_SURFACE,
            kind::SBOM,
            kind::UNKNOWN_SOURCE,
            kind::SIGNATURE_STATUS,
            kind::TRUST_SCORE,
            // Environment inference for legacy Forge packs uses one archive
            // filename vote per checksum fact. Dropping these before report
            // assembly let two copied modern descriptors outvote dozens of
            // 1.12.2 filenames in large/full scans.
            kind::CHECKSUM,
            kind::USES_PROCESS_SPAWN,
            kind::USES_UNSAFE,
            kind::USES_DYNAMIC_CLASS_DEFINITION,
            kind::USES_SCRIPT_ENGINE,
            kind::USES_SOCKET,
            kind::USES_REFLECTION_SET_ACCESSIBLE,
            kind::USES_NATIVE_LIBRARY,
            kind::USES_DESERIALIZATION,
            kind::USES_SYSTEM_EXIT,
            kind::USES_METHOD_HANDLES,
            kind::RESOURCE_PLATFORM_OBSERVATION,
            kind::DEFERRED_LAYER,
            // Layer M — keep the *compact* conclusion-bearing facts; the verbose
            // per-edge `resource_reference` / `resource_definition` are evidence
            // only and remain droppable (preserved when a finding cites them).
            kind::RESOURCE_SEMANTIC_DIFF,
            kind::RESOURCE_SEMANTIC_CONFLICT,
            kind::RESOURCE_SEMANTIC_ISSUE,
            kind::IMPLICIT_DEPENDENCY_CANDIDATE,
            kind::RESOURCE_RESOLVE_RESULT,
            kind::NAMESPACE_OWNER,
        ] {
            keep.insert(k.to_string());
        }
        Self {
            max_facts: 50_000,
            keep_kinds: keep,
        }
    }
}

/// Append-only store of facts gathered during one diagnosis run.
#[derive(Debug, Default)]
pub struct FactStore {
    facts: Vec<Fact>,
    next_id: u64,
    /// Per-predicate index into `facts`. Locating the postings list is
    /// `O(log P)` for `P` predicates; iterating its `K` matches is `O(K)`.
    kind_index: BTreeMap<InternedString, Vec<usize>>,
    /// Per-subject index into `facts`. Lets cross-fact passes (suppression /
    /// finding merge, Layer-M ↔ Layer-E correlation) join on the shared subject
    /// (usually a resource path or mod id) without an O(n·m) scan.
    subject_index: BTreeMap<InternedString, Vec<usize>>,
    /// FactId → optional position in `facts`. A dense vector is substantially
    /// smaller than one tree node per fact while retaining stable ids across
    /// [`FactStore::compact`]. See `get_still_works_after_compaction`.
    id_index: Vec<Option<usize>>,
    /// Optional collection-time soft bound. When crossed, low-priority facts are
    /// compacted before the next collector can grow the store without limit.
    live_policy: Option<FactRetentionPolicy>,
    /// Next collection length at which legacy opt-in live retention retries.
    /// A failed pass backs off exponentially when protected facts dominate.
    pub(super) live_next_compaction_at: usize,
    live_dropped: usize,
    emitted_stats: BTreeMap<InternedString, usize>,
    /// Per-run pool for schema symbols and repeated archive/source locators.
    /// Dynamic subjects and attribute values deliberately remain owned: many
    /// are unique resource or class names and would only grow this pool.
    interned: HashSet<InternedString>,
    /// Opt-in predicate read trace used by rule contract tests. Production
    /// stores leave this as `None`, so normal indexed reads pay only one branch.
    read_trace: Option<std::sync::Arc<std::sync::Mutex<BTreeSet<String>>>>,
}

impl FactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start recording predicates requested through [`FactStore::by_kind`] and
    /// [`FactStore::by_kind_subject`]. Intended for rule read-set sanitizers.
    pub fn enable_read_tracking(&mut self) {
        self.read_trace = Some(Default::default());
    }

    /// Return the predicate read-set recorded since tracking was enabled.
    #[must_use]
    pub fn recorded_reads(&self) -> BTreeSet<String> {
        self.read_trace
            .as_ref()
            .and_then(|trace| trace.lock().ok().map(|reads| reads.clone()))
            .unwrap_or_default()
    }

    fn record_read(&self, kind: &str) {
        if let Some(trace) = &self.read_trace
            && let Ok(mut reads) = trace.lock()
        {
            reads.insert(kind.to_string());
        }
    }

    /// Create an append-only staging store whose identifiers continue after
    /// this store.  The engine uses it while an immutable view of `self` is
    /// visible to a collector, then merges the staged observations back.
    #[must_use]
    pub fn staging_after(&self) -> Self {
        Self {
            next_id: self.next_id,
            ..Self::default()
        }
    }

    /// Append a staging store created by [`FactStore::staging_after`], retaining
    /// its already-issued identifiers and rebuilding only the affected indexes.
    pub fn append_staged(&mut self, mut staged: Self) {
        debug_assert!(staged.facts.iter().all(|fact| fact.id.0 >= self.next_id));
        self.next_id = self.next_id.max(staged.next_id);
        for (kind, count) in staged.emitted_stats {
            let kind = self.intern_arc(kind);
            *self.emitted_stats.entry(kind).or_insert(0) += count;
        }
        for mut fact in staged.facts.drain(..) {
            fact.kind = self.intern_arc(fact.kind);
            fact.extractor = self.intern_arc(fact.extractor);
            fact.subject = self.intern_arc(fact.subject);
            fact.source.locator = self.intern_arc(fact.source.locator);
            fact.attributes = std::mem::take(&mut fact.attributes)
                .into_iter()
                .map(|(key, value)| (self.intern_arc(key), value))
                .collect();
            let idx = self.facts.len();
            let id = fact.id;
            self.kind_index
                .entry(fact.kind.clone())
                .or_default()
                .push(idx);
            self.subject_index
                .entry(fact.subject.clone())
                .or_default()
                .push(idx);
            let id_slot = id.0 as usize;
            if self.id_index.len() <= id_slot {
                self.id_index.resize(id_slot + 1, None);
            }
            self.id_index[id_slot] = Some(idx);
            self.facts.push(fact);
        }
    }

    /// Create a store with collection-time semantic retention enabled. Protected
    /// predicates may exceed the soft count bound, but bulk detail cannot; this
    /// preserves sparse causal evidence while bounding the dominant allocations.
    pub fn with_live_retention(policy: FactRetentionPolicy) -> Self {
        let slack = (policy.max_facts / 20).clamp(256, 4_096);
        Self {
            live_next_compaction_at: policy.max_facts.saturating_add(slack),
            live_policy: Some(policy),
            ..Self::default()
        }
    }

    fn maybe_compact_live(&mut self) {
        let Some(policy) = self.live_policy.clone() else {
            return;
        };
        if self.facts.len() <= self.live_next_compaction_at {
            return;
        }
        let dropped = self.compact_preserving(&policy, &BTreeSet::new());
        self.live_dropped = self.live_dropped.saturating_add(dropped);
        let slack = (policy.max_facts / 20).clamp(256, 4_096);
        let normal_threshold = policy.max_facts.saturating_add(slack);
        self.live_next_compaction_at = if self.facts.len() > normal_threshold {
            // Protected facts cannot be removed. Do not rescan the entire store
            // after every subsequent emit; retry only after substantial growth.
            self.facts
                .len()
                .saturating_mul(2)
                .max(self.facts.len().saturating_add(slack))
        } else {
            normal_threshold
        };
    }

    /// Begin building a fact. `extractor` is the producing collector's id.
    pub fn fact(&mut self, extractor: &str, kind: &str) -> FactBuilder<'_> {
        let extractor = self.intern_str(extractor);
        let kind = self.intern_str(kind);
        let subject = self.intern_str("");
        FactBuilder {
            store: self,
            kind,
            subject,
            attributes: Attributes::default(),
            source: SourceRef::file("<unknown>"),
            confidence: 1.0,
            extractor,
        }
    }

    fn intern_str(&mut self, value: &str) -> InternedString {
        if let Some(existing) = self.interned.get(value) {
            return existing.clone();
        }
        let value = InternedString::from(value);
        self.interned.insert(value.clone());
        value
    }

    fn intern_arc(&mut self, value: InternedString) -> InternedString {
        if let Some(existing) = self.interned.get(value.as_ref()) {
            return existing.clone();
        }
        self.interned.insert(value.clone());
        value
    }

    pub fn all(&self) -> &[Fact] {
        &self.facts
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn interned_len(&self) -> usize {
        self.interned.len()
    }

    #[must_use]
    pub fn live_dropped(&self) -> usize {
        self.live_dropped
    }

    #[must_use]
    pub fn emitted_stats(&self) -> BTreeMap<String, usize> {
        self.emitted_stats
            .iter()
            .map(|(kind, count)| (kind.to_string(), *count))
            .collect()
    }

    /// Facts discarded by collection-time retention, grouped by predicate.
    #[must_use]
    pub fn live_dropped_stats(&self) -> BTreeMap<String, usize> {
        let retained = self.stats();
        self.emitted_stats
            .iter()
            .filter_map(|(kind, emitted)| {
                let dropped = emitted.saturating_sub(*retained.get(kind.as_str()).unwrap_or(&0));
                (dropped > 0).then(|| (kind.to_string(), dropped))
            })
            .collect()
    }

    /// All facts with the given predicate (indexed; O(k) not O(n)).
    pub fn by_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a Fact> + 'a {
        self.record_read(kind);
        let facts = &self.facts;
        self.kind_index
            .get(kind)
            .into_iter()
            .flatten()
            .copied()
            .map(move |i| &facts[i])
    }

    /// All facts with the given subject (indexed; O(k) not O(n)). Used by passes
    /// that correlate facts sharing a subject — e.g. a Layer-M semantic diff and
    /// a Layer-E byte collision on the same resource path.
    pub fn by_subject<'a>(&'a self, subject: &'a str) -> impl Iterator<Item = &'a Fact> + 'a {
        let facts = &self.facts;
        self.subject_index
            .get(subject)
            .into_iter()
            .flatten()
            .copied()
            .map(move |i| &facts[i])
    }

    /// All facts with the given predicate **and** subject. Intersects the kind
    /// and subject indexes, scanning the smaller postings list.
    pub fn by_kind_subject<'a>(
        &'a self,
        kind: &'a str,
        subject: &'a str,
    ) -> impl Iterator<Item = &'a Fact> + 'a {
        self.record_read(kind);
        let facts = &self.facts;
        let by_kind = self.kind_index.get(kind);
        let by_subject = self.subject_index.get(subject);
        // Walk whichever postings list is shorter, filtering by the other axis.
        let (drive, want_subject) = match (by_kind, by_subject) {
            (Some(k), Some(s)) if k.len() <= s.len() => (Some(k), true),
            (Some(_), Some(s)) => (Some(s), false),
            _ => (None, false),
        };
        drive
            .into_iter()
            .flatten()
            .copied()
            .map(move |i| &facts[i])
            .filter(move |f| {
                if want_subject {
                    f.subject == subject
                } else {
                    f.kind.as_ref() == kind
                }
            })
    }

    /// Drop verbose facts not listed in `policy.keep_kinds` when over `max_facts`.
    ///
    /// Rebuilds ids and the kind index. Returns how many facts were removed.
    pub fn compact(&mut self, policy: &FactRetentionPolicy) -> usize {
        self.compact_preserving(policy, &BTreeSet::new())
    }

    /// Like [`FactStore::compact`], but never drops a fact whose id is in
    /// `keep_ids`. Evidence edges on findings cite facts by id; dropping a cited
    /// fact left the report rendering it as a bare `fact #N` with no kind,
    /// subject, or source. The engine passes every fact id referenced by a
    /// finding's evidence here so provenance always resolves.
    pub fn compact_preserving(
        &mut self,
        policy: &FactRetentionPolicy,
        keep_ids: &BTreeSet<FactId>,
    ) -> usize {
        if self.facts.len() <= policy.max_facts {
            return 0;
        }
        let before = self.facts.len();
        self.facts
            .retain(|f| policy.keep_kinds.contains(f.kind.as_ref()) || keep_ids.contains(&f.id));
        if self.facts.len() >= before {
            return 0;
        }
        self.rebuild_index();
        before.saturating_sub(self.facts.len())
    }

    fn rebuild_index(&mut self) {
        self.kind_index.clear();
        self.subject_index.clear();
        self.id_index.clear();
        self.id_index.resize(self.next_id as usize, None);
        for (idx, fact) in self.facts.iter().enumerate() {
            self.kind_index
                .entry(fact.kind.clone())
                .or_default()
                .push(idx);
            self.subject_index
                .entry(fact.subject.clone())
                .or_default()
                .push(idx);
            self.id_index[fact.id.0 as usize] = Some(idx);
        }
        // Ids are *not* renumbered: existing FactIds (e.g. held by findings'
        // evidence edges) must stay valid after compaction. next_id continues
        // monotonically past the largest surviving id.
        // Never lower `next_id`: facts removed by live retention still consumed
        // identifiers, and a later fact must not reuse one of them.
    }

    /// Per-predicate counts, for report fact-stats.
    pub fn stats(&self) -> BTreeMap<String, usize> {
        self.kind_index
            .iter()
            .map(|(kind, facts)| (kind.to_string(), facts.len()))
            .collect()
    }

    /// Lookup by fact id, used by `doctor --explain` and evidence resolution.
    ///
    /// Resolves through `id_index` rather than treating `id.0` as a slot index,
    /// so it stays correct after [`FactStore::compact`] has dropped facts.
    pub fn get(&self, id: FactId) -> Option<&Fact> {
        self.id_index
            .get(id.0 as usize)
            .and_then(|idx| *idx)
            .and_then(|idx| self.facts.get(idx))
    }

    /// Rehydrate a store from a prior diagnosis snapshot (`--dump-facts` round-trip).
    pub fn from_snapshot(facts: Vec<Fact>) -> Self {
        let next_id = facts
            .iter()
            .map(|f| f.id.0)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);
        let mut store = Self {
            facts,
            next_id,
            kind_index: BTreeMap::new(),
            subject_index: BTreeMap::new(),
            id_index: Vec::new(),
            live_policy: None,
            live_next_compaction_at: 0,
            live_dropped: 0,
            emitted_stats: BTreeMap::new(),
            interned: HashSet::new(),
            read_trace: None,
        };
        for fact in &mut store.facts {
            fact.kind = intern_into(&mut store.interned, fact.kind.clone());
            fact.extractor = intern_into(&mut store.interned, fact.extractor.clone());
            fact.subject = intern_into(&mut store.interned, fact.subject.clone());
            fact.source.locator = intern_into(&mut store.interned, fact.source.locator.clone());
            fact.attributes = std::mem::take(&mut fact.attributes)
                .into_iter()
                .map(|(key, value)| (intern_into(&mut store.interned, key), value))
                .collect();
        }
        store.emitted_stats = store.facts.iter().fold(BTreeMap::new(), |mut stats, fact| {
            *stats.entry(fact.kind.clone()).or_insert(0) += 1;
            stats
        });
        store.rebuild_index();
        store
    }
}

fn intern_into(pool: &mut HashSet<InternedString>, value: InternedString) -> InternedString {
    if let Some(existing) = pool.get(value.as_ref()) {
        return existing.clone();
    }
    pool.insert(value.clone());
    value
}

impl FactWrite for FactStore {
    fn fact<'a>(&'a mut self, extractor: &str, kind: &str) -> FactBuilder<'a> {
        FactStore::fact(self, extractor, kind)
    }
}

impl FactRead for FactStore {
    fn by_kind<'a>(&'a self, kind: &'a str) -> Box<dyn Iterator<Item = &'a Fact> + 'a> {
        Box::new(FactStore::by_kind(self, kind))
    }

    fn get(&self, id: FactId) -> Option<&Fact> {
        FactStore::get(self, id)
    }
}
