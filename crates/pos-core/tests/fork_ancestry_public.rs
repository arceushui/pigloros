//! ADR-021 Revision 4 Decision 3: the shared Fork-ancestry helpers (#499).

use std::collections::HashMap;

use pos_core::{
    authorize_fork_scopes, fork_ancestry, validate_fork_ancestry, with_fork_ancestry_fence,
    CoreError, ErasureContainmentErrorV1, ErasureContainmentGateV1, ErasureGate,
    ErasureLifecycleV1, ErasureProtectedOperationV1, Event, EventDraft, EventStore, Seq, SeqRange,
    Timeline, TimelineId, TimelineMeta,
};

const READ: ErasureProtectedOperationV1 = ErasureProtectedOperationV1::Read;

/// A topology-only store whose metadata the test controls directly.
#[derive(Default)]
struct TopologyStore {
    timelines: HashMap<TimelineId, Timeline>,
    hidden: Option<TimelineId>,
    failing: Option<TimelineId>,
}

impl TopologyStore {
    fn insert(&mut self, meta: TimelineMeta) -> TimelineId {
        let id = meta.id;
        self.timelines.insert(id, Timeline::new(meta));
        id
    }

    fn root(&mut self) -> TimelineId {
        self.insert(TimelineMeta::root("root"))
    }

    fn add_fork(&mut self, parent: TimelineId) -> TimelineId {
        self.insert(TimelineMeta::forked_from(parent, Seq::ZERO, "fork"))
    }
}

impl EventStore for TopologyStore {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        Ok(Timeline::new(TimelineMeta::root(name)))
    }

    fn append(
        &mut self,
        _timeline: TimelineId,
        _drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        Ok(Vec::new())
    }

    fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
        Ok(Vec::new())
    }

    fn fork(
        &mut self,
        _parent: TimelineId,
        _at_seq: Seq,
        name: &str,
    ) -> Result<Timeline, CoreError> {
        Ok(Timeline::new(TimelineMeta::root(name)))
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        Ok(self.timelines.values().cloned().collect())
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        if self.failing == Some(id) {
            return Err(CoreError::ErasureAccessFrozen);
        }
        if self.hidden == Some(id) {
            return Ok(None);
        }
        Ok(self.timelines.get(&id).cloned())
    }
}

fn ids(ancestry: &[TimelineMeta]) -> Vec<TimelineId> {
    ancestry.iter().map(|meta| meta.id).collect()
}

fn meta(id: TimelineId, parent: Option<TimelineId>) -> TimelineMeta {
    TimelineMeta {
        id,
        fork_point: parent.map(|parent| (parent, Seq::ZERO)),
        ..TimelineMeta::root("member")
    }
}

#[test]
fn fork_ancestry_walks_the_store_from_the_timeline_to_its_root(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = TopologyStore::default();
    let root = store.root();
    let child = store.add_fork(root);
    let grandchild = store.add_fork(child);

    assert_eq!(ids(&fork_ancestry(&store, root)?), [root]);
    assert_eq!(ids(&fork_ancestry(&store, child)?), [child, root]);
    let chain = fork_ancestry(&store, grandchild)?;
    assert_eq!(ids(&chain), [grandchild, child, root]);
    assert_eq!(validate_fork_ancestry(grandchild, &chain), Ok(()));
    Ok(())
}

#[test]
fn fork_ancestry_fails_closed_for_missing_hidden_denied_and_cyclic_members() {
    let mut store = TopologyStore::default();
    let root = store.root();
    let child = store.add_fork(root);
    let missing = TimelineId::new();
    assert!(matches!(
        fork_ancestry(&store, missing),
        Err(CoreError::TimelineNotFound(id)) if id == missing
    ));

    store.hidden = Some(root);
    assert!(matches!(
        fork_ancestry(&store, child),
        Err(CoreError::TimelineNotFound(id)) if id == root
    ));
    store.hidden = None;

    store.failing = Some(root);
    assert!(matches!(
        fork_ancestry(&store, child),
        Err(CoreError::ErasureAccessFrozen)
    ));
    store.failing = None;

    let first = TimelineId::new();
    let second = TimelineId::new();
    store.insert(meta(first, Some(second)));
    store.insert(meta(second, Some(first)));
    assert!(matches!(
        fork_ancestry(&store, first),
        Err(CoreError::Storage(message)) if message.contains("cycle")
    ));
}

#[test]
fn validation_rejects_empty_wrongly_rooted_non_contiguous_and_unterminated_chains() {
    let root = TimelineId::new();
    let child = TimelineId::new();
    let unrelated = TimelineId::new();
    let valid = [meta(child, Some(root)), meta(root, None)];
    assert_eq!(validate_fork_ancestry(child, &valid), Ok(()));
    assert_eq!(validate_fork_ancestry(root, &[meta(root, None)]), Ok(()));

    let unavailable = Err(ErasureContainmentErrorV1::RecoveryUnavailable);
    assert_eq!(validate_fork_ancestry(child, &[]), unavailable);
    // Contiguous and rooted, but for another Timeline.
    assert_eq!(validate_fork_ancestry(root, &valid), unavailable);
    // Starts at the Timeline and ends at a root, but skips the real parent.
    assert_eq!(
        validate_fork_ancestry(child, &[meta(child, Some(root)), meta(unrelated, None)]),
        unavailable
    );
    // Starts at the Timeline and links contiguously, but never reaches a root.
    assert_eq!(
        validate_fork_ancestry(child, &[meta(child, Some(root))]),
        unavailable
    );
}

#[test]
fn every_contributing_scope_is_authorized_for_the_operation() {
    let gate = ErasureContainmentGateV1::new_test_open();
    let root = TimelineId::new();
    let child = TimelineId::new();
    assert_eq!(authorize_fork_scopes(&gate, [child, root], READ), Ok(()));
    gate.freeze_timeline_for_test(root);
    assert_eq!(
        authorize_fork_scopes(&gate, [child, root], READ),
        Err(ErasureContainmentErrorV1::AccessFrozen)
    );
    assert_eq!(authorize_fork_scopes(&gate, [child], READ), Ok(()));
}

#[test]
fn the_ancestry_fence_runs_the_effect_only_when_every_scope_permits() {
    let gate = ErasureContainmentGateV1::new_test_open();
    let root = TimelineId::new();
    let child = TimelineId::new();
    let grandchild = TimelineId::new();
    let chain = [
        meta(grandchild, Some(child)),
        meta(child, Some(root)),
        meta(root, None),
    ];
    let mut runs = 0;
    assert_eq!(
        with_fork_ancestry_fence(&gate, grandchild, &chain, READ, &mut || runs += 1),
        Ok(())
    );
    assert_eq!(runs, 1);

    assert_eq!(
        with_fork_ancestry_fence(&gate, child, &chain, READ, &mut || runs += 1),
        Err(ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    assert_eq!(runs, 1);

    gate.freeze_timeline_for_test(root);
    assert_eq!(
        with_fork_ancestry_fence(&gate, grandchild, &chain, READ, &mut || runs += 1),
        Err(ErasureContainmentErrorV1::AccessFrozen)
    );
    assert_eq!(runs, 1);

    let frozen_leaf = ErasureContainmentGateV1::new_test_open();
    frozen_leaf.freeze_timeline_for_test(grandchild);
    let dynamic: &dyn ErasureGate = &frozen_leaf;
    assert_eq!(
        with_fork_ancestry_fence(dynamic, grandchild, &chain, READ, &mut || runs += 1),
        Err(ErasureContainmentErrorV1::AccessFrozen)
    );
    assert_eq!(runs, 1);
}

#[test]
fn a_completed_erasure_keeps_its_scope_frozen_and_leaves_others_open() {
    let gate = ErasureContainmentGateV1::new_test_open();
    let erased = TimelineId::new();
    let unrelated = TimelineId::new();
    assert_eq!(
        gate.complete_timeline_erasure_for_test(erased),
        Ok(ErasureLifecycleV1::Complete)
    );
    for operation in [
        ErasureProtectedOperationV1::Read,
        ErasureProtectedOperationV1::Export,
        ErasureProtectedOperationV1::Snapshot,
        ErasureProtectedOperationV1::PluginInput,
    ] {
        assert_eq!(
            gate.authorize(erased, operation),
            Err(ErasureContainmentErrorV1::AccessFrozen)
        );
        assert_eq!(gate.authorize(unrelated, operation), Ok(()));
    }
    // Driving the same request again is idempotent at the terminal state.
    assert_eq!(
        gate.complete_timeline_erasure_for_test(erased),
        Ok(ErasureLifecycleV1::Complete)
    );
}
