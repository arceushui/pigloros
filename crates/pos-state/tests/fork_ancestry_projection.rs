//! ADR-021 Revision 4 Decision 3: projection folds and refolds of a Fork's
//! stitched history keep fencing every inherited ancestor scope (#499).

use pos_core::{
    AuthorityErrorV1, CanonicalBytes, EntityId, ErasureContainmentGateV1, Event, EventId, Hash,
    Kind, SchemaVersion, Seq, TimelineId, TimelineMeta, WallTime,
};
use pos_state::{EntityStateProjection, ProjectionRegistry};
use std::{fmt::Debug, sync::Arc};

trait TestOk<T> {
    fn test_ok(self) -> T;
}

impl<T, E: Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}

const UNAVAILABLE: Result<(), AuthorityErrorV1> = Err(AuthorityErrorV1::SourceUnavailable);

/// A root, its Fork, and that Fork's own Fork, as the store would report.
struct Lineage {
    root: TimelineId,
    child: TimelineId,
    grandchild: TimelineId,
}

impl Lineage {
    fn new() -> Self {
        Self {
            root: TimelineId::new(),
            child: TimelineId::new(),
            grandchild: TimelineId::new(),
        }
    }

    fn member(id: TimelineId, parent: Option<TimelineId>) -> TimelineMeta {
        TimelineMeta {
            id,
            fork_point: parent.map(|parent| (parent, Seq::from_u64(1))),
            ..TimelineMeta::root("member")
        }
    }

    fn grandchild_ancestry(&self) -> Vec<TimelineMeta> {
        let mut ancestry = vec![Self::member(self.grandchild, Some(self.child))];
        ancestry.extend(self.child_ancestry());
        ancestry
    }

    fn child_ancestry(&self) -> Vec<TimelineMeta> {
        vec![
            Self::member(self.child, Some(self.root)),
            Self::member(self.root, None),
        ]
    }
}

fn event(entity: EntityId) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new("profile.changed"),
        payload: CanonicalBytes::from_static(b"{}"),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(1),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([1; 32]),
    }
}

fn registry(gate: &Arc<ErasureContainmentGateV1>) -> ProjectionRegistry {
    let mut registry = ProjectionRegistry::new().with_erasure_gate(gate.clone());
    registry.register("events", Box::new(EntityStateProjection));
    registry
}

fn read(
    registry: &ProjectionRegistry,
    timeline: TimelineId,
    entity: EntityId,
) -> Result<(), AuthorityErrorV1> {
    registry.state_for(timeline, &entity).map(|_| ())
}

#[test]
fn a_bound_ancestry_fences_every_later_snapshot_read_of_its_timeline() {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let lineage = Lineage::new();
    let entity = EntityId::new();
    let mut projections = registry(&gate);
    projections.fold_events(lineage.child, &[event(entity)]);
    assert_eq!(
        projections.bind_fork_ancestry(lineage.child, &[]),
        UNAVAILABLE
    );
    assert_eq!(
        projections.bind_fork_ancestry(lineage.root, &lineage.child_ancestry()),
        UNAVAILABLE
    );
    projections
        .bind_fork_ancestry(lineage.child, &lineage.child_ancestry())
        .test_ok();
    read(&projections, lineage.child, entity).test_ok();

    gate.freeze_timeline_for_test(lineage.root);
    assert_eq!(read(&projections, lineage.child, entity), UNAVAILABLE);
    assert!(projections.state_snapshot(lineage.child).is_err());
    assert_eq!(projections.validate_fork_source(lineage.child), UNAVAILABLE);

    // A chain bound for another Timeline never serves the source Timeline.
    let unrelated = TimelineId::new();
    let mut other = registry(&gate);
    other.fold_events(unrelated, &[event(entity)]);
    other
        .bind_fork_ancestry(lineage.child, &lineage.child_ancestry())
        .test_ok();
    assert_eq!(read(&other, unrelated, entity), UNAVAILABLE);
    // Binding the source Timeline's own chain restores service.
    other
        .bind_fork_ancestry(unrelated, &[Lineage::member(unrelated, None)])
        .test_ok();
    read(&other, unrelated, entity).test_ok();
}

#[test]
fn refold_and_restore_fail_closed_on_a_denied_ancestor_and_keep_the_chain() {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let lineage = Lineage::new();
    let entity = EntityId::new();
    let events = [event(entity)];
    let ancestry = lineage.child_ancestry();

    let mut refolded = registry(&gate);
    assert_eq!(
        refolded.refold_events(lineage.child, &ancestry[1..], &events, None),
        UNAVAILABLE
    );
    refolded
        .refold_events(lineage.child, &ancestry, &events, None)
        .test_ok();
    let snapshot = refolded.state_snapshot(lineage.child).test_ok();

    let mut restored = registry(&gate);
    restored
        .restore_from_snapshot(lineage.child, &ancestry, &snapshot, None)
        .test_ok();
    read(&restored, lineage.child, entity).test_ok();

    gate.freeze_timeline_for_test(lineage.root);
    // The chain bound by the refold and the restore keeps fencing reads.
    assert_eq!(read(&refolded, lineage.child, entity), UNAVAILABLE);
    assert_eq!(read(&restored, lineage.child, entity), UNAVAILABLE);
    assert_eq!(
        refolded.refold_events(lineage.child, &ancestry, &events, None),
        UNAVAILABLE
    );
    let mut denied = registry(&gate);
    assert_eq!(
        denied.restore_from_snapshot(lineage.child, &ancestry, &snapshot, None),
        UNAVAILABLE
    );
    assert_eq!(read(&denied, lineage.child, entity), Ok(()));
}

#[test]
fn an_adopted_fork_requires_and_keeps_its_complete_ancestry() {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let lineage = Lineage::new();
    let entity = EntityId::new();
    let complete = lineage.grandchild_ancestry();

    let mut adopted = registry(&gate);
    adopted.fold_events(lineage.child, &[event(entity)]);
    // Empty, foreign, and a chain that skips the parent all fail closed.
    let foreign = lineage.child_ancestry();
    let skipping = [
        Lineage::member(lineage.grandchild, Some(lineage.root)),
        Lineage::member(lineage.root, None),
    ];
    let invalid: [&[TimelineMeta]; 3] = [&[], &foreign, &skipping];
    for ancestry in invalid {
        assert_eq!(
            adopted.adopt_committed_fork(lineage.child, lineage.grandchild, ancestry),
            UNAVAILABLE
        );
    }
    adopted
        .adopt_committed_fork(lineage.child, lineage.grandchild, &complete)
        .test_ok();
    read(&adopted, lineage.grandchild, entity).test_ok();

    // A failed refold binds nothing.
    let mut stale = registry(&gate);
    assert_eq!(
        stale.refold_events(
            lineage.child,
            &lineage.child_ancestry(),
            &[event(entity)],
            Some(pos_core::ErasureReferenceV1::from_digest([9; 32])),
        ),
        UNAVAILABLE
    );
    stale.fold_events(lineage.child, &[event(entity)]);

    gate.freeze_timeline_for_test(lineage.root);
    assert_eq!(read(&adopted, lineage.grandchild, entity), UNAVAILABLE);
    assert_eq!(read(&stale, lineage.child, entity), Ok(()));
}
