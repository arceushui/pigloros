use std::sync::Arc;

use pos_core::{
    store::{export_timeline_raw, EventStore, SeqRange},
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, EntityId, ErasureArtifactClassV1,
    ErasureContainmentErrorV1, ErasureContainmentGateV1, ErasureGate, ErasureProtectedOperationV1,
    ErasureReferenceV1, ErasureReplayClaimV1, EventDraft, Kind, RegisteredArtifactV1,
    ReplayClaimEvaluatorV1, SchemaVersion,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};

const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([211; 32]);

fn export_evaluation() -> pos_core::ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                EXPORT_DIGEST,
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([212; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn draft() -> EventDraft {
    EventDraft {
        entity: EntityId::new(),
        event_type: Kind::new("world.test"),
        payload: CanonicalBytes::from_vec(vec![1]),
        wall_time: None,
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
    }
}

fn assert_blocked<S: EventStore>(mut store: S) -> Result<(), Box<dyn std::error::Error>> {
    let timeline = store.create_timeline("erasure-containment")?;
    let gate = Arc::new(ErasureContainmentGateV1::new());
    gate.block_timeline(timeline.id());
    let gate_for_store: Arc<dyn ErasureGate> = gate.clone();
    store.bind_erasure_gate(gate_for_store)?;
    let second_binding = store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new()));
    assert!(second_binding.is_err());

    let append_error = store.append(timeline.id(), &[draft()]).err();
    assert_eq!(
        append_error.map(|error| error.to_string()),
        Some("erasure containment boundary is unavailable".to_owned())
    );
    let read_error = store.read(timeline.id(), SeqRange::all()).err();
    assert_eq!(
        read_error.map(|error| error.to_string()),
        Some("erasure containment boundary is unavailable".to_owned())
    );
    let export_error =
        export_timeline_raw(&store, timeline.id(), EXPORT_DIGEST, &export_evaluation()).err();
    assert_eq!(
        export_error.map(|error| error.to_string()),
        Some("erasure containment boundary is unavailable".to_owned())
    );
    assert_eq!(
        store.list_timelines().err().map(|error| error.to_string()),
        Some("erasure containment boundary is unavailable".to_owned())
    );
    assert_eq!(
        store
            .root_timeline_count_bounded(usize::MAX)
            .err()
            .map(|error| error.to_string()),
        Some("erasure containment boundary is unavailable".to_owned())
    );
    assert_eq!(
        gate.authorize(timeline.id(), ErasureProtectedOperationV1::Export),
        Err(pos_core::ErasureContainmentErrorV1::RecoveryUnavailable)
    );
    Ok(())
}

struct SelectiveGate {
    blocked: pos_core::TimelineId,
}

impl ErasureGate for SelectiveGate {
    fn authorize(
        &self,
        timeline: pos_core::TimelineId,
        _operation: ErasureProtectedOperationV1,
    ) -> Result<(), ErasureContainmentErrorV1> {
        if timeline == self.blocked {
            Err(ErasureContainmentErrorV1::AccessFrozen)
        } else {
            Ok(())
        }
    }

    fn with_fence(
        &self,
        timeline: pos_core::TimelineId,
        operation: ErasureProtectedOperationV1,
        effect: &mut dyn FnMut(),
    ) -> Result<(), ErasureContainmentErrorV1> {
        self.authorize(timeline, operation)?;
        effect();
        Ok(())
    }
}

fn assert_listing_filters_frozen_scope<S: EventStore>(
    mut store: S,
) -> Result<(), Box<dyn std::error::Error>> {
    let blocked = store.create_timeline("blocked")?;
    let available = store.create_timeline("available")?;
    store.bind_erasure_gate(Arc::new(SelectiveGate {
        blocked: blocked.id(),
    }))?;

    let listed = store.list_timelines()?;
    assert!(listed
        .iter()
        .any(|timeline| timeline.id() == available.id()));
    assert!(!listed.iter().any(|timeline| timeline.id() == blocked.id()));
    assert_eq!(store.root_timeline_count_bounded(0)?, 1);
    assert_eq!(store.root_timeline_count_bounded(usize::MAX)?, 1);
    Ok(())
}

fn assert_unbound_fails_closed<S: EventStore>(
    mut store: S,
) -> Result<(), Box<dyn std::error::Error>> {
    let timeline = store.create_timeline("unbound")?;
    let expected = Some("erasure containment boundary is unavailable".to_owned());
    assert_eq!(
        store
            .append(timeline.id(), &[draft()])
            .err()
            .map(|error| error.to_string()),
        expected
    );
    assert_eq!(
        store
            .read(timeline.id(), SeqRange::all())
            .err()
            .map(|error| error.to_string()),
        expected
    );
    assert_eq!(
        store.list_timelines().err().map(|error| error.to_string()),
        expected
    );
    assert_eq!(
        store
            .root_timeline_count_bounded(usize::MAX)
            .err()
            .map(|error| error.to_string()),
        expected
    );
    Ok(())
}

#[test]
fn memory_store_fails_closed_for_unavailable_erasure_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_blocked(MemoryStore::new())
}

#[test]
fn sqlite_store_fails_closed_for_unavailable_erasure_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_blocked(SqliteStore::open_in_memory()?)
}

#[test]
fn memory_store_filters_frozen_scopes_from_listing_and_count(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_listing_filters_frozen_scope(MemoryStore::new())
}

#[test]
fn sqlite_store_filters_frozen_scopes_from_listing_and_count(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_listing_filters_frozen_scope(SqliteStore::open_in_memory()?)
}

#[test]
fn memory_store_without_erasure_gate_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    assert_unbound_fails_closed(MemoryStore::new().without_erasure_gate())
}

#[test]
fn sqlite_store_without_erasure_gate_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    assert_unbound_fails_closed(SqliteStore::open_in_memory()?.without_erasure_gate())
}
