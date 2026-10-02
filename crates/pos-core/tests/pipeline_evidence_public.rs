use pos_core::{
    CanonicalBytes, EntityId, Event, EventId, Hash, Kind, PipelineAttemptIdV1,
    PipelineCommitEvidenceV1, PipelineCommitReceiptV1, PipelineCommittedRangeV1, PipelineIngressV1,
    PipelineProjectionCutV1, ScheduledObservationProfileV1, SchemaVersion, Seq, TimelineId,
    WallTime,
};
use ulid::Ulid;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected evidence error: {error:?}")))
    })
}

fn timeline(value: u128) -> TimelineId {
    TimelineId::from_ulid(Ulid::from(value))
}

fn committed(id: u128, seq: u64) -> Event {
    Event {
        id: EventId::from_ulid(Ulid::from(id)),
        entity: EntityId::from_ulid(Ulid::from(7_u128)),
        event_type: Kind::new("fixture.evidence"),
        payload: CanonicalBytes::from_static(b"evidence"),
        wall_time: WallTime::from_micros(seq),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([9; 32]),
    }
}

/// A receipt for Events `first..=last` committed on `timeline_id`.
fn receipt(timeline_id: TimelineId, first: u64, last: u64) -> PipelineCommitReceiptV1 {
    let events: Vec<Event> = (first..=last)
        .map(|seq| committed(u128::from(seq) + 100, seq))
        .collect();
    ok(PipelineCommitReceiptV1::try_from_retained_events(
        ok(PipelineAttemptIdV1::try_new([4; 16])),
        timeline_id,
        Hash::from_bytes([5; 32]),
        &events,
    ))
}

#[test]
fn commit_evidence_names_the_exact_committed_range_without_a_fold() {
    let timeline_id = timeline(1);
    let receipt = receipt(timeline_id, 3, 5);
    let evidence = PipelineCommitEvidenceV1::committed(
        PipelineIngressV1::HumanProposedAction,
        ScheduledObservationProfileV1::NonParticipant,
        receipt.clone(),
    );

    let range = evidence.committed_range();
    assert_eq!(range, PipelineCommittedRangeV1::of_receipt(&receipt));
    assert_eq!(range.timeline_id(), timeline_id);
    assert_eq!(range.first(), Seq::from_u64(3));
    assert_eq!(range.last(), Seq::from_u64(5));
    assert_eq!(evidence.ingress(), PipelineIngressV1::HumanProposedAction);
    assert_eq!(
        evidence.observation_profile(),
        ScheduledObservationProfileV1::NonParticipant
    );
    assert_eq!(evidence.receipt(), &receipt);
    assert_eq!(evidence.projection_cut(), None);
}

#[test]
fn only_a_completed_fold_containing_the_whole_range_is_bound() {
    let timeline_id = timeline(1);
    let evidence = PipelineCommitEvidenceV1::committed(
        PipelineIngressV1::ScheduledAiDriver,
        ScheduledObservationProfileV1::ParticipantBound,
        receipt(timeline_id, 3, 5),
    );

    let partial = PipelineProjectionCutV1::new(timeline_id, Seq::from_u64(4));
    assert!(!partial.contains(evidence.committed_range()));
    assert_eq!(
        evidence
            .clone()
            .with_completed_fold(partial)
            .projection_cut(),
        None
    );

    let foreign = PipelineProjectionCutV1::new(timeline(2), Seq::from_u64(9));
    assert!(!foreign.contains(evidence.committed_range()));
    assert_eq!(
        evidence
            .clone()
            .with_completed_fold(foreign)
            .projection_cut(),
        None
    );

    let complete = PipelineProjectionCutV1::new(timeline_id, Seq::from_u64(5));
    assert_eq!(complete.timeline_id(), timeline_id);
    assert_eq!(complete.folded_through(), Seq::from_u64(5));
    let folded = evidence.with_completed_fold(complete);
    assert_eq!(folded.projection_cut(), Some(complete));
    assert_eq!(
        folded.observation_profile(),
        ScheduledObservationProfileV1::ParticipantBound,
        "binding a fold never changes the observation profile"
    );

    let later = PipelineProjectionCutV1::new(timeline_id, Seq::from_u64(8));
    assert!(later.contains(folded.committed_range()));
    assert_eq!(
        folded.with_completed_fold(later).projection_cut(),
        Some(complete),
        "the first completed fold remains the named cut"
    );
}
