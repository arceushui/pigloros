use pos_core::{
    EventId, EventOriginRecordInputV1, EventOriginRecordV1, ForkEventClassificationV1,
    ForkEventClassifierV1, ForkEventOriginKindV1, ForkEventProvenanceErrorV1,
    ForkEventSourceDescriptorV1, ForkEventSourceV1, ForkExternalInputRouteV1,
    ForkInterventionAdmissionInputV1, ForkInterventionAdmissionV1, Hash, TimelineId,
};

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn classifier() -> Result<ForkEventClassifierV1, ForkEventProvenanceErrorV1> {
    ForkEventClassifierV1::new(
        hash(1),
        vec![
            ForkExternalInputRouteV1::new(
                ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?,
                true,
            ),
            ForkExternalInputRouteV1::new(
                ForkEventSourceDescriptorV1::new("bridge.sample.v1", hash(3))?,
                false,
            ),
        ],
    )
}

fn origin_record() -> Result<EventOriginRecordV1, ForkEventProvenanceErrorV1> {
    EventOriginRecordV1::new(EventOriginRecordInputV1 {
        fork_timeline_id: TimelineId::new(),
        logical_seq: 9,
        event_id: EventId::new(),
        classification: ForkEventClassificationV1::new(ForkEventOriginKindV1::ExternalInput, true)?,
        classifier_revision_digest: hash(4),
        fork_admission_digest: hash(5),
    })
}

fn intervention_record(
    origin: &EventOriginRecordV1,
) -> Result<ForkInterventionAdmissionV1, ForkEventProvenanceErrorV1> {
    ForkInterventionAdmissionV1::new(ForkInterventionAdmissionInputV1 {
        operation_id: hash(6),
        fork_timeline_id: origin.input().fork_timeline_id,
        logical_seq: origin.input().logical_seq,
        event_id: origin.input().event_id,
        payload_hash: hash(7),
        room_revision_descriptor_hash: hash(8),
        classifier_revision_digest: origin.input().classifier_revision_digest,
        fork_admission_digest: origin.input().fork_admission_digest,
    })
}

#[test]
fn eor1_and_fia1_round_trip_at_public_seam() -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let intervention = intervention_record(&origin)?;

    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&origin.to_canonical_cbor()),
        Ok(origin.clone())
    );
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&intervention.to_canonical_cbor()),
        Ok(intervention.clone())
    );
    assert_ne!(origin.digest(), Hash::zero());
    assert_ne!(intervention.digest(), Hash::zero());
    Ok(())
}

#[test]
fn classifier_is_total_for_internal_and_admitted_external_sources(
) -> Result<(), Box<dyn std::error::Error>> {
    let classifier = classifier()?;
    assert_eq!(
        classifier.classify(&ForkEventSourceV1::HostInternal)?,
        ForkEventClassificationV1::new(ForkEventOriginKindV1::HostInternal, false)?
    );

    let intervention_source = ForkEventSourceV1::ExternalInput(ForkEventSourceDescriptorV1::new(
        "gateway.action.v1",
        hash(2),
    )?);
    assert_eq!(
        classifier.classify(&intervention_source)?,
        ForkEventClassificationV1::new(ForkEventOriginKindV1::ExternalInput, true)?
    );

    let non_intervention_source = ForkEventSourceV1::ExternalInput(
        ForkEventSourceDescriptorV1::new("bridge.sample.v1", hash(3))?,
    );
    assert_eq!(
        classifier.classify(&non_intervention_source)?,
        ForkEventClassificationV1::new(ForkEventOriginKindV1::ExternalInput, false)?
    );
    Ok(())
}

#[test]
fn classifier_rejects_unknown_and_duplicate_external_source_descriptors(
) -> Result<(), Box<dyn std::error::Error>> {
    let classifier = classifier()?;
    let unknown = ForkEventSourceV1::ExternalInput(ForkEventSourceDescriptorV1::new(
        "gateway.action.v1",
        hash(99),
    )?);
    assert_eq!(
        classifier.classify(&unknown),
        Err(ForkEventProvenanceErrorV1::SourceRejected)
    );

    let duplicated = ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?;
    assert_eq!(
        ForkEventClassifierV1::new(
            hash(1),
            vec![
                ForkExternalInputRouteV1::new(duplicated.clone(), true),
                ForkExternalInputRouteV1::new(duplicated, false),
            ],
        ),
        Err(ForkEventProvenanceErrorV1::DuplicateSourceRoute)
    );
    Ok(())
}

#[test]
fn eor1_rejects_impossible_imported_and_noncanonical_forms(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        ForkEventClassificationV1::new(ForkEventOriginKindV1::HostInternal, true),
        Err(ForkEventProvenanceErrorV1::ImpossibleClassification)
    );

    let origin = origin_record()?;
    let canonical = origin.to_canonical_cbor();
    let mut imported = canonical.clone();
    imported[42] = 2;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&imported),
        Err(ForkEventProvenanceErrorV1::ImportedAuthorityUnavailable)
    );

    let mut noncanonical = canonical;
    noncanonical[24] = 0x18;
    noncanonical.insert(25, 9);
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&noncanonical),
        Err(ForkEventProvenanceErrorV1::NonCanonical)
    );
    Ok(())
}

#[test]
fn records_reject_absent_required_fields() -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let mut origin_input = origin.input().clone();
    origin_input.logical_seq = 0;
    assert_eq!(
        EventOriginRecordV1::new(origin_input),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );

    let intervention = intervention_record(&origin)?;
    let mut intervention_input = intervention.input().clone();
    intervention_input.operation_id = Hash::zero();
    assert_eq!(
        ForkInterventionAdmissionV1::new(intervention_input),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    Ok(())
}
