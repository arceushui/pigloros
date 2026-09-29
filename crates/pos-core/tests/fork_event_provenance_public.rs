use ciborium::value::Value;
use pos_core::{
    CorrelationId, EntityId, EventId, EventOriginRecordInputV1, EventOriginRecordV1,
    ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAppendOperationInputV1,
    ForkAppendOperationV1, ForkAppendSourceIdentityV1, ForkAttributionOriginV1,
    ForkClassifiedEventV1, ForkClassifiedProvenanceV1, ForkClassifierRegistrationInputV1,
    ForkClassifierRegistrationV1, ForkClassifierSourceInputV1, ForkClassifierSourceV1,
    ForkClassifierTableInputV1, ForkClassifierTableV1, ForkEventAppendRequestV1,
    ForkEventClassificationV1, ForkEventClassifierV1, ForkEventOriginKindV1,
    ForkEventProvenanceErrorV1, ForkEventSourceDescriptorV1, ForkEventSourceV1,
    ForkExternalInputRouteV1, ForkInterventionAdmissionInputV1, ForkInterventionAdmissionV1, Hash,
    OwnerIdV1, TimelineId, WallTime, MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1,
};

const EOR1_HEX: &str = concat!(
    "8964454f52310150111111111111111111111111111111110950222222222222",
    "2222222222222222222201015820040404040404040404040404040404040404",
    "0404040404040404040404040404582005050505050505050505050505050505",
    "05050505050505050505050505050505",
);
const FIA1_HEX: &str = concat!(
    "8a64464941310158200606060606060606060606060606060606060606060606",
    "0606060606060606065011111111111111111111111111111111095022222222",
    "2222222222222222222222225820070707070707070707070707070707070707",
    "0707070707070707070707070707582008080808080808080808080808080808",
    "0808080808080808080808080808080858200404040404040404040404040404",
    "0404040404040404040404040404040404045820050505050505050505050505",
    "0505050505050505050505050505050505050505",
);

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

type DurableAppendRecords = (
    ForkClassifierSourceV1,
    ForkClassifierTableV1,
    ForkClassifierRegistrationV1,
    ForkEventAppendRequestV1,
    ForkAppendOperationV1,
);

fn durable_append_records() -> Result<DurableAppendRecords, ForkEventProvenanceErrorV1> {
    let child = TimelineId::new();
    let routes = vec![ForkExternalInputRouteV1::new(
        ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?,
        true,
    )];
    let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
        room_revision_descriptor_hash: hash(10),
        registrar_identifier: "host-registry.v1".to_owned(),
        routes: routes.clone(),
    })?;
    let table = ForkClassifierTableV1::new(ForkClassifierTableInputV1 {
        child_timeline_id: child,
        fork_admission_digest: hash(11),
        room_revision_descriptor_hash: hash(10),
        registrar_identifier: "host-registry.v1".to_owned(),
        source_configuration_revision_digest: source.digest(),
        routes,
    })?;
    let registration = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
        operation_id: hash(12),
        child_timeline_id: child,
        fork_admission_digest: hash(11),
        room_revision_descriptor_hash: hash(10),
        classifier_revision_digest: table.digest(),
    })?;
    let source_identity = ForkAppendSourceIdentityV1::ExternalInput {
        adapter_identifier: "gateway-adapter.v1".to_owned(),
        source: ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?,
    };
    let request = ForkEventAppendRequestV1::new(ForkEventAppendRequestV1 {
        operation_id: hash(13),
        child_timeline_id: child,
        source: source_identity.clone(),
        entity_id: EntityId::new(),
        event_type: "decision.intervened.v1".to_owned(),
        payload: vec![1, 2, 3],
        causation_id: Some(EventId::new()),
        correlation_id: Some(CorrelationId::new()),
        wall_time_override: Some(WallTime::from_micros(17)),
    })?;
    let operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
        operation_id: hash(13),
        child_timeline_id: child,
        logical_seq: 1,
        event_id: EventId::new(),
        request_digest: request.digest(),
        source: source_identity,
        wall_time: WallTime::from_micros(17),
        payload_hash: hash(14),
        classifier_revision_digest: table.digest(),
        fork_admission_digest: hash(11),
        event_origin_digest: hash(15),
        intervention_admission_digest: Some(hash(16)),
    })?;
    Ok((source, table, registration, request, operation))
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("odd golden hex length".into());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(bytes)
}

#[test]
fn eor1_and_fia1_match_fixed_public_bytes_and_digests() -> Result<(), Box<dyn std::error::Error>> {
    let origin = EventOriginRecordV1::new(EventOriginRecordInputV1 {
        fork_timeline_id: TimelineId::from_ulid(ulid::Ulid::from(u128::from_be_bytes([0x11; 16]))),
        logical_seq: 9,
        event_id: EventId::from_ulid(ulid::Ulid::from(u128::from_be_bytes([0x22; 16]))),
        classification: ForkEventClassificationV1::new(ForkEventOriginKindV1::ExternalInput, true)?,
        classifier_revision_digest: hash(4),
        fork_admission_digest: hash(5),
    })?;
    let intervention = intervention_record(&origin)?;
    assert_eq!(origin.to_canonical_cbor(), hex_bytes(EOR1_HEX)?);
    assert_eq!(intervention.to_canonical_cbor(), hex_bytes(FIA1_HEX)?);
    let mut binary_eor1_marker = hex_bytes(EOR1_HEX)?;
    binary_eor1_marker[1] = 0x44;
    assert!(EventOriginRecordV1::from_canonical_cbor(&binary_eor1_marker).is_err());
    let mut binary_fia1_marker = hex_bytes(FIA1_HEX)?;
    binary_fia1_marker[1] = 0x44;
    assert!(ForkInterventionAdmissionV1::from_canonical_cbor(&binary_fia1_marker).is_err());
    assert_eq!(
        origin.digest().as_bytes().to_vec(),
        hex_bytes("8ad16936dbd67c51c47b07d3d65047753eef4431a49dd6a37f523f1791c25e52")?
    );
    assert_eq!(
        intervention.digest().as_bytes().to_vec(),
        hex_bytes("3c99f7643d89dc0f97c37a91878ec1ff8293656d8efb68090a7dcd64a39eadf0")?
    );
    Ok(())
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

#[test]
fn durable_classifier_and_append_records_round_trip_at_public_seam(
) -> Result<(), Box<dyn std::error::Error>> {
    let (source, table, registration, request, operation) = durable_append_records()?;

    assert_eq!(
        ForkClassifierSourceV1::from_canonical_cbor(&source.to_canonical_cbor()),
        Ok(source)
    );
    assert_eq!(
        ForkClassifierTableV1::from_canonical_cbor(&table.to_canonical_cbor()),
        Ok(table)
    );
    assert_eq!(
        ForkClassifierRegistrationV1::from_canonical_cbor(&registration.to_canonical_cbor()),
        Ok(registration)
    );
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&request.to_canonical_cbor()),
        Ok(request.clone())
    );
    assert_eq!(
        ForkAppendOperationV1::from_canonical_cbor(&operation.to_canonical_cbor()),
        Ok(operation.clone())
    );
    assert_ne!(request.digest(), Hash::zero());
    assert_ne!(operation.digest(), Hash::zero());
    Ok(())
}

#[test]
fn durable_records_reject_binary_markers_at_public_seam() -> Result<(), Box<dyn std::error::Error>>
{
    let (source, table, registration, request, operation) = durable_append_records()?;
    let mut source_binary_marker = source.to_canonical_cbor();
    assert_eq!(source_binary_marker[1], 0x64);
    source_binary_marker[1] = 0x44;
    assert!(ForkClassifierSourceV1::from_canonical_cbor(&source_binary_marker).is_err());
    let mut table_binary_marker = table.to_canonical_cbor();
    assert_eq!(table_binary_marker[1], 0x64);
    table_binary_marker[1] = 0x44;
    assert!(ForkClassifierTableV1::from_canonical_cbor(&table_binary_marker).is_err());
    let mut registration_binary_marker = registration.to_canonical_cbor();
    assert_eq!(registration_binary_marker[1], 0x64);
    registration_binary_marker[1] = 0x44;
    assert!(
        ForkClassifierRegistrationV1::from_canonical_cbor(&registration_binary_marker).is_err()
    );
    let mut request_binary_marker = request.to_canonical_cbor();
    assert_eq!(request_binary_marker[1], 0x64);
    request_binary_marker[1] = 0x44;
    assert!(ForkEventAppendRequestV1::from_canonical_cbor(&request_binary_marker).is_err());
    let mut operation_binary_marker = operation.to_canonical_cbor();
    assert_eq!(operation_binary_marker[1], 0x64);
    operation_binary_marker[1] = 0x44;
    assert!(ForkAppendOperationV1::from_canonical_cbor(&operation_binary_marker).is_err());
    Ok(())
}

#[test]
fn append_records_reject_truncated_and_trailing_cbor() -> Result<(), Box<dyn std::error::Error>> {
    let (_, _, _, request, operation) = durable_append_records()?;
    let request_bytes = request.to_canonical_cbor();
    let mut request_trailing = request_bytes.clone();
    request_trailing.push(0);
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&request_bytes[..request_bytes.len() - 1]),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&request_trailing),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    let operation_bytes = operation.to_canonical_cbor();
    let mut operation_trailing = operation_bytes.clone();
    operation_trailing.push(0);
    assert_eq!(
        ForkAppendOperationV1::from_canonical_cbor(&operation_bytes[..operation_bytes.len() - 1]),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ForkAppendOperationV1::from_canonical_cbor(&operation_trailing),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn append_request_rejects_invalid_public_fields() -> Result<(), Box<dyn std::error::Error>> {
    let child = TimelineId::new();
    let descriptor = ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?;
    assert_eq!(
        ForkEventSourceDescriptorV1::new("", hash(2)),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkEventSourceDescriptorV1::new("gateway.action.v1", Hash::zero()),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let invalid_request = ForkEventAppendRequestV1 {
        operation_id: Hash::zero(),
        child_timeline_id: child,
        source: ForkAppendSourceIdentityV1::HostInternal,
        entity_id: EntityId::new(),
        event_type: "event.v1".to_owned(),
        payload: vec![],
        causation_id: None,
        correlation_id: None,
        wall_time_override: None,
    };
    assert_eq!(
        ForkEventAppendRequestV1::new(invalid_request),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkEventAppendRequestV1::new(ForkEventAppendRequestV1 {
            operation_id: hash(3),
            child_timeline_id: child,
            source: ForkAppendSourceIdentityV1::HostInternal,
            entity_id: EntityId::new(),
            event_type: String::new(),
            payload: vec![],
            causation_id: None,
            correlation_id: None,
            wall_time_override: None,
        }),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let request = ForkEventAppendRequestV1::new(ForkEventAppendRequestV1 {
        operation_id: hash(3),
        child_timeline_id: child,
        source: ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway.adapter.v1".to_owned(),
            source: descriptor,
        },
        entity_id: EntityId::new(),
        event_type: "event.v1".to_owned(),
        payload: vec![1],
        causation_id: None,
        correlation_id: None,
        wall_time_override: None,
    })?;
    let mut malformed = request.to_canonical_cbor();
    malformed[0] = 0x9f;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&malformed),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn append_operation_rejects_invalid_public_fields() -> Result<(), Box<dyn std::error::Error>> {
    let child = TimelineId::new();
    let descriptor = ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?;
    let request = ForkEventAppendRequestV1::new(ForkEventAppendRequestV1 {
        operation_id: hash(3),
        child_timeline_id: child,
        source: ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway.adapter.v1".to_owned(),
            source: descriptor,
        },
        entity_id: EntityId::new(),
        event_type: "event.v1".to_owned(),
        payload: vec![1],
        causation_id: None,
        correlation_id: None,
        wall_time_override: None,
    })?;
    let invalid_operation = ForkAppendOperationInputV1 {
        operation_id: hash(3),
        child_timeline_id: child,
        logical_seq: 0,
        event_id: EventId::new(),
        request_digest: request.digest(),
        source: request.source.clone(),
        wall_time: WallTime::from_micros(1),
        payload_hash: hash(4),
        classifier_revision_digest: hash(5),
        fork_admission_digest: hash(6),
        event_origin_digest: hash(7),
        intervention_admission_digest: None,
    };
    assert_eq!(
        ForkAppendOperationV1::new(invalid_operation),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let operation = ForkAppendOperationInputV1 {
        operation_id: hash(3),
        child_timeline_id: child,
        logical_seq: 1,
        event_id: EventId::new(),
        request_digest: request.digest(),
        source: request.source,
        wall_time: WallTime::from_micros(1),
        payload_hash: hash(4),
        classifier_revision_digest: hash(5),
        fork_admission_digest: hash(6),
        event_origin_digest: hash(7),
        intervention_admission_digest: None,
    };
    let mut zero_request_digest = operation.clone();
    zero_request_digest.request_digest = Hash::zero();
    assert_eq!(
        ForkAppendOperationV1::new(zero_request_digest),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut zero_payload_hash = operation.clone();
    zero_payload_hash.payload_hash = Hash::zero();
    assert_eq!(
        ForkAppendOperationV1::new(zero_payload_hash),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut zero_classifier_digest = operation.clone();
    zero_classifier_digest.classifier_revision_digest = Hash::zero();
    assert_eq!(
        ForkAppendOperationV1::new(zero_classifier_digest),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut zero_admission_digest = operation.clone();
    zero_admission_digest.fork_admission_digest = Hash::zero();
    assert_eq!(
        ForkAppendOperationV1::new(zero_admission_digest),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut zero_origin_digest = operation.clone();
    zero_origin_digest.event_origin_digest = Hash::zero();
    assert_eq!(
        ForkAppendOperationV1::new(zero_origin_digest),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut zero_intervention_digest = operation;
    zero_intervention_digest.intervention_admission_digest = Some(Hash::zero());
    assert_eq!(
        ForkAppendOperationV1::new(zero_intervention_digest),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn durable_classifier_records_reject_ambiguous_authority_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?;
    assert_eq!(
        ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: Hash::zero(),
            registrar_identifier: "host-registry.v1".to_owned(),
            routes: vec![],
        }),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: hash(10),
            registrar_identifier: "host-registry.v1".to_owned(),
            routes: vec![
                ForkExternalInputRouteV1::new(descriptor.clone(), true),
                ForkExternalInputRouteV1::new(descriptor, false),
            ],
        }),
        Err(ForkEventProvenanceErrorV1::DuplicateSourceRoute)
    );
    Ok(())
}

#[test]
fn append_evidence_covers_host_internal_and_null_optional_forms(
) -> Result<(), Box<dyn std::error::Error>> {
    let child = TimelineId::new();
    let request = ForkEventAppendRequestV1::new(ForkEventAppendRequestV1 {
        operation_id: hash(21),
        child_timeline_id: child,
        source: ForkAppendSourceIdentityV1::HostInternal,
        entity_id: EntityId::new(),
        event_type: "host.tick.v1".to_owned(),
        payload: vec![],
        causation_id: None,
        correlation_id: None,
        wall_time_override: None,
    })?;
    let operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
        operation_id: hash(21),
        child_timeline_id: child,
        logical_seq: 2,
        event_id: EventId::new(),
        request_digest: request.digest(),
        source: ForkAppendSourceIdentityV1::HostInternal,
        wall_time: WallTime::from_micros(18),
        payload_hash: hash(22),
        classifier_revision_digest: hash(23),
        fork_admission_digest: hash(24),
        event_origin_digest: hash(25),
        intervention_admission_digest: None,
    })?;

    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&request.to_canonical_cbor()),
        Ok(request)
    );
    assert_eq!(
        ForkAppendOperationV1::from_canonical_cbor(&operation.to_canonical_cbor()),
        Ok(operation)
    );
    Ok(())
}

fn incomplete_prefixes_fail_closed<T>(
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, ForkEventProvenanceErrorV1>,
) {
    for end in 0..bytes.len() {
        assert!(
            decode(&bytes[..end]).is_err(),
            "accepted incomplete prefix {end}"
        );
    }
}

#[test]
fn every_durable_provenance_codec_rejects_each_incomplete_prefix(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let intervention = intervention_record(&origin)?;
    let (source, table, registration, request, operation) = durable_append_records()?;

    incomplete_prefixes_fail_closed(
        &source.to_canonical_cbor(),
        ForkClassifierSourceV1::from_canonical_cbor,
    );
    incomplete_prefixes_fail_closed(
        &table.to_canonical_cbor(),
        ForkClassifierTableV1::from_canonical_cbor,
    );
    incomplete_prefixes_fail_closed(
        &registration.to_canonical_cbor(),
        ForkClassifierRegistrationV1::from_canonical_cbor,
    );
    incomplete_prefixes_fail_closed(
        &request.to_canonical_cbor(),
        ForkEventAppendRequestV1::from_canonical_cbor,
    );
    incomplete_prefixes_fail_closed(
        &operation.to_canonical_cbor(),
        ForkAppendOperationV1::from_canonical_cbor,
    );
    incomplete_prefixes_fail_closed(
        &origin.to_canonical_cbor(),
        EventOriginRecordV1::from_canonical_cbor,
    );
    incomplete_prefixes_fail_closed(
        &intervention.to_canonical_cbor(),
        ForkInterventionAdmissionV1::from_canonical_cbor,
    );
    Ok(())
}

#[test]
fn boundary_length_provenance_records_round_trip_at_public_seam(
) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = ForkEventSourceDescriptorV1::new("r".repeat(128), hash(31))?;
    let registrar_identifier = "a".repeat(64);
    let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
        room_revision_descriptor_hash: hash(32),
        registrar_identifier: registrar_identifier.clone(),
        routes: vec![ForkExternalInputRouteV1::new(descriptor.clone(), true)],
    })?;
    assert_eq!(
        ForkClassifierSourceV1::from_canonical_cbor(&source.to_canonical_cbor()),
        Ok(source)
    );

    let request = ForkEventAppendRequestV1::new(ForkEventAppendRequestV1 {
        operation_id: hash(33),
        child_timeline_id: TimelineId::new(),
        source: ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: registrar_identifier,
            source: descriptor,
        },
        entity_id: EntityId::new(),
        event_type: "e".repeat(256),
        payload: vec![0x7a; 65_536],
        causation_id: Some(EventId::new()),
        correlation_id: Some(CorrelationId::new()),
        wall_time_override: Some(WallTime::from_micros(u64::from(u32::MAX) + 1)),
    })?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&request.to_canonical_cbor()),
        Ok(request)
    );
    Ok(())
}

#[test]
fn classifier_custody_maximum_routes_round_trips_and_binds_digests(
) -> Result<(), Box<dyn std::error::Error>> {
    let routes = (0..MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1)
        .map(|index| {
            Ok(ForkExternalInputRouteV1::new(
                ForkEventSourceDescriptorV1::new(format!("route-{index:04}.v1"), hash(41))?,
                index.is_multiple_of(2),
            ))
        })
        .collect::<Result<Vec<_>, ForkEventProvenanceErrorV1>>()?;
    let child_timeline_id = TimelineId::new();
    let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
        room_revision_descriptor_hash: hash(42),
        registrar_identifier: "host-registry.v1".to_owned(),
        routes: routes.clone(),
    })?;
    let table = ForkClassifierTableV1::new(ForkClassifierTableInputV1 {
        child_timeline_id,
        fork_admission_digest: hash(43),
        room_revision_descriptor_hash: hash(42),
        registrar_identifier: "host-registry.v1".to_owned(),
        source_configuration_revision_digest: source.digest(),
        routes,
    })?;
    let registration = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
        operation_id: hash(44),
        child_timeline_id,
        fork_admission_digest: hash(43),
        room_revision_descriptor_hash: hash(42),
        classifier_revision_digest: table.digest(),
    })?;

    let decoded_source = ForkClassifierSourceV1::from_canonical_cbor(&source.to_canonical_cbor())?;
    let decoded_table = ForkClassifierTableV1::from_canonical_cbor(&table.to_canonical_cbor())?;
    let decoded_registration =
        ForkClassifierRegistrationV1::from_canonical_cbor(&registration.to_canonical_cbor())?;
    assert_eq!(decoded_source, source);
    assert_eq!(
        decoded_source.digest(),
        table.input().source_configuration_revision_digest
    );
    assert_eq!(decoded_table, table);
    assert_eq!(
        decoded_table.digest(),
        registration.input().classifier_revision_digest
    );
    assert_eq!(decoded_registration, registration);

    let classifier =
        ForkEventClassifierV1::new(decoded_table.digest(), decoded_table.input().routes.clone())?;
    let first = ForkEventSourceV1::ExternalInput(ForkEventSourceDescriptorV1::new(
        "route-0000.v1",
        hash(41),
    )?);
    let last_route = format!("route-{:04}.v1", MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1 - 1);
    let last =
        ForkEventSourceV1::ExternalInput(ForkEventSourceDescriptorV1::new(last_route, hash(41))?);
    assert_eq!(
        classifier.classify(&first)?,
        ForkEventClassificationV1::new(ForkEventOriginKindV1::ExternalInput, true)?
    );
    assert_eq!(
        classifier.classify(&last)?,
        ForkEventClassificationV1::new(ForkEventOriginKindV1::ExternalInput, false)?
    );
    Ok(())
}

#[test]
fn classifier_custody_constructors_reject_each_missing_authority_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let (source, table, _registration, _, _) = durable_append_records()?;
    let descriptor = ForkEventSourceDescriptorV1::new("route.v1", hash(41))?;

    assert_eq!(
        ForkEventSourceDescriptorV1::new("r".repeat(129), hash(41)),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: hash(42),
            registrar_identifier: String::new(),
            routes: vec![],
        }),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: hash(42),
            registrar_identifier: "r".repeat(65),
            routes: vec![],
        }),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: hash(42),
            registrar_identifier: "registrar.v1".to_owned(),
            routes: vec![ForkExternalInputRouteV1::new(descriptor, false); 1025],
        }),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );

    let mut missing_admission = table.input().clone();
    missing_admission.fork_admission_digest = Hash::zero();
    assert_eq!(
        ForkClassifierTableV1::new(missing_admission),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut missing_source_revision = table.input().clone();
    missing_source_revision.source_configuration_revision_digest = Hash::zero();
    assert_eq!(
        ForkClassifierTableV1::new(missing_source_revision),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkEventClassifierV1::new(Hash::zero(), vec![]),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        source.input().routes[0].source().route(),
        "gateway.action.v1"
    );
    assert!(source.input().routes[0].intervention());
    assert_eq!(classifier()?.revision_digest(), hash(1));
    Ok(())
}

#[test]
fn registration_and_origin_constructors_reject_each_missing_digest(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let intervention = intervention_record(&origin)?;
    let (_, _, registration, _, _) = durable_append_records()?;

    let mut missing_operation = registration.input().clone();
    missing_operation.operation_id = Hash::zero();
    assert_eq!(
        ForkClassifierRegistrationV1::new(missing_operation),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut missing_admission = registration.input().clone();
    missing_admission.fork_admission_digest = Hash::zero();
    assert_eq!(
        ForkClassifierRegistrationV1::new(missing_admission),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut missing_room = registration.input().clone();
    missing_room.room_revision_descriptor_hash = Hash::zero();
    assert_eq!(
        ForkClassifierRegistrationV1::new(missing_room),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut missing_classifier = registration.input().clone();
    missing_classifier.classifier_revision_digest = Hash::zero();
    assert_eq!(
        ForkClassifierRegistrationV1::new(missing_classifier),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );

    let mut missing_origin_classifier = origin.input().clone();
    missing_origin_classifier.classifier_revision_digest = Hash::zero();
    assert_eq!(
        EventOriginRecordV1::new(missing_origin_classifier),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut missing_origin_admission = origin.input().clone();
    missing_origin_admission.fork_admission_digest = Hash::zero();
    assert_eq!(
        EventOriginRecordV1::new(missing_origin_admission),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );

    let mut missing_payload = intervention.input().clone();
    missing_payload.payload_hash = Hash::zero();
    assert_eq!(
        ForkInterventionAdmissionV1::new(missing_payload),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut missing_room = intervention.input().clone();
    missing_room.room_revision_descriptor_hash = Hash::zero();
    assert_eq!(
        ForkInterventionAdmissionV1::new(missing_room),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut missing_classifier = intervention.input().clone();
    missing_classifier.classifier_revision_digest = Hash::zero();
    assert_eq!(
        ForkInterventionAdmissionV1::new(missing_classifier),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut missing_admission = intervention.input().clone();
    missing_admission.fork_admission_digest = Hash::zero();
    assert_eq!(
        ForkInterventionAdmissionV1::new(missing_admission),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn append_request_rejects_invalid_external_identity_and_maximum_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, _, _, request, operation) = durable_append_records()?;
    let mut missing_adapter = request.clone();
    missing_adapter.source = ForkAppendSourceIdentityV1::ExternalInput {
        adapter_identifier: String::new(),
        source: ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?,
    };
    assert_eq!(
        ForkEventAppendRequestV1::new(missing_adapter),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut overlong_adapter = request.clone();
    overlong_adapter.source = ForkAppendSourceIdentityV1::ExternalInput {
        adapter_identifier: "a".repeat(65),
        source: ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?,
    };
    assert_eq!(
        ForkEventAppendRequestV1::new(overlong_adapter),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut overlong_event_type = request;
    overlong_event_type.event_type = "e".repeat(257);
    assert_eq!(
        ForkEventAppendRequestV1::new(overlong_event_type),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );

    let mut missing_operation = operation.input().clone();
    missing_operation.operation_id = Hash::zero();
    assert_eq!(
        ForkAppendOperationV1::new(missing_operation),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut missing_source = operation.input().clone();
    missing_source.source = ForkAppendSourceIdentityV1::ExternalInput {
        adapter_identifier: String::new(),
        source: ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?,
    };
    assert_eq!(
        ForkAppendOperationV1::new(missing_source),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

fn mutate_record(
    bytes: &[u8],
    mutate: impl FnOnce(&mut Vec<Value>),
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value: Value = ciborium::from_reader(bytes)?;
    let Value::Array(fields) = &mut value else {
        return Err("durable record was not an array".into());
    };
    mutate(fields);
    let mut changed = Vec::new();
    ciborium::into_writer(&value, &mut changed)?;
    Ok(changed)
}

#[test]
fn durable_provenance_decoders_reject_malformed_semantic_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let (source, _, _, request, operation) = durable_append_records()?;

    let wrong_magic = mutate_record(&origin.to_canonical_cbor(), |fields| {
        fields[0] = Value::Text("XXXX".to_owned());
    })?;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&wrong_magic),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    let unsupported_version = mutate_record(&origin.to_canonical_cbor(), |fields| {
        fields[1] = Value::Integer(2.into());
    })?;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&unsupported_version),
        Err(ForkEventProvenanceErrorV1::UnsupportedVersion)
    );
    let unavailable_origin = mutate_record(&origin.to_canonical_cbor(), |fields| {
        fields[5] = Value::Integer(2.into());
    })?;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&unavailable_origin),
        Err(ForkEventProvenanceErrorV1::ImportedAuthorityUnavailable)
    );
    let invalid_intervention = mutate_record(&origin.to_canonical_cbor(), |fields| {
        fields[6] = Value::Integer(2.into());
    })?;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&invalid_intervention),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );

    let empty_registrar = mutate_record(&source.to_canonical_cbor(), |fields| {
        fields[3] = Value::Text(String::new());
    })?;
    assert_eq!(
        ForkClassifierSourceV1::from_canonical_cbor(&empty_registrar),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut invalid_route_bool = source.to_canonical_cbor();
    *invalid_route_bool
        .last_mut()
        .ok_or("canonical FCS1 must contain a route disposition")? = 2;
    assert_eq!(
        ForkClassifierSourceV1::from_canonical_cbor(&invalid_route_bool),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );

    let invalid_host_source = mutate_record(&request.to_canonical_cbor(), |fields| {
        fields[4] = Value::Array(vec![Value::Integer(1.into())]);
    })?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&invalid_host_source),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    let unknown_source_shape = mutate_record(&request.to_canonical_cbor(), |fields| {
        fields[4] = Value::Array(vec![Value::Integer(0.into()), Value::Integer(0.into())]);
    })?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&unknown_source_shape),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    let wrong_hash_length = mutate_record(&operation.to_canonical_cbor(), |fields| {
        fields[2] = Value::Bytes(vec![1]);
    })?;
    assert_eq!(
        ForkAppendOperationV1::from_canonical_cbor(&wrong_hash_length),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn durable_provenance_decoders_recheck_required_fields_after_parsing(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let intervention = intervention_record(&origin)?;
    let (source, table, registration, request, operation) = durable_append_records()?;
    let zero_hash = Value::Bytes(vec![0; 32]);
    let invalid_source = mutate_record(&source.to_canonical_cbor(), |fields| {
        fields[2] = zero_hash.clone();
    })?;
    assert_eq!(
        ForkClassifierSourceV1::from_canonical_cbor(&invalid_source),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let invalid_table = mutate_record(&table.to_canonical_cbor(), |fields| {
        fields[6] = zero_hash.clone();
    })?;
    assert_eq!(
        ForkClassifierTableV1::from_canonical_cbor(&invalid_table),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let invalid_registration = mutate_record(&registration.to_canonical_cbor(), |fields| {
        fields[2] = zero_hash.clone();
    })?;
    assert_eq!(
        ForkClassifierRegistrationV1::from_canonical_cbor(&invalid_registration),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let invalid_request = mutate_record(&request.to_canonical_cbor(), |fields| {
        fields[2] = zero_hash.clone();
    })?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&invalid_request),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let invalid_operation = mutate_record(&operation.to_canonical_cbor(), |fields| {
        fields[6] = zero_hash.clone();
    })?;
    assert_eq!(
        ForkAppendOperationV1::from_canonical_cbor(&invalid_operation),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let invalid_origin = mutate_record(&origin.to_canonical_cbor(), |fields| {
        fields[3] = Value::Integer(0.into());
    })?;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&invalid_origin),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let invalid_intervention = mutate_record(&intervention.to_canonical_cbor(), |fields| {
        fields[6] = zero_hash;
    })?;
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&invalid_intervention),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn durable_provenance_decoders_reject_invalid_utf8_and_oversize_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let (source, table, registration, request, operation) = durable_append_records()?;
    let mut invalid_utf8 = source.to_canonical_cbor();
    let route_offset = invalid_utf8
        .windows("gateway.action.v1".len())
        .position(|window| window == b"gateway.action.v1")
        .ok_or("route literal missing from FCS1")?;
    invalid_utf8[route_offset] = 0xff;
    assert_eq!(
        ForkClassifierSourceV1::from_canonical_cbor(&invalid_utf8),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );

    assert_oversized(
        source.to_canonical_cbor(),
        ForkClassifierSourceV1::from_canonical_cbor,
    );
    assert_oversized(
        table.to_canonical_cbor(),
        ForkClassifierTableV1::from_canonical_cbor,
    );
    assert_oversized(
        registration.to_canonical_cbor(),
        ForkClassifierRegistrationV1::from_canonical_cbor,
    );
    assert_oversized(
        operation.to_canonical_cbor(),
        ForkAppendOperationV1::from_canonical_cbor,
    );
    assert_oversized(
        request.to_canonical_cbor(),
        ForkEventAppendRequestV1::from_canonical_cbor,
    );
    Ok(())
}

fn assert_oversized<T>(
    mut bytes: Vec<u8>,
    decode: impl Fn(&[u8]) -> Result<T, ForkEventProvenanceErrorV1>,
) {
    bytes.resize(16_778_001, 0);
    assert_eq!(
        decode(&bytes).err(),
        Some(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
}

fn assert_trailing_bytes_rejected<T>(
    mut bytes: Vec<u8>,
    decode: impl Fn(&[u8]) -> Result<T, ForkEventProvenanceErrorV1>,
) {
    bytes.push(0);
    assert_eq!(
        decode(&bytes).err(),
        Some(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
}

#[test]
fn durable_provenance_decoders_reject_trailing_and_incomplete_table_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let intervention = intervention_record(&origin)?;
    let (source, table, registration, request, operation) = durable_append_records()?;

    assert_trailing_bytes_rejected(
        source.to_canonical_cbor(),
        ForkClassifierSourceV1::from_canonical_cbor,
    );
    assert_trailing_bytes_rejected(
        table.to_canonical_cbor(),
        ForkClassifierTableV1::from_canonical_cbor,
    );
    assert_trailing_bytes_rejected(
        registration.to_canonical_cbor(),
        ForkClassifierRegistrationV1::from_canonical_cbor,
    );
    assert_trailing_bytes_rejected(
        request.to_canonical_cbor(),
        ForkEventAppendRequestV1::from_canonical_cbor,
    );
    assert_trailing_bytes_rejected(
        operation.to_canonical_cbor(),
        ForkAppendOperationV1::from_canonical_cbor,
    );
    assert_trailing_bytes_rejected(
        origin.to_canonical_cbor(),
        EventOriginRecordV1::from_canonical_cbor,
    );
    assert_trailing_bytes_rejected(
        intervention.to_canonical_cbor(),
        ForkInterventionAdmissionV1::from_canonical_cbor,
    );

    let wrong_field_count = mutate_record(&source.to_canonical_cbor(), |fields| {
        fields.pop();
    })?;
    assert_eq!(
        ForkClassifierSourceV1::from_canonical_cbor(&wrong_field_count),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    let too_many_routes = mutate_record(&source.to_canonical_cbor(), |fields| {
        let first_route = match &fields[4] {
            Value::Array(routes) => routes.first().cloned(),
            _ => None,
        };
        if let Some(route) = first_route {
            fields[4] = Value::Array(vec![route; 1025]);
        }
    })?;
    assert_eq!(
        ForkClassifierSourceV1::from_canonical_cbor(&too_many_routes),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let zero_route_schema = mutate_record(&source.to_canonical_cbor(), |fields| {
        if let Value::Array(routes) = &mut fields[4] {
            if let Value::Array(route) = &mut routes[0] {
                route[1] = Value::Bytes(vec![0; 32]);
            }
        }
    })?;
    assert_eq!(
        ForkClassifierSourceV1::from_canonical_cbor(&zero_route_schema),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn append_provenance_decoders_reject_every_source_and_payload_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let (_, _, _, request, _) = durable_append_records()?;

    let external_source_wrong_tag = mutate_record(&request.to_canonical_cbor(), |fields| {
        fields[4] = Value::Array(vec![
            Value::Integer(0.into()),
            Value::Text("adapter.v1".to_owned()),
            Value::Text("gateway.action.v1".to_owned()),
            Value::Bytes(hash(2).as_bytes().to_vec()),
        ]);
    })?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&external_source_wrong_tag),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    let external_source_short_schema = mutate_record(&request.to_canonical_cbor(), |fields| {
        fields[4] = Value::Array(vec![
            Value::Integer(1.into()),
            Value::Text("adapter.v1".to_owned()),
            Value::Text("gateway.action.v1".to_owned()),
            Value::Bytes(vec![1]),
        ]);
    })?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&external_source_short_schema),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    let external_source_empty_adapter = mutate_record(&request.to_canonical_cbor(), |fields| {
        fields[4] = Value::Array(vec![
            Value::Integer(1.into()),
            Value::Text(String::new()),
            Value::Text("gateway.action.v1".to_owned()),
            Value::Bytes(hash(2).as_bytes().to_vec()),
        ]);
    })?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&external_source_empty_adapter),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let invalid_origin = mutate_record(&origin.to_canonical_cbor(), |fields| {
        fields[5] = Value::Integer(3.into());
    })?;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&invalid_origin),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );

    let mut oversized_payload = request.to_canonical_cbor();
    let payload = [0x43, 1, 2, 3];
    let offset = oversized_payload
        .windows(payload.len())
        .position(|window| window == payload)
        .ok_or("FEQ1 payload literal missing")?;
    oversized_payload.splice(offset..=offset, [0x5a, 1, 0, 0, 1]);
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&oversized_payload),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn provenance_codecs_round_trip_large_integer_and_payload_encodings(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let mut origin_input = origin.input().clone();
    origin_input.logical_seq = u64::MAX;
    let origin = EventOriginRecordV1::new(origin_input)?;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&origin.to_canonical_cbor())?,
        origin
    );

    let intervention = intervention_record(&origin)?;
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&intervention.to_canonical_cbor())?,
        intervention
    );

    let (_, _, _, mut request, operation) = durable_append_records()?;
    request.event_type = "e".repeat(256);
    request.payload = vec![0xab; 65_536];
    request.wall_time_override = Some(WallTime::from_micros(u64::MAX));
    let request = ForkEventAppendRequestV1::new(request)?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&request.to_canonical_cbor())?,
        request
    );

    let mut operation_input = operation.input().clone();
    operation_input.logical_seq = u64::MAX;
    operation_input.wall_time = WallTime::from_micros(u64::MAX);
    let operation = ForkAppendOperationV1::new(operation_input)?;
    assert_eq!(
        ForkAppendOperationV1::from_canonical_cbor(&operation.to_canonical_cbor())?,
        operation
    );
    Ok(())
}

fn classified_event() -> ForkClassifiedEventV1 {
    ForkClassifiedEventV1 {
        event_id: EventId::new(),
        logical_seq: 4,
        wall_time: WallTime::from_micros(17),
        payload_hash: hash(14),
    }
}

#[test]
fn classified_provenance_derivation_binds_table_request_and_event(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, table, _, request, _) = durable_append_records()?;
    let classifier = ForkEventClassifierV1::from_table(&table);
    assert_eq!(classifier.revision_digest(), table.digest());
    let classification = classifier.classify_identity(&request.source)?;
    assert_eq!(
        classification,
        ForkEventClassificationV1::new(ForkEventOriginKindV1::ExternalInput, true)?
    );
    assert_eq!(
        classifier.classify_identity(&ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway-adapter.v1".to_owned(),
            source: ForkEventSourceDescriptorV1::new("gateway.unknown.v1", hash(2))?,
        }),
        Err(ForkEventProvenanceErrorV1::SourceRejected)
    );
    let derived =
        ForkClassifiedProvenanceV1::derive(&request, &table, classification, classified_event())?;
    let intervention = derived
        .intervention
        .clone()
        .ok_or("external intervention requires FIA1")?;
    assert_eq!(derived.origin.input().classification, classification);
    assert_eq!(intervention.input().room_revision_descriptor_hash, hash(10));
    assert_eq!(derived.operation.input().request_digest, request.digest());
    assert_eq!(
        derived.operation.input().event_origin_digest,
        derived.origin.digest()
    );
    assert_eq!(
        derived.operation.input().intervention_admission_digest,
        Some(intervention.digest())
    );
    assert_eq!(
        ForkAppendOperationV1::from_canonical_cbor(&derived.operation.to_canonical_cbor())?,
        derived.operation
    );
    assert_eq!(
        derived
            .operation
            .expected_provenance(&table, classification),
        (derived.origin, derived.intervention)
    );

    let host_source = ForkAppendSourceIdentityV1::HostInternal;
    let host = ForkClassifiedProvenanceV1::derive(
        &ForkEventAppendRequestV1 {
            source: host_source.clone(),
            ..request
        },
        &table,
        classifier.classify_identity(&host_source)?,
        classified_event(),
    )?;
    assert!(host.intervention.is_none());
    assert_eq!(host.operation.input().intervention_admission_digest, None);
    Ok(())
}

#[test]
fn classified_provenance_derivation_rejects_incomplete_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let (source, table, _, request, _) = durable_append_records()?;
    let classification =
        ForkEventClassifierV1::from_table(&table).classify_identity(&request.source)?;
    let event = classified_event();
    for (candidate, candidate_event) in [
        (
            ForkEventAppendRequestV1 {
                child_timeline_id: TimelineId::new(),
                ..request.clone()
            },
            event,
        ),
        (
            ForkEventAppendRequestV1 {
                operation_id: Hash::zero(),
                ..request.clone()
            },
            event,
        ),
        (
            request.clone(),
            ForkClassifiedEventV1 {
                logical_seq: 0,
                ..event
            },
        ),
        (
            request.clone(),
            ForkClassifiedEventV1 {
                payload_hash: Hash::zero(),
                ..event
            },
        ),
        (
            ForkEventAppendRequestV1 {
                source: ForkAppendSourceIdentityV1::ExternalInput {
                    adapter_identifier: String::new(),
                    source: ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?,
                },
                ..request
            },
            event,
        ),
    ] {
        assert_eq!(
            ForkClassifiedProvenanceV1::derive(&candidate, &table, classification, candidate_event),
            Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
        );
    }

    let admission = ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
        operation_id: hash(20),
        principal_owner_binding_digest: hash(21),
        creator: OwnerIdV1::from_static("test-owner"),
        parent_timeline_id: TimelineId::new(),
        child_timeline_id: table.input().child_timeline_id,
        room_revision_descriptor_hash: hash(10),
        parent_logical_head: 0,
        parent_chain_head_hash: hash(22),
        completed_fold_cursor: 0,
        post_fold_tick_boundary: 0,
        plugin_composition_hash: hash(23),
        attribution_required: false,
        origin: ForkAttributionOriginV1::Local,
    })?;
    assert_eq!(
        ForkClassifierTableV1::for_admitted_source(&admission, &source),
        ForkClassifierTableV1::new(ForkClassifierTableInputV1 {
            child_timeline_id: table.input().child_timeline_id,
            fork_admission_digest: admission.digest(),
            room_revision_descriptor_hash: hash(10),
            registrar_identifier: source.input().registrar_identifier.clone(),
            source_configuration_revision_digest: source.digest(),
            routes: source.input().routes.clone(),
        })?
    );
    Ok(())
}

#[test]
fn origin_and_intervention_decoders_reject_oversize_and_impossible_forms(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let intervention = intervention_record(&origin)?;
    assert_oversized(
        origin.to_canonical_cbor(),
        EventOriginRecordV1::from_canonical_cbor,
    );
    assert_oversized(
        intervention.to_canonical_cbor(),
        ForkInterventionAdmissionV1::from_canonical_cbor,
    );
    let host_internal_intervention = mutate_record(&origin.to_canonical_cbor(), |fields| {
        fields[5] = Value::Integer(0.into());
        fields[6] = Value::Integer(1.into());
    })?;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&host_internal_intervention),
        Err(ForkEventProvenanceErrorV1::ImpossibleClassification)
    );
    Ok(())
}

#[test]
fn append_and_table_seams_reject_malformed_source_and_registrar(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, table, _, request, _) = durable_append_records()?;
    let host_source_text_tag = mutate_record(&request.to_canonical_cbor(), |fields| {
        fields[4] = Value::Array(vec![Value::Text("host".to_owned())]);
    })?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&host_source_text_tag),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    let external_source_zero_schema = mutate_record(&request.to_canonical_cbor(), |fields| {
        fields[4] = Value::Array(vec![
            Value::Integer(1.into()),
            Value::Text("adapter.v1".to_owned()),
            Value::Text("gateway.action.v1".to_owned()),
            Value::Bytes(vec![0; 32]),
        ]);
    })?;
    assert_eq!(
        ForkEventAppendRequestV1::from_canonical_cbor(&external_source_zero_schema),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut empty_registrar = table.input().clone();
    empty_registrar.registrar_identifier = String::new();
    assert_eq!(
        ForkClassifierTableV1::new(empty_registrar),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    Ok(())
}
