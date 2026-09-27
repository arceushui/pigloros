use pos_core::{
    EventId, EventOriginRecordInputV1, EventOriginRecordV1, ForkEventClassificationV1,
    ForkEventClassifierV1, ForkEventOriginKindV1, ForkEventProvenanceErrorV1,
    ForkEventSourceDescriptorV1, ForkEventSourceV1, ForkExternalInputRouteV1,
    ForkInterventionAdmissionInputV1, ForkInterventionAdmissionV1, Hash, TimelineId,
    MAX_EVENT_ORIGIN_RECORD_BYTES_V1, MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1,
    MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1,
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
    const EOR1_HEX: &str = concat!(
        "8944454f52310150111111111111111111111111111111110950222222222222",
        "2222222222222222222201015820040404040404040404040404040404040404",
        "0404040404040404040404040404582005050505050505050505050505050505",
        "05050505050505050505050505050505",
    );
    const FIA1_HEX: &str = concat!(
        "8a44464941310158200606060606060606060606060606060606060606060606",
        "0606060606060606065011111111111111111111111111111111095022222222",
        "2222222222222222222222225820070707070707070707070707070707070707",
        "0707070707070707070707070707582008080808080808080808080808080808",
        "0808080808080808080808080808080858200404040404040404040404040404",
        "0404040404040404040404040404040404045820050505050505050505050505",
        "0505050505050505050505050505050505050505",
    );
    assert_eq!(origin.to_canonical_cbor(), hex_bytes(EOR1_HEX)?);
    assert_eq!(intervention.to_canonical_cbor(), hex_bytes(FIA1_HEX)?);
    assert_eq!(
        origin.digest().as_bytes().to_vec(),
        hex_bytes("a786d528859cd46b43577c4bfeba6ac29681ae326ddb185ce11beedb2be82b31")?
    );
    assert_eq!(
        intervention.digest().as_bytes().to_vec(),
        hex_bytes("4a98f9d3afe615e35d6a5bb3c488083b6a13699898611377d4ddb076ca2988f1")?
    );
    Ok(())
}

#[test]
fn eor1_and_fia1_round_trip_at_public_seam() -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let intervention = intervention_record(&origin)?;
    let host_origin = EventOriginRecordV1::new(EventOriginRecordInputV1 {
        classification: ForkEventClassificationV1::new(ForkEventOriginKindV1::HostInternal, false)?,
        ..origin.input().clone()
    })?;

    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&origin.to_canonical_cbor()),
        Ok(origin.clone())
    );
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&intervention.to_canonical_cbor()),
        Ok(intervention.clone())
    );
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&host_origin.to_canonical_cbor()),
        Ok(host_origin)
    );
    assert_ne!(origin.digest(), Hash::zero());
    assert_ne!(intervention.digest(), Hash::zero());
    Ok(())
}

#[test]
fn classifier_is_total_for_internal_and_admitted_external_sources(
) -> Result<(), Box<dyn std::error::Error>> {
    let classifier = classifier()?;
    assert_eq!(classifier.revision_digest(), hash(1));
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
fn public_accessors_and_all_constructor_bounds_are_enforced(
) -> Result<(), Box<dyn std::error::Error>> {
    let source = ForkEventSourceDescriptorV1::new("gateway.action.v1", hash(2))?;
    assert_eq!(source.route(), "gateway.action.v1");
    assert_eq!(source.schema_digest(), hash(2));
    assert_eq!(
        ForkEventSourceDescriptorV1::new("", hash(2)),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkEventSourceDescriptorV1::new(
            "x".repeat(MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1 + 1),
            hash(2),
        ),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ForkEventSourceDescriptorV1::new("gateway.action.v1", Hash::zero()),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );

    let route = ForkExternalInputRouteV1::new(source.clone(), true);
    assert_eq!(route.source(), &source);
    assert!(route.intervention());
    assert_eq!(
        ForkEventClassifierV1::new(Hash::zero(), vec![route]),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );

    let origin = origin_record()?;
    for invalid in [
        EventOriginRecordInputV1 {
            logical_seq: 0,
            ..origin.input().clone()
        },
        EventOriginRecordInputV1 {
            classifier_revision_digest: Hash::zero(),
            ..origin.input().clone()
        },
        EventOriginRecordInputV1 {
            fork_admission_digest: Hash::zero(),
            ..origin.input().clone()
        },
    ] {
        assert_eq!(
            EventOriginRecordV1::new(invalid),
            Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
        );
    }

    let intervention = intervention_record(&origin)?;
    for invalid in [
        ForkInterventionAdmissionInputV1 {
            operation_id: Hash::zero(),
            ..intervention.input().clone()
        },
        ForkInterventionAdmissionInputV1 {
            logical_seq: 0,
            ..intervention.input().clone()
        },
        ForkInterventionAdmissionInputV1 {
            payload_hash: Hash::zero(),
            ..intervention.input().clone()
        },
        ForkInterventionAdmissionInputV1 {
            room_revision_descriptor_hash: Hash::zero(),
            ..intervention.input().clone()
        },
        ForkInterventionAdmissionInputV1 {
            classifier_revision_digest: Hash::zero(),
            ..intervention.input().clone()
        },
        ForkInterventionAdmissionInputV1 {
            fork_admission_digest: Hash::zero(),
            ..intervention.input().clone()
        },
    ] {
        assert_eq!(
            ForkInterventionAdmissionV1::new(invalid),
            Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
        );
    }
    Ok(())
}

#[test]
fn records_round_trip_every_cbor_unsigned_integer_width() -> Result<(), Box<dyn std::error::Error>>
{
    for logical_seq in [24, 256, 65_536, u64::from(u32::MAX) + 1] {
        let origin = EventOriginRecordV1::new(EventOriginRecordInputV1 {
            logical_seq,
            ..origin_record()?.input().clone()
        })?;
        let intervention = ForkInterventionAdmissionV1::new(ForkInterventionAdmissionInputV1 {
            logical_seq,
            ..intervention_record(&origin)?.input().clone()
        })?;
        assert_eq!(
            EventOriginRecordV1::from_canonical_cbor(&origin.to_canonical_cbor()),
            Ok(origin)
        );
        assert_eq!(
            ForkInterventionAdmissionV1::from_canonical_cbor(&intervention.to_canonical_cbor()),
            Ok(intervention)
        );
    }
    Ok(())
}

#[test]
fn eor1_decoder_rejects_each_structural_failure_class() -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let eor = origin.to_canonical_cbor();

    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&vec![0; MAX_EVENT_ORIGIN_RECORD_BYTES_V1 + 1]),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    for (offset, value) in [(0, 0x88), (2, b'X'), (7, 0), (24, 0x1c), (25, 0x4f)] {
        let mut invalid = eor.clone();
        invalid[offset] = value;
        assert_eq!(
            EventOriginRecordV1::from_canonical_cbor(&invalid),
            Err(ForkEventProvenanceErrorV1::InvalidEncoding)
        );
    }
    for (offset, value) in [
        (0, 0x00),
        (1, 0x43),
        (6, 0x20),
        (42, 0x20),
        (43, 0x20),
        (44, 0x50),
    ] {
        let mut invalid = eor.clone();
        invalid[offset] = value;
        assert_eq!(
            EventOriginRecordV1::from_canonical_cbor(&invalid),
            Err(ForkEventProvenanceErrorV1::InvalidEncoding)
        );
    }
    for truncated in [&[][..], &[0x98][..]] {
        assert_eq!(
            EventOriginRecordV1::from_canonical_cbor(truncated),
            Err(ForkEventProvenanceErrorV1::InvalidEncoding)
        );
    }
    let mut unsupported = eor.clone();
    unsupported[6] = 2;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&unsupported),
        Err(ForkEventProvenanceErrorV1::UnsupportedVersion)
    );
    for (offset, error) in [
        (42, ForkEventProvenanceErrorV1::InvalidEncoding),
        (43, ForkEventProvenanceErrorV1::InvalidEncoding),
    ] {
        let mut invalid = eor.clone();
        invalid[offset] = 3;
        assert_eq!(
            EventOriginRecordV1::from_canonical_cbor(&invalid),
            Err(error)
        );
    }
    let mut impossible = eor.clone();
    impossible[42] = 0;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&impossible),
        Err(ForkEventProvenanceErrorV1::ImpossibleClassification)
    );
    let mut absent_required_field = eor.clone();
    absent_required_field[24] = 0;
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&absent_required_field),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut trailing = eor.clone();
    trailing.push(0);
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&trailing),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    assert_eq!(
        EventOriginRecordV1::from_canonical_cbor(&eor[..eor.len() - 1]),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn fia1_decoder_rejects_each_structural_failure_class() -> Result<(), Box<dyn std::error::Error>> {
    let origin = origin_record()?;
    let fia = intervention_record(&origin)?.to_canonical_cbor();
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&vec![
            0;
            MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1
                + 1
        ]),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );

    for (offset, value) in [
        (0, 0x89),
        (2, b'X'),
        (7, 0),
        (8, 31),
        (41, 0x4f),
        (59, 0x4f),
    ] {
        let mut invalid = fia.clone();
        invalid[offset] = value;
        assert_eq!(
            ForkInterventionAdmissionV1::from_canonical_cbor(&invalid),
            Err(ForkEventProvenanceErrorV1::InvalidEncoding)
        );
    }
    for (offset, value) in [(58, 0x20), (76, 0x50), (110, 0x50), (144, 0x50)] {
        let mut invalid = fia.clone();
        invalid[offset] = value;
        assert_eq!(
            ForkInterventionAdmissionV1::from_canonical_cbor(&invalid),
            Err(ForkEventProvenanceErrorV1::InvalidEncoding)
        );
    }
    let mut noncanonical_seq = fia.clone();
    noncanonical_seq.splice(58..59, [0x18, 9]);
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&noncanonical_seq),
        Err(ForkEventProvenanceErrorV1::NonCanonical)
    );
    let mut unsupported = fia.clone();
    unsupported[6] = 2;
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&unsupported),
        Err(ForkEventProvenanceErrorV1::UnsupportedVersion)
    );
    let mut absent_required_field = fia.clone();
    absent_required_field[58] = 0;
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&absent_required_field),
        Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
    );
    let mut trailing = fia.clone();
    trailing.push(0);
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&trailing),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ForkInterventionAdmissionV1::from_canonical_cbor(&fia[..fia.len() - 1]),
        Err(ForkEventProvenanceErrorV1::InvalidEncoding)
    );
    Ok(())
}
