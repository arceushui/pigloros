use pos_core::{
    ArtifactRegistrationV1, CanonicalBytes, EntityId, ErasureArtifactClassV1, EventId, Hash,
    TimelineId, WorldEventOccurrenceV1, WorldEventRowInputV1, WorldEventRowV1, WorldHistoryErrorV1,
    MAX_WORLD_EVENT_OCCURRENCE_BYTES_V1,
};
use ulid::Ulid;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn id(bytes: [u8; 16]) -> Ulid {
    Ulid::from(u128::from_be_bytes(bytes))
}

fn vector() -> TestResult<WorldEventOccurrenceV1> {
    let row = WorldEventRowV1::new(WorldEventRowInputV1 {
        logical_seq: 1,
        source_timeline_id: TimelineId::from_ulid(id([0x20; 16])),
        source_segment_seq: 1,
        event_id: EventId::from_ulid(id([0x30; 16])),
        entity_id: EntityId::from_ulid(id([0x40; 16])),
        event_type: "x".to_owned(),
        schema_version: 1,
        wall_time_micros: 0,
        causation_id: None,
        correlation_id: None,
        payload_hash: Hash::from_bytes([0x50; 32]),
        payload_byte_length: 1,
        previous_source_chain_hash: Hash::zero(),
        resulting_source_chain_hash: Hash::from_bytes([0x60; 32]),
        signature: None,
        signature_identity_leaf_hash: None,
        payload_leaf_hash: Hash::from_bytes([0x70; 32]),
        applicable_dependency_root_hash: Hash::from_bytes([0x80; 32]),
    })?;
    Ok(WorldEventOccurrenceV1::new(
        TimelineId::from_ulid(id([0x10; 16])),
        row,
    ))
}

fn from_hex(text: &str) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for pair in text.as_bytes().chunks_exact(2) {
        let digits = std::str::from_utf8(pair)?;
        bytes.push(u8::from_str_radix(digits, 16)?);
    }
    Ok(bytes)
}

#[test]
fn normative_wor1_bytes_and_both_digests_match() -> TestResult<()> {
    let occurrence = vector()?;
    let bytes = from_hex(concat!(
        "8444574f52310150101010101010101010101010101010109201502020202020",
        "2020202020202020202020015030303030303030303030303030303030504040",
        "404040404040404040404040404061780100f6f6582050505050505050505050",
        "5050505050505050505050505050505050505050505001582000000000000000",
        "0000000000000000000000000000000000000000000000000058206060606060",
        "606060606060606060606060606060606060606060606060606060f6f6582070",
        "7070707070707070707070707070707070707070707070707070707070707058",
        "2080808080808080808080808080808080808080808080808080808080808080",
        "80"
    ))?;
    assert_eq!(bytes.len(), 257);
    assert_eq!(occurrence.encode().as_slice(), bytes);
    assert_eq!(
        WorldEventOccurrenceV1::decode(&CanonicalBytes::from_vec(bytes.clone())),
        Ok(occurrence.clone())
    );
    assert_eq!(occurrence.queried_timeline_id().inner(), id([0x10; 16]));
    assert_eq!(occurrence.row().as_input().source_segment_seq, 1);
    assert_eq!(
        occurrence.digest().as_bytes().to_vec(),
        from_hex("c50509a22c36676988e27eec683b8a960de20e6d40bac3b69cca043ac41cc8ba")?
    );
    assert_eq!(
        ArtifactRegistrationV1::artifact_digest(ErasureArtifactClassV1::TimelineReplay, &bytes)?
            .as_bytes()
            .to_vec(),
        from_hex("3fb69ba4546a64846264f0224d17b5d03a96d8482538e941b0e1fa8a331c8241")?
    );
    Ok(())
}

#[test]
fn queried_timeline_changes_occurrence_identity() -> TestResult<()> {
    let first = vector()?;
    let second =
        WorldEventOccurrenceV1::new(TimelineId::from_ulid(id([0x11; 16])), first.row().clone());
    assert_ne!(first.digest(), second.digest());
    assert_ne!(first.encode(), second.encode());
    assert_eq!(second.row(), first.row());
    assert_eq!(WorldEventOccurrenceV1::decode(&second.encode()), Ok(second));
    Ok(())
}

#[test]
fn occurrence_decoder_rejects_malformed_and_noncanonical_bytes() -> TestResult<()> {
    let good = vector()?.encode().as_slice().to_vec();
    let mut cases = vec![
        (Vec::new(), WorldHistoryErrorV1::InvalidEncoding),
        (good[..25].to_vec(), WorldHistoryErrorV1::InvalidEncoding),
        (
            vec![0; MAX_WORLD_EVENT_OCCURRENCE_BYTES_V1 + 1],
            WorldHistoryErrorV1::FieldOutOfBounds,
        ),
    ];
    for (offset, value, error) in [
        (0, 0x83, WorldHistoryErrorV1::InvalidEncoding),
        (2, b'X', WorldHistoryErrorV1::WrongMagic),
        (6, 2, WorldHistoryErrorV1::WrongVersion),
        (7, 0x51, WorldHistoryErrorV1::InvalidEncoding),
        (24, 0x91, WorldHistoryErrorV1::InvalidEncoding),
    ] {
        let mut bytes = good.clone();
        bytes[offset] = value;
        cases.push((bytes, error));
    }
    let mut trailing = good.clone();
    trailing.push(0);
    cases.push((trailing, WorldHistoryErrorV1::InvalidEncoding));
    let mut overlong_sequence = good;
    overlong_sequence[25] = 0x18;
    overlong_sequence.insert(26, 1);
    cases.push((overlong_sequence, WorldHistoryErrorV1::NonCanonicalEncoding));
    for (bytes, error) in cases {
        assert_eq!(
            WorldEventOccurrenceV1::decode(&CanonicalBytes::from_vec(bytes)),
            Err(error)
        );
    }
    Ok(())
}
