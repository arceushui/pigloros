use pos_core::{
    CanonicalBytes, CorrelationId, EntityId, EventId, Hash, SchemaVersion, Signature, TimelineId,
    WorldEventPageV1, WorldEventRowInputV1, WorldEventRowV1, WorldHistoryBranchInputV1,
    WorldHistoryBranchV1, WorldHistoryChildRecordRefV1, WorldHistoryChildV1, WorldHistoryErrorV1,
    MAX_WORLD_EVENT_PAGE_ROWS_V1, MAX_WORLD_EVENT_TYPE_BYTES_V1,
    MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1,
};
use ulid::Ulid;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn timeline(value: u128) -> TimelineId {
    TimelineId::from_ulid(Ulid::from(value))
}

fn event(value: u128) -> EventId {
    EventId::from_ulid(Ulid::from(value))
}

fn entity(value: u128) -> EntityId {
    EntityId::from_ulid(Ulid::from(value))
}

fn correlation(value: u128) -> CorrelationId {
    CorrelationId::from_ulid(Ulid::from(value))
}

fn row_input(logical_seq: u64, source_seq: u64, event_id: u128) -> WorldEventRowInputV1 {
    WorldEventRowInputV1 {
        logical_seq,
        source_timeline_id: timeline(2),
        source_segment_seq: source_seq,
        event_id: event(event_id),
        entity_id: entity(4),
        event_type: "thing".to_owned(),
        schema_version: u64::from(SchemaVersion::V1.as_u32()),
        wall_time_micros: 9,
        causation_id: None,
        correlation_id: None,
        payload_hash: hash(10),
        payload_byte_length: 3,
        previous_source_chain_hash: Hash::zero(),
        resulting_source_chain_hash: hash(11),
        signature: None,
        signature_identity_leaf_hash: None,
        payload_leaf_hash: hash(12),
        applicable_dependency_root_hash: hash(13),
    }
}

fn row(
    logical_seq: u64,
    source_seq: u64,
    event_id: u128,
) -> Result<WorldEventRowV1, WorldHistoryErrorV1> {
    WorldEventRowV1::new(row_input(logical_seq, source_seq, event_id))
}

fn page() -> Result<WorldEventPageV1, WorldHistoryErrorV1> {
    WorldEventPageV1::new(timeline(1), vec![row(1, 5, 3)?])
}

fn history_child(
    first: u64,
    last: u64,
    count: u64,
    address_byte: u8,
) -> Result<WorldHistoryChildV1, WorldHistoryErrorV1> {
    WorldHistoryChildV1::new(first, last, count, hash(address_byte))
}

fn history_branch(
    height: u8,
    first: u64,
    last: u64,
    count: u64,
    children: Vec<WorldHistoryChildV1>,
) -> Result<WorldHistoryBranchV1, WorldHistoryErrorV1> {
    WorldHistoryBranchV1::new(WorldHistoryBranchInputV1 {
        timeline_id: timeline(1),
        height,
        first_logical_seq: first,
        last_logical_seq: last,
        event_count: count,
        children,
    })
}

fn uint(value: u64) -> ciborium::value::Value {
    ciborium::value::Value::Integer(value.into())
}

fn id_value(value: u128) -> ciborium::value::Value {
    ciborium::value::Value::Bytes(value.to_be_bytes().to_vec())
}

fn repeated_bytes(byte: u8, length: usize) -> ciborium::value::Value {
    ciborium::value::Value::Bytes(vec![byte; length])
}

fn indexed_hash(index: usize) -> Hash {
    let mut bytes = [0; 32];
    let value = u16::try_from(index + 1).unwrap_or(u16::MAX);
    bytes[30..].copy_from_slice(&value.to_be_bytes());
    Hash::from_bytes(bytes)
}

fn expected_row() -> ciborium::value::Value {
    use ciborium::value::Value::{Array, Null, Text};

    Array(vec![
        uint(1),
        id_value(2),
        uint(5),
        id_value(3),
        id_value(4),
        Text("thing".to_owned()),
        uint(1),
        uint(9),
        Null,
        Null,
        repeated_bytes(10, 32),
        uint(3),
        repeated_bytes(0, 32),
        repeated_bytes(11, 32),
        Null,
        Null,
        repeated_bytes(12, 32),
        repeated_bytes(13, 32),
    ])
}

fn independent_cbor(
    value: &ciborium::value::Value,
) -> Result<CanonicalBytes, ciborium::ser::Error<std::io::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(CanonicalBytes::from_vec(bytes))
}

#[test]
fn public_wep1_matches_independent_cbor_and_domain_digest() -> Result<(), Box<dyn std::error::Error>>
{
    use ciborium::value::Value::Array;

    let expected = independent_cbor(&Array(vec![
        ciborium::value::Value::Bytes(b"WEP1".to_vec()),
        uint(1),
        id_value(1),
        uint(1),
        uint(1),
        Array(vec![expected_row()]),
    ]))?;
    let page = page()?;

    assert_eq!(page.encode().as_slice(), expected.as_slice());
    assert_eq!(WorldEventPageV1::decode(&expected), Ok(page.clone()));
    assert_eq!(
        page.digest().as_bytes(),
        &[
            0x7d, 0x2f, 0xae, 0x3f, 0xee, 0x7d, 0x47, 0x2f, 0x7c, 0xfd, 0x6b, 0x19, 0x80, 0x2b,
            0x42, 0x92, 0x83, 0xf6, 0x2a, 0xa9, 0xb1, 0x76, 0x27, 0xe7, 0x6a, 0x1a, 0x16, 0x49,
            0x6c, 0x40, 0xa9, 0xad,
        ]
    );
    Ok(())
}

#[test]
fn public_wep1_preserves_independent_optional_fields_and_integer_widths(
) -> Result<(), Box<dyn std::error::Error>> {
    let wall_times = [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ];
    let rows = wall_times
        .into_iter()
        .enumerate()
        .map(|(index, wall_time)| {
            let mut input = row_input(
                u64::try_from(index + 1).unwrap_or(u64::MAX),
                u64::try_from(index + 5).unwrap_or(u64::MAX),
                u128::try_from(index + 3).unwrap_or(u128::MAX),
            );
            input.wall_time_micros = wall_time;
            if index == 0 {
                input.signature = Some(Signature::from_bytes([21; 64]));
            }
            if index == 1 {
                input.signature_identity_leaf_hash = Some(hash(22));
            }
            if index == 2 {
                input.causation_id = Some(event(23));
                input.correlation_id = Some(correlation(24));
            }
            WorldEventRowV1::new(input)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let page = WorldEventPageV1::new(timeline(1), rows)?;
    let encoded = page.encode();
    assert_eq!(WorldEventPageV1::decode(&encoded), Ok(page));
    Ok(())
}

#[test]
fn public_wep1_rejects_invalid_row_fields_and_addresses() {
    let input = row_input(0, 1, 1);
    assert_eq!(
        WorldEventRowV1::new(input),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let input = row_input(1, 0, 1);
    assert_eq!(
        WorldEventRowV1::new(input),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut input = row_input(1, 1, 1);
    input.event_type.clear();
    assert_eq!(
        WorldEventRowV1::new(input),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );

    let mut input = row_input(1, 1, 1);
    input.event_type = "x".repeat(MAX_WORLD_EVENT_TYPE_BYTES_V1 + 1);
    assert_eq!(
        WorldEventRowV1::new(input),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut input = row_input(1, 1, 1);
    input.event_type = "é".repeat(MAX_WORLD_EVENT_TYPE_BYTES_V1 / 2 + 1);
    assert_eq!(
        WorldEventRowV1::new(input),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut input = row_input(1, 1, 1);
    input.event_type = "é".repeat(MAX_WORLD_EVENT_TYPE_BYTES_V1 / 2);
    assert!(WorldEventRowV1::new(input).is_ok());
    let mut input = row_input(1, 1, 1);
    input.schema_version = 2;
    assert_eq!(
        WorldEventRowV1::new(input),
        Err(WorldHistoryErrorV1::UnsupportedSchemaVersion)
    );

    for zero_address in 0..4 {
        let mut input = row_input(1, 1, 1);
        match zero_address {
            0 => input.payload_hash = Hash::zero(),
            1 => input.payload_leaf_hash = Hash::zero(),
            2 => input.applicable_dependency_root_hash = Hash::zero(),
            _ => input.signature_identity_leaf_hash = Some(Hash::zero()),
        }
        assert_eq!(
            WorldEventRowV1::new(input),
            Err(WorldHistoryErrorV1::ZeroContentAddress)
        );
    }
}

#[test]
fn public_accessors_expose_checked_history_records() -> Result<(), Box<dyn std::error::Error>> {
    let page = page()?;
    assert_eq!(page.timeline_id(), timeline(1));
    assert_eq!(page.first_logical_seq(), 1);
    assert_eq!(page.last_logical_seq(), 1);
    assert_eq!(page.rows().len(), 1);
    assert_eq!(page.rows()[0].as_input().logical_seq, 1);

    let child = WorldHistoryChildV1::new(1, 1, 1, page.digest())?;
    assert_eq!(child.first_logical_seq(), 1);
    assert_eq!(child.last_logical_seq(), 1);
    assert_eq!(child.event_count(), 1);
    assert_eq!(child.node_hash(), page.digest());

    let branch = WorldHistoryBranchV1::new(WorldHistoryBranchInputV1 {
        timeline_id: timeline(1),
        height: 1,
        first_logical_seq: 1,
        last_logical_seq: 1,
        event_count: 1,
        children: vec![child],
    })?;
    assert_eq!(branch.as_input().timeline_id, timeline(1));
    assert_eq!(branch.as_input().height, 1);
    assert_eq!(branch.as_input().first_logical_seq, 1);
    assert_eq!(branch.as_input().last_logical_seq, 1);
    assert_eq!(branch.as_input().event_count, 1);
    assert_eq!(branch.as_input().children.len(), 1);
    Ok(())
}

#[test]
fn public_wep1_checks_page_bounds_sequence_and_source_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        WorldEventPageV1::new(timeline(1), Vec::new()),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        WorldEventPageV1::new(timeline(1), vec![row(1, 1, 1)?, row(3, 2, 2)?]),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        WorldEventPageV1::new(timeline(1), vec![row(1, 1, 1)?, row(2, 3, 2)?]),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        WorldEventPageV1::new(timeline(1), vec![row(2, 1, 1)?, row(1, 2, 2)?]),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        WorldEventPageV1::new(timeline(1), vec![row(u64::MAX, 1, 1)?, row(1, 2, 2)?]),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        WorldEventPageV1::new(timeline(1), vec![row(1, 1, 1)?, row(2, 2, 1)?]),
        Err(WorldHistoryErrorV1::DuplicateSourceEvent)
    );
    let mut intervening_source_row = row_input(2, 1, 2);
    intervening_source_row.source_timeline_id = timeline(3);
    let mut repeated_source_position = row_input(3, 1, 3);
    repeated_source_position.source_timeline_id = timeline(2);
    assert_eq!(
        WorldEventPageV1::new(
            timeline(1),
            vec![
                row(1, 1, 1)?,
                WorldEventRowV1::new(intervening_source_row)?,
                WorldEventRowV1::new(repeated_source_position)?,
            ]
        ),
        Err(WorldHistoryErrorV1::DuplicateSourceEvent)
    );
    let mut fork_segment_row = row_input(2, 1, 2);
    fork_segment_row.source_timeline_id = timeline(3);
    assert!(WorldEventPageV1::new(
        timeline(1),
        vec![row(1, 7, 1)?, WorldEventRowV1::new(fork_segment_row)?]
    )
    .is_ok());
    assert!(WorldEventPageV1::new(timeline(1), vec![row(u64::MAX, 1, 1)?]).is_ok());

    let maximum = (1..=u64::try_from(MAX_WORLD_EVENT_PAGE_ROWS_V1).unwrap_or(u64::MAX))
        .map(|seq| row(seq, seq, u128::from(seq)))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(WorldEventPageV1::new(timeline(1), maximum).is_ok());
    let oversized = (1..=u64::try_from(MAX_WORLD_EVENT_PAGE_ROWS_V1 + 1).unwrap_or(u64::MAX))
        .map(|seq| row(seq, seq, u128::from(seq)))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        WorldEventPageV1::new(timeline(1), oversized),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_wep1_checks_interleaved_source_sequence_in_constructor_and_decoder(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut other_source = row_input(2, 1, 2);
    other_source.source_timeline_id = timeline(3);
    let other_source = WorldEventRowV1::new(other_source)?;
    let valid = WorldEventPageV1::new(
        timeline(1),
        vec![row(1, 1, 1)?, other_source.clone(), row(3, 2, 3)?],
    )?;
    assert_eq!(WorldEventPageV1::decode(&valid.encode()), Ok(valid.clone()));

    assert_eq!(
        WorldEventPageV1::new(
            timeline(1),
            vec![row(1, 1, 1)?, other_source, row(3, 3, 3)?],
        ),
        Err(WorldHistoryErrorV1::InvalidRange)
    );

    let mut encoded: ciborium::value::Value = ciborium::from_reader(valid.encode().as_slice())?;
    let page_fields = encoded.as_array_mut().ok_or("WEP1 page must be an array")?;
    let rows = page_fields[5]
        .as_array_mut()
        .ok_or("WEP1 rows must be an array")?;
    let third_row = rows[2]
        .as_array_mut()
        .ok_or("WEP1 source row must be an array")?;
    third_row[2] = uint(3);
    let skipped_source = independent_cbor(&encoded)?;
    assert_eq!(
        WorldEventPageV1::decode(&skipped_source),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    Ok(())
}

#[test]
fn public_whb1_matches_independent_cbor_and_round_trips() -> Result<(), Box<dyn std::error::Error>>
{
    use ciborium::value::Value::Array;

    let branch = WorldHistoryBranchV1::new(WorldHistoryBranchInputV1 {
        timeline_id: timeline(1),
        height: 1,
        first_logical_seq: 1,
        last_logical_seq: 1,
        event_count: 1,
        children: vec![WorldHistoryChildV1::new(1, 1, 1, hash(2))?],
    })?;
    let expected = independent_cbor(&Array(vec![
        ciborium::value::Value::Bytes(b"WHB1".to_vec()),
        uint(1),
        id_value(1),
        uint(1),
        uint(1),
        uint(1),
        uint(1),
        Array(vec![Array(vec![
            uint(1),
            uint(1),
            uint(1),
            repeated_bytes(2, 32),
        ])]),
    ]))?;
    assert_eq!(branch.encode().as_slice(), expected.as_slice());
    assert_eq!(WorldHistoryBranchV1::decode(&expected), Ok(branch.clone()));
    assert_eq!(
        branch.digest().as_bytes(),
        &[
            0x29, 0xf7, 0x59, 0x61, 0xc5, 0x6a, 0x9e, 0x2c, 0x83, 0x3d, 0x88, 0x88, 0x2c, 0xaa,
            0x42, 0x12, 0x7b, 0x7f, 0x99, 0xb1, 0x34, 0x8e, 0x4a, 0xaf, 0xb4, 0xb6, 0xea, 0x3c,
            0xe5, 0x45, 0xe0, 0x3e,
        ]
    );
    Ok(())
}

#[test]
fn public_whb1_rejects_invalid_child_fields_and_branch_bounds(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        history_child(0, 1, 1, 1),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        history_child(2, 1, 1, 1),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        history_child(1, 1, 0, 1),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        history_child(1, 1, 1, 0),
        Err(WorldHistoryErrorV1::ZeroContentAddress)
    );
    assert_eq!(
        history_branch(0, 1, 1, 1, vec![history_child(1, 1, 1, 1)?]),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        history_branch(9, 1, 1, 1, vec![history_child(1, 1, 1, 1)?]),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        history_branch(1, 1, 1, 1, Vec::new()),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_whb1_enforces_contiguous_nonoverlapping_partitions(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        history_branch(
            1,
            1,
            66,
            66,
            vec![history_child(1, 64, 64, 1)?, history_child(66, 66, 1, 2)?]
        ),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        history_branch(
            1,
            1,
            64,
            64,
            vec![history_child(1, 64, 64, 1)?, history_child(64, 64, 1, 2)?]
        ),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert!(history_branch(
        1,
        1,
        65,
        65,
        vec![history_child(1, 64, 64, 1)?, history_child(65, 65, 1, 2)?]
    )
    .is_ok());
    assert_eq!(
        history_branch(
            1,
            1,
            65,
            64,
            vec![history_child(1, 64, 64, 1)?, history_child(65, 65, 1, 2)?]
        ),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        history_branch(
            1,
            1,
            64,
            64,
            vec![history_child(1, 64, 64, 1)?, history_child(65, 65, 1, 2)?]
        ),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        history_branch(
            1,
            1,
            65,
            65,
            vec![history_child(1, 64, 64, 1)?, history_child(65, 65, 1, 1)?]
        ),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    assert_eq!(
        history_branch(
            1,
            u64::MAX - 63,
            u64::MAX,
            64,
            vec![
                history_child(u64::MAX - 63, u64::MAX, 64, 3)?,
                history_child(1, 1, 1, 4)?,
            ],
        ),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    Ok(())
}

#[test]
fn public_whb1_enforces_height_derived_child_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let page_capacity = u64::try_from(MAX_WORLD_EVENT_PAGE_ROWS_V1).unwrap_or(u64::MAX);
    let branch_capacity =
        u64::try_from(MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1).unwrap_or(u64::MAX) * page_capacity;
    assert_eq!(
        history_branch(
            1,
            1,
            branch_capacity + 1,
            branch_capacity + 1,
            vec![history_child(
                1,
                branch_capacity + 1,
                branch_capacity + 1,
                1
            )?]
        ),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        history_branch(
            1,
            1,
            page_capacity + 1,
            page_capacity + 1,
            vec![history_child(1, page_capacity + 1, page_capacity + 1, 1)?]
        ),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        history_branch(
            2,
            1,
            branch_capacity + 1,
            branch_capacity + 1,
            vec![history_child(
                1,
                branch_capacity + 1,
                branch_capacity + 1,
                1
            )?]
        ),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        history_branch(
            2,
            1,
            branch_capacity + 1,
            branch_capacity + 1,
            vec![history_child(
                1,
                branch_capacity + 1,
                branch_capacity + 1,
                9
            )?]
        ),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        history_branch(
            2,
            1,
            branch_capacity + 1,
            branch_capacity + 1,
            vec![
                history_child(1, branch_capacity - 1, branch_capacity - 1, 1)?,
                history_child(branch_capacity, branch_capacity + 1, 2, 2)?,
            ]
        ),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    Ok(())
}

#[test]
fn public_whb1_handles_maximum_sequence_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let near_max = history_branch(
        1,
        u64::MAX - 127,
        u64::MAX,
        128,
        vec![
            history_child(u64::MAX - 127, u64::MAX - 64, 64, 1)?,
            history_child(u64::MAX - 63, u64::MAX, 64, 2)?,
        ],
    );
    assert!(near_max.is_ok());

    let child_capacity = (u64::MAX >> 2) + 1;
    assert!(history_branch(
        8,
        1,
        u64::MAX,
        u64::MAX,
        vec![
            history_child(1, child_capacity, child_capacity, 3)?,
            history_child(child_capacity + 1, child_capacity * 2, child_capacity, 4)?,
            history_child(
                child_capacity * 2 + 1,
                child_capacity * 3,
                child_capacity,
                5
            )?,
            history_child(
                child_capacity * 3 + 1,
                u64::MAX,
                u64::MAX - child_capacity * 3,
                6
            )?,
        ],
    )
    .is_ok());
    assert_eq!(
        history_branch(
            1,
            u64::MAX,
            u64::MAX,
            1,
            vec![
                history_child(u64::MAX, u64::MAX, 1, 3)?,
                history_child(u64::MAX, u64::MAX, 1, 4)?,
            ],
        ),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    Ok(())
}

#[test]
fn public_whb1_validates_resolved_event_page_scope() -> Result<(), Box<dyn std::error::Error>> {
    let event_page = page()?;
    let event_child = WorldHistoryChildV1::new(
        event_page.first_logical_seq(),
        event_page.last_logical_seq(),
        u64::try_from(event_page.rows().len()).unwrap_or(u64::MAX),
        event_page.digest(),
    )?;
    let page_parent = history_branch(1, 1, 1, 1, vec![event_child])?;
    assert_eq!(
        page_parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::EventPage(&event_page)],
        ),
        Ok(())
    );
    assert_eq!(
        page_parent.validate_resolved_children(
            timeline(2),
            &[WorldHistoryChildRecordRefV1::EventPage(&event_page)],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );
    assert_eq!(
        page_parent.validate_resolved_children(timeline(1), &[]),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );

    let wrong_timeline_page = WorldEventPageV1::new(timeline(2), vec![row(1, 5, 3)?])?;
    let wrong_timeline_parent = history_branch(
        1,
        1,
        1,
        1,
        vec![WorldHistoryChildV1::new(
            1,
            1,
            1,
            wrong_timeline_page.digest(),
        )?],
    )?;
    assert_eq!(
        wrong_timeline_parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::EventPage(
                &wrong_timeline_page
            )],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );
    Ok(())
}

#[test]
fn public_whb1_validates_resolved_event_page_digest_and_range(
) -> Result<(), Box<dyn std::error::Error>> {
    let event_page = page()?;
    let page_parent = history_branch(
        1,
        1,
        1,
        1,
        vec![WorldHistoryChildV1::new(1, 1, 1, event_page.digest())?],
    )?;
    let different_page = WorldEventPageV1::new(timeline(1), vec![row(1, 5, 4)?])?;
    assert_eq!(
        page_parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::EventPage(&different_page)],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );

    let wrong_first_parent = history_branch(
        1,
        2,
        2,
        1,
        vec![WorldHistoryChildV1::new(2, 2, 1, event_page.digest())?],
    )?;
    assert_eq!(
        wrong_first_parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::EventPage(&event_page)],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );
    let wrong_range_parent = history_branch(
        1,
        1,
        2,
        2,
        vec![WorldHistoryChildV1::new(1, 2, 2, event_page.digest())?],
    )?;
    assert_eq!(
        wrong_range_parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::EventPage(&event_page)],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );

    let lower_branch = history_branch(1, 1, 1, 1, vec![history_child(1, 1, 1, 9)?])?;
    assert_eq!(
        page_parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::HistoryBranch(&lower_branch)],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );
    Ok(())
}

#[test]
fn public_whb1_accepts_resolved_history_branch_child() -> Result<(), Box<dyn std::error::Error>> {
    let lower_branch = history_branch(1, 1, 1, 1, vec![history_child(1, 1, 1, 9)?])?;
    let parent = history_branch(
        2,
        1,
        1,
        1,
        vec![WorldHistoryChildV1::new(1, 1, 1, lower_branch.digest())?],
    )?;
    assert_eq!(
        parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::HistoryBranch(&lower_branch)],
        ),
        Ok(())
    );
    Ok(())
}

#[test]
fn public_whb1_rejects_resolved_history_branch_scope_and_range_mismatches(
) -> Result<(), Box<dyn std::error::Error>> {
    let lower_branch = history_branch(1, 1, 1, 1, vec![history_child(1, 1, 1, 9)?])?;
    let parent = history_branch(
        2,
        1,
        1,
        1,
        vec![WorldHistoryChildV1::new(1, 1, 1, lower_branch.digest())?],
    )?;
    let wrong_timeline_branch = WorldHistoryBranchV1::new(WorldHistoryBranchInputV1 {
        timeline_id: timeline(2),
        height: 1,
        first_logical_seq: 1,
        last_logical_seq: 1,
        event_count: 1,
        children: vec![WorldHistoryChildV1::new(1, 1, 1, hash(11))?],
    })?;
    assert_eq!(
        parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::HistoryBranch(
                &wrong_timeline_branch
            )],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );

    let wrong_first_branch = history_branch(1, 2, 2, 1, vec![history_child(2, 2, 1, 13)?])?;
    assert_eq!(
        parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::HistoryBranch(
                &wrong_first_branch
            )],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );
    let wrong_last_branch = history_branch(1, 1, 2, 2, vec![history_child(1, 2, 2, 14)?])?;
    assert_eq!(
        parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::HistoryBranch(
                &wrong_last_branch
            )],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );
    Ok(())
}

#[test]
fn public_whb1_rejects_resolved_history_branch_digest_and_level_mismatches(
) -> Result<(), Box<dyn std::error::Error>> {
    let lower_branch = history_branch(1, 1, 1, 1, vec![history_child(1, 1, 1, 9)?])?;
    let parent = history_branch(
        2,
        1,
        1,
        1,
        vec![WorldHistoryChildV1::new(1, 1, 1, lower_branch.digest())?],
    )?;
    let wrong_digest_branch = history_branch(1, 1, 1, 1, vec![history_child(1, 1, 1, 12)?])?;
    assert_eq!(
        parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::HistoryBranch(
                &wrong_digest_branch
            )],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );

    let wrong_level_branch = history_branch(2, 1, 1, 1, vec![history_child(1, 1, 1, 10)?])?;
    assert_eq!(
        parent.validate_resolved_children(
            timeline(1),
            &[WorldHistoryChildRecordRefV1::HistoryBranch(
                &wrong_level_branch
            )],
        ),
        Err(WorldHistoryErrorV1::InvalidChildReference)
    );
    Ok(())
}

#[test]
fn public_whb1_accepts_exact_child_limit_and_rejects_one_more(
) -> Result<(), Box<dyn std::error::Error>> {
    let page_capacity = u64::try_from(MAX_WORLD_EVENT_PAGE_ROWS_V1).unwrap_or(u64::MAX);
    let children = (0..MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1)
        .map(|index| {
            let first = u64::try_from(index).unwrap_or(u64::MAX) * page_capacity + 1;
            let last = first + page_capacity - 1;
            WorldHistoryChildV1::new(first, last, page_capacity, indexed_hash(index))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let total_event_count =
        u64::try_from(MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1).unwrap_or(u64::MAX) * page_capacity;
    let maximum = WorldHistoryBranchV1::new(WorldHistoryBranchInputV1 {
        timeline_id: timeline(1),
        height: 1,
        first_logical_seq: 1,
        last_logical_seq: total_event_count,
        event_count: total_event_count,
        children,
    })?;
    let encoded = maximum.encode();
    assert_eq!(WorldHistoryBranchV1::decode(&encoded), Ok(maximum));

    let too_many = (0..=MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1)
        .map(|index| {
            let sequence = u64::try_from(index + 1).unwrap_or(u64::MAX);
            WorldHistoryChildV1::new(sequence, sequence, 1, indexed_hash(index))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        WorldHistoryBranchV1::new(WorldHistoryBranchInputV1 {
            timeline_id: timeline(1),
            height: 1,
            first_logical_seq: 1,
            last_logical_seq: u64::try_from(MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1 + 1)
                .unwrap_or(u64::MAX),
            event_count: u64::try_from(MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1 + 1)
                .unwrap_or(u64::MAX),
            children: too_many,
        }),
        Err(WorldHistoryErrorV1::FieldOutOfBounds),
    );
    Ok(())
}

#[test]
fn public_decoders_reject_wrong_magic_version_noncanonical_and_trailing_data(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid_page = page()?.encode();
    let mut wrong_magic = valid_page.as_slice().to_vec();
    wrong_magic[2] = b'X';
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(wrong_magic)),
        Err(WorldHistoryErrorV1::WrongMagic)
    );
    let mut wrong_version = valid_page.as_slice().to_vec();
    wrong_version[6] = 2;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(wrong_version)),
        Err(WorldHistoryErrorV1::WrongVersion)
    );
    let mut wrong_version_type = valid_page.as_slice().to_vec();
    wrong_version_type[6] = 0x61;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(wrong_version_type)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    let mut noncanonical = valid_page.as_slice().to_vec();
    noncanonical[6] = 0x18;
    noncanonical.insert(7, 1);
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(noncanonical)),
        Err(WorldHistoryErrorV1::NonCanonicalEncoding)
    );
    for (extra_info, extra_bytes) in [
        (0x19, vec![0, 1]),
        (0x1a, vec![0, 0, 0, 1]),
        (0x1b, vec![0, 0, 0, 0, 0, 0, 0, 1]),
    ] {
        let mut overlong = valid_page.as_slice().to_vec();
        overlong[6] = extra_info;
        overlong.splice(7..7, extra_bytes);
        assert_eq!(
            WorldEventPageV1::decode(&CanonicalBytes::from_vec(overlong)),
            Err(WorldHistoryErrorV1::NonCanonicalEncoding)
        );
    }
    let mut trailing = valid_page.as_slice().to_vec();
    trailing.push(0);
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(trailing)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(Vec::new())),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );

    let valid_branch = WorldHistoryBranchV1::new(WorldHistoryBranchInputV1 {
        timeline_id: timeline(1),
        height: 1,
        first_logical_seq: 1,
        last_logical_seq: 1,
        event_count: 1,
        children: vec![WorldHistoryChildV1::new(1, 1, 1, hash(1))?],
    })?
    .encode();
    let mut bad_branch_magic = valid_branch.as_slice().to_vec();
    bad_branch_magic[2] = b'X';
    assert_eq!(
        WorldHistoryBranchV1::decode(&CanonicalBytes::from_vec(bad_branch_magic)),
        Err(WorldHistoryErrorV1::WrongMagic)
    );
    let mut bad_branch_version = valid_branch.as_slice().to_vec();
    bad_branch_version[6] = 2;
    assert_eq!(
        WorldHistoryBranchV1::decode(&CanonicalBytes::from_vec(bad_branch_version)),
        Err(WorldHistoryErrorV1::WrongVersion)
    );
    let mut noncanonical_branch = valid_branch.as_slice().to_vec();
    noncanonical_branch[0] = 0x98;
    noncanonical_branch.insert(1, 8);
    assert_eq!(
        WorldHistoryBranchV1::decode(&CanonicalBytes::from_vec(noncanonical_branch)),
        Err(WorldHistoryErrorV1::NonCanonicalEncoding)
    );
    let mut trailing_branch = valid_branch.as_slice().to_vec();
    trailing_branch.push(0);
    assert_eq!(
        WorldHistoryBranchV1::decode(&CanonicalBytes::from_vec(trailing_branch)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn public_decoders_reject_schema_bounds_and_malformed_cbor(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid = page()?.encode();
    let mut bad_schema = valid.as_slice().to_vec();
    bad_schema[87] = 2;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(bad_schema)),
        Err(WorldHistoryErrorV1::UnsupportedSchemaVersion)
    );
    let mut wrong_array = valid.as_slice().to_vec();
    wrong_array[0] = 0x85;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(wrong_array)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    let mut wrong_row_length = valid.as_slice().to_vec();
    wrong_row_length[27] = 0x91;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(wrong_row_length)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    let oversized = vec![0; pos_core::MAX_WORLD_EVENT_PAGE_BYTES_V1 + 1];
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(oversized)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );

    let malformed = CanonicalBytes::from_vec(vec![0x9f, 0xff]);
    assert_eq!(
        WorldEventPageV1::decode(&malformed),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    let oversized_branch =
        CanonicalBytes::from_vec(vec![0; pos_core::MAX_WORLD_HISTORY_BRANCH_BYTES_V1 + 1]);
    assert_eq!(
        WorldHistoryBranchV1::decode(&oversized_branch),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_wep1_parser_rejects_field_lengths_types_and_truncation(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid = page()?.encode();

    let mut wrong_id_length = valid.as_slice().to_vec();
    wrong_id_length[7] = 0x4f;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(wrong_id_length)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    let mut empty_rows = valid.as_slice().to_vec();
    empty_rows[26] = 0x80;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(empty_rows)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut too_many_rows = valid.as_slice().to_vec();
    too_many_rows[26] = 0x98;
    too_many_rows.insert(27, 65);
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(too_many_rows)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut empty_type = valid.as_slice().to_vec();
    empty_type[81] = 0x60;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(empty_type)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut too_long_type = valid.as_slice().to_vec();
    too_long_type[81] = 0x78;
    too_long_type.insert(82, 129);
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(too_long_type)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut hostile_type_length = valid.as_slice().to_vec();
    hostile_type_length[81] = 0x7b;
    hostile_type_length.splice(82..82, [0xff; 8]);
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(hostile_type_length)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut invalid_utf8 = valid.as_slice().to_vec();
    invalid_utf8[82] = 0xff;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(invalid_utf8)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    let mut mismatched_header = valid.as_slice().to_vec();
    mismatched_header[24] = 2;
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(mismatched_header)),
        Err(WorldHistoryErrorV1::InvalidRange)
    );
    let mut truncated_integer = valid.as_slice().to_vec();
    truncated_integer[6] = 0x18;
    truncated_integer.truncate(7);
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(truncated_integer)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    let mut truncated_fixed = valid.as_slice().to_vec();
    truncated_fixed.truncate(10);
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(truncated_fixed)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn public_wep1_decoder_rejects_payload_lengths_over_u32() -> Result<(), Box<dyn std::error::Error>>
{
    let mut overlong_payload = page()?.encode().as_slice().to_vec();
    overlong_payload[125] = 0x1b;
    overlong_payload.splice(126..126, [0, 0, 0, 1, 0, 0, 0, 0]);
    assert_eq!(
        WorldEventPageV1::decode(&CanonicalBytes::from_vec(overlong_payload)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_whb1_parser_rejects_bad_child_ranges_and_height() -> Result<(), Box<dyn std::error::Error>>
{
    let valid = WorldHistoryBranchV1::new(WorldHistoryBranchInputV1 {
        timeline_id: timeline(1),
        height: 1,
        first_logical_seq: 1,
        last_logical_seq: 1,
        event_count: 1,
        children: vec![WorldHistoryChildV1::new(1, 1, 1, hash(1))?],
    })?
    .encode();

    let mut no_children = valid.as_slice().to_vec();
    no_children[28] = 0x80;
    assert_eq!(
        WorldHistoryBranchV1::decode(&CanonicalBytes::from_vec(no_children)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut too_many_children = valid.as_slice().to_vec();
    too_many_children[28] = 0x99;
    too_many_children.splice(29..29, [1, 1]);
    assert_eq!(
        WorldHistoryBranchV1::decode(&CanonicalBytes::from_vec(too_many_children)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    let mut wrong_child_size = valid.as_slice().to_vec();
    wrong_child_size[29] = 0x83;
    assert_eq!(
        WorldHistoryBranchV1::decode(&CanonicalBytes::from_vec(wrong_child_size)),
        Err(WorldHistoryErrorV1::InvalidEncoding)
    );
    let mut hostile_child_count = valid.as_slice().to_vec();
    hostile_child_count[28] = 0x9b;
    hostile_child_count.splice(29..29, [0xff; 8]);
    assert_eq!(
        WorldHistoryBranchV1::decode(&CanonicalBytes::from_vec(hostile_child_count)),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );

    let oversized_height = independent_cbor(&ciborium::value::Value::Array(vec![
        ciborium::value::Value::Bytes(b"WHB1".to_vec()),
        uint(1),
        id_value(1),
        uint(256),
        uint(1),
        uint(1),
        uint(1),
        ciborium::value::Value::Array(vec![ciborium::value::Value::Array(vec![
            uint(1),
            uint(1),
            uint(1),
            repeated_bytes(1, 32),
        ])]),
    ]))?;
    assert_eq!(
        WorldHistoryBranchV1::decode(&oversized_height),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_whb1_decoder_rejects_height_derived_cardinality_overflow(
) -> Result<(), Box<dyn std::error::Error>> {
    let maximum = u64::try_from(MAX_WORLD_EVENT_PAGE_ROWS_V1).unwrap_or(u64::MAX)
        * u64::try_from(MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1).unwrap_or(u64::MAX);
    let out_of_bounds = independent_cbor(&ciborium::value::Value::Array(vec![
        ciborium::value::Value::Bytes(b"WHB1".to_vec()),
        uint(1),
        id_value(1),
        uint(1),
        uint(1),
        uint(maximum + 1),
        uint(maximum + 1),
        ciborium::value::Value::Array(vec![ciborium::value::Value::Array(vec![
            uint(1),
            uint(maximum + 1),
            uint(maximum + 1),
            repeated_bytes(1, 32),
        ])]),
    ]))?;
    assert_eq!(
        WorldHistoryBranchV1::decode(&out_of_bounds),
        Err(WorldHistoryErrorV1::FieldOutOfBounds)
    );
    Ok(())
}
