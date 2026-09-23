use pos_core::{
    Hash, TimelineId, WorldClosureBindingErrorV1, WorldClosureBindingInputV1,
    WorldClosureBindingV1, WorldClosureCutCoordinateV1, WorldClosureReadLimitsV1,
    MAX_WORLD_CLOSURE_BINDING_BYTES_V1,
};
use ulid::Ulid;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn baseline_input() -> WorldClosureBindingInputV1 {
    WorldClosureBindingInputV1 {
        timeline_id: TimelineId::from_ulid(Ulid::nil()),
        operation_id: hash(1),
        cut_coordinate: WorldClosureCutCoordinateV1 {
            cut_id: 0,
            partition_id: 0,
            reservation_identity: [0; 32],
        },
        logical_head: 0,
        stitched_head_hash: Hash::zero(),
        retention_lease_leaf_hash: hash(2),
        consumer_set_hash: hash(3),
        dependency_root_hash: hash(4),
        history_root_hash: None,
        predecessor_binding_hash: None,
        parent_lineage_reference: None,
        read_limits: WorldClosureReadLimitsV1 {
            max_node_visits: 1,
            max_native_bytes: 1,
            max_combined_depth: 1,
        },
    }
}

// Deliberately assembled independently of the WCB1 encoder. Its BLAKE3 digest
// was fixed with /usr/bin/b3sum over the accepted ASCII domain, NUL and bytes.
fn literal_baseline() -> Vec<u8> {
    let mut bytes = vec![0x8e, 0x44, b'W', b'C', b'B', b'1', 1, 0x50];
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(&[0x58, 0x20]);
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&[0x83, 0, 0, 0x58, 0x20]);
    bytes.extend_from_slice(&[0; 32]);
    bytes.extend_from_slice(&[0, 0x58, 0x20]);
    bytes.extend_from_slice(&[0; 32]);
    for byte in [2, 3, 4] {
        bytes.extend_from_slice(&[0x58, 0x20]);
        bytes.extend_from_slice(&[byte; 32]);
    }
    bytes.extend_from_slice(&[0xf6, 0xf6, 0xf6, 0x83, 1, 1, 1]);
    bytes
}

#[test]
fn public_wcb1_matches_literal_cbor_and_fixed_digest() -> Result<(), Box<dyn std::error::Error>> {
    let binding = WorldClosureBindingV1::new(baseline_input())?;
    let literal = literal_baseline();
    assert_eq!(literal.len(), 239);
    assert_eq!(binding.to_canonical_cbor(), literal);
    let expected_digest = Hash::from_bytes([
        0x04, 0x53, 0x1a, 0xc9, 0x6e, 0xd1, 0x02, 0x57, 0x96, 0xa4, 0x02, 0x27, 0xd6, 0xdf, 0x95,
        0x91, 0x4c, 0x39, 0x16, 0xc3, 0xa9, 0x28, 0x9b, 0x17, 0x3b, 0x8d, 0x09, 0x29, 0x06, 0xc6,
        0x9c, 0xd8,
    ]);
    assert_eq!(binding.digest(), expected_digest);
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&literal),
        Ok(binding)
    );
    assert_eq!(binding.as_input(), &baseline_input());
    Ok(())
}

#[test]
fn public_wcb1_roundtrips_numeric_boundaries_and_optional_references(
) -> Result<(), Box<dyn std::error::Error>> {
    for value in [
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ] {
        let mut input = baseline_input();
        input.cut_coordinate.cut_id = value;
        input.cut_coordinate.partition_id = u16::MAX;
        input.cut_coordinate.reservation_identity = [9; 32];
        input.logical_head = value;
        input.history_root_hash = Some(hash(5));
        input.predecessor_binding_hash = Some(hash(6));
        input.parent_lineage_reference = Some(hash(7));
        input.read_limits.max_node_visits = value;
        input.read_limits.max_native_bytes = value;
        input.read_limits.max_combined_depth = 32;
        let binding = WorldClosureBindingV1::new(input)?;
        let bytes = binding.to_canonical_cbor();
        assert!(bytes.len() < MAX_WORLD_CLOSURE_BINDING_BYTES_V1);
        assert_eq!(
            WorldClosureBindingV1::from_canonical_cbor(&bytes),
            Ok(binding)
        );
        assert_eq!(binding.as_input(), &input);
    }
    Ok(())
}

#[test]
fn public_constructor_enforces_addresses_history_and_finite_limits() {
    let mut input = baseline_input();
    input.retention_lease_leaf_hash = Hash::zero();
    assert_eq!(
        WorldClosureBindingV1::new(input),
        Err(WorldClosureBindingErrorV1::ZeroContentAddress)
    );
    input = baseline_input();
    input.consumer_set_hash = Hash::zero();
    assert_eq!(
        WorldClosureBindingV1::new(input),
        Err(WorldClosureBindingErrorV1::ZeroContentAddress)
    );
    input = baseline_input();
    input.dependency_root_hash = Hash::zero();
    assert_eq!(
        WorldClosureBindingV1::new(input),
        Err(WorldClosureBindingErrorV1::ZeroContentAddress)
    );
    for location in 0..3 {
        input = baseline_input();
        match location {
            0 => input.history_root_hash = Some(Hash::zero()),
            1 => input.predecessor_binding_hash = Some(Hash::zero()),
            _ => input.parent_lineage_reference = Some(Hash::zero()),
        }
        assert_eq!(
            WorldClosureBindingV1::new(input),
            Err(WorldClosureBindingErrorV1::ZeroContentAddress)
        );
    }
    input = baseline_input();
    input.logical_head = 1;
    assert_eq!(
        WorldClosureBindingV1::new(input),
        Err(WorldClosureBindingErrorV1::InvalidHistoryRelation)
    );
    input = baseline_input();
    input.history_root_hash = Some(hash(5));
    assert_eq!(
        WorldClosureBindingV1::new(input),
        Err(WorldClosureBindingErrorV1::InvalidHistoryRelation)
    );
    input = baseline_input();
    input.read_limits.max_node_visits = 0;
    assert_eq!(
        WorldClosureBindingV1::new(input),
        Err(WorldClosureBindingErrorV1::FieldOutOfBounds)
    );
    input = baseline_input();
    input.read_limits.max_native_bytes = 0;
    assert_eq!(
        WorldClosureBindingV1::new(input),
        Err(WorldClosureBindingErrorV1::FieldOutOfBounds)
    );
    for depth in [0, 33] {
        input = baseline_input();
        input.read_limits.max_combined_depth = depth;
        assert_eq!(
            WorldClosureBindingV1::new(input),
            Err(WorldClosureBindingErrorV1::FieldOutOfBounds)
        );
    }
}

#[test]
fn public_decoder_rejects_malformed_truncated_and_oversized_inputs() {
    let valid = literal_baseline();
    for size in 0..valid.len() {
        assert!(WorldClosureBindingV1::from_canonical_cbor(&valid[..size]).is_err());
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&trailing),
        Err(WorldClosureBindingErrorV1::InvalidEncoding)
    );
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&vec![
            0;
            MAX_WORLD_CLOSURE_BINDING_BYTES_V1 + 1
        ]),
        Err(WorldClosureBindingErrorV1::FieldOutOfBounds)
    );
    for (offset, replacement, expected) in [
        (0, 0x8d, WorldClosureBindingErrorV1::InvalidEncoding),
        (2, b'X', WorldClosureBindingErrorV1::InvalidEncoding),
        (6, 2, WorldClosureBindingErrorV1::UnsupportedVersion),
        (7, 0x4f, WorldClosureBindingErrorV1::InvalidEncoding),
        (24, 0x40, WorldClosureBindingErrorV1::InvalidEncoding),
        (58, 0x82, WorldClosureBindingErrorV1::InvalidEncoding),
        (59, 0x40, WorldClosureBindingErrorV1::InvalidEncoding),
        (61, 0x41, WorldClosureBindingErrorV1::InvalidEncoding),
        (96, 0x40, WorldClosureBindingErrorV1::InvalidEncoding),
        (232, 0xf7, WorldClosureBindingErrorV1::InvalidEncoding),
        (235, 0x82, WorldClosureBindingErrorV1::InvalidEncoding),
    ] {
        let mut bytes = valid.clone();
        bytes[offset] = replacement;
        assert_eq!(
            WorldClosureBindingV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }

    let mut hostile_length = valid;
    hostile_length.splice(
        7..=7,
        [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    );
    assert!(hostile_length.len() < MAX_WORLD_CLOSURE_BINDING_BYTES_V1);
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&hostile_length),
        Err(WorldClosureBindingErrorV1::InvalidEncoding)
    );
}

#[test]
fn public_decoder_rejects_nonpreferred_integer_length_and_array_headers() {
    let valid = literal_baseline();
    for (offset, replacement) in [
        (0, vec![0x98, 14]),
        (6, vec![0x18, 1]),
        (7, vec![0x58, 16]),
        (59, vec![0x18, 0]),
        (232, vec![0xf8, 22]),
    ] {
        let mut bytes = valid.clone();
        bytes.splice(offset..=offset, replacement);
        let expected = if offset == 232 {
            WorldClosureBindingErrorV1::InvalidEncoding
        } else {
            WorldClosureBindingErrorV1::NonCanonicalEncoding
        };
        assert_eq!(
            WorldClosureBindingV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }
    for initial in [0x9f, 0xbf, 0xff] {
        let mut bytes = valid.clone();
        bytes[0] = initial;
        assert_eq!(
            WorldClosureBindingV1::from_canonical_cbor(&bytes),
            Err(WorldClosureBindingErrorV1::InvalidEncoding)
        );
    }
}

#[test]
fn public_decoder_enforces_integer_width_and_structural_relations() {
    let valid = literal_baseline();
    let mut partition_overflow = valid.clone();
    partition_overflow.splice(60..=60, [0x1a, 0, 1, 0, 0]);
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&partition_overflow),
        Err(WorldClosureBindingErrorV1::FieldOutOfBounds)
    );
    let mut depth_overflow = valid.clone();
    depth_overflow.splice(238..=238, [0x19, 1, 0]);
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&depth_overflow),
        Err(WorldClosureBindingErrorV1::FieldOutOfBounds)
    );
    let mut no_visits = valid.clone();
    no_visits[236] = 0;
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&no_visits),
        Err(WorldClosureBindingErrorV1::FieldOutOfBounds)
    );
    let mut no_history = valid.clone();
    no_history[95] = 1;
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&no_history),
        Err(WorldClosureBindingErrorV1::InvalidHistoryRelation)
    );
    let mut extra_history = valid.clone();
    extra_history.splice(232..=232, [0x58, 0x20].into_iter().chain([5; 32]));
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&extra_history),
        Err(WorldClosureBindingErrorV1::InvalidHistoryRelation)
    );
    let mut zero_lease = valid;
    zero_lease[132..164].fill(0);
    assert_eq!(
        WorldClosureBindingV1::from_canonical_cbor(&zero_lease),
        Err(WorldClosureBindingErrorV1::ZeroContentAddress)
    );
}

#[test]
fn public_closed_errors_have_nonempty_display() {
    for error in [
        WorldClosureBindingErrorV1::InvalidEncoding,
        WorldClosureBindingErrorV1::UnsupportedVersion,
        WorldClosureBindingErrorV1::FieldOutOfBounds,
        WorldClosureBindingErrorV1::InvalidHistoryRelation,
        WorldClosureBindingErrorV1::ZeroContentAddress,
        WorldClosureBindingErrorV1::NonCanonicalEncoding,
    ] {
        assert!(!error.to_string().is_empty());
    }
}
