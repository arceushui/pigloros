use pos_core::{
    Hash, WorldRecordingReceiptErrorV1, WorldRecordingReceiptInputV1, WorldRecordingReceiptV1,
    MAX_WORLD_RECORDING_RECEIPT_BYTES_V1,
};

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn baseline_input() -> WorldRecordingReceiptInputV1 {
    WorldRecordingReceiptInputV1 {
        binding_hash: hash(1),
        operation_id: Hash::zero(),
        actual_commit_receipt_digest: hash(2),
        installed_inventory_generation: Hash::zero(),
    }
}

// Assembled independently of the WCR1 encoder. The fixed digest was computed
// with /usr/bin/b3sum over the accepted ASCII domain, NUL and these bytes.
fn literal_baseline() -> Vec<u8> {
    let mut bytes = vec![0x86, 0x44, b'W', b'C', b'R', b'1', 1];
    for value in [1, 0, 2, 0] {
        bytes.extend_from_slice(&[0x58, 0x20]);
        bytes.extend_from_slice(&[value; 32]);
    }
    bytes
}

#[test]
fn public_wcr1_matches_literal_wire_and_fixed_digest() -> Result<(), Box<dyn std::error::Error>> {
    let record = WorldRecordingReceiptV1::new(baseline_input())?;
    let literal = literal_baseline();
    assert_eq!(literal.len(), 143);
    assert_eq!(record.to_canonical_cbor(), literal);
    assert_eq!(
        record.digest(),
        Hash::from_bytes([
            0x08, 0xeb, 0x5a, 0x5f, 0xb7, 0xe4, 0x7f, 0x2a, 0x08, 0xc8, 0x46, 0xe1, 0x5e, 0xcf,
            0x27, 0x73, 0x5e, 0x81, 0x1d, 0x77, 0xaa, 0x4f, 0x8b, 0x59, 0x59, 0xbe, 0xb6, 0x40,
            0xab, 0x30, 0x0a, 0x61,
        ])
    );
    assert_eq!(
        WorldRecordingReceiptV1::from_canonical_cbor(&literal),
        Ok(record)
    );
    assert_eq!(record.as_input(), &baseline_input());
    Ok(())
}

#[test]
fn public_wcr1_preserves_opaque_owner_values_without_claiming_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = WorldRecordingReceiptInputV1 {
        binding_hash: hash(9),
        operation_id: hash(10),
        actual_commit_receipt_digest: hash(11),
        installed_inventory_generation: hash(12),
    };
    let record = WorldRecordingReceiptV1::new(input)?;
    assert_eq!(
        WorldRecordingReceiptV1::from_canonical_cbor(&record.to_canonical_cbor()),
        Ok(record)
    );
    assert_eq!(record.as_input(), &input);
    assert_ne!(
        record.digest(),
        WorldRecordingReceiptV1::new(baseline_input())?.digest()
    );
    Ok(())
}

#[test]
fn public_wcr1_rejects_zero_content_addresses_but_preserves_zero_opaque_ids() {
    let mut input = baseline_input();
    assert!(WorldRecordingReceiptV1::new(input).is_ok());
    input.binding_hash = Hash::zero();
    assert_eq!(
        WorldRecordingReceiptV1::new(input),
        Err(WorldRecordingReceiptErrorV1::ZeroContentAddress)
    );
    input = baseline_input();
    input.actual_commit_receipt_digest = Hash::zero();
    assert_eq!(
        WorldRecordingReceiptV1::new(input),
        Err(WorldRecordingReceiptErrorV1::ZeroContentAddress)
    );

    for offset in [9, 77] {
        let mut bytes = literal_baseline();
        bytes[offset..offset + 32].fill(0);
        assert_eq!(
            WorldRecordingReceiptV1::from_canonical_cbor(&bytes),
            Err(WorldRecordingReceiptErrorV1::ZeroContentAddress)
        );
    }
}

#[test]
fn public_wcr1_decoder_rejects_truncated_trailing_and_oversized_input() {
    let literal = literal_baseline();
    for prefix_length in 0..literal.len() {
        assert!(WorldRecordingReceiptV1::from_canonical_cbor(&literal[..prefix_length]).is_err());
    }
    let mut trailing = literal;
    trailing.push(0);
    assert_eq!(
        WorldRecordingReceiptV1::from_canonical_cbor(&trailing),
        Err(WorldRecordingReceiptErrorV1::InvalidEncoding)
    );
    assert_eq!(
        WorldRecordingReceiptV1::from_canonical_cbor(&vec![
            0;
            MAX_WORLD_RECORDING_RECEIPT_BYTES_V1
        ]),
        Err(WorldRecordingReceiptErrorV1::InvalidEncoding)
    );
    assert_eq!(
        WorldRecordingReceiptV1::from_canonical_cbor(&vec![
            0;
            MAX_WORLD_RECORDING_RECEIPT_BYTES_V1 + 1
        ]),
        Err(WorldRecordingReceiptErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn public_wcr1_decoder_rejects_wrong_types_and_nonpreferred_headers() {
    let literal = literal_baseline();
    for (offset, replacement) in [
        (0, 0x85),
        (1, 0x64),
        (2, b'X'),
        (7, 0x78),
        (8, 0x1f),
        (41, 0x40),
        (42, 0x1f),
        (75, 0x40),
        (76, 0x1f),
        (109, 0x40),
        (110, 0x1f),
    ] {
        let mut bytes = literal.clone();
        bytes[offset] = replacement;
        assert_eq!(
            WorldRecordingReceiptV1::from_canonical_cbor(&bytes),
            Err(WorldRecordingReceiptErrorV1::InvalidEncoding)
        );
    }
    let mut version = literal.clone();
    version[6] = 2;
    assert_eq!(
        WorldRecordingReceiptV1::from_canonical_cbor(&version),
        Err(WorldRecordingReceiptErrorV1::UnsupportedVersion)
    );

    for (offset, replacement) in [
        (0, vec![0x98, 6]),
        (1, vec![0x58, 4]),
        (6, vec![0x18, 1]),
        (7, vec![0x59, 0, 32]),
        (41, vec![0x59, 0, 32]),
        (75, vec![0x59, 0, 32]),
        (109, vec![0x59, 0, 32]),
    ] {
        let mut bytes = literal.clone();
        bytes.splice(offset..=offset, replacement);
        assert_eq!(
            WorldRecordingReceiptV1::from_canonical_cbor(&bytes),
            Err(WorldRecordingReceiptErrorV1::InvalidEncoding)
        );
    }
    let mut hostile_length = literal;
    hostile_length.splice(
        7..=7,
        [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    );
    assert!(hostile_length.len() < MAX_WORLD_RECORDING_RECEIPT_BYTES_V1);
    assert_eq!(
        WorldRecordingReceiptV1::from_canonical_cbor(&hostile_length),
        Err(WorldRecordingReceiptErrorV1::InvalidEncoding)
    );
}

#[test]
fn public_wcr1_errors_have_bounded_display_messages() {
    for (error, message) in [
        (
            WorldRecordingReceiptErrorV1::InvalidEncoding,
            "invalid WCR1 encoding",
        ),
        (
            WorldRecordingReceiptErrorV1::UnsupportedVersion,
            "unsupported WCR1 version",
        ),
        (
            WorldRecordingReceiptErrorV1::FieldOutOfBounds,
            "WCR1 record is too large",
        ),
        (
            WorldRecordingReceiptErrorV1::ZeroContentAddress,
            "WCR1 content address is zero",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
}
