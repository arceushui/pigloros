use pos_core::{
    Hash, TimelineId, WorldReplayHandleErrorV1, WorldReplayHandleInputV1, WorldReplayHandleV1,
    MAX_WORLD_REPLAY_HANDLE_BYTES_V1,
};
use ulid::Ulid;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn input() -> WorldReplayHandleInputV1 {
    WorldReplayHandleInputV1 {
        owner_reference: Hash::from_bytes([
            0x36, 0x56, 0x78, 0xef, 0x22, 0x86, 0xc7, 0xe6, 0x8a, 0xb7, 0xad, 0xa3, 0xf9, 0x0f,
            0x20, 0xfe, 0xca, 0x82, 0x2e, 0xfb, 0xc8, 0x8a, 0xbc, 0x5a, 0x7b, 0xf6, 0x0e, 0x95,
            0x0a, 0x65, 0x17, 0x6c,
        ]),
        timeline_id: TimelineId::from_ulid(Ulid::from(u128::from_be_bytes([0x10; 16]))),
        cut_id: 7,
        commit_receipt_digest: Hash::from_bytes([0x21; 32]),
        recording_receipt_digest: Hash::from_bytes([0x31; 32]),
        logical_head: 1,
        stitched_head_hash: Hash::from_bytes([0x41; 32]),
    }
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
fn normative_wrh1_selector_is_exact_and_round_trips() -> TestResult<()> {
    let handle = WorldReplayHandleV1::new(input())?;
    let expected = from_hex(concat!(
        "894457524831015820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc",
        "5a7bf60e950a65176c5010101010101010101010101010101010075820212121",
        "2121212121212121212121212121212121212121212121212121212121582031",
        "3131313131313131313131313131313131313131313131313131313131313101",
        "5820414141414141414141414141414141414141414141414141414141414141"
    ))?;
    assert_eq!(expected.len(), 162);
    assert_eq!(handle.to_canonical_cbor(), expected);
    assert_eq!(
        WorldReplayHandleV1::from_canonical_cbor(&expected),
        Ok(handle)
    );
    assert_eq!(handle.as_input(), &input());
    Ok(())
}

#[test]
fn integer_widths_and_exact_cut_identity_are_preserved() -> TestResult<()> {
    for value in [
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
        u64::MAX,
    ] {
        let handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
            cut_id: value,
            logical_head: value,
            ..input()
        })?;
        let bytes = handle.to_canonical_cbor();
        assert!(bytes.len() <= MAX_WORLD_REPLAY_HANDLE_BYTES_V1);
        assert_eq!(WorldReplayHandleV1::from_canonical_cbor(&bytes), Ok(handle));
    }
    let first = WorldReplayHandleV1::new(input())?;
    let second = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
        cut_id: 8,
        ..input()
    })?;
    assert_ne!(first.to_canonical_cbor(), second.to_canonical_cbor());
    Ok(())
}

#[test]
fn zero_cut_or_required_digest_rejects() {
    for candidate in [
        WorldReplayHandleInputV1 {
            cut_id: 0,
            ..input()
        },
        WorldReplayHandleInputV1 {
            owner_reference: Hash::zero(),
            ..input()
        },
        WorldReplayHandleInputV1 {
            commit_receipt_digest: Hash::zero(),
            ..input()
        },
        WorldReplayHandleInputV1 {
            recording_receipt_digest: Hash::zero(),
            ..input()
        },
        WorldReplayHandleInputV1 {
            stitched_head_hash: Hash::zero(),
            ..input()
        },
    ] {
        assert_eq!(
            WorldReplayHandleV1::new(candidate),
            Err(WorldReplayHandleErrorV1::InvalidHandle)
        );
    }
}

#[test]
fn malformed_noncanonical_and_oversized_handles_reject() -> TestResult<()> {
    let good = WorldReplayHandleV1::new(input())?.to_canonical_cbor();
    let mut cases = vec![
        (Vec::new(), WorldReplayHandleErrorV1::InvalidEncoding),
        (
            good[..58].to_vec(),
            WorldReplayHandleErrorV1::InvalidEncoding,
        ),
        (
            vec![0; MAX_WORLD_REPLAY_HANDLE_BYTES_V1 + 1],
            WorldReplayHandleErrorV1::FieldOutOfBounds,
        ),
    ];
    for (offset, value, error) in [
        (0, 0x88, WorldReplayHandleErrorV1::InvalidEncoding),
        (2, b'X', WorldReplayHandleErrorV1::InvalidEncoding),
        (6, 2, WorldReplayHandleErrorV1::InvalidEncoding),
        (7, 0x57, WorldReplayHandleErrorV1::InvalidEncoding),
        (41, 0x51, WorldReplayHandleErrorV1::InvalidEncoding),
        (58, 0, WorldReplayHandleErrorV1::InvalidHandle),
        (58, 0x1f, WorldReplayHandleErrorV1::InvalidEncoding),
    ] {
        let mut bytes = good.clone();
        bytes[offset] = value;
        cases.push((bytes, error));
    }
    let mut trailing = good.clone();
    trailing.push(0);
    cases.push((trailing, WorldReplayHandleErrorV1::InvalidEncoding));
    let mut overlong_cut = good;
    overlong_cut[58] = 0x18;
    overlong_cut.insert(59, 7);
    cases.push((overlong_cut, WorldReplayHandleErrorV1::NonCanonical));
    for (bytes, error) in cases {
        assert_eq!(WorldReplayHandleV1::from_canonical_cbor(&bytes), Err(error));
    }
    Ok(())
}
