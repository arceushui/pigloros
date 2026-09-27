use pos_core::{
    Hash, ReproManifestRootErrorV1, ReproManifestRootInputV1, ReproManifestRootV1,
    WorldReplayHandleV1, MAX_REPRO_MANIFEST_LABEL_BYTES_V1, MAX_REPRO_MANIFEST_ROOT_BYTES_V1,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn from_hex(text: &str) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for pair in text.as_bytes().chunks_exact(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?);
    }
    Ok(bytes)
}

fn vector() -> TestResult<Vec<u8>> {
    from_hex(concat!(
        "89444d524d31015820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e950a6517",
        "6c58a2894457524831015820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e95",
        "0a65176c501010101010101010101010101010101007582021212121212121212121212121212121",
        "21212121212121212121212121212121582031313131313131313131313131313131313131313131",
        "31313131313131313131015820414141414141414141414141414141414141414141414141414141",
        "41414141415820424242424242424242424242424242424242424242424242424242424242424258",
        "20434343434343434343434343434343434343434343434343434343434343434358205473435d6f",
        "e01b0ef3a6a8dc5e77380fafc4b06bb420bdf60f1d4f8502b95d3e01f6",
    ))
}

fn input() -> TestResult<ReproManifestRootInputV1> {
    let bytes = vector()?;
    Ok(ReproManifestRootInputV1 {
        owner_reference: Hash::from_bytes(<[u8; 32]>::try_from(&bytes[9..41])?),
        world_handle: WorldReplayHandleV1::from_canonical_cbor(&bytes[43..205])?,
        run_operation_id: Hash::from_bytes([0x42; 32]),
        plugin_roster_digest: Hash::from_bytes([0x43; 32]),
        adapter_transcript_digest: Hash::from_bytes(<[u8; 32]>::try_from(&bytes[275..307])?),
        created_at_micros: 1,
        label: None,
    })
}

#[test]
fn normative_mrm1_serialization_and_native_digest() -> TestResult<()> {
    let root = ReproManifestRootV1::new(input()?)?;
    let expected = vector()?;
    assert_eq!(expected.len(), 309);
    assert_eq!(root.to_canonical_cbor(), expected);
    assert_eq!(
        ReproManifestRootV1::from_canonical_cbor(&expected),
        Ok(root.clone())
    );
    assert_eq!(root.as_input(), &input()?);
    assert_eq!(
        root.digest().as_bytes().to_vec(),
        from_hex("1a2a8ec470055900d089307579f250e2f1f477d889f6d7fabb7c0fc6454f1b65")?
    );
    Ok(())
}

#[test]
fn labels_and_timestamp_integer_widths_round_trip() -> TestResult<()> {
    for timestamp in [
        0,
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
        let root = ReproManifestRootV1::new(ReproManifestRootInputV1 {
            created_at_micros: timestamp,
            label: Some("é".repeat(12)),
            ..input()?
        })?;
        let bytes = root.to_canonical_cbor();
        assert_eq!(ReproManifestRootV1::from_canonical_cbor(&bytes), Ok(root));
    }
    for length in [0, 23, 24, 255, MAX_REPRO_MANIFEST_LABEL_BYTES_V1] {
        let root = ReproManifestRootV1::new(ReproManifestRootInputV1 {
            label: Some("x".repeat(length)),
            ..input()?
        })?;
        let bytes = root.to_canonical_cbor();
        assert!(bytes.len() <= MAX_REPRO_MANIFEST_ROOT_BYTES_V1);
        assert_eq!(ReproManifestRootV1::from_canonical_cbor(&bytes), Ok(root));
    }
    Ok(())
}

#[test]
fn zero_or_mismatched_identity_and_long_label_reject() -> TestResult<()> {
    for candidate in [
        ReproManifestRootInputV1 {
            owner_reference: Hash::zero(),
            ..input()?
        },
        ReproManifestRootInputV1 {
            owner_reference: Hash::from_bytes([1; 32]),
            ..input()?
        },
        ReproManifestRootInputV1 {
            run_operation_id: Hash::zero(),
            ..input()?
        },
        ReproManifestRootInputV1 {
            plugin_roster_digest: Hash::zero(),
            ..input()?
        },
        ReproManifestRootInputV1 {
            adapter_transcript_digest: Hash::zero(),
            ..input()?
        },
    ] {
        assert_eq!(
            ReproManifestRootV1::new(candidate),
            Err(ReproManifestRootErrorV1::InvalidIdentity)
        );
    }
    assert_eq!(
        ReproManifestRootV1::new(ReproManifestRootInputV1 {
            label: Some("x".repeat(MAX_REPRO_MANIFEST_LABEL_BYTES_V1 + 1)),
            ..input()?
        }),
        Err(ReproManifestRootErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn malformed_noncanonical_and_oversized_roots_reject() -> TestResult<()> {
    let good = vector()?;
    let mut cases = vec![
        (Vec::new(), ReproManifestRootErrorV1::InvalidEncoding),
        (
            good[..45].to_vec(),
            ReproManifestRootErrorV1::InvalidEncoding,
        ),
        (
            vec![0; MAX_REPRO_MANIFEST_ROOT_BYTES_V1 + 1],
            ReproManifestRootErrorV1::FieldOutOfBounds,
        ),
    ];
    for (offset, value, error) in [
        (0, 0x88, ReproManifestRootErrorV1::InvalidEncoding),
        (2, b'X', ReproManifestRootErrorV1::InvalidEncoding),
        (6, 2, ReproManifestRootErrorV1::InvalidEncoding),
        (7, 0x57, ReproManifestRootErrorV1::InvalidEncoding),
        (41, 0x57, ReproManifestRootErrorV1::InvalidEncoding),
        (43, 0x88, ReproManifestRootErrorV1::InvalidEncoding),
        (205, 0x57, ReproManifestRootErrorV1::InvalidEncoding),
        (239, 0x57, ReproManifestRootErrorV1::InvalidEncoding),
        (273, 0x57, ReproManifestRootErrorV1::InvalidEncoding),
        (308, 0xff, ReproManifestRootErrorV1::InvalidEncoding),
        (308, 0x7f, ReproManifestRootErrorV1::InvalidEncoding),
    ] {
        let mut bytes = good.clone();
        bytes[offset] = value;
        cases.push((bytes, error));
    }
    let mut wrong_owner = good.clone();
    wrong_owner[9] ^= 1;
    cases.push((wrong_owner, ReproManifestRootErrorV1::InvalidIdentity));
    for range in [207..239, 241..273, 275..307] {
        let mut bytes = good.clone();
        bytes[range].fill(0);
        cases.push((bytes, ReproManifestRootErrorV1::InvalidIdentity));
    }
    let mut trailing = good.clone();
    trailing.push(0);
    cases.push((trailing, ReproManifestRootErrorV1::NonCanonical));
    let mut overlong_time = good.clone();
    overlong_time[307] = 0x18;
    overlong_time.insert(308, 1);
    cases.push((overlong_time, ReproManifestRootErrorV1::NonCanonical));
    let mut overlong_handle = good.clone();
    overlong_handle[41] = 0x59;
    overlong_handle.insert(42, 0);
    cases.push((overlong_handle, ReproManifestRootErrorV1::NonCanonical));
    let mut overbound_handle = good.clone();
    overbound_handle[41] = 0x59;
    overbound_handle[42] = 0x01;
    overbound_handle.insert(43, 0x01);
    cases.push((overbound_handle, ReproManifestRootErrorV1::FieldOutOfBounds));
    let mut enormous_label = good.clone();
    enormous_label[308] = 0x7a;
    enormous_label.extend_from_slice(&65_536_u32.to_be_bytes());
    cases.push((enormous_label, ReproManifestRootErrorV1::FieldOutOfBounds));
    for (bytes, expected) in cases {
        assert_eq!(
            ReproManifestRootV1::from_canonical_cbor(&bytes),
            Err(expected)
        );
    }
    Ok(())
}

#[test]
fn label_text_and_length_boundaries_reject() -> TestResult<()> {
    let root = ReproManifestRootV1::new(ReproManifestRootInputV1 {
        label: Some("x".to_owned()),
        ..input()?
    })?;
    let good = root.to_canonical_cbor();
    let mut invalid_utf8 = good.clone();
    let last = invalid_utf8.len() - 1;
    invalid_utf8[last] = 0xff;
    assert_eq!(
        ReproManifestRootV1::from_canonical_cbor(&invalid_utf8),
        Err(ReproManifestRootErrorV1::InvalidEncoding)
    );
    let mut long_label = vector()?;
    long_label.truncate(308);
    long_label.extend_from_slice(&[0x79, 0x01, 0x01]);
    long_label.extend_from_slice(&[b'x'; 257]);
    assert_eq!(
        ReproManifestRootV1::from_canonical_cbor(&long_label),
        Err(ReproManifestRootErrorV1::FieldOutOfBounds)
    );
    let mut truncated_label = good;
    truncated_label.pop();
    assert_eq!(
        ReproManifestRootV1::from_canonical_cbor(&truncated_label),
        Err(ReproManifestRootErrorV1::InvalidEncoding)
    );
    Ok(())
}
