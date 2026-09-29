use pos_core::{
    ForkAdmissionAuthorityCodecErrorV1, ForkAdmissionHostRecordV1,
    ForkAdmissionInitializeChallengeV1, ForkAdmissionOpenChallengeV1, Hash, PublicKey,
};

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

const fn key(value: u8) -> PublicKey {
    PublicKey::from_bytes([value; 32])
}

fn expect_out_of_bounds<T>(result: Result<T, ForkAdmissionAuthorityCodecErrorV1>) {
    assert_eq!(
        result.err(),
        Some(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn public_authority_codecs_reject_each_invalid_field_and_cbor_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkAdmissionHostRecordV1::new(hash(1), key(2), hash(3))?;
    let initialize = ForkAdmissionInitializeChallengeV1::new(hash(1), hash(2), key(3), hash(4))?;
    let open = ForkAdmissionOpenChallengeV1::new(hash(1), hash(2), hash(3))?;

    assert_eq!(
        initialize.host_record(),
        ForkAdmissionHostRecordV1::new(hash(1), key(3), hash(4))?
    );

    for field in [9, 43, 77] {
        let mut bytes = host.to_canonical_cbor()?;
        bytes[field..field + 32].fill(0);
        expect_out_of_bounds(ForkAdmissionHostRecordV1::from_canonical_cbor(&bytes));
    }
    for field in [9, 43, 77, 111] {
        let mut bytes = initialize.to_canonical_cbor()?;
        bytes[field..field + 32].fill(0);
        expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::from_canonical_cbor(
            &bytes,
        ));
    }
    for field in [9, 43, 77] {
        let mut bytes = open.to_canonical_cbor()?;
        bytes[field..field + 32].fill(0);
        expect_out_of_bounds(ForkAdmissionOpenChallengeV1::from_canonical_cbor(&bytes));
    }

    expect_out_of_bounds(ForkAdmissionHostRecordV1::new(
        Hash::zero(),
        key(2),
        hash(3),
    ));
    expect_out_of_bounds(ForkAdmissionHostRecordV1::new(hash(1), key(0), hash(3)));
    expect_out_of_bounds(ForkAdmissionHostRecordV1::new(
        hash(1),
        key(2),
        Hash::zero(),
    ));
    expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::new(
        Hash::zero(),
        hash(2),
        key(3),
        hash(4),
    ));
    expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::new(
        hash(1),
        Hash::zero(),
        key(3),
        hash(4),
    ));
    expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::new(
        hash(1),
        hash(2),
        key(0),
        hash(4),
    ));
    expect_out_of_bounds(ForkAdmissionInitializeChallengeV1::new(
        hash(1),
        hash(2),
        key(3),
        Hash::zero(),
    ));
    expect_out_of_bounds(ForkAdmissionOpenChallengeV1::new(
        Hash::zero(),
        hash(2),
        hash(3),
    ));
    expect_out_of_bounds(ForkAdmissionOpenChallengeV1::new(
        hash(1),
        Hash::zero(),
        hash(3),
    ));
    expect_out_of_bounds(ForkAdmissionOpenChallengeV1::new(
        hash(1),
        hash(2),
        Hash::zero(),
    ));

    let mut trailing_field = host.to_canonical_cbor()?;
    trailing_field[0] = 0x84;
    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&trailing_field),
        Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&[0]),
        Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
    );
    let mut non_integer_version = host.to_canonical_cbor()?;
    non_integer_version[6] = 0xf5;
    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&non_integer_version),
        Err(ForkAdmissionAuthorityCodecErrorV1::InvalidEncoding)
    );
    let mut non_bytes_field = host.to_canonical_cbor()?;
    non_bytes_field.splice(7..41, [0xf6]);
    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&non_bytes_field),
        Err(ForkAdmissionAuthorityCodecErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn public_authority_codecs_round_trip_valid_records() -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkAdmissionHostRecordV1::new(hash(1), key(2), hash(3))?;
    let initialize = ForkAdmissionInitializeChallengeV1::new(hash(4), hash(5), key(6), hash(7))?;
    let open = ForkAdmissionOpenChallengeV1::new(hash(8), hash(9), hash(10))?;

    assert_eq!(initialize.store_id(), hash(4));
    assert_eq!(initialize.authentication_policy_digest(), hash(7));

    assert_eq!(
        ForkAdmissionHostRecordV1::from_canonical_cbor(&host.canonical_bytes())?,
        host
    );
    assert_eq!(
        ForkAdmissionInitializeChallengeV1::from_canonical_cbor(&initialize.canonical_bytes())?,
        initialize
    );
    assert_eq!(
        ForkAdmissionOpenChallengeV1::from_canonical_cbor(&open.canonical_bytes())?,
        open
    );
    Ok(())
}
