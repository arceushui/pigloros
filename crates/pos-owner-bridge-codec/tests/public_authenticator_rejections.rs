use pos_owner_bridge_codec::{
    parse_assertion_authenticator_data, parse_none_attestation_object, CoseEs256PublicKey,
    OwnerBridgeCodecError, OwnerUserHandle, SubjectCredentialBindingInputV1,
    SubjectCredentialBindingV1, SubjectId, TransportCodes, VerificationReason as Reason,
};

/// Bytes of a valid attestation object up to and including the `authData` byte-string head.
const TRUNCATED_ATTESTATION_LENGTH: usize = 30;

/// One byte past the 1,024-byte credential-ID bound.
const OVERSIZED_EXPECTED_CREDENTIAL_ID: [u8; 1_025] = [0; 1_025];

const CREDENTIAL_ID: [u8; 2] = [0x80, 0x81];
const RP_ID_HASH: [u8; 32] = [
    0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
    0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63,
];

fn verified<T>(result: Result<T, Reason>) -> Result<T, OwnerBridgeCodecError> {
    result.map_err(OwnerBridgeCodecError::Verification)
}

#[test]
fn public_none_attestation_parser_accepts_the_closed_baseline() -> Result<(), OwnerBridgeCodecError>
{
    let authenticator_data = create_authenticator_data(&cose_key());
    let attestation = none_attestation_object(&authenticator_data)?;
    let parsed = verified(parse_none_attestation_object(&attestation, &CREDENTIAL_ID))?;
    assert_eq!(parsed.credential_id(), CREDENTIAL_ID);
    assert_eq!(parsed.sign_count(), 7);
    assert!(!parsed.backup_eligible());
    assert!(!parsed.backup_state());
    assert_eq!(parsed.public_key().canonical_encoding(), cose_key());
    Ok(())
}

#[test]
fn public_none_attestation_parser_rejects_closed_envelope_variations(
) -> Result<(), OwnerBridgeCodecError> {
    let authenticator_data = create_authenticator_data(&cose_key());
    let attestation = none_attestation_object(&authenticator_data)?;

    let mut wrong_format = attestation.clone();
    wrong_format[9] = b'x';
    assert_invalid_attestation(&wrong_format, &CREDENTIAL_ID);

    let mut non_empty_statement = attestation.clone();
    non_empty_statement[18] = 0xa1;
    assert_invalid_attestation(&non_empty_statement, &CREDENTIAL_ID);

    let mut unknown_field = attestation.clone();
    unknown_field[4] = b'x';
    assert_invalid_attestation(&unknown_field, &CREDENTIAL_ID);

    assert_eq!(
        parse_none_attestation_object(&attestation, &[0x81, 0x80]),
        Err(Reason::CredentialMismatch)
    );
    assert_invalid_attestation(b"\xa2\x63fmt\x64none\x67attStmt\xa0", &CREDENTIAL_ID);

    let mut trailing = attestation;
    trailing.push(0);
    assert_invalid_attestation(&trailing, &CREDENTIAL_ID);
    assert_invalid_attestation(&[], &CREDENTIAL_ID);
    let oversized = vec![0; 65_537];
    assert_invalid_attestation(&oversized, &CREDENTIAL_ID);
    assert_eq!(
        parse_none_attestation_object(b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x40", &[]),
        Err(Reason::CredentialMismatch)
    );
    // The expected ID is over the bound, so the truncated `authData` claim is never read.
    let truncated = &trailing[..TRUNCATED_ATTESTATION_LENGTH];
    assert_eq!(
        parse_none_attestation_object(truncated, &OVERSIZED_EXPECTED_CREDENTIAL_ID),
        Err(Reason::CredentialMismatch)
    );
    Ok(())
}

#[test]
fn public_none_attestation_parser_rejects_duplicate_fields_and_wrong_cbor_types(
) -> Result<(), OwnerBridgeCodecError> {
    let authenticator_data = create_authenticator_data(&cose_key());
    let attestation = none_attestation_object(&authenticator_data)?;

    let mut wrong_format_type = attestation.clone();
    wrong_format_type[5] = 0x40;
    assert_invalid_attestation(&wrong_format_type, &CREDENTIAL_ID);

    let mut wrong_authenticator_data_type = attestation;
    wrong_authenticator_data_type[28] = 0x60;
    assert_invalid_attestation(&wrong_authenticator_data_type, &CREDENTIAL_ID);

    let mut duplicate_authenticator_data = Vec::from(b"\xa3\x68authData\x58".as_slice());
    let authenticator_data_length = u8::try_from(authenticator_data.len())
        .map_err(|_| OwnerBridgeCodecError::BoundsExceeded)?;
    duplicate_authenticator_data.push(authenticator_data_length);
    duplicate_authenticator_data.extend_from_slice(&authenticator_data);
    duplicate_authenticator_data.extend_from_slice(b"\x68authData");
    assert_invalid_attestation(&duplicate_authenticator_data, &CREDENTIAL_ID);
    Ok(())
}

#[test]
fn public_none_attestation_parser_rejects_truncated_cbor_claims(
) -> Result<(), OwnerBridgeCodecError> {
    for envelope in [
        b"\xa3\x78\x04x".as_slice(),
        b"\xa3\x61\xff".as_slice(),
        b"\xa3\x63fmt\x78\x04".as_slice(),
        b"\xa3\x63fmt\x61\xff".as_slice(),
    ] {
        assert_invalid_attestation(envelope, &CREDENTIAL_ID);
    }
    assert_invalid_attestation(b"\xa3\x63fmt\x78\x18", &CREDENTIAL_ID);

    let authenticator_data = create_authenticator_data(&cose_key());
    let missing_attested_fields = assertion_authenticator_data(0x45, &[]);
    for truncated in [&missing_attested_fields[..], &authenticator_data[..55]] {
        assert_eq!(
            parse_none_attestation_object(&none_attestation_object(truncated)?, &CREDENTIAL_ID),
            Err(Reason::Malformed)
        );
    }

    let mut truncated_algorithm_head = authenticator_data;
    truncated_algorithm_head[57 + 4] = 0x3b;
    truncated_algorithm_head.truncate(57 + 5);
    assert_eq!(
        parse_none_attestation_object(
            &none_attestation_object(&truncated_algorithm_head)?,
            &CREDENTIAL_ID,
        ),
        Err(Reason::CoseKey)
    );
    Ok(())
}

#[test]
fn public_none_attestation_parser_rejects_authenticator_and_cose_fields(
) -> Result<(), OwnerBridgeCodecError> {
    let authenticator_data = create_authenticator_data(&cose_key());

    let mut wrong_rp_id = authenticator_data.clone();
    wrong_rp_id[0] ^= 1;
    assert_eq!(
        parse_none_attestation_object(&none_attestation_object(&wrong_rp_id)?, &CREDENTIAL_ID),
        Err(Reason::RpIdHash)
    );

    for (label, flags, reason) in [
        ("missing user presence", 0x44, Reason::UserPresence),
        ("missing user verification", 0x41, Reason::UserVerification),
        ("reserved low bit", 0x47, Reason::Malformed),
        ("reserved high bit", 0x65, Reason::Malformed),
        ("backup state, no eligibility", 0x55, Reason::BackupFlags),
        ("missing attested credential data", 0x05, Reason::Malformed),
    ] {
        let mut mutated = authenticator_data.clone();
        mutated[32] = flags;
        assert_eq!(
            parse_none_attestation_object(&none_attestation_object(&mutated)?, &CREDENTIAL_ID),
            Err(reason),
            "{label}"
        );
    }

    let mut zero_credential_length = authenticator_data.clone();
    zero_credential_length[53..55].copy_from_slice(&0_u16.to_be_bytes());
    assert_eq!(
        parse_none_attestation_object(
            &none_attestation_object(&zero_credential_length)?,
            &CREDENTIAL_ID,
        ),
        Err(Reason::Malformed)
    );

    let mut oversized_credential_length = authenticator_data.clone();
    oversized_credential_length[53..55].copy_from_slice(&1_025_u16.to_be_bytes());
    assert_eq!(
        parse_none_attestation_object(
            &none_attestation_object(&oversized_credential_length)?,
            &CREDENTIAL_ID,
        ),
        Err(Reason::Malformed)
    );

    for (label, cose_offset, value, reason) in [
        ("wrong key type", 2, 1, Reason::CoseKey),
        ("wrong algorithm", 4, 0x25, Reason::Algorithm),
        ("wrong curve", 6, 2, Reason::CoseKey),
    ] {
        let mut mutated = authenticator_data.clone();
        mutated[57 + cose_offset] = value;
        assert_eq!(
            parse_none_attestation_object(&none_attestation_object(&mutated)?, &CREDENTIAL_ID),
            Err(reason),
            "{label}"
        );
    }
    let mut wrong_x_width = authenticator_data;
    wrong_x_width[57 + 8] = 0x57;
    assert_eq!(
        parse_none_attestation_object(&none_attestation_object(&wrong_x_width)?, &CREDENTIAL_ID),
        Err(Reason::CoseKey)
    );
    Ok(())
}

#[test]
fn public_attestation_parser_reports_a_foreign_algorithm_before_the_key_shape(
) -> Result<(), OwnerBridgeCodecError> {
    let key = cose_key();
    let mut eddsa = b"\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20".to_vec();
    eddsa.extend_from_slice(&key[10..42]);
    let mut rs256 = b"\xa5\x01\x02\x03\x39\x01\x00\x20\x01\x21".to_vec();
    rs256.extend_from_slice(&key[8..10]);
    rs256.extend_from_slice(&key[10..42]);
    rs256.extend_from_slice(&key[42..]);
    for foreign in [eddsa, rs256] {
        assert_cose_reason(&foreign, Reason::Algorithm)?;
    }
    Ok(())
}

#[test]
fn public_attestation_parser_defers_to_the_key_shape_when_no_algorithm_is_found(
) -> Result<(), OwnerBridgeCodecError> {
    let key = cose_key();
    let mut duplicate_algorithm = b"\xa5\x01\x02\x03\x26\x03\x26\x20\x01".to_vec();
    duplicate_algorithm.extend_from_slice(&key[7..42]);
    let malformed_keys: [&[u8]; 6] = [
        b"\x80",
        b"\xa1\x40",
        b"\xa1\x01\xf9\x00\x00",
        b"\xa1\x01\x02",
        b"\xa1\x03\x61a",
        &duplicate_algorithm,
    ];
    for malformed in malformed_keys {
        assert_cose_reason(malformed, Reason::CoseKey)?;
    }
    Ok(())
}

#[test]
fn public_attestation_parser_rejects_every_duplicated_envelope_member(
) -> Result<(), OwnerBridgeCodecError> {
    let data = create_authenticator_data(&cose_key());
    let mut authenticator_member = b"\x68authData\x58".to_vec();
    let length = u8::try_from(data.len()).map_err(|_| OwnerBridgeCodecError::BoundsExceeded)?;
    authenticator_member.push(length);
    authenticator_member.extend_from_slice(&data);
    let format = b"\x63fmt\x64none".as_slice();
    let statement = b"\x67attStmt\xa0".as_slice();
    let authenticator = authenticator_member.as_slice();
    for members in [
        [format, format, authenticator],
        [format, statement, statement],
        [authenticator, authenticator, format],
    ] {
        let object = [b"\xa3".as_slice(), &members.concat()].concat();
        assert_eq!(
            parse_none_attestation_object(&object, &CREDENTIAL_ID),
            Err(Reason::AttestationFormat)
        );
    }
    Ok(())
}

#[test]
fn public_cose_members_reject_duplicates() -> Result<(), OwnerBridgeCodecError> {
    let key = cose_key();
    let (kty, algorithm, curve) = (&key[1..3], &key[3..5], &key[5..7]);
    let (x_member, y_member) = (&key[7..42], &key[42..]);
    for members in [
        [kty, kty, algorithm, curve, x_member],
        [kty, algorithm, curve, curve, x_member],
        [kty, algorithm, curve, x_member, x_member],
        [kty, algorithm, curve, y_member, y_member],
    ] {
        let duplicated = [b"\xa5".as_slice(), &members.concat()].concat();
        assert_cose_reason(&duplicated, Reason::CoseKey)?;
    }
    let mut unsigned_algorithm = key;
    unsigned_algorithm[4] = 0x05;
    assert_cose_reason(&unsigned_algorithm, Reason::Algorithm)
}

#[test]
fn public_parsers_accept_the_exact_limits() -> Result<(), OwnerBridgeCodecError> {
    let mut sixteen_entries = Vec::from([0xb0]);
    for name in b'a'..=b'p' {
        sixteen_entries.extend([0x61, name, 0xf5]);
    }
    let mut largest = Vec::from([0xa1, 0x61, b'a', 0x59, 0x03, 0xd5]);
    largest.extend(core::iter::repeat_n(0, 981));
    let accepted = [
        sixteen_entries,
        b"\xa1\x61a\x81\x81\x81\xf5".to_vec(),
        b"\xa1\x61a\xa1\x61b\xa1\x61c\xa1\x61d\xf5".to_vec(),
        largest,
    ];
    for extension in &accepted {
        let data = assertion_authenticator_data(0x85, extension);
        let parsed = verified(parse_assertion_authenticator_data(&data))?;
        assert_eq!(parsed.sign_count(), 9);
    }
    let largest_data = assertion_authenticator_data(0x85, &accepted[3]);
    assert_eq!(largest_data.len(), 1_024);
    assert_assertion_data_reason(
        &assertion_authenticator_data(0x85, b"\xa1\x61x\xf7"),
        Reason::Extensions,
    );

    let mut backed_up = create_authenticator_data(&cose_key());
    backed_up[32] = 0x5d;
    let attestation = none_attestation_object(&backed_up)?;
    let parsed = verified(parse_none_attestation_object(&attestation, &CREDENTIAL_ID))?;
    assert!(parsed.backup_eligible());
    assert!(parsed.backup_state());
    Ok(())
}

#[test]
fn public_durable_binding_rejects_a_non_curve_attestation_key() -> Result<(), OwnerBridgeCodecError>
{
    let mut authenticator_data = create_authenticator_data(&cose_key());
    authenticator_data[57 + 10..57 + 42].fill(0);
    let attestation = none_attestation_object(&authenticator_data)?;
    let parsed = verified(parse_none_attestation_object(&attestation, &CREDENTIAL_ID))?;

    assert_eq!(
        SubjectCredentialBindingV1::new(SubjectCredentialBindingInputV1 {
            owner_id: "owner",
            subject_id: SubjectId::from_bytes([0; 16]),
            epoch: 1,
            credential_id: parsed.credential_id(),
            user_handle: OwnerUserHandle::from_bytes([0; 32]),
            public_key: parsed.public_key(),
            backup_eligible: parsed.backup_eligible(),
            backup_state: parsed.backup_state(),
            sign_count: parsed.sign_count(),
            transports: TransportCodes::new(&[])?,
        }),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    Ok(())
}

#[test]
fn public_authenticator_parsers_reject_every_truncated_public_record(
) -> Result<(), OwnerBridgeCodecError> {
    let authenticator_data = create_authenticator_data(&cose_key());
    let attestation = none_attestation_object(&authenticator_data)?;
    for length in 0..attestation.len() {
        assert!(
            parse_none_attestation_object(&attestation[..length], &CREDENTIAL_ID).is_err(),
            "attestation prefix {length}"
        );
    }

    let assertion = assertion_authenticator_data(0x85, b"\xa1\x61x\xf5");
    for length in 0..assertion.len() {
        assert!(
            parse_assertion_authenticator_data(&assertion[..length]).is_err(),
            "assertion prefix {length}"
        );
    }

    let key = cose_key();
    for length in 0..key.len() {
        assert!(
            CoseEs256PublicKey::from_canonical_encoding(&key[..length]).is_err(),
            "COSE key prefix {length}"
        );
    }
    Ok(())
}

#[test]
fn public_assertion_authenticator_parser_enforces_flags_and_exact_length(
) -> Result<(), OwnerBridgeCodecError> {
    let baseline = assertion_authenticator_data(0x05, &[]);
    let parsed_baseline = verified(parse_assertion_authenticator_data(&baseline))?;
    assert_eq!(parsed_baseline.sign_count(), 9);

    for (flags, backup_state) in [(0x0d, false), (0x1d, true)] {
        let data = assertion_authenticator_data(flags, &[]);
        let parsed = verified(parse_assertion_authenticator_data(&data))?;
        assert!(parsed.backup_eligible());
        assert_eq!(parsed.backup_state(), backup_state);
    }

    let mut wrong_rp_id = baseline.clone();
    wrong_rp_id[0] ^= 1;
    assert_assertion_data_reason(&wrong_rp_id, Reason::RpIdHash);

    for (label, flags, reason) in [
        ("missing user presence", 0x04, Reason::UserPresence),
        ("missing user verification", 0x01, Reason::UserVerification),
        ("reserved low bit", 0x07, Reason::Malformed),
        ("reserved high bit", 0x25, Reason::Malformed),
        ("backup state, no eligibility", 0x15, Reason::BackupFlags),
        (
            "attested credential data on assertion",
            0x45,
            Reason::Malformed,
        ),
    ] {
        let data = assertion_authenticator_data(flags, &[]);
        assert_eq!(
            parse_assertion_authenticator_data(&data),
            Err(reason),
            "{label}"
        );
    }

    let mut trailing = baseline;
    trailing.push(0);
    assert_assertion_data_reason(&trailing, Reason::Extensions);
    assert_assertion_data_reason(&[0; 36], Reason::Malformed);
    assert_assertion_data_reason(&[0; 1_025], Reason::Malformed);
    Ok(())
}

#[test]
fn public_assertion_authenticator_parser_enforces_the_extension_profile(
) -> Result<(), OwnerBridgeCodecError> {
    let valid_extension = assertion_authenticator_data(0x85, b"\xa1\x61x\xf5");
    let parsed_extension = verified(parse_assertion_authenticator_data(&valid_extension))?;
    assert_eq!(parsed_extension.sign_count(), 9);
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, &[])),
        Err(Reason::Extensions)
    );

    let invalid_extensions: [(&str, &[u8]); 4] = [
        ("array instead of map", b"\x81\xf5"),
        ("integer map key", b"\xa1\x01\xf5"),
        ("duplicate map key", b"\xa2\x61x\xf5\x61x\xf4"),
        ("tagged value", b"\xa1\x61x\xc0\xf5"),
    ];
    for (label, extension) in invalid_extensions {
        let data = assertion_authenticator_data(0x85, extension);
        assert_eq!(
            parse_assertion_authenticator_data(&data),
            Err(Reason::Extensions),
            "{label}"
        );
    }
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(
            0x85,
            b"\xa1\x61x\xf5\x00",
        )),
        Err(Reason::Extensions)
    );

    let mut too_many_entries = Vec::from([0xb1]);
    for key in b'a'..=b'q' {
        too_many_entries.extend([0x61, key, 0xf5]);
    }
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, &too_many_entries)),
        Err(Reason::Extensions)
    );

    let nested_too_deep = b"\xa1\x61a\xa1\x61b\xa1\x61c\xa1\x61d\xa1\x61e\xf5";
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, nested_too_deep)),
        Err(Reason::Extensions)
    );
    let nested_array_too_deep = b"\xa1\x61a\x81\x81\x81\x81\xf5";
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(
            0x85,
            nested_array_too_deep,
        )),
        Err(Reason::Extensions)
    );
    Ok(())
}

#[test]
fn public_assertion_extension_parser_accepts_every_closed_value_class(
) -> Result<(), OwnerBridgeCodecError> {
    let extension = extension_map_with_every_closed_value_class();
    let parsed = verified(parse_assertion_authenticator_data(
        &assertion_authenticator_data(0x85, &extension),
    ))?;
    assert_eq!(parsed.sign_count(), 9);

    let invalid_extensions: [(&str, &[u8]); 4] = [
        (
            "duplicate unsigned nested key",
            b"\xa1\x61m\xa2\x01\xf4\x01\xf5",
        ),
        (
            "duplicate negative nested key",
            b"\xa1\x61m\xa2\x20\xf4\x20\xf5",
        ),
        ("invalid UTF-8 extension text", b"\xa1\x61s\x61\xff"),
        ("indefinite extension value", b"\xa1\x61x\x9f"),
    ];
    for (label, extension) in invalid_extensions {
        assert_eq!(
            parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, extension)),
            Err(Reason::Extensions),
            "{label}"
        );
    }
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(
            0x85,
            b"\xa1\x61x\x58\x18",
        )),
        Err(Reason::Extensions)
    );
    Ok(())
}

#[test]
fn public_assertion_extension_parser_rejects_truncated_cbor_values() {
    for extension in [
        b"\xa1\x61x\x58\x04x".as_slice(),
        b"\xa1\x61x\x78\x04x".as_slice(),
    ] {
        assert_eq!(
            parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, extension)),
            Err(Reason::Extensions)
        );
    }
    for extension in [
        b"\xa1\x61x\x98\x10".as_slice(),
        b"\xa1\x61x\xb8\x10".as_slice(),
    ] {
        assert_eq!(
            parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, extension)),
            Err(Reason::Extensions)
        );
    }
}

#[test]
fn public_assertion_extension_parser_rejects_malformed_map_keys_and_counted_text() {
    for extension in [b"\xa1\x61\xff\xf4".as_slice(), b"\xa1\x40\xf4".as_slice()] {
        assert_eq!(
            parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, extension)),
            Err(Reason::Extensions)
        );
    }
    for extension in [b"\xa1\x78\x18".as_slice(), b"\xa1\x61x\x78\x18".as_slice()] {
        assert_eq!(
            parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, extension)),
            Err(Reason::Extensions)
        );
    }
}

#[test]
fn public_cose_canonical_decoder_rejects_each_closed_map_shape() {
    let key = cose_key();

    let mut wrong_map_length = key;
    wrong_map_length[0] = 0xa4;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&wrong_map_length),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut duplicate_y = key;
    duplicate_y[7] = 0x22;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&duplicate_y),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut unknown_key = key;
    unknown_key[1] = 4;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&unknown_key),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut x_as_text = key;
    x_as_text[8] = 0x60;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&x_as_text),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut oversized_algorithm = Vec::from(key);
    oversized_algorithm.splice(4..5, [0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&oversized_algorithm),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
}

#[test]
fn public_cose_canonical_decoder_rejects_malformed_numeric_claims() {
    let key = cose_key();

    let mut kty_as_negative = key;
    kty_as_negative[2] = 0x20;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&kty_as_negative),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut algorithm_as_unsigned = key;
    algorithm_as_unsigned[4] = 0;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&algorithm_as_unsigned),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
}

#[test]
fn public_cose_canonical_decoder_rejects_alternate_encodings_and_invalid_points(
) -> Result<(), OwnerBridgeCodecError> {
    let key = cose_key();
    let parsed = CoseEs256PublicKey::from_canonical_encoding(&key)?;
    assert_eq!(parsed.canonical_encoding(), key);
    assert_eq!(parsed.x(), key[10..42]);
    assert_eq!(parsed.y(), key[45..]);
    let sec1 = parsed.uncompressed_sec1_bytes();
    assert_eq!(sec1[0], 4);
    assert_eq!(sec1[1..33], key[10..42]);
    assert_eq!(sec1[33..], key[45..]);

    let mut invalid_point = key;
    invalid_point[10..42].fill(0);
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&invalid_point),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut trailing = Vec::from(key);
    trailing.push(0);
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&trailing),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut noncanonical = Vec::from([0xb8, 5]);
    noncanonical.extend_from_slice(&key[1..]);
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&noncanonical),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut algorithm_as_bytes = key;
    algorithm_as_bytes[4] = 0x40;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&algorithm_as_bytes),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut duplicate_kty = key;
    duplicate_kty[3] = 1;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&duplicate_kty),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut duplicate_x = key;
    duplicate_x[42] = 0x21;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&duplicate_x),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut non_integer_cose_key = key;
    non_integer_cose_key[1] = 0x41;
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&non_integer_cose_key),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    Ok(())
}

fn assert_cose_reason(cose: &[u8], reason: Reason) -> Result<(), OwnerBridgeCodecError> {
    let attestation = none_attestation_object(&create_authenticator_data(cose))?;
    assert_eq!(
        parse_none_attestation_object(&attestation, &CREDENTIAL_ID),
        Err(reason)
    );
    Ok(())
}

fn assert_invalid_attestation(attestation: &[u8], raw_id: &[u8]) {
    assert_eq!(
        parse_none_attestation_object(attestation, raw_id),
        Err(Reason::AttestationFormat)
    );
}

fn assert_assertion_data_reason(input: &[u8], reason: Reason) {
    assert_eq!(parse_assertion_authenticator_data(input), Err(reason));
}

fn create_authenticator_data(cose_key: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(134);
    output.extend_from_slice(&RP_ID_HASH);
    output.push(0x45);
    output.extend_from_slice(&7_u32.to_be_bytes());
    output.extend_from_slice(&[0; 16]);
    output.extend_from_slice(&2_u16.to_be_bytes());
    output.extend_from_slice(&CREDENTIAL_ID);
    output.extend_from_slice(cose_key);
    output
}

fn assertion_authenticator_data(flags: u8, extension: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(37 + extension.len());
    output.extend_from_slice(&RP_ID_HASH);
    output.push(flags);
    output.extend_from_slice(&9_u32.to_be_bytes());
    output.extend_from_slice(extension);
    output
}

fn extension_map_with_every_closed_value_class() -> Vec<u8> {
    let mut output = Vec::from([
        0xa9, 0x61, b'u', 0x18, 24, 0x61, b'v', 0x19, 0, 24, 0x61, b'w', 0x1a, 0, 0, 0, 24, 0x61,
        b'x', 0x1b, 0, 0, 0, 0, 0, 0, 0, 24, 0x61, b'n', 0x38, 24, 0x61, b'b', 0x58, 24,
    ]);
    output.extend(core::iter::repeat_n(0, 24));
    output.extend(b"\x61s\x78\x18abcdefghijklmnopqrstuvwx");
    output.extend(b"\x61a\x85\x01\x20\xf4\xf5\xf6\x61m\xa3\x01\xf4\x20\xf5\x61q\x61r");
    output
}

fn none_attestation_object(authenticator_data: &[u8]) -> Result<Vec<u8>, OwnerBridgeCodecError> {
    let length = u8::try_from(authenticator_data.len())
        .map_err(|_| OwnerBridgeCodecError::BoundsExceeded)?;
    let mut output = Vec::with_capacity(30 + authenticator_data.len());
    output.extend_from_slice(b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58");
    output.push(length);
    output.extend_from_slice(authenticator_data);
    Ok(output)
}

fn cose_key() -> [u8; 77] {
    hex::<77>(b"a50102032620012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
}

fn hex<const N: usize>(input: &[u8]) -> [u8; N] {
    assert_eq!(input.len(), N * 2);
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(input[index * 2]);
        let low = hex_nibble(input[index * 2 + 1]);
        assert!(high < 16);
        assert!(low < 16);
        *byte = (high << 4) | low;
    }
    output
}

const fn hex_nibble(input: u8) -> u8 {
    match input {
        b'0'..=b'9' => input - b'0',
        b'a'..=b'f' => input - b'a' + 10,
        _ => u8::MAX,
    }
}
