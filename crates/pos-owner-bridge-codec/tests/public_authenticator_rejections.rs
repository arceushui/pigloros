use pos_owner_bridge_codec::{
    parse_assertion_authenticator_data, parse_none_attestation_object, CoseEs256PublicKey,
    OwnerBridgeCodecError,
};

const CREDENTIAL_ID: [u8; 2] = [0x80, 0x81];
const RP_ID_HASH: [u8; 32] = [
    0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
    0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63,
];

#[test]
fn public_none_attestation_parser_accepts_the_closed_baseline() -> Result<(), OwnerBridgeCodecError>
{
    let authenticator_data = create_authenticator_data(cose_key());
    let attestation = none_attestation_object(&authenticator_data)?;
    let parsed = parse_none_attestation_object(&attestation, &CREDENTIAL_ID)?;
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
    let authenticator_data = create_authenticator_data(cose_key());
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

    assert_invalid_attestation(&attestation, &[0x81, 0x80]);
    assert_invalid_attestation(b"\xa2\x63fmt\x64none\x67attStmt\xa0", &CREDENTIAL_ID);

    let mut trailing = attestation;
    trailing.push(0);
    assert_eq!(
        parse_none_attestation_object(&trailing, &CREDENTIAL_ID),
        Err(OwnerBridgeCodecError::TrailingBytes)
    );
    assert_eq!(
        parse_none_attestation_object(&[], &CREDENTIAL_ID),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    let oversized = vec![0; 65_537];
    assert_eq!(
        parse_none_attestation_object(&oversized, &CREDENTIAL_ID),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        parse_none_attestation_object(b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x40", &[]),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn public_none_attestation_parser_rejects_authenticator_and_cose_fields(
) -> Result<(), OwnerBridgeCodecError> {
    let authenticator_data = create_authenticator_data(cose_key());

    let mut wrong_rp_id = authenticator_data.clone();
    wrong_rp_id[0] ^= 1;
    assert_invalid_attestation(&none_attestation_object(&wrong_rp_id)?, &CREDENTIAL_ID);

    for (label, flags) in [
        ("missing user presence", 0x44),
        ("missing user verification", 0x41),
        ("reserved low bit", 0x47),
        ("reserved high bit", 0x65),
        ("backup state without eligibility", 0x55),
        ("missing attested credential data", 0x05),
    ] {
        let mut mutated = authenticator_data.clone();
        mutated[32] = flags;
        assert_eq!(
            parse_none_attestation_object(&none_attestation_object(&mutated)?, &CREDENTIAL_ID),
            Err(OwnerBridgeCodecError::InvalidPayload),
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
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );

    for (label, cose_offset, value) in [
        ("wrong key type", 2, 1),
        ("wrong algorithm", 4, 0x25),
        ("wrong curve", 6, 2),
    ] {
        let mut mutated = authenticator_data.clone();
        mutated[57 + cose_offset] = value;
        assert_eq!(
            parse_none_attestation_object(&none_attestation_object(&mutated)?, &CREDENTIAL_ID),
            Err(OwnerBridgeCodecError::InvalidPayload),
            "{label}"
        );
    }
    let mut wrong_x_width = authenticator_data;
    wrong_x_width[57 + 8] = 0x57;
    assert_eq!(
        parse_none_attestation_object(&none_attestation_object(&wrong_x_width)?, &CREDENTIAL_ID),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn public_assertion_authenticator_parser_enforces_flags_and_exact_length(
) -> Result<(), OwnerBridgeCodecError> {
    let baseline = assertion_authenticator_data(0x05, &[]);
    assert_eq!(
        parse_assertion_authenticator_data(&baseline)?.sign_count(),
        9
    );

    let mut wrong_rp_id = baseline.clone();
    wrong_rp_id[0] ^= 1;
    assert_invalid_assertion_data(&wrong_rp_id);

    for (label, flags) in [
        ("missing user presence", 0x04),
        ("missing user verification", 0x01),
        ("reserved low bit", 0x07),
        ("reserved high bit", 0x25),
        ("backup state without eligibility", 0x15),
        ("attested credential data on assertion", 0x45),
    ] {
        let data = assertion_authenticator_data(flags, &[]);
        assert_eq!(
            parse_assertion_authenticator_data(&data),
            Err(OwnerBridgeCodecError::InvalidPayload),
            "{label}"
        );
    }

    let mut trailing = baseline;
    trailing.push(0);
    assert_eq!(
        parse_assertion_authenticator_data(&trailing),
        Err(OwnerBridgeCodecError::TrailingBytes)
    );
    assert_eq!(
        parse_assertion_authenticator_data(&[0; 36]),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        parse_assertion_authenticator_data(&[0; 1_025]),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn public_assertion_authenticator_parser_enforces_the_extension_profile(
) -> Result<(), OwnerBridgeCodecError> {
    let valid_extension = assertion_authenticator_data(0x85, b"\xa1\x61x\xf5");
    assert_eq!(
        parse_assertion_authenticator_data(&valid_extension)?.sign_count(),
        9
    );
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, &[])),
        Err(OwnerBridgeCodecError::BoundsExceeded)
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
            Err(OwnerBridgeCodecError::InvalidPayload),
            "{label}"
        );
    }
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(
            0x85,
            b"\xa1\x61x\xf5\x00",
        )),
        Err(OwnerBridgeCodecError::TrailingBytes)
    );

    let mut too_many_entries = Vec::from([0xb1]);
    for key in b'a'..=b'q' {
        too_many_entries.extend([0x61, key, 0xf5]);
    }
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, &too_many_entries)),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );

    let nested_too_deep = b"\xa1\x61a\xa1\x61b\xa1\x61c\xa1\x61d\xa1\x61e\xf5";
    assert_eq!(
        parse_assertion_authenticator_data(&assertion_authenticator_data(0x85, nested_too_deep)),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn public_cose_canonical_decoder_rejects_alternate_encodings_and_invalid_points(
) -> Result<(), OwnerBridgeCodecError> {
    let key = cose_key();
    assert_eq!(
        CoseEs256PublicKey::from_canonical_encoding(&key)?.canonical_encoding(),
        key
    );

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
    Ok(())
}

fn assert_invalid_attestation(attestation: &[u8], raw_id: &[u8]) {
    assert_eq!(
        parse_none_attestation_object(attestation, raw_id),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
}

fn assert_invalid_assertion_data(input: &[u8]) {
    assert_eq!(
        parse_assertion_authenticator_data(input),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
}

fn create_authenticator_data(cose_key: [u8; 77]) -> Vec<u8> {
    let mut output = Vec::with_capacity(134);
    output.extend_from_slice(&RP_ID_HASH);
    output.push(0x45);
    output.extend_from_slice(&7_u32.to_be_bytes());
    output.extend_from_slice(&[0; 16]);
    output.extend_from_slice(&2_u16.to_be_bytes());
    output.extend_from_slice(&CREDENTIAL_ID);
    output.extend_from_slice(&cose_key);
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
