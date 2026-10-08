use pos_owner_bridge_codec::{
    decode_assertion_reply, decode_attestation_reply, decode_create_options, decode_get_options,
    encode_assertion_reply, encode_attestation_reply, encode_create_options, encode_get_options,
    AssertionReplyV1, AttestationReplyV1, CeremonyId, CreateOptionsV1, GetOptionsV1,
    OwnerBridgeCodecError, OwnerUserHandle, PrfInput, PrfResult, TransportCodes,
    VerificationReason as Reason, WebAuthnChallenge,
};

/// A CBOR byte-string head (`0x58 0x20`) plus its 32 content bytes.
const FIXED_BYTES_ITEM: usize = 2 + 32;

/// An Assertion reply ends with the PRF result item, then the null `second` item.
const RESULT_ITEM_FROM_END: usize = FIXED_BYTES_ITEM + 1;

/// The user-handle item sits directly before the PRF result item.
const HANDLE_ITEM_FROM_END: usize = FIXED_BYTES_ITEM + RESULT_ITEM_FROM_END;

const CEREMONY_ID: CeremonyId = CeremonyId::from_bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);
const CHALLENGE: WebAuthnChallenge = WebAuthnChallenge::from_bytes([
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
]);
const USER_HANDLE: OwnerUserHandle = OwnerUserHandle::from_bytes([
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
]);
const PRF_INPUT: PrfInput = PrfInput::from_bytes([
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
]);
const PRF_RESULT: PrfResult = PrfResult::from_bytes([
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
]);

#[test]
fn public_payload_values_expose_every_field_and_enforce_bounds() -> Result<(), OwnerBridgeCodecError>
{
    let create = CreateOptionsV1::new(CEREMONY_ID, CHALLENGE, USER_HANDLE, PRF_INPUT);
    assert_eq!(create.ceremony_id(), CEREMONY_ID);
    assert_eq!(create.challenge(), CHALLENGE);
    assert_eq!(create.user_handle(), USER_HANDLE);
    assert_eq!(create.prf_input(), PRF_INPUT);

    let credential_id = [0x80, 0x81];
    let get = GetOptionsV1::new(CEREMONY_ID, CHALLENGE, &credential_id, PRF_INPUT)?;
    assert_eq!(get.ceremony_id(), CEREMONY_ID);
    assert_eq!(get.challenge(), CHALLENGE);
    assert_eq!(get.credential_id(), credential_id);
    assert_eq!(get.prf_input(), PRF_INPUT);
    assert_eq!(
        GetOptionsV1::new(CEREMONY_ID, CHALLENGE, &[], PRF_INPUT),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    let oversized_credential_id = vec![0; 1_025];
    assert_eq!(
        GetOptionsV1::new(CEREMONY_ID, CHALLENGE, &oversized_credential_id, PRF_INPUT),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );

    let all_transports = TransportCodes::new(&[0, 1, 2, 3, 4, 5])?;
    assert_eq!(all_transports.as_slice(), &[0, 1, 2, 3, 4, 5]);
    assert_eq!(
        TransportCodes::new(&[0, 1, 2, 3, 4, 5, 6]),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        TransportCodes::new(&[6]),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    assert_eq!(
        TransportCodes::new(&[1, 1]),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let attestation = AttestationReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        b"\xa0",
        all_transports,
        true,
        Some(PRF_RESULT),
    )?;
    assert_eq!(attestation.ceremony_id(), CEREMONY_ID);
    assert_eq!(attestation.raw_id(), credential_id);
    assert_eq!(attestation.client_data_json(), b"{}");
    assert_eq!(attestation.attestation_object(), b"\xa0");
    assert_eq!(attestation.transports(), all_transports);
    assert!(attestation.prf_enabled());
    assert_eq!(attestation.prf_first(), Some(PRF_RESULT));

    let assertion_authenticator_data = [0; 37];
    let assertion_signature = [0; 8];
    let assertion = AssertionReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        &assertion_authenticator_data,
        &assertion_signature,
        Some(USER_HANDLE),
        PRF_RESULT,
    )?;
    assert_eq!(assertion.ceremony_id(), CEREMONY_ID);
    assert_eq!(assertion.raw_id(), credential_id);
    assert_eq!(assertion.client_data_json(), b"{}");
    assert_eq!(assertion.authenticator_data(), assertion_authenticator_data);
    assert_eq!(assertion.signature(), assertion_signature);
    assert_eq!(assertion.user_handle(), Some(USER_HANDLE));
    assert_eq!(assertion.prf_first(), PRF_RESULT);

    assert_attestation_bounds(&oversized_credential_id)?;
    assert_assertion_bounds(&oversized_credential_id);
    Ok(())
}

#[test]
fn public_payload_codecs_cover_dynamic_lengths_and_short_buffers(
) -> Result<(), OwnerBridgeCodecError> {
    let create = CreateOptionsV1::new(CEREMONY_ID, CHALLENGE, USER_HANDLE, PRF_INPUT);
    let mut create_output = [0; 148];
    let create_length = encode_create_options(&create, &mut create_output)?;
    assert_eq!(
        decode_create_options(&create_output[..create_length]),
        Ok(create)
    );
    let mut create_short_output = [0; 147];
    assert_eq!(
        encode_create_options(&create, &mut create_short_output),
        Err(OwnerBridgeCodecError::BufferTooSmall)
    );

    let credential_id = vec![0x80; 1_024];
    let get = GetOptionsV1::new(CEREMONY_ID, CHALLENGE, &credential_id, PRF_INPUT)?;
    let mut get_output = vec![0; 1_200];
    let get_length = encode_get_options(&get, &mut get_output)?;
    assert_eq!(decode_get_options(&get_output[..get_length]), Ok(get));
    let mut get_short_output = vec![0; get_length - 1];
    assert_eq!(
        encode_get_options(&get, &mut get_short_output),
        Err(OwnerBridgeCodecError::BufferTooSmall)
    );

    let attestation_raw_id = vec![0x81; 24];
    let attestation_client_data = vec![b'c'; 256];
    let attestation_object = vec![b'a'; 65_536];
    let attestation = AttestationReplyV1::new(
        CEREMONY_ID,
        &attestation_raw_id,
        &attestation_client_data,
        &attestation_object,
        TransportCodes::new(&[0, 1, 2, 3, 4, 5])?,
        true,
        None,
    )?;
    let mut attestation_output = vec![0; 70_000];
    let attestation_length = encode_attestation_reply(&attestation, &mut attestation_output)?;
    assert_eq!(
        decode_attestation_reply(&attestation_output[..attestation_length]),
        Ok(attestation)
    );
    let mut attestation_short_output = vec![0; attestation_length - 1];
    assert_eq!(
        encode_attestation_reply(&attestation, &mut attestation_short_output),
        Err(OwnerBridgeCodecError::BufferTooSmall)
    );

    let assertion_raw_id = vec![0x82; 256];
    let assertion_client_data = vec![b'c'; 4_096];
    let assertion_authenticator_data = vec![0; 1_024];
    let assertion_signature = vec![0; 80];
    let assertion = AssertionReplyV1::new(
        CEREMONY_ID,
        &assertion_raw_id,
        &assertion_client_data,
        &assertion_authenticator_data,
        &assertion_signature,
        Some(USER_HANDLE),
        PRF_RESULT,
    )?;
    let mut assertion_output = vec![0; 6_000];
    let assertion_length = encode_assertion_reply(&assertion, &mut assertion_output)?;
    assert_eq!(
        decode_assertion_reply(&assertion_output[..assertion_length]),
        Ok(assertion)
    );
    let mut assertion_short_output = vec![0; assertion_length - 1];
    assert_eq!(
        encode_assertion_reply(&assertion, &mut assertion_short_output),
        Err(OwnerBridgeCodecError::BufferTooSmall)
    );
    Ok(())
}

#[test]
fn public_payload_decoders_reject_noncanonical_and_closed_schema_variations(
) -> Result<(), OwnerBridgeCodecError> {
    let create = CreateOptionsV1::new(CEREMONY_ID, CHALLENGE, USER_HANDLE, PRF_INPUT);
    let mut create_output = [0; 148];
    let create_length = encode_create_options(&create, &mut create_output)?;
    let create_bytes = &create_output[..create_length];

    let mut wrong_array = Vec::from(create_bytes);
    wrong_array[0] = 0x8a;
    assert_eq!(
        decode_create_options(&wrong_array),
        Err(OwnerBridgeCodecError::InvalidCbor)
    );
    let mut wrong_magic = Vec::from(create_bytes);
    wrong_magic[2] = b'X';
    assert_eq!(
        decode_create_options(&wrong_magic),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    let mut wrong_version = Vec::from(create_bytes);
    wrong_version[6] = 2;
    assert_eq!(
        decode_create_options(&wrong_version),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    let mut noncanonical_version = Vec::from(create_bytes);
    noncanonical_version.splice(6..7, [0x18, 1]);
    assert_eq!(
        decode_create_options(&noncanonical_version),
        Err(OwnerBridgeCodecError::NonCanonicalCbor)
    );
    let mut wrong_ceremony_width = Vec::from(create_bytes);
    wrong_ceremony_width[7] = 0x51;
    assert_eq!(
        decode_create_options(&wrong_ceremony_width),
        Err(OwnerBridgeCodecError::InvalidCbor)
    );
    let mut trailing = Vec::from(create_bytes);
    trailing.push(0);
    assert_eq!(
        decode_create_options(&trailing),
        Err(OwnerBridgeCodecError::TrailingBytes)
    );

    let raw_id = [0x80, 0x81];
    let attestation = AttestationReplyV1::new(
        CEREMONY_ID,
        &raw_id,
        b"{}",
        b"\xa0",
        TransportCodes::new(&[0, 1, 2, 3, 4, 5])?,
        true,
        None,
    )?;
    let mut attestation_output = [0; 96];
    let attestation_length = encode_attestation_reply(&attestation, &mut attestation_output)?;
    let attestation_bytes = &attestation_output[..attestation_length];

    let transport_offset = attestation_bytes
        .windows(7)
        .position(|window| window == [0x86, 0, 1, 2, 3, 4, 5])
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    let mut too_many_transports = Vec::from(attestation_bytes);
    too_many_transports[transport_offset] = 0x87;
    assert_eq!(
        decode_attestation_reply(&too_many_transports),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    let null_offset = attestation_bytes
        .iter()
        .position(|&value| value == 0xf6)
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    let mut invalid_optional = Vec::from(attestation_bytes);
    invalid_optional[null_offset] = 0xf4;
    assert_eq!(
        decode_attestation_reply(&invalid_optional),
        Err(OwnerBridgeCodecError::Verification(Reason::PrfMalformed))
    );
    let boolean_offset = attestation_bytes
        .iter()
        .position(|&value| value == 0xf5)
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    let mut invalid_boolean = Vec::from(attestation_bytes);
    invalid_boolean[boolean_offset] = 0xf6;
    assert_eq!(
        decode_attestation_reply(&invalid_boolean),
        Err(OwnerBridgeCodecError::InvalidCbor)
    );
    Ok(())
}

#[test]
fn public_payload_encoders_reject_short_buffers_at_wide_cbor_length_heads(
) -> Result<(), OwnerBridgeCodecError> {
    let credential_id = [0x80; 256];
    let get = GetOptionsV1::new(CEREMONY_ID, CHALLENGE, &credential_id, PRF_INPUT)?;
    let mut get_output = vec![0; 400];
    let get_length = encode_get_options(&get, &mut get_output)?;
    let credential_header = get_output[..get_length]
        .windows(3)
        .position(|window| window == [0x59, 1, 0])
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    for output_length in [credential_header, credential_header + 1] {
        let mut output = vec![0; output_length];
        assert_eq!(
            encode_get_options(&get, &mut output),
            Err(OwnerBridgeCodecError::BufferTooSmall),
            "Get output length {output_length}"
        );
    }

    let raw_id = [0x81];
    let attestation_object = vec![0xa0; 65_536];
    let attestation = AttestationReplyV1::new(
        CEREMONY_ID,
        &raw_id,
        b"{}",
        &attestation_object,
        TransportCodes::new(&[])?,
        false,
        None,
    )?;
    let mut attestation_output = vec![0; 66_000];
    let attestation_length = encode_attestation_reply(&attestation, &mut attestation_output)?;
    let attestation_header = attestation_output[..attestation_length]
        .windows(5)
        .position(|window| window == [0x5a, 0, 1, 0, 0])
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    for output_length in [attestation_header, attestation_header + 1] {
        let mut output = vec![0; output_length];
        assert_eq!(
            encode_attestation_reply(&attestation, &mut output),
            Err(OwnerBridgeCodecError::BufferTooSmall),
            "attestation output length {output_length}"
        );
    }
    Ok(())
}

#[test]
fn public_payload_codecs_reject_every_truncated_input_and_output_boundary(
) -> Result<(), OwnerBridgeCodecError> {
    let create = CreateOptionsV1::new(CEREMONY_ID, CHALLENGE, USER_HANDLE, PRF_INPUT);
    let mut create_bytes = [0; 148];
    let create_length = encode_create_options(&create, &mut create_bytes)?;
    for length in 0..create_length {
        let mut output = vec![0; length];
        assert_eq!(
            encode_create_options(&create, &mut output),
            Err(OwnerBridgeCodecError::BufferTooSmall),
            "Create output length {length}"
        );
        assert!(
            decode_create_options(&create_bytes[..length]).is_err(),
            "Create input prefix {length}"
        );
    }

    let credential_id = [0x80, 0x81];
    let get = GetOptionsV1::new(CEREMONY_ID, CHALLENGE, &credential_id, PRF_INPUT)?;
    let mut get_bytes = [0; 106];
    let get_length = encode_get_options(&get, &mut get_bytes)?;
    for length in 0..get_length {
        let mut output = vec![0; length];
        assert_eq!(
            encode_get_options(&get, &mut output),
            Err(OwnerBridgeCodecError::BufferTooSmall),
            "Get output length {length}"
        );
        assert!(
            decode_get_options(&get_bytes[..length]).is_err(),
            "Get input prefix {length}"
        );
    }

    let attestation = AttestationReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        b"\xa0",
        TransportCodes::new(&[0])?,
        true,
        Some(PRF_RESULT),
    )?;
    let mut attestation_bytes = [0; 70];
    let attestation_length = encode_attestation_reply(&attestation, &mut attestation_bytes)?;
    for length in 0..attestation_length {
        let mut output = vec![0; length];
        assert_eq!(
            encode_attestation_reply(&attestation, &mut output),
            Err(OwnerBridgeCodecError::BufferTooSmall),
            "attestation output length {length}"
        );
        assert!(
            decode_attestation_reply(&attestation_bytes[..length]).is_err(),
            "attestation input prefix {length}"
        );
    }

    let authenticator_data = [0; 37];
    let signature = [0; 8];
    let assertion = AssertionReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        &authenticator_data,
        &signature,
        None,
        PRF_RESULT,
    )?;
    let mut assertion_bytes = [0; 114];
    let assertion_length = encode_assertion_reply(&assertion, &mut assertion_bytes)?;
    for length in 0..assertion_length {
        let mut output = vec![0; length];
        assert_eq!(
            encode_assertion_reply(&assertion, &mut output),
            Err(OwnerBridgeCodecError::BufferTooSmall),
            "assertion output length {length}"
        );
        assert!(
            decode_assertion_reply(&assertion_bytes[..length]).is_err(),
            "assertion input prefix {length}"
        );
    }
    Ok(())
}

#[test]
fn public_create_options_decoder_rejects_each_closed_schema_field(
) -> Result<(), OwnerBridgeCodecError> {
    let create = CreateOptionsV1::new(CEREMONY_ID, CHALLENGE, USER_HANDLE, PRF_INPUT);
    let mut create_bytes = [0; 148];
    encode_create_options(&create, &mut create_bytes)?;
    for (label, offset, value, expected) in [
        (
            "challenge width",
            24,
            0x41,
            OwnerBridgeCodecError::InvalidCbor,
        ),
        (
            "user-handle width",
            58,
            0x41,
            OwnerBridgeCodecError::InvalidCbor,
        ),
        (
            "RP ID width",
            92,
            0x68,
            OwnerBridgeCodecError::InvalidPayload,
        ),
        (
            "RP ID contents",
            93,
            b'X',
            OwnerBridgeCodecError::InvalidPayload,
        ),
        (
            "RP name width",
            102,
            0x69,
            OwnerBridgeCodecError::InvalidPayload,
        ),
        (
            "RP name contents",
            103,
            b'X',
            OwnerBridgeCodecError::InvalidPayload,
        ),
        (
            "algorithm type",
            111,
            0x60,
            OwnerBridgeCodecError::InvalidCbor,
        ),
        ("algorithm", 111, 6, OwnerBridgeCodecError::InvalidPayload),
        (
            "required code one",
            112,
            1,
            OwnerBridgeCodecError::InvalidPayload,
        ),
        (
            "required code two",
            113,
            1,
            OwnerBridgeCodecError::InvalidPayload,
        ),
        ("PRF width", 114, 0x51, OwnerBridgeCodecError::InvalidCbor),
    ] {
        let mut malformed = create_bytes;
        malformed[offset] = value;
        assert_eq!(decode_create_options(&malformed), Err(expected), "{label}");
    }
    let noncanonical_versions: [&[u8]; 3] = [
        &[0x19, 0, 1],
        &[0x1a, 0, 0, 0, 1],
        &[0x1b, 0, 0, 0, 0, 0, 0, 0, 1],
    ];
    for version in noncanonical_versions {
        let mut noncanonical = Vec::from(create_bytes);
        noncanonical.splice(6..7, version.iter().copied());
        assert_eq!(
            decode_create_options(&noncanonical),
            Err(OwnerBridgeCodecError::NonCanonicalCbor)
        );
    }
    let mut unsupported_additional_info = create_bytes;
    unsupported_additional_info[6] = 0x1c;
    assert_eq!(
        decode_create_options(&unsupported_additional_info),
        Err(OwnerBridgeCodecError::InvalidCbor)
    );
    let mut signed_integer_overflow = Vec::from(create_bytes);
    signed_integer_overflow.splice(111..112, [0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        decode_create_options(&signed_integer_overflow),
        Err(OwnerBridgeCodecError::InvalidCbor)
    );
    Ok(())
}

#[test]
fn public_get_options_decoder_rejects_each_closed_schema_field() -> Result<(), OwnerBridgeCodecError>
{
    let credential_id = [0x80, 0x81];
    let get = GetOptionsV1::new(CEREMONY_ID, CHALLENGE, &credential_id, PRF_INPUT)?;
    let mut get_bytes = [0; 106];
    encode_get_options(&get, &mut get_bytes)?;
    for (label, offset, value, expected) in [
        (
            "RP ID width",
            58,
            0x68,
            OwnerBridgeCodecError::InvalidPayload,
        ),
        (
            "RP ID contents",
            59,
            b'X',
            OwnerBridgeCodecError::InvalidPayload,
        ),
        (
            "empty credential",
            68,
            0x40,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "oversized credential",
            68,
            0x5a,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "required code",
            71,
            1,
            OwnerBridgeCodecError::InvalidPayload,
        ),
        ("PRF width", 72, 0x51, OwnerBridgeCodecError::InvalidCbor),
    ] {
        let mut malformed = get_bytes;
        malformed[offset] = value;
        assert_eq!(decode_get_options(&malformed), Err(expected), "Get {label}");
    }
    Ok(())
}

#[test]
fn public_attestation_decoder_rejects_each_closed_schema_field() -> Result<(), OwnerBridgeCodecError>
{
    let credential_id = [0x80, 0x81];
    let attestation = AttestationReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        b"\xa0",
        TransportCodes::new(&[0])?,
        true,
        Some(PRF_RESULT),
    )?;
    let mut attestation_bytes = [0; 70];
    encode_attestation_reply(&attestation, &mut attestation_bytes)?;
    for (label, offset, value, expected) in [
        (
            "empty raw ID",
            24,
            0x40,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "empty client data",
            27,
            0x40,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "empty attestation object",
            30,
            0x40,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "too many transports",
            32,
            0x87,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "unknown transport",
            33,
            6,
            OwnerBridgeCodecError::InvalidPayload,
        ),
        ("PRF boolean", 34, 0xf6, OwnerBridgeCodecError::InvalidCbor),
        (
            "optional PRF width",
            35,
            0xf4,
            OwnerBridgeCodecError::Verification(Reason::PrfMalformed),
        ),
        (
            "required null",
            69,
            0xf4,
            OwnerBridgeCodecError::Verification(Reason::PrfMalformed),
        ),
    ] {
        let mut malformed = attestation_bytes;
        malformed[offset] = value;
        assert_eq!(
            decode_attestation_reply(&malformed),
            Err(expected),
            "attestation {label}"
        );
    }
    let false_prf = AttestationReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        b"\xa0",
        TransportCodes::new(&[])?,
        false,
        None,
    )?;
    let mut false_prf_bytes = [0; 40];
    let false_prf_length = encode_attestation_reply(&false_prf, &mut false_prf_bytes)?;
    assert_eq!(
        decode_attestation_reply(&false_prf_bytes[..false_prf_length]),
        Ok(false_prf)
    );

    let mut overwide_transport = Vec::from(attestation_bytes);
    overwide_transport.splice(33..34, [0x19, 1, 0]);
    assert_eq!(
        decode_attestation_reply(&overwide_transport),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    Ok(())
}

#[test]
fn public_payload_decoders_reject_trailing_bytes_for_each_remaining_shape(
) -> Result<(), OwnerBridgeCodecError> {
    let credential_id = [0x80, 0x81];
    let get = GetOptionsV1::new(CEREMONY_ID, CHALLENGE, &credential_id, PRF_INPUT)?;
    let mut get_bytes = [0; 106];
    let get_length = encode_get_options(&get, &mut get_bytes)?;
    let mut get_trailing = Vec::from(&get_bytes[..get_length]);
    get_trailing.push(0);
    assert_eq!(
        decode_get_options(&get_trailing),
        Err(OwnerBridgeCodecError::TrailingBytes)
    );

    let attestation = AttestationReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        b"\xa0",
        TransportCodes::new(&[0])?,
        true,
        Some(PRF_RESULT),
    )?;
    let mut attestation_bytes = [0; 70];
    let attestation_length = encode_attestation_reply(&attestation, &mut attestation_bytes)?;
    let mut attestation_trailing = Vec::from(&attestation_bytes[..attestation_length]);
    attestation_trailing.push(0);
    assert_eq!(
        decode_attestation_reply(&attestation_trailing),
        Err(OwnerBridgeCodecError::TrailingBytes)
    );

    let assertion = AssertionReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        &[0; 37],
        &[0; 8],
        None,
        PRF_RESULT,
    )?;
    let mut assertion_bytes = [0; 114];
    let assertion_length = encode_assertion_reply(&assertion, &mut assertion_bytes)?;
    let mut assertion_trailing = Vec::from(&assertion_bytes[..assertion_length]);
    assertion_trailing.push(0);
    assert_eq!(
        decode_assertion_reply(&assertion_trailing),
        Err(OwnerBridgeCodecError::TrailingBytes)
    );
    Ok(())
}

#[test]
fn public_assertion_decoder_rejects_each_closed_schema_field() -> Result<(), OwnerBridgeCodecError>
{
    let credential_id = [0x80, 0x81];
    let authenticator_data = [0; 37];
    let signature = [0; 8];
    let assertion = AssertionReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        &authenticator_data,
        &signature,
        None,
        PRF_RESULT,
    )?;
    let mut assertion_bytes = [0; 114];
    encode_assertion_reply(&assertion, &mut assertion_bytes)?;
    for (label, offset, value, expected) in [
        (
            "empty raw ID",
            24,
            0x40,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "empty client data",
            27,
            0x40,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "short authenticator data",
            31,
            36,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "short signature",
            69,
            0x47,
            OwnerBridgeCodecError::BoundsExceeded,
        ),
        (
            "user-handle width",
            78,
            0xf4,
            OwnerBridgeCodecError::Verification(Reason::UserHandleMismatch),
        ),
        (
            "PRF width",
            79,
            0x51,
            OwnerBridgeCodecError::Verification(Reason::PrfMalformed),
        ),
        (
            "required null",
            113,
            0xf4,
            OwnerBridgeCodecError::Verification(Reason::PrfMalformed),
        ),
    ] {
        let mut malformed = assertion_bytes;
        malformed[offset] = value;
        assert_eq!(
            decode_assertion_reply(&malformed),
            Err(expected),
            "assertion {label}"
        );
    }
    Ok(())
}

#[test]
fn public_reply_decoders_keep_noncanonical_lengths_apart_from_field_faults(
) -> Result<(), OwnerBridgeCodecError> {
    let credential_id = [0x80, 0x81];
    let attestation = AttestationReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        b"\xa0",
        TransportCodes::new(&[0])?,
        true,
        Some(PRF_RESULT),
    )?;
    let mut attestation_bytes = [0; 70];
    let attestation_length = encode_attestation_reply(&attestation, &mut attestation_bytes)?;
    let mut noncanonical_prf = Vec::from(&attestation_bytes[..attestation_length]);
    noncanonical_prf.splice(35..37, [0x59, 0, 0x20]);
    assert_eq!(
        decode_attestation_reply(&noncanonical_prf),
        Err(OwnerBridgeCodecError::NonCanonicalCbor)
    );

    let assertion = AssertionReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        &[0; 37],
        &[0; 8],
        Some(USER_HANDLE),
        PRF_RESULT,
    )?;
    let mut assertion_bytes = [0; 160];
    let assertion_length = encode_assertion_reply(&assertion, &mut assertion_bytes)?;
    let encoded = &assertion_bytes[..assertion_length];
    let mut noncanonical_handle = Vec::from(encoded);
    let handle_head = assertion_length - HANDLE_ITEM_FROM_END;
    noncanonical_handle.splice(handle_head..handle_head + 2, [0x59, 0, 0x20]);
    assert_eq!(
        decode_assertion_reply(&noncanonical_handle),
        Err(OwnerBridgeCodecError::NonCanonicalCbor)
    );
    let mut noncanonical_result = Vec::from(encoded);
    let result_head = assertion_length - RESULT_ITEM_FROM_END;
    noncanonical_result.splice(result_head..result_head + 2, [0x59, 0, 0x20]);
    assert_eq!(
        decode_assertion_reply(&noncanonical_result),
        Err(OwnerBridgeCodecError::NonCanonicalCbor)
    );
    Ok(())
}

fn assert_attestation_bounds(oversized_credential_id: &[u8]) -> Result<(), OwnerBridgeCodecError> {
    let oversized_client_data = vec![0; 4_097];
    let oversized_attestation = vec![0; 65_537];
    let transports = TransportCodes::new(&[])?;
    assert_eq!(
        AttestationReplyV1::new(CEREMONY_ID, &[], b"{}", b"\xa0", transports, false, None,),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        AttestationReplyV1::new(
            CEREMONY_ID,
            oversized_credential_id,
            b"{}",
            b"\xa0",
            transports,
            false,
            None,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        AttestationReplyV1::new(
            CEREMONY_ID,
            &[0x80],
            &oversized_client_data,
            b"\xa0",
            transports,
            false,
            None,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        AttestationReplyV1::new(
            CEREMONY_ID,
            &[0x80],
            b"{}",
            &oversized_attestation,
            transports,
            false,
            None,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    Ok(())
}

fn assert_assertion_bounds(oversized_credential_id: &[u8]) {
    let oversized_client_data = vec![0; 4_097];
    let short_authenticator_data = [0; 36];
    let oversized_authenticator_data = vec![0; 1_025];
    let short_signature = [0; 7];
    let oversized_signature = [0; 81];
    let valid_authenticator_data = [0; 37];
    let valid_signature = [0; 8];
    assert_eq!(
        AssertionReplyV1::new(
            CEREMONY_ID,
            &[],
            b"{}",
            &valid_authenticator_data,
            &valid_signature,
            None,
            PRF_RESULT,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        AssertionReplyV1::new(
            CEREMONY_ID,
            oversized_credential_id,
            b"{}",
            &valid_authenticator_data,
            &valid_signature,
            None,
            PRF_RESULT,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        AssertionReplyV1::new(
            CEREMONY_ID,
            &[0x80],
            &oversized_client_data,
            &valid_authenticator_data,
            &valid_signature,
            None,
            PRF_RESULT,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        AssertionReplyV1::new(
            CEREMONY_ID,
            &[0x80],
            b"{}",
            &short_authenticator_data,
            &valid_signature,
            None,
            PRF_RESULT,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        AssertionReplyV1::new(
            CEREMONY_ID,
            &[0x80],
            b"{}",
            &oversized_authenticator_data,
            &valid_signature,
            None,
            PRF_RESULT,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        AssertionReplyV1::new(
            CEREMONY_ID,
            &[0x80],
            b"{}",
            &valid_authenticator_data,
            &short_signature,
            None,
            PRF_RESULT,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    assert_eq!(
        AssertionReplyV1::new(
            CEREMONY_ID,
            &[0x80],
            b"{}",
            &valid_authenticator_data,
            &oversized_signature,
            None,
            PRF_RESULT,
        ),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
}
