use pos_owner_bridge_codec::{
    admit_loopback_http_request, decode_assertion_reply, decode_attestation_reply,
    decode_create_options, decode_get_options, encode_assertion_reply, encode_attestation_reply,
    encode_create_options, encode_get_options, parse_assertion_authenticator_data,
    parse_none_attestation_object, validate_client_data_json, AssertionReplyV1, AttestationReplyV1,
    CeremonyId, CeremonyKind, ControlState, CreateOptionsV1, GetOptionsV1,
    LoopbackRequestDisposition, OwnerBridgeCodecError, OwnerBridgeControlV1, OwnerUserHandle,
    PrfInput, PrfResult, TransportCodes, VerificationReason as Reason, WebAuthnChallenge,
};

mod common;

use common::verified;

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
fn public_wire_codecs_match_adr_110_golden_vectors() -> Result<(), OwnerBridgeCodecError> {
    let create = CreateOptionsV1::new(CEREMONY_ID, CHALLENGE, USER_HANDLE, PRF_INPUT);
    let mut create_output = [0; 148];
    assert_eq!(encode_create_options(&create, &mut create_output), Ok(148));
    assert_eq!(
        create_output,
        hex::<148>(b"8b44574352310150000102030405060708090a0b0c0d0e0f5820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f5820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f696c6f63616c686f7374685069676c6f724f532600005820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f")
    );
    assert_eq!(decode_create_options(&create_output), Ok(create));

    let credential_id = [0x80, 0x81];
    let get = GetOptionsV1::new(CEREMONY_ID, CHALLENGE, &credential_id, PRF_INPUT)?;
    let mut get_output = [0; 106];
    assert_eq!(encode_get_options(&get, &mut get_output), Ok(106));
    assert_eq!(
        get_output,
        hex::<106>(b"8844574752310150000102030405060708090a0b0c0d0e0f5820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f696c6f63616c686f7374428081005820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f")
    );
    assert_eq!(decode_get_options(&get_output), Ok(get));

    let transports = TransportCodes::new(&[0])?;
    let attestation = AttestationReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        &[0xa0],
        transports,
        true,
        Some(PRF_RESULT),
    )?;
    let mut attestation_output = [0; 70];
    assert_eq!(
        encode_attestation_reply(&attestation, &mut attestation_output),
        Ok(70)
    );
    assert_eq!(
        attestation_output,
        hex::<70>(b"8a44574152310150000102030405060708090a0b0c0d0e0f428081427b7d41a08100f55820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebff6")
    );
    assert_eq!(
        decode_attestation_reply(&attestation_output),
        Ok(attestation)
    );

    let authenticator_data = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    ];
    let signature = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37];
    let assertion = AssertionReplyV1::new(
        CEREMONY_ID,
        &credential_id,
        b"{}",
        &authenticator_data,
        &signature,
        None,
        PRF_RESULT,
    )?;
    let mut assertion_output = [0; 114];
    assert_eq!(
        encode_assertion_reply(&assertion, &mut assertion_output),
        Ok(114)
    );
    assert_eq!(
        assertion_output,
        hex::<114>(b"8a44574153310150000102030405060708090a0b0c0d0e0f428081427b7d5825000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324483031323334353637f65820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebff6")
    );
    assert_eq!(decode_assertion_reply(&assertion_output), Ok(assertion));
    Ok(())
}

#[test]
fn public_control_headers_match_adr_110_vectors_and_reject_tampering(
) -> Result<(), OwnerBridgeCodecError> {
    let request = OwnerBridgeControlV1::new_request(CeremonyKind::Create, 1, CEREMONY_ID, 148)?;
    let expected_request = hex::<64>(b"50574231010040000000000001000000000102030405060708090a0b0c0d0e0f0010000094000000020000000000000000000000000000000000000000000000");
    assert_eq!(request.encode(), expected_request);
    assert_eq!(OwnerBridgeControlV1::decode(&expected_request), Ok(request));

    let reply = OwnerBridgeControlV1::new_reply(CeremonyKind::Get, 1, CEREMONY_ID)?;
    let ready_reply = reply.with_reply_state(114, ControlState::Ready)?;
    let expected_ready_reply = hex::<64>(b"50574231010040000101000001000000000102030405060708090a0b0c0d0e0f0020000072000000020000000000000000000000000000000000000000000000");
    assert_eq!(ready_reply.encode(), expected_ready_reply);
    assert_eq!(
        OwnerBridgeControlV1::decode(&expected_ready_reply),
        Ok(ready_reply)
    );

    let mut nonzero_reserved = expected_ready_reply;
    nonzero_reserved[44] = 1;
    assert_eq!(
        OwnerBridgeControlV1::decode(&nonzero_reserved),
        Err(OwnerBridgeCodecError::NonzeroReserved)
    );
    assert_eq!(
        reply.with_reply_state(0, ControlState::Ready),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    Ok(())
}

#[test]
fn public_http_admission_requires_one_exact_loopback_document_request() {
    let document = b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n";
    assert_eq!(
        admit_loopback_http_request(document),
        Ok(LoopbackRequestDisposition::OwnerDocument)
    );

    let not_found = b"GET /missing HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n";
    assert_eq!(
        admit_loopback_http_request(not_found),
        Ok(LoopbackRequestDisposition::NotFound)
    );

    let head = b"HEAD /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n";
    assert_eq!(
        admit_loopback_http_request(head),
        Err(OwnerBridgeCodecError::InvalidHttpRequest)
    );

    let body = b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nContent-Length: 1\r\n\r\nx";
    assert_eq!(
        admit_loopback_http_request(body),
        Err(OwnerBridgeCodecError::InvalidHttpRequest)
    );
}

#[test]
fn public_client_data_validation_enforces_the_closed_web_authn_shape() {
    let create = b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"crossOrigin\":false,\"futureField\":\"\\uD83D\\uDE00\"}";
    assert_eq!(
        validate_client_data_json(create, CeremonyKind::Create, &CHALLENGE),
        Ok(())
    );

    let get = b"{\"type\":\"webauthn.get\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http:\\/\\/localhost:49291\",\"futureBoolean\":true}";
    assert_eq!(
        validate_client_data_json(get, CeremonyKind::Get, &CHALLENGE),
        Ok(())
    );

    let duplicate_after_unescaping = b"{\"type\":\"webauthn.create\",\"\\u0074ype\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}";
    assert_eq!(
        validate_client_data_json(duplicate_after_unescaping, CeremonyKind::Create, &CHALLENGE),
        Err(Reason::Malformed)
    );

    let escaped_challenge = b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj\\u0038\",\"origin\":\"http://localhost:49291\"}";
    assert_eq!(
        validate_client_data_json(escaped_challenge, CeremonyKind::Create, &CHALLENGE),
        Err(Reason::Challenge)
    );

    let cross_origin = b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"crossOrigin\":true}";
    assert_eq!(
        validate_client_data_json(cross_origin, CeremonyKind::Create, &CHALLENGE),
        Err(Reason::CrossOrigin)
    );

    let top_origin = b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"topOrigin\":false}";
    assert_eq!(
        validate_client_data_json(top_origin, CeremonyKind::Create, &CHALLENGE),
        Err(Reason::CrossOrigin)
    );
}

#[test]
fn public_authenticator_parsers_enforce_none_cose_and_extension_rules(
) -> Result<(), OwnerBridgeCodecError> {
    let cose_key = hex::<77>(b"a50102032620012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    let mut authenticator_data = [0; 134];
    authenticator_data[..32].copy_from_slice(&rp_id_hash());
    authenticator_data[32] = 0x45;
    authenticator_data[33..37].copy_from_slice(&7_u32.to_be_bytes());
    authenticator_data[53..55].copy_from_slice(&2_u16.to_be_bytes());
    authenticator_data[55..57].copy_from_slice(&[0x80, 0x81]);
    authenticator_data[57..].copy_from_slice(&cose_key);

    let attestation = none_attestation_object(&authenticator_data);
    let create = verified(parse_none_attestation_object(&attestation, &[0x80, 0x81]))?;
    assert_eq!(create.credential_id(), &[0x80, 0x81]);
    assert_eq!(create.sign_count(), 7);
    assert_eq!(create.public_key().canonical_encoding(), cose_key);

    let mut assertion = [0; 42];
    assertion[..32].copy_from_slice(&rp_id_hash());
    assertion[32] = 0x85;
    assertion[33..37].copy_from_slice(&9_u32.to_be_bytes());
    assertion[37..].copy_from_slice(&[0xa1, 0x62, b't', b'x', 0xf5]);
    let parsed_assertion = verified(parse_assertion_authenticator_data(&assertion))?;
    assert_eq!(parsed_assertion.sign_count(), 9);

    let mut duplicate_extension = [0; 44];
    duplicate_extension[..37].copy_from_slice(&assertion[..37]);
    duplicate_extension[37..].copy_from_slice(&[0xa2, 0x61, b'x', 0xf5, 0x61, b'x', 0xf4]);
    assert_eq!(
        parse_assertion_authenticator_data(&duplicate_extension),
        Err(Reason::Extensions)
    );

    let mut backup_state_without_eligibility = assertion;
    backup_state_without_eligibility[32] = 0x95;
    assert_eq!(
        parse_assertion_authenticator_data(&backup_state_without_eligibility),
        Err(Reason::BackupFlags)
    );
    Ok(())
}

fn rp_id_hash() -> [u8; 32] {
    hex::<32>(b"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763")
}

fn none_attestation_object(authenticator_data: &[u8; 134]) -> [u8; 164] {
    let mut output = [0; 164];
    output[..4].copy_from_slice(&[0xa3, 0x63, b'f', b'm']);
    output[4] = b't';
    output[5..10].copy_from_slice(&[0x64, b'n', b'o', b'n', b'e']);
    output[10..18].copy_from_slice(&[0x67, b'a', b't', b't', b'S', b't', b'm', b't']);
    output[18] = 0xa0;
    output[19..28].copy_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']);
    output[28..30].copy_from_slice(&[0x58, 134]);
    output[30..].copy_from_slice(authenticator_data);
    output
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
