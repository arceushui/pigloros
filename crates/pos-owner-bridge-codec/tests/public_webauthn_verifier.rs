use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use pos_owner_bridge_codec::{
    verify_assertion_reply, verify_attestation_reply, AssertionReplyV1,
    AssertionVerificationContext, AttestationReplyV1, CreateVerificationContext,
    OwnerBridgeCodecError, StoredCredential, TransportCodes,
};
use sha2::{Digest, Sha256};

const CEREMONY_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const CHALLENGE: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];
static CREDENTIAL_ID: [u8; 2] = [0x80, 0x81];
const USER_HANDLE: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
];
const PRF_RESULT: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
const FIXTURE_PRIVATE_KEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const CREATE_CLIENT_DATA: &[u8] = b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}";
const GET_CLIENT_DATA: &[u8] = b"{\"type\":\"webauthn.get\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}";

#[test]
fn public_verifier_accepts_closed_create_and_assertion() -> Result<(), OwnerBridgeCodecError> {
    let authenticator_data = create_authenticator_data(cose_key());
    let attestation_object = none_attestation_object(&authenticator_data);
    let registration_reply = AttestationReplyV1::new(
        CEREMONY_ID,
        &CREDENTIAL_ID,
        CREATE_CLIENT_DATA,
        &attestation_object,
        TransportCodes::new(&[0])?,
        true,
        Some(PRF_RESULT),
    )?;
    let registration = verify_attestation_reply(
        &registration_reply,
        CreateVerificationContext::new(CEREMONY_ID, CHALLENGE),
    )?;
    assert_eq!(registration.credential_id(), CREDENTIAL_ID);
    assert_eq!(registration.sign_count(), 0);
    assert_eq!(registration.prf_first(), Some(PRF_RESULT));

    let credential = StoredCredential::new(
        registration.credential_id(),
        USER_HANDLE,
        registration.public_key(),
        registration.backup_eligible(),
        registration.backup_state(),
        registration.sign_count(),
    )?;
    let assertion_data = assertion_authenticator_data(0x05, 1);
    let mut signature = [0; 80];
    let signature_length = sign_assertion(&assertion_data, GET_CLIENT_DATA, &mut signature)?;
    let assertion_reply = AssertionReplyV1::new(
        CEREMONY_ID,
        &CREDENTIAL_ID,
        GET_CLIENT_DATA,
        &assertion_data,
        &signature[..signature_length],
        Some(USER_HANDLE),
        PRF_RESULT,
    )?;
    let assertion = verify_assertion_reply(
        &assertion_reply,
        AssertionVerificationContext::new(CEREMONY_ID, CHALLENGE, credential),
    )?;
    assert_eq!(assertion.sign_count(), 1);
    assert!(!assertion.backup_state());
    assert_eq!(assertion.prf_first(), PRF_RESULT);
    Ok(())
}

#[test]
fn public_verifier_rejects_invalid_create_replies() -> Result<(), OwnerBridgeCodecError> {
    let authenticator_data = create_authenticator_data(cose_key());
    let attestation_object = none_attestation_object(&authenticator_data);
    let disabled_prf = AttestationReplyV1::new(
        CEREMONY_ID,
        &CREDENTIAL_ID,
        CREATE_CLIENT_DATA,
        &attestation_object,
        TransportCodes::new(&[0])?,
        false,
        None,
    )?;
    assert_eq!(
        verify_attestation_reply(
            &disabled_prf,
            CreateVerificationContext::new(CEREMONY_ID, CHALLENGE),
        ),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut invalid_point_key = cose_key();
    invalid_point_key[10..42].fill(0);
    let invalid_point_data = create_authenticator_data(invalid_point_key);
    let invalid_point_attestation = none_attestation_object(&invalid_point_data);
    let invalid_point_reply = AttestationReplyV1::new(
        CEREMONY_ID,
        &CREDENTIAL_ID,
        CREATE_CLIENT_DATA,
        &invalid_point_attestation,
        TransportCodes::new(&[0])?,
        true,
        None,
    )?;
    assert_eq!(
        verify_attestation_reply(
            &invalid_point_reply,
            CreateVerificationContext::new(CEREMONY_ID, CHALLENGE),
        ),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    Ok(())
}

#[test]
fn public_verifier_rejects_identity_and_counter_violations() -> Result<(), OwnerBridgeCodecError> {
    let credential = fixture_credential(1)?;
    let assertion_data = assertion_authenticator_data(0x05, 2);
    let mut signature = [0; 80];
    let signature_length = sign_assertion(&assertion_data, GET_CLIENT_DATA, &mut signature)?;

    let wrong_raw_id = AssertionReplyV1::new(
        CEREMONY_ID,
        &[0x82],
        GET_CLIENT_DATA,
        &assertion_data,
        &signature[..signature_length],
        None,
        PRF_RESULT,
    )?;
    assert_invalid_assertion(&wrong_raw_id, credential);

    let wrong_handle = AssertionReplyV1::new(
        CEREMONY_ID,
        &CREDENTIAL_ID,
        GET_CLIENT_DATA,
        &assertion_data,
        &signature[..signature_length],
        Some([0; 32]),
        PRF_RESULT,
    )?;
    assert_invalid_assertion(&wrong_handle, credential);

    let repeated_counter_data = assertion_authenticator_data(0x05, 1);
    let repeated_counter_length =
        sign_assertion(&repeated_counter_data, GET_CLIENT_DATA, &mut signature)?;
    let repeated_counter = AssertionReplyV1::new(
        CEREMONY_ID,
        &CREDENTIAL_ID,
        GET_CLIENT_DATA,
        &repeated_counter_data,
        &signature[..repeated_counter_length],
        None,
        PRF_RESULT,
    )?;
    assert_invalid_assertion(&repeated_counter, credential);
    Ok(())
}

#[test]
fn public_verifier_rejects_backup_and_signature_violations() -> Result<(), OwnerBridgeCodecError> {
    let credential = fixture_credential(1)?;
    let assertion_data = assertion_authenticator_data(0x05, 2);
    let mut signature = [0; 80];
    let backup_eligibility_mismatch_data = assertion_authenticator_data(0x0d, 2);
    let backup_eligibility_mismatch_length = sign_assertion(
        &backup_eligibility_mismatch_data,
        GET_CLIENT_DATA,
        &mut signature,
    )?;
    let backup_eligibility_mismatch = AssertionReplyV1::new(
        CEREMONY_ID,
        &CREDENTIAL_ID,
        GET_CLIENT_DATA,
        &backup_eligibility_mismatch_data,
        &signature[..backup_eligibility_mismatch_length],
        None,
        PRF_RESULT,
    )?;
    assert_invalid_assertion(&backup_eligibility_mismatch, credential);

    let final_signature_length = sign_assertion(&assertion_data, GET_CLIENT_DATA, &mut signature)?;
    let mut invalid_signature = signature;
    invalid_signature[0] ^= 1;
    let invalid_signature_reply = AssertionReplyV1::new(
        CEREMONY_ID,
        &CREDENTIAL_ID,
        GET_CLIENT_DATA,
        &assertion_data,
        &invalid_signature[..final_signature_length],
        None,
        PRF_RESULT,
    )?;
    assert_invalid_assertion(&invalid_signature_reply, credential);
    Ok(())
}

fn fixture_credential(sign_count: u32) -> Result<StoredCredential<'static>, OwnerBridgeCodecError> {
    let authenticator_data = create_authenticator_data(cose_key());
    let attestation_object = none_attestation_object(&authenticator_data);
    let reply = AttestationReplyV1::new(
        CEREMONY_ID,
        &CREDENTIAL_ID,
        CREATE_CLIENT_DATA,
        &attestation_object,
        TransportCodes::new(&[0])?,
        true,
        None,
    )?;
    let registration = verify_attestation_reply(
        &reply,
        CreateVerificationContext::new(CEREMONY_ID, CHALLENGE),
    )?;
    StoredCredential::new(
        &CREDENTIAL_ID,
        USER_HANDLE,
        registration.public_key(),
        registration.backup_eligible(),
        registration.backup_state(),
        sign_count,
    )
}

fn assert_invalid_assertion(reply: &AssertionReplyV1<'_>, credential: StoredCredential<'_>) {
    assert_eq!(
        verify_assertion_reply(
            reply,
            AssertionVerificationContext::new(CEREMONY_ID, CHALLENGE, credential),
        ),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
}

fn create_authenticator_data(cose_key: [u8; 77]) -> [u8; 134] {
    let mut output = [0; 134];
    output[..32].copy_from_slice(&rp_id_hash());
    output[32] = 0x45;
    output[53..55].copy_from_slice(&[0, 2]);
    output[55..57].copy_from_slice(&CREDENTIAL_ID);
    output[57..].copy_from_slice(&cose_key);
    output
}

fn assertion_authenticator_data(flags: u8, sign_count: u32) -> [u8; 37] {
    let mut output = [0; 37];
    output[..32].copy_from_slice(&rp_id_hash());
    output[32] = flags;
    output[33..].copy_from_slice(&sign_count.to_be_bytes());
    output
}

fn sign_assertion(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    output: &mut [u8; 80],
) -> Result<usize, OwnerBridgeCodecError> {
    let signing_key = SigningKey::from_slice(&FIXTURE_PRIVATE_KEY)
        .map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
    let client_data_digest: [u8; 32] = Sha256::digest(client_data_json).into();
    let message_length = authenticator_data
        .len()
        .checked_add(client_data_digest.len())
        .ok_or(OwnerBridgeCodecError::BoundsExceeded)?;
    let mut message = [0; 69];
    message[..authenticator_data.len()].copy_from_slice(authenticator_data);
    message[authenticator_data.len()..message_length].copy_from_slice(&client_data_digest);
    let signature: Signature = signing_key.sign(&message[..message_length]);
    let der_signature = signature.to_der();
    let der_bytes = der_signature.as_bytes();
    if der_bytes.len() > output.len() {
        return Err(OwnerBridgeCodecError::BoundsExceeded);
    }
    output[..der_bytes.len()].copy_from_slice(der_bytes);
    Ok(der_bytes.len())
}

fn cose_key() -> [u8; 77] {
    hex::<77>(b"a50102032620012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
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
