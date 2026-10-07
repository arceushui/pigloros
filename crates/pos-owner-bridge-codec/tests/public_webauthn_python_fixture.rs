use pos_owner_bridge_codec::{
    verify_assertion_reply, verify_attestation_reply, AssertionReplyV1,
    AssertionVerificationContext, AttestationReplyV1, CeremonyId, CreateVerificationContext,
    OwnerBridgeCodecError, OwnerUserHandle, PrfResult, StoredCredential, TransportCodes,
    VerificationReason, WebAuthnChallenge,
};

const FIXTURE: &str = include_str!("../../../fixtures/owner-bridge/webauthn-es256-v1.fixture");

#[test]
fn public_verifier_accepts_independently_generated_python_fixture(
) -> Result<(), OwnerBridgeCodecError> {
    let ceremony_id = CeremonyId::from_bytes(fixture_array("ceremony_id")?);
    let challenge = WebAuthnChallenge::from_bytes(fixture_array("challenge")?);
    let credential_id = fixture_bytes("credential_id")?;
    let user_handle = OwnerUserHandle::from_bytes(fixture_array("user_handle")?);
    let create_client_data = fixture_bytes("create_client_data_json")?;
    let attestation_object = fixture_bytes("attestation_object")?;
    let prf_first = PrfResult::from_bytes(fixture_array("prf_first")?);
    let registration_reply = AttestationReplyV1::new(
        ceremony_id,
        &credential_id,
        &create_client_data,
        &attestation_object,
        TransportCodes::new(&[0])?,
        true,
        Some(prf_first),
    )?;
    let registration = verify_attestation_reply(
        &registration_reply,
        CreateVerificationContext::new(ceremony_id, challenge),
    )?;
    let public_key_cose = fixture_bytes("public_key_cose")?;
    let public_key_encoding = registration.public_key().canonical_encoding();
    assert_eq!(public_key_encoding.as_slice(), public_key_cose.as_slice());

    let credential = StoredCredential::new(
        &credential_id,
        user_handle,
        registration.public_key(),
        fixture_bool("backup_eligible")?,
        fixture_bool("backup_state")?,
        fixture_u32("stored_sign_count")?,
    )?;
    let assertion_client_data = fixture_bytes("assertion_client_data_json")?;
    let assertion_authenticator_data = fixture_bytes("assertion_authenticator_data")?;
    let signature = fixture_bytes("assertion_signature_der")?;
    let assertion_reply = AssertionReplyV1::new(
        ceremony_id,
        &credential_id,
        &assertion_client_data,
        &assertion_authenticator_data,
        &signature,
        None,
        prf_first,
    )?;
    let assertion = verify_assertion_reply(
        &assertion_reply,
        AssertionVerificationContext::new(ceremony_id, challenge, credential),
    )?;
    assert_eq!(assertion.sign_count(), fixture_u32("assertion_sign_count")?);
    assert_eq!(assertion.prf_first(), prf_first);

    let high_s_signature = fixture_bytes("assertion_signature_high_s_der")?;
    let high_s_reply = AssertionReplyV1::new(
        ceremony_id,
        &credential_id,
        &assertion_client_data,
        &assertion_authenticator_data,
        &high_s_signature,
        None,
        prf_first,
    )?;
    assert_eq!(
        verify_assertion_reply(
            &high_s_reply,
            AssertionVerificationContext::new(ceremony_id, challenge, credential),
        )?,
        assertion
    );

    let mut invalid_signature = signature;
    invalid_signature[0] ^= 1;
    let invalid_reply = AssertionReplyV1::new(
        ceremony_id,
        &credential_id,
        &assertion_client_data,
        &assertion_authenticator_data,
        &invalid_signature,
        None,
        prf_first,
    )?;
    assert_eq!(
        verify_assertion_reply(
            &invalid_reply,
            AssertionVerificationContext::new(ceremony_id, challenge, credential),
        ),
        Err(VerificationReason::Signature)
    );
    Ok(())
}

fn fixture_value(name: &str) -> Result<&'static str, OwnerBridgeCodecError> {
    for line in FIXTURE.lines() {
        let Some((field, value)) = line.split_once('=') else {
            continue;
        };
        if field == name {
            return Ok(value);
        }
    }
    Err(OwnerBridgeCodecError::InvalidPayload)
}

fn fixture_bytes(name: &str) -> Result<Vec<u8>, OwnerBridgeCodecError> {
    let input = fixture_value(name)?.as_bytes();
    if input.len() % 2 != 0 {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    let mut output = Vec::with_capacity(input.len() / 2);
    for pair in input.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn fixture_array<const N: usize>(name: &str) -> Result<[u8; N], OwnerBridgeCodecError> {
    fixture_bytes(name)?
        .try_into()
        .map_err(|_| OwnerBridgeCodecError::InvalidPayload)
}

fn fixture_bool(name: &str) -> Result<bool, OwnerBridgeCodecError> {
    match fixture_value(name)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(OwnerBridgeCodecError::InvalidPayload),
    }
}

fn fixture_u32(name: &str) -> Result<u32, OwnerBridgeCodecError> {
    fixture_value(name)?
        .parse()
        .map_err(|_| OwnerBridgeCodecError::InvalidPayload)
}

const fn hex_nibble(value: u8) -> Result<u8, OwnerBridgeCodecError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(OwnerBridgeCodecError::InvalidPayload),
    }
}
