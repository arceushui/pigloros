use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_core::{
    fork_authentication::{
        principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
        ForkAuthenticationPolicyV1,
    },
    ForkAdmissionHostCommandV1, ForkAdmissionRecoveryProofV1, Hash, PrincipalRefV1, PublicKey,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, verify_fork_admission_host_command_v1,
    verify_fork_admission_recovery_proof_v1, ForkAuthenticationAdapterSigningKeyV1,
    ForkAuthenticationSignatureErrorV1, ForkHostSigningKeyV1,
    VerifiedAuthenticatedPrincipalEvidenceV1,
};
use pos_crypto::signing::verifying_key_from_public_key;

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(ciborium::from_reader(bytes)?)
}

fn hash(value: u8) -> Value {
    Value::Bytes(vec![value; 32])
}

fn array(value: Value) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err("expected CBOR array".into()),
    }
}

fn verified_evidence(
) -> Result<VerifiedAuthenticatedPrincipalEvidenceV1, Box<dyn std::error::Error>> {
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([1; 32])?;
    let record = AuthenticatedPrincipalRecordV1 {
        principal: PrincipalRefV1::try_new([2; 16], "local-unix")?,
        adapter_id: "local-unix".to_owned(),
        assurance: 1,
        issued_at: 1,
        expires_at: 2,
        registry_binding: Hash::from_bytes([3; 32]),
        operation_nonce: [4; 32],
    };
    let evidence = adapter.sign_authenticated_principal(record)?;
    let policy = ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
        adapter_id: "local-unix".to_owned(),
        verifying_key: adapter.public_key(),
        minimum_assurance: 1,
        registry_bindings: vec![Hash::from_bytes([3; 32])],
    }])?;
    Ok(verify_authenticated_principal_evidence_v1(
        &policy, evidence,
    )?)
}

fn signed_fac1(
    host: &ForkHostSigningKeyV1,
    command: Vec<u8>,
    evidence: &VerifiedAuthenticatedPrincipalEvidenceV1,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let signature = host.sign_command(&command, evidence)?;
    encode(&Value::Array(vec![
        Value::Text("FAC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(command),
        Value::Bytes(evidence.evidence().to_canonical_cbor()?),
        Value::Bytes(signature.as_bytes().to_vec()),
    ]))
}

fn valid_poc1(
    evidence: &VerifiedAuthenticatedPrincipalEvidenceV1,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let evidence_digest = evidence.evidence().digest()?;
    let principal_digest = principal_digest_v1(&evidence.evidence().record().principal)?;
    encode(&Value::Array(vec![
        Value::Text("POC1".to_owned()),
        Value::Integer(1.into()),
        hash(1),
        hash(2),
        hash(3),
        Value::Bytes(evidence_digest.as_bytes().to_vec()),
        Value::Bytes(principal_digest.as_bytes().to_vec()),
        Value::Text("owner".to_owned()),
    ]))
}

fn valid_fcc1(
    evidence: &VerifiedAuthenticatedPrincipalEvidenceV1,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let evidence_digest = evidence.evidence().digest()?;
    let principal_digest = principal_digest_v1(&evidence.evidence().record().principal)?;
    encode(&Value::Array(vec![
        Value::Text("FCC1".to_owned()),
        Value::Integer(1.into()),
        hash(1),
        hash(2),
        hash(3),
        Value::Bytes(evidence_digest.as_bytes().to_vec()),
        Value::Bytes(principal_digest.as_bytes().to_vec()),
        Value::Bytes(vec![4; 16]),
        Value::Integer(5.into()),
        Value::Integer(5.into()),
        hash(6),
        hash(7),
        Value::Integer(1.into()),
        Value::Text("immutable-child".to_owned()),
    ]))
}

fn tamper_fac1_command(
    bytes: &[u8],
    field: usize,
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut outer = array(decode(bytes)?)?;
    let Value::Bytes(command) = &outer[2] else {
        return Err("FAC1 command must be bytes".into());
    };
    let mut command = array(decode(command)?)?;
    command[field] = replacement;
    outer[2] = Value::Bytes(encode(&Value::Array(command))?);
    encode(&Value::Array(outer))
}

fn tamper_fac1_evidence(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut outer = array(decode(bytes)?)?;
    let Value::Bytes(evidence) = &outer[3] else {
        return Err("FAC1 evidence must be bytes".into());
    };
    let mut evidence = array(decode(evidence)?)?;
    evidence[3] = Value::Bytes(vec![9; 64]);
    outer[3] = Value::Bytes(encode(&Value::Array(evidence))?);
    encode(&Value::Array(outer))
}

fn tamper_fac1_principal(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut outer = array(decode(bytes)?)?;
    let Value::Bytes(evidence) = &outer[3] else {
        return Err("FAC1 evidence must be bytes".into());
    };
    let mut evidence = array(decode(evidence)?)?;
    let Value::Bytes(record) = &evidence[2] else {
        return Err("FAE1 record must be bytes".into());
    };
    let mut record = array(decode(record)?)?;
    let Value::Bytes(principal) = &record[2] else {
        return Err("APR1 principal must be bytes".into());
    };
    let mut principal = array(decode(principal)?)?;
    principal[2] = Value::Bytes(vec![8; 16]);
    record[2] = Value::Bytes(encode(&Value::Array(principal))?);
    evidence[2] = Value::Bytes(encode(&Value::Array(record))?);
    outer[3] = Value::Bytes(encode(&Value::Array(evidence))?);
    encode(&Value::Array(outer))
}

fn assert_fac1_rejected(
    host_key: PublicKey,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let command = ForkAdmissionHostCommandV1::from_canonical_cbor(bytes)?;
    assert_eq!(
        verify_fork_admission_host_command_v1(host_key, &command),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
    );
    Ok(())
}

fn valid_frp1(host: &ForkHostSigningKeyV1) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let command = encode(&Value::Array(vec![
        Value::Text("FRC1".to_owned()),
        Value::Integer(1.into()),
        hash(1),
        hash(2),
        Value::Integer(1.into()),
        hash(3),
    ]))?;
    let signature = host.sign_recovery(&command)?;
    encode(&Value::Array(vec![
        Value::Text("FRP1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(command),
        Value::Bytes(signature.as_bytes().to_vec()),
    ]))
}

fn tamper_frp1_command(
    bytes: &[u8],
    field: usize,
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut outer = array(decode(bytes)?)?;
    let Value::Bytes(command) = &outer[2] else {
        return Err("FRP1 command must be bytes".into());
    };
    let mut command = array(decode(command)?)?;
    command[field] = replacement;
    outer[2] = Value::Bytes(encode(&Value::Array(command))?);
    encode(&Value::Array(outer))
}

fn assert_frp1_rejected(
    host_key: PublicKey,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let proof = ForkAdmissionRecoveryProofV1::from_canonical_cbor(bytes)?;
    assert_eq!(
        verify_fork_admission_recovery_proof_v1(host_key, &proof),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
    );
    Ok(())
}

#[test]
fn public_command_and_recovery_proofs_bind_their_exact_purposes(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkHostSigningKeyV1::from_seed([5; 32])?;
    let host_key = PublicKey::from_bytes(host.public_key());
    let evidence = verified_evidence()?;
    let command = ForkAdmissionHostCommandV1::from_canonical_cbor(&signed_fac1(
        &host,
        valid_poc1(&evidence)?,
        &evidence,
    )?)?;
    assert_eq!(
        verify_fork_admission_host_command_v1(host_key, &command),
        Ok(())
    );

    let proof = ForkAdmissionRecoveryProofV1::from_canonical_cbor(&valid_frp1(&host)?)?;
    assert_eq!(
        verify_fork_admission_recovery_proof_v1(host_key, &proof),
        Ok(())
    );
    assert_eq!(
        verify_fork_admission_recovery_proof_v1(PublicKey::from_bytes([9; 32]), &proof),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
    );
    let invalid_key = (1..=u8::MAX)
        .map(|byte| PublicKey::from_bytes([byte; 32]))
        .find(|key| verifying_key_from_public_key(key).is_err())
        .ok_or("no invalid compressed public key fixture")?;
    assert_eq!(
        verify_fork_admission_host_command_v1(invalid_key, &command),
        Err(ForkAuthenticationSignatureErrorV1::InvalidVerifyingKey)
    );
    assert_eq!(
        verify_fork_admission_recovery_proof_v1(invalid_key, &proof),
        Err(ForkAuthenticationSignatureErrorV1::InvalidVerifyingKey)
    );
    Ok(())
}

#[test]
fn public_fac1_verifier_rejects_each_principal_owner_binding_tamper(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkHostSigningKeyV1::from_seed([5; 32])?;
    let host_key = PublicKey::from_bytes(host.public_key());
    let evidence = verified_evidence()?;
    let fac1 = signed_fac1(&host, valid_poc1(&evidence)?, &evidence)?;

    for (field, replacement) in [
        (2, hash(9)),
        (3, hash(9)),
        (4, hash(9)),
        (5, hash(9)),
        (6, hash(9)),
        (7, Value::Text("other-owner".to_owned())),
    ] {
        assert_fac1_rejected(host_key, &tamper_fac1_command(&fac1, field, replacement)?)?;
    }
    assert_fac1_rejected(host_key, &tamper_fac1_principal(&fac1)?)?;
    assert_fac1_rejected(host_key, &tamper_fac1_evidence(&fac1)?)?;
    Ok(())
}

#[test]
fn public_fac1_verifier_rejects_immutable_fork_intent_and_wrong_host_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkHostSigningKeyV1::from_seed([5; 32])?;
    let host_key = PublicKey::from_bytes(host.public_key());
    let evidence = verified_evidence()?;
    let fac1 = signed_fac1(&host, valid_fcc1(&evidence)?, &evidence)?;
    let command = ForkAdmissionHostCommandV1::from_canonical_cbor(&fac1)?;

    assert_eq!(
        verify_fork_admission_host_command_v1(host_key, &command),
        Ok(())
    );
    assert_eq!(
        verify_fork_admission_host_command_v1(PublicKey::from_bytes([9; 32]), &command),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
    );
    for (field, replacement) in [
        (2, hash(9)),
        (3, hash(9)),
        (4, hash(9)),
        (5, hash(9)),
        (6, hash(9)),
        (7, Value::Bytes(vec![9; 16])),
        (10, hash(9)),
        (11, hash(9)),
        (12, Value::Integer(0.into())),
        (13, Value::Text("other-child".to_owned())),
    ] {
        assert_fac1_rejected(host_key, &tamper_fac1_command(&fac1, field, replacement)?)?;
    }
    // Fold and tick must stay equal to decode, so they are tampered together.
    let retimed = tamper_fac1_command(&fac1, 8, Value::Integer(6.into()))?;
    assert_fac1_rejected(
        host_key,
        &tamper_fac1_command(&retimed, 9, Value::Integer(6.into()))?,
    )
}

#[test]
fn public_fac1_verifier_rejects_a_recovery_purpose_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkHostSigningKeyV1::from_seed([5; 32])?;
    let host_key = PublicKey::from_bytes(host.public_key());
    let evidence = verified_evidence()?;
    let command = valid_poc1(&evidence)?;
    let evidence_bytes = evidence.evidence().to_canonical_cbor()?;

    let mut recovery_preimage = b"pigloros/fork-admission-recovery/v1".to_vec();
    recovery_preimage.extend_from_slice(&command);
    recovery_preimage.extend_from_slice(&evidence_bytes);
    let recovery_signature = SigningKey::from_bytes(&[5; 32]).sign(&recovery_preimage);
    let wrong_purpose = encode(&Value::Array(vec![
        Value::Text("FAC1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(command),
        Value::Bytes(evidence_bytes),
        Value::Bytes(recovery_signature.to_bytes().to_vec()),
    ]))?;
    assert_fac1_rejected(host_key, &wrong_purpose)
}

#[test]
fn public_frp1_verifier_rejects_each_binding_tamper_and_wrong_purpose(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkHostSigningKeyV1::from_seed([5; 32])?;
    let host_key = PublicKey::from_bytes(host.public_key());
    let frp1 = valid_frp1(&host)?;
    let proof = ForkAdmissionRecoveryProofV1::from_canonical_cbor(&frp1)?;

    assert_eq!(
        verify_fork_admission_recovery_proof_v1(host_key, &proof),
        Ok(())
    );
    assert_eq!(
        verify_fork_admission_recovery_proof_v1(PublicKey::from_bytes([9; 32]), &proof),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
    );
    for (field, replacement) in [
        (2, hash(9)),
        (3, hash(9)),
        (4, Value::Integer(2.into())),
        (5, hash(9)),
    ] {
        assert_frp1_rejected(host_key, &tamper_frp1_command(&frp1, field, replacement)?)?;
    }

    let mut command_preimage = b"pigloros/fork-admission-host-command/v1".to_vec();
    command_preimage.extend_from_slice(&proof.command_bytes());
    let command_signature = SigningKey::from_bytes(&[5; 32]).sign(&command_preimage);
    let wrong_purpose = encode(&Value::Array(vec![
        Value::Text("FRP1".to_owned()),
        Value::Integer(1.into()),
        Value::Bytes(proof.command_bytes()),
        Value::Bytes(command_signature.to_bytes().to_vec()),
    ]))?;
    assert_frp1_rejected(host_key, &wrong_purpose)
}
