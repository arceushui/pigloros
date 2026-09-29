use ciborium::value::Value;
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use pos_core::{
    fork_authentication::{
        principal_digest_v1, AuthenticatedPrincipalEvidenceV1, AuthenticatedPrincipalRecordV1,
        ForkAuthenticationAdapterPolicyV1, ForkAuthenticationPolicyV1,
    },
    Hash, PrincipalRefV1,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, ForkAuthenticationAdapterSigningKeyV1,
    ForkAuthenticationSignatureErrorV1, ForkHostSigningKeyV1,
};

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn bytes(value: u8, length: usize) -> Value {
    Value::Bytes(vec![value; length])
}

#[test]
fn host_proof_decoders_reject_full_length_wrong_marker_records(
) -> Result<(), Box<dyn std::error::Error>> {
    let host = ForkHostSigningKeyV1::from_seed([4; 32])?;
    let initialize = encode(&Value::Array(vec![
        Value::Text("BAD1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        Value::Bytes(host.public_key().to_vec()),
        bytes(4, 32),
    ]))?;
    assert_eq!(initialize.len(), 143);
    assert_eq!(
        host.sign_initialize(&initialize),
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    );

    let open = encode(&Value::Array(vec![
        Value::Text("BAD1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
    ]))?;
    assert_eq!(open.len(), 109);
    assert_eq!(
        host.sign_open(&open),
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    );

    let recovery = encode(&Value::Array(vec![
        Value::Text("BAD1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        Value::Integer(1.into()),
        bytes(3, 32),
    ]))?;
    assert_eq!(recovery.len(), 110);
    assert_eq!(
        host.sign_recovery(&recovery),
        Err(ForkAuthenticationSignatureErrorV1::InvalidRecord)
    );
    Ok(())
}

const ADAPTER_SEED: [u8; 32] = [7; 32];
const HOST_SEED: [u8; 32] = [4; 32];

fn record() -> Result<AuthenticatedPrincipalRecordV1, Box<dyn std::error::Error>> {
    Ok(AuthenticatedPrincipalRecordV1 {
        principal: PrincipalRefV1::try_new([1; 16], "unix-user")?,
        adapter_id: "local-unix".to_owned(),
        assurance: 2,
        issued_at: 1,
        expires_at: 2,
        registry_binding: Hash::from_bytes([2; 32]),
        operation_nonce: [3; 32],
    })
}

fn policy(
    verifying_key: [u8; 32],
) -> Result<ForkAuthenticationPolicyV1, Box<dyn std::error::Error>> {
    Ok(ForkAuthenticationPolicyV1::new(vec![
        ForkAuthenticationAdapterPolicyV1 {
            adapter_id: "local-unix".to_owned(),
            verifying_key,
            minimum_assurance: 2,
            registry_bindings: vec![Hash::from_bytes([2; 32])],
        },
    ])?)
}

/// Verify with `ed25519_dalek` directly over `literal_domain || parts...`,
/// independent of the crate's private domain constants.
fn verify_literal_preimage(
    public_key: [u8; 32],
    literal_domain: &[u8],
    parts: &[&[u8]],
    signature: &[u8; 64],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut preimage = literal_domain.to_vec();
    for part in parts {
        preimage.extend_from_slice(part);
    }
    VerifyingKey::from_bytes(&public_key)?
        .verify_strict(&preimage, &DalekSignature::from_bytes(signature))?;
    Ok(())
}

#[test]
fn signatures_cover_literal_adr106_domain_preimages() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)?;
    let evidence = adapter.sign_authenticated_principal(record()?)?;
    let apr1 = evidence.record().to_canonical_cbor()?;
    verify_literal_preimage(
        adapter.public_key(),
        b"pigloros/authenticated-principal-result/v1",
        &[&apr1],
        evidence.signature(),
    )?;
    let evidence =
        verify_authenticated_principal_evidence_v1(&policy(adapter.public_key())?, evidence)?;

    let host = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let fai1 = encode(&Value::Array(vec![
        Value::Text("FAI1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        Value::Bytes(host.public_key().to_vec()),
        bytes(4, 32),
    ]))?;
    verify_literal_preimage(
        host.public_key(),
        b"pigloros/fork-admission-host-bootstrap/v1",
        &[&fai1],
        host.sign_initialize(&fai1)?.as_bytes(),
    )?;

    let fao1 = encode(&Value::Array(vec![
        Value::Text("FAO1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
    ]))?;
    verify_literal_preimage(
        host.public_key(),
        b"pigloros/fork-admission-host-open/v1",
        &[&fao1],
        host.sign_open(&fao1)?.as_bytes(),
    )?;

    let evidence_digest = evidence.evidence().digest()?;
    let principal_digest = principal_digest_v1(&evidence.evidence().record().principal)?;
    let poc1 = encode(&Value::Array(vec![
        Value::Text("POC1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
        Value::Bytes(evidence_digest.as_bytes().to_vec()),
        Value::Bytes(principal_digest.as_bytes().to_vec()),
        Value::Text("owner".to_owned()),
    ]))?;
    let fae1 = evidence.evidence().to_canonical_cbor()?;
    verify_literal_preimage(
        host.public_key(),
        b"pigloros/fork-admission-host-command/v1",
        &[&poc1, &fae1],
        host.sign_command(&poc1, &evidence)?.as_bytes(),
    )?;

    let frc1 = encode(&Value::Array(vec![
        Value::Text("FRC1".to_owned()),
        Value::Integer(1.into()),
        bytes(1, 32),
        bytes(2, 32),
        Value::Integer(1.into()),
        bytes(3, 32),
    ]))?;
    verify_literal_preimage(
        host.public_key(),
        b"pigloros/fork-admission-recovery/v1",
        &[&frc1],
        host.sign_recovery(&frc1)?.as_bytes(),
    )?;
    Ok(())
}

#[test]
fn adapter_policy_rejects_small_order_key_universal_forgery(
) -> Result<(), Box<dyn std::error::Error>> {
    // Compressed Edwards identity: a valid point encoding of order one.
    let mut identity = [0; 32];
    identity[0] = 1;
    // R = identity, S = 0 satisfies the cofactorless equation for any message
    // under the identity key, so non-strict verification would accept it.
    let mut forged = [0; 64];
    forged[0] = 1;
    let evidence = AuthenticatedPrincipalEvidenceV1::new(record()?, forged)?;
    assert_eq!(
        verify_authenticated_principal_evidence_v1(&policy(identity)?, evidence),
        Err(ForkAuthenticationSignatureErrorV1::InvalidVerifyingKey)
    );
    Ok(())
}

#[test]
fn adapter_policy_pinning_a_different_valid_key_rejects_the_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)?;
    let other = ForkAuthenticationAdapterSigningKeyV1::from_seed([8; 32])?;
    assert_ne!(adapter.public_key(), other.public_key());
    let evidence = adapter.sign_authenticated_principal(record()?)?;
    assert_eq!(
        verify_authenticated_principal_evidence_v1(&policy(other.public_key())?, evidence),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
    );
    Ok(())
}
