//! Public trust-root authentication and malformed-snapshot tests.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{
    SandboxProviderProtocolError as ProtocolError, SandboxRevocationSnapshot, SandboxTrustError,
    SandboxTrustRole, SandboxTrustSnapshot,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).expect("test CBOR encodes");
    bytes
}

fn key_record(id: &str, role: u64) -> Value {
    Value::Array(vec![
        Value::Text(id.to_owned()),
        integer(role),
        Value::Bytes(
            SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        ),
        integer(2),
    ])
}

fn certificate(serial: u64) -> Value {
    Value::Array(vec![Value::Bytes(vec![8; 32]), integer(serial), integer(2)])
}

fn snapshot(keys: Vec<Value>, certificates: Vec<Value>, signer: &str) -> Value {
    Value::Array(vec![
        Value::Text("TRS1".to_owned()),
        integer(1),
        integer(2),
        Value::Array(keys),
        Value::Array(certificates),
        Value::Text(signer.to_owned()),
    ])
}

fn sign(unsigned: Value, root: &SigningKey) -> Vec<u8> {
    sign_record("TRS1", unsigned, root)
}

fn sign_record(magic: &str, unsigned: Value, root: &SigningKey) -> Vec<u8> {
    let mut digest = blake3::Hasher::new();
    digest.update(format!("PiglorOS.{magic}.v1\0").as_bytes());
    digest.update(&encode(&unsigned));
    let digest = digest.finalize();
    let mut message = format!("PiglorOS.{magic}.Signature.v1\0").into_bytes();
    message.extend_from_slice(digest.as_bytes());
    encode(&Value::Array(vec![
        unsigned,
        Value::Bytes(digest.as_bytes().to_vec()),
        Value::Bytes(root.sign(&message).to_bytes().to_vec()),
    ]))
}

fn revocation(trust: &SandboxTrustSnapshot, epoch: u64, keys: Vec<Value>) -> Value {
    Value::Array(vec![
        Value::Text("RVS1".to_owned()),
        integer(1),
        Value::Bytes(trust.snapshot_digest().to_vec()),
        integer(epoch),
        Value::Array(keys),
        Value::Array(vec![Value::Bytes(vec![3; 32])]),
        Value::Array(vec![Value::Bytes(vec![4; 32])]),
        Value::Text("policy".to_owned()),
    ])
}

fn trusted_registry(role: u64) -> SandboxTrustSnapshot {
    let root = SigningKey::from_bytes(&[1; 32]);
    let bytes = sign(
        snapshot(vec![key_record("policy", role)], vec![], "root"),
        &root,
    );
    SandboxTrustSnapshot::authenticate(&bytes, "root", &root.verifying_key())
        .expect("trusted registry")
}

#[test]
fn revocation_enforces_roles_registry_binding_and_revoked_keys() -> TestResult {
    let trust = trusted_registry(1);
    let policy = SigningKey::from_bytes(&[7; 32]);
    let bytes = sign_record("RVS1", revocation(&trust, 5, vec![]), &policy);
    let current = SandboxRevocationSnapshot::authenticate(&bytes, &trust)?;
    assert_eq!(current.revocation_epoch(), 5);
    assert_ne!(current.snapshot_digest(), [0; 32]);
    assert!(current.provider_revoked(&[3; 32]));
    assert!(!current.provider_revoked(&[8; 32]));
    assert!(current.image_revoked(&[4; 32]));
    assert!(!current.image_revoked(&[8; 32]));
    assert_eq!(
        current.active_key(&trust, "policy", SandboxTrustRole::AdministratorPolicy)?,
        policy.verifying_key()
    );
    assert_eq!(
        current.active_key(&trust, "policy", SandboxTrustRole::ImageProject),
        Err(SandboxTrustError::WrongRole)
    );
    assert_eq!(
        current.active_key(&trust, "missing", SandboxTrustRole::ImageProject),
        Err(SandboxTrustError::UnknownKey)
    );
    assert_eq!(
        current.active_key(
            &trusted_registry(2),
            "policy",
            SandboxTrustRole::ProviderRelease
        ),
        Err(SandboxTrustError::AuthorityMismatch)
    );
    let bytes = sign_record(
        "RVS1",
        revocation(&trust, 6, vec![Value::Text("policy".to_owned())]),
        &policy,
    );
    let next = SandboxRevocationSnapshot::authenticate(&bytes, &trust)?;
    current.validate_successor(&next)?;
    assert_eq!(
        next.active_key(&trust, "policy", SandboxTrustRole::AdministratorPolicy),
        Err(SandboxTrustError::Revoked)
    );
    assert_eq!(
        next.validate_successor(&current),
        Err(SandboxTrustError::EpochDiscontinuity)
    );
    assert_eq!(
        current.validate_successor(&current),
        Err(SandboxTrustError::EpochDiscontinuity)
    );
    Ok(())
}

#[test]
fn revocation_rejects_untrusted_signatures_roles_and_epoch_gaps() -> TestResult {
    let trust = trusted_registry(1);
    let policy = SigningKey::from_bytes(&[7; 32]);
    let forged = sign_record(
        "RVS1",
        revocation(&trust, 0, vec![]),
        &SigningKey::from_bytes(&[9; 32]),
    );
    assert_eq!(
        SandboxRevocationSnapshot::authenticate(&forged, &trust),
        Err(SandboxTrustError::Protocol(ProtocolError::SignatureInvalid))
    );
    let wrong_role = trusted_registry(2);
    let bytes = sign_record("RVS1", revocation(&wrong_role, 0, vec![]), &policy);
    assert_eq!(
        SandboxRevocationSnapshot::authenticate(&bytes, &wrong_role),
        Err(SandboxTrustError::WrongRole)
    );
    let bytes = sign_record("RVS1", revocation(&wrong_role, 0, vec![]), &policy);
    assert_eq!(
        SandboxRevocationSnapshot::authenticate(&bytes, &trust),
        Err(SandboxTrustError::AuthorityMismatch)
    );
    let current = SandboxRevocationSnapshot::authenticate(
        &sign_record("RVS1", revocation(&trust, 0, vec![]), &policy),
        &trust,
    )?;
    for epoch in [2, u64::MAX] {
        let next = SandboxRevocationSnapshot::authenticate(
            &sign_record("RVS1", revocation(&trust, epoch, vec![]), &policy),
            &trust,
        )?;
        assert_eq!(
            current.validate_successor(&next),
            Err(SandboxTrustError::EpochDiscontinuity)
        );
        assert_eq!(
            next.validate_successor(&current),
            Err(SandboxTrustError::EpochDiscontinuity)
        );
    }
    Ok(())
}

#[test]
fn authenticates_each_role_and_certificate_with_external_root() -> TestResult {
    let root = SigningKey::from_bytes(&[1; 32]);
    let roles = [
        SandboxTrustRole::OfflineTrustRoot,
        SandboxTrustRole::AdministratorPolicy,
        SandboxTrustRole::ProviderRelease,
        SandboxTrustRole::ProviderRuntimeAttestation,
        SandboxTrustRole::IndependentConformanceReviewer,
        SandboxTrustRole::ImageProject,
    ];
    for (code, expected) in (0_u64..).zip(roles) {
        let bytes = sign(
            snapshot(vec![key_record("key", code)], vec![certificate(3)], "root"),
            &root,
        );
        let trusted = SandboxTrustSnapshot::authenticate(&bytes, "root", &root.verifying_key())?;
        assert_eq!(trusted.trust_epoch(), 2);
        assert_ne!(trusted.snapshot_digest(), [0; 32]);
        assert_eq!(trusted.keys()[0].role, expected);
        assert_eq!(trusted.keys()[0].key_id, "key");
        assert_eq!(trusted.keys()[0].epoch, 2);
        assert_eq!(trusted.certificates()[0].fingerprint, [8; 32]);
        assert_eq!(trusted.certificates()[0].keyring_serial, 3);
        assert_eq!(trusted.certificates()[0].epoch, 2);
    }
    let bytes = sign(snapshot(vec![], vec![], "root"), &root);
    let empty = SandboxTrustSnapshot::authenticate(&bytes, "root", &root.verifying_key())?;
    assert!(empty.keys().is_empty());
    assert!(empty.certificates().is_empty());
    Ok(())
}

#[test]
fn rejects_untrusted_root_and_wrong_named_signer() {
    let root = SigningKey::from_bytes(&[1; 32]);
    let attacker = SigningKey::from_bytes(&[2; 32]);
    let forged = sign(
        snapshot(vec![key_record("root", 0)], vec![], "root"),
        &attacker,
    );
    assert_eq!(
        SandboxTrustSnapshot::authenticate(&forged, "root", &root.verifying_key()),
        Err(ProtocolError::SignatureInvalid)
    );
    let renamed = sign(snapshot(vec![], vec![], "other"), &root);
    assert_eq!(
        SandboxTrustSnapshot::authenticate(&renamed, "root", &root.verifying_key()),
        Err(ProtocolError::SignatureInvalid)
    );
}

#[test]
fn rejects_ambiguous_registry_identities_even_with_valid_root_signature() {
    let root = SigningKey::from_bytes(&[1; 32]);
    for unsigned in [
        snapshot(
            vec![key_record("same", 1), key_record("same", 2)],
            vec![],
            "root",
        ),
        snapshot(vec![], vec![certificate(1), certificate(2)], "root"),
        snapshot(vec![key_record("b", 1), key_record("a", 1)], vec![], "root"),
    ] {
        assert_eq!(
            SandboxTrustSnapshot::authenticate(
                &sign(unsigned, &root),
                "root",
                &root.verifying_key()
            ),
            Err(ProtocolError::NonCanonicalOrder)
        );
    }
}

#[test]
fn rejects_unknown_roles_malformed_fields_and_tampering() {
    let root = SigningKey::from_bytes(&[1; 32]);
    let unknown = sign(snapshot(vec![key_record("key", 6)], vec![], "root"), &root);
    assert_eq!(
        SandboxTrustSnapshot::authenticate(&unknown, "root", &root.verifying_key()),
        Err(ProtocolError::FieldOutOfBounds)
    );
    for unsigned in [
        snapshot(vec![Value::Null], vec![], "root"),
        snapshot(vec![], vec![Value::Null], "root"),
        snapshot(vec![key_record("", 1)], vec![], "root"),
    ] {
        assert!(SandboxTrustSnapshot::authenticate(
            &sign(unsigned, &root),
            "root",
            &root.verifying_key()
        )
        .is_err());
    }
    let bytes = sign(snapshot(vec![], vec![], "root"), &root);
    let mut wrapper: Value = ciborium::from_reader(bytes.as_slice()).expect("valid test CBOR");
    let Value::Array(ref mut fields) = wrapper else {
        panic!("array")
    };
    fields[1] = Value::Bytes(vec![9; 32]);
    assert_eq!(
        SandboxTrustSnapshot::authenticate(&encode(&wrapper), "root", &root.verifying_key()),
        Err(ProtocolError::DigestMismatch)
    );
}
