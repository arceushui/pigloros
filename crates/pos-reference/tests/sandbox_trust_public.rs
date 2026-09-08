//! Public trust-root authentication and malformed-snapshot tests.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{
    SandboxProviderProtocolError as ProtocolError, SandboxTrustRole, SandboxTrustSnapshot,
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
    let mut digest = blake3::Hasher::new();
    digest.update(b"PiglorOS.TRS1.v1\0");
    digest.update(&encode(&unsigned));
    let digest = digest.finalize();
    let mut message = b"PiglorOS.TRS1.Signature.v1\0".to_vec();
    message.extend_from_slice(digest.as_bytes());
    encode(&Value::Array(vec![
        unsigned,
        Value::Bytes(digest.as_bytes().to_vec()),
        Value::Bytes(root.sign(&message).to_bytes().to_vec()),
    ]))
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
