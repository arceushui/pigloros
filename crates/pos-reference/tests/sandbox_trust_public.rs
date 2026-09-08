//! Public trust-root authentication and malformed-snapshot tests.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{
    SandboxAdministratorPolicy, SandboxProviderProtocolError as ProtocolError,
    SandboxRevocationSnapshot, SandboxTrustError, SandboxTrustRole, SandboxTrustSnapshot,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn integer(value: u64) -> Value {
    Value::Integer(value.into())
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
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

fn sign(unsigned: Value, root: &SigningKey) -> TestResult<Vec<u8>> {
    sign_record("TRS1", unsigned, root)
}

fn sign_record(magic: &str, unsigned: Value, root: &SigningKey) -> TestResult<Vec<u8>> {
    let mut digest = blake3::Hasher::new();
    digest.update(format!("PiglorOS.{magic}.v1\0").as_bytes());
    digest.update(&encode(&unsigned)?);
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

fn trusted_registry(role: u64) -> TestResult<SandboxTrustSnapshot> {
    let root = SigningKey::from_bytes(&[1; 32]);
    let bytes = sign(
        snapshot(vec![key_record("policy", role)], vec![], "root"),
        &root,
    )?;
    Ok(SandboxTrustSnapshot::authenticate(
        &bytes,
        "root",
        &root.verifying_key(),
    )?)
}

fn policy_fields(
    trust: &SandboxTrustSnapshot,
    revocation: &SandboxRevocationSnapshot,
) -> Vec<Value> {
    vec![
        Value::Text("APT1".to_owned()),
        integer(1),
        integer(7),
        Value::Bytes(vec![10; 32]),
        Value::Bytes(vec![11; 32]),
        Value::Array(vec![Value::Bytes(vec![12; 32])]),
        Value::Array(vec![Value::Bytes(vec![13; 32])]),
        Value::Bytes(vec![14; 32]),
        Value::Bytes(vec![15; 32]),
        Value::Bytes(vec![16; 32]),
        Value::Bytes(trust.snapshot_digest().to_vec()),
        Value::Bytes(revocation.snapshot_digest().to_vec()),
        integer(trust.trust_epoch()),
        integer(revocation.revocation_epoch()),
        Value::Bytes(vec![17; 32]),
        Value::Text("policy".to_owned()),
    ]
}

#[test]
fn administrator_policy_binds_every_selected_artifact_and_epoch() -> TestResult {
    let trust = trusted_registry(1)?;
    let signer = SigningKey::from_bytes(&[7; 32]);
    let rvs = SandboxRevocationSnapshot::authenticate(
        &sign_record("RVS1", revocation(&trust, 5, vec![]), &signer)?,
        &trust,
    )?;
    let fields = policy_fields(&trust, &rvs);
    let bytes = sign_record("APT1", Value::Array(fields.clone()), &signer)?;
    let policy = SandboxAdministratorPolicy::authenticate(&bytes, &trust, &rvs)?;
    assert_eq!(policy.policy_epoch(), 7);
    assert_ne!(policy.policy_digest(), [0; 32]);
    assert_eq!(policy.selection().provider_manifest, [10; 32]);
    assert_eq!(policy.selection().provider_binary, [11; 32]);
    assert_eq!(policy.selection().broker_hard_caps, [14; 32]);
    assert_eq!(policy.selection().conformance_profile, [15; 32]);
    assert_eq!(policy.selection().conformance_report, [16; 32]);
    assert_eq!(policy.selection().syscall_set, [17; 32]);
    assert!(policy.accepts_launch_policy(&[12; 32]));
    assert!(!policy.accepts_launch_policy(&[13; 32]));
    assert!(policy.accepts_image(&[13; 32]));
    assert!(!policy.accepts_image(&[12; 32]));
    for index in [10, 11, 12, 13] {
        let mut changed = fields.clone();
        changed[index] = if index < 12 {
            Value::Bytes(vec![99; 32])
        } else {
            integer(99)
        };
        let bytes = sign_record("APT1", Value::Array(changed), &signer)?;
        assert_eq!(
            SandboxAdministratorPolicy::authenticate(&bytes, &trust, &rvs),
            Err(SandboxTrustError::AuthorityMismatch)
        );
    }
    for index in [3, 4] {
        let mut changed = fields.clone();
        changed[index] = Value::Bytes(vec![3; 32]);
        let bytes = sign_record("APT1", Value::Array(changed), &signer)?;
        assert_eq!(
            SandboxAdministratorPolicy::authenticate(&bytes, &trust, &rvs),
            Err(SandboxTrustError::Revoked)
        );
    }
    Ok(())
}

#[test]
fn administrator_policy_rejects_forgery_revoked_signers_and_duplicate_authority() -> TestResult {
    let trust = trusted_registry(1)?;
    let signer = SigningKey::from_bytes(&[7; 32]);
    let rvs = SandboxRevocationSnapshot::authenticate(
        &sign_record("RVS1", revocation(&trust, 5, vec![]), &signer)?,
        &trust,
    )?;
    let fields = policy_fields(&trust, &rvs);
    let forged = sign_record(
        "APT1",
        Value::Array(fields.clone()),
        &SigningKey::from_bytes(&[8; 32]),
    )?;
    assert_eq!(
        SandboxAdministratorPolicy::authenticate(&forged, &trust, &rvs),
        Err(SandboxTrustError::Protocol(ProtocolError::SignatureInvalid))
    );
    for index in [5, 6] {
        let mut changed = fields.clone();
        changed[index] = Value::Array(vec![Value::Bytes(vec![12; 32]), Value::Bytes(vec![12; 32])]);
        let bytes = sign_record("APT1", Value::Array(changed), &signer)?;
        assert_eq!(
            SandboxAdministratorPolicy::authenticate(&bytes, &trust, &rvs),
            Err(SandboxTrustError::Protocol(
                ProtocolError::NonCanonicalOrder
            ))
        );
    }
    let revoked = SandboxRevocationSnapshot::authenticate(
        &sign_record(
            "RVS1",
            revocation(&trust, 6, vec![Value::Text("policy".to_owned())]),
            &signer,
        )?,
        &trust,
    )?;
    let bytes = sign_record(
        "APT1",
        Value::Array(policy_fields(&trust, &revoked)),
        &signer,
    )?;
    assert_eq!(
        SandboxAdministratorPolicy::authenticate(&bytes, &trust, &revoked),
        Err(SandboxTrustError::Revoked)
    );
    Ok(())
}

#[test]
fn revocation_enforces_roles_registry_binding_and_revoked_keys() -> TestResult {
    let trust = trusted_registry(1)?;
    let policy = SigningKey::from_bytes(&[7; 32]);
    let bytes = sign_record("RVS1", revocation(&trust, 5, vec![]), &policy)?;
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
            &trusted_registry(2)?,
            "policy",
            SandboxTrustRole::ProviderRelease
        ),
        Err(SandboxTrustError::AuthorityMismatch)
    );
    let bytes = sign_record(
        "RVS1",
        revocation(&trust, 6, vec![Value::Text("policy".to_owned())]),
        &policy,
    )?;
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
    let trust = trusted_registry(1)?;
    let policy = SigningKey::from_bytes(&[7; 32]);
    let forged = sign_record(
        "RVS1",
        revocation(&trust, 0, vec![]),
        &SigningKey::from_bytes(&[9; 32]),
    )?;
    assert_eq!(
        SandboxRevocationSnapshot::authenticate(&forged, &trust),
        Err(SandboxTrustError::Protocol(ProtocolError::SignatureInvalid))
    );
    let wrong_role = trusted_registry(2)?;
    let bytes = sign_record("RVS1", revocation(&wrong_role, 0, vec![]), &policy)?;
    assert_eq!(
        SandboxRevocationSnapshot::authenticate(&bytes, &wrong_role),
        Err(SandboxTrustError::WrongRole)
    );
    let bytes = sign_record("RVS1", revocation(&wrong_role, 0, vec![]), &policy)?;
    assert_eq!(
        SandboxRevocationSnapshot::authenticate(&bytes, &trust),
        Err(SandboxTrustError::AuthorityMismatch)
    );
    let current = SandboxRevocationSnapshot::authenticate(
        &sign_record("RVS1", revocation(&trust, 0, vec![]), &policy)?,
        &trust,
    )?;
    for epoch in [2, u64::MAX] {
        let next = SandboxRevocationSnapshot::authenticate(
            &sign_record("RVS1", revocation(&trust, epoch, vec![]), &policy)?,
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
        )?;
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
    let bytes = sign(snapshot(vec![], vec![], "root"), &root)?;
    let empty = SandboxTrustSnapshot::authenticate(&bytes, "root", &root.verifying_key())?;
    assert!(empty.keys().is_empty());
    assert!(empty.certificates().is_empty());
    Ok(())
}

#[test]
fn rejects_untrusted_root_and_wrong_named_signer() -> TestResult {
    let root = SigningKey::from_bytes(&[1; 32]);
    let attacker = SigningKey::from_bytes(&[2; 32]);
    let forged = sign(
        snapshot(vec![key_record("root", 0)], vec![], "root"),
        &attacker,
    )?;
    assert_eq!(
        SandboxTrustSnapshot::authenticate(&forged, "root", &root.verifying_key()),
        Err(ProtocolError::SignatureInvalid)
    );
    let renamed = sign(snapshot(vec![], vec![], "other"), &root)?;
    assert_eq!(
        SandboxTrustSnapshot::authenticate(&renamed, "root", &root.verifying_key()),
        Err(ProtocolError::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn rejects_ambiguous_registry_identities_even_with_valid_root_signature() -> TestResult {
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
                &sign(unsigned, &root)?,
                "root",
                &root.verifying_key()
            ),
            Err(ProtocolError::NonCanonicalOrder)
        );
    }
    Ok(())
}

#[test]
fn rejects_unknown_roles_malformed_fields_and_tampering() -> TestResult {
    let root = SigningKey::from_bytes(&[1; 32]);
    let unknown = sign(snapshot(vec![key_record("key", 6)], vec![], "root"), &root)?;
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
            &sign(unsigned, &root)?,
            "root",
            &root.verifying_key()
        )
        .is_err());
    }
    let bytes = sign(snapshot(vec![], vec![], "root"), &root)?;
    let mut wrapper: Value = ciborium::from_reader(bytes.as_slice())?;
    let Value::Array(ref mut fields) = wrapper else {
        return Err("expected test CBOR array".into());
    };
    fields[1] = Value::Bytes(vec![9; 32]);
    assert_eq!(
        SandboxTrustSnapshot::authenticate(&encode(&wrapper)?, "root", &root.verifying_key()),
        Err(ProtocolError::DigestMismatch)
    );
    Ok(())
}

#[test]
fn trust_snapshot_rejects_each_malformed_field_and_nested_record() -> TestResult {
    let root = SigningKey::from_bytes(&[1; 32]);
    let Value::Array(fields) =
        snapshot(vec![key_record("policy", 1)], vec![certificate(3)], "root")
    else {
        return Err("expected test TRS1 array".into());
    };
    for index in 2..fields.len() {
        let mut changed = fields.clone();
        changed[index] = Value::Null;
        assert!(SandboxTrustSnapshot::authenticate(
            &sign(Value::Array(changed), &root)?,
            "root",
            &root.verifying_key()
        )
        .is_err());
    }
    let Value::Array(key_fields) = key_record("policy", 1) else {
        return Err("expected test key array".into());
    };
    for index in 0..key_fields.len() {
        let mut changed = key_fields.clone();
        changed[index] = Value::Null;
        assert!(SandboxTrustSnapshot::authenticate(
            &sign(snapshot(vec![Value::Array(changed)], vec![], "root"), &root)?,
            "root",
            &root.verifying_key()
        )
        .is_err());
    }
    let Value::Array(certificate_fields) = certificate(3) else {
        return Err("expected test certificate array".into());
    };
    for index in 0..certificate_fields.len() {
        let mut changed = certificate_fields.clone();
        changed[index] = Value::Null;
        assert!(SandboxTrustSnapshot::authenticate(
            &sign(snapshot(vec![], vec![Value::Array(changed)], "root"), &root)?,
            "root",
            &root.verifying_key()
        )
        .is_err());
    }
    let first = Value::Array(vec![Value::Bytes(vec![7; 32]), integer(1), integer(2)]);
    let second = Value::Array(vec![Value::Bytes(vec![8; 32]), integer(1), integer(2)]);
    assert_eq!(
        SandboxTrustSnapshot::authenticate(
            &sign(snapshot(vec![], vec![second, first], "root"), &root)?,
            "root",
            &root.verifying_key()
        ),
        Err(ProtocolError::NonCanonicalOrder)
    );
    assert!(
        SandboxTrustSnapshot::authenticate(b"not-cbor", "root", &root.verifying_key()).is_err()
    );
    Ok(())
}

#[test]
fn revocation_rejects_each_malformed_field_collection_and_key_material() -> TestResult {
    let trust = trusted_registry(1)?;
    let signer = SigningKey::from_bytes(&[7; 32]);
    let Value::Array(fields) = revocation(&trust, 5, vec![]) else {
        return Err("expected test RVS1 array".into());
    };
    for index in 2..fields.len() {
        let mut changed = fields.clone();
        changed[index] = Value::Null;
        assert!(SandboxRevocationSnapshot::authenticate(
            &sign_record("RVS1", Value::Array(changed), &signer)?,
            &trust
        )
        .is_err());
    }
    for index in [4, 5, 6] {
        let mut changed = fields.clone();
        changed[index] = Value::Array(vec![Value::Null]);
        assert!(SandboxRevocationSnapshot::authenticate(
            &sign_record("RVS1", Value::Array(changed), &signer)?,
            &trust
        )
        .is_err());
    }
    let mut unknown_signer = fields;
    unknown_signer[7] = Value::Text("missing".to_owned());
    assert_eq!(
        SandboxRevocationSnapshot::authenticate(
            &sign_record("RVS1", Value::Array(unknown_signer), &signer)?,
            &trust
        ),
        Err(SandboxTrustError::UnknownKey)
    );
    let root = SigningKey::from_bytes(&[1; 32]);
    let invalid_key = Value::Array(vec![
        Value::Text("policy".to_owned()),
        integer(1),
        Value::Bytes(vec![u8::MAX; 32]),
        integer(2),
    ]);
    let invalid_trust = SandboxTrustSnapshot::authenticate(
        &sign(snapshot(vec![invalid_key], vec![], "root"), &root)?,
        "root",
        &root.verifying_key(),
    )?;
    let invalid_rvs = revocation(&invalid_trust, 5, vec![]);
    assert_eq!(
        SandboxRevocationSnapshot::authenticate(
            &sign_record("RVS1", invalid_rvs, &signer)?,
            &invalid_trust
        ),
        Err(SandboxTrustError::Protocol(ProtocolError::SignatureInvalid))
    );
    let foreign_trust = SandboxTrustSnapshot::authenticate(
        &sign(
            snapshot(vec![key_record("policy", 1)], vec![certificate(9)], "root"),
            &root,
        )?,
        "root",
        &root.verifying_key(),
    )?;
    let foreign = SandboxRevocationSnapshot::authenticate(
        &sign_record("RVS1", revocation(&foreign_trust, 6, vec![]), &signer)?,
        &foreign_trust,
    )?;
    let current = SandboxRevocationSnapshot::authenticate(
        &sign_record("RVS1", revocation(&trust, 5, vec![]), &signer)?,
        &trust,
    )?;
    assert_eq!(
        current.validate_successor(&foreign),
        Err(SandboxTrustError::AuthorityMismatch)
    );
    assert!(SandboxRevocationSnapshot::authenticate(b"not-cbor", &trust).is_err());
    Ok(())
}

#[test]
fn administrator_policy_rejects_each_malformed_field_and_collection() -> TestResult {
    let trust = trusted_registry(1)?;
    let signer = SigningKey::from_bytes(&[7; 32]);
    let revocation = SandboxRevocationSnapshot::authenticate(
        &sign_record("RVS1", revocation(&trust, 5, vec![]), &signer)?,
        &trust,
    )?;
    let fields = policy_fields(&trust, &revocation);
    for index in 2..fields.len() {
        let mut changed = fields.clone();
        changed[index] = Value::Null;
        assert!(SandboxAdministratorPolicy::authenticate(
            &sign_record("APT1", Value::Array(changed), &signer)?,
            &trust,
            &revocation
        )
        .is_err());
    }
    for index in [5, 6] {
        let mut changed = fields.clone();
        changed[index] = Value::Array(vec![Value::Null]);
        assert!(SandboxAdministratorPolicy::authenticate(
            &sign_record("APT1", Value::Array(changed), &signer)?,
            &trust,
            &revocation
        )
        .is_err());
    }
    assert!(SandboxAdministratorPolicy::authenticate(b"not-cbor", &trust, &revocation).is_err());
    Ok(())
}
