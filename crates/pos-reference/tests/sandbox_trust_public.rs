//! Public trust-root authentication and malformed-snapshot tests.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{
    SandboxAdministratorPolicy, SandboxProviderProtocolError as ProtocolError,
    SandboxRevocationSnapshot, SandboxRevocationUpdateError, SandboxTrustError, SandboxTrustRole,
    SandboxTrustSnapshot, SelectorRevocationState,
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

fn test_nonce() -> [u8; 16] {
    loop {
        let nonce = rand::random();
        if nonce != [0; 16] {
            return nonce;
        }
    }
}

fn corrupt_signed_digest(bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut wrapper: Value = ciborium::from_reader(bytes)?;
    let Value::Array(fields) = &mut wrapper else {
        return Err("expected signed test record".into());
    };
    fields[1] = Value::Bytes(vec![0; 32]);
    encode(&wrapper)
}

fn resign_unsigned_field(
    bytes: &[u8],
    magic: &str,
    field: usize,
    replacement: Value,
    signer: &SigningKey,
) -> TestResult<Vec<u8>> {
    let Value::Array(wrapper) = ciborium::from_reader(bytes)? else {
        return Err("expected signed test record".into());
    };
    let Value::Array(mut unsigned) = wrapper
        .into_iter()
        .next()
        .ok_or("signed test record is empty")?
    else {
        return Err("expected unsigned field array".into());
    };
    *unsigned.get_mut(field).ok_or("unsigned field missing")? = replacement;
    sign_record(magic, Value::Array(unsigned), signer)
}

fn assert_revocation_collection_rejections(
    fields: &[Value],
    signer: &SigningKey,
    trust: &SandboxTrustSnapshot,
) -> TestResult {
    for index in [4, 5, 6] {
        let mut changed = fields.to_vec();
        changed[index] = Value::Array(vec![Value::Null]);
        assert!(SandboxRevocationSnapshot::authenticate(
            &sign_record("RVS1", Value::Array(changed), signer)?,
            trust
        )
        .is_err());
    }
    for (index, values) in [
        (
            4,
            vec![Value::Text("z".to_owned()), Value::Text("a".to_owned())],
        ),
        (
            5,
            vec![Value::Bytes(vec![8; 32]), Value::Bytes(vec![3; 32])],
        ),
        (
            6,
            vec![Value::Bytes(vec![8; 32]), Value::Bytes(vec![4; 32])],
        ),
    ] {
        let mut changed = fields.to_vec();
        changed[index] = Value::Array(values);
        assert_eq!(
            SandboxRevocationSnapshot::authenticate(
                &sign_record("RVS1", Value::Array(changed), signer)?,
                trust
            ),
            Err(SandboxTrustError::Protocol(
                ProtocolError::NonCanonicalOrder
            ))
        );
    }
    let valid = sign_record("RVS1", Value::Array(fields.to_vec()), signer)?;
    assert_eq!(
        SandboxRevocationSnapshot::authenticate(&corrupt_signed_digest(&valid)?, trust),
        Err(SandboxTrustError::Protocol(ProtocolError::DigestMismatch))
    );
    Ok(())
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

fn sign_trust_snapshot(unsigned: Value, root: &SigningKey) -> TestResult<Vec<u8>> {
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
    let bytes = sign_trust_snapshot(
        snapshot(vec![key_record("policy", role)], vec![], "root"),
        &root,
    )?;
    Ok(SandboxTrustSnapshot::authenticate(
        &bytes,
        "root",
        &root.verifying_key(),
    )?)
}

fn update_registry() -> TestResult<SandboxTrustSnapshot> {
    let root = SigningKey::from_bytes(&[1; 32]);
    let bytes = sign_trust_snapshot(
        snapshot(
            vec![key_record("policy", 1), key_record("runtime", 3)],
            vec![],
            "root",
        ),
        &root,
    )?;
    Ok(SandboxTrustSnapshot::authenticate(
        &bytes,
        "root",
        &root.verifying_key(),
    )?)
}

fn revocation_update(
    current: &SandboxRevocationSnapshot,
    next_bytes: &[u8],
    next: &SandboxRevocationSnapshot,
    signer: &SigningKey,
    nonce: [u8; 16],
) -> TestResult<Vec<u8>> {
    revocation_update_with_id(current, next_bytes, next, signer, nonce, [21; 16])
}

fn revocation_update_with_id(
    current: &SandboxRevocationSnapshot,
    next_bytes: &[u8],
    next: &SandboxRevocationSnapshot,
    signer: &SigningKey,
    nonce: [u8; 16],
    request_id: [u8; 16],
) -> TestResult<Vec<u8>> {
    sign_record(
        "RCU1",
        Value::Array(vec![
            Value::Text("RCU1".to_owned()),
            integer(1),
            Value::Bytes(request_id.to_vec()),
            Value::Bytes(current.snapshot_digest().to_vec()),
            Value::Bytes(next_bytes.to_vec()),
            Value::Bytes(next.snapshot_digest().to_vec()),
            Value::Bytes(nonce.to_vec()),
            Value::Text("policy".to_owned()),
        ]),
        signer,
    )
}

fn revocation_acknowledgement(
    next: &SandboxRevocationSnapshot,
    signer: &SigningKey,
    cancelled: Vec<Value>,
) -> TestResult<Vec<u8>> {
    revocation_acknowledgement_fields(
        next.snapshot_digest(),
        signer,
        cancelled,
        [21; 16],
        0,
        "runtime",
    )
}

fn revocation_acknowledgement_fields(
    revocation_digest: [u8; 32],
    signer: &SigningKey,
    cancelled: Vec<Value>,
    request_id: [u8; 16],
    status: u64,
    runtime_key_id: &str,
) -> TestResult<Vec<u8>> {
    sign_record(
        "RCA1",
        Value::Array(vec![
            Value::Text("RCA1".to_owned()),
            integer(1),
            Value::Bytes(request_id.to_vec()),
            Value::Bytes(revocation_digest.to_vec()),
            Value::Array(cancelled),
            integer(status),
            Value::Text(runtime_key_id.to_owned()),
        ]),
        signer,
    )
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
    current.validate_immediate_epoch_for_same_registry(&next)?;
    assert_eq!(
        next.active_key(&trust, "policy", SandboxTrustRole::AdministratorPolicy),
        Err(SandboxTrustError::Revoked)
    );
    assert_eq!(
        next.validate_immediate_epoch_for_same_registry(&current),
        Err(SandboxTrustError::EpochDiscontinuity)
    );
    assert_eq!(
        current.validate_immediate_epoch_for_same_registry(&current),
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
            current.validate_immediate_epoch_for_same_registry(&next),
            Err(SandboxTrustError::EpochDiscontinuity)
        );
        assert_eq!(
            next.validate_immediate_epoch_for_same_registry(&current),
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
        let bytes = sign_trust_snapshot(
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
    let bytes = sign_trust_snapshot(snapshot(vec![], vec![], "root"), &root)?;
    let empty = SandboxTrustSnapshot::authenticate(&bytes, "root", &root.verifying_key())?;
    assert!(empty.keys().is_empty());
    assert!(empty.certificates().is_empty());
    Ok(())
}

#[test]
fn rejects_untrusted_root_and_wrong_named_signer() -> TestResult {
    let root = SigningKey::from_bytes(&[1; 32]);
    let attacker = SigningKey::from_bytes(&[2; 32]);
    let forged = sign_trust_snapshot(
        snapshot(vec![key_record("root", 0)], vec![], "root"),
        &attacker,
    )?;
    assert_eq!(
        SandboxTrustSnapshot::authenticate(&forged, "root", &root.verifying_key()),
        Err(ProtocolError::SignatureInvalid)
    );
    let renamed = sign_trust_snapshot(snapshot(vec![], vec![], "other"), &root)?;
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
                &sign_trust_snapshot(unsigned, &root)?,
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
    let unknown = sign_trust_snapshot(snapshot(vec![key_record("key", 6)], vec![], "root"), &root)?;
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
            &sign_trust_snapshot(unsigned, &root)?,
            "root",
            &root.verifying_key()
        )
        .is_err());
    }
    let bytes = sign_trust_snapshot(snapshot(vec![], vec![], "root"), &root)?;
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
            &sign_trust_snapshot(Value::Array(changed), &root)?,
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
            &sign_trust_snapshot(snapshot(vec![Value::Array(changed)], vec![], "root"), &root)?,
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
            &sign_trust_snapshot(snapshot(vec![], vec![Value::Array(changed)], "root"), &root)?,
            "root",
            &root.verifying_key()
        )
        .is_err());
    }
    let first = Value::Array(vec![Value::Bytes(vec![7; 32]), integer(1), integer(2)]);
    let second = Value::Array(vec![Value::Bytes(vec![8; 32]), integer(1), integer(2)]);
    assert_eq!(
        SandboxTrustSnapshot::authenticate(
            &sign_trust_snapshot(snapshot(vec![], vec![second, first], "root"), &root)?,
            "root",
            &root.verifying_key()
        ),
        Err(ProtocolError::NonCanonicalOrder)
    );
    assert!(
        SandboxTrustSnapshot::authenticate(b"not-cbor", "root", &root.verifying_key()).is_err()
    );
    assert!(SandboxTrustSnapshot::authenticate(
        &encode(&Value::Null)?,
        "root",
        &root.verifying_key()
    )
    .is_err());
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
    assert_revocation_collection_rejections(&fields, &signer, &trust)?;
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
    let mut invalid_public_key = [u8::MAX; 32];
    invalid_public_key[0] = 0xed;
    invalid_public_key[31] = 0x7f;
    let invalid_key = Value::Array(vec![
        Value::Text("policy".to_owned()),
        integer(1),
        Value::Bytes(invalid_public_key.to_vec()),
        integer(2),
    ]);
    let invalid_trust = SandboxTrustSnapshot::authenticate(
        &sign_trust_snapshot(snapshot(vec![invalid_key], vec![], "root"), &root)?,
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
        &sign_trust_snapshot(
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
        current.validate_immediate_epoch_for_same_registry(&foreign),
        Err(SandboxTrustError::AuthorityMismatch)
    );
    assert!(SandboxRevocationSnapshot::authenticate(b"not-cbor", &trust).is_err());
    assert!(SandboxRevocationSnapshot::authenticate(&encode(&Value::Null)?, &trust).is_err());
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
    let valid_policy = sign_record("APT1", Value::Array(fields), &signer)?;
    assert_eq!(
        SandboxAdministratorPolicy::authenticate(
            &corrupt_signed_digest(&valid_policy)?,
            &trust,
            &revocation
        ),
        Err(SandboxTrustError::Protocol(ProtocolError::DigestMismatch))
    );
    assert!(SandboxAdministratorPolicy::authenticate(b"not-cbor", &trust, &revocation).is_err());
    assert!(
        SandboxAdministratorPolicy::authenticate(&encode(&Value::Null)?, &trust, &revocation)
            .is_err()
    );
    Ok(())
}

#[test]
fn selector_revocation_state_requires_exact_timely_cancellation_acknowledgement() -> TestResult {
    let trust = update_registry()?;
    let signer = SigningKey::from_bytes(&[7; 32]);
    let current = SandboxRevocationSnapshot::authenticate(
        &sign_record("RVS1", revocation(&trust, 5, vec![]), &signer)?,
        &trust,
    )?;
    let next_bytes = sign_record("RVS1", revocation(&trust, 6, vec![]), &signer)?;
    let next = SandboxRevocationSnapshot::authenticate(&next_bytes, &trust)?;
    let update_id = test_nonce();
    let update = revocation_update(&current, &next_bytes, &next, &signer, update_id)?;
    let cancelled = vec![[23; 16], [24; 16]];
    let mut state = SelectorRevocationState::new(current.clone());
    state.begin_update(&update, &trust, cancelled.clone(), 1_000)?;
    state.begin_update(&update, &trust, cancelled.clone(), 1_001)?;

    let wrong_ack = revocation_acknowledgement(&next, &signer, vec![Value::Bytes(vec![23; 16])])?;
    assert_eq!(
        state.acknowledge(&wrong_ack, "runtime", &signer.verifying_key(), 1_050),
        Err(SandboxRevocationUpdateError::AcknowledgementMismatch)
    );
    let acknowledgement = revocation_acknowledgement(
        &next,
        &signer,
        cancelled
            .iter()
            .map(|attempt| Value::Bytes(attempt.to_vec()))
            .collect(),
    )?;
    state.acknowledge(&acknowledgement, "runtime", &signer.verifying_key(), 1_100)?;
    assert_eq!(state.current().snapshot_digest(), next.snapshot_digest());
    state.begin_update(&update, &trust, cancelled, 2_000)?;
    state.acknowledge(&acknowledgement, "runtime", &signer.verifying_key(), 2_000)?;

    let conflicting = revocation_update(&current, &next_bytes, &next, &signer, test_nonce())?;
    assert_eq!(
        state.begin_update(&conflicting, &trust, vec![], 2_000),
        Err(SandboxRevocationUpdateError::RequestIdentityConflict)
    );

    let mut late = SelectorRevocationState::new(current);
    late.begin_update(&update, &trust, vec![[23; 16], [24; 16]], 1_000)?;
    assert_eq!(
        late.acknowledge(&acknowledgement, "runtime", &signer.verifying_key(), 1_101,),
        Err(SandboxRevocationUpdateError::AcknowledgementDeadline)
    );
    Ok(())
}

struct RevocationTransitionFixture {
    trust: SandboxTrustSnapshot,
    signer: SigningKey,
    current: SandboxRevocationSnapshot,
    next_bytes: Vec<u8>,
    next: SandboxRevocationSnapshot,
}

fn revocation_transition_fixture() -> TestResult<RevocationTransitionFixture> {
    let trust = update_registry()?;
    let signer = SigningKey::from_bytes(&[7; 32]);
    let current_bytes = sign_record("RVS1", revocation(&trust, 5, vec![]), &signer)?;
    let current = SandboxRevocationSnapshot::authenticate(&current_bytes, &trust)?;
    let next_bytes = sign_record("RVS1", revocation(&trust, 6, vec![]), &signer)?;
    let next = SandboxRevocationSnapshot::authenticate(&next_bytes, &trust)?;
    Ok(RevocationTransitionFixture {
        trust,
        signer,
        current,
        next_bytes,
        next,
    })
}

#[test]
fn selector_revocation_state_rejects_pending_update_conflicts() -> TestResult {
    let fixture = revocation_transition_fixture()?;
    let first_nonce = test_nonce();
    let second_nonce = loop {
        let candidate = test_nonce();
        if candidate != first_nonce {
            break candidate;
        }
    };
    let update = revocation_update(
        &fixture.current,
        &fixture.next_bytes,
        &fixture.next,
        &fixture.signer,
        first_nonce,
    )?;
    let conflicting = revocation_update(
        &fixture.current,
        &fixture.next_bytes,
        &fixture.next,
        &fixture.signer,
        second_nonce,
    )?;
    let other_request = revocation_update_with_id(
        &fixture.current,
        &fixture.next_bytes,
        &fixture.next,
        &fixture.signer,
        test_nonce(),
        [22; 16],
    )?;
    let cancelled = vec![[23; 16], [24; 16]];
    let mut state = SelectorRevocationState::new(fixture.current.clone());
    state.begin_update(&update, &fixture.trust, cancelled.clone(), 1_000)?;
    assert_eq!(
        state.begin_update(&conflicting, &fixture.trust, cancelled.clone(), 1_001),
        Err(SandboxRevocationUpdateError::RequestIdentityConflict)
    );
    assert_eq!(
        state.begin_update(&other_request, &fixture.trust, cancelled, 1_001),
        Err(SandboxRevocationUpdateError::UpdateInFlight)
    );

    let mut no_pending = SelectorRevocationState::new(fixture.current);
    for invalid in [
        vec![[0; 16]],
        vec![[23; 16], [23; 16]],
        vec![[24; 16], [23; 16]],
        vec![[1; 16]; 257],
    ] {
        assert!(matches!(
            no_pending.begin_update(&update, &fixture.trust, invalid, 1_000),
            Err(SandboxRevocationUpdateError::Protocol(_))
        ));
    }
    assert_eq!(
        no_pending.begin_update(&update, &fixture.trust, Vec::new(), u64::MAX),
        Err(SandboxRevocationUpdateError::AcknowledgementDeadline)
    );
    Ok(())
}

#[test]
fn selector_revocation_state_rejects_update_authority_and_signer_substitution() -> TestResult {
    let fixture = revocation_transition_fixture()?;
    let update = revocation_update(
        &fixture.current,
        &fixture.next_bytes,
        &fixture.next,
        &fixture.signer,
        test_nonce(),
    )?;
    for (field, replacement, expected) in [
        (
            3,
            Value::Bytes(vec![99; 32]),
            SandboxRevocationUpdateError::Trust(SandboxTrustError::AuthorityMismatch),
        ),
        (
            5,
            Value::Bytes(vec![99; 32]),
            SandboxRevocationUpdateError::Trust(SandboxTrustError::AuthorityMismatch),
        ),
        (
            7,
            Value::Text("runtime".to_owned()),
            SandboxRevocationUpdateError::Trust(SandboxTrustError::WrongRole),
        ),
    ] {
        let changed = resign_unsigned_field(&update, "RCU1", field, replacement, &fixture.signer)?;
        let mut state = SelectorRevocationState::new(fixture.current.clone());
        assert_eq!(
            state.begin_update(&changed, &fixture.trust, Vec::new(), 1_000),
            Err(expected)
        );
    }
    Ok(())
}

#[test]
fn selector_revocation_state_rejects_malformed_update_fields() -> TestResult {
    let fixture = revocation_transition_fixture()?;
    let update = revocation_update(
        &fixture.current,
        &fixture.next_bytes,
        &fixture.next,
        &fixture.signer,
        test_nonce(),
    )?;
    for field in 2..=7 {
        let changed = resign_unsigned_field(&update, "RCU1", field, Value::Null, &fixture.signer)?;
        let mut state = SelectorRevocationState::new(fixture.current.clone());
        assert!(matches!(
            state.begin_update(&changed, &fixture.trust, Vec::new(), 1_000),
            Err(SandboxRevocationUpdateError::Protocol(_))
                | Err(SandboxRevocationUpdateError::Trust(
                    SandboxTrustError::Protocol(_)
                ))
        ));
    }
    assert!(matches!(
        SelectorRevocationState::new(fixture.current).begin_update(
            &corrupt_signed_digest(&update)?,
            &fixture.trust,
            Vec::new(),
            1_000
        ),
        Err(SandboxRevocationUpdateError::Protocol(
            ProtocolError::DigestMismatch
        ))
    ));
    Ok(())
}

#[test]
fn selector_revocation_state_rejects_acknowledgement_conflicts() -> TestResult {
    let fixture = revocation_transition_fixture()?;
    let update = revocation_update(
        &fixture.current,
        &fixture.next_bytes,
        &fixture.next,
        &fixture.signer,
        test_nonce(),
    )?;
    let cancelled = vec![[23; 16], [24; 16]];
    let cancelled_values = cancelled
        .iter()
        .map(|attempt| Value::Bytes(attempt.to_vec()))
        .collect::<Vec<_>>();
    let mut state = SelectorRevocationState::new(fixture.current.clone());
    state.begin_update(&update, &fixture.trust, cancelled, 1_000)?;
    let wrong_request_ack = revocation_acknowledgement_fields(
        fixture.next.snapshot_digest(),
        &fixture.signer,
        cancelled_values.clone(),
        [22; 16],
        0,
        "runtime",
    )?;
    assert_eq!(
        state.acknowledge(
            &wrong_request_ack,
            "runtime",
            &fixture.signer.verifying_key(),
            1_050
        ),
        Err(SandboxRevocationUpdateError::AcknowledgementMismatch)
    );
    let wrong_snapshot_ack = revocation_acknowledgement_fields(
        fixture.current.snapshot_digest(),
        &fixture.signer,
        cancelled_values.clone(),
        [21; 16],
        0,
        "runtime",
    )?;
    assert_eq!(
        state.acknowledge(
            &wrong_snapshot_ack,
            "runtime",
            &fixture.signer.verifying_key(),
            1_050
        ),
        Err(SandboxRevocationUpdateError::AcknowledgementMismatch)
    );
    let wrong_status_ack = revocation_acknowledgement_fields(
        fixture.next.snapshot_digest(),
        &fixture.signer,
        cancelled_values.clone(),
        [21; 16],
        1,
        "runtime",
    )?;
    assert!(matches!(
        state.acknowledge(
            &wrong_status_ack,
            "runtime",
            &fixture.signer.verifying_key(),
            1_050
        ),
        Err(SandboxRevocationUpdateError::Protocol(_))
    ));
    let forged_acknowledgement = revocation_acknowledgement(
        &fixture.next,
        &SigningKey::from_bytes(&[8; 32]),
        cancelled_values.clone(),
    )?;
    assert!(matches!(
        state.acknowledge(
            &forged_acknowledgement,
            "runtime",
            &fixture.signer.verifying_key(),
            1_050
        ),
        Err(SandboxRevocationUpdateError::Protocol(
            ProtocolError::SignatureInvalid
        ))
    ));
    let acknowledgement =
        revocation_acknowledgement(&fixture.next, &fixture.signer, cancelled_values)?;
    assert_eq!(
        state.acknowledge(
            &acknowledgement,
            "other",
            &fixture.signer.verifying_key(),
            1_050
        ),
        Err(SandboxRevocationUpdateError::AcknowledgementMismatch)
    );
    Ok(())
}

#[test]
fn selector_revocation_state_rejects_malformed_acknowledgement_fields() -> TestResult {
    let fixture = revocation_transition_fixture()?;
    let acknowledgement = revocation_acknowledgement(&fixture.next, &fixture.signer, Vec::new())?;
    for field in 2..=6 {
        let changed = resign_unsigned_field(
            &acknowledgement,
            "RCA1",
            field,
            Value::Null,
            &fixture.signer,
        )?;
        let mut state = SelectorRevocationState::new(fixture.current.clone());
        assert!(matches!(
            state.acknowledge(&changed, "runtime", &fixture.signer.verifying_key(), 1_000),
            Err(SandboxRevocationUpdateError::Protocol(_))
        ));
    }
    let malformed_cancelled_attempt = resign_unsigned_field(
        &acknowledgement,
        "RCA1",
        4,
        Value::Array(vec![Value::Null]),
        &fixture.signer,
    )?;
    let mut state = SelectorRevocationState::new(fixture.current.clone());
    assert!(matches!(
        state.acknowledge(
            &malformed_cancelled_attempt,
            "runtime",
            &fixture.signer.verifying_key(),
            1_000
        ),
        Err(SandboxRevocationUpdateError::Protocol(_))
    ));
    assert!(matches!(
        SelectorRevocationState::new(fixture.current).acknowledge(
            &corrupt_signed_digest(&acknowledgement)?,
            "runtime",
            &fixture.signer.verifying_key(),
            1_000
        ),
        Err(SandboxRevocationUpdateError::Protocol(
            ProtocolError::DigestMismatch
        ))
    ));
    Ok(())
}

#[test]
fn selector_revocation_state_rejects_completed_acknowledgement_conflicts() -> TestResult {
    let fixture = revocation_transition_fixture()?;
    let update = revocation_update(
        &fixture.current,
        &fixture.next_bytes,
        &fixture.next,
        &fixture.signer,
        test_nonce(),
    )?;
    let cancelled = vec![[23; 16], [24; 16]];
    let cancelled_values = cancelled
        .iter()
        .map(|attempt| Value::Bytes(attempt.to_vec()))
        .collect::<Vec<_>>();
    let acknowledgement =
        revocation_acknowledgement(&fixture.next, &fixture.signer, cancelled_values)?;
    let mut state = SelectorRevocationState::new(fixture.current.clone());
    state.begin_update(&update, &fixture.trust, cancelled, 1_000)?;
    state.acknowledge(
        &acknowledgement,
        "runtime",
        &fixture.signer.verifying_key(),
        1_050,
    )?;

    let conflicting_ack = revocation_acknowledgement_fields(
        fixture.next.snapshot_digest(),
        &fixture.signer,
        vec![Value::Bytes(vec![23; 16])],
        [21; 16],
        0,
        "runtime",
    )?;
    assert_eq!(
        state.acknowledge(
            &conflicting_ack,
            "runtime",
            &fixture.signer.verifying_key(),
            1_051
        ),
        Err(SandboxRevocationUpdateError::RequestIdentityConflict)
    );

    let mut no_pending = SelectorRevocationState::new(fixture.current);
    assert_eq!(
        no_pending.acknowledge(
            &acknowledgement,
            "runtime",
            &fixture.signer.verifying_key(),
            1_050
        ),
        Err(SandboxRevocationUpdateError::AcknowledgementMismatch)
    );
    Ok(())
}
