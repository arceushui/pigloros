use std::error::Error;

use ciborium::value::Value;
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use pos_core::{
    fork_admission_authority::{
        ForkAdmissionHostRecordV1, ForkAdmissionInitializeChallengeV1, ForkAdmissionOpenChallengeV1,
    },
    fork_authentication::{
        principal_digest_v1, AuthenticatedPrincipalEvidenceV1, AuthenticatedPrincipalRecordV1,
        ForkAuthenticationAdapterPolicyV1, ForkAuthenticationPolicyV1,
    },
    Hash, PrincipalRefV1, PublicKey, Signature,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, verify_fork_admission_initialize_v1,
    verify_fork_admission_open_v1, ForkAuthenticationAdapterSigningKeyV1,
    ForkAuthenticationSignatureErrorV1, ForkHostSigningKeyV1,
    VerifiedAuthenticatedPrincipalEvidenceV1,
};

type TestResult = Result<(), Box<dyn Error>>;

const INVALID_RECORD: ForkAuthenticationSignatureErrorV1 =
    ForkAuthenticationSignatureErrorV1::InvalidRecord;

/// RFC 8032 section 7.1 TEST 1 secret key.
const ADAPTER_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
/// RFC 8032 section 7.1 TEST 1 public key.
const RFC8032_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const HOST_SEED: [u8; 32] = [4; 32];

const ADAPTER_DOMAIN: &[u8] = b"pigloros/authenticated-principal-result/v1";
const INITIALIZE_DOMAIN: &[u8] = b"pigloros/fork-admission-host-bootstrap/v1";
const OPEN_DOMAIN: &[u8] = b"pigloros/fork-admission-host-open/v1";
const COMMAND_DOMAIN: &[u8] = b"pigloros/fork-admission-host-command/v1";
const RECOVERY_DOMAIN: &[u8] = b"pigloros/fork-admission-recovery/v1";

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn array(fields: Vec<Value>) -> Result<Vec<u8>, Box<dyn Error>> {
    encode(&Value::Array(fields))
}

fn bytes(value: u8, length: usize) -> Value {
    Value::Bytes(vec![value; length])
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn int(value: u64) -> Value {
    Value::Integer(value.into())
}

fn record() -> Result<AuthenticatedPrincipalRecordV1, Box<dyn Error>> {
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

fn policy_entry(
    adapter_id: &str,
    verifying_key: [u8; 32],
    minimum_assurance: u8,
    registry_binding: u8,
) -> Result<ForkAuthenticationPolicyV1, Box<dyn Error>> {
    Ok(ForkAuthenticationPolicyV1::new(vec![
        ForkAuthenticationAdapterPolicyV1 {
            adapter_id: adapter_id.to_owned(),
            verifying_key,
            minimum_assurance,
            registry_bindings: vec![Hash::from_bytes([registry_binding; 32])],
        },
    ])?)
}

fn policy(verifying_key: [u8; 32]) -> Result<ForkAuthenticationPolicyV1, Box<dyn Error>> {
    policy_entry("local-unix", verifying_key, 2, 2)
}

fn verified_evidence() -> Result<VerifiedAuthenticatedPrincipalEvidenceV1, Box<dyn Error>> {
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)?;
    let evidence = adapter.sign_authenticated_principal(record()?)?;
    Ok(verify_authenticated_principal_evidence_v1(
        &policy(adapter.public_key())?,
        evidence,
    )?)
}

fn initialize_fields(marker: &str, host_key: [u8; 32]) -> Vec<Value> {
    vec![
        text(marker),
        int(1),
        bytes(1, 32),
        bytes(2, 32),
        Value::Bytes(host_key.to_vec()),
        bytes(4, 32),
    ]
}

fn open_fields(marker: &str) -> Vec<Value> {
    vec![
        text(marker),
        int(1),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
    ]
}

fn recovery_fields(marker: &str, kind: u64) -> Vec<Value> {
    vec![
        text(marker),
        int(1),
        bytes(1, 32),
        bytes(2, 32),
        int(kind),
        bytes(3, 32),
    ]
}

/// POC1/FCC1 fields 0..=6: marker, version, store, session, operation, and
/// the evidence (5) and Principal (6) digests bound to `evidence`.
fn command_prefix(
    marker: &str,
    evidence: &VerifiedAuthenticatedPrincipalEvidenceV1,
) -> Result<Vec<Value>, Box<dyn Error>> {
    let evidence_digest = evidence.evidence().digest()?;
    let principal_digest = principal_digest_v1(&evidence.evidence().record().principal)?;
    Ok(vec![
        text(marker),
        int(1),
        bytes(1, 32),
        bytes(2, 32),
        bytes(3, 32),
        Value::Bytes(evidence_digest.as_bytes().to_vec()),
        Value::Bytes(principal_digest.as_bytes().to_vec()),
    ])
}

fn owner_command_fields(
    evidence: &VerifiedAuthenticatedPrincipalEvidenceV1,
    owner: &str,
) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut fields = command_prefix("POC1", evidence)?;
    fields.push(text(owner));
    Ok(fields)
}

fn fork_command_fields(
    evidence: &VerifiedAuthenticatedPrincipalEvidenceV1,
) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut fields = command_prefix("FCC1", evidence)?;
    fields.extend([
        bytes(6, 16),
        int(7),
        int(7),
        bytes(8, 32),
        bytes(9, 32),
        int(1),
        text("child"),
    ]);
    Ok(fields)
}

/// Verify with `ed25519_dalek` directly over `literal_domain || parts...`,
/// independent of the crate's private preimage construction.
fn verify_literal_preimage(
    public_key: [u8; 32],
    literal_domain: &[u8],
    parts: &[&[u8]],
    signature: &[u8; 64],
) -> TestResult {
    let mut preimage = literal_domain.to_vec();
    for part in parts {
        preimage.extend_from_slice(part);
    }
    VerifyingKey::from_bytes(&public_key)?
        .verify_strict(&preimage, &DalekSignature::from_bytes(signature))?;
    Ok(())
}

#[test]
fn adapter_signing_uses_rfc8032_key_and_policy_pinned_preimage() -> TestResult {
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)?;
    assert_eq!(adapter.public_key(), RFC8032_PUBLIC_KEY);
    let evidence = adapter.sign_authenticated_principal(record()?)?;
    let record_bytes = evidence.record().to_canonical_cbor()?;
    verify_literal_preimage(
        RFC8032_PUBLIC_KEY,
        ADAPTER_DOMAIN,
        &[&record_bytes],
        evidence.signature(),
    )?;
    assert!(verify_literal_preimage(
        RFC8032_PUBLIC_KEY,
        OPEN_DOMAIN,
        &[&record_bytes],
        evidence.signature(),
    )
    .is_err());
    let verified =
        verify_authenticated_principal_evidence_v1(&policy(RFC8032_PUBLIC_KEY)?, evidence)?;
    assert_eq!(verified.evidence().record(), &record()?);
    Ok(())
}

#[test]
fn policy_verification_rejects_missing_adapter_assurance_binding_and_signature() -> TestResult {
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)?;
    let key = adapter.public_key();
    let evidence = adapter.sign_authenticated_principal(record()?)?;
    for mismatched in [
        policy_entry("another-adapter", key, 2, 2)?,
        policy_entry("local-unix", key, 3, 2)?,
        policy_entry("local-unix", key, 2, 9)?,
    ] {
        assert_eq!(
            verify_authenticated_principal_evidence_v1(&mismatched, evidence.clone()),
            Err(ForkAuthenticationSignatureErrorV1::PolicyMismatch)
        );
    }
    let mut altered = evidence.to_canonical_cbor()?;
    let Some(last) = altered.last_mut() else {
        return Err(std::io::Error::other("FAE1 is empty").into());
    };
    *last ^= 1;
    let altered = AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&altered)?;
    assert_eq!(
        verify_authenticated_principal_evidence_v1(&policy(key)?, altered),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
    );
    Ok(())
}

#[test]
fn adapter_rejects_non_decompressible_key_and_invalid_record() -> TestResult {
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)?;
    let evidence = adapter.sign_authenticated_principal(record()?)?;
    // Compressed Edwards y = 2 with sign bit 0: (y^2 - 1) / (d*y^2 + 1) is not
    // a square mod 2^255 - 19, so no curve point has this encoding.
    let mut not_on_curve = [0; 32];
    not_on_curve[0] = 2;
    assert!(VerifyingKey::from_bytes(&not_on_curve).is_err());
    assert_eq!(
        verify_authenticated_principal_evidence_v1(&policy(not_on_curve)?, evidence),
        Err(ForkAuthenticationSignatureErrorV1::InvalidVerifyingKey)
    );
    let mut invalid_record = record()?;
    invalid_record.assurance = 0;
    assert_eq!(
        adapter.sign_authenticated_principal(invalid_record),
        Err(INVALID_RECORD)
    );
    Ok(())
}

#[test]
fn adapter_policy_rejects_small_order_key_universal_forgery() -> TestResult {
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
fn adapter_policy_pinning_a_different_valid_key_rejects_the_signature() -> TestResult {
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

#[test]
fn host_signatures_cover_literal_adr106_domain_preimages() -> TestResult {
    let host = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed(ADAPTER_SEED)?;
    let key = host.public_key();
    assert_ne!(key, adapter.public_key());

    let initialize_bytes = array(initialize_fields("FAI1", key))?;
    assert_eq!(initialize_bytes.len(), 143);
    let initialize = host.sign_initialize(&initialize_bytes)?;
    let initialize = initialize.as_bytes();
    verify_literal_preimage(key, INITIALIZE_DOMAIN, &[&initialize_bytes], initialize)?;
    assert!(verify_literal_preimage(key, OPEN_DOMAIN, &[&initialize_bytes], initialize).is_err());

    let open_bytes = array(open_fields("FAO1"))?;
    assert_eq!(open_bytes.len(), 109);
    let open = host.sign_open(&open_bytes)?;
    verify_literal_preimage(key, OPEN_DOMAIN, &[&open_bytes], open.as_bytes())?;

    let evidence = verified_evidence()?;
    let evidence_bytes = evidence.evidence().to_canonical_cbor()?;
    for command_bytes in [
        array(owner_command_fields(&evidence, "owner")?)?,
        array(fork_command_fields(&evidence)?)?,
    ] {
        let command = host.sign_command(&command_bytes, &evidence)?;
        verify_literal_preimage(
            key,
            COMMAND_DOMAIN,
            &[&command_bytes, &evidence_bytes],
            command.as_bytes(),
        )?;
    }

    let recovery_bytes = array(recovery_fields("FRC1", 1))?;
    assert_eq!(recovery_bytes.len(), 110);
    let recovery = host.sign_recovery(&recovery_bytes)?;
    verify_literal_preimage(
        key,
        RECOVERY_DOMAIN,
        &[&recovery_bytes],
        recovery.as_bytes(),
    )?;
    Ok(())
}

#[test]
fn poc1_reachable_maximum_is_accepted_and_one_byte_over_is_rejected() -> TestResult {
    let host = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let evidence = verified_evidence()?;
    let maximum = array(owner_command_fields(&evidence, &"o".repeat(128))?)?;
    assert_eq!(maximum.len(), 307);
    assert!(host.sign_command(&maximum, &evidence).is_ok());

    let mut oversized = maximum;
    oversized.push(0);
    assert_eq!(
        host.sign_command(&oversized, &evidence),
        Err(INVALID_RECORD)
    );
    Ok(())
}

#[test]
fn fcc1_reachable_maximum_is_accepted_and_one_byte_over_is_rejected() -> TestResult {
    let host = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let evidence = verified_evidence()?;
    let mut fields = fork_command_fields(&evidence)?;
    fields[2] = bytes(0xff, 32);
    fields[3] = bytes(0xfe, 32);
    fields[4] = bytes(0xfd, 32);
    fields[7] = bytes(0xff, 16);
    fields[8] = int(u64::MAX);
    fields[9] = int(u64::MAX);
    fields[10] = bytes(0xfa, 32);
    fields[11] = bytes(0xf9, 32);
    fields[13] = text(&"c".repeat(128));
    let maximum = array(fields)?;
    assert_eq!(maximum.len(), 411);
    assert_eq!(
        &maximum[..8],
        &[0x8e, 0x64, b'F', b'C', b'C', b'1', 0x01, 0x58]
    );
    assert!(host.sign_command(&maximum, &evidence).is_ok());

    let mut oversized = maximum;
    oversized.push(0);
    assert_eq!(
        host.sign_command(&oversized, &evidence),
        Err(INVALID_RECORD)
    );
    Ok(())
}

#[test]
fn host_signing_rejects_commands_with_mismatched_evidence_or_principal_digests() -> TestResult {
    let host = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let evidence = verified_evidence()?;
    for fields in [
        owner_command_fields(&evidence, "owner")?,
        fork_command_fields(&evidence)?,
    ] {
        // Field 5 is the FAE1 evidence digest and field 6 the Principal digest.
        for digest in [5, 6] {
            let mut mismatched = fields.clone();
            mismatched[digest] = bytes(4, 32);
            assert_eq!(
                host.sign_command(&array(mismatched)?, &evidence),
                Err(INVALID_RECORD)
            );
        }
    }
    Ok(())
}

#[test]
fn host_signing_rejects_invalid_fcc1_fields() -> TestResult {
    let host = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let evidence = verified_evidence()?;
    for (field, value) in [
        (4, bytes(0, 32)),
        (7, bytes(6, 15)),
        (8, text("invalid cursor")),
        (9, int(8)),
        (10, bytes(0, 32)),
        (11, bytes(0, 32)),
        (12, int(2)),
        (13, text("")),
        (13, text("nul\0")),
    ] {
        let mut fields = fork_command_fields(&evidence)?;
        fields[field] = value;
        assert_eq!(
            host.sign_command(&array(fields)?, &evidence),
            Err(INVALID_RECORD)
        );
    }
    Ok(())
}

#[test]
fn host_signing_rejects_zero_seeds_and_wrong_purpose_shapes() -> TestResult {
    assert!(matches!(
        ForkAuthenticationAdapterSigningKeyV1::from_seed([0; 32]),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSeed)
    ));
    assert!(matches!(
        ForkHostSigningKeyV1::from_seed([0; 32]),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSeed)
    ));
    let host = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let open_bytes = array(open_fields("FAO1"))?;
    assert_eq!(host.sign_initialize(&open_bytes), Err(INVALID_RECORD));
    assert_eq!(host.sign_recovery(&open_bytes), Err(INVALID_RECORD));
    let foreign_host = array(initialize_fields("FAI1", [3; 32]))?;
    assert_eq!(host.sign_initialize(&foreign_host), Err(INVALID_RECORD));
    let noncanonical = [0x98, 0x05, b'F', b'A', b'O', b'1'];
    assert_eq!(host.sign_open(&noncanonical), Err(INVALID_RECORD));
    Ok(())
}

#[test]
fn host_signing_rejects_canonical_invalid_fields_and_noncanonical_forms() -> TestResult {
    let host = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let evidence = verified_evidence()?;
    let mut zero_initialize = initialize_fields("FAI1", host.public_key());
    zero_initialize[2] = bytes(0, 32);
    assert_eq!(
        host.sign_initialize(&array(zero_initialize)?),
        Err(INVALID_RECORD)
    );
    let mut zero_open = open_fields("FAO1");
    zero_open[3] = bytes(0, 32);
    assert_eq!(host.sign_open(&array(zero_open)?), Err(INVALID_RECORD));
    let invalid_owner = array(owner_command_fields(&evidence, "")?)?;
    assert_eq!(
        host.sign_command(&invalid_owner, &evidence),
        Err(INVALID_RECORD)
    );
    let valid_owner_command = array(owner_command_fields(&evidence, "owner")?)?;
    let mut trailing = valid_owner_command.clone();
    trailing.push(0);
    assert_eq!(host.sign_command(&trailing, &evidence), Err(INVALID_RECORD));
    // Re-encode version 1 as the non-minimal `0x18 0x01`.
    let mut noncanonical = valid_owner_command;
    noncanonical[6] = 0x18;
    noncanonical.insert(7, 1);
    assert_eq!(
        host.sign_command(&noncanonical, &evidence),
        Err(INVALID_RECORD)
    );
    for malformed in [vec![0xff], encode(&int(1))?] {
        assert_eq!(
            host.sign_command(&malformed, &evidence),
            Err(INVALID_RECORD)
        );
    }
    let invalid_kind = array(recovery_fields("FRC1", 3))?;
    assert_eq!(host.sign_recovery(&invalid_kind), Err(INVALID_RECORD));
    let mut zero_recovery = recovery_fields("FRC1", 2);
    zero_recovery[5] = bytes(0, 32);
    assert_eq!(
        host.sign_recovery(&array(zero_recovery)?),
        Err(INVALID_RECORD)
    );
    Ok(())
}

#[test]
fn host_proof_decoders_reject_full_length_wrong_marker_records() -> TestResult {
    let host = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let initialize = array(initialize_fields("BAD1", host.public_key()))?;
    assert_eq!(initialize.len(), 143);
    assert_eq!(host.sign_initialize(&initialize), Err(INVALID_RECORD));

    let open = array(open_fields("BAD1"))?;
    assert_eq!(open.len(), 109);
    assert_eq!(host.sign_open(&open), Err(INVALID_RECORD));

    let recovery = array(recovery_fields("BAD1", 1))?;
    assert_eq!(recovery.len(), 110);
    assert_eq!(host.sign_recovery(&recovery), Err(INVALID_RECORD));
    Ok(())
}

#[test]
fn bootstrap_proofs_bind_host_key_store_and_policy() -> TestResult {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let store_id = Hash::from_bytes([1; 32]);
    let policy_digest = Hash::from_bytes([2; 32]);
    let host_key = PublicKey::from_bytes(signer.public_key());
    let initialize = ForkAdmissionInitializeChallengeV1::new(
        store_id,
        Hash::from_bytes([3; 32]),
        host_key,
        policy_digest,
    )?;
    let initialize_signature = signer.sign_initialize(&initialize.to_canonical_cbor()?)?;
    assert_eq!(
        verify_fork_admission_initialize_v1(&initialize, &initialize_signature),
        Ok(())
    );
    let altered_initialize = ForkAdmissionInitializeChallengeV1::new(
        store_id,
        Hash::from_bytes([9; 32]),
        host_key,
        policy_digest,
    )?;
    assert_eq!(
        verify_fork_admission_initialize_v1(&altered_initialize, &initialize_signature),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
    );

    let host = ForkAdmissionHostRecordV1::new(store_id, host_key, policy_digest)?;
    let open =
        ForkAdmissionOpenChallengeV1::new(store_id, Hash::from_bytes([4; 32]), policy_digest)?;
    let open_signature = signer.sign_open(&open.to_canonical_cbor()?)?;
    assert_eq!(
        verify_fork_admission_open_v1(&host, &open, &open_signature),
        Ok(())
    );
    let foreign_store =
        ForkAdmissionHostRecordV1::new(Hash::from_bytes([5; 32]), host_key, policy_digest)?;
    assert_eq!(
        verify_fork_admission_open_v1(&foreign_store, &open, &open_signature),
        Err(ForkAuthenticationSignatureErrorV1::PolicyMismatch)
    );
    let foreign_policy =
        ForkAdmissionHostRecordV1::new(store_id, host_key, Hash::from_bytes([6; 32]))?;
    assert_eq!(
        verify_fork_admission_open_v1(&foreign_policy, &open, &open_signature),
        Err(ForkAuthenticationSignatureErrorV1::PolicyMismatch)
    );
    assert_eq!(
        verify_fork_admission_open_v1(&host, &open, &Signature::from_bytes([0; 64])),
        Err(ForkAuthenticationSignatureErrorV1::InvalidSignature)
    );

    let malformed_key = (1..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
        .ok_or_else(|| std::io::Error::other("no malformed Ed25519 key fixture found"))?;
    let invalid_key = PublicKey::from_bytes(malformed_key);
    let invalid_initialize = ForkAdmissionInitializeChallengeV1::new(
        store_id,
        Hash::from_bytes([3; 32]),
        invalid_key,
        policy_digest,
    )?;
    assert_eq!(
        verify_fork_admission_initialize_v1(&invalid_initialize, &initialize_signature),
        Err(ForkAuthenticationSignatureErrorV1::InvalidVerifyingKey)
    );
    let invalid_host = ForkAdmissionHostRecordV1::new(store_id, invalid_key, policy_digest)?;
    assert_eq!(
        verify_fork_admission_open_v1(&invalid_host, &open, &open_signature),
        Err(ForkAuthenticationSignatureErrorV1::InvalidVerifyingKey)
    );
    Ok(())
}
