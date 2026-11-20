//! The recovery peer's SIR1 key reader (ADR-069 R12 §5.6), on SIR1 records
//! committed through the live update path in an owned directory.

use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;

use super::PendingRecoveryRuntimeKey;
use crate::evaluator_protocol::{array, array_values, encode_with_limit};
use crate::selector::installation::tests::updates::{SuccessorRevocation, UpdateFixture};
use crate::selector::installation::tests::TestResult;
use crate::selector::installation::RECOVERY_NAME;
use crate::selector::SelectorBoundaryError;

const RECOVERY_LIMIT: usize = 48 * 1024 * 1024;

/// One change to the unsigned SIR1 fields.
type Alteration = Box<dyn Fn(&mut Vec<Value>) -> TestResult>;

fn read(
    fixture: &UpdateFixture,
) -> TestResult<Result<PendingRecoveryRuntimeKey, SelectorBoundaryError>> {
    let root = File::open(fixture.path())?;
    let owner = root.metadata()?.uid();
    Ok(PendingRecoveryRuntimeKey::read_at(&root, owner))
}

fn replace_sir1(fixture: &UpdateFixture, bytes: &[u8]) -> TestResult {
    let path = fixture.path().join(RECOVERY_NAME);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    fs::write(&path, bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

/// The SIR1 envelope of `unsigned`, with an independently computed
/// self-digest, or with `digest` instead when one is given.
fn envelope(unsigned: Value, digest: Option<[u8; 32]>) -> TestResult<Vec<u8>> {
    let unsigned_bytes = encode_with_limit(&unsigned, RECOVERY_LIMIT)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SIR1.v1\0");
    hasher.update(&unsigned_bytes);
    let digest = digest.unwrap_or_else(|| *hasher.finalize().as_bytes());
    Ok(encode_with_limit(
        &Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]),
        RECOVERY_LIMIT,
    )?)
}

/// The pending SIR1's unsigned fields.
fn unsigned_fields(fixture: &UpdateFixture) -> TestResult<Vec<Value>> {
    let bytes = fs::read(fixture.path().join(RECOVERY_NAME))?;
    let document = crate::evaluator_protocol::decode_canonical_with_limit(&bytes, RECOVERY_LIMIT)?;
    Ok(array_values(&array(&document, 2)?[0])?.to_vec())
}

/// Rewrites the pending SIR1 with `alter` applied to its unsigned fields
/// and a recomputed self-digest.
fn rewrite(fixture: &UpdateFixture, alter: impl FnOnce(&mut Vec<Value>)) -> TestResult {
    let mut fields = unsigned_fields(fixture)?;
    alter(&mut fields);
    replace_sir1(fixture, &envelope(Value::Array(fields), None)?)
}

#[test]
fn the_peer_reads_the_previous_runtime_key_even_when_the_next_rvs1_revokes_it() -> TestResult {
    for revocation in [
        SuccessorRevocation::Nothing,
        SuccessorRevocation::SelectedProvider,
        SuccessorRevocation::RuntimeKey,
    ] {
        let fixture = UpdateFixture::new()?;
        let admitted = fixture.admitted()?;
        let expected = admitted.runtime_attestation_key()?;
        fixture.commit_pending_update(vec![[7; 16]], vec![[7; 16]], revocation)?;
        let key = read(&fixture)??;
        assert_eq!(key.key_id(), expected.key_id, "{revocation:?}");
        assert_eq!(
            key.public_key().to_bytes(),
            expected.public_key,
            "{revocation:?}"
        );
        assert_eq!(
            key.key_id(),
            admitted.provider().manifest().runtime_attestation_key_id
        );
    }
    Ok(())
}

#[test]
fn the_peer_needs_an_immutable_sir1_under_a_safe_root() -> TestResult {
    // No SIR1.
    let fixture = UpdateFixture::new()?;
    assert_eq!(read(&fixture)?.err(), Some(SelectorBoundaryError::Io));
    // A SIR1 that breaks the SIC1 file rules (mode 0600).
    fixture.commit_live_update()?;
    let path = fixture.path().join(RECOVERY_NAME);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        read(&fixture)?.err(),
        Some(SelectorBoundaryError::ArtifactInvalid)
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    read(&fixture)??;
    // A root another owner holds.
    let root = File::open(fixture.path())?;
    let foreign = root.metadata()?.uid() ^ 1;
    assert!(PendingRecoveryRuntimeKey::read_at(&root, foreign).is_err());
    // The fixed installation does not exist on a test host.
    assert!(PendingRecoveryRuntimeKey::read().is_err());
    Ok(())
}

#[test]
fn the_self_digest_and_the_envelope_must_verify() -> TestResult {
    let fixture = UpdateFixture::new()?;
    fixture.commit_live_update()?;
    let fields = unsigned_fields(&fixture)?;
    for refused in [
        // A changed self-digest.
        envelope(Value::Array(fields.clone()), Some([9; 32]))?,
        // A self-digest that is not 32 bytes.
        encode_with_limit(
            &Value::Array(vec![
                Value::Array(fields.clone()),
                Value::Bytes(vec![1; 31]),
            ]),
            RECOVERY_LIMIT,
        )?,
        // An envelope of three members.
        encode_with_limit(
            &Value::Array(vec![
                Value::Array(fields.clone()),
                Value::Bytes(vec![1; 32]),
                Value::Null,
            ]),
            RECOVERY_LIMIT,
        )?,
        // Not CBOR.
        vec![0xff],
        // Eight unsigned fields.
        envelope(Value::Array(fields[..8].to_vec()), None)?,
    ] {
        replace_sir1(&fixture, &refused)?;
        assert_eq!(
            read(&fixture)?.err(),
            Some(SelectorBoundaryError::ArtifactInvalid)
        );
    }
    Ok(())
}

#[test]
fn the_header_and_the_runtime_key_must_be_well_formed() -> TestResult {
    let invalid_point = (0_u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
        .ok_or("every candidate is a valid point")?;
    let alterations: [(&str, Alteration); 9] = [
        (
            "magic",
            Box::new(|fields| {
                fields[0] = Value::Text("SIC1".to_owned());
                Ok(())
            }),
        ),
        (
            "version",
            Box::new(|fields| {
                fields[1] = Value::Integer(2.into());
                Ok(())
            }),
        ),
        (
            "binding width",
            Box::new(|fields| {
                fields[5] = Value::Array(Vec::new());
                Ok(())
            }),
        ),
        (
            "key width",
            Box::new(|fields| key(fields, |key| key.truncate(3))),
        ),
        (
            "key id",
            Box::new(|fields| key(fields, |key| key[0] = Value::Bytes(Vec::new()))),
        ),
        (
            "role",
            Box::new(|fields| key(fields, |key| key[1] = Value::Integer(2.into()))),
        ),
        (
            "public key length",
            Box::new(|fields| key(fields, |key| key[2] = Value::Bytes(vec![1; 31]))),
        ),
        (
            "public key point",
            Box::new(move |fields| {
                key(fields, |key| key[2] = Value::Bytes(invalid_point.to_vec()))
            }),
        ),
        (
            "epoch",
            Box::new(|fields| key(fields, |key| key[3] = Value::Text("1".to_owned()))),
        ),
    ];
    for (name, alter) in alterations {
        let fixture = UpdateFixture::new()?;
        fixture.commit_live_update()?;
        let mut outcome = Ok(());
        rewrite(&fixture, |fields| outcome = alter(fields))?;
        outcome?;
        assert_eq!(
            read(&fixture)?.err(),
            Some(SelectorBoundaryError::ArtifactInvalid),
            "{name}"
        );
    }
    // An unchanged rewrite still reads, so each refusal above is its own.
    let fixture = UpdateFixture::new()?;
    fixture.commit_live_update()?;
    rewrite(&fixture, |_| {})?;
    read(&fixture)??;
    Ok(())
}

/// Applies `alter` to the runtime key array of the binding in `fields`.
fn key(fields: &mut [Value], alter: impl FnOnce(&mut Vec<Value>)) -> TestResult {
    match &mut fields[5] {
        Value::Array(binding) => match &mut binding[4] {
            Value::Array(key) => {
                alter(key);
                Ok(())
            }
            _ => Err("the runtime key is not an array".into()),
        },
        _ => Err("the binding is not an array".into()),
    }
}
