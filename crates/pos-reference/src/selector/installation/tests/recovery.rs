//! Public-seam tests of the pending-SIR1 loader (ADR-069 R12 §4.1, P1).
//!
//! Each case commits one real transaction through the live update path, then
//! reopens the installation the way a restarted selector does. Altered SIR1
//! records carry a recomputed self-digest, so they reach the rebuild rather
//! than failing at the envelope.

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use ciborium::value::Value;

use super::updates::{SuccessorRevocation, UpdateFixture};
use super::TestResult;
use crate::evaluator_protocol::{array, array_values, decode_canonical, encode_with_limit};
use crate::selector::installation::authority::VerifiedPendingRecovery;
use crate::selector::installation::{
    FixedInstallation, InstalledSelectorState, MANIFEST_NAME, RECOVERY_NAME,
};
use crate::selector::SelectorBoundaryError;

const RECOVERY_LIMIT: usize = 48 * 1024 * 1024;
const EMBEDDED_RECORD_LIMIT: usize = 16 * 1024 * 1024;

fn load(
    fixture: &UpdateFixture,
) -> TestResult<Result<VerifiedPendingRecovery, SelectorBoundaryError>> {
    match InstalledSelectorState::open_fixed_at_for_test(&File::open(fixture.path())?)? {
        FixedInstallation::RecoveryPending(installed) => {
            Ok(VerifiedPendingRecovery::load(&installed))
        }
        FixedInstallation::Admissible(_) => Err("no SIR1 is pending".into()),
    }
}

fn replace_immutable(path: &Path, bytes: &[u8]) -> TestResult {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

/// Rewrites the pending SIR1 through `alter` on its unsigned fields, with an
/// independently recomputed self-digest.
fn rewrite_sir1(fixture: &UpdateFixture, alter: impl FnOnce(&mut Vec<Value>)) -> TestResult {
    let path = fixture.path().join(RECOVERY_NAME);
    let document = decode_canonical_unbounded(&fs::read(&path)?)?;
    let mut unsigned = array_values(&array(&document, 2)?[0])?.to_vec();
    alter(&mut unsigned);
    let unsigned = Value::Array(unsigned);
    let unsigned_bytes = encode_with_limit(&unsigned, RECOVERY_LIMIT)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SIR1.v1\0");
    hasher.update(&unsigned_bytes);
    let digest = hasher.finalize().as_bytes().to_vec();
    replace_immutable(
        &path,
        &encode_with_limit(
            &Value::Array(vec![unsigned, Value::Bytes(digest)]),
            RECOVERY_LIMIT,
        )?,
    )
}

fn decode_canonical_unbounded(bytes: &[u8]) -> TestResult<Value> {
    Ok(crate::evaluator_protocol::decode_canonical_with_limit(
        bytes,
        RECOVERY_LIMIT,
    )?)
}

fn record_field(request: &[u8], index: usize) -> TestResult<Vec<u8>> {
    let document = decode_canonical(request)?;
    match &array(&document, 5)?[index] {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err("SIU1 record is not bytes".into()),
    }
}

#[test]
fn the_loader_rebuilds_the_exact_committed_transaction() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let previous_digest = fixture
        .admitted()?
        .bootstrap()
        .installed()
        .manifest()
        .digest();
    let (committed, request) = fixture.commit_pending_update(
        vec![[41; 16], [42; 16]],
        vec![[42; 16]],
        SuccessorRevocation::Nothing,
    )?;
    let loaded = load(&fixture)??;
    let context = committed.cancellation_context()?;
    assert_eq!(loaded.sir1_digest, committed.sir1_digest());
    assert_eq!(
        loaded.previous_provider_binding_digest,
        context.previous_provider_binding_digest
    );
    assert_eq!(loaded.previous_live_attempt_ids, vec![[41; 16], [42; 16]]);
    assert_eq!(loaded.previous_installation_digest, previous_digest);
    assert_eq!(loaded.pending_update, request);
    let rcu1 = decode_canonical(&record_field(&request, 4)?)?;
    let rcu1_fields = array(&array(&rcu1, 3)?[0], 8)?;
    assert_eq!(rcu1_fields[6], Value::Bytes(loaded.selector_nonce.to_vec()));
    let mut ids = vec![
        loaded.previous_runtime_instance_id,
        loaded.previous_lifecycle_scope_id,
    ];
    ids.extend(loaded.recovery_peer_slot);
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 5);
    assert!(!ids.contains(&[0; 16]));
    Ok(())
}

#[test]
fn the_loader_accepts_a_published_successor_and_a_revoked_provider() -> TestResult {
    // Crash row 7: the next SIC1 is installed, SIR1 is not yet removed.
    let fixture = UpdateFixture::new()?;
    let (committed, request) =
        fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
    replace_immutable(
        &fixture.path().join(MANIFEST_NAME),
        &record_field(&request, 3)?,
    )?;
    assert_eq!(load(&fixture)??.sir1_digest, committed.sir1_digest());

    // The next RVS1 revokes the previous provider (field 5) or its role-3
    // runtime key (field 4, R12 I10): the key is still resolved from the
    // previous state, both before and after the next SIC1 is installed.
    for revocation in [
        SuccessorRevocation::SelectedProvider,
        SuccessorRevocation::RuntimeKey,
    ] {
        let revoking = UpdateFixture::new()?;
        let (committed, request) =
            revoking.commit_pending_update(Vec::new(), Vec::new(), revocation)?;
        let loaded = load(&revoking)??;
        assert_eq!(
            loaded.sir1_digest,
            committed.sir1_digest(),
            "{revocation:?}"
        );
        assert_eq!(
            loaded.previous_provider_binding_digest,
            committed
                .cancellation_context()?
                .previous_provider_binding_digest
        );
        assert_eq!(loaded.pending_update, request);
        replace_immutable(
            &revoking.path().join(MANIFEST_NAME),
            &record_field(&request, 3)?,
        )?;
        assert_eq!(load(&revoking)??.sir1_digest, committed.sir1_digest());
    }
    Ok(())
}

#[test]
fn the_loader_requires_the_previous_or_next_installation() -> TestResult {
    let fixture = UpdateFixture::new()?;
    let (_committed, request) =
        fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
    // A SIR1 naming the real successor as its previous SIC1, and another
    // next SIC1: the current SIC1 is neither of them.
    let path = fixture.path().join(RECOVERY_NAME);
    let original = fs::read(&path)?;
    let next = record_field(&request, 3)?;
    rewrite_sir1(&fixture, |unsigned| {
        unsigned[2] = Value::Bytes(next);
        unsigned[3] = Value::Bytes(vec![1]);
    })?;
    assert_eq!(
        load(&fixture)?.err(),
        Some(SelectorBoundaryError::ArtifactInvalid)
    );

    // The current SIC1 is the previous one, but the next SIC1 is no SIC1.
    replace_immutable(&path, &original)?;
    rewrite_sir1(&fixture, |unsigned| unsigned[3] = Value::Bytes(vec![1]))?;
    assert_eq!(
        load(&fixture)?.err(),
        Some(SelectorBoundaryError::ArtifactInvalid)
    );
    Ok(())
}

#[test]
fn the_loader_rejects_an_altered_or_malformed_envelope() -> TestResult {
    let fixture = UpdateFixture::new()?;
    fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
    let path = fixture.path().join(RECOVERY_NAME);
    let original = fs::read(&path)?;

    let mut wrong_digest = original.clone();
    let last = wrong_digest.len() - 1;
    wrong_digest[last] ^= 1;
    replace_immutable(&path, &wrong_digest)?;
    assert_eq!(
        load(&fixture)?.err(),
        Some(SelectorBoundaryError::ArtifactInvalid)
    );

    replace_immutable(&path, b"not a SIR1")?;
    assert_eq!(
        load(&fixture)?.err(),
        Some(SelectorBoundaryError::ArtifactInvalid)
    );

    replace_immutable(&path, &original)?;
    assert!(load(&fixture)?.is_ok());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert!(load(&fixture)?.is_err());
    Ok(())
}

#[test]
fn the_loader_bounds_each_embedded_record_and_the_whole_file() -> TestResult {
    let fixture = UpdateFixture::new()?;
    fixture.commit_pending_update(Vec::new(), Vec::new(), SuccessorRevocation::Nothing)?;
    let path = fixture.path().join(RECOVERY_NAME);
    let original = fs::read(&path)?;

    // One byte over the 16 MiB embedded-record bound, inside the 48 MiB
    // SIR1 bound; an empty record is outside it too.
    for oversized in [vec![0; EMBEDDED_RECORD_LIMIT + 1], Vec::new()] {
        rewrite_sir1(&fixture, |unsigned| unsigned[4] = Value::Bytes(oversized))?;
        assert_eq!(
            load(&fixture)?.err(),
            Some(SelectorBoundaryError::ArtifactInvalid)
        );
        replace_immutable(&path, &original)?;
    }

    // One byte over the 48 MiB SIR1 bound.
    let mut over_file = original.clone();
    over_file.resize(RECOVERY_LIMIT + 1, 0);
    replace_immutable(&path, &over_file)?;
    assert_eq!(
        load(&fixture)?.err(),
        Some(SelectorBoundaryError::ArtifactInvalid)
    );
    replace_immutable(&path, &original)?;
    assert!(load(&fixture)?.is_ok());
    Ok(())
}

#[test]
fn the_loader_rejects_each_malformed_field() -> TestResult {
    let fixture = UpdateFixture::new()?;
    fixture.commit_pending_update(vec![[41; 16]], vec![[41; 16]], SuccessorRevocation::Nothing)?;
    let path = fixture.path().join(RECOVERY_NAME);
    let original = fs::read(&path)?;
    for index in 2..9 {
        rewrite_sir1(&fixture, |unsigned| unsigned[index] = Value::Null)?;
        assert_eq!(
            load(&fixture)?.err(),
            Some(SelectorBoundaryError::ArtifactInvalid),
            "field {index}"
        );
        replace_immutable(&path, &original)?;
    }
    for (field, index) in [(5, 5), (5, 6), (5, 7), (5, 8), (6, 0), (6, 1), (6, 2)] {
        rewrite_sir1(&fixture, |unsigned| {
            if let Value::Array(values) = &mut unsigned[field] {
                values[index] = Value::Null;
            }
        })?;
        assert_eq!(
            load(&fixture)?.err(),
            Some(SelectorBoundaryError::ArtifactInvalid),
            "field {field}.{index}"
        );
        replace_immutable(&path, &original)?;
    }
    rewrite_sir1(&fixture, |unsigned| {
        unsigned[8] = Value::Array(vec![Value::Null]);
    })?;
    assert_eq!(
        load(&fixture)?.err(),
        Some(SelectorBoundaryError::ArtifactInvalid)
    );
    replace_immutable(&path, &original)?;
    assert!(load(&fixture)?.is_ok());
    Ok(())
}

#[test]
fn the_loader_rebinds_every_identity_and_attempt_set() -> TestResult {
    let fixture = UpdateFixture::new()?;
    fixture.commit_pending_update(vec![[41; 16]], vec![[41; 16]], SuccessorRevocation::Nothing)?;
    let path = fixture.path().join(RECOVERY_NAME);
    let original = fs::read(&path)?;
    let alterations: [fn(&mut Vec<Value>); 6] = [
        // A provider identity the previous state did not select.
        |unsigned| set_binding(unsigned, 0, Value::Text("foreign".to_owned())),
        // Zero main PID.
        |unsigned| set_binding(unsigned, 7, Value::Integer(0_u64.into())),
        // A recovery-slot ID repeating the previous runtime ID.
        |unsigned| {
            let runtime = binding_value(unsigned, 5);
            set_slot(unsigned, 0, runtime);
        },
        // Two equal recovery-slot IDs.
        |unsigned| {
            let endpoint = slot_value(unsigned, 2);
            set_slot(unsigned, 1, endpoint);
        },
        // A zero recovery-slot ID.
        |unsigned| set_slot(unsigned, 2, Value::Bytes(vec![0; 16])),
        // A required cancellation outside the previous-live set.
        |unsigned| unsigned[8] = Value::Array(vec![Value::Bytes(vec![42; 16])]),
    ];
    for (case, alter) in alterations.into_iter().enumerate() {
        rewrite_sir1(&fixture, alter)?;
        assert_eq!(
            load(&fixture)?.err(),
            Some(SelectorBoundaryError::ArtifactInvalid),
            "alteration {case}"
        );
        replace_immutable(&path, &original)?;
    }
    Ok(())
}

fn binding_value(unsigned: &[Value], index: usize) -> Value {
    match &unsigned[5] {
        Value::Array(values) => values[index].clone(),
        _ => Value::Null,
    }
}

fn slot_value(unsigned: &[Value], index: usize) -> Value {
    match &unsigned[6] {
        Value::Array(values) => values[index].clone(),
        _ => Value::Null,
    }
}

fn set_binding(unsigned: &mut [Value], index: usize, value: Value) {
    if let Value::Array(values) = &mut unsigned[5] {
        values[index] = value;
    }
}

fn set_slot(unsigned: &mut [Value], index: usize, value: Value) {
    if let Value::Array(values) = &mut unsigned[6] {
        values[index] = value;
    }
}
